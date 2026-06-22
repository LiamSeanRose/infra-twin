"""Anomaly / drift detector: deterministic, rule-based detection of risky changes.

Two rules ship here:
- ``anomaly_public_ip_on_database``: a database CI (RDS or db_instance) is flagged when
  it is currently internet-reachable AND that exposure was newly introduced inside the scan
  window (a new edge terminating at the DB, or the DB itself was created/updated in window).
- ``anomaly_security_group_opened_to_world``: a security-group CI is flagged when a
  ``created`` CONNECTS_TO edge from the internet CI into it appears in the window.

This is deterministic rule-based drift detection — NOT machine-learning, NOT statistical
baselining, NOT predictive simulation. The rules scan the bitemporal change feed and
current graph topology using only queried facts. No LLM is invoked.

Module-boundary note: this module MUST NOT import ``infra_twin.query`` at the top level.
The change_feed and reachability functions are imported lazily inside the orchestrator body
so the static import graph of ``services/reconciliation`` gains no dependency on
``services/query``. Tests and the API layer may inject custom callables via keyword arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Callable
from uuid import UUID

import psycopg

from infra_twin.core_model import CIType, Finding
from infra_twin.db.findings import FindingRepository
from infra_twin.db.repositories import CIRepository

if TYPE_CHECKING:
    from infra_twin.query.change_feed import ChangeEvent
    from infra_twin.query.reachability import Reachability

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

RULE_PUBLIC_IP_ON_DATABASE: str = "anomaly_public_ip_on_database"
RULE_SECURITY_GROUP_OPENED_TO_WORLD: str = "anomaly_security_group_opened_to_world"

ANOMALIES_SOURCE: str = "anomaly-detection"

# CI types treated as "databases" for the public-IP rule.
DATABASE_CI_TYPES: frozenset[CIType] = frozenset({CIType.rds, CIType.db_instance})

# Severities (each is a member of VALID_SEVERITIES).
PUBLIC_IP_ON_DATABASE_SEVERITY: str = "critical"
SECURITY_GROUP_OPENED_TO_WORLD_SEVERITY: str = "high"

# Re-export the same tuples findings.py exposes (identical values), so tests can import
# them from infra_twin.reconciliation.anomalies just like from infra_twin.reconciliation.findings.
VALID_SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
VALID_STATUSES: tuple[str, ...] = ("open", "resolved")

# Default scan window length when the caller/endpoint does not pass an explicit ``since``.
DEFAULT_SCAN_WINDOW: timedelta = timedelta(days=7)

# CIDR string that marks a world-open ingress for the SG rule.
WORLD_CIDR: str = "0.0.0.0/0"

# Edge types that constitute an exposure path for the public-IP rule.
_EXPOSURE_EDGE_TYPES: frozenset[str] = frozenset({"CONNECTS_TO", "EXPOSES", "ROUTES_TO", "RESOLVES_TO"})

# Reachability + change-feed callable signatures (injection seams, mirror findings.ReachabilityFn).
ReachabilityFn = Callable[..., "Reachability"]
ChangeFeedFn = Callable[..., "list[ChangeEvent]"]


# ---------------------------------------------------------------------------
# Result summary dataclass (mirrors findings.EvaluateResult)
# ---------------------------------------------------------------------------


@dataclass
class AnomalyEvaluateResult:
    scanned_events: int   # number of change events examined across the window
    opened: int           # findings newly opened this run
    resolved: int         # previously-open findings closed this run
    open_count: int       # total currently-open anomaly findings after the run


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _nearest_internet_source(internet_sources):
    """Choose the nearest internet source: smallest distance, ties broken by str(id)."""
    return min(internet_sources, key=lambda s: (s.distance, str(s.id)))


def _serialize_event(e: "ChangeEvent") -> dict:
    return {
        "entity": e.entity,
        "kind": e.kind,
        "at": e.at.isoformat(),
        "id": str(e.id),
        "type": e.type,
        "from_id": str(e.from_id) if e.from_id else None,
        "to_id": str(e.to_id) if e.to_id else None,
    }


# ---------------------------------------------------------------------------
# Per-rule evaluator: anomaly_public_ip_on_database
# ---------------------------------------------------------------------------


def _evaluate_public_ip_on_database(
    conn: psycopg.Connection,
    tenant_id: UUID,
    repo: FindingRepository,
    ci_repo: CIRepository,
    *,
    since,
    until,
    change_feed_fn: ChangeFeedFn,
    reachability_fn: ReachabilityFn,
    max_depth: int,
    min_confidence: float,
) -> AnomalyEvaluateResult:
    """Evaluate the anomaly_public_ip_on_database rule for the given tenant.

    A database CI is flagged when it is currently internet-reachable AND that exposure
    was newly introduced inside the scan window. Scoped to RULE_PUBLIC_IP_ON_DATABASE
    findings only. All open/resolve reconciliation is keyed on subject_ci_id.
    """
    # Step 1: fetch change events for the window
    events: list[ChangeEvent] = change_feed_fn(conn, tenant_id, since=since, until=until)
    scanned_events = len(events)

    # Step 2: build the set of current database CIs
    dbs = []
    for ci_type in DATABASE_CI_TYPES:
        dbs.extend(ci_repo.get_current(type=ci_type))

    # Step 3: index this rule's open findings by subject_ci_id
    open_by_subject: dict[UUID, Finding] = {
        f.subject_ci_id: f
        for f in repo.get_open(rule_id=RULE_PUBLIC_IP_ON_DATABASE)
    }
    unmatched: set[UUID] = set(open_by_subject)

    opened = 0
    resolved = 0

    # Step 4: for each current database CI, determine triggering events and reconcile
    for db in dbs:
        # Condition 1: edge 'created' event with exposure type terminating at this DB
        edge_trigger_events = [
            e for e in events
            if e.entity == "edge"
            and e.kind == "created"
            and e.type in _EXPOSURE_EDGE_TYPES
            and e.to_id == db.id
        ]
        # Condition 2: CI 'created' or 'updated' event on this DB itself
        ci_trigger_events = [
            e for e in events
            if e.entity == "ci"
            and e.kind in {"created", "updated"}
            and e.id == db.id
        ]
        triggering_events = sorted(
            edge_trigger_events + ci_trigger_events,
            key=lambda e: (e.at, str(e.id)),
        )

        # Remove from unmatched set (this subject has been evaluated)
        unmatched.discard(db.id)

        if triggering_events:
            # Check current internet reachability
            r: Reachability = reachability_fn(
                conn, tenant_id, db.id,
                max_depth=max_depth,
                min_confidence=min_confidence,
            )
            internet_sources = [s for s in r.sources if s.is_internet]

            if internet_sources:
                # Both conditions hold: triggered in window AND internet-reachable now
                if db.id in open_by_subject:
                    # Already has an open finding — leave untouched (idempotent)
                    pass
                else:
                    chosen = _nearest_internet_source(internet_sources)
                    label = db.name or db.external_id
                    evidence = {
                        "rule_id": RULE_PUBLIC_IP_ON_DATABASE,
                        "subject_external_id": db.external_id,
                        "triggering_events": [_serialize_event(e) for e in triggering_events],
                        "reaching_source": {
                            "id": str(chosen.id),
                            "type": "internet",
                            "name": chosen.name,
                            "distance": chosen.distance,
                        },
                        "window": {"since": since.isoformat(), "until": until.isoformat()},
                    }
                    finding = Finding(
                        tenant_id=tenant_id,
                        rule_id=RULE_PUBLIC_IP_ON_DATABASE,
                        severity=PUBLIC_IP_ON_DATABASE_SEVERITY,
                        subject_ci_id=db.id,
                        title=f"Public exposure newly attached to database: {label}",
                        description=(
                            f"Database {label} ({db.type.value}) has a public-internet "
                            f"reachability path that appeared within the scan window "
                            f"[{since.isoformat()}, {until.isoformat()})."
                        ),
                        evidence=evidence,
                        status="open",
                    )
                    repo.open_finding(finding)
                    opened += 1
            else:
                # Triggered in window but not internet-reachable now — resolve if open
                if db.id in open_by_subject:
                    repo.resolve(open_by_subject[db.id].id)
                    resolved += 1
        else:
            # No triggering events in window — resolve if there is an open finding
            if db.id in open_by_subject:
                repo.resolve(open_by_subject[db.id].id)
                resolved += 1

    # Step 5: resolve findings for subjects no longer in the current DB set
    for subject_id in unmatched:
        repo.resolve(open_by_subject[subject_id].id)
        resolved += 1

    # Step 6: per-rule open count after reconciliation
    open_count = len(repo.get_open(rule_id=RULE_PUBLIC_IP_ON_DATABASE))
    return AnomalyEvaluateResult(scanned_events, opened, resolved, open_count)


# ---------------------------------------------------------------------------
# Per-rule evaluator: anomaly_security_group_opened_to_world
# ---------------------------------------------------------------------------


def _evaluate_security_group_opened_to_world(
    conn: psycopg.Connection,
    tenant_id: UUID,
    repo: FindingRepository,
    ci_repo: CIRepository,
    *,
    since,
    until,
    change_feed_fn: ChangeFeedFn,
) -> AnomalyEvaluateResult:
    """Evaluate the anomaly_security_group_opened_to_world rule for the given tenant.

    A security-group CI is flagged when a 'created' CONNECTS_TO edge from the internet CI
    into it appears in the scan window. Scoped to RULE_SECURITY_GROUP_OPENED_TO_WORLD only.
    """
    # Step 1: fetch change events for the window
    events: list[ChangeEvent] = change_feed_fn(conn, tenant_id, since=since, until=until)
    scanned_events = len(events)

    # Candidate: 'created' CONNECTS_TO edge events
    connects_to_events = [
        e for e in events
        if e.entity == "edge"
        and e.kind == "created"
        and e.type == "CONNECTS_TO"
    ]

    # Step 2: index this rule's open findings by subject_ci_id
    open_by_subject: dict[UUID, Finding] = {
        f.subject_ci_id: f
        for f in repo.get_open(rule_id=RULE_SECURITY_GROUP_OPENED_TO_WORLD)
    }
    unmatched: set[UUID] = set(open_by_subject)

    # Step 3: build mapping of security-group CIs that have world-open events in window
    # Map: sg_ci_id -> list of triggering events
    sg_trigger_map: dict[UUID, list] = {}

    for e in connects_to_events:
        if e.from_id is None or e.to_id is None:
            continue
        # Resolve the 'from' endpoint: must be the internet CI
        from_ci = ci_repo.get_current_by_id(e.from_id)
        if from_ci is None or from_ci.type != CIType.internet:
            continue
        # Resolve the 'to' endpoint: must be a security group
        to_ci = ci_repo.get_current_by_id(e.to_id)
        if to_ci is None or to_ci.type != CIType.security_group:
            continue
        # This is a world-open edge into a security group
        sg_id = to_ci.id
        if sg_id not in sg_trigger_map:
            sg_trigger_map[sg_id] = []
        sg_trigger_map[sg_id].append(e)

    opened = 0
    resolved = 0

    # Step 4: reconcile for each flagged security group
    for sg_id, trigger_events in sg_trigger_map.items():
        unmatched.discard(sg_id)
        if sg_id in open_by_subject:
            # Already open — leave untouched (idempotent)
            pass
        else:
            sg = ci_repo.get_current_by_id(sg_id)
            if sg is None:
                continue
            label = sg.name or sg.external_id
            sorted_triggers = sorted(trigger_events, key=lambda e: (e.at, str(e.id)))
            evidence = {
                "rule_id": RULE_SECURITY_GROUP_OPENED_TO_WORLD,
                "subject_external_id": sg.external_id,
                "world_cidr": WORLD_CIDR,
                "triggering_events": [_serialize_event(e) for e in sorted_triggers],
                "window": {"since": since.isoformat(), "until": until.isoformat()},
            }
            finding = Finding(
                tenant_id=tenant_id,
                rule_id=RULE_SECURITY_GROUP_OPENED_TO_WORLD,
                severity=SECURITY_GROUP_OPENED_TO_WORLD_SEVERITY,
                subject_ci_id=sg_id,
                title=f"Security group opened to the world: {label}",
                description=(
                    f"Security group {label} received an ingress from "
                    f"{WORLD_CIDR} (internet) via a CONNECTS_TO edge created "
                    f"within the scan window [{since.isoformat()}, {until.isoformat()})."
                ),
                evidence=evidence,
                status="open",
            )
            repo.open_finding(finding)
            opened += 1

    # Step 5: resolve findings for SGs that no longer have world-open events in window
    for subject_id in unmatched:
        repo.resolve(open_by_subject[subject_id].id)
        resolved += 1

    # Step 6: per-rule open count after reconciliation
    open_count = len(repo.get_open(rule_id=RULE_SECURITY_GROUP_OPENED_TO_WORLD))
    return AnomalyEvaluateResult(scanned_events, opened, resolved, open_count)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_anomalies_with_summary(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    since,
    until,
    change_feed_fn: ChangeFeedFn | None = None,
    reachability_fn: ReachabilityFn | None = None,
    max_depth: int = 6,
    min_confidence: float = 0.0,
) -> tuple[AnomalyEvaluateResult, list[Finding]]:
    """Evaluate all anomaly rules, returning aggregated counters and open anomaly findings.

    Runs inside the caller's ``tenant_session`` transaction on the passed ``conn``.
    Does NOT open or commit a transaction.

    Pipeline (idempotent, bitemporal):
    1. Resolve change_feed_fn and reachability_fn (defaults: lazily imported from
       infra_twin.query).
    2. Construct CIRepository and FindingRepository once on the passed conn.
    3. Run _evaluate_public_ip_on_database (scoped to RULE_PUBLIC_IP_ON_DATABASE).
    4. Run _evaluate_security_group_opened_to_world (scoped to
       RULE_SECURITY_GROUP_OPENED_TO_WORLD).
    5. Aggregate per-rule AnomalyEvaluateResult fields (sum each counter).
    6. Return aggregated result + combined open anomaly findings across BOTH rules
       (newest-first by detected_at desc, id desc).

    The combined finding list is obtained via two scoped calls
    (repo.get_open(rule_id=RULE_PUBLIC_IP_ON_DATABASE) +
    repo.get_open(rule_id=RULE_SECURITY_GROUP_OPENED_TO_WORLD)) so that risk findings
    from findings.py are never included.
    """
    if change_feed_fn is None:
        from infra_twin.query.change_feed import change_feed as _default_cf
        change_feed_fn = _default_cf
    if reachability_fn is None:
        from infra_twin.query.reachability import reachability as _default_reach
        reachability_fn = _default_reach

    ci_repo = CIRepository(conn, tenant_id)
    repo = FindingRepository(conn, tenant_id)

    result_public_ip = _evaluate_public_ip_on_database(
        conn, tenant_id, repo, ci_repo,
        since=since,
        until=until,
        change_feed_fn=change_feed_fn,
        reachability_fn=reachability_fn,
        max_depth=max_depth,
        min_confidence=min_confidence,
    )
    result_sg = _evaluate_security_group_opened_to_world(
        conn, tenant_id, repo, ci_repo,
        since=since,
        until=until,
        change_feed_fn=change_feed_fn,
    )

    # Aggregate counters across both rules
    aggregated = AnomalyEvaluateResult(
        scanned_events=result_public_ip.scanned_events + result_sg.scanned_events,
        opened=result_public_ip.opened + result_sg.opened,
        resolved=result_public_ip.resolved + result_sg.resolved,
        open_count=result_public_ip.open_count + result_sg.open_count,
    )

    # Return combined open anomaly findings across BOTH rules, newest-first.
    # Do NOT use bare repo.get_open() — that would include risk findings from findings.py.
    open_findings = (
        repo.get_open(rule_id=RULE_PUBLIC_IP_ON_DATABASE)
        + repo.get_open(rule_id=RULE_SECURITY_GROUP_OPENED_TO_WORLD)
    )
    open_findings.sort(key=lambda f: (f.detected_at, str(f.id)), reverse=True)

    return aggregated, open_findings


def evaluate_anomalies(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    since,
    until,
    change_feed_fn: ChangeFeedFn | None = None,
    reachability_fn: ReachabilityFn | None = None,
    max_depth: int = 6,
    min_confidence: float = 0.0,
) -> list[Finding]:
    """Currently-open anomaly findings across both rules after the run.

    Delegates to evaluate_anomalies_with_summary and returns only the findings list.
    """
    _, findings = evaluate_anomalies_with_summary(
        conn,
        tenant_id,
        since=since,
        until=until,
        change_feed_fn=change_feed_fn,
        reachability_fn=reachability_fn,
        max_depth=max_depth,
        min_confidence=min_confidence,
    )
    return findings
