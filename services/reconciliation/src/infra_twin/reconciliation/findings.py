"""Risk-findings evaluator: multi-rule pipeline for detecting infrastructure risk.

Two rules are shipped here:
- ``internet_reachable_database``: any database CI (currently: RDS) whose reachability
  traversal finds at least one internet-type source is a critical finding.
- ``over_permissive_iam_role``: any IAM principal (iam_role or iam_user) with access
  breadth (distinct HAS_ACCESS_TO targets) at or above the threshold is a high finding.

Module-boundary note: this module MUST NOT import ``infra_twin.query`` at the top level.
The reachability function is imported lazily inside the function body so the static
import graph of ``services/reconciliation`` gains no dependency on ``services/query``.
Tests and the API layer may inject a custom ``reachability_fn`` via the keyword argument.
The IAM rule does NOT import ``infra_twin.query`` at all; it uses EdgeRepository/CIRepository.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable
from uuid import UUID

import psycopg

from infra_twin.core_model import CIType, EdgeType, Finding
from infra_twin.db.findings import FindingRepository
from infra_twin.db.notifications import NotificationRepository
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.reconciliation.notifications import HttpSender, notify_finding_opened

if TYPE_CHECKING:
    from infra_twin.query.reachability import Reachability

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

RULE_INTERNET_REACHABLE_DATABASE: str = "internet_reachable_database"
RULE_OVER_PERMISSIVE_IAM_ROLE: str = "over_permissive_iam_role"
FINDINGS_SOURCE: str = "risk-findings"
DATABASE_CI_TYPES: frozenset[CIType] = frozenset({CIType.rds})
IAM_PRINCIPAL_CI_TYPES: frozenset[CIType] = frozenset({CIType.iam_role, CIType.iam_user})
INTERNET_DB_SEVERITY: str = "critical"
OVER_PERMISSIVE_IAM_SEVERITY: str = "high"
OVER_PERMISSIVE_ACCESS_THRESHOLD: int = 10
VALID_SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
VALID_STATUSES: tuple[str, ...] = ("open", "resolved")

# Reachability callable signature (injection seam).
ReachabilityFn = Callable[..., "Reachability"]


# ---------------------------------------------------------------------------
# Result summary dataclass
# ---------------------------------------------------------------------------


@dataclass
class EvaluateResult:
    evaluated: int    # number of CIs examined
    opened: int       # findings newly opened this run
    resolved: int     # previously-open findings closed this run
    open_count: int   # total currently-open findings for this rule after the run


# ---------------------------------------------------------------------------
# Internal helpers for internet_reachable_database rule
# ---------------------------------------------------------------------------


def _build_internet_finding(db, tenant_id: UUID, chosen) -> Finding:
    """Construct the Finding for an internet-reachable database CI."""
    label = db.name or db.external_id
    path_items = [
        {
            "from_id": str(hop.from_id),
            "to_id": str(hop.to_id),
            "edge_type": hop.edge_type,
            "evidence": hop.evidence,
        }
        for hop in chosen.path
    ]
    evidence = {
        "rule_id": RULE_INTERNET_REACHABLE_DATABASE,
        "subject_external_id": db.external_id,
        "reaching_source": {
            "id": str(chosen.id),
            "type": "internet",
            "name": chosen.name,
            "distance": chosen.distance,
        },
        "path": path_items,
    }
    return Finding(
        tenant_id=tenant_id,
        rule_id=RULE_INTERNET_REACHABLE_DATABASE,
        severity=INTERNET_DB_SEVERITY,
        subject_ci_id=db.id,
        title=f"Internet-reachable database: {label}",
        description=(
            f"Database {label} ({db.type.value}) is reachable from "
            f"the public internet via a {chosen.distance}-hop path."
        ),
        evidence=evidence,
        status="open",
    )


def _nearest_internet_source(internet_sources):
    """Choose the nearest internet source: smallest distance, ties broken by str(id)."""
    return min(internet_sources, key=lambda s: (s.distance, str(s.id)))


# ---------------------------------------------------------------------------
# Per-rule evaluator: internet_reachable_database
# ---------------------------------------------------------------------------


def _evaluate_internet_reachable_database(
    conn: psycopg.Connection,
    tenant_id: UUID,
    repo: FindingRepository,
    ci_repo: CIRepository,
    *,
    reachability_fn: ReachabilityFn,
    max_depth: int,
    min_confidence: float,
    notify_sender: HttpSender | None = None,
    notif_repo: NotificationRepository | None = None,
) -> EvaluateResult:
    """Evaluate the internet_reachable_database rule for the given tenant.

    Scoped to RULE_INTERNET_REACHABLE_DATABASE findings only. All per-rule
    open/resolve reconciliation is done against repo.get_open(rule_id=...).
    """
    # Collect all current database CIs
    dbs = []
    for ci_type in DATABASE_CI_TYPES:
        dbs.extend(ci_repo.get_current(type=ci_type))
    evaluated = len(dbs)

    # Index currently-open findings for this rule by subject_ci_id
    open_by_subject: dict[UUID, Finding] = {
        f.subject_ci_id: f
        for f in repo.get_open(rule_id=RULE_INTERNET_REACHABLE_DATABASE)
    }

    opened = 0
    resolved = 0
    unmatched: set[UUID] = set(open_by_subject)

    for db in dbs:
        r = reachability_fn(
            conn, tenant_id, db.id,
            max_depth=max_depth,
            min_confidence=min_confidence,
        )
        internet_sources = [s for s in r.sources if s.is_internet]

        # This subject has been evaluated; remove from unmatched set
        unmatched.discard(db.id)

        if internet_sources:
            # Database is reachable from internet
            if db.id in open_by_subject:
                # Already has an open finding — leave untouched (idempotent)
                pass
            else:
                chosen = _nearest_internet_source(internet_sources)
                finding = _build_internet_finding(db, tenant_id, chosen)
                persisted = repo.open_finding(finding)
                opened += 1
                if notify_sender is not None:
                    subject_ci = ci_repo.get_current_by_id(persisted.subject_ci_id)
                    notify_finding_opened(notif_repo, persisted, subject_ci, send=notify_sender)
        else:
            # Database is NOT reachable from internet
            if db.id in open_by_subject:
                repo.resolve(open_by_subject[db.id].id)
                resolved += 1

    # Resolve findings for CIs that are no longer current database CIs
    for subject_id in unmatched:
        repo.resolve(open_by_subject[subject_id].id)
        resolved += 1

    open_count = len(repo.get_open(rule_id=RULE_INTERNET_REACHABLE_DATABASE))
    return EvaluateResult(evaluated, opened, resolved, open_count)


# ---------------------------------------------------------------------------
# Per-rule evaluator: over_permissive_iam_role
# ---------------------------------------------------------------------------


def _evaluate_over_permissive_iam_role(
    conn: psycopg.Connection,
    tenant_id: UUID,
    repo: FindingRepository,
    ci_repo: CIRepository,
    *,
    access_threshold: int,
    notify_sender: HttpSender | None = None,
    notif_repo: NotificationRepository | None = None,
) -> EvaluateResult:
    """Evaluate the over_permissive_iam_role rule for the given tenant.

    Counts distinct HAS_ACCESS_TO targets per IAM principal via EdgeRepository.
    Scoped to RULE_OVER_PERMISSIVE_IAM_ROLE findings only.
    """
    edge_repo = EdgeRepository(conn, tenant_id)

    # Step 1: load all current IAM principal CIs
    principals = []
    for ci_type in IAM_PRINCIPAL_CI_TYPES:
        principals.extend(ci_repo.get_current(type=ci_type))
    evaluated = len(principals)

    # Step 2: index this rule's open findings by subject
    open_by_subject: dict[UUID, Finding] = {
        f.subject_ci_id: f
        for f in repo.get_open(rule_id=RULE_OVER_PERMISSIVE_IAM_ROLE)
    }
    unmatched: set[UUID] = set(open_by_subject)

    opened = 0
    resolved = 0

    # Step 3: for each principal, compute access breadth and reconcile
    for p in principals:
        # Get all current out-edges from this principal; filter to HAS_ACCESS_TO
        edges = edge_repo.get_current(from_id=p.id)
        has_access_edges = [e for e in edges if e.type == EdgeType.HAS_ACCESS_TO]

        # Deduplicate by to_id to count distinct targets
        distinct_to_ids: list[UUID] = list({e.to_id for e in has_access_edges})
        access_count = len(distinct_to_ids)

        unmatched.discard(p.id)

        if access_count >= access_threshold:
            if p.id in open_by_subject:
                # Already has an open finding — leave untouched (idempotent)
                pass
            else:
                # Resolve target CI types for evidence; sort deterministically by id str
                targets_sorted = sorted(distinct_to_ids, key=str)
                target_entries = []
                for to_id in targets_sorted:
                    target_ci = ci_repo.get_current_by_id(to_id)
                    target_entries.append({
                        "id": str(to_id),
                        "type": target_ci.type.value if target_ci is not None else None,
                    })

                label = p.name or p.external_id
                evidence = {
                    "rule_id": RULE_OVER_PERMISSIVE_IAM_ROLE,
                    "subject_external_id": p.external_id,
                    "access_count": access_count,
                    "threshold": access_threshold,
                    "targets": target_entries,
                }
                finding = Finding(
                    tenant_id=tenant_id,
                    rule_id=RULE_OVER_PERMISSIVE_IAM_ROLE,
                    severity=OVER_PERMISSIVE_IAM_SEVERITY,
                    subject_ci_id=p.id,
                    title=f"Over-permissive IAM principal: {label} ({access_count} resources)",
                    description=(
                        f"IAM {p.type.value} {label} has access to {access_count} distinct "
                        f"resources via HAS_ACCESS_TO (threshold {access_threshold})."
                    ),
                    evidence=evidence,
                    status="open",
                )
                persisted = repo.open_finding(finding)
                opened += 1
                if notify_sender is not None:
                    subject_ci = ci_repo.get_current_by_id(persisted.subject_ci_id)
                    notify_finding_opened(notif_repo, persisted, subject_ci, send=notify_sender)
        else:
            # access_count < access_threshold
            if p.id in open_by_subject:
                repo.resolve(open_by_subject[p.id].id)
                resolved += 1

    # Step 4: resolve findings for IAM principals that are no longer current CIs
    for subject_id in unmatched:
        repo.resolve(open_by_subject[subject_id].id)
        resolved += 1

    # Step 5: per-rule open count
    open_count = len(repo.get_open(rule_id=RULE_OVER_PERMISSIVE_IAM_ROLE))
    return EvaluateResult(evaluated, opened, resolved, open_count)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_findings_with_summary(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    reachability_fn: ReachabilityFn | None = None,
    max_depth: int = 6,
    min_confidence: float = 0.0,
    access_threshold: int = OVER_PERMISSIVE_ACCESS_THRESHOLD,
    notify_sender: HttpSender | None = None,
) -> tuple[EvaluateResult, list[Finding]]:
    """Evaluate all risk-findings rules, returning aggregated counters and open findings.

    Runs inside the caller's ``tenant_session`` transaction on the passed ``conn``.
    Does NOT open or commit a transaction.

    Pipeline (idempotent, bitemporal):
    1. Resolve reachability_fn (default: lazily import from infra_twin.query.reachability).
    2. Construct CIRepository and FindingRepository once on the passed conn.
    3. Run _evaluate_internet_reachable_database (existing behavior, scoped to its rule_id).
    4. Run _evaluate_over_permissive_iam_role (new, scoped to its rule_id).
    5. Aggregate per-rule EvaluateResult fields (sum each counter across all rules).
    6. Return aggregated result + combined open findings across ALL rules (newest-first).

    When ``notify_sender`` is not None, a ``NotificationRepository`` is constructed once
    and passed to each per-rule evaluator, which will call ``notify_finding_opened`` for
    every newly opened finding. When ``notify_sender`` is None, behavior is identical to
    the pre-notification baseline (no deliveries written).
    """
    if reachability_fn is None:
        from infra_twin.query.reachability import reachability as _default_reach
        reachability_fn = _default_reach

    ci_repo = CIRepository(conn, tenant_id)
    repo = FindingRepository(conn, tenant_id)

    notif_repo: NotificationRepository | None = None
    if notify_sender is not None:
        notif_repo = NotificationRepository(conn, tenant_id)

    # Run each rule evaluator in sequence
    result_internet = _evaluate_internet_reachable_database(
        conn, tenant_id, repo, ci_repo,
        reachability_fn=reachability_fn,
        max_depth=max_depth,
        min_confidence=min_confidence,
        notify_sender=notify_sender,
        notif_repo=notif_repo,
    )
    result_iam = _evaluate_over_permissive_iam_role(
        conn, tenant_id, repo, ci_repo,
        access_threshold=access_threshold,
        notify_sender=notify_sender,
        notif_repo=notif_repo,
    )

    # Aggregate counters across all rules
    aggregated = EvaluateResult(
        evaluated=result_internet.evaluated + result_iam.evaluated,
        opened=result_internet.opened + result_iam.opened,
        resolved=result_internet.resolved + result_iam.resolved,
        open_count=result_internet.open_count + result_iam.open_count,
    )

    # Return combined open findings across ALL rules, newest-first
    open_findings = repo.get_open()
    return aggregated, open_findings


def evaluate_findings(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    reachability_fn: ReachabilityFn | None = None,
    max_depth: int = 6,
    min_confidence: float = 0.0,
    access_threshold: int = OVER_PERMISSIVE_ACCESS_THRESHOLD,
    notify_sender: HttpSender | None = None,
) -> list[Finding]:
    """Currently-open findings across all rules after the run.

    Delegates to evaluate_findings_with_summary and returns only the findings list.
    """
    _, findings = evaluate_findings_with_summary(
        conn,
        tenant_id,
        reachability_fn=reachability_fn,
        max_depth=max_depth,
        min_confidence=min_confidence,
        access_threshold=access_threshold,
        notify_sender=notify_sender,
    )
    return findings
