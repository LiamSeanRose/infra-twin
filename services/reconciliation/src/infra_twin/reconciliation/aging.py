"""Inferred-edge aging sweep: decay and TTL-close stale inferred edges.

This module implements the lifecycle complement to the observation-strengthen path in
``packages/db/.../repositories.py``.  Where repeated observations raise confidence via
``confidence_for_observations``, the aging sweep *lowers* confidence for edges that have
not been re-observed within ``INFERRED_FRESHNESS_WINDOW``, and closes edges that have
exceeded ``INFERRED_EDGE_TTL``.

Design constraints (non-negotiable):
- Declared edges are NEVER touched; the filter is applied before any mutation.
- Bitemporal: decay writes a close + new-open pair (same id, lower confidence); TTL
  sets ``valid_to`` only (no new row, no hard delete).
- Tenant-scoped: the entire sweep runs inside a single ``tenant_session`` transaction;
  RLS prevents cross-tenant access.
- AGE projection: the same ``project()`` call used by ``apply_delta`` keeps the graph
  consistent with the relational state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from uuid import UUID

from psycopg_pool import ConnectionPool

from infra_twin.core_model import (
    INFERRED_EDGE_TTL,
    INFERRED_FRESHNESS_WINDOW,
    Edge,
    EdgeSource,
    Evidence,
    decayed_confidence,
)
from infra_twin.db.connector_health import ConnectorRunRepository
from infra_twin.db.repositories import EdgeRepository, last_observed_at_of
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation.projection import project

# Label used in ``connector_runs.source`` for sweeps produced by this module.
# Mirrors the ``EVENT_SOURCE`` pattern in ``events.py``.
AGING_SOURCE: str = "inferred-edge-aging"


@dataclass
class AgingResult:
    """Counters produced by one ``age_inferred_edges`` call."""

    decayed: int = 0
    """Inferred edges re-versioned with a lowered confidence."""

    closed: int = 0
    """Inferred edges bitemporally closed (age > TTL)."""

    untouched: int = 0
    """Inferred edges left as-is (age <= freshness window, no count marker, etc.)."""

    connector_run_id: UUID | None = None
    """The ``connector_runs`` row created by this sweep."""


def age_inferred_edges(
    pool: ConnectionPool,
    tenant_id: UUID,
    *,
    now: datetime,
) -> AgingResult:
    """Sweep all current inferred edges for ``tenant_id`` and apply decay or TTL-close.

    The ``now`` argument is the wall-clock reference used to compute staleness age;
    it is NOT substituted for SQL ``now()`` in any DML statement (the DB transaction
    timestamp governs ``valid_from`` / ``valid_to``).

    All mutations run inside a single ``tenant_session`` transaction: either everything
    commits or the whole sweep rolls back, leaving no partial state.

    Parameters
    ----------
    pool:
        Connection pool backed by the ``DATABASE_URL`` (RLS-enforced).
    tenant_id:
        The owning tenant.  RLS prevents this sweep from touching any other tenant's
        rows regardless of what the caller passes.
    now:
        Wall-clock reference for age computation.  Must be timezone-aware UTC.

    Returns
    -------
    AgingResult
        Aggregated counters for the sweep plus the ``connector_run_id``.
    """
    result = AgingResult()

    with tenant_session(pool, tenant_id) as conn:
        run_id = ConnectorRunRepository(conn, tenant_id).start(AGING_SOURCE)
        result.connector_run_id = run_id

        edge_repo = EdgeRepository(conn, tenant_id)

        # Fetch all open edges for this tenant (RLS-scoped).  The loop below
        # filters to inferred; declared edges are skipped without ever touching them.
        current_edges: list[Edge] = edge_repo.get_current()

        decayed_edges: list[Edge] = []
        closed_edges: list[Edge] = []

        for edge in current_edges:
            # Declared edges are never aged regardless of timestamps.
            if edge.source != EdgeSource.inferred:
                continue

            last = last_observed_at_of(edge.evidence)

            # No count marker: pre-feature row or edge without an observation stamp.
            # Cannot determine staleness; leave untouched (edge case 6).
            if last is None:
                result.untouched += 1
                continue

            # Normalise to timezone-aware UTC so arithmetic is well-defined.
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)

            age: timedelta = now - last

            # Clock skew: last_observed_at is in the future relative to now
            # (e.g. replayed batch with a future timestamp).  Do not decay
            # or raise an error — leave untouched (edge case 7).
            if age < timedelta(0):
                result.untouched += 1
                continue

            if age > INFERRED_EDGE_TTL:
                # Past TTL: close the edge bitemporally.  No new row is opened.
                edge_repo.close(edge.type, edge.from_id, edge.to_id, edge.edge_key)
                closed_edges.append(edge)
                result.closed += 1

            elif age > INFERRED_FRESHNESS_WINDOW:
                # Idempotency guard: if a decay entry for this exact `now` was already
                # written (same-`now` repeated sweep), treat as untouched rather than
                # decaying again.  Normalise both sides to UTC before comparing so that
                # timezone-aware and naive-UTC stamps compare equal.
                _now_utc = now.astimezone(timezone.utc)
                _already_decayed = any(
                    ev.source == "inferred-edge-decay"
                    and (
                        ev.observed_at.astimezone(timezone.utc)
                        if ev.observed_at.tzinfo is not None
                        else ev.observed_at.replace(tzinfo=timezone.utc)
                    )
                    == _now_utc
                    for ev in edge.evidence
                )
                if _already_decayed:
                    result.untouched += 1
                    continue

                # Past the freshness window but still within TTL: apply linear decay.
                new_conf = decayed_confidence(edge.confidence, age)

                if new_conf >= edge.confidence:
                    # No actual decrease (e.g. confidence already at the floor, or
                    # floating-point precision produces equality).  No-op to avoid
                    # writing a version that does not lower confidence (edge case 5).
                    result.untouched += 1
                    continue

                age_days = int(age.total_seconds() / 86400)
                decay_ev = Evidence(
                    source="inferred-edge-decay",
                    observed_at=now,
                    detail=f"decayed {edge.confidence:.4f}->{new_conf:.4f} age_days={age_days}",
                )
                new_edge = edge_repo.write_decayed_version(
                    edge, new_conf, decay_evidence=decay_ev
                )
                decayed_edges.append(new_edge)
                result.decayed += 1

            else:
                # Within the freshness window: no action.
                result.untouched += 1

        ConnectorRunRepository(conn, tenant_id).finish_ok(run_id)

        # Project updated confidence values and removed relationships into AGE.
        # - decayed_edges: existing MERGE path sets r.confidence to the new lower value.
        # - closed_edges:  DELETE path removes the relationship from the graph.
        project(
            conn,
            current_cis=[],
            current_edges=decayed_edges,
            closed_cis=[],
            closed_edges=closed_edges,
        )

    return result
