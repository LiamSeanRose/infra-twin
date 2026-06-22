"""Bitemporal history retention sweep.

Collapses OLD LOW-VALUE closed interior CI/edge versions into a compact,
immutable ``history_aggregates`` rollup row and then physically removes the
superseded detail rows — without ever touching current state (``valid_to IS NULL``)
or the single most-recent closed boundary row per entity.

Design constraints (non-negotiable):
- Current-state rows (``valid_to IS NULL``) are NEVER touched.
- The single most-recent closed version that the current row supersedes is also
  sacrosanct (retained as the boundary row); if no current row exists, the most
  recent closed version overall is the boundary.
- ``history_aggregates`` row is ALWAYS inserted BEFORE the detail is deleted
  (inside one transaction: rollback leaves both intact).
- The entire sweep runs inside a single ``tenant_session`` transaction.
- ``now`` is used only to compute the eligibility horizon — never substituted
  for SQL ``now()`` in any DML.
- Naive ``now`` is normalised to UTC before horizon arithmetic, matching the
  ``aging.py`` precedent.
- Idempotent: a second consecutive sweep over already-swept state produces
  ``versions_collapsed == 0``, ``aggregates_written == 0``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from uuid import UUID

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from infra_twin.db.connector_health import ConnectorRunRepository
from infra_twin.db.retention import RetentionPolicy, RetentionPolicyRepository
from infra_twin.db.session import tenant_session

# Label used in ``connector_runs.source`` for sweeps produced by this module.
# Mirrors the ``AGING_SOURCE`` pattern in ``aging.py``.
RETENTION_SOURCE: str = "history-retention"


@dataclass(frozen=True)
class RetentionKindReport:
    """Per-entity-kind counters for one ``sweep_history`` call."""

    versions_collapsed: int = 0
    """Interior closed detail rows physically deleted this run."""

    aggregates_written: int = 0
    """``history_aggregates`` rows inserted this run."""

    retained_current: int = 0
    """Rows left untouched because ``valid_to IS NULL`` (sacrosanct current state)."""

    retained_boundary: int = 0
    """Closed rows left as the single retained boundary per entity."""

    eligible: int = 0
    """Closed interior rows that satisfied the horizon predicate (collapsed or not)."""


@dataclass(frozen=True)
class RetentionReport:
    """Result of one ``sweep_history`` call."""

    tenant_id: UUID
    swept: bool
    """False when no policy exists or policy is disabled (no-op)."""

    ci: RetentionKindReport
    edge: RetentionKindReport
    connector_run_id: UUID | None = None


def _sweep_kind(
    conn,
    tenant_id: UUID,
    kind: str,           # 'ci' or 'edge'
    horizon: datetime,
) -> RetentionKindReport:
    """Sweep one entity kind (ci or edge) and return counters.

    Runs on an already-open tenant-session connection; all DML is part of the
    caller's transaction.
    """
    table = "cis" if kind == "ci" else "edges"
    id_col = "id"

    # Fetch ALL closed versions (valid_to IS NOT NULL) older than the horizon
    # together with every current version, grouped by entity id.
    # We also need to know the most-recent closed version per entity to protect
    # the boundary row.
    #
    # Strategy: pull all versions (current + all closed) ordered by
    # (id, valid_from ASC).  Then in Python determine, per entity, which rows
    # are the collapsible interior set.

    if kind == "ci":
        columns = f"{id_col}, valid_from, valid_to, type"
    else:
        columns = f"{id_col}, valid_from, valid_to, type, source"

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {columns} FROM {table} "
            f"ORDER BY {id_col}, valid_from ASC",
        )
        rows = cur.fetchall()

    # Group by entity id
    entity_versions: dict[UUID, list[dict]] = defaultdict(list)
    for row in rows:
        entity_versions[row["id"]].append(row)

    versions_collapsed = 0
    aggregates_written = 0
    retained_current = 0
    retained_boundary = 0
    eligible = 0

    for entity_id, versions in entity_versions.items():
        # Versions are already ordered by valid_from ASC (from the ORDER BY above).

        # Separate current (valid_to IS NULL) and closed versions.
        current_versions = [v for v in versions if v["valid_to"] is None]
        closed_versions = [v for v in versions if v["valid_to"] is not None]

        retained_current += len(current_versions)

        if not closed_versions:
            # Nothing closed; nothing to do.
            continue

        # The boundary row: the most-recent closed version.
        # Sort closed by valid_from DESC to find the most recent.
        closed_sorted_desc = sorted(closed_versions, key=lambda v: v["valid_from"], reverse=True)
        boundary_row = closed_sorted_desc[0]

        # Eligible closed interior rows: valid_to < horizon AND NOT the boundary.
        # We identify the boundary by (id, valid_from) pair since that is the PK.
        boundary_key = (entity_id, boundary_row["valid_from"])

        collapsible = []
        for v in closed_versions:
            # valid_to is timezone-aware from Postgres; horizon may be naive-UTC or tz-aware.
            vto = v["valid_to"]
            if vto.tzinfo is None:
                vto = vto.replace(tzinfo=timezone.utc)

            _horizon = horizon
            if _horizon.tzinfo is None:
                _horizon = _horizon.replace(tzinfo=timezone.utc)

            if vto < _horizon:
                # This row is eligible for collapse (satisfies the horizon predicate).
                eligible += 1
                row_key = (entity_id, v["valid_from"])
                if row_key != boundary_key:
                    collapsible.append(v)

        # Boundary row is always retained (whether it was eligible or not).
        retained_boundary += 1

        if not collapsible:
            continue

        # Compute aggregate over the collapsible set.
        version_count = len(collapsible)
        earliest_valid_from = min(v["valid_from"] for v in collapsible)
        latest_valid_to = max(v["valid_to"] for v in collapsible)

        distinct_types = sorted({v["type"] for v in collapsible})
        if kind == "ci":
            rollup: dict = {
                "types": distinct_types,
                "version_count": version_count,
            }
        else:
            distinct_sources = sorted({v["source"] for v in collapsible})
            rollup = {
                "types": distinct_types,
                "sources": distinct_sources,
                "version_count": version_count,
            }

        # a. INSERT the history_aggregates row FIRST (audit rollup before detail removal).
        conn.execute(
            "INSERT INTO history_aggregates "
            "(tenant_id, entity_kind, entity_id, version_count, "
            "earliest_valid_from, latest_valid_to, rollup) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                tenant_id,
                kind,
                entity_id,
                version_count,
                earliest_valid_from,
                latest_valid_to,
                Jsonb(rollup),
            ),
        )
        aggregates_written += 1

        # b. DELETE the collapsible interior detail rows.
        # Safety predicate: valid_to IS NOT NULL AND valid_to < horizon,
        # excluding the boundary (most-recent closed) row identified by its valid_from.
        collapsible_valid_froms = [v["valid_from"] for v in collapsible]

        conn.execute(
            f"DELETE FROM {table} "
            f"WHERE {id_col} = %s "
            f"  AND valid_to IS NOT NULL "
            f"  AND valid_from = ANY(%s)",
            (entity_id, collapsible_valid_froms),
        )
        versions_collapsed += version_count

    return RetentionKindReport(
        versions_collapsed=versions_collapsed,
        aggregates_written=aggregates_written,
        retained_current=retained_current,
        retained_boundary=retained_boundary,
        eligible=eligible,
    )


def sweep_history(
    pool: ConnectionPool,
    tenant_id: UUID,
    *,
    now: datetime,
) -> RetentionReport:
    """Sweep closed bitemporal CI/edge versions older than the tenant's retention horizon.

    The ``now`` argument is the wall-clock reference used to compute the eligibility
    horizon (``horizon = now - timedelta(days=policy.retain_closed_days)``); it is NOT
    substituted for SQL ``now()`` in any DML statement.

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
        Wall-clock reference for horizon computation.  Should be timezone-aware UTC;
        naive datetimes are normalised to UTC before arithmetic.

    Returns
    -------
    RetentionReport
        Counters for the sweep plus the ``connector_run_id`` (None when no-op).
    """
    # Normalise now to timezone-aware UTC, matching the aging.py precedent.
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    empty_ci = RetentionKindReport()
    empty_edge = RetentionKindReport()

    with tenant_session(pool, tenant_id) as conn:
        policy: RetentionPolicy | None = RetentionPolicyRepository(conn, tenant_id).get_policy()

        # Step 2: no-op if no policy or disabled.
        if policy is None or not policy.enabled:
            return RetentionReport(
                tenant_id=tenant_id,
                swept=False,
                ci=empty_ci,
                edge=empty_edge,
                connector_run_id=None,
            )

        # Step 3: start a connector_runs row.
        run_repo = ConnectorRunRepository(conn, tenant_id)
        run_id: UUID = run_repo.start(RETENTION_SOURCE)

        # Step 4: compute eligibility horizon.
        horizon: datetime = now - timedelta(days=policy.retain_closed_days)

        # Step 5: sweep each entity kind.
        ci_report = _sweep_kind(conn, tenant_id, "ci", horizon)
        edge_report = _sweep_kind(conn, tenant_id, "edge", horizon)

        # Step 6: mark the connector run complete.
        run_repo.finish_ok(run_id)

    # Step 7: return the report.
    return RetentionReport(
        tenant_id=tenant_id,
        swept=True,
        ci=ci_report,
        edge=edge_report,
        connector_run_id=run_id,
    )
