"""Retention policy configuration and history-aggregate repository.

Operates on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every
statement.  ``tenant_id`` is used only to stamp inserts, never as a query
filter — exactly like :class:`infra_twin.db.freshness.FreshnessSloRepository`.

One retention policy per tenant (opt-in).  ``history_aggregates`` is
append-only (SELECT, INSERT only) and may not be mutated after creation.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel


class RetentionPolicy(BaseModel):
    id: UUID
    tenant_id: UUID
    retain_closed_days: int
    enabled: bool
    created_at: datetime
    updated_at: datetime


class HistoryAggregate(BaseModel):
    aggregate_id: UUID
    tenant_id: UUID
    entity_kind: str            # 'ci' | 'edge'
    entity_id: UUID             # the bitemporal entity id (cis.id / edges.id)
    version_count: int          # number of detail versions collapsed into this aggregate
    earliest_valid_from: datetime
    latest_valid_to: datetime
    rollup: dict                # JSONB: distinct types/sources + version count (see spec §3.2)
    created_at: datetime


_POLICY_COLUMNS = (
    "id, tenant_id, retain_closed_days, enabled, created_at, updated_at"
)

_AGGREGATE_COLUMNS = (
    "aggregate_id, tenant_id, entity_kind, entity_id, version_count, "
    "earliest_valid_from, latest_valid_to, rollup, created_at"
)


def _row_to_policy(row: dict) -> RetentionPolicy:
    return RetentionPolicy(
        id=row["id"],
        tenant_id=row["tenant_id"],
        retain_closed_days=row["retain_closed_days"],
        enabled=row["enabled"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_aggregate(row: dict) -> HistoryAggregate:
    return HistoryAggregate(
        aggregate_id=row["aggregate_id"],
        tenant_id=row["tenant_id"],
        entity_kind=row["entity_kind"],
        entity_id=row["entity_id"],
        version_count=row["version_count"],
        earliest_valid_from=row["earliest_valid_from"],
        latest_valid_to=row["latest_valid_to"],
        rollup=row["rollup"],
        created_at=row["created_at"],
    )


class RetentionPolicyRepository:
    """Retention policy configuration and history-aggregate listing, scoped to one tenant.

    Constructed with an open ``psycopg.Connection`` that has already had the
    ``app.tenant_id`` GUC set via :func:`infra_twin.db.session.tenant_session`.
    Row-Level Security scopes every statement to the tenant; ``tenant_id`` is
    only used to stamp inserts, never as a query filter.
    """

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def _cur(self):
        return self._conn.cursor(row_factory=dict_row)

    def upsert_policy(self, *, retain_closed_days: int, enabled: bool) -> RetentionPolicy:
        """Create or update the single retention policy for the tenant.

        Uses INSERT ... ON CONFLICT (tenant_id) DO UPDATE so the id and
        created_at are stable across re-upserts.  Returns the persisted row.
        """
        with self._cur() as cur:
            row = cur.execute(
                f"INSERT INTO history_retention_policies "
                f"(tenant_id, retain_closed_days, enabled) "
                f"VALUES (%s, %s, %s) "
                f"ON CONFLICT (tenant_id) DO UPDATE SET "
                f"retain_closed_days = EXCLUDED.retain_closed_days, "
                f"enabled = EXCLUDED.enabled, "
                f"updated_at = now() "
                f"RETURNING {_POLICY_COLUMNS}",
                (self._tenant_id, retain_closed_days, enabled),
            ).fetchone()
        return _row_to_policy(row)

    def get_policy(self) -> RetentionPolicy | None:
        """Return the tenant's retention policy, or None when no policy row exists."""
        with self._cur() as cur:
            row = cur.execute(
                f"SELECT {_POLICY_COLUMNS} FROM history_retention_policies LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return _row_to_policy(row)

    def list_aggregates(self, *, limit: int = 200) -> list[HistoryAggregate]:
        """All history aggregates visible to the tenant (RLS-scoped).

        Ordered ``created_at DESC, aggregate_id DESC`` for deterministic pagination.
        """
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_AGGREGATE_COLUMNS} FROM history_aggregates "
                f"ORDER BY created_at DESC, aggregate_id DESC "
                f"LIMIT %s",
                (limit,),
            ).fetchall()
        return [_row_to_aggregate(r) for r in rows]
