"""Freshness SLO configuration and breach-evaluation repository.

Operates on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every
statement.  ``tenant_id`` is used only to stamp inserts, never as a query
filter — exactly like :class:`infra_twin.db.connectors.ConnectorRegistry`.

Two-state model: ``fresh`` and ``breaching`` only.  ``warn_after_seconds`` is
intentionally omitted this cycle (documented design choice); a future cycle may
add a third ``warn`` state when that column is introduced.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel


class FreshnessSlo(BaseModel):
    id: UUID
    tenant_id: UUID
    source: str
    expected_interval_seconds: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class FreshnessEvaluation:
    source: str
    expected_interval_seconds: int
    age_seconds: float | None  # now() - finished_at of latest run; None when never finished/never run
    last_run_status: str | None  # 'ok' | 'error' | 'partial' | None (no run ever)
    status: str  # 'fresh' | 'breaching'


_COLUMNS = "id, tenant_id, source, expected_interval_seconds, created_at, updated_at"


def _row_to_slo(row: dict) -> FreshnessSlo:
    return FreshnessSlo(
        id=row["id"],
        tenant_id=row["tenant_id"],
        source=row["source"],
        expected_interval_seconds=row["expected_interval_seconds"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class FreshnessSloRepository:
    """Freshness SLO configuration and evaluation, scoped to one tenant.

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

    def upsert_slo(self, source: str, expected_interval_seconds: int) -> FreshnessSlo:
        """Create or update the single SLO for ``source`` within the tenant.

        Uses INSERT ... ON CONFLICT (tenant_id, source) DO UPDATE so the id
        and created_at are stable across re-upserts.  Returns the persisted row.
        """
        with self._cur() as cur:
            row = cur.execute(
                f"INSERT INTO freshness_slos (tenant_id, source, expected_interval_seconds) "
                f"VALUES (%s, %s, %s) "
                f"ON CONFLICT (tenant_id, source) DO UPDATE SET "
                f"expected_interval_seconds = EXCLUDED.expected_interval_seconds, "
                f"updated_at = now() "
                f"RETURNING {_COLUMNS}",
                (self._tenant_id, source, expected_interval_seconds),
            ).fetchone()
        return _row_to_slo(row)

    def list_slos(self) -> list[FreshnessSlo]:
        """All configured SLOs visible to the tenant (RLS-scoped), ORDER BY source ASC."""
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_COLUMNS} FROM freshness_slos ORDER BY source ASC"
            ).fetchall()
        return [_row_to_slo(r) for r in rows]

    def evaluate(self) -> list[FreshnessEvaluation]:
        """One row per CONFIGURED SLO, ORDER BY source ASC.

        LEFT JOINs ``freshness_slos`` (driving table) against the latest run
        per source using the same DISTINCT ON (source) / age = now()-finished_at
        projection as :meth:`~infra_twin.db.connector_health.ConnectorRunRepository.latest_per_source`.
        Configured-but-never-run sources still produce a row (breaching).
        Sources with runs but no SLO are NOT returned.

        Status resolution rules (two-state: fresh | breaching):
        1. No run ever -> breaching, age_seconds=None, last_run_status=None.
        2. Latest run in-flight (finished_at NULL) -> breaching, age_seconds=None.
        3. Latest run status='error' -> breaching (regardless of age).
        4. Latest run status='ok' and age_seconds <= expected_interval_seconds -> fresh.
        5. Latest run status='ok' and age_seconds > expected_interval_seconds -> breaching.
        6. Latest run status='partial' with finished_at set -> breaching (not ok).
        """
        rows = self._conn.execute(
            """
            WITH latest_runs AS (
                SELECT DISTINCT ON (source)
                    source,
                    status,
                    finished_at,
                    EXTRACT(EPOCH FROM (now() - finished_at)) AS age_seconds
                FROM connector_runs
                ORDER BY source, started_at DESC NULLS LAST
            )
            SELECT
                fs.source,
                fs.expected_interval_seconds,
                lr.age_seconds,
                lr.status         AS last_run_status,
                CASE
                    WHEN lr.source IS NULL                                    THEN 'breaching'
                    WHEN lr.finished_at IS NULL                               THEN 'breaching'
                    WHEN lr.status = 'error'                                  THEN 'breaching'
                    WHEN lr.status = 'ok'
                         AND lr.age_seconds <= fs.expected_interval_seconds   THEN 'fresh'
                    ELSE 'breaching'
                END AS status
            FROM freshness_slos fs
            LEFT JOIN latest_runs lr ON lr.source = fs.source
            ORDER BY fs.source ASC
            """
        ).fetchall()

        return [
            FreshnessEvaluation(
                source=row[0],
                expected_interval_seconds=row[1],
                age_seconds=float(row[2]) if row[2] is not None else None,
                last_run_status=row[3],
                status=row[4],
            )
            for row in rows
        ]
