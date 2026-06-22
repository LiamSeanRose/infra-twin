"""Repositories for connector run lifecycle and raw fact persistence.

Both repositories operate on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every statement, so
these methods take ``tenant_id`` only to stamp inserts, never as a query filter — exactly
like :class:`infra_twin.db.repositories.CIRepository`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb


@dataclass(frozen=True)
class ConnectorRunSummary:
    source: str
    status: str  # 'ok' | 'error' | 'partial'
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    age_seconds: float | None  # now() - finished_at; None when finished_at is None


class ConnectorRunRepository:
    """Lifecycle tracking for connector runs, scoped to one tenant."""

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def start(self, source: str, connector_id: UUID | None = None) -> UUID:
        """Insert a connector_runs row with status='partial', started_at=now().

        Returns the new run_id. The insert is committed when the surrounding
        tenant_session block exits.  ``connector_id`` is optional: existing
        callers that omit it write NULL, which is allowed by the nullable FK.
        """
        row = self._conn.execute(
            "INSERT INTO connector_runs (tenant_id, source, status, started_at, connector_id) "
            "VALUES (%s, %s, 'partial', now(), %s) RETURNING run_id",
            (self._tenant_id, source, connector_id),
        ).fetchone()
        return row[0]  # type: ignore[index]

    def finish_ok(self, run_id: UUID) -> None:
        """Mark the run as successfully completed."""
        self._conn.execute(
            "UPDATE connector_runs SET status='ok', finished_at=now() WHERE run_id=%s",
            (run_id,),
        )

    def finish_error(self, run_id: UUID, error: str) -> None:
        """Mark the run as failed, recording the error text."""
        self._conn.execute(
            "UPDATE connector_runs SET status='error', finished_at=now(), error=%s "
            "WHERE run_id=%s",
            (error, run_id),
        )

    def latest_per_source(self) -> list[ConnectorRunSummary]:
        """One row per source: the most recent run by started_at, ordered by source ascending."""
        rows = self._conn.execute(
            "SELECT DISTINCT ON (source) source, status, started_at, finished_at, error, "
            "EXTRACT(EPOCH FROM (now() - finished_at)) AS age_seconds "
            "FROM connector_runs ORDER BY source, started_at DESC NULLS LAST"
        ).fetchall()
        return [
            ConnectorRunSummary(
                source=row[0],
                status=row[1],
                started_at=row[2],
                finished_at=row[3],
                error=row[4],
                age_seconds=float(row[5]) if row[5] is not None else None,
            )
            for row in rows
        ]


class RawFactRepository:
    """Append-only store for immutable raw connector observations, scoped to one tenant."""

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def record(
        self,
        source: str,
        observed_at: datetime,
        payloads: list[dict],
        connector_id: UUID | None = None,
    ) -> int:
        """Bulk-insert one immutable raw_facts row per payload.

        Returns the number of rows inserted. No-op returning 0 when payloads is empty.
        Raw facts are never updated or deleted (immutability rule).
        ``connector_id`` is optional: existing callers that omit it write NULL,
        which is allowed by the nullable FK.
        """
        if not payloads:
            return 0

        with self._conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO raw_facts (tenant_id, source, observed_at, payload, connector_id) "
                "VALUES (%s, %s, %s, %s, %s)",
                [
                    (self._tenant_id, source, observed_at, Jsonb(payload), connector_id)
                    for payload in payloads
                ],
            )
            return len(payloads)
