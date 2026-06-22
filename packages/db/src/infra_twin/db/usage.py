"""Usage metering writer and counter.

All functions operate on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every
statement, so ``tenant_id`` is used only to stamp the insert, never as a query
filter — exactly like :mod:`infra_twin.db.audit`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import psycopg


def record_usage(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    api_key_id: UUID | None,
    method: str,
    path: str,
    permission: str | None,  # "read" | "write" | None
) -> UUID:
    """INSERT exactly one usage_event row; return usage_id.

    ``occurred_at`` is intentionally omitted from the column list so the
    column DEFAULT (``now()``) fills it in SQL.  The caller must NOT call
    ``conn.commit()``; the surrounding ``tenant_session`` owns the transaction.

    ``api_key_id`` is None for OIDC-authenticated requests.
    """
    row = conn.execute(
        "INSERT INTO usage_event "
        "(tenant_id, api_key_id, method, path, permission) "
        "VALUES (%s, %s, %s, %s, %s) "
        "RETURNING usage_id",
        (tenant_id, api_key_id, method, path, permission),
    ).fetchone()
    return row[0]  # type: ignore[index]


def count_usage_in_window(
    conn: psycopg.Connection,
    tenant_id: UUID,
    since: datetime,
) -> int:
    """Return COUNT(*) of usage_event rows with occurred_at >= since.

    RLS restricts the count to the tenant bound by the surrounding
    ``tenant_session``; ``tenant_id`` is accepted for symmetry/consistency with
    the audit module but MUST NOT be added as an explicit WHERE tenant_id filter
    (RLS is the isolation boundary).  ``since`` MUST be passed as a bound
    parameter, never string-interpolated.
    """
    row = conn.execute(
        "SELECT count(*) FROM usage_event WHERE occurred_at >= %s",
        (since,),
    ).fetchone()
    return int(row[0])  # type: ignore[index]


def current_calendar_month_start(now: datetime | None = None) -> datetime:
    """Return the UTC start (00:00:00) of the calendar month of ``now``.

    ``now`` defaults to ``datetime.now(timezone.utc)``.  The returned value is
    timezone-aware (``tzinfo == timezone.utc``), ``day=1``,
    ``hour=minute=second=microsecond=0``.  This is the metering window boundary
    used everywhere.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
