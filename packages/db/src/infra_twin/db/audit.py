"""Audit log writer and reader.

Both functions operate on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every
statement, so ``tenant_id`` is used only to stamp the insert, never as a query
filter — exactly like :class:`infra_twin.db.repositories.CIRepository`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg


@dataclass(frozen=True)
class AuditEntry:
    audit_id: UUID
    api_key_id: UUID | None   # None for OIDC-authenticated requests
    role: str
    method: str
    path: str
    permission: str | None      # "read" | "write" | None
    decision: str               # "allow" | "deny"
    status_code: int
    occurred_at: datetime
    auth_method: str            # "api_key" | "oidc"


def record_access(
    conn: psycopg.Connection,
    tenant_id: UUID,
    *,
    api_key_id: UUID | None,
    role: str,
    method: str,
    path: str,
    permission: str | None,
    decision: str,              # "allow" | "deny"
    status_code: int,
    auth_method: str = "api_key",
) -> UUID:
    """INSERT exactly one audit_log row; return audit_id.

    ``occurred_at`` is intentionally omitted from the column list so the
    column DEFAULT (``now()``) fills it in SQL.  The caller must NOT call
    ``conn.commit()``; the surrounding ``tenant_session`` owns the transaction.

    ``api_key_id`` is None for OIDC-authenticated requests.
    ``auth_method`` is ``"api_key"`` (default) or ``"oidc"``.
    """
    row = conn.execute(
        "INSERT INTO audit_log "
        "(tenant_id, api_key_id, role, method, path, permission, decision, status_code, auth_method) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "RETURNING audit_id",
        (tenant_id, api_key_id, role, method, path, permission, decision, status_code, auth_method),
    ).fetchone()
    return row[0]  # type: ignore[index]


def list_audit(conn: psycopg.Connection, limit: int = 200) -> list[AuditEntry]:
    """Return the calling tenant's audit rows, newest-first.

    ``ORDER BY occurred_at DESC, audit_id DESC`` gives deterministic ordering
    for rows sharing the same ``occurred_at`` (e.g. same-transaction ``now()``).
    RLS restricts results to the tenant bound by the surrounding
    ``tenant_session``; no explicit tenant filter is added here.
    Negative ``limit`` values are clamped to 0 so SQL never receives a
    negative ``LIMIT``.
    """
    effective_limit = max(0, limit)
    rows = conn.execute(
        "SELECT audit_id, api_key_id, role, method, path, permission, decision, "
        "status_code, occurred_at, auth_method "
        "FROM audit_log "
        "ORDER BY occurred_at DESC, audit_id DESC "
        "LIMIT %s",
        (effective_limit,),
    ).fetchall()
    return [
        AuditEntry(
            audit_id=row[0],
            api_key_id=row[1],
            role=row[2],
            method=row[3],
            path=row[4],
            permission=row[5],
            decision=row[6],
            status_code=row[7],
            occurred_at=row[8],
            auth_method=row[9],
        )
        for row in rows
    ]
