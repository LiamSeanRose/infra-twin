"""Bitemporal, tenant-scoped repository for risk findings.

Operates on a connection already bound to a tenant by
:func:`infra_twin.db.session.tenant_session`; Row-Level Security scopes every
statement, so these methods never accept a tenant_id as a query filter.

Bitemporal rule: findings are never hard-deleted. A re-evaluation closes a
finding (sets valid_to + status='resolved') and a subsequent positive evaluation
opens a fresh row with a new id. The partial unique index finding_open_identity
ensures at most one open finding per (tenant, rule, subject) at any time.
"""

from __future__ import annotations

from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from infra_twin.core_model import Finding

_FINDING_COLUMNS = (
    "id, tenant_id, rule_id, severity, subject_ci_id, title, description, "
    "evidence, status, detected_at, valid_from, valid_to"
)


def _row_to_finding(row: dict) -> Finding:
    return Finding(
        id=row["id"],
        tenant_id=row["tenant_id"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        subject_ci_id=row["subject_ci_id"],
        title=row["title"],
        description=row["description"],
        evidence=row["evidence"] if row["evidence"] is not None else {},
        status=row["status"],
        detected_at=row["detected_at"],
        valid_from=row["valid_from"],
        valid_to=row["valid_to"],
    )


class FindingRepository:
    """Bitemporal store for risk findings, scoped to one tenant."""

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def _cur(self):
        return self._conn.cursor(row_factory=dict_row)

    def get_open(self, rule_id: str | None = None) -> list[Finding]:
        """Currently-open findings (valid_to IS NULL AND status='open'), newest-first
        (ORDER BY detected_at DESC, id DESC). Optionally filtered by rule_id."""
        clauses = ["valid_to IS NULL", "status = 'open'"]
        params: list[object] = []
        if rule_id is not None:
            clauses.append("rule_id = %s")
            params.append(rule_id)
        with self._cur() as cur:
            rows = cur.execute(
                f"SELECT {_FINDING_COLUMNS} FROM finding "
                f"WHERE {' AND '.join(clauses)} "
                "ORDER BY detected_at DESC, id DESC",
                params,
            ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def get_open_for_subject(self, rule_id: str, subject_ci_id: UUID) -> Finding | None:
        """The single currently-open finding for (rule_id, subject_ci_id), or None.
        At most one can exist (partial unique index finding_open_identity)."""
        with self._cur() as cur:
            row = cur.execute(
                f"SELECT {_FINDING_COLUMNS} FROM finding "
                "WHERE rule_id = %s AND subject_ci_id = %s AND valid_to IS NULL",
                (rule_id, subject_ci_id),
            ).fetchone()
        return _row_to_finding(row) if row else None

    def open_finding(self, finding: Finding) -> Finding:
        """INSERT one new open finding row (status='open', valid_to NULL).
        detected_at and valid_from are filled by SQL now() (omit from the INSERT
        column list, matching the pattern used for occurred_at in record_access).
        Returns the persisted Finding."""
        with self._cur() as cur:
            row = cur.execute(
                "INSERT INTO finding "
                "(id, tenant_id, rule_id, severity, subject_ci_id, title, description, "
                "evidence, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                f"RETURNING {_FINDING_COLUMNS}",
                (
                    finding.id,
                    self._tenant_id,
                    finding.rule_id,
                    finding.severity,
                    finding.subject_ci_id,
                    finding.title,
                    finding.description,
                    Jsonb(finding.evidence),
                    finding.status,
                ),
            ).fetchone()
        return _row_to_finding(row)

    def resolve(self, finding_id: UUID) -> bool:
        """Close the currently-open version: UPDATE finding SET status='resolved',
        valid_to=now() WHERE id=%s AND valid_to IS NULL. Never DELETEs.
        Returns True if a row was closed."""
        with self._cur() as cur:
            row = cur.execute(
                "UPDATE finding SET status = 'resolved', valid_to = now() "
                "WHERE id = %s AND valid_to IS NULL "
                "RETURNING id",
                (finding_id,),
            ).fetchone()
        return row is not None
