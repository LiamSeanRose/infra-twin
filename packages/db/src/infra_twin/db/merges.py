"""Read-only repository for entity-resolution merge and un-merge provenance.

This module is READ-ONLY — it writes nothing. All queries operate on a connection
already bound to a tenant by :func:`infra_twin.db.session.tenant_session`; Row-Level
Security scopes every statement automatically, so no ``WHERE tenant_id`` filter is
needed or added (exactly as in sibling repositories such as
:class:`infra_twin.db.connector_health.ConnectorRunRepository`).

Queries target the ``ci_merges``, ``ci_alias_keys``, and ``ci_unmerges`` tables
created by ``migrations/0021_entity_alias_keys.sql`` and
``migrations/0022_ci_unmerges.sql``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg


@dataclass(frozen=True)
class UnmergeRecord:
    unmerge_id: UUID
    original_merge_id: UUID
    canonical_ci_id: UUID
    restored_ci_id: UUID
    restored_source: str
    restored_external_id: str
    evidence: str
    unmerged_at: datetime


@dataclass(frozen=True)
class MergeRecord:
    merge_id: UUID
    canonical_ci_id: UUID
    merged_source: str
    merged_external_id: str
    matched_alias_key: str
    evidence: str
    merged_at: datetime


@dataclass(frozen=True)
class AliasKeyBinding:
    alias_key: str
    ci_type: str
    source: str
    observed_at: datetime


@dataclass(frozen=True)
class CIMergeProvenance:
    canonical_ci_id: UUID
    merges: list[MergeRecord]
    alias_keys: list[AliasKeyBinding]


@dataclass(frozen=True)
class MergeCandidateRecord:
    candidate_id: UUID
    ci_id_a: UUID
    ci_id_b: UUID
    ci_type: str
    confidence: float
    evidence: str
    status: str
    resolved_merge_id: UUID | None
    generated_at: datetime
    resolved_at: datetime | None


class MergeReviewRepository:
    """Read-only access to entity-resolution merge provenance, scoped to one tenant."""

    def __init__(self, conn: psycopg.Connection, tenant_id: UUID) -> None:
        self._conn = conn
        self._tenant_id = tenant_id

    def list_merges(self) -> list[MergeRecord]:
        """All ci_merges rows visible to the tenant (RLS), newest first.

        Ordered by merged_at DESC, tie-broken by merge_id DESC for determinism.
        """
        rows = self._conn.execute(
            "SELECT merge_id, canonical_ci_id, merged_source, merged_external_id, "
            "matched_alias_key, evidence, merged_at "
            "FROM ci_merges "
            "ORDER BY merged_at DESC, merge_id DESC"
        ).fetchall()
        return [
            MergeRecord(
                merge_id=row[0],
                canonical_ci_id=row[1],
                merged_source=row[2],
                merged_external_id=row[3],
                matched_alias_key=row[4],
                evidence=row[5],
                merged_at=row[6],
            )
            for row in rows
        ]

    def list_unmerges(self) -> list[UnmergeRecord]:
        """All ci_unmerges rows visible to the tenant (RLS), newest first.

        Ordered by unmerged_at DESC, tie-broken by unmerge_id DESC for determinism.
        Read-only (SELECT only). RLS scopes the tenant; no WHERE tenant_id added.
        """
        rows = self._conn.execute(
            "SELECT unmerge_id, original_merge_id, canonical_ci_id, restored_ci_id, "
            "restored_source, restored_external_id, evidence, unmerged_at "
            "FROM ci_unmerges "
            "ORDER BY unmerged_at DESC, unmerge_id DESC"
        ).fetchall()
        return [
            UnmergeRecord(
                unmerge_id=row[0],
                original_merge_id=row[1],
                canonical_ci_id=row[2],
                restored_ci_id=row[3],
                restored_source=row[4],
                restored_external_id=row[5],
                evidence=row[6],
                unmerged_at=row[7],
            )
            for row in rows
        ]

    def get_merges_for_ci(self, canonical_ci_id: UUID) -> CIMergeProvenance:
        """All ci_merges rows for one canonical_ci_id plus all ci_alias_keys rows bound to it.

        Returns a :class:`CIMergeProvenance` with both lists populated. Does NOT check CI
        existence — the API layer performs the 404 decision against CIRepository.

        ``merges`` ordered merged_at DESC, merge_id DESC.
        ``alias_keys`` ordered observed_at DESC, alias_key ASC.
        """
        merge_rows = self._conn.execute(
            "SELECT merge_id, canonical_ci_id, merged_source, merged_external_id, "
            "matched_alias_key, evidence, merged_at "
            "FROM ci_merges "
            "WHERE canonical_ci_id = %s "
            "ORDER BY merged_at DESC, merge_id DESC",
            (canonical_ci_id,),
        ).fetchall()

        alias_rows = self._conn.execute(
            "SELECT alias_key, ci_type, source, observed_at "
            "FROM ci_alias_keys "
            "WHERE ci_id = %s "
            "ORDER BY observed_at DESC, alias_key ASC",
            (canonical_ci_id,),
        ).fetchall()

        merges = [
            MergeRecord(
                merge_id=row[0],
                canonical_ci_id=row[1],
                merged_source=row[2],
                merged_external_id=row[3],
                matched_alias_key=row[4],
                evidence=row[5],
                merged_at=row[6],
            )
            for row in merge_rows
        ]

        alias_keys = [
            AliasKeyBinding(
                alias_key=row[0],
                ci_type=row[1],
                source=row[2],
                observed_at=row[3],
            )
            for row in alias_rows
        ]

        return CIMergeProvenance(
            canonical_ci_id=canonical_ci_id,
            merges=merges,
            alias_keys=alias_keys,
        )

    def list_merge_candidates(
        self, status: str | None = "pending"
    ) -> list[MergeCandidateRecord]:
        """Candidates visible to the tenant (RLS), newest-first.

        status=None -> all statuses; otherwise filter to that status.
        ORDER BY generated_at DESC, candidate_id DESC.
        """
        if status is not None:
            rows = self._conn.execute(
                "SELECT candidate_id, ci_id_a, ci_id_b, ci_type, confidence, evidence, "
                "status, resolved_merge_id, generated_at, resolved_at "
                "FROM ci_merge_candidates "
                "WHERE status = %s "
                "ORDER BY generated_at DESC, candidate_id DESC",
                (status,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT candidate_id, ci_id_a, ci_id_b, ci_type, confidence, evidence, "
                "status, resolved_merge_id, generated_at, resolved_at "
                "FROM ci_merge_candidates "
                "ORDER BY generated_at DESC, candidate_id DESC"
            ).fetchall()
        return [
            MergeCandidateRecord(
                candidate_id=row[0],
                ci_id_a=row[1],
                ci_id_b=row[2],
                ci_type=row[3],
                confidence=row[4],
                evidence=row[5],
                status=row[6],
                resolved_merge_id=row[7],
                generated_at=row[8],
                resolved_at=row[9],
            )
            for row in rows
        ]
