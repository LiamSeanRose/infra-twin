"""Un-merge engine: reverse a single deterministic cross-source merge.

Splits the previously-fused source out of its canonical CI into a freshly-inserted
distinct CI by re-binding mappings and bitemporally re-pointing that source's edges,
recording the reversal as new provenance.  Physically deletes nothing and leaves the
forward merge engine untouched.

Edge-repointing rule (deterministic, conservative):
    Re-point only DECLARED current edges (source == 'declared') attached to the
    canonical CI (from_id == canonical_ci_id OR to_id == canonical_ci_id) whose
    evidence provably originates from the restored source — i.e. at least one Evidence
    entry has source == restored_source, OR an Evidence.detail references
    restored_external_id.  Inferred edges and edges lacking such a provenance link
    stay on the canonical CI unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

from infra_twin.core_model import CI, Edge, EdgeSource, Evidence
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.reconciliation.projection import project


# ---------------------------------------------------------------------------
# Typed error hierarchy
# ---------------------------------------------------------------------------


class UnmergeError(Exception):
    """Base class for all un-merge errors."""


class MergeNotFoundError(UnmergeError):
    """The requested merge_id is not visible to this tenant (or does not exist)."""


class MergeAlreadyReversedError(UnmergeError):
    """A ci_unmerges row already exists for this original_merge_id."""


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnmergeOutcome:
    unmerge_id: UUID
    original_merge_id: UUID
    canonical_ci_id: UUID
    restored_ci_id: UUID
    restored_source: str
    restored_external_id: str
    evidence: str
    unmerged_at: datetime


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def unmerge(
    conn: psycopg.Connection,
    tenant_id: UUID,
    merge_id: UUID,
) -> UnmergeOutcome:
    """Reverse a single ci_merges row identified by merge_id.

    Operates on a connection already bound by ``tenant_session``; RLS scopes every
    statement automatically, so no explicit ``WHERE tenant_id`` filter is needed.

    Steps:
    1. Load the target merge row (RLS-filtered).
    2. Guard against double-reversal.
    3. Load the canonical CI.
    4. Insert a new distinct CI for the split-off source.
    5. Re-point source_keys (UPDATE, never DELETE).
    6. Re-point ci_alias_keys for the restored source (UPDATE, never DELETE).
    7. Re-point matching declared edges (bitemporal close+reopen, never hard-delete).
    8. Insert the ci_unmerges provenance row.
    9. Project to AGE.
    10. Return UnmergeOutcome.

    Raises MergeNotFoundError if the merge_id is unknown or the canonical CI is closed.
    Raises MergeAlreadyReversedError if a reversal row already exists.
    Raises UnmergeError on the defensive impossible case (restored_ci == canonical_ci).
    """

    # ------------------------------------------------------------------
    # Step 1: Load target merge (RLS guards cross-tenant access).
    # ------------------------------------------------------------------
    row = conn.execute(
        "SELECT canonical_ci_id, merged_source, merged_external_id, "
        "matched_alias_key, evidence "
        "FROM ci_merges WHERE merge_id = %s",
        (merge_id,),
    ).fetchone()

    if row is None:
        raise MergeNotFoundError(f"merge_id {merge_id} not found")

    canonical_ci_id: UUID = row[0]
    restored_source: str = row[1]
    restored_external_id: str = row[2]

    # ------------------------------------------------------------------
    # Step 2: Already-reversed guard. No writes if reversed.
    # ------------------------------------------------------------------
    already = conn.execute(
        "SELECT 1 FROM ci_unmerges WHERE original_merge_id = %s LIMIT 1",
        (merge_id,),
    ).fetchone()

    if already is not None:
        raise MergeAlreadyReversedError(
            f"merge_id {merge_id} has already been reversed"
        )

    # ------------------------------------------------------------------
    # Step 3: Load canonical CI.
    # ------------------------------------------------------------------
    ci_repo = CIRepository(conn, tenant_id)
    canonical = ci_repo.get_current_by_id(canonical_ci_id)
    if canonical is None:
        raise MergeNotFoundError(
            f"canonical CI {canonical_ci_id} is no longer open; cannot split"
        )
    canonical_type = canonical.type

    # ------------------------------------------------------------------
    # Step 4: Insert split-off CI with a fresh id.
    # Attributes are NOT fabricated: pass attributes={} and name=None.
    # The upsert keys on (type, external_id) so a distinct external_id
    # guarantees a distinct id; defensive assert catches any impossible collision.
    # ------------------------------------------------------------------
    split_ci = CI(
        tenant_id=tenant_id,
        type=canonical_type,
        external_id=restored_external_id,
        name=None,
        attributes={},
    )
    restored_ci = ci_repo.upsert(split_ci)
    restored_ci_id: UUID = restored_ci.id

    if restored_ci_id == canonical_ci_id:
        # Impossible by merge construction (merged_external_id != canonical.external_id),
        # but defensive guard in case of data anomaly.
        raise UnmergeError(
            f"restored_ci_id {restored_ci_id} equals canonical_ci_id; "
            "cannot split a CI into itself"
        )

    # ------------------------------------------------------------------
    # Step 5: Re-point source_keys (UPDATE, never DELETE).
    # ------------------------------------------------------------------
    conn.execute(
        "UPDATE source_keys "
        "SET ci_id = %s, observed_at = now() "
        "WHERE source = %s AND native_id = %s",
        (restored_ci_id, restored_source, restored_external_id),
    )

    # ------------------------------------------------------------------
    # Step 6: Re-point ci_alias_keys for the restored source (UPDATE, never DELETE).
    # Only rows contributed by the reversed source that still point at the canonical CI
    # are moved; alias-key rows from other sources remain on the canonical CI.
    # ------------------------------------------------------------------
    conn.execute(
        "UPDATE ci_alias_keys "
        "SET ci_id = %s, observed_at = now() "
        "WHERE ci_id = %s AND source = %s",
        (restored_ci_id, canonical_ci_id, restored_source),
    )

    # ------------------------------------------------------------------
    # Step 7: Re-point graph edges (bitemporal close+reopen, never hard-delete).
    #
    # Edge-repointing rule (deterministic, conservative — see module docstring):
    #   Re-point only DECLARED current edges (source == 'declared') attached to the
    #   canonical CI (from_id == canonical_ci_id OR to_id == canonical_ci_id) whose
    #   evidence provably originates from the restored source — i.e. at least one
    #   Evidence entry has source == restored_source, OR an Evidence.detail references
    #   restored_external_id.  Inferred edges and edges lacking such a provenance link
    #   stay on the canonical CI unchanged.
    # ------------------------------------------------------------------
    edge_repo = EdgeRepository(conn, tenant_id)

    # Collect all current edges; filter in Python on the rule.
    all_current_edges = edge_repo.get_current()

    def _provenance_matches(edge: Edge) -> bool:
        """Return True iff the edge's evidence provably originates from the restored source."""
        for ev in edge.evidence:
            if ev.source == restored_source:
                return True
            if ev.detail is not None and restored_external_id in ev.detail:
                return True
        return False

    def _is_repoint_candidate(edge: Edge) -> bool:
        if edge.source != EdgeSource.declared:
            return False
        if edge.from_id != canonical_ci_id and edge.to_id != canonical_ci_id:
            return False
        return _provenance_matches(edge)

    candidates = [e for e in all_current_edges if _is_repoint_candidate(e)]

    reopened_edges: list[Edge] = []
    closed_edges: list[Edge] = []

    for e in candidates:
        # Compute re-pointed endpoints.
        new_from = restored_ci_id if e.from_id == canonical_ci_id else e.from_id
        new_to = restored_ci_id if e.to_id == canonical_ci_id else e.to_id

        # Append unmerge provenance to the evidence list.
        repoint_evidence = Evidence(
            source="unmerge",
            detail=(
                f"re-pointed from {canonical_ci_id} to {restored_ci_id} "
                f"via unmerge of {merge_id}"
            ),
        )
        new_evidence = list(e.evidence) + [repoint_evidence]

        # Close the current edge (UPDATE valid_to; no DELETE).
        edge_repo.close(e.type, e.from_id, e.to_id, e.edge_key)
        closed_edges.append(e)

        # Reopen at re-pointed endpoints with all original metadata + provenance note.
        reopened = edge_repo.upsert(
            Edge(
                tenant_id=tenant_id,
                type=e.type,
                from_id=new_from,
                to_id=new_to,
                edge_key=e.edge_key,
                source=e.source,
                confidence=e.confidence,
                evidence=new_evidence,
            )
        )
        reopened_edges.append(reopened)

    # ------------------------------------------------------------------
    # Step 8: Record the reversal (append-only; non-empty evidence string).
    # The original ci_merges row is NOT mutated.
    # ------------------------------------------------------------------
    evidence_text = (
        f"un-merged {restored_source}:{restored_external_id} out of canonical "
        f"{canonical_ci_id} into {restored_ci_id} (reverses merge {merge_id})"
    )

    result_row = conn.execute(
        "INSERT INTO ci_unmerges "
        "    (tenant_id, original_merge_id, canonical_ci_id, restored_ci_id, "
        "     restored_source, restored_external_id, evidence) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s) "
        "RETURNING unmerge_id, unmerged_at",
        (
            tenant_id,
            merge_id,
            canonical_ci_id,
            restored_ci_id,
            restored_source,
            restored_external_id,
            evidence_text,
        ),
    ).fetchone()

    unmerge_id: UUID = result_row[0]
    unmerged_at: datetime = result_row[1]

    # ------------------------------------------------------------------
    # Step 9: Project to AGE.
    # New restored CI node + re-pointed edges into the graph.
    # Canonical CI node is unchanged; closed edges are removed.
    # ------------------------------------------------------------------
    project(
        conn,
        current_cis=[restored_ci],
        current_edges=reopened_edges,
        closed_cis=[],
        closed_edges=closed_edges,
    )

    # ------------------------------------------------------------------
    # Step 10: Return outcome.
    # ------------------------------------------------------------------
    return UnmergeOutcome(
        unmerge_id=unmerge_id,
        original_merge_id=merge_id,
        canonical_ci_id=canonical_ci_id,
        restored_ci_id=restored_ci_id,
        restored_source=restored_source,
        restored_external_id=restored_external_id,
        evidence=evidence_text,
        unmerged_at=unmerged_at,
    )
