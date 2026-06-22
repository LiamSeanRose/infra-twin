"""Probabilistic / fuzzy entity-resolution candidate engine (plan §24.1).

Generates confidence-scored, evidence-backed merge SUGGESTIONS for same-type CIs from
different sources that the deterministic engine deliberately did NOT merge.  Persists
candidates append-only in ci_merge_candidates.  Candidates are surfaced for human review
only; no auto-merge ever occurs from this module.

NEVER A SILENT AUTO-MERGE: generate_candidates writes ONLY ci_merge_candidates.
It must not mutate cis, edges, source_keys, ci_alias_keys, or write ci_merges rows.

Accept goes through the existing deterministic merge provenance path (_record_merge),
so the resulting merge is viewable via GET /merges and reversible via unmerge().
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

from infra_twin.core_model import CI, CIType, Edge, EdgeSource, Evidence
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.reconciliation.projection import project
from infra_twin.reconciliation.reconcile import (
    _bind_source_key,
    _record_merge,
    _register_alias_keys,
)

# ---------------------------------------------------------------------------
# Constants (documented)
# ---------------------------------------------------------------------------

# Inclusive lower bound for emitting a candidate row.  Pairs scoring below this
# threshold are NOT written to ci_merge_candidates.
CANDIDATE_THRESHOLD: float = 0.5

# Source label used when creating synthetic source_keys bindings so that unmerge
# can reverse an accepted fuzzy candidate even when the merged CI had no real
# source_key row before acceptance.
GENERATION_SOURCE: str = "fuzzy-candidate"


# ---------------------------------------------------------------------------
# Typed surface
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MergeCandidate:
    candidate_id: UUID
    tenant_id: UUID
    ci_id_a: UUID
    ci_id_b: UUID
    ci_type: str
    confidence: float
    evidence: str
    status: str  # 'pending' | 'accepted' | 'dismissed'
    resolved_merge_id: UUID | None
    generated_at: datetime
    resolved_at: datetime | None


@dataclass(frozen=True)
class AcceptOutcome:
    candidate_id: UUID
    merge_id: UUID  # the new ci_merges row
    canonical_ci_id: UUID  # surviving CI
    merged_ci_id: UUID  # closed CI
    merged_source: str
    merged_external_id: str
    confidence: float
    evidence: str
    resolved_at: datetime


# ---------------------------------------------------------------------------
# Typed error hierarchy (mirrors unmerge.py)
# ---------------------------------------------------------------------------


class CandidateError(Exception):
    """Base class for all candidate errors."""


class CandidateNotFoundError(CandidateError):
    """The requested candidate_id is not visible to this tenant (or does not exist)."""


class CandidateAlreadyResolvedError(CandidateError):
    """The candidate has already been accepted or dismissed."""


# ---------------------------------------------------------------------------
# Internal scoring helpers
# ---------------------------------------------------------------------------

_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)


def _normalize(s: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    s = s.lower()
    s = _PUNCT_RE.sub("", s)
    s = " ".join(s.split())
    return s


def _token_set(s: str) -> set[str]:
    return set(s.split())


def _jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity of two token sets."""
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _name_score(x: CI, y: CI) -> tuple[float, str]:
    """Signal: normalized name similarity.

    Exact normalized equality -> 1.0.
    Otherwise token-set Jaccard of normalized names.
    Either name absent -> 0.
    Returns (score, description).
    """
    if not x.name or not y.name:
        return 0.0, ""
    nx = _normalize(x.name)
    ny = _normalize(y.name)
    if not nx or not ny:
        return 0.0, ""
    if nx == ny:
        return 1.0, f"exact normalized name '{nx}'"
    j = _jaccard(_token_set(nx), _token_set(ny))
    if j <= 0:
        return 0.0, ""
    return j, f"normalized name jaccard({nx!r},{ny!r})={j:.2f}"


def _dns_score(x: CI, y: CI) -> tuple[float, str]:
    """Signal: DNS/hostname similarity.

    Checks attributes keys dns_name, hostname, fqdn, private_dns.
    Exact match on any shared key -> 1.0.
    Otherwise Jaccard across all present values (normalized).
    Returns (score, description).
    """
    dns_keys = ("dns_name", "hostname", "fqdn", "private_dns")
    x_vals = [_normalize(str(x.attributes[k])) for k in dns_keys if x.attributes.get(k)]
    y_vals = [_normalize(str(y.attributes[k])) for k in dns_keys if y.attributes.get(k)]
    if not x_vals or not y_vals:
        return 0.0, ""

    # Check for any exact value overlap first.
    x_set = set(x_vals)
    y_set = set(y_vals)
    shared = x_set & y_set
    if shared:
        val = next(iter(shared))
        return 1.0, f"exact dns/hostname match '{val}'"

    # Jaccard over token sets of all values.
    x_tokens = _token_set(" ".join(x_vals))
    y_tokens = _token_set(" ".join(y_vals))
    j = _jaccard(x_tokens, y_tokens)
    if j <= 0:
        return 0.0, ""
    return j, f"dns/hostname token jaccard={j:.2f}"


def _ip_score(x: CI, y: CI) -> tuple[float, str]:
    """Signal: shared IP address.

    Any shared non-empty value among private_ip, public_ip, ip -> 0.9.
    """
    ip_keys = ("private_ip", "public_ip", "ip")
    x_ips = {str(x.attributes[k]) for k in ip_keys if x.attributes.get(k)}
    y_ips = {str(y.attributes[k]) for k in ip_keys if y.attributes.get(k)}
    shared = x_ips & y_ips
    if shared:
        ip = next(iter(shared))
        return 0.9, f"shared ip={ip!r}"
    return 0.0, ""


def _alias_overlap_score(
    x_alias_keys: set[str], y_alias_keys: set[str]
) -> tuple[float, str]:
    """Signal: partial alias-key overlap (NOT exact full-key match).

    Token-level overlap between the two CIs' alias-key sets where no key is a
    full exact match between the two sets.  Scaled by overlap ratio, capped at 0.8.
    Exact full-key matches are handled by the deterministic engine so we exclude them.
    """
    # Exclude any key that appears in both sets (that would be deterministic domain).
    exact_shared = x_alias_keys & y_alias_keys
    if exact_shared:
        # Exact overlap: deterministic engine's domain -> not a fuzzy signal.
        return 0.0, ""

    # Compute token overlap across all alias keys.
    x_tokens = _token_set(" ".join(x_alias_keys))
    y_tokens = _token_set(" ".join(y_alias_keys))
    if not x_tokens or not y_tokens:
        return 0.0, ""

    j = _jaccard(x_tokens, y_tokens)
    if j <= 0:
        return 0.0, ""
    score = min(j, 0.8)
    return score, f"partial alias-key token overlap={j:.2f} (capped at 0.8)"


def _score_pair(
    x: CI,
    y: CI,
    x_alias_keys: set[str],
    y_alias_keys: set[str],
) -> tuple[float, str]:
    """Compute aggregate confidence and evidence for a pair.

    Score = max over all signal scores (each clamped to [0,1]).
    Evidence lists every signal that contributed > 0.
    """
    signals: list[tuple[float, str]] = [
        _name_score(x, y),
        _dns_score(x, y),
        _ip_score(x, y),
        _alias_overlap_score(x_alias_keys, y_alias_keys),
    ]

    max_score = 0.0
    descriptions: list[str] = []
    for score, desc in signals:
        score = max(0.0, min(1.0, score))  # clamp to [0,1]
        if score > 0 and desc:
            descriptions.append(desc)
        if score > max_score:
            max_score = score

    if not descriptions:
        evidence = "no signal"
    else:
        evidence = "probable match: " + "; ".join(descriptions)

    return max_score, evidence


# ---------------------------------------------------------------------------
# Row converter
# ---------------------------------------------------------------------------


def _row_to_candidate(row: tuple) -> MergeCandidate:
    return MergeCandidate(
        candidate_id=row[0],
        tenant_id=row[1],
        ci_id_a=row[2],
        ci_id_b=row[3],
        ci_type=row[4],
        confidence=row[5],
        evidence=row[6],
        status=row[7],
        resolved_merge_id=row[8],
        generated_at=row[9],
        resolved_at=row[10],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_candidates(
    conn: psycopg.Connection, tenant_id: UUID
) -> list[MergeCandidate]:
    """Generate confidence-scored fuzzy merge candidates for the tenant.

    Writes ONLY ci_merge_candidates — never cis, edges, source_keys,
    ci_alias_keys, or ci_merges.

    Algorithm:
    1. Load all current open CIs grouped by type.
    2. Load source_keys and ci_alias_keys for cross-source and alias-key filters.
    3. For each same-type unordered pair (x, y):
       - Skip same id, already-fused, same-single-source, or exact-alias-key pairs.
       - Score with documented signals.
       - Skip if confidence < CANDIDATE_THRESHOLD.
    4. Upsert qualifying pairs (ON CONFLICT refreshes pending rows; never reopens resolved).
    5. Return generated/refreshed candidates newest-first.
    """
    ci_repo = CIRepository(conn, tenant_id)

    # --- Load all current open CIs grouped by type ---
    all_cis = ci_repo.get_current()  # type=None -> all types
    by_type: dict[str, list[CI]] = {}
    for ci in all_cis:
        type_str = ci.type.value
        by_type.setdefault(type_str, []).append(ci)

    # --- Load source_keys: ci_id -> set of (source, native_id) ---
    # RLS scopes this automatically via tenant_session.
    sk_rows = conn.execute(
        "SELECT ci_id, source, native_id FROM source_keys"
    ).fetchall()
    ci_sources: dict[UUID, set[str]] = {}  # ci_id -> set of source strings
    ci_native_ids: dict[UUID, set[str]] = {}  # ci_id -> set of native_ids
    for ci_id, source, native_id in sk_rows:
        ci_sources.setdefault(ci_id, set()).add(source)
        ci_native_ids.setdefault(ci_id, set()).add(native_id)

    # --- Load ci_alias_keys: ci_id -> set of alias_keys ---
    ak_rows = conn.execute(
        "SELECT ci_id, alias_key FROM ci_alias_keys"
    ).fetchall()
    ci_alias_key_map: dict[UUID, set[str]] = {}
    for ci_id, alias_key in ak_rows:
        ci_alias_key_map.setdefault(ci_id, set()).add(alias_key)

    # Collect candidate rows to upsert.
    results: list[MergeCandidate] = []

    for type_str, cis in by_type.items():
        n = len(cis)
        for i in range(n):
            for j in range(i + 1, n):
                x = cis[i]
                y = cis[j]

                # Skip same id (should not happen; defensive guard).
                if x.id == y.id:
                    continue

                # Skip if NOT cross-source: both must have at least one source
                # that the other lacks (disjoint-enough source sets).
                x_srcs = ci_sources.get(x.id, set())
                y_srcs = ci_sources.get(y.id, set())
                # Require at least one source in x not in y AND at least one in y not in x.
                if not (x_srcs - y_srcs) or not (y_srcs - x_srcs):
                    continue

                # Skip if the deterministic engine WOULD have merged them:
                # any shared exact alias key means they are not the ambiguous tail.
                x_aliases = ci_alias_key_map.get(x.id, set())
                y_aliases = ci_alias_key_map.get(y.id, set())
                if x_aliases & y_aliases:
                    continue

                # Score the pair.
                confidence, evidence = _score_pair(x, y, x_aliases, y_aliases)

                # Skip below threshold.
                if confidence < CANDIDATE_THRESHOLD:
                    continue

                # Canonicalize order: ci_id_a < ci_id_b.
                ci_id_a, ci_id_b = sorted((x.id, y.id))

                # Upsert into ci_merge_candidates.
                # ON CONFLICT refreshes pending rows; resolved rows are NOT reopened.
                row = conn.execute(
                    "INSERT INTO ci_merge_candidates "
                    "    (tenant_id, ci_id_a, ci_id_b, ci_type, confidence, evidence, status) "
                    "VALUES (%s, %s, %s, %s, %s, %s, 'pending') "
                    "ON CONFLICT (tenant_id, ci_id_a, ci_id_b) DO UPDATE "
                    "    SET confidence = EXCLUDED.confidence, "
                    "        evidence   = EXCLUDED.evidence, "
                    "        generated_at = now() "
                    "    WHERE ci_merge_candidates.status = 'pending' "
                    "RETURNING candidate_id, tenant_id, ci_id_a, ci_id_b, ci_type, confidence, "
                    "          evidence, status, resolved_merge_id, generated_at, resolved_at",
                    (tenant_id, ci_id_a, ci_id_b, type_str, confidence, evidence),
                ).fetchone()

                # When the conflicting row is already resolved, RETURNING yields no row.
                if row is not None:
                    results.append(_row_to_candidate(row))

    # Sort newest-first by generated_at DESC, candidate_id DESC for determinism.
    results.sort(key=lambda c: (c.generated_at, c.candidate_id), reverse=True)
    return results


def accept_candidate(
    conn: psycopg.Connection,
    tenant_id: UUID,
    candidate_id: UUID,
) -> AcceptOutcome:
    """Accept a pending fuzzy merge candidate, fusing two CIs via the reversible path.

    Steps:
    1. Load candidate; raise CandidateNotFoundError (404) or CandidateAlreadyResolvedError (409).
    2. Load both CIs; stale CI (already closed) -> CandidateNotFoundError.
    3. Choose canonical vs merged deterministically (lex smaller external_id; tie-break id).
    4. Determine merged_source + merged_external_id for reversibility from source_keys.
    5. Re-point source_keys and ci_alias_keys bindings to canonical (UPDATE, never DELETE).
    6. Re-point declared current edges (bitemporal close+reopen).
    7. Close merged CI bitemporally.
    8. Write ci_merges row via _record_merge.
    9. Resolve candidate (UPDATE status='accepted').
    10. Project to AGE.
    11. Return AcceptOutcome.
    """
    # ------------------------------------------------------------------
    # Step 1: Load candidate.
    # ------------------------------------------------------------------
    row = conn.execute(
        "SELECT candidate_id, tenant_id, ci_id_a, ci_id_b, ci_type, confidence, "
        "evidence, status, resolved_merge_id, generated_at, resolved_at "
        "FROM ci_merge_candidates WHERE candidate_id = %s",
        (candidate_id,),
    ).fetchone()

    if row is None:
        raise CandidateNotFoundError(f"candidate {candidate_id} not found")

    candidate = _row_to_candidate(row)

    if candidate.status != "pending":
        raise CandidateAlreadyResolvedError(
            f"candidate {candidate_id} is already {candidate.status}"
        )

    # ------------------------------------------------------------------
    # Step 2: Load both CIs. Stale (already closed) -> CandidateNotFoundError.
    # ------------------------------------------------------------------
    ci_repo = CIRepository(conn, tenant_id)
    ci_a = ci_repo.get_current_by_id(candidate.ci_id_a)
    ci_b = ci_repo.get_current_by_id(candidate.ci_id_b)

    if ci_a is None or ci_b is None:
        raise CandidateNotFoundError(
            f"one or both CIs for candidate {candidate_id} are no longer open"
        )

    # ------------------------------------------------------------------
    # Step 3: Choose canonical vs merged deterministically.
    # Canonical = CI with lexicographically smaller external_id; tie-break: smaller id.
    # ------------------------------------------------------------------
    if ci_a.external_id < ci_b.external_id:
        canonical_ci = ci_a
        merged_ci = ci_b
    elif ci_b.external_id < ci_a.external_id:
        canonical_ci = ci_b
        merged_ci = ci_a
    else:
        # Tie-break on id.
        if str(ci_a.id) <= str(ci_b.id):
            canonical_ci = ci_a
            merged_ci = ci_b
        else:
            canonical_ci = ci_b
            merged_ci = ci_a

    canonical_id: UUID = canonical_ci.id
    merged_id: UUID = merged_ci.id

    # ------------------------------------------------------------------
    # Step 4: Determine merged_source + merged_external_id for reversibility.
    # Pick smallest (source, native_id) from source_keys for merged_id.
    # Fallback: use GENERATION_SOURCE and bind it.
    # ------------------------------------------------------------------
    sk_row = conn.execute(
        "SELECT source, native_id FROM source_keys WHERE ci_id = %s "
        "ORDER BY source ASC, native_id ASC LIMIT 1",
        (merged_id,),
    ).fetchone()

    if sk_row is not None:
        merged_source: str = sk_row[0]
        merged_external_id: str = sk_row[1]
    else:
        # No source_keys row: synthesize one so unmerge can reverse.
        merged_source = GENERATION_SOURCE
        merged_external_id = merged_ci.external_id
        _bind_source_key(conn, tenant_id, merged_source, merged_external_id, merged_id)

    # Defensive guard: merged_external_id must differ from canonical.external_id.
    if merged_external_id == canonical_ci.external_id:
        raise CandidateError(
            f"merged_external_id {merged_external_id!r} equals canonical external_id; "
            "cannot accept this candidate (ambiguous identity)"
        )

    # ------------------------------------------------------------------
    # Step 5: Re-point source_keys and ci_alias_keys to canonical (UPDATE, never DELETE).
    # ------------------------------------------------------------------
    conn.execute(
        "UPDATE source_keys SET ci_id = %s, observed_at = now() WHERE ci_id = %s",
        (canonical_id, merged_id),
    )
    conn.execute(
        "UPDATE ci_alias_keys SET ci_id = %s, observed_at = now() WHERE ci_id = %s",
        (canonical_id, merged_id),
    )

    # ------------------------------------------------------------------
    # Step 6: Re-point declared current edges (bitemporal close+reopen).
    # Mirror the edge-repointing pattern from unmerge.py step 7.
    # Skip self-edges that would collapse to from == to after repointing.
    # ------------------------------------------------------------------
    edge_repo = EdgeRepository(conn, tenant_id)
    all_current_edges = edge_repo.get_current()

    def _is_repoint_candidate(edge: Edge) -> bool:
        """Re-point declared edges attached to merged_id."""
        if edge.source != EdgeSource.declared:
            return False
        return edge.from_id == merged_id or edge.to_id == merged_id

    repoint_candidates = [e for e in all_current_edges if _is_repoint_candidate(e)]

    closed_edges: list[Edge] = []
    reopened_edges: list[Edge] = []

    for e in repoint_candidates:
        new_from = canonical_id if e.from_id == merged_id else e.from_id
        new_to = canonical_id if e.to_id == merged_id else e.to_id

        # Skip self-edges that collapse (from == to).
        if new_from == new_to:
            continue

        repoint_evidence = Evidence(
            source="merge-candidate",
            detail=(
                f"re-pointed from merged CI {merged_id} to canonical CI {canonical_id} "
                f"via accepted fuzzy candidate {candidate_id}"
            ),
        )
        new_evidence = list(e.evidence) + [repoint_evidence]

        edge_repo.close(e.type, e.from_id, e.to_id, e.edge_key)
        closed_edges.append(e)

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
    # Step 7: Close merged CI bitemporally (valid_to set, never deleted).
    # ------------------------------------------------------------------
    ci_repo.close(merged_ci.type, merged_ci.external_id)

    # ------------------------------------------------------------------
    # Step 8: Write ci_merges row via existing writer (_record_merge).
    # matched_alias_key encodes the candidate id for traceability.
    # evidence is self-describing.
    # ------------------------------------------------------------------
    matched_alias_key = f"fuzzy-candidate:{candidate_id}"
    merge_evidence = (
        f"accepted fuzzy candidate {candidate_id} "
        f"(confidence={candidate.confidence}): {candidate.evidence}"
    )
    _record_merge(
        conn,
        tenant_id,
        canonical_id,
        merged_source,
        merged_external_id,
        matched_alias_key,
        merge_evidence,
    )

    # Recover merge_id by re-selecting the row just written.
    merge_row = conn.execute(
        "SELECT merge_id FROM ci_merges "
        "WHERE canonical_ci_id = %s AND merged_source = %s "
        "  AND merged_external_id = %s AND matched_alias_key = %s "
        "ORDER BY merged_at DESC, merge_id DESC LIMIT 1",
        (canonical_id, merged_source, merged_external_id, matched_alias_key),
    ).fetchone()

    if merge_row is None:
        raise CandidateError("ci_merges row not found immediately after _record_merge; data anomaly")

    merge_id: UUID = merge_row[0]

    # ------------------------------------------------------------------
    # Step 9: Resolve the candidate (UPDATE, not delete).
    # WHERE status='pending' guards against lost races -> rowcount==0 -> 409.
    # ------------------------------------------------------------------
    resolved_row = conn.execute(
        "UPDATE ci_merge_candidates "
        "SET status = 'accepted', resolved_merge_id = %s, resolved_at = now() "
        "WHERE candidate_id = %s AND status = 'pending' "
        "RETURNING resolved_at",
        (merge_id, candidate_id),
    ).fetchone()

    if resolved_row is None:
        raise CandidateAlreadyResolvedError(
            f"candidate {candidate_id} was resolved by a concurrent request"
        )

    resolved_at: datetime = resolved_row[0]

    # ------------------------------------------------------------------
    # Step 10: Project to AGE.
    # canonical CI stays open; merged CI is now closed; edges re-pointed.
    # ------------------------------------------------------------------
    project(
        conn,
        current_cis=[canonical_ci],
        current_edges=reopened_edges,
        closed_cis=[merged_ci],
        closed_edges=closed_edges,
    )

    # ------------------------------------------------------------------
    # Step 11: Return AcceptOutcome.
    # ------------------------------------------------------------------
    return AcceptOutcome(
        candidate_id=candidate_id,
        merge_id=merge_id,
        canonical_ci_id=canonical_id,
        merged_ci_id=merged_id,
        merged_source=merged_source,
        merged_external_id=merged_external_id,
        confidence=candidate.confidence,
        evidence=merge_evidence,
        resolved_at=resolved_at,
    )


def dismiss_candidate(
    conn: psycopg.Connection,
    tenant_id: UUID,
    candidate_id: UUID,
) -> MergeCandidate:
    """Dismiss a pending fuzzy merge candidate.

    Sets status='dismissed' and resolved_at; leaves graph unchanged.
    Graph (cis, edges, source_keys, ci_alias_keys, AGE, ci_merges) is NOT touched.

    Raises CandidateNotFoundError (404) if not found.
    Raises CandidateAlreadyResolvedError (409) if already resolved.
    """
    # Step 1: Load candidate.
    row = conn.execute(
        "SELECT candidate_id, tenant_id, ci_id_a, ci_id_b, ci_type, confidence, "
        "evidence, status, resolved_merge_id, generated_at, resolved_at "
        "FROM ci_merge_candidates WHERE candidate_id = %s",
        (candidate_id,),
    ).fetchone()

    if row is None:
        raise CandidateNotFoundError(f"candidate {candidate_id} not found")

    candidate = _row_to_candidate(row)

    if candidate.status != "pending":
        raise CandidateAlreadyResolvedError(
            f"candidate {candidate_id} is already {candidate.status}"
        )

    # Step 2: Dismiss (UPDATE, WHERE status='pending' guards races).
    resolved_row = conn.execute(
        "UPDATE ci_merge_candidates "
        "SET status = 'dismissed', resolved_at = now() "
        "WHERE candidate_id = %s AND status = 'pending' "
        "RETURNING candidate_id, tenant_id, ci_id_a, ci_id_b, ci_type, confidence, "
        "          evidence, status, resolved_merge_id, generated_at, resolved_at",
        (candidate_id,),
    ).fetchone()

    if resolved_row is None:
        raise CandidateAlreadyResolvedError(
            f"candidate {candidate_id} was resolved by a concurrent request"
        )

    return _row_to_candidate(resolved_row)
