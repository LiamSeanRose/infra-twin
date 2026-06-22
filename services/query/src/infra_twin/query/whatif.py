"""What-if topology-based impact estimation.

Given a proposed change to a single CI and a whitelisted change kind, computes the set of
CIs that would be impacted over the existing current-state edge graph, each with a confidence
score and an evidence path.

This is topology-based impact estimation, NOT behavioral simulation. It estimates which
configuration items depend on the target over the current dependency graph. It does not
model runtime behavior, capacity, or timing.

Impact direction mirrors blast_radius semantics exactly:
  - OUTGOING_IMPACT (CONTAINS): walk (target)-[CONTAINS]->(child); a container change
    impacts what it contains.
  - INCOMING_IMPACT (DEPENDS_ON, RUNS_ON, ROUTES_TO, EXPOSES): walk (target)<-[r]-(dependent);
    things that depend on / run on / route to / are exposed-via the target are impacted.

Confidence derivation:
  base_path_confidence = product(hop.confidence for hop in evidence_path)
  remove:  confidence = base_path_confidence
  modify:  confidence = base_path_confidence * MODIFY_CONFIDENCE_FACTOR (= 0.5)

The change kind affects ONLY computed confidence, never stored state. This module is
PURE/READ-ONLY: it never executes any INSERT/UPDATE/DELETE, never closes or opens any CI/edge
row, never calls any reconciliation/apply path, and never mutates the AGE graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

import psycopg

from infra_twin.db.graph import cypher
from infra_twin.query.blast_radius import (
    INCOMING_IMPACT,
    OUTGOING_IMPACT,
    Supernode,
    _scalar,
)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

WHATIF_CHANGE_KINDS: frozenset[str] = frozenset({"remove", "modify"})
WHATIF_METHOD: str = "topology_impact_estimation"
MODIFY_CONFIDENCE_FACTOR: float = 0.5
WHATIF_DISCLAIMER: str = (
    "Topology-based impact estimation, not behavioral simulation: this estimates which "
    "configuration items depend on the target over the current dependency graph. It does "
    "not model runtime behavior, capacity, or timing."
)


# ---------------------------------------------------------------------------
# Typed error
# ---------------------------------------------------------------------------


class UnknownChangeKindError(ValueError):
    """Raised when a what-if change kind is not in WHATIF_CHANGE_KINDS."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class WhatIfEdgeHop:
    from_id: UUID          # source endpoint CI id of this edge (toward target)
    to_id: UUID            # destination endpoint CI id of this edge
    edge_type: str         # the AGE relationship type, e.g. "DEPENDS_ON"
    source: str            # edge provenance: "declared" | "inferred"
    confidence: float      # the edge's own confidence (0.0–1.0), from the relational edges row


@dataclass
class ImpactedCI:                       # distinct from blast_radius.ImpactedCI (lives here)
    id: UUID
    type: str
    external_id: str
    name: str | None
    distance: int          # hops from target (>= 1)
    confidence: float      # DERIVED path confidence (0.0–1.0); product of per-hop confidences
    evidence: list[WhatIfEdgeHop]   # ordered target -> ... -> impacted; len == distance


@dataclass
class WhatIfImpact:
    target_id: UUID
    change_kind: str               # echoes the validated change kind ("remove" | "modify")
    method: str                    # ALWAYS the literal WHATIF_METHOD
    disclaimer: str                # ALWAYS WHATIF_DISCLAIMER
    max_depth: int
    impacted: list[ImpactedCI] = field(default_factory=list)
    truncated_supernodes: list[Supernode] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _impact_neighbors_with_type(
    conn: psycopg.Connection,
    tenant_id: UUID,
    ci_id: str,
    min_confidence: float,
) -> list[tuple[str, str]]:
    """Return (neighbor_ci_id, edge_type) pairs for impact-direction neighbors of ci_id.

    Direction semantics mirror blast_radius._impact_neighbors:
      OUTGOING_IMPACT (CONTAINS): walk (ci_id)-[r]->(b); child is impacted.
      INCOMING_IMPACT (DEPENDS_ON, ...): walk (ci_id)<-[r]-(b); dependent is impacted.
    """
    tenant = str(tenant_id)
    conf = float(min_confidence)
    out_types = ", ".join(f"'{t}'" for t in OUTGOING_IMPACT)
    in_types = ", ".join(f"'{t}'" for t in INCOMING_IMPACT)

    out_rows = cypher(
        conn,
        f"MATCH (a {{ci_id: '{ci_id}'}})-[r]->(b) "
        f"WHERE type(r) IN [{out_types}] AND r.tenant_id = '{tenant}' "
        f"AND r.confidence >= {conf} RETURN b.ci_id, type(r)",
        "(ci_id agtype, etype agtype)",
    )
    in_rows = cypher(
        conn,
        f"MATCH (a {{ci_id: '{ci_id}'}})<-[r]-(b) "
        f"WHERE type(r) IN [{in_types}] AND r.tenant_id = '{tenant}' "
        f"AND r.confidence >= {conf} RETURN b.ci_id, type(r)",
        "(ci_id agtype, etype agtype)",
    )
    result: list[tuple[str, str]] = []
    for row in out_rows:
        result.append((_scalar(row[0]), _scalar(row[1])))
    for row in in_rows:
        result.append((_scalar(row[0]), _scalar(row[1])))
    return result


# ---------------------------------------------------------------------------
# Engine entrypoint
# ---------------------------------------------------------------------------


def what_if_impact(
    conn: psycopg.Connection,
    tenant_id: UUID,
    ci_id: UUID,
    *,
    change_kind: str,
    max_depth: int = 4,
    min_confidence: float = 0.0,
    max_fanout: int = 1000,
) -> WhatIfImpact:
    """Compute the topology-based impact of a proposed change to ci_id.

    Raises UnknownChangeKindError immediately (before any DB read) if change_kind is not
    in WHATIF_CHANGE_KINDS.

    The function is PURE/READ-ONLY: it executes only SELECT and read-only cypher MATCH
    queries. It never modifies cis, edges, or the AGE graph.

    Parameters
    ----------
    conn:
        A psycopg connection already bound to a tenant_session (RLS-scoped).
    tenant_id:
        The owning tenant UUID.
    ci_id:
        The target CI whose hypothetical change is being simulated.
    change_kind:
        One of WHATIF_CHANGE_KINDS ("remove" | "modify"). Validated before any DB read.
    max_depth:
        Maximum BFS depth (hops from target). Default 4, matching blast_radius.
    min_confidence:
        Minimum edge confidence to traverse. Default 0.0.
    max_fanout:
        Maximum deduped neighbor count before a node is recorded as a supernode and
        expansion is truncated. Default 1000, matching blast_radius.
    """
    if change_kind not in WHATIF_CHANGE_KINDS:
        raise UnknownChangeKindError(
            f"change_kind {change_kind!r} is not valid; must be one of {sorted(WHATIF_CHANGE_KINDS)}"
        )

    target = str(ci_id)
    # visited maps ci_id_str -> first-discovery depth (target at depth 0)
    visited: dict[str, int] = {target: 0}
    # predecessor maps ci_id_str -> (predecessor_ci_id_str, edge_type)
    # recorded on first discovery of each node; used for evidence-path reconstruction
    predecessor: dict[str, tuple[str, str]] = {}
    frontier = [target]
    discovered: list[tuple[str, int]] = []  # (ci_id_str, depth)
    supernodes: list[Supernode] = []

    for depth in range(1, max_depth + 1):
        next_frontier: list[str] = []
        for node in frontier:
            raw_neighbors = _impact_neighbors_with_type(conn, tenant_id, node, min_confidence)
            # Deduplicate by neighbor id, preserving first-occurrence order for stable BFS.
            seen: dict[str, str] = {}
            for neighbor_id, edge_type in raw_neighbors:
                if neighbor_id not in seen:
                    seen[neighbor_id] = edge_type
            neighbor_pairs = list(seen.items())  # [(ci_id, edge_type), ...]

            if len(neighbor_pairs) > max_fanout:
                supernodes.append(Supernode(UUID(node), len(neighbor_pairs), visited[node]))
                neighbor_pairs = neighbor_pairs[:max_fanout]

            for neighbor, edge_type in neighbor_pairs:
                if neighbor not in visited:
                    visited[neighbor] = depth
                    predecessor[neighbor] = (node, edge_type)
                    next_frontier.append(neighbor)
                    discovered.append((neighbor, depth))

        frontier = next_frontier
        if not frontier:
            break

    result = WhatIfImpact(
        target_id=ci_id,
        change_kind=change_kind,
        method=WHATIF_METHOD,
        disclaimer=WHATIF_DISCLAIMER,
        max_depth=max_depth,
        truncated_supernodes=supernodes,
    )

    if not discovered:
        return result

    # Resolve discovered CI ids against cis (RLS-scoped) for current type/external_id/name.
    # Only currently-present CIs in this tenant become ImpactedCI entries; closed/dangling/
    # cross-tenant ids are dropped (identical to blast_radius's details filter).
    ids = [UUID(node) for node, _ in discovered]
    ci_rows = conn.execute(
        "SELECT id, type, external_id, name FROM cis WHERE id = ANY(%s) AND valid_to IS NULL",
        (ids,),
    ).fetchall()
    ci_details: dict[str, tuple[str, str, str | None]] = {
        str(r[0]): (r[1], r[2], r[3]) for r in ci_rows
    }

    # Collect pending items for path reconstruction and evidence fetching.
    # Each entry: (node_str, distance, hops)
    # Each hop: (edge_type, from_id_str, to_id_str)
    # Direction: target -> ... -> impacted (the path from target to the impacted node)
    # predecessor[node] = (pred_node, edge_type) where pred_node is closer to target.
    # So to walk target -> impacted: reconstruct backward from node to target, then reverse.
    items_pending: list[tuple[str, int, list[tuple[str, str, str]]]] = []

    for node, distance in discovered:
        if ci_details.get(node) is None:
            continue  # not a current CI in this tenant

        # Reconstruct path from target to this impacted node.
        # Walk backward via predecessor chain, collecting hops in reverse order.
        hops_reversed: list[tuple[str, str, str]] = []  # (edge_type, from_str, to_str)
        cur = node
        while cur in predecessor:
            pred_node, edge_type = predecessor[cur]
            # The edge goes from pred_node toward target when going backward,
            # but in the impact direction (target -> impacted) the edge goes
            # from pred_node toward cur. So from_id=pred_node, to_id=cur.
            hops_reversed.append((edge_type, pred_node, cur))
            cur = pred_node
        # hops_reversed is [impacted_end, ..., near_target_end]; reverse to get target -> impacted.
        hops = list(reversed(hops_reversed))
        # hops[0] = (edge_type, target_or_near_target, next_node)
        # hops[-1] = (edge_type, node_before_impacted, impacted_node)
        items_pending.append((node, distance, hops))

    if not items_pending:
        return result

    # Batch-fetch per-hop provenance (source, confidence) from the relational edges table.
    # Query: WHERE (type, from_id, to_id) IN (...) AND valid_to IS NULL
    all_hop_keys: list[tuple[str, str, str]] = []
    for _, _, hops in items_pending:
        all_hop_keys.extend(hops)

    unique_keys = list(dict.fromkeys(all_hop_keys))

    # Map (edge_type, from_id_str, to_id_str) -> (source, confidence)
    edge_prov_map: dict[tuple[str, str, str], tuple[str, float]] = {}
    if unique_keys:
        type_vals = [k[0] for k in unique_keys]
        from_vals = [UUID(k[1]) for k in unique_keys]
        to_vals = [UUID(k[2]) for k in unique_keys]

        edge_rows = conn.execute(
            "SELECT type, from_id, to_id, source, confidence FROM edges "
            "WHERE (type, from_id, to_id) IN (SELECT * FROM unnest(%s::text[], %s::uuid[], %s::uuid[])) "
            "AND valid_to IS NULL",
            (type_vals, from_vals, to_vals),
        ).fetchall()

        for er in edge_rows:
            key = (er[0], str(er[1]), str(er[2]))
            edge_prov_map[key] = (er[3], float(er[4]))

    # Assemble ImpactedCI objects.
    _DEFAULT_SOURCE = "declared"
    _DEFAULT_CONFIDENCE = 1.0

    for node, distance, hops in items_pending:
        ci_detail = ci_details[node]
        ci_type = ci_detail[0]
        ci_external_id = ci_detail[1]
        ci_name = ci_detail[2]

        # Build the evidence chain and compute path confidence.
        evidence_hops: list[WhatIfEdgeHop] = []
        path_confidence = 1.0

        for edge_type, from_str, to_str in hops:
            prov = edge_prov_map.get((edge_type, from_str, to_str))
            if prov is not None:
                hop_source, hop_confidence = prov
            else:
                # Dangling/closed edge: use safe defaults (§4.3).
                hop_source = _DEFAULT_SOURCE
                hop_confidence = _DEFAULT_CONFIDENCE

            path_confidence *= hop_confidence
            evidence_hops.append(WhatIfEdgeHop(
                from_id=UUID(from_str),
                to_id=UUID(to_str),
                edge_type=edge_type,
                source=hop_source,
                confidence=hop_confidence,
            ))

        # Apply change-kind factor (§4.3).
        if change_kind == "modify":
            derived_confidence = path_confidence * MODIFY_CONFIDENCE_FACTOR
        else:
            # "remove"
            derived_confidence = path_confidence

        result.impacted.append(ImpactedCI(
            id=UUID(node),
            type=ci_type,
            external_id=ci_external_id,
            name=ci_name,
            distance=distance,
            confidence=derived_confidence,
            evidence=evidence_hops,
        ))

    # Sort: (distance, -confidence, type, str(id)) — closest first; within a distance,
    # higher derived confidence first; then CI type alphabetically; then UUID string.
    result.impacted.sort(key=lambda i: (i.distance, -i.confidence, i.type, str(i.id)))
    return result
