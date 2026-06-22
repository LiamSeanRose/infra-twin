"""Bounded reachability / access-path query: "what can reach this CI?"

Performs a backward BFS from the target CI over CONNECTS_TO / ROUTES_TO /
HAS_ACCESS_TO / EXPOSES edges in the tenant's AGE graph slice. Returns each
reaching source together with its shortest path and per-hop evidence pulled
from the relational ``edges`` table.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from uuid import UUID

import psycopg

from infra_twin.db.graph import cypher
from infra_twin.query.blast_radius import Supernode, _scalar

REACHABILITY_EDGE_TYPES: tuple[str, ...] = (
    "CONNECTS_TO",
    "ROUTES_TO",
    "HAS_ACCESS_TO",
    "EXPOSES",
)


@dataclass
class PathHop:
    from_id: UUID          # source endpoint CI id of this edge
    to_id: UUID            # target endpoint CI id of this edge
    edge_type: str         # one of REACHABILITY_EDGE_TYPES
    evidence: list[dict]   # the edge's evidence JSON list (may be [])


@dataclass
class ReachingSource:
    id: UUID
    type: str              # CI type of the reaching source (e.g. "internet", "security_group")
    name: str | None
    distance: int          # number of hops from this source to the target (>=1)
    is_internet: bool      # True iff type == "internet"
    path: list[PathHop]    # ordered source -> ... -> target; len(path) == distance


@dataclass
class Reachability:
    target_id: UUID
    max_depth: int
    reached_by_internet: bool
    sources: list[ReachingSource] = field(default_factory=list)
    truncated_supernodes: list[Supernode] = field(default_factory=list)


def _reachability_neighbors(
    conn: psycopg.Connection,
    tenant_id: UUID,
    ci_id: str,
    min_confidence: float,
) -> list[tuple[str, str]]:
    """Return (neighbor_ci_id, edge_type) pairs for all incoming edges to ci_id."""
    tenant = str(tenant_id)
    conf = float(min_confidence)
    in_types = ", ".join(f"'{t}'" for t in REACHABILITY_EDGE_TYPES)

    rows = cypher(
        conn,
        f"MATCH (a {{ci_id: '{ci_id}'}})<-[r]-(b) "
        f"WHERE type(r) IN [{in_types}] AND r.tenant_id = '{tenant}' "
        f"AND r.confidence >= {conf} RETURN b.ci_id, type(r)",
        "(ci_id agtype, etype agtype)",
    )
    return [(_scalar(row[0]), _scalar(row[1])) for row in rows]


def reachability(
    conn: psycopg.Connection,
    tenant_id: UUID,
    target_id: UUID,
    *,
    max_depth: int = 6,
    min_confidence: float = 0.0,
    max_fanout: int = 1000,
) -> Reachability:
    target = str(target_id)
    # visited maps ci_id_str -> depth at which it was first discovered
    visited: dict[str, int] = {target: 0}
    # predecessor maps ci_id_str -> (predecessor_ci_id_str, edge_type)
    predecessor: dict[str, tuple[str, str]] = {}
    frontier = [target]
    discovered: list[tuple[str, int]] = []  # (ci_id_str, depth)
    supernodes: list[Supernode] = []

    for depth in range(1, max_depth + 1):
        next_frontier: list[str] = []
        for node in frontier:
            raw_neighbors = _reachability_neighbors(conn, tenant_id, node, min_confidence)
            # deduplicate by neighbor id (keep first occurrence for stable BFS order)
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

    result = Reachability(
        target_id=target_id,
        max_depth=max_depth,
        reached_by_internet=False,
        truncated_supernodes=supernodes,
    )

    if not discovered:
        return result

    # Resolve discovered node ids against cis (RLS-scoped) for current type/name.
    # Only currently-present CIs become ReachingSources; dangling/closed nodes are dropped.
    ids = [UUID(node) for node, _ in discovered]
    rows = conn.execute(
        "SELECT id, type, name FROM cis WHERE id = ANY(%s) AND valid_to IS NULL",
        (ids,),
    ).fetchall()
    details: dict[str, tuple[str, str | None]] = {str(r[0]): (r[1], r[2]) for r in rows}

    # Collect the hops we need to resolve evidence for, grouped by (type, from_id, to_id).
    # We do path reconstruction first to gather all hop tuples, then batch-fetch evidence.
    sources_pending: list[tuple[str, int, list[tuple[str, str, str]]]] = []
    # Each item: (node_str, distance, hops_list)
    # Each hop: (edge_type, from_id_str, to_id_str)

    for node, distance in discovered:
        detail = details.get(node)
        if detail is None:
            continue  # not a current CI in this tenant

        # Reconstruct path from this source back to target
        hops: list[tuple[str, str, str]] = []  # (edge_type, from_id_str, to_id_str)
        cur = node
        while cur in predecessor:
            pred_node, edge_type = predecessor[cur]
            hops.append((edge_type, cur, pred_node))
            cur = pred_node
        # hops are built source->..., already in forward direction
        # hops[0] = (edge_type, source_node, next_node_toward_target)
        # hops[-1] = (edge_type, node_before_target, target)
        # PathHop.from_id = source end, PathHop.to_id = destination toward target
        # The edge direction is b -[r]-> a (backward traversal found b going into a),
        # so from_id=b (the source, i.e. cur in predecessor) and to_id=pred_node (toward target).
        sources_pending.append((node, distance, hops))

    if not sources_pending:
        return result

    # Batch-fetch evidence for all hops from the relational edges table.
    # Query: WHERE (type, from_id, to_id) IN (...) AND valid_to IS NULL
    all_hop_keys: list[tuple[str, str, str]] = []
    for _, _, hops in sources_pending:
        all_hop_keys.extend(hops)

    # Deduplicate hop keys before querying
    unique_keys = list(dict.fromkeys(all_hop_keys))

    evidence_map: dict[tuple[str, str, str], list[dict]] = {}
    if unique_keys:
        # Build the query using unnest for batch lookup
        # Columns: type, from_id (uuid), to_id (uuid)
        type_vals = [k[0] for k in unique_keys]
        from_vals = [UUID(k[1]) for k in unique_keys]
        to_vals = [UUID(k[2]) for k in unique_keys]

        edge_rows = conn.execute(
            "SELECT type, from_id, to_id, evidence FROM edges "
            "WHERE (type, from_id, to_id) IN (SELECT * FROM unnest(%s::text[], %s::uuid[], %s::uuid[])) "
            "AND valid_to IS NULL",
            (type_vals, from_vals, to_vals),
        ).fetchall()

        for er in edge_rows:
            key = (er[0], str(er[1]), str(er[2]))
            evidence_map[key] = er[3] if er[3] is not None else []

    # Assemble ReachingSource objects
    for node, distance, hops in sources_pending:
        detail = details[node]
        ci_type = detail[0]
        ci_name = detail[1]

        path_hops = []
        for edge_type, from_str, to_str in hops:
            ev = evidence_map.get((edge_type, from_str, to_str), [])
            path_hops.append(PathHop(
                from_id=UUID(from_str),
                to_id=UUID(to_str),
                edge_type=edge_type,
                evidence=ev,
            ))

        is_internet = ci_type == "internet"
        result.sources.append(ReachingSource(
            id=UUID(node),
            type=ci_type,
            name=ci_name,
            distance=distance,
            is_internet=is_internet,
            path=path_hops,
        ))

    result.sources.sort(key=lambda s: (s.distance, s.type, str(s.id)))
    result.reached_by_internet = any(s.is_internet for s in result.sources)
    return result
