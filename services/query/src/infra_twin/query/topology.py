"""Current graph (nodes + edges) for visualization.

Returns the tenant's current CIs and the edges among them, bounded by ``limit`` so a large
graph can't overwhelm the UI. Edges are restricted to the returned node set so there are no
dangling endpoints. Reads are RLS-scoped to the session tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

import psycopg


@dataclass
class TopologyNode:
    id: UUID
    type: str
    external_id: str
    name: str | None


@dataclass
class TopologyEdge:
    id: UUID
    type: str
    from_id: UUID
    to_id: UUID
    source: str
    confidence: float


@dataclass
class Topology:
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)


def topology(conn: psycopg.Connection, tenant_id: UUID, *, limit: int = 500) -> Topology:
    node_rows = conn.execute(
        "SELECT id, type, external_id, name FROM cis WHERE valid_to IS NULL "
        "ORDER BY type, external_id LIMIT %s",
        (limit,),
    ).fetchall()
    nodes = [TopologyNode(r[0], r[1], r[2], r[3]) for r in node_rows]

    edges: list[TopologyEdge] = []
    ids = [n.id for n in nodes]
    if ids:
        edge_rows = conn.execute(
            "SELECT id, type, from_id, to_id, source, confidence FROM edges "
            "WHERE valid_to IS NULL AND from_id = ANY(%s) AND to_id = ANY(%s)",
            (ids, ids),
        ).fetchall()
        edges = [TopologyEdge(r[0], r[1], r[2], r[3], r[4], r[5]) for r in edge_rows]

    return Topology(nodes=nodes, edges=edges)
