"""Blast-radius traversal: "what breaks if this CI fails?"

Impact is direction-sensitive per edge type:

- ``CONTAINS`` flows **outward** — if a parent (VPC) fails, the things it contains are impacted.
- ``DEPENDS_ON`` / ``RUNS_ON`` / ``ROUTES_TO`` / ``EXPOSES`` flow **inward** — if a CI fails,
  the things that depend on / run on / route to / expose it are impacted.

The traversal is a bounded-depth BFS over the tenant's slice of the AGE graph (edges carry
``tenant_id``). Fan-out is capped per node to contain the supernode problem; nodes that
exceed the cap are reported as truncated rather than expanded fully. Impacted CIs are then
resolved against the relational store (RLS-scoped) for their current type and name.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from uuid import UUID

import psycopg

from infra_twin.db.graph import cypher

OUTGOING_IMPACT = ("CONTAINS",)
INCOMING_IMPACT = ("DEPENDS_ON", "RUNS_ON", "ROUTES_TO", "EXPOSES")


@dataclass
class ImpactedCI:
    id: UUID
    type: str
    name: str | None
    distance: int


@dataclass
class Supernode:
    id: UUID
    degree: int
    depth: int


@dataclass
class BlastRadius:
    source_id: UUID
    max_depth: int
    impacted: list[ImpactedCI] = field(default_factory=list)
    truncated_supernodes: list[Supernode] = field(default_factory=list)


def _scalar(value) -> str:
    """Convert an AGE agtype scalar (a JSON-encoded string) to a plain Python str."""
    text = value if isinstance(value, str) else str(value)
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return text.strip('"')


def _impact_neighbors(
    conn: psycopg.Connection, tenant_id: UUID, ci_id: str, min_confidence: float
) -> list[str]:
    tenant = str(tenant_id)
    conf = float(min_confidence)
    out_types = ", ".join(f"'{t}'" for t in OUTGOING_IMPACT)
    in_types = ", ".join(f"'{t}'" for t in INCOMING_IMPACT)

    rows = cypher(
        conn,
        f"MATCH (a {{ci_id: '{ci_id}'}})-[r]->(b) "
        f"WHERE type(r) IN [{out_types}] AND r.tenant_id = '{tenant}' "
        f"AND r.confidence >= {conf} RETURN b.ci_id",
        "(ci_id agtype)",
    )
    rows += cypher(
        conn,
        f"MATCH (a {{ci_id: '{ci_id}'}})<-[r]-(b) "
        f"WHERE type(r) IN [{in_types}] AND r.tenant_id = '{tenant}' "
        f"AND r.confidence >= {conf} RETURN b.ci_id",
        "(ci_id agtype)",
    )
    return [_scalar(row[0]) for row in rows]


def blast_radius(
    conn: psycopg.Connection,
    tenant_id: UUID,
    ci_id: UUID,
    *,
    max_depth: int = 4,
    min_confidence: float = 0.0,
    max_fanout: int = 1000,
) -> BlastRadius:
    source = str(ci_id)
    visited: dict[str, int] = {source: 0}
    frontier = [source]
    discovered: list[tuple[str, int]] = []
    supernodes: list[Supernode] = []

    for depth in range(1, max_depth + 1):
        next_frontier: list[str] = []
        for node in frontier:
            neighbors = list(dict.fromkeys(_impact_neighbors(conn, tenant_id, node, min_confidence)))
            if len(neighbors) > max_fanout:
                supernodes.append(Supernode(UUID(node), len(neighbors), visited[node]))
                neighbors = neighbors[:max_fanout]
            for neighbor in neighbors:
                if neighbor not in visited:
                    visited[neighbor] = depth
                    next_frontier.append(neighbor)
                    discovered.append((neighbor, depth))
        frontier = next_frontier
        if not frontier:
            break

    result = BlastRadius(source_id=ci_id, max_depth=max_depth, truncated_supernodes=supernodes)
    if not discovered:
        return result

    ids = [UUID(node) for node, _ in discovered]
    rows = conn.execute(
        "SELECT id, type, name FROM cis WHERE id = ANY(%s) AND valid_to IS NULL",
        (ids,),
    ).fetchall()
    details = {str(r[0]): (r[1], r[2]) for r in rows}

    for node, distance in discovered:
        detail = details.get(node)
        if detail is not None:  # only currently-present CIs in this tenant
            result.impacted.append(ImpactedCI(UUID(node), detail[0], detail[1], distance))
    result.impacted.sort(key=lambda i: (i.distance, i.type, str(i.id)))
    return result
