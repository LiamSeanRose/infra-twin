"""Project the current relational graph into the Apache AGE graph.

The relational tables are the source of truth and append-only. The graph reflects only
*current* state, so closed CIs/edges are removed from it. Vertices and edges carry
``tenant_id`` so traversal queries can scope to a tenant (AGE itself is not RLS-protected).

Labels (vertex = CIType, edge = EdgeType) are pre-created in the migration, so we only ever
MERGE/MATCH/DELETE here — never create labels. Values come from our own model (uuids, enum
labels, attribute strings), and string values are escaped before being embedded in cypher.
"""

from __future__ import annotations

from collections.abc import Iterable

import psycopg

from infra_twin.core_model import CI, Edge
from infra_twin.db.graph import cypher


def _lit(value: str) -> str:
    """Escape a string for safe embedding as a cypher single-quoted literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def project(
    conn: psycopg.Connection,
    *,
    current_cis: Iterable[CI],
    current_edges: Iterable[Edge],
    closed_cis: Iterable[CI],
    closed_edges: Iterable[Edge],
) -> None:
    for ci in current_cis:
        label = ci.type.value
        sets = [
            f"n.tenant_id = '{ci.tenant_id}'",
            f"n.type = '{label}'",
            f"n.external_id = '{_lit(ci.external_id)}'",
        ]
        if ci.name:
            sets.append(f"n.name = '{_lit(ci.name)}'")
        cypher(
            conn,
            f"MERGE (n:{label} {{ci_id: '{ci.id}'}}) SET {', '.join(sets)}",
        )

    for edge in current_edges:
        cypher(
            conn,
            f"MATCH (a {{ci_id: '{edge.from_id}'}}), (b {{ci_id: '{edge.to_id}'}}) "
            f"MERGE (a)-[r:{edge.type.value} {{edge_key: '{_lit(edge.edge_key)}'}}]->(b) "
            f"SET r.tenant_id = '{edge.tenant_id}', r.source = '{edge.source.value}', "
            f"r.confidence = {edge.confidence}, r.edge_key = '{_lit(edge.edge_key)}'",
        )

    for edge in closed_edges:
        cypher(
            conn,
            f"MATCH (a {{ci_id: '{edge.from_id}'}})-[r:{edge.type.value} {{edge_key: '{_lit(edge.edge_key)}'}}]->"
            f"(b {{ci_id: '{edge.to_id}'}}) DELETE r",
        )

    for ci in closed_cis:
        cypher(conn, f"MATCH (n {{ci_id: '{ci.id}'}}) DETACH DELETE n")
