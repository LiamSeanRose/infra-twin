"""The Apache AGE graph is created and usable by the app role."""

from __future__ import annotations

from uuid import uuid4

from infra_twin.db.graph import cypher


def test_age_graph_roundtrip(pool):
    key = uuid4().hex
    with pool.connection() as conn:
        cypher(conn, f"CREATE (n:ec2_instance {{k:'{key}'}}) RETURN n")
        rows = cypher(conn, f"MATCH (n:ec2_instance {{k:'{key}'}}) RETURN n")
    assert len(rows) == 1
