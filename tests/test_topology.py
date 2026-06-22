"""The /graph topology endpoint returns the tenant's current nodes and edges."""

from __future__ import annotations

from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.session import tenant_session
from infra_twin.query import topology
from infra_twin.reconciliation import reconcile

CI_SCOPE = frozenset({CIType.vpc, CIType.subnet})
EDGE_SCOPE = frozenset({EdgeType.CONTAINS})


def _seed(pool, tenant):
    events = [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net"),
        DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="a"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
            to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            evidence=[Evidence(source="test")],
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events, source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE
        )


def test_topology_returns_nodes_and_edges(pool, make_tenant):
    tenant = make_tenant()
    _seed(pool, tenant)
    with tenant_session(pool, tenant) as conn:
        topo = topology(conn, tenant)
    assert {n.external_id for n in topo.nodes} == {"vpc-1", "sub-1"}
    assert [e.type for e in topo.edges] == ["CONTAINS"]


def test_graph_endpoint_is_tenant_scoped(pool, make_tenant_with_key):
    tenant_a, key_a = make_tenant_with_key("A")
    _, key_b = make_tenant_with_key("B")
    _seed(pool, tenant_a)
    client = TestClient(create_app(pool=pool))

    body = client.get("/graph", headers={"Authorization": f"Bearer {key_a}"}).json()
    assert len(body["nodes"]) == 2 and len(body["edges"]) == 1

    other = client.get("/graph", headers={"Authorization": f"Bearer {key_b}"}).json()
    assert other["nodes"] == [] and other["edges"] == []
