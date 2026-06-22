"""Blast-radius traversal: direction, depth, supernode capping, tenant scoping."""

from __future__ import annotations

from uuid import uuid4

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.query import blast_radius
from infra_twin.reconciliation import reconcile

CI_SCOPE = frozenset(
    {CIType.vpc, CIType.subnet, CIType.ec2_instance, CIType.rds}
)
EDGE_SCOPE = frozenset({EdgeType.CONTAINS, EdgeType.DEPENDS_ON})


def _ev():
    return [Evidence(source="test")]


def _ci(t, ext):
    return DiscoveredCI(type=t, external_id=ext, name=ext)


def _edge(etype, ft, fx, tt, tx):
    return DiscoveredEdge(
        type=etype,
        from_ref=CIRef(type=ft, external_id=fx),
        to_ref=CIRef(type=tt, external_id=tx),
        evidence=_ev(),
    )


def _seed(pool, tenant, events):
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events, source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE
        )


def _id(conn, tenant, t, ext):
    return CIRepository(conn, tenant).get_current(type=t, external_id=ext)[0].id


def test_contains_impact_flows_downward(pool, make_tenant):
    tenant = make_tenant()
    _seed(
        pool,
        tenant,
        [
            _ci(CIType.vpc, "vpc-1"),
            _ci(CIType.subnet, "sub-1"),
            _ci(CIType.ec2_instance, "i-1"),
            _ci(CIType.rds, "db-1"),
            _edge(EdgeType.CONTAINS, CIType.vpc, "vpc-1", CIType.subnet, "sub-1"),
            _edge(EdgeType.CONTAINS, CIType.subnet, "sub-1", CIType.ec2_instance, "i-1"),
            _edge(EdgeType.DEPENDS_ON, CIType.ec2_instance, "i-1", CIType.rds, "db-1"),
        ],
    )
    with tenant_session(pool, tenant) as conn:
        vpc_id = _id(conn, tenant, CIType.vpc, "vpc-1")
        result = blast_radius(conn, tenant, vpc_id, max_depth=4)

    by_type = {i.type: i.distance for i in result.impacted}
    # The subnet and instance the VPC contains are impacted; the DB the instance depends on
    # is not (impact does not flow up a dependency).
    assert by_type == {"subnet": 1, "ec2_instance": 2}


def test_dependency_impact_flows_to_dependents(pool, make_tenant):
    tenant = make_tenant()
    _seed(
        pool,
        tenant,
        [
            _ci(CIType.ec2_instance, "i-1"),
            _ci(CIType.rds, "db-1"),
            _edge(EdgeType.DEPENDS_ON, CIType.ec2_instance, "i-1", CIType.rds, "db-1"),
        ],
    )
    with tenant_session(pool, tenant) as conn:
        db_id = _id(conn, tenant, CIType.rds, "db-1")
        result = blast_radius(conn, tenant, db_id, max_depth=4)

    # The instance that depends on the DB is impacted by the DB failing.
    assert [(i.type, i.distance) for i in result.impacted] == [("ec2_instance", 1)]


def test_max_depth_bounds_traversal(pool, make_tenant):
    tenant = make_tenant()
    _seed(
        pool,
        tenant,
        [
            _ci(CIType.vpc, "vpc-1"),
            _ci(CIType.subnet, "sub-1"),
            _ci(CIType.ec2_instance, "i-1"),
            _edge(EdgeType.CONTAINS, CIType.vpc, "vpc-1", CIType.subnet, "sub-1"),
            _edge(EdgeType.CONTAINS, CIType.subnet, "sub-1", CIType.ec2_instance, "i-1"),
        ],
    )
    with tenant_session(pool, tenant) as conn:
        vpc_id = _id(conn, tenant, CIType.vpc, "vpc-1")
        result = blast_radius(conn, tenant, vpc_id, max_depth=1)
    assert [i.type for i in result.impacted] == ["subnet"]  # instance is 2 hops away


def test_supernode_fanout_is_capped(pool, make_tenant):
    tenant = make_tenant()
    children = [_ci(CIType.subnet, f"sub-{n}") for n in range(5)]
    edges = [
        _edge(EdgeType.CONTAINS, CIType.vpc, "vpc-1", CIType.subnet, f"sub-{n}")
        for n in range(5)
    ]
    _seed(pool, tenant, [_ci(CIType.vpc, "vpc-1"), *children, *edges])

    with tenant_session(pool, tenant) as conn:
        vpc_id = _id(conn, tenant, CIType.vpc, "vpc-1")
        result = blast_radius(conn, tenant, vpc_id, max_depth=4, max_fanout=2)

    assert len(result.impacted) == 2
    assert len(result.truncated_supernodes) == 1
    sn = result.truncated_supernodes[0]
    assert sn.id == vpc_id and sn.degree == 5 and sn.depth == 0


def test_blast_radius_is_tenant_scoped(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    _seed(
        pool,
        a,
        [
            _ci(CIType.vpc, "vpc-1"),
            _ci(CIType.subnet, "sub-1"),
            _edge(EdgeType.CONTAINS, CIType.vpc, "vpc-1", CIType.subnet, "sub-1"),
        ],
    )
    with tenant_session(pool, a) as conn:
        vpc_id = _id(conn, a, CIType.vpc, "vpc-1")
    # Traversing tenant A's node from a tenant B session yields nothing (edges are scoped).
    with tenant_session(pool, b) as conn:
        result = blast_radius(conn, b, vpc_id, max_depth=4)
    assert result.impacted == []
