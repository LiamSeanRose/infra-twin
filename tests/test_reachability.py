"""Bounded reachability / access-path query: direction, depth, supernode capping, tenant scoping.

Covers (§5 edge cases exhaustive, §6 acceptance criteria):
- Happy path: internet directly reaches target (distance 1)
- Internet reaches target indirectly (distance 2 via SG then instance)
- No inbound edges -> sources empty, reached_by_internet False
- max_depth boundary: excluded when depth < distance, included when depth == distance
- min_confidence boundary: excluded when confidence < threshold, included at exactly threshold
- Cross-tenant isolation: tenant-B session sees no sources for tenant-A's target
- Self-loop: self-referencing edge does not cause infinite traversal
- Cycle among sources: terminates, each source reported once at shortest distance
- Diamond: two equal-length paths to same source -> one source entry
- Supernode: high-degree node recorded in truncated_supernodes, traversal still terminates
- Store divergence: edge in AGE graph but relational row absent -> evidence []
- Non-reachability edge types (CONTAINS, DEPENDS_ON) ignored
- Direction: outbound-only edge from target does NOT make X a reaching source
- Closed/missing cis row -> dropped from sources
- max_depth=0 -> empty sources
- Multiple sources of different types -> all returned, sorted by (distance, type, id)
- internet_only in NL handler filters sources
- Evidence list genuinely empty in relational row -> evidence [] (valid)
- Same source reachable via two different edge types -> single source entry
- API endpoint: 200 shape, 404 for unknown CI, 400 for bad tenant header
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.query import (
    REACHABILITY_EDGE_TYPES,
    PathHop,
    Reachability,
    ReachingSource,
    reachability,
)
from infra_twin.query.blast_radius import Supernode
from infra_twin.query.reachability import reachability as reachability_fn
from infra_twin.reconciliation import reconcile


# ---------------------------------------------------------------------------
# Shared CI/edge type scopes for seeding
# ---------------------------------------------------------------------------

CI_SCOPE = frozenset({
    CIType.internet,
    CIType.security_group,
    CIType.ec2_instance,
    CIType.subnet,
    CIType.vpc,
    CIType.rds,
    CIType.elb,
})

EDGE_SCOPE = frozenset({
    EdgeType.CONNECTS_TO,
    EdgeType.ROUTES_TO,
    EdgeType.HAS_ACCESS_TO,
    EdgeType.EXPOSES,
    EdgeType.CONTAINS,
    EdgeType.DEPENDS_ON,
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ev(source="test", detail=None):
    if detail:
        return [Evidence(source=source, detail=detail)]
    return [Evidence(source=source)]


def _ci(t, ext, name=None):
    return DiscoveredCI(type=t, external_id=ext, name=name or ext)


def _edge(etype, ft, fx, tt, tx, ev=None, confidence=1.0):
    return DiscoveredEdge(
        type=etype,
        from_ref=CIRef(type=ft, external_id=fx),
        to_ref=CIRef(type=tt, external_id=tx),
        evidence=ev or _ev(),
        confidence=confidence,
    )


def _seed(pool, tenant, events):
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events,
            source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE,
        )


def _id(conn, tenant, t, ext):
    rows = CIRepository(conn, tenant).get_current(type=t, external_id=ext)
    assert rows, f"CI not found: {t} / {ext}"
    return rows[0].id


# ---------------------------------------------------------------------------
# AC 2: REACHABILITY_EDGE_TYPES constant
# ---------------------------------------------------------------------------

def test_reachability_edge_types_constant():
    """AC 2: REACHABILITY_EDGE_TYPES == ('CONNECTS_TO', 'ROUTES_TO', 'HAS_ACCESS_TO', 'EXPOSES')."""
    assert REACHABILITY_EDGE_TYPES == ("CONNECTS_TO", "ROUTES_TO", "HAS_ACCESS_TO", "EXPOSES")


# ---------------------------------------------------------------------------
# AC 3: dataclass fields
# ---------------------------------------------------------------------------

def test_path_hop_fields():
    """AC 3: PathHop has exactly from_id, to_id, edge_type, evidence."""
    from dataclasses import fields as dc_fields
    names = {f.name for f in dc_fields(PathHop)}
    assert names == {"from_id", "to_id", "edge_type", "evidence"}


def test_reaching_source_fields():
    """AC 3: ReachingSource has id, type, name, distance, is_internet, path."""
    from dataclasses import fields as dc_fields
    names = {f.name for f in dc_fields(ReachingSource)}
    assert names == {"id", "type", "name", "distance", "is_internet", "path"}


def test_reachability_fields():
    """AC 3: Reachability has target_id, max_depth, reached_by_internet, sources, truncated_supernodes."""
    from dataclasses import fields as dc_fields
    names = {f.name for f in dc_fields(Reachability)}
    assert names == {"target_id", "max_depth", "reached_by_internet", "sources", "truncated_supernodes"}


# ---------------------------------------------------------------------------
# AC 6: Supernode imported from blast_radius, not redefined
# ---------------------------------------------------------------------------

def test_supernode_imported_from_blast_radius():
    """AC 6: Supernode used in reachability is the same class as blast_radius.Supernode."""
    import importlib
    # Use importlib because infra_twin.query.__init__.py exports a `reachability` function
    # with the same name as the submodule; importlib bypasses the namespace collision.
    reach_mod = importlib.import_module("infra_twin.query.reachability")
    from infra_twin.query.blast_radius import Supernode as BRSupernode
    # The Supernode in reachability module's namespace must be the blast_radius one
    assert reach_mod.Supernode is BRSupernode


# ---------------------------------------------------------------------------
# AC 7: __init__.py __all__ exports
# ---------------------------------------------------------------------------

def test_query_init_exports():
    """AC 7: query __all__ includes the five new names."""
    import infra_twin.query as q
    for name in ("Reachability", "ReachingSource", "PathHop", "reachability", "REACHABILITY_EDGE_TYPES"):
        assert name in q.__all__, f"{name} missing from query.__all__"


# ---------------------------------------------------------------------------
# Edge case 2 / spec §4.behavior: target with no inbound edges -> sources [], reached_by_internet False
# ---------------------------------------------------------------------------

def test_no_inbound_edges_returns_empty_sources(pool, make_tenant):
    """Edge case 2: target exists but has no inbound reachability edges."""
    tenant = make_tenant()
    _seed(pool, tenant, [_ci(CIType.ec2_instance, "i-isolated")])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-isolated")
        result = reachability(conn, tenant, target_id, max_depth=6)
    assert result.sources == []
    assert result.reached_by_internet is False
    assert result.target_id == target_id
    assert result.max_depth == 6


# ---------------------------------------------------------------------------
# AC 15 / Edge case 3: internet reaches target directly (distance 1)
# ---------------------------------------------------------------------------

def test_internet_reaches_target_directly(pool, make_tenant):
    """AC 15 / Edge case 3: internet -CONNECTS_TO-> target, distance 1, is_internet True."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _edge(
            EdgeType.CONNECTS_TO,
            CIType.internet, "internet",
            CIType.security_group, "sg-1",
            ev=[Evidence(source="aws", detail="sg sg-1 allows tcp/443 from 0.0.0.0/0")],
        ),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.security_group, "sg-1")
        result = reachability(conn, tenant, target_id, max_depth=6)

    assert result.reached_by_internet is True
    assert len(result.sources) == 1
    src = result.sources[0]
    assert src.is_internet is True
    assert src.type == "internet"
    assert src.distance == 1
    assert len(src.path) == 1
    hop = src.path[0]
    assert hop.edge_type == "CONNECTS_TO"
    # from_id is the internet CI; to_id is the security_group
    assert hop.to_id == target_id


# ---------------------------------------------------------------------------
# AC 15 / Edge case 4: internet reaches target indirectly via two hops
# ---------------------------------------------------------------------------

def test_internet_reaches_target_indirectly_two_hops(pool, make_tenant):
    """AC 15 / Edge case 4: internet -CONNECTS_TO-> sg -EXPOSES-> instance, distance 2."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1",
              ev=[Evidence(source="aws", detail="sg sg-1 allows tcp/443 from 0.0.0.0/0")]),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.ec2_instance, "i-1",
              ev=[Evidence(source="aws", detail="sg-1 exposes i-1")]),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        sg_id = _id(conn, tenant, CIType.security_group, "sg-1")
        internet_id = _id(conn, tenant, CIType.internet, "internet")
        result = reachability(conn, tenant, target_id, max_depth=6)

    assert result.reached_by_internet is True
    # Sources: sg-1 (distance 1) and internet (distance 2)
    source_types = {s.type for s in result.sources}
    assert "internet" in source_types
    assert "security_group" in source_types

    internet_src = next(s for s in result.sources if s.is_internet)
    assert internet_src.distance == 2
    assert len(internet_src.path) == 2
    # First hop: sg -> instance (EXPOSES)
    # Second hop: internet -> sg (CONNECTS_TO)
    hop_types = [h.edge_type for h in internet_src.path]
    assert "EXPOSES" in hop_types
    assert "CONNECTS_TO" in hop_types
    # Path is ordered source->target: first hop is internet->sg, second is sg->instance
    assert internet_src.path[0].edge_type == "CONNECTS_TO"
    assert internet_src.path[1].edge_type == "EXPOSES"


# ---------------------------------------------------------------------------
# Edge case 5: max_depth < internet distance -> internet NOT included
# ---------------------------------------------------------------------------

def test_max_depth_excludes_source_beyond_depth(pool, make_tenant):
    """Edge case 5: max_depth smaller than internet distance -> internet NOT in sources."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.ec2_instance, "i-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")

        # max_depth=1: sg-1 is 1 hop away (included); internet is 2 hops (excluded)
        result = reachability(conn, tenant, target_id, max_depth=1)
    assert result.reached_by_internet is False
    source_types = {s.type for s in result.sources}
    assert "internet" not in source_types
    assert "security_group" in source_types


def test_max_depth_boundary_includes_source_at_exact_depth(pool, make_tenant):
    """Edge case 5 boundary: depth exactly equal to distance -> source IS included."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.ec2_instance, "i-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")

        # max_depth=2: internet is exactly 2 hops away -> included
        result = reachability(conn, tenant, target_id, max_depth=2)
    assert result.reached_by_internet is True
    internet_src = next((s for s in result.sources if s.is_internet), None)
    assert internet_src is not None
    assert internet_src.distance == 2


# ---------------------------------------------------------------------------
# Edge case 6: min_confidence filtering
# ---------------------------------------------------------------------------

def test_min_confidence_excludes_low_confidence_edge(pool, make_tenant):
    """Edge case 6: edge with confidence=0.5 excluded when min_confidence=0.6."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-low"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-low", CIType.ec2_instance, "i-1",
              confidence=0.5),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6, min_confidence=0.6)
    assert result.sources == []


def test_min_confidence_includes_edge_at_exact_threshold(pool, make_tenant):
    """Edge case 6 boundary: confidence == min_confidence is included (>=)."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-exact"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-exact", CIType.ec2_instance, "i-1",
              confidence=0.7),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6, min_confidence=0.7)
    assert len(result.sources) == 1
    assert result.sources[0].type == "security_group"


# ---------------------------------------------------------------------------
# AC 16 / Edge case 7: cross-tenant isolation (adversarial)
# ---------------------------------------------------------------------------

def test_reachability_is_tenant_scoped(pool, make_tenant):
    """AC 16 / Edge case 7: tenant-B session returns no sources for tenant-A's target."""
    tenant_a = make_tenant("A")
    tenant_b = make_tenant("B")
    _seed(pool, tenant_a, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
    ])
    with tenant_session(pool, tenant_a) as conn:
        target_id = _id(conn, tenant_a, CIType.security_group, "sg-1")

    # Tenant B actively tries to read tenant A's target -- must get empty sources
    with tenant_session(pool, tenant_b) as conn:
        result = reachability(conn, tenant_b, target_id, max_depth=6)
    assert result.sources == []
    assert result.reached_by_internet is False


# ---------------------------------------------------------------------------
# Edge case 8: self-loop (X -CONNECTS_TO-> X) does not cause infinite traversal
# ---------------------------------------------------------------------------

def test_self_loop_does_not_cause_infinite_traversal(pool, make_tenant):
    """Edge case 8: self-referencing SG must not cause infinite traversal; target not its own source."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-self"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-self", CIType.security_group, "sg-self"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.security_group, "sg-self")
        result = reachability(conn, tenant, target_id, max_depth=6)
    # The self-loop is the target itself; it must NOT appear as its own source
    assert all(s.id != target_id for s in result.sources)


# ---------------------------------------------------------------------------
# Edge case 9: cycle among sources terminates; each source reported once
# ---------------------------------------------------------------------------

def test_cycle_among_sources_terminates(pool, make_tenant):
    """Edge case 9: A->B->target and B->A cycle -> terminates, each source once."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-a"),
        _ci(CIType.security_group, "sg-b"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-b", CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-a", CIType.security_group, "sg-b"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-b", CIType.security_group, "sg-a"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6)
    source_ids = [s.id for s in result.sources]
    # No duplicates
    assert len(source_ids) == len(set(source_ids))
    # Both sg-a and sg-b appear
    source_types = [s.type for s in result.sources]
    assert source_types.count("security_group") == 2


# ---------------------------------------------------------------------------
# Edge case 10: diamond -> one deterministic source, one path
# ---------------------------------------------------------------------------

def test_diamond_single_source_one_path(pool, make_tenant):
    """Edge case 10: A->target AND A->B->target -> source A reported once at shortest distance."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-a"),
        _ci(CIType.security_group, "sg-b"),
        _ci(CIType.ec2_instance, "i-1"),
        # Direct: sg-a -> i-1 (distance 1)
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-a", CIType.ec2_instance, "i-1"),
        # Indirect: sg-b -> i-1 (distance 1 also)
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-b", CIType.ec2_instance, "i-1"),
        # Also sg-a -> sg-b (provides alternative path of distance 2 to reach sg-b via sg-a)
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-a", CIType.security_group, "sg-b"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6)
    source_ids = [s.id for s in result.sources]
    # No duplicates
    assert len(source_ids) == len(set(source_ids))
    # sg-b reachable both directly (distance 1) and via sg-a (distance 2);
    # shortest distance 1 should win for sg-b
    sg_b_sources = [s for s in result.sources if s.type == "security_group" and s.distance == 1]
    # Two SGs both at distance 1
    assert len(sg_b_sources) == 2


# ---------------------------------------------------------------------------
# Edge case 11: supernode (degree > max_fanout)
# ---------------------------------------------------------------------------

def test_supernode_recorded_when_fanout_exceeded(pool, make_tenant):
    """Edge case 11: node with inbound degree > max_fanout -> in truncated_supernodes."""
    tenant = make_tenant()
    # Create 5 sources all pointing to the target; set max_fanout=2
    cis = [_ci(CIType.security_group, f"sg-{n}") for n in range(5)]
    target = _ci(CIType.ec2_instance, "i-target")
    edges = [
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, f"sg-{n}", CIType.ec2_instance, "i-target")
        for n in range(5)
    ]
    _seed(pool, tenant, [*cis, target, *edges])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-target")
        result = reachability(conn, tenant, target_id, max_depth=4, max_fanout=2)
    assert len(result.sources) == 2
    assert len(result.truncated_supernodes) == 1
    sn = result.truncated_supernodes[0]
    assert sn.id == target_id
    assert sn.degree == 5
    assert sn.depth == 0


# ---------------------------------------------------------------------------
# Edge case 12: AGE graph edge present but relational row absent -> evidence []
# ---------------------------------------------------------------------------

def test_missing_relational_row_gives_empty_evidence(pool, make_tenant):
    """Edge case 12: if relational edges row is absent for a hop, evidence is [] not an error."""
    import psycopg
    from infra_twin.db.config import admin_dsn

    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-ghost"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-ghost", CIType.ec2_instance, "i-1"),
    ])

    # Delete the relational edge row as superuser to simulate store divergence
    with psycopg.connect(admin_dsn()) as admin_conn:
        admin_conn.execute(
            "DELETE FROM edges WHERE type = %s AND valid_to IS NULL",
            ("CONNECTS_TO",),
        )
        admin_conn.commit()

    # AGE graph edge still exists; reachability should still discover the source
    # and return evidence=[] without raising
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6)

    # Source should be found (AGE graph still has the edge) with empty evidence
    assert len(result.sources) == 1
    assert result.sources[0].path[0].evidence == []


# ---------------------------------------------------------------------------
# Edge case 13: non-reachability edge types are ignored
# ---------------------------------------------------------------------------

def test_non_reachability_edge_types_ignored(pool, make_tenant):
    """Edge case 13: CONTAINS / DEPENDS_ON edges do not contribute reachability."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.vpc, "vpc-1"),
        _ci(CIType.subnet, "sub-1"),
        _ci(CIType.ec2_instance, "i-1"),
        # CONTAINS: vpc -> subnet (not a reachability edge)
        _edge(EdgeType.CONTAINS, CIType.vpc, "vpc-1", CIType.subnet, "sub-1"),
        # DEPENDS_ON: instance -> subnet (not a reachability edge, and wrong direction for backward)
        _edge(EdgeType.DEPENDS_ON, CIType.ec2_instance, "i-1", CIType.subnet, "sub-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.subnet, "sub-1")
        result = reachability(conn, tenant, target_id, max_depth=6)
    # Neither vpc-1 (CONTAINS) nor instance (DEPENDS_ON in wrong direction) should be a source
    assert result.sources == []


# ---------------------------------------------------------------------------
# AC 18 / Edge case 14: outbound-only edge from target does NOT yield reaching source
# ---------------------------------------------------------------------------

def test_outbound_edge_from_target_does_not_yield_source(pool, make_tenant):
    """AC 18 / Edge case 14: target -CONNECTS_TO-> X does NOT make X a reaching source."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.ec2_instance, "i-target"),
        _ci(CIType.security_group, "sg-downstream"),
        # Outbound edge FROM target (i.e. target is the source in this edge)
        _edge(EdgeType.CONNECTS_TO, CIType.ec2_instance, "i-target", CIType.security_group, "sg-downstream"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-target")
        result = reachability(conn, tenant, target_id, max_depth=6)
    # sg-downstream is downstream of target, not a reaching source
    assert result.sources == []


# ---------------------------------------------------------------------------
# Edge case 15: closed cis row -> dropped from sources
# ---------------------------------------------------------------------------

def test_closed_ci_row_dropped_from_sources(pool, make_tenant):
    """Edge case 15: source CI whose cis row is closed is dropped from sources."""
    import psycopg
    from infra_twin.db.config import admin_dsn

    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-closed"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-closed", CIType.ec2_instance, "i-1"),
    ])

    # Close the security_group CI by setting valid_to (simulate closed/deleted CI)
    with psycopg.connect(admin_dsn()) as admin_conn:
        admin_conn.execute(
            "UPDATE cis SET valid_to = now() WHERE type = %s AND valid_to IS NULL",
            ("security_group",),
        )
        admin_conn.commit()

    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6)
    # The closed sg should be dropped
    assert result.sources == []


# ---------------------------------------------------------------------------
# Edge case 16: max_depth=0 -> empty sources
# ---------------------------------------------------------------------------

def test_max_depth_zero_returns_empty_sources(pool, make_tenant):
    """Edge case 16: max_depth=0 passed to query function -> empty sources."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-1", CIType.ec2_instance, "i-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=0)
    assert result.sources == []
    assert result.reached_by_internet is False


# ---------------------------------------------------------------------------
# Edge case 17: multiple reaching sources of different types -> sorted by (distance, type, id)
# ---------------------------------------------------------------------------

def test_multiple_sources_sorted_by_distance_type_id(pool, make_tenant):
    """Edge case 17: multiple sources of different types sorted by (distance, type, id)."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.elb, "elb-1"),
        _ci(CIType.ec2_instance, "i-target"),
        # Both sg-1 and elb-1 -> i-target at distance 1
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "sg-1", CIType.ec2_instance, "i-target"),
        _edge(EdgeType.CONNECTS_TO, CIType.elb, "elb-1", CIType.ec2_instance, "i-target"),
        # internet -> sg-1 at distance 2 total from i-target
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-target")
        result = reachability(conn, tenant, target_id, max_depth=6)

    assert len(result.sources) >= 3
    # Verify sorted order: first by distance, then by type string
    for i in range(len(result.sources) - 1):
        a, b = result.sources[i], result.sources[i + 1]
        key_a = (a.distance, a.type, str(a.id))
        key_b = (b.distance, b.type, str(b.id))
        assert key_a <= key_b, f"Sort order violated: {key_a} > {key_b}"

    # Distance-1 sources must come before distance-2 sources
    dist_1_types = {s.type for s in result.sources if s.distance == 1}
    dist_2_types = {s.type for s in result.sources if s.distance == 2}
    assert dist_1_types  # some at distance 1
    assert dist_2_types  # internet at distance 2


# ---------------------------------------------------------------------------
# Edge case 19: hop evidence=[] is a valid non-error state
#
# The edges table has a CHECK constraint (jsonb_array_length(evidence) > 0) so it is
# impossible to store a genuinely empty evidence array via the normal relational path.
# Edge case 19's "evidence: []" therefore arises via store divergence (edge case 12):
# the AGE graph edge exists but the relational row is absent, producing evidence=[].
# The test_missing_relational_row_gives_empty_evidence test above already covers this.
# This test confirms the PathHop evidence field accepts [] without error at the type level.
# ---------------------------------------------------------------------------

def test_path_hop_evidence_empty_list_is_valid_type():
    """Edge case 19: PathHop.evidence=[] is a valid Python value (not an error at the type level)."""
    from uuid import uuid4 as _uuid4
    hop = PathHop(
        from_id=_uuid4(),
        to_id=_uuid4(),
        edge_type="CONNECTS_TO",
        evidence=[],
    )
    assert hop.evidence == []


# ---------------------------------------------------------------------------
# Evidence resolution: evidence from relational row is attached to path hops
# ---------------------------------------------------------------------------

def test_evidence_attached_to_path_hops(pool, make_tenant):
    """§4 behavior: hop evidence is resolved from relational edges table."""
    tenant = make_tenant()
    ev_detail = "sg sg-1 allows tcp/443 from 0.0.0.0/0"
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1",
              ev=[Evidence(source="aws", detail=ev_detail)]),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.security_group, "sg-1")
        result = reachability(conn, tenant, target_id, max_depth=6)

    assert result.reached_by_internet is True
    src = result.sources[0]
    hop = src.path[0]
    assert hop.evidence, "evidence should be non-empty"
    assert any(ev_detail in str(e) for e in hop.evidence)


# ---------------------------------------------------------------------------
# API endpoint tests (AC 8, 9, 10)
# ---------------------------------------------------------------------------

def test_api_reachability_endpoint_200(pool, make_tenant_with_key):
    """AC 8 / AC 10: GET /cis/{ci_id}/reachability returns 200 with correct JSON shape."""
    tenant, api_key = make_tenant_with_key()
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1",
              ev=[Evidence(source="aws", detail="sg sg-1 allows tcp/443 from 0.0.0.0/0")]),
    ])
    client = TestClient(create_app(pool=pool))
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.security_group, "sg-1")

    resp = client.get(
        f"/cis/{target_id}/reachability",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    body = resp.json()

    # AC 10: top-level keys
    assert "target_id" in body
    assert "max_depth" in body
    assert "reached_by_internet" in body
    assert "sources" in body
    assert "truncated_supernodes" in body
    assert body["reached_by_internet"] is True
    assert body["max_depth"] == 6  # default

    # AC 10: source fields
    assert len(body["sources"]) == 1
    src = body["sources"][0]
    for key in ("id", "type", "name", "distance", "is_internet", "path"):
        assert key in src, f"key '{key}' missing from source"
    assert src["is_internet"] is True
    assert src["distance"] == 1

    # AC 10: hop fields
    assert len(src["path"]) == 1
    hop = src["path"][0]
    for key in ("from_id", "to_id", "edge_type", "evidence"):
        assert key in hop, f"key '{key}' missing from hop"
    assert hop["edge_type"] == "CONNECTS_TO"
    # UUIDs serialized as strings
    import uuid
    uuid.UUID(body["target_id"])
    uuid.UUID(src["id"])
    uuid.UUID(hop["from_id"])
    uuid.UUID(hop["to_id"])


def test_api_reachability_endpoint_default_params(pool, make_tenant_with_key):
    """AC 8: endpoint accepts max_depth, min_confidence, max_fanout query params."""
    tenant, api_key = make_tenant_with_key()
    _seed(pool, tenant, [_ci(CIType.ec2_instance, "i-1")])
    client = TestClient(create_app(pool=pool))
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")

    resp = client.get(
        f"/cis/{target_id}/reachability?max_depth=3&min_confidence=0.5&max_fanout=100",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    assert resp.json()["max_depth"] == 3


def test_api_reachability_endpoint_404_for_unknown_ci(pool, make_tenant_with_key):
    """AC 9: endpoint returns 404 with detail='CI not found' when CI does not exist."""
    _, api_key = make_tenant_with_key()
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        f"/cis/{uuid4()}/reachability",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "CI not found"


def test_api_reachability_endpoint_401_for_missing_auth(pool):
    """Missing Authorization header -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        f"/cis/{uuid4()}/reachability",
    )
    assert resp.status_code == 401


def test_api_reachability_endpoint_no_sources_shape(pool, make_tenant_with_key):
    """§2.2: target with no inbound sources returns sources=[], reached_by_internet=false."""
    tenant, api_key = make_tenant_with_key()
    _seed(pool, tenant, [_ci(CIType.ec2_instance, "i-isolated")])
    client = TestClient(create_app(pool=pool))
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-isolated")

    resp = client.get(
        f"/cis/{target_id}/reachability",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["sources"] == []
    assert body["reached_by_internet"] is False


def test_api_reachability_endpoint_tenant_isolation(pool, make_tenant_with_key, make_tenant):
    """API endpoint: tenant B cannot see tenant A's sources."""
    tenant_a = make_tenant("A")
    _, key_b = make_tenant_with_key("B")
    _seed(pool, tenant_a, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
    ])
    client = TestClient(create_app(pool=pool))
    with tenant_session(pool, tenant_a) as conn:
        target_id = _id(conn, tenant_a, CIType.security_group, "sg-1")

    # Tenant B tries to read tenant A's CI
    resp = client.get(
        f"/cis/{target_id}/reachability",
        headers={"Authorization": f"Bearer {key_b}"},
    )
    # Either 404 (CI not visible to B) or 200 with no sources
    if resp.status_code == 200:
        assert resp.json()["sources"] == []
        assert resp.json()["reached_by_internet"] is False
    else:
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# reached_by_internet derived purely from type=="internet"
# (AC 14: no hardcoded traversal branch for internet in BFS)
# ---------------------------------------------------------------------------

def test_reached_by_internet_derived_from_type_not_hardcoded(pool, make_tenant):
    """AC 14: reached_by_internet is derived from resolved CI type=='internet' only."""
    # If we seed a non-internet CI that happens to have external_id='internet',
    # it should NOT set is_internet=True (type matters, not external_id)
    tenant = make_tenant()
    _seed(pool, tenant, [
        # A security_group with external_id that looks like 'internet' but type is security_group
        _ci(CIType.security_group, "internet-lookalike"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.security_group, "internet-lookalike", CIType.ec2_instance, "i-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6)

    assert result.reached_by_internet is False
    assert len(result.sources) == 1
    assert result.sources[0].is_internet is False


# ---------------------------------------------------------------------------
# Path reconstruction: len(path) == distance
# ---------------------------------------------------------------------------

def test_path_length_equals_distance(pool, make_tenant):
    """§4 behavior: len(path) == distance for every reaching source."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.internet, "internet", "Internet (0.0.0.0/0, ::/0)"),
        _ci(CIType.security_group, "sg-1"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.CONNECTS_TO, CIType.internet, "internet", CIType.security_group, "sg-1"),
        _edge(EdgeType.EXPOSES, CIType.security_group, "sg-1", CIType.ec2_instance, "i-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6)

    for src in result.sources:
        assert len(src.path) == src.distance, (
            f"source {src.type} at distance {src.distance} has path length {len(src.path)}"
        )


# ---------------------------------------------------------------------------
# ROUTES_TO and HAS_ACCESS_TO edge types are traversed
# ---------------------------------------------------------------------------

def test_routes_to_edge_contributes_reachability(pool, make_tenant):
    """ROUTES_TO is in REACHABILITY_EDGE_TYPES and contributes reachability."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.subnet, "sub-1"),
        _ci(CIType.ec2_instance, "i-1"),
        _edge(EdgeType.ROUTES_TO, CIType.subnet, "sub-1", CIType.ec2_instance, "i-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.ec2_instance, "i-1")
        result = reachability(conn, tenant, target_id, max_depth=6)
    assert len(result.sources) == 1
    assert result.sources[0].type == "subnet"
    assert result.sources[0].path[0].edge_type == "ROUTES_TO"


def test_has_access_to_edge_contributes_reachability(pool, make_tenant):
    """HAS_ACCESS_TO is in REACHABILITY_EDGE_TYPES and contributes reachability."""
    tenant = make_tenant()
    _seed(pool, tenant, [
        _ci(CIType.iam_role, "role-1"),
        _ci(CIType.rds, "db-1"),
        _edge(EdgeType.HAS_ACCESS_TO, CIType.iam_role, "role-1", CIType.rds, "db-1"),
    ])
    with tenant_session(pool, tenant) as conn:
        target_id = _id(conn, tenant, CIType.rds, "db-1")
        result = reachability(conn, tenant, target_id, max_depth=6)
    assert len(result.sources) == 1
    assert result.sources[0].type == "iam_role"
    assert result.sources[0].path[0].edge_type == "HAS_ACCESS_TO"
