"""Change feed derives created/updated/removed from bitemporal history."""

from __future__ import annotations

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.session import tenant_session
from infra_twin.query import change_feed
from infra_twin.reconciliation import reconcile

CI_SCOPE = frozenset({CIType.vpc, CIType.subnet})
EDGE_SCOPE = frozenset({EdgeType.CONTAINS})


def _run(pool, tenant, events):
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn, tenant, events, source="test", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE
        )


def _initial():
    return [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net"),
        DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="a"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
            to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            evidence=[Evidence(source="test")],
        ),
    ]


def _kinds(pool, tenant, **kwargs):
    with tenant_session(pool, tenant) as conn:
        events = change_feed(conn, tenant, **kwargs)
    return {(e.entity, e.kind, e.type) for e in events}


def test_first_run_is_all_created(pool, make_tenant):
    tenant = make_tenant()
    _run(pool, tenant, _initial())
    kinds = _kinds(pool, tenant)
    assert ("ci", "created", "vpc") in kinds
    assert ("ci", "created", "subnet") in kinds
    assert ("edge", "created", "CONTAINS") in kinds


def test_change_then_removal_is_reflected(pool, make_tenant):
    tenant = make_tenant()
    _run(pool, tenant, _initial())
    # Rename the subnet, drop the vpc entirely.
    _run(pool, tenant, [DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="b")])

    kinds = _kinds(pool, tenant)
    assert ("ci", "updated", "subnet") in kinds
    assert ("ci", "removed", "vpc") in kinds
    assert ("edge", "removed", "CONTAINS") in kinds
    # The original creations are still within the window.
    assert ("ci", "created", "vpc") in kinds


def test_empty_window_returns_nothing(pool, make_tenant):
    tenant = make_tenant()
    _run(pool, tenant, _initial())
    with tenant_session(pool, tenant) as conn:
        assert change_feed(conn, tenant, days=0) == []


def test_change_feed_is_tenant_scoped(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    _run(pool, a, _initial())
    with tenant_session(pool, b) as conn:
        assert change_feed(conn, b) == []
