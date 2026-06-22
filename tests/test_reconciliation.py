"""Reconciliation versions changed facts, closes absent ones, and is idempotent."""

from __future__ import annotations

from uuid import UUID

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile

CI_SCOPE = frozenset({CIType.vpc, CIType.subnet, CIType.ec2_instance})
EDGE_SCOPE = frozenset({EdgeType.CONTAINS})


def _evidence():
    return [Evidence(source="aws", detail="test")]


def _run(pool, tenant, events):
    with tenant_session(pool, tenant) as conn:
        return reconcile(
            conn, tenant, events, source="aws", ci_types=CI_SCOPE, edge_types=EDGE_SCOPE
        )


def _vpc_and_subnet():
    return [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net"),
        DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="a"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
            to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            evidence=_evidence(),
        ),
    ]


def test_first_run_creates_cis_edges_and_source_keys(pool, make_tenant):
    tenant = make_tenant()
    result = _run(pool, tenant, _vpc_and_subnet())
    assert (result.cis_created, result.edges_written) == (2, 1)

    with tenant_session(pool, tenant) as conn:
        current = {c.external_id for c in CIRepository(conn, tenant).get_current()}
        keys = conn.execute(
            "SELECT source, native_id FROM source_keys ORDER BY native_id"
        ).fetchall()
    assert current == {"vpc-1", "sub-1"}
    assert keys == [("aws", "sub-1"), ("aws", "vpc-1")]


def test_rerun_is_idempotent(pool, make_tenant):
    tenant = make_tenant()
    _run(pool, tenant, _vpc_and_subnet())
    again = _run(pool, tenant, _vpc_and_subnet())
    assert again.cis_created == 0
    assert again.cis_unchanged == 2
    assert again.cis_closed == 0
    assert again.edges_closed == 0


def test_change_versions_and_absence_closes(pool, make_tenant):
    tenant = make_tenant()
    _run(pool, tenant, _vpc_and_subnet())

    with tenant_session(pool, tenant) as conn:
        vpc = CIRepository(conn, tenant).get_current(
            type=CIType.vpc, external_id="vpc-1"
        )[0]

    # Second run: subnet renamed, vpc gone entirely.
    second = _run(
        pool,
        tenant,
        [DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="renamed")],
    )
    assert second.cis_updated == 1  # subnet changed
    assert second.cis_closed == 1  # vpc absent -> closed
    assert second.edges_closed == 1  # CONTAINS edge closed with its endpoint

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        current = {c.external_id for c in repo.get_current()}
        vpc_history = repo.history(vpc.id)
    assert current == {"sub-1"}
    # The vpc is retained in history, just closed — never deleted.
    assert len(vpc_history) == 1 and vpc_history[0].valid_to is not None


def test_reconcile_is_tenant_scoped(pool, make_tenant):
    a, b = make_tenant("A"), make_tenant("B")
    _run(pool, a, _vpc_and_subnet())
    with tenant_session(pool, b) as conn:
        assert CIRepository(conn, b).get_current() == []
        assert EdgeRepository(conn, b).get_current() == []
