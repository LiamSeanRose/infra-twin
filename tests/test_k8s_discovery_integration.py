"""End-to-end and adversarial isolation tests for the Kubernetes connector.

Runs against the local dockerised Postgres + AGE instance (same stack used by all E2E tests).
Uses the same FakeK8sClient as the contract tests — no live cluster, no network.

Covers:
  - AC 26: discover_and_reconcile returns cis_created > 0, edges_written > 0
  - AC 27: connector row exists with type='kubernetes'
  - AC 28: connector_run with status='ok' and >= 1 raw_facts row
  - AC 29: k8s CIs and edges persisted current (valid_to IS NULL), edge provenance present
  - AC 30: AGE graph contains k8s nodes and edges for tenant A
  - AC 31: second reconcile of same fixture is a no-op
  - AC 32: adversarial cross-tenant isolation (tenant B sees none of A's k8s data)
"""

from __future__ import annotations

import psycopg
import pytest

from infra_twin.collectors.k8s import KubernetesConnector
from infra_twin.core_model import CIType, EdgeSource
from infra_twin.db.connector_health import ConnectorRunRepository
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.graph import cypher
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import discover_and_reconcile

# ---------------------------------------------------------------------------
# Import the same fake client from the contract tests to ensure identical data.
# The fake is self-contained in the tests package.
# ---------------------------------------------------------------------------

from test_k8s_connector import (
    CLUSTER_ID,
    CLUSTER_NAME,
    NS_DEFAULT_UID,
    NS_STAGING_UID,
    NS_EMPTY_UID,
    NODE_A_UID,
    NODE_B_UID,
    WORKLOAD_WEB_UID,
    WORKLOAD_NOSELECTOR_UID,
    SVC_WEB_UID,
    SVC_EMPTY_UID,
    POD_A_UID,
    POD_B_UID,
    POD_NONODENAME_UID,
    POD_UNKNOWNNODE_UID,
    POD_NOLABELS_UID,
    POD_STAGING_UID,
    FakeK8sClient,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_connector() -> KubernetesConnector:
    return KubernetesConnector(
        FakeK8sClient(), cluster_id=CLUSTER_ID, cluster_name=CLUSTER_NAME
    )


# ---------------------------------------------------------------------------
# AC 26: discover_and_reconcile returns positive CI and edge counts
# ---------------------------------------------------------------------------


def test_discover_and_reconcile_returns_positive_counts(pool, make_tenant):
    """AC 26: discover_and_reconcile creates CIs and writes edges."""
    tenant = make_tenant("k8s-a")
    result = discover_and_reconcile(pool, tenant, _make_connector())

    assert result.cis_created > 0, f"Expected cis_created > 0, got {result.cis_created}"
    assert result.edges_written > 0, f"Expected edges_written > 0, got {result.edges_written}"


# ---------------------------------------------------------------------------
# AC 27: connector row registered as type 'kubernetes'
# ---------------------------------------------------------------------------


def test_connector_registry_has_kubernetes_type(pool, make_tenant):
    """AC 27: after discover_and_reconcile, a connectors row with type='kubernetes' exists."""
    tenant = make_tenant("k8s-registry")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        registry = ConnectorRegistry(conn, tenant)
        connectors = registry.list()

    k8s_connectors = [c for c in connectors if c.type == "kubernetes"]
    assert k8s_connectors, (
        f"No connector with type='kubernetes' found; got types: {[c.type for c in connectors]}"
    )
    assert k8s_connectors[0].display_name == "kubernetes"


# ---------------------------------------------------------------------------
# AC 28: connector_run recorded with status='ok', >= 1 raw_facts row
# ---------------------------------------------------------------------------


def test_connector_run_ok_and_raw_facts(pool, make_tenant):
    """AC 28: a connector_runs row with source='kubernetes' status='ok' exists,
    and at least one raw_facts row was written for the run."""
    tenant = make_tenant("k8s-run")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        run_repo = ConnectorRunRepository(conn, tenant)
        summaries = run_repo.latest_per_source()

    k8s_runs = [s for s in summaries if s.source == "kubernetes"]
    assert k8s_runs, "No connector_run with source='kubernetes' found"
    assert k8s_runs[0].status == "ok", (
        f"connector_run status expected 'ok', got {k8s_runs[0].status!r}"
    )

    # Check raw_facts rows exist for this tenant and source.
    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("kubernetes",)
        ).fetchone()[0]
    assert count >= 1, f"Expected at least 1 raw_facts row, got {count}"


# ---------------------------------------------------------------------------
# AC 29: k8s CIs persisted current, edges have provenance
# ---------------------------------------------------------------------------


def test_k8s_cis_persisted_current_with_correct_tenant(pool, make_tenant):
    """AC 29a: all expected k8s CI types persisted with valid_to IS NULL and tenant_id == tenant."""
    tenant = make_tenant("k8s-cis")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        for ci_type in (
            CIType.k8s_cluster,
            CIType.k8s_namespace,
            CIType.k8s_node,
            CIType.k8s_workload,
            CIType.k8s_pod,
            CIType.k8s_service,
        ):
            cis = repo.get_current(type=ci_type)
            assert cis, f"No current {ci_type.value} CIs found"
            for ci in cis:
                assert ci.valid_to is None, (
                    f"{ci_type.value} CI {ci.external_id} has valid_to={ci.valid_to}, expected NULL"
                )
                assert ci.tenant_id == tenant, (
                    f"{ci_type.value} CI tenant_id {ci.tenant_id} != expected {tenant}"
                )


def test_k8s_edges_persisted_with_provenance(pool, make_tenant):
    """AC 29b: persisted k8s edges have source, confidence, and non-empty evidence."""
    tenant = make_tenant("k8s-edges")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT source, confidence, evidence FROM edges WHERE valid_to IS NULL",
        ).fetchall()

    assert rows, "No current edges found after k8s reconcile"
    for source, confidence, evidence in rows:
        assert source in ("declared", "inferred"), (
            f"Edge source must be 'declared' or 'inferred'; got {source!r}"
        )
        assert confidence is not None, "Edge confidence must be set"
        assert evidence, "Edge evidence must be non-empty"
        # Each evidence entry must have a source field
        for ev in evidence:
            assert "source" in ev, f"Evidence entry missing 'source' key: {ev!r}"


def test_k8s_specific_cis_external_ids_persisted(pool, make_tenant):
    """AC 29c: the exact seeded external_ids are persisted."""
    tenant = make_tenant("k8s-extids")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        all_cis = repo.get_current()

    external_ids = {ci.external_id for ci in all_cis}
    expected = {
        CLUSTER_ID,
        NS_DEFAULT_UID, NS_STAGING_UID, NS_EMPTY_UID,
        NODE_A_UID, NODE_B_UID,
        WORKLOAD_WEB_UID, WORKLOAD_NOSELECTOR_UID,
        SVC_WEB_UID, SVC_EMPTY_UID,
        POD_A_UID, POD_B_UID, POD_NONODENAME_UID,
        POD_UNKNOWNNODE_UID, POD_NOLABELS_UID, POD_STAGING_UID,
    }
    for uid in expected:
        assert uid in external_ids, f"Expected external_id {uid!r} not found in persisted CIs"


# ---------------------------------------------------------------------------
# AC 30: AGE projection contains k8s nodes and edges
# ---------------------------------------------------------------------------


def test_age_projection_k8s_pods(pool, make_tenant):
    """AC 30a: MATCH (n:k8s_pod) WHERE n.tenant_id = '<A>' RETURN n returns >= 2 rows."""
    tenant = make_tenant("k8s-age-pods")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (n:k8s_pod) WHERE n.tenant_id = '{tenant}' RETURN n",
        )
    assert len(rows) >= 2, (
        f"Expected >= 2 k8s_pod nodes in AGE for tenant {tenant}, got {len(rows)}"
    )


def test_age_projection_cluster_contains_namespace_edges(pool, make_tenant):
    """AC 30b: MATCH (:k8s_cluster)-[r:CONTAINS]->(:k8s_namespace) returns >= 2 rows."""
    tenant = make_tenant("k8s-age-edges")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:k8s_cluster)-[r:CONTAINS]->(:k8s_namespace) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )
    assert len(rows) >= 2, (
        f"Expected >= 2 CONTAINS edges cluster->namespace in AGE, got {len(rows)}"
    )


def test_age_projection_runs_on_edges(pool, make_tenant):
    """AC 30: MATCH (:k8s_pod)-[r:RUNS_ON]->(:k8s_node) returns >= 2 rows."""
    tenant = make_tenant("k8s-age-runs-on")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:k8s_pod)-[r:RUNS_ON]->(:k8s_node) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )
    assert len(rows) >= 2, (
        f"Expected >= 2 RUNS_ON edges in AGE, got {len(rows)}"
    )


def test_age_projection_k8s_cluster_node(pool, make_tenant):
    """AC 30: the cluster node is present in AGE."""
    tenant = make_tenant("k8s-age-cluster")
    discover_and_reconcile(pool, tenant, _make_connector())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (n:k8s_cluster) WHERE n.tenant_id = '{tenant}' RETURN n",
        )
    assert len(rows) == 1, (
        f"Expected exactly 1 k8s_cluster node in AGE, got {len(rows)}"
    )


# ---------------------------------------------------------------------------
# AC 31: second reconcile of same fixture is a no-op
# ---------------------------------------------------------------------------


def test_second_reconcile_is_noop(pool, make_tenant):
    """AC 31: cis_created==0, cis_closed==0, edges_closed==0 on second run of same fixture."""
    tenant = make_tenant("k8s-idempotent")

    # First run — seeds the graph.
    discover_and_reconcile(pool, tenant, _make_connector())

    # Second run — identical fixture; must be a no-op.
    result2 = discover_and_reconcile(pool, tenant, _make_connector())

    assert result2.cis_created == 0, (
        f"Second reconcile should create 0 CIs; got {result2.cis_created}"
    )
    assert result2.cis_closed == 0, (
        f"Second reconcile should close 0 CIs; got {result2.cis_closed}"
    )
    assert result2.edges_closed == 0, (
        f"Second reconcile should close 0 edges; got {result2.edges_closed}"
    )


# ---------------------------------------------------------------------------
# AC 32: adversarial cross-tenant isolation
# ---------------------------------------------------------------------------


def test_cross_tenant_isolation_cis(pool, make_tenant):
    """AC 32a: tenant B sees zero k8s CIs that belong to tenant A."""
    tenant_a = make_tenant("k8s-iso-a")
    tenant_b = make_tenant("k8s-iso-b")

    discover_and_reconcile(pool, tenant_a, _make_connector())

    with tenant_session(pool, tenant_b) as conn:
        repo = CIRepository(conn, tenant_b)
        b_cis = repo.get_current()

    k8s_types = {
        CIType.k8s_cluster,
        CIType.k8s_namespace,
        CIType.k8s_node,
        CIType.k8s_workload,
        CIType.k8s_pod,
        CIType.k8s_service,
    }
    b_k8s = [c for c in b_cis if c.type in k8s_types]
    assert not b_k8s, (
        f"Tenant B should see 0 k8s CIs belonging to A; got {len(b_k8s)}: {b_k8s[:3]}"
    )


def test_cross_tenant_isolation_edges(pool, make_tenant):
    """AC 32b: tenant B sees zero edges written for tenant A."""
    tenant_a = make_tenant("k8s-iso-edge-a")
    tenant_b = make_tenant("k8s-iso-edge-b")

    discover_and_reconcile(pool, tenant_a, _make_connector())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute("SELECT count(*) FROM edges WHERE valid_to IS NULL").fetchone()[0]
    assert count == 0, f"Tenant B should see 0 edges; got {count}"


def test_cross_tenant_isolation_connector_runs(pool, make_tenant):
    """AC 32c: tenant B sees no connector_runs with source='kubernetes'."""
    tenant_a = make_tenant("k8s-iso-run-a")
    tenant_b = make_tenant("k8s-iso-run-b")

    discover_and_reconcile(pool, tenant_a, _make_connector())

    with tenant_session(pool, tenant_b) as conn:
        run_repo = ConnectorRunRepository(conn, tenant_b)
        summaries = run_repo.latest_per_source()

    k8s = [s for s in summaries if s.source == "kubernetes"]
    assert not k8s, f"Tenant B should see no k8s connector_runs; got {k8s}"


def test_cross_tenant_isolation_connector_registry(pool, make_tenant):
    """AC 32d: ConnectorRegistry for tenant B shows no 'kubernetes' connector."""
    tenant_a = make_tenant("k8s-iso-reg-a")
    tenant_b = make_tenant("k8s-iso-reg-b")

    discover_and_reconcile(pool, tenant_a, _make_connector())

    with tenant_session(pool, tenant_b) as conn:
        registry = ConnectorRegistry(conn, tenant_b)
        b_connectors = registry.list()

    k8s = [c for c in b_connectors if c.type == "kubernetes"]
    assert not k8s, (
        f"Tenant B should have no kubernetes connector in registry; got {k8s}"
    )


def test_cross_tenant_isolation_raw_facts(pool, make_tenant):
    """AC 32: tenant B sees zero raw_facts rows written for tenant A's k8s run."""
    tenant_a = make_tenant("k8s-iso-rf-a")
    tenant_b = make_tenant("k8s-iso-rf-b")

    discover_and_reconcile(pool, tenant_a, _make_connector())

    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = %s", ("kubernetes",)
        ).fetchone()[0]
    assert count == 0, f"Tenant B should see 0 kubernetes raw_facts; got {count}"


# ---------------------------------------------------------------------------
# Additional: verify the FakeK8sClient conforms to the K8sClient Protocol
# ---------------------------------------------------------------------------


def test_fake_k8s_client_satisfies_protocol():
    """The FakeK8sClient used in tests must satisfy the K8sClient Protocol."""
    from infra_twin.collectors.k8s import K8sClient
    assert isinstance(FakeK8sClient(), K8sClient)
