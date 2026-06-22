"""The query API: tenant-scoped endpoints for inventory, blast-radius and changes."""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from uuid import UUID, uuid4

import psycopg
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.config import admin_dsn
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile

CI_SCOPE = frozenset({CIType.vpc, CIType.subnet})
EDGE_SCOPE = frozenset({EdgeType.CONTAINS})

_FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "cloudtrail"
_SEED_SOURCE = "test-seed-connector"


def _load_fixture(name: str) -> dict:
    return json.loads((_FIXTURE_DIR / name).read_text())


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


def _seed_vpc_subnet_and_sg(pool, tenant: UUID) -> None:
    """Mirror of the same helper in test_event_intake.py for use in API tests."""
    evidence = [Evidence(source="test", detail="seed")]
    events = [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-0bbb2222", name="net"),
        DiscoveredCI(type=CIType.subnet, external_id="subnet-0aaa1111", name="subnet-a"),
        DiscoveredCI(type=CIType.security_group, external_id="sg-0ccc3333", name="default"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-0bbb2222"),
            to_ref=CIRef(type=CIType.subnet, external_id="subnet-0aaa1111"),
            evidence=evidence,
        ),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-0bbb2222"),
            to_ref=CIRef(type=CIType.security_group, external_id="sg-0ccc3333"),
            evidence=evidence,
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            events,
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.vpc, CIType.subnet, CIType.security_group}),
            edge_types=frozenset({EdgeType.CONTAINS}),
        )


def _seed_ec2_for_terminate(pool, tenant: UUID) -> None:
    """Seed an ec2_instance CI for terminate tests."""
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [DiscoveredCI(type=CIType.ec2_instance, external_id="i-0abc123def456", name="inst")],
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.ec2_instance}),
            edge_types=frozenset(),
        )


def _seed_two_sgs(pool, tenant: UUID, sg_source: str, sg_target: str, vpc_id: str) -> None:
    """Seed two SGs and a CONNECTS_TO edge for revoke tests."""
    evidence = [Evidence(source="test", detail="seed")]
    events = [
        DiscoveredCI(type=CIType.vpc, external_id=vpc_id, name="net"),
        DiscoveredCI(type=CIType.security_group, external_id=sg_source, name="source-sg"),
        DiscoveredCI(type=CIType.security_group, external_id=sg_target, name="target-sg"),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.security_group, external_id=sg_source),
            to_ref=CIRef(type=CIType.security_group, external_id=sg_target),
            evidence=evidence,
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            events,
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.vpc, CIType.security_group}),
            edge_types=frozenset({EdgeType.CONNECTS_TO}),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXPECTED_RESPONSE_KEYS = {
    "connector_run_id",
    "cis_created",
    "cis_updated",
    "cis_unchanged",
    "cis_closed",
    "edges_written",
    "edges_closed",
}


def _count_rows_admin(table: str, tenant: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        return conn.execute(
            f"SELECT count(*) FROM {table} WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]


def _count_rows_tenant(pool, tenant: UUID, table: str) -> int:
    with tenant_session(pool, tenant) as conn:
        return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


# ===========================================================================
# Existing tests (updated to use Bearer auth)
# ===========================================================================


def test_api_endpoints(pool, make_tenant_with_key):
    tenant, api_key = make_tenant_with_key()
    _seed(pool, tenant)
    client = TestClient(create_app(pool=pool))
    headers = _auth(api_key)

    assert client.get("/health").json() == {"status": "ok"}

    cis = client.get("/cis", headers=headers).json()
    by_ext = {c["external_id"]: c for c in cis}
    assert {"vpc-1", "sub-1"} <= by_ext.keys()

    # Missing auth header returns 401 (not 422).
    assert client.get("/cis").status_code == 401

    vpc_id = by_ext["vpc-1"]["id"]
    blast = client.get(f"/cis/{vpc_id}/blast-radius", headers=headers).json()
    assert any(i["type"] == "subnet" and i["distance"] == 1 for i in blast["impacted"])

    changes = client.get("/changes", headers=headers).json()
    assert any(e["kind"] == "created" and e["type"] == "vpc" for e in changes)


def test_api_unknown_ci_is_404(pool, make_tenant_with_key):
    tenant, api_key = make_tenant_with_key()
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        f"/cis/{uuid4()}/blast-radius", headers=_auth(api_key)
    )
    assert resp.status_code == 404


def test_api_is_tenant_isolated(pool, make_tenant_with_key):
    _, key_a = make_tenant_with_key("A")
    _, key_b = make_tenant_with_key("B")
    # Seed data only for tenant A (we need its pool-session tenant_id)
    tenant_a, _ = _resolve_tenant(key_a)
    _seed(pool, tenant_a)
    client = TestClient(create_app(pool=pool))
    assert client.get("/cis", headers=_auth(key_b)).json() == []


def _resolve_tenant(api_key: str) -> tuple[UUID, str]:
    """Look up the tenant_id for an api_key directly via the DB (for test setup)."""
    from infra_twin.db.api_keys import parse_key
    parsed = parse_key(api_key)
    assert parsed is not None
    key_id, _ = parsed
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT tenant_id FROM api_keys WHERE key_id = %s", (key_id,)
        ).fetchone()
    return row[0], api_key


# ===========================================================================
# POST /events/aws — basic response shape and route existence
# ===========================================================================


def test_events_aws_route_exists_and_returns_200(pool, make_tenant_with_key):
    """AC3: POST /events/aws returns 200 with a 7-key JSON object on a valid supported event."""
    tenant, api_key = make_tenant_with_key("api-evt-shape")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == _EXPECTED_RESPONSE_KEYS, (
        f"response keys mismatch: {set(body.keys())}"
    )


def test_events_aws_response_keys_are_exactly_seven(pool, make_tenant_with_key):
    """AC3: response JSON has exactly 7 keys, no extras."""
    tenant, api_key = make_tenant_with_key("api-evt-7keys")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 7


# ===========================================================================
# AC-FEATURE-1 — RunInstances create
# ===========================================================================


def test_run_instances_response_counters(pool, make_tenant_with_key):
    """AC-FEATURE-1: RunInstances returns cis_created==1, edges_written==2."""
    tenant, api_key = make_tenant_with_key("api-run-counters")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["cis_created"] == 1, f"expected cis_created=1, got {body['cis_created']}"
    assert body["edges_written"] == 2, f"expected edges_written=2, got {body['edges_written']}"
    assert body["cis_closed"] == 0
    assert body["edges_closed"] == 0


def test_run_instances_creates_ec2_instance_ci(pool, make_tenant_with_key):
    """AC-FEATURE-1: RunInstances creates exactly one open ec2_instance CI with the correct external_id."""
    tenant, api_key = make_tenant_with_key("api-run-ci")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-0abc123def456"
        )
    assert len(cis) == 1
    assert cis[0].valid_to is None
    assert cis[0].external_id == "i-0abc123def456"


def test_run_instances_sibling_subnet_untouched(pool, make_tenant_with_key):
    """AC-FEATURE-1: after RunInstances POST, sibling subnet-0aaa1111 CI is untouched (same valid_from, valid_to IS NULL)."""
    tenant, api_key = make_tenant_with_key("api-run-sibling")
    _seed_vpc_subnet_and_sg(pool, tenant)

    with tenant_session(pool, tenant) as conn:
        subnet_before = CIRepository(conn, tenant).get_current(
            type=CIType.subnet, external_id="subnet-0aaa1111"
        )
    assert subnet_before, "setup: subnet not seeded"
    original_valid_from = subnet_before[0].valid_from

    client = TestClient(create_app(pool=pool))
    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        subnet_after = CIRepository(conn, tenant).get_current(
            type=CIType.subnet, external_id="subnet-0aaa1111"
        )
    assert len(subnet_after) == 1
    assert subnet_after[0].valid_from == original_valid_from
    assert subnet_after[0].valid_to is None


def test_run_instances_connector_run_id_is_valid_uuid(pool, make_tenant_with_key):
    """AC2/AC3: connector_run_id in the response is a valid UUID string."""
    tenant, api_key = make_tenant_with_key("api-run-runid")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]
    parsed = UUID(run_id_str)
    assert str(parsed) == run_id_str


def test_run_instances_connector_run_id_matches_db_row(pool, make_tenant_with_key):
    """AC2: connector_run_id in the response equals the connector_runs.run_id written to the DB."""
    tenant, api_key = make_tenant_with_key("api-run-dbmatch")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT run_id FROM connector_runs WHERE source = 'aws-events' ORDER BY started_at DESC LIMIT 1"
        ).fetchall()
    assert len(rows) == 1
    db_run_id = str(rows[0][0])
    assert db_run_id == run_id_str, (
        f"response connector_run_id {run_id_str} != DB run_id {db_run_id}"
    )


# ===========================================================================
# AC-FEATURE-2 — TerminateInstances: bitemporal close + run/fact rows
# ===========================================================================


def test_terminate_returns_200_with_cis_closed_one(pool, make_tenant_with_key):
    """AC-FEATURE-2: TerminateInstances POST returns 200 with cis_closed==1."""
    tenant, api_key = make_tenant_with_key("api-term-200")
    _seed_ec2_for_terminate(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("terminate_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["cis_closed"] == 1


def test_terminate_does_not_hard_delete_ci(pool, make_tenant_with_key):
    """AC-FEATURE-2: after TerminateInstances POST, the ec2_instance row still physically exists in the DB with valid_to set."""
    tenant, api_key = make_tenant_with_key("api-term-nodelete")
    _seed_ec2_for_terminate(pool, tenant)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("terminate_instances.json")},
        headers=_auth(api_key),
    )

    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM cis WHERE type = 'ec2_instance' "
            "AND external_id = %s AND tenant_id = %s",
            ("i-0abc123def456", tenant),
        ).fetchone()
    assert row is not None, "ec2_instance row must physically exist (no hard-delete)"
    assert row[0] is not None, "valid_to must be set after TerminateInstances"


def test_terminate_connector_run_written_with_status_ok(pool, make_tenant_with_key):
    """AC-FEATURE-2: after TerminateInstances, exactly one connector_runs row with status ok is written."""
    tenant, api_key = make_tenant_with_key("api-term-runrow")
    _seed_ec2_for_terminate(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("terminate_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT status, source FROM connector_runs WHERE source = 'aws-events'"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "ok"


def test_terminate_raw_facts_written(pool, make_tenant_with_key):
    """AC-FEATURE-2: after TerminateInstances, at least one raw_facts row is written."""
    tenant, api_key = make_tenant_with_key("api-term-rawfacts")
    _seed_ec2_for_terminate(pool, tenant)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("terminate_instances.json")},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = 'aws-events'"
        ).fetchone()[0]
    assert count >= 1


def test_terminate_connector_run_id_matches_response(pool, make_tenant_with_key):
    """AC-FEATURE-2: response connector_run_id equals the aws-events connector_runs.run_id."""
    tenant, api_key = make_tenant_with_key("api-term-runid")
    _seed_ec2_for_terminate(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("terminate_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]

    with tenant_session(pool, tenant) as conn:
        db_run_id = conn.execute(
            "SELECT run_id FROM connector_runs WHERE source = 'aws-events'"
        ).fetchone()[0]
    assert str(db_run_id) == run_id_str


def test_terminate_run_facts_stamped_with_aws_events_connector_id(pool, make_tenant_with_key):
    """AC-FEATURE-2: connector_runs and raw_facts rows are stamped with the aws-events connector_id."""
    tenant, api_key = make_tenant_with_key("api-term-connid")
    _seed_ec2_for_terminate(pool, tenant)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("terminate_instances.json")},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        connector_id = conn.execute(
            "SELECT connector_id FROM connectors WHERE type = 'aws-events'"
        ).fetchone()[0]
        run_connector_id = conn.execute(
            "SELECT connector_id FROM connector_runs WHERE source = 'aws-events'"
        ).fetchone()[0]
        fact_connector_id = conn.execute(
            "SELECT connector_id FROM raw_facts WHERE source = 'aws-events' LIMIT 1"
        ).fetchone()[0]

    assert run_connector_id == connector_id
    assert fact_connector_id == connector_id


# ===========================================================================
# AC-FEATURE-2 (revoke) — RevokeSecurityGroupIngress: bitemporal close
# ===========================================================================


def test_revoke_returns_200_with_edges_closed_one(pool, make_tenant_with_key):
    """AC-FEATURE-2: RevokeSecurityGroupIngress POST returns 200 with edges_closed==1."""
    tenant, api_key = make_tenant_with_key("api-revoke-200")
    _seed_two_sgs(pool, tenant, "sg-0source", "sg-0target", "vpc-0test")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("revoke_sg_ingress_sg_source.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["edges_closed"] == 1


def test_revoke_does_not_hard_delete_edge(pool, make_tenant_with_key):
    """AC-FEATURE-2: after RevokeSecurityGroupIngress, the CONNECTS_TO edge row still exists with valid_to set."""
    tenant, api_key = make_tenant_with_key("api-revoke-nodelete")
    _seed_two_sgs(pool, tenant, "sg-0source", "sg-0target", "vpc-0test2")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("revoke_sg_ingress_sg_source.json")},
        headers=_auth(api_key),
    )

    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM edges WHERE type = 'CONNECTS_TO' AND tenant_id = %s",
            (tenant,),
        ).fetchone()
    assert row is not None, "CONNECTS_TO edge row must physically exist (no hard-delete)"
    assert row[0] is not None, "valid_to must be set after RevokeSecurityGroupIngress"


# ===========================================================================
# AC-FEATURE-3 — Unsupported event => 422, no writes
# ===========================================================================


def test_unsupported_event_returns_422(pool, make_tenant_with_key):
    """AC-FEATURE-3 / E1: an unsupported eventName returns HTTP 422."""
    tenant, api_key = make_tenant_with_key("api-unsupported-422")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("unsupported_event.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_unsupported_event_detail_mentions_event_name(pool, make_tenant_with_key):
    """AC-FEATURE-3 / E1: 422 detail for unsupported event is descriptive and mentions the offending eventName."""
    tenant, api_key = make_tenant_with_key("api-unsupported-detail")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("unsupported_event.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422
    body = resp.json()
    detail = body.get("detail", "")
    assert "DescribeInstances" in detail or "unsupported" in detail.lower(), (
        f"detail should mention the event name or 'unsupported': {detail}"
    )


def test_unsupported_event_no_connector_runs_written(pool, make_tenant_with_key):
    """AC-FEATURE-3 / E1: after unsupported event 422, zero connector_runs rows are written."""
    tenant, api_key = make_tenant_with_key("api-unsupported-norun")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("unsupported_event.json")},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "connector_runs") == 0


def test_unsupported_event_no_raw_facts_written(pool, make_tenant_with_key):
    """AC-FEATURE-3 / E1: after unsupported event 422, zero raw_facts rows are written."""
    tenant, api_key = make_tenant_with_key("api-unsupported-nofacts")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("unsupported_event.json")},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "raw_facts") == 0


def test_unsupported_event_no_cis_written(pool, make_tenant_with_key):
    """AC-FEATURE-3 / E1: after unsupported event 422, zero cis rows are written."""
    tenant, api_key = make_tenant_with_key("api-unsupported-noci")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("unsupported_event.json")},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "cis") == 0


def test_unsupported_event_no_edges_written(pool, make_tenant_with_key):
    """AC-FEATURE-3 / E1: after unsupported event 422, zero edge rows are written."""
    tenant, api_key = make_tenant_with_key("api-unsupported-noedge")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("unsupported_event.json")},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "edges") == 0


# ===========================================================================
# AC-FEATURE-4 — Adversarial tenant isolation
# ===========================================================================


def test_tenant_b_sees_no_cis_from_tenant_a_via_get_cis(pool, make_tenant_with_key):
    """AC-FEATURE-4 / E12: GET /cis under tenant B returns [] after a RunInstances POST under tenant A."""
    tenant_a, key_a = make_tenant_with_key("api-iso-ci-A")
    _, key_b = make_tenant_with_key("api-iso-ci-B")
    _seed_vpc_subnet_and_sg(pool, tenant_a)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(key_a),
    )

    resp_b = client.get("/cis", headers=_auth(key_b))
    assert resp_b.status_code == 200
    assert resp_b.json() == [], "tenant B must see no CIs after tenant A's RunInstances POST"


def test_tenant_b_sees_no_cis_rls_scoped(pool, make_tenant_with_key):
    """AC-FEATURE-4 / E12: tenant B's RLS-scoped session sees zero of tenant A's CIs."""
    tenant_a, key_a = make_tenant_with_key("api-iso-rls-ci-A")
    tenant_b, key_b = make_tenant_with_key("api-iso-rls-ci-B")
    _seed_vpc_subnet_and_sg(pool, tenant_a)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(key_a),
    )

    with tenant_session(pool, tenant_b) as conn:
        b_cis = CIRepository(conn, tenant_b).get_current()
    assert b_cis == []


def test_tenant_b_sees_no_edges_rls_scoped(pool, make_tenant_with_key):
    """AC-FEATURE-4: tenant B's RLS session sees zero of tenant A's edges."""
    tenant_a, key_a = make_tenant_with_key("api-iso-rls-edge-A")
    tenant_b, key_b = make_tenant_with_key("api-iso-rls-edge-B")
    _seed_vpc_subnet_and_sg(pool, tenant_a)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(key_a),
    )

    with tenant_session(pool, tenant_b) as conn:
        b_edges = EdgeRepository(conn, tenant_b).get_current()
    assert b_edges == []


def test_tenant_b_sees_no_connector_runs_from_tenant_a(pool, make_tenant_with_key):
    """AC-FEATURE-4: tenant B sees zero connector_runs rows created by tenant A's POST."""
    tenant_a, key_a = make_tenant_with_key("api-iso-rls-run-A")
    tenant_b, key_b = make_tenant_with_key("api-iso-rls-run-B")
    _seed_vpc_subnet_and_sg(pool, tenant_a)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(key_a),
    )

    assert _count_rows_tenant(pool, tenant_a, "connector_runs") == 1
    assert _count_rows_tenant(pool, tenant_b, "connector_runs") == 0


def test_tenant_b_graph_not_mutated_by_tenant_a_post(pool, make_tenant_with_key):
    """AC-FEATURE-4: posting a RunInstances event under tenant A does not create or mutate any row visible to tenant B."""
    tenant_a, key_a = make_tenant_with_key("api-iso-mutate-A")
    tenant_b, key_b = make_tenant_with_key("api-iso-mutate-B")
    _seed_vpc_subnet_and_sg(pool, tenant_a)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(key_a),
    )

    # B should have nothing across all tenant-data tables.
    for table in ("cis", "edges", "connector_runs", "raw_facts", "connectors"):
        count = _count_rows_tenant(pool, tenant_b, table)
        assert count == 0, f"tenant B should see 0 rows in {table}, got {count}"


# ===========================================================================
# E2 — Missing required fields in record => 422
# ===========================================================================


def test_missing_event_name_returns_422(pool, make_tenant_with_key):
    """E2: record missing eventName returns 422."""
    tenant, api_key = make_tenant_with_key("api-e2-name")
    client = TestClient(create_app(pool=pool))

    record = {
        "eventID": "evt-001",
        "eventTime": "2024-03-10T14:22:00Z",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
    }
    resp = client.post(
        "/events/aws",
        json={"record": record},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_missing_event_id_returns_422(pool, make_tenant_with_key):
    """E2: record missing eventID returns 422."""
    tenant, api_key = make_tenant_with_key("api-e2-id")
    client = TestClient(create_app(pool=pool))

    record = {
        "eventName": "RunInstances",
        "eventTime": "2024-03-10T14:22:00Z",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "requestParameters": {},
        "responseElements": {"instancesSet": {"items": []}},
    }
    resp = client.post(
        "/events/aws",
        json={"record": record},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_missing_event_time_returns_422(pool, make_tenant_with_key):
    """E2: record missing eventTime returns 422 (parse_event raises ValueError)."""
    tenant, api_key = make_tenant_with_key("api-e2-time")
    client = TestClient(create_app(pool=pool))

    record = {
        "eventName": "RunInstances",
        "eventID": "evt-001",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "requestParameters": {},
        "responseElements": {"instancesSet": {"items": []}},
    }
    resp = client.post(
        "/events/aws",
        json={"record": record},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


# ===========================================================================
# E3 — Malformed item payload => 422
# ===========================================================================


def test_malformed_run_instances_item_returns_422(pool, make_tenant_with_key):
    """E3: RunInstances item missing instanceId returns 422."""
    tenant, api_key = make_tenant_with_key("api-e3-malformed")
    client = TestClient(create_app(pool=pool))

    record = {
        "eventName": "RunInstances",
        "eventID": "evt-bad-001",
        "eventTime": "2024-03-10T14:22:00Z",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "requestParameters": {"instanceType": "t3.micro", "minCount": 1, "maxCount": 1},
        "responseElements": {
            "instancesSet": {
                "items": [
                    {
                        # missing instanceId intentionally
                        "instanceType": "t3.micro",
                        "subnetId": "subnet-0aaa1111",
                        "vpcId": "vpc-0bbb2222",
                        "currentState": {"code": 0, "name": "pending"},
                        "groupSet": {"items": []},
                    }
                ]
            }
        },
    }
    resp = client.post(
        "/events/aws",
        json={"record": record},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_malformed_event_no_rows_written(pool, make_tenant_with_key):
    """E3: after malformed payload 422, no rows are written to the DB."""
    tenant, api_key = make_tenant_with_key("api-e3-norows")
    client = TestClient(create_app(pool=pool))

    record = {
        "eventName": "RunInstances",
        "eventID": "evt-bad-002",
        "eventTime": "2024-03-10T14:22:00Z",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "requestParameters": {},
        "responseElements": {
            "instancesSet": {
                "items": [{"instanceType": "t3.micro"}]  # missing instanceId
            }
        },
    }
    client.post(
        "/events/aws",
        json={"record": record},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "cis") == 0
    assert _count_rows_tenant(pool, tenant, "connector_runs") == 0


# ===========================================================================
# E5 — Unresolved edge endpoint => 422, transaction rolled back
# ===========================================================================


def test_unresolved_endpoint_returns_422(pool, make_tenant_with_key):
    """E5: RunInstances without pre-seeded subnet/sg returns 422 (apply_event_delta raises ValueError)."""
    tenant, api_key = make_tenant_with_key("api-e5-unresolved")
    # Do NOT seed — edge endpoints unresolvable
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_unresolved_endpoint_detail_mentions_unresolved(pool, make_tenant_with_key):
    """E5: 422 detail for unresolved endpoint mentions 'unresolved'."""
    tenant, api_key = make_tenant_with_key("api-e5-detail")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422
    detail = resp.json().get("detail", "")
    assert "unresolved" in detail.lower(), f"expected 'unresolved' in detail: {detail}"


def test_unresolved_endpoint_no_ci_written(pool, make_tenant_with_key):
    """E5: after unresolved-endpoint 422, the transaction rolled back — no CI row written."""
    tenant, api_key = make_tenant_with_key("api-e5-noci")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "cis") == 0


def test_unresolved_endpoint_no_run_written(pool, make_tenant_with_key):
    """E5: after unresolved-endpoint 422, no connector_runs row is written (rollback)."""
    tenant, api_key = make_tenant_with_key("api-e5-norun")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "connector_runs") == 0


def test_unresolved_endpoint_no_raw_facts_written(pool, make_tenant_with_key):
    """E5: after unresolved-endpoint 422, no raw_facts rows are written (rollback)."""
    tenant, api_key = make_tenant_with_key("api-e5-nofacts")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )

    assert _count_rows_tenant(pool, tenant, "raw_facts") == 0


# ===========================================================================
# Auth errors (replaces old E6/E7 X-Tenant-Id tests)
# ===========================================================================


def test_missing_auth_header_returns_401(pool):
    """Missing Authorization header returns 401 (not 422)."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
    )
    assert resp.status_code == 401


def test_bogus_api_key_returns_401(pool):
    """Authorization: Bearer with a bogus key returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers={"Authorization": "Bearer itw_bogus.bogus"},
    )
    assert resp.status_code == 401


# ===========================================================================
# E8 — Missing/empty/non-object request body => 422 (FastAPI body validation)
# ===========================================================================


def test_missing_record_key_returns_422(pool, make_tenant_with_key):
    """E8: body missing the 'record' key returns 422."""
    tenant, api_key = make_tenant_with_key("api-e8-norecord")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"not_record": {}},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_empty_body_returns_422(pool, make_tenant_with_key):
    """E8: empty JSON body {} returns 422."""
    tenant, api_key = make_tenant_with_key("api-e8-empty")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_non_object_record_returns_422(pool, make_tenant_with_key):
    """E8: 'record' set to a string (non-dict) returns 422."""
    tenant, api_key = make_tenant_with_key("api-e8-nonobj")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": "not-a-dict"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


# ===========================================================================
# E9 — Terminate/Revoke non-existent => 200 with zero close counters
# ===========================================================================


def test_terminate_non_existent_ci_returns_200_zero_closed(pool, make_tenant_with_key):
    """E9: terminating an ec2_instance that does not exist returns 200 with cis_closed==0."""
    tenant, api_key = make_tenant_with_key("api-e9-term-noop")
    # No ec2_instance seeded
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("terminate_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["cis_closed"] == 0


def test_revoke_non_existent_edge_returns_200_zero_closed(pool, make_tenant_with_key):
    """E9: revoking an edge that does not exist returns 200 with edges_closed==0."""
    tenant, api_key = make_tenant_with_key("api-e9-revoke-noop")
    # No SGs or edges seeded
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("revoke_sg_ingress_sg_source.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    assert resp.json()["edges_closed"] == 0


# ===========================================================================
# E10 — Repeated identical RunInstances POST (idempotency / distinct run ids)
# ===========================================================================


def test_repeated_run_instances_second_call_returns_cis_unchanged(pool, make_tenant_with_key):
    """E10: second RunInstances POST for the same instance returns cis_unchanged rather than cis_created."""
    tenant, api_key = make_tenant_with_key("api-e10-repeat")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    first = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert first.status_code == 200
    assert first.json()["cis_created"] == 1

    second = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert second.status_code == 200
    # Second call: CI already exists, so cis_created should be 0
    assert second.json()["cis_created"] == 0


def test_repeated_run_instances_distinct_run_ids(pool, make_tenant_with_key):
    """E10: each RunInstances POST produces a distinct connector_run_id."""
    tenant, api_key = make_tenant_with_key("api-e10-runids")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    first = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    second = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["connector_run_id"] != second.json()["connector_run_id"]


def test_repeated_run_instances_single_connector_row(pool, make_tenant_with_key):
    """E10: two RunInstances POSTs produce exactly one aws-events connector row (idempotent register)."""
    tenant, api_key = make_tenant_with_key("api-e10-connrow")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connectors WHERE type = 'aws-events'"
        ).fetchone()[0]
    assert count == 1


# ===========================================================================
# E11 — eventTime with explicit offset (no Z)
# ===========================================================================


def test_event_time_with_explicit_offset_returns_200(pool, make_tenant_with_key):
    """E11: an eventTime with an explicit UTC offset (not Z) is accepted and the call succeeds."""
    tenant, api_key = make_tenant_with_key("api-e11-offset")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    record = dict(_load_fixture("run_instances.json"))
    record["eventTime"] = "2024-03-10T14:22:00+00:00"

    resp = client.post(
        "/events/aws",
        json={"record": record},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200


# ===========================================================================
# AC9 — eventTime is used as observed_at for raw_facts
# ===========================================================================


def test_event_time_used_as_observed_at_in_raw_facts(pool, make_tenant_with_key):
    """AC9: the eventTime '2024-03-10T14:22:00Z' from run_instances.json is stored as observed_at in raw_facts (truncated to seconds)."""
    tenant, api_key = make_tenant_with_key("api-ac9-obs")
    _seed_vpc_subnet_and_sg(pool, tenant)
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/events/aws",
        json={"record": _load_fixture("run_instances.json")},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    expected_obs = datetime(2024, 3, 10, 14, 22, 0, tzinfo=timezone.utc)

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT observed_at FROM raw_facts WHERE source = 'aws-events'"
        ).fetchall()

    assert len(rows) > 0
    for row in rows:
        stored = row[0]
        if stored.tzinfo is None:
            stored = stored.replace(tzinfo=timezone.utc)
        assert stored.replace(microsecond=0) == expected_obs, (
            f"observed_at {stored} does not match expected {expected_obs}"
        )
