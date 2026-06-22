"""Per-tenant connector registry tests.

Covers every test case from spec §8 and edge cases from spec §6:

Registry repository (tests 1-8):
1. register returns a Connector with UUID connector_id, the given fields, enabled=True, and a created_at.
2. register is idempotent: same (type, display_name) twice -> same connector_id, count==1.
3. register with differing config on second call does NOT overwrite the first config.
4. register(config=None) stores {}.
5. list returns all tenant connectors ordered by (type, display_name).
6. get returns the connector for a valid id and None for unknown id.
7. resolve_or_register creates on first call and returns same row on second call.
8. set_enabled(id, False) then set_enabled(id, True) flips enabled; set_enabled(unknown_id) -> None.

REST endpoints (tests 9-14):
9. POST /connectors returns 201 with the object and exactly the §2.3 keys (no tenant_id).
10. POST /connectors twice with same type+display_name -> both 201, same connector_id.
11. GET /connectors returns {"connectors": []} for a fresh tenant; ordered list after registration.
12. POST /connectors/{id}/disable -> 200, enabled=false; then /enable -> 200, enabled=true.
13. POST /connectors/{unknown_id}/enable -> 404 with {"detail": "Connector not found"}.
14. Missing X-Tenant-Id -> 422; malformed X-Tenant-Id -> 400.

discover_and_reconcile linkage (tests 15-19):
15. After successful discover_and_reconcile, a connectors row exists and connector_runs.connector_id equals it.
16. After successful run, every raw_facts row for that source has connector_id equal to the registry connector's id.
17. Two successive runs reuse a single connectors row; both runs' connector_id equals it.
18. Failed run still produces a connectors row and a run row stamped with connector_id; zero raw_facts.
19. Direct start(src) / record(src, obs, payloads) calls without connector_id write NULL connector_id.

Adversarial tenant isolation (tests 20-23):
20. Tenant B's list() / GET /connectors returns none of tenant A's connectors.
21. Bare pool connection (no GUC) sees count(*)==0 on connectors.
22. Cross-tenant INSERT stamping B's tenant_id under A's session raises psycopg.Error.
23. Tenant B calling set_enabled(A_connector_id) returns None; POST /connectors/{A_id}/disable under B -> 404.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterator
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.connector_health import ConnectorRunRepository, RawFactRepository
from infra_twin.db.connectors import Connector, ConnectorRegistry
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import discover_and_reconcile


# ---------------------------------------------------------------------------
# Minimal fake connectors (mirrors test_connector_health.py style)
# ---------------------------------------------------------------------------


class _FakeConnector:
    """A connector emitting a fixed set of known events."""

    source: str = "fake-aws"
    ci_types: frozenset = frozenset({CIType.vpc, CIType.subnet})
    edge_types: frozenset = frozenset({EdgeType.CONTAINS})

    def __init__(self, events=None):
        self._events = events or [
            DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net"),
            DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="a"),
            DiscoveredEdge(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
                evidence=[Evidence(source="test")],
            ),
        ]

    def discover(self) -> Iterator:
        yield from self._events


class _EmptyConnector:
    """A connector that emits zero events."""

    source: str = "empty-source"
    ci_types: frozenset = frozenset({CIType.vpc})
    edge_types: frozenset = frozenset()

    def discover(self) -> Iterator:
        return iter([])


class _FailingConnector:
    """A connector whose discover() raises immediately."""

    source: str = "failing-source"
    ci_types: frozenset = frozenset({CIType.vpc})
    edge_types: frozenset = frozenset()

    def __init__(self, exc=None):
        self._exc = exc or RuntimeError("discovery exploded")

    def discover(self) -> Iterator:
        raise self._exc
        yield  # make it a generator (unreachable)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _count_connectors(pool, tenant) -> int:
    """Count connectors rows visible to the tenant (via RLS)."""
    with tenant_session(pool, tenant) as conn:
        return conn.execute("SELECT count(*) FROM connectors").fetchone()[0]


def _get_run_connector_id(pool, tenant, source) -> UUID | None:
    """Fetch connector_id from the most recent connector_runs row for (tenant, source)."""
    with tenant_session(pool, tenant) as conn:
        row = conn.execute(
            "SELECT connector_id FROM connector_runs WHERE source=%s "
            "ORDER BY started_at DESC NULLS LAST LIMIT 1",
            (source,),
        ).fetchone()
    return row[0] if row else None


def _get_distinct_fact_connector_ids(pool, tenant, source) -> set:
    """Fetch distinct connector_id values from raw_facts for (tenant, source)."""
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT DISTINCT connector_id FROM raw_facts WHERE source=%s",
            (source,),
        ).fetchall()
    return {row[0] for row in rows}


def _get_all_run_connector_ids(pool, tenant, source) -> list:
    """Fetch connector_id from all connector_runs rows for (tenant, source)."""
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT connector_id FROM connector_runs WHERE source=%s "
            "ORDER BY started_at ASC",
            (source,),
        ).fetchall()
    return [row[0] for row in rows]


_EXPECTED_CONNECTOR_KEYS = {"connector_id", "type", "display_name", "config", "enabled", "created_at"}


# ===========================================================================
# 1. REGISTRY REPOSITORY — test cases 1-8
# ===========================================================================


def test_register_returns_connector_with_correct_fields(pool, make_tenant):
    """Test case 1: register returns a Connector with UUID connector_id, given fields,
    enabled=True default, and a non-None created_at."""
    tenant = make_tenant("reg-1")
    with tenant_session(pool, tenant) as conn:
        c = ConnectorRegistry(conn, tenant).register(
            type="aws", display_name="prod-aws", config={"region": "us-east-1"}
        )

    assert isinstance(c, Connector)
    assert isinstance(c.connector_id, UUID)
    assert c.type == "aws"
    assert c.display_name == "prod-aws"
    assert c.config == {"region": "us-east-1"}
    assert c.enabled is True
    assert c.created_at is not None
    assert isinstance(c.created_at, datetime)
    assert c.tenant_id == tenant


def test_register_is_idempotent_same_connector_id(pool, make_tenant):
    """Test case 2: registering the same (type, display_name) twice returns the same connector_id."""
    tenant = make_tenant("reg-2")
    with tenant_session(pool, tenant) as conn:
        first = ConnectorRegistry(conn, tenant).register(type="aws", display_name="acct-1")

    with tenant_session(pool, tenant) as conn:
        second = ConnectorRegistry(conn, tenant).register(type="aws", display_name="acct-1")

    assert first.connector_id == second.connector_id


def test_register_is_idempotent_no_duplicate_rows(pool, make_tenant):
    """Test case 2: registering the same (type, display_name) twice creates only one DB row."""
    tenant = make_tenant("reg-2b")
    with tenant_session(pool, tenant) as conn:
        ConnectorRegistry(conn, tenant).register(type="aws", display_name="acct-1")

    with tenant_session(pool, tenant) as conn:
        ConnectorRegistry(conn, tenant).register(type="aws", display_name="acct-1")

    count = _count_connectors(pool, tenant)
    assert count == 1


def test_register_does_not_overwrite_config_on_second_call(pool, make_tenant):
    """Test case 3: second register call with different config does NOT overwrite first config."""
    tenant = make_tenant("reg-3")
    original_config = {"region": "us-east-1", "account_id": "111111111111"}

    with tenant_session(pool, tenant) as conn:
        first = ConnectorRegistry(conn, tenant).register(
            type="aws", display_name="prod", config=original_config
        )

    with tenant_session(pool, tenant) as conn:
        second = ConnectorRegistry(conn, tenant).register(
            type="aws", display_name="prod", config={"region": "eu-west-1"}
        )

    # The second call must return the original config unchanged.
    assert second.config == original_config
    assert second.connector_id == first.connector_id


def test_register_config_none_stores_empty_dict(pool, make_tenant):
    """Test case 4: register(config=None) stores {} (not NULL)."""
    tenant = make_tenant("reg-4")
    with tenant_session(pool, tenant) as conn:
        c = ConnectorRegistry(conn, tenant).register(
            type="gcp", display_name="proj-1", config=None
        )

    assert c.config == {}
    # Also verify the DB value round-trips.
    with tenant_session(pool, tenant) as conn:
        fetched = ConnectorRegistry(conn, tenant).get(c.connector_id)
    assert fetched is not None
    assert fetched.config == {}


def test_list_returns_all_connectors_ordered(pool, make_tenant):
    """Test case 5: list returns all tenant connectors ordered by (type, display_name) asc."""
    tenant = make_tenant("reg-5")
    registrations = [
        ("aws", "z-account"),
        ("azure", "a-subscription"),
        ("aws", "a-account"),
        ("k8s", "cluster-prod"),
    ]
    with tenant_session(pool, tenant) as conn:
        registry = ConnectorRegistry(conn, tenant)
        for typ, name in registrations:
            registry.register(type=typ, display_name=name)

    with tenant_session(pool, tenant) as conn:
        connectors = ConnectorRegistry(conn, tenant).list()

    assert len(connectors) == 4
    order = [(c.type, c.display_name) for c in connectors]
    assert order == sorted(order), f"not ordered: {order}"
    # Verify the specific expected order.
    assert order == [
        ("aws", "a-account"),
        ("aws", "z-account"),
        ("azure", "a-subscription"),
        ("k8s", "cluster-prod"),
    ]


def test_get_returns_connector_by_id(pool, make_tenant):
    """Test case 6a: get returns the correct connector when id is valid."""
    tenant = make_tenant("reg-6a")
    with tenant_session(pool, tenant) as conn:
        created = ConnectorRegistry(conn, tenant).register(type="aws", display_name="test")

    with tenant_session(pool, tenant) as conn:
        fetched = ConnectorRegistry(conn, tenant).get(created.connector_id)

    assert fetched is not None
    assert fetched.connector_id == created.connector_id
    assert fetched.type == "aws"
    assert fetched.display_name == "test"


def test_get_returns_none_for_unknown_id(pool, make_tenant):
    """Test case 6b: get returns None when the id does not exist."""
    tenant = make_tenant("reg-6b")
    unknown_id = uuid.uuid4()

    with tenant_session(pool, tenant) as conn:
        result = ConnectorRegistry(conn, tenant).get(unknown_id)

    assert result is None


def test_resolve_or_register_creates_on_first_call(pool, make_tenant):
    """Test case 7a: resolve_or_register creates a row on the first call."""
    tenant = make_tenant("reg-7a")
    with tenant_session(pool, tenant) as conn:
        c = ConnectorRegistry(conn, tenant).resolve_or_register(
            type="aws", display_name="aws"
        )

    assert isinstance(c, Connector)
    assert isinstance(c.connector_id, UUID)
    assert _count_connectors(pool, tenant) == 1


def test_resolve_or_register_returns_same_row_on_second_call(pool, make_tenant):
    """Test case 7b: resolve_or_register returns the same connector_id on the second call."""
    tenant = make_tenant("reg-7b")
    with tenant_session(pool, tenant) as conn:
        first = ConnectorRegistry(conn, tenant).resolve_or_register(
            type="aws", display_name="aws"
        )

    with tenant_session(pool, tenant) as conn:
        second = ConnectorRegistry(conn, tenant).resolve_or_register(
            type="aws", display_name="aws"
        )

    assert first.connector_id == second.connector_id
    assert _count_connectors(pool, tenant) == 1


def test_resolve_or_register_creates_with_empty_config(pool, make_tenant):
    """resolve_or_register creates a connector with empty config and enabled=True."""
    tenant = make_tenant("reg-7c")
    with tenant_session(pool, tenant) as conn:
        c = ConnectorRegistry(conn, tenant).resolve_or_register(
            type="k8s", display_name="k8s"
        )

    assert c.config == {}
    assert c.enabled is True


def test_set_enabled_flips_enabled_state(pool, make_tenant):
    """Test case 8a: set_enabled(id, False) then set_enabled(id, True) flips enabled
    and returns the updated record each time."""
    tenant = make_tenant("reg-8a")
    with tenant_session(pool, tenant) as conn:
        c = ConnectorRegistry(conn, tenant).register(type="aws", display_name="flip-me")
    assert c.enabled is True

    with tenant_session(pool, tenant) as conn:
        disabled = ConnectorRegistry(conn, tenant).set_enabled(c.connector_id, False)
    assert disabled is not None
    assert disabled.enabled is False
    assert disabled.connector_id == c.connector_id

    with tenant_session(pool, tenant) as conn:
        re_enabled = ConnectorRegistry(conn, tenant).set_enabled(c.connector_id, True)
    assert re_enabled is not None
    assert re_enabled.enabled is True
    assert re_enabled.connector_id == c.connector_id


def test_set_enabled_unknown_id_returns_none(pool, make_tenant):
    """Test case 8b: set_enabled with an unknown id returns None."""
    tenant = make_tenant("reg-8b")
    unknown_id = uuid.uuid4()

    with tenant_session(pool, tenant) as conn:
        result = ConnectorRegistry(conn, tenant).set_enabled(unknown_id, False)

    assert result is None


# ===========================================================================
# 2. REST ENDPOINTS — test cases 9-14
# ===========================================================================


def test_post_connectors_returns_201_with_correct_keys(pool, make_tenant_with_key):
    """Test case 9: POST /connectors returns 201 with exactly the §2.3 keys (no tenant_id)."""
    _, api_key = make_tenant_with_key("api-9")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "prod-aws", "config": {"account": "123"}, "enabled": True},
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert set(body.keys()) == _EXPECTED_CONNECTOR_KEYS
    assert "tenant_id" not in body
    assert body["type"] == "aws"
    assert body["display_name"] == "prod-aws"
    assert body["config"] == {"account": "123"}
    assert body["enabled"] is True
    assert UUID(body["connector_id"])  # must be a valid UUID string
    assert body["created_at"] is not None


def test_post_connectors_twice_returns_same_connector_id(pool, make_tenant_with_key):
    """Test case 10: POST /connectors twice with same type+display_name -> both 201, same connector_id."""
    _, api_key = make_tenant_with_key("api-10")
    client = TestClient(create_app(pool=pool))
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {"type": "aws", "display_name": "prod"}

    resp1 = client.post("/connectors", json=payload, headers=headers)
    resp2 = client.post("/connectors", json=payload, headers=headers)

    assert resp1.status_code == 201
    assert resp2.status_code == 201
    assert resp1.json()["connector_id"] == resp2.json()["connector_id"]


def test_get_connectors_empty_for_fresh_tenant(pool, make_tenant_with_key):
    """Test case 11a: GET /connectors returns {"connectors": []} for a fresh tenant."""
    _, api_key = make_tenant_with_key("api-11a")
    client = TestClient(create_app(pool=pool))

    resp = client.get("/connectors", headers={"Authorization": f"Bearer {api_key}"})

    assert resp.status_code == 200
    assert resp.json() == {"connectors": []}


def test_get_connectors_returns_registered_connectors_ordered(pool, make_tenant_with_key):
    """Test case 11b: GET /connectors returns registered connectors ordered by type, display_name."""
    _, api_key = make_tenant_with_key("api-11b")
    client = TestClient(create_app(pool=pool))
    headers = {"Authorization": f"Bearer {api_key}"}

    # Register in non-sorted order.
    for typ, name in [("gcp", "proj-b"), ("aws", "acct-z"), ("aws", "acct-a")]:
        client.post("/connectors", json={"type": typ, "display_name": name}, headers=headers)

    resp = client.get("/connectors", headers=headers)
    assert resp.status_code == 200
    connectors = resp.json()["connectors"]
    assert len(connectors) == 3

    order = [(c["type"], c["display_name"]) for c in connectors]
    assert order == sorted(order)
    assert order == [("aws", "acct-a"), ("aws", "acct-z"), ("gcp", "proj-b")]


def test_post_disable_then_enable_connector(pool, make_tenant_with_key):
    """Test case 12: POST /connectors/{id}/disable -> 200, enabled=false; then /enable -> 200, enabled=true."""
    _, api_key = make_tenant_with_key("api-12")
    client = TestClient(create_app(pool=pool))
    headers = {"Authorization": f"Bearer {api_key}"}

    # Register a connector.
    reg = client.post(
        "/connectors", json={"type": "aws", "display_name": "toggle-test"}, headers=headers
    )
    connector_id = reg.json()["connector_id"]

    # Disable.
    disable_resp = client.post(f"/connectors/{connector_id}/disable", headers=headers)
    assert disable_resp.status_code == 200
    assert disable_resp.json()["enabled"] is False
    assert set(disable_resp.json().keys()) == _EXPECTED_CONNECTOR_KEYS
    assert "tenant_id" not in disable_resp.json()

    # Enable.
    enable_resp = client.post(f"/connectors/{connector_id}/enable", headers=headers)
    assert enable_resp.status_code == 200
    assert enable_resp.json()["enabled"] is True
    assert set(enable_resp.json().keys()) == _EXPECTED_CONNECTOR_KEYS


def test_enable_unknown_connector_returns_404(pool, make_tenant_with_key):
    """Test case 13a: POST /connectors/{unknown_id}/enable -> 404 with correct detail."""
    _, api_key = make_tenant_with_key("api-13a")
    client = TestClient(create_app(pool=pool))
    unknown_id = uuid.uuid4()

    resp = client.post(
        f"/connectors/{unknown_id}/enable",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert resp.status_code == 404
    assert resp.json() == {"detail": "Connector not found"}


def test_disable_unknown_connector_returns_404(pool, make_tenant_with_key):
    """Test case 13b: POST /connectors/{unknown_id}/disable -> 404 with correct detail."""
    _, api_key = make_tenant_with_key("api-13b")
    client = TestClient(create_app(pool=pool))
    unknown_id = uuid.uuid4()

    resp = client.post(
        f"/connectors/{unknown_id}/disable",
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert resp.status_code == 404
    assert resp.json() == {"detail": "Connector not found"}


def test_missing_auth_header_returns_401(pool):
    """Missing Authorization header -> 401."""
    client = TestClient(create_app(pool=pool))

    resp = client.get("/connectors")

    assert resp.status_code == 401


def test_bogus_api_key_returns_401(pool):
    """Bogus Bearer token -> 401."""
    client = TestClient(create_app(pool=pool))

    resp = client.get("/connectors", headers={"Authorization": "Bearer itw_bogus.bogus"})

    assert resp.status_code == 401


def test_post_connectors_missing_auth_returns_401(pool):
    """POST /connectors with missing Authorization -> 401."""
    client = TestClient(create_app(pool=pool))

    resp = client.post("/connectors", json={"type": "aws", "display_name": "x"})

    assert resp.status_code == 401


def test_connector_response_never_contains_tenant_id(pool, make_tenant_with_key):
    """All connector endpoints exclude tenant_id from the response body (spec §2.3, AC 14, edge case 20)."""
    _, api_key = make_tenant_with_key("api-noleak")
    client = TestClient(create_app(pool=pool))
    headers = {"Authorization": f"Bearer {api_key}"}

    post_resp = client.post(
        "/connectors", json={"type": "aws", "display_name": "noleak"}, headers=headers
    )
    connector_id = post_resp.json()["connector_id"]
    assert "tenant_id" not in post_resp.json()

    list_resp = client.get("/connectors", headers=headers)
    for c in list_resp.json()["connectors"]:
        assert "tenant_id" not in c

    dis_resp = client.post(f"/connectors/{connector_id}/disable", headers=headers)
    assert "tenant_id" not in dis_resp.json()

    en_resp = client.post(f"/connectors/{connector_id}/enable", headers=headers)
    assert "tenant_id" not in en_resp.json()


def test_empty_config_round_trips(pool, make_tenant_with_key):
    """Edge case 3: empty config={} round-trips as {} in the response."""
    _, api_key = make_tenant_with_key("api-emptyconfig")
    client = TestClient(create_app(pool=pool))
    headers = {"Authorization": f"Bearer {api_key}"}

    resp = client.post(
        "/connectors", json={"type": "aws", "display_name": "empty-cfg", "config": {}},
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json()["config"] == {}


# ===========================================================================
# 3. DISCOVER_AND_RECONCILE LINKAGE — test cases 15-19
# ===========================================================================


def test_discover_creates_connectors_row_and_stamps_run(pool, make_tenant):
    """Test case 15: after successful discover_and_reconcile, a connectors row exists
    and connector_runs.connector_id equals that connector's id."""
    tenant = make_tenant("link-15")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    # There should be exactly one connectors row for this source.
    assert _count_connectors(pool, tenant) == 1

    # Verify the registry entry matches expected type/display_name (both equal to source).
    with tenant_session(pool, tenant) as conn:
        registry_connector = ConnectorRegistry(conn, tenant).resolve_or_register(
            type=connector.source, display_name=connector.source
        )

    run_connector_id = _get_run_connector_id(pool, tenant, connector.source)
    assert run_connector_id is not None
    assert run_connector_id == registry_connector.connector_id


def test_discover_stamps_connector_id_on_all_raw_facts(pool, make_tenant):
    """Test case 16: after successful run, EVERY raw_facts row for that source has
    connector_id equal to the registry connector's id."""
    tenant = make_tenant("link-16")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    with tenant_session(pool, tenant) as conn:
        registry_connector = ConnectorRegistry(conn, tenant).resolve_or_register(
            type=connector.source, display_name=connector.source
        )

    fact_connector_ids = _get_distinct_fact_connector_ids(pool, tenant, connector.source)
    # All 3 facts should have exactly one distinct connector_id, equal to the registry connector.
    assert len(fact_connector_ids) == 1
    assert fact_connector_ids == {registry_connector.connector_id}


def test_two_successive_runs_reuse_single_connectors_row(pool, make_tenant):
    """Test case 17: two successive runs of the same source reuse a single connectors row
    and both runs' connector_id equals it."""
    tenant = make_tenant("link-17")
    connector = _FakeConnector()

    discover_and_reconcile(pool, tenant, connector)
    discover_and_reconcile(pool, tenant, connector)

    # Only one connectors row should exist.
    assert _count_connectors(pool, tenant) == 1

    with tenant_session(pool, tenant) as conn:
        registry_connector = ConnectorRegistry(conn, tenant).resolve_or_register(
            type=connector.source, display_name=connector.source
        )

    # Both run rows should carry the same connector_id.
    all_run_ids = _get_all_run_connector_ids(pool, tenant, connector.source)
    assert len(all_run_ids) == 2
    for cid in all_run_ids:
        assert cid == registry_connector.connector_id


def test_failed_run_still_stamps_connector_id(pool, make_tenant):
    """Test case 18: a failed run still produces a connectors row and a run row stamped
    with the connector_id; zero raw_facts are written."""
    tenant = make_tenant("link-18")
    connector = _FailingConnector()

    with pytest.raises(RuntimeError):
        discover_and_reconcile(pool, tenant, connector)

    # A connectors row must exist.
    assert _count_connectors(pool, tenant) == 1

    with tenant_session(pool, tenant) as conn:
        registry_connector = ConnectorRegistry(conn, tenant).resolve_or_register(
            type=connector.source, display_name=connector.source
        )

    # The run row's connector_id must be stamped.
    run_connector_id = _get_run_connector_id(pool, tenant, connector.source)
    assert run_connector_id is not None
    assert run_connector_id == registry_connector.connector_id

    # No raw_facts because the discovery failed before writing any.
    fact_ids = _get_distinct_fact_connector_ids(pool, tenant, connector.source)
    assert len(fact_ids) == 0


def test_direct_start_without_connector_id_writes_null(pool, make_tenant):
    """Test case 19a: direct ConnectorRunRepository.start(src) without connector_id writes NULL."""
    tenant = make_tenant("link-19a")
    with tenant_session(pool, tenant) as conn:
        ConnectorRunRepository(conn, tenant).start("bare-source")

    run_connector_id = _get_run_connector_id(pool, tenant, "bare-source")
    assert run_connector_id is None


def test_direct_record_without_connector_id_writes_null(pool, make_tenant):
    """Test case 19b: direct RawFactRepository.record(src, obs, payloads) without connector_id writes NULL."""
    tenant = make_tenant("link-19b")
    obs = datetime.now(timezone.utc)
    with tenant_session(pool, tenant) as conn:
        RawFactRepository(conn, tenant).record("bare-source", obs, [{"kind": "ci", "event": {}}])

    fact_ids = _get_distinct_fact_connector_ids(pool, tenant, "bare-source")
    # The single fact should have NULL connector_id.
    assert fact_ids == {None}


def test_discover_connector_type_and_display_name_equal_source(pool, make_tenant):
    """After discover_and_reconcile, the registry connector has type==source and display_name==source (spec §5)."""
    tenant = make_tenant("link-type")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    with tenant_session(pool, tenant) as conn:
        connectors = ConnectorRegistry(conn, tenant).list()

    assert len(connectors) == 1
    c = connectors[0]
    assert c.type == connector.source
    assert c.display_name == connector.source


def test_discover_empty_connector_stamps_run_no_facts(pool, make_tenant):
    """Edge case 15: empty discovery run stamped with connector_id; zero raw_facts."""
    tenant = make_tenant("link-empty")
    connector = _EmptyConnector()
    discover_and_reconcile(pool, tenant, connector)

    assert _count_connectors(pool, tenant) == 1

    run_connector_id = _get_run_connector_id(pool, tenant, connector.source)
    assert run_connector_id is not None

    fact_ids = _get_distinct_fact_connector_ids(pool, tenant, connector.source)
    assert len(fact_ids) == 0


def test_connector_runs_and_facts_connector_id_match_registry(pool, make_tenant):
    """Edge case 13: connector_runs.connector_id and raw_facts.connector_id match the registry row
    (joinable; equal to resolve_or_register(source, source).connector_id)."""
    tenant = make_tenant("link-joinable")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    with tenant_session(pool, tenant) as conn:
        registry_connector = ConnectorRegistry(conn, tenant).get(
            _get_run_connector_id(pool, tenant, connector.source)
        )

    assert registry_connector is not None
    assert registry_connector.type == connector.source
    assert registry_connector.display_name == connector.source

    fact_connector_ids = _get_distinct_fact_connector_ids(pool, tenant, connector.source)
    assert fact_connector_ids == {registry_connector.connector_id}


# ===========================================================================
# 4. ADVERSARIAL TENANT ISOLATION — test cases 20-23
# ===========================================================================


def test_tenant_b_list_sees_none_of_tenant_a_connectors(pool, make_tenant):
    """Test case 20a: tenant B's list() returns none of tenant A's connectors."""
    a = make_tenant("iso-reg-A")
    b = make_tenant("iso-reg-B")

    with tenant_session(pool, a) as conn:
        ConnectorRegistry(conn, a).register(type="aws", display_name="a-connector")

    with tenant_session(pool, b) as conn:
        b_connectors = ConnectorRegistry(conn, b).list()

    assert b_connectors == []


def test_tenant_b_get_returns_none_for_tenant_a_connector(pool, make_tenant):
    """Test case 20b: tenant B calling get(A_connector_id) returns None."""
    a = make_tenant("iso-get-A")
    b = make_tenant("iso-get-B")

    with tenant_session(pool, a) as conn:
        a_connector = ConnectorRegistry(conn, a).register(type="aws", display_name="a-only")

    with tenant_session(pool, b) as conn:
        result = ConnectorRegistry(conn, b).get(a_connector.connector_id)

    assert result is None


def test_get_connectors_api_b_sees_none_of_a_connectors(pool, make_tenant_with_key):
    """Test case 20c: tenant B's GET /connectors returns none of tenant A's connectors."""
    _, key_a = make_tenant_with_key("iso-api-A")
    _, key_b = make_tenant_with_key("iso-api-B")

    client = TestClient(create_app(pool=pool))

    # Register a connector under A.
    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "a-connector"},
        headers={"Authorization": f"Bearer {key_a}"},
    )

    # B's GET should return nothing.
    resp = client.get("/connectors", headers={"Authorization": f"Bearer {key_b}"})
    assert resp.status_code == 200
    assert resp.json() == {"connectors": []}


def test_bare_connection_sees_zero_connectors(pool, make_tenant):
    """Test case 21: bare pool connection (no app.tenant_id GUC) sees count(*)==0 on connectors."""
    a = make_tenant("bare-A")

    with tenant_session(pool, a) as conn:
        ConnectorRegistry(conn, a).register(type="aws", display_name="bare-test")

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM connectors").fetchone()[0]

    assert count == 0


def test_rls_blocks_cross_tenant_insert_connectors(pool, make_tenant):
    """Test case 22: cross-tenant INSERT stamping B's tenant_id under A's session
    raises psycopg.Error (RLS WITH CHECK)."""
    a = make_tenant("xins-A")
    b = make_tenant("xins-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            # Stamp B's tenant_id while under A's session — should be rejected.
            conn.execute(
                "INSERT INTO connectors (tenant_id, type, display_name) "
                "VALUES (%s, 'aws', 'adversarial')",
                (str(b),),
            )


def test_tenant_b_set_enabled_on_a_connector_returns_none(pool, make_tenant):
    """Test case 23a: tenant B calling set_enabled(A_connector_id) returns None
    (RLS hides the row; zero rows updated; no cross-tenant mutation)."""
    a = make_tenant("xse-A")
    b = make_tenant("xse-B")

    with tenant_session(pool, a) as conn:
        a_connector = ConnectorRegistry(conn, a).register(type="aws", display_name="a-only")

    with tenant_session(pool, b) as conn:
        result = ConnectorRegistry(conn, b).set_enabled(a_connector.connector_id, False)

    assert result is None

    # Verify A's connector was NOT mutated.
    with tenant_session(pool, a) as conn:
        still_a = ConnectorRegistry(conn, a).get(a_connector.connector_id)
    assert still_a is not None
    assert still_a.enabled is True


def test_cross_tenant_disable_via_api_returns_404(pool, make_tenant_with_key):
    """Test case 23b: POST /connectors/{A_id}/disable under tenant B -> 404."""
    _, key_a = make_tenant_with_key("xapi-A")
    _, key_b = make_tenant_with_key("xapi-B")

    client = TestClient(create_app(pool=pool))

    # Register a connector under A.
    reg = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "a-connector"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    a_connector_id = reg.json()["connector_id"]

    # Tenant B tries to disable A's connector.
    resp = client.post(
        f"/connectors/{a_connector_id}/disable",
        headers={"Authorization": f"Bearer {key_b}"},
    )

    assert resp.status_code == 404
    assert resp.json() == {"detail": "Connector not found"}


def test_cross_tenant_enable_via_api_returns_404(pool, make_tenant_with_key):
    """Tenant B calling POST /connectors/{A_id}/enable -> 404."""
    _, key_a = make_tenant_with_key("xapi-en-A")
    _, key_b = make_tenant_with_key("xapi-en-B")

    client = TestClient(create_app(pool=pool))

    reg = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "a-connector"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    a_connector_id = reg.json()["connector_id"]

    resp = client.post(
        f"/connectors/{a_connector_id}/enable",
        headers={"Authorization": f"Bearer {key_b}"},
    )

    assert resp.status_code == 404
    assert resp.json() == {"detail": "Connector not found"}


def test_connector_count_not_visible_across_tenants(pool, make_tenant):
    """Tenant B's SELECT count(*) on connectors under B's session sees 0 of A's rows."""
    a = make_tenant("cnt-conn-A")
    b = make_tenant("cnt-conn-B")

    with tenant_session(pool, a) as conn:
        ConnectorRegistry(conn, a).register(type="aws", display_name="a-only")

    # A sees its own row.
    assert _count_connectors(pool, a) == 1

    # B sees nothing.
    assert _count_connectors(pool, b) == 0


# ===========================================================================
# 5. ADDITIONAL EDGE CASES
# ===========================================================================


def test_register_idempotent_returns_same_created_at(pool, make_tenant):
    """Edge case 1: idempotent register returns same created_at (row not touched)."""
    tenant = make_tenant("ec-1")
    with tenant_session(pool, tenant) as conn:
        first = ConnectorRegistry(conn, tenant).register(type="aws", display_name="same")

    with tenant_session(pool, tenant) as conn:
        second = ConnectorRegistry(conn, tenant).register(type="aws", display_name="same")

    assert first.created_at == second.created_at


def test_register_idempotent_enabled_not_overwritten(pool, make_tenant):
    """Edge case 1: idempotent register does not overwrite enabled field."""
    tenant = make_tenant("ec-1b")
    # First register with enabled=False explicitly.
    with tenant_session(pool, tenant) as conn:
        first = ConnectorRegistry(conn, tenant).register(
            type="aws", display_name="disabled-one", enabled=False
        )
    assert first.enabled is False

    # Second call with enabled=True should NOT change it.
    with tenant_session(pool, tenant) as conn:
        second = ConnectorRegistry(conn, tenant).register(
            type="aws", display_name="disabled-one", enabled=True
        )
    assert second.enabled is False


def test_nullable_fk_integrity_connector_id_references_existing_row(pool, make_tenant):
    """Edge case 18: non-NULL connector_id on a connector_runs row references an existing
    connectors row (FK enforced)."""
    tenant = make_tenant("fk-int")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    run_connector_id = _get_run_connector_id(pool, tenant, connector.source)
    assert run_connector_id is not None

    # Verify the FK target exists.
    with tenant_session(pool, tenant) as conn:
        row = conn.execute(
            "SELECT connector_id FROM connectors WHERE connector_id = %s",
            (run_connector_id,),
        ).fetchone()
    assert row is not None
    assert row[0] == run_connector_id


def test_raw_facts_partition_connector_id_selectable(pool, make_tenant):
    """Edge case 17: connector_id is selectable through the raw_facts partition parent."""
    tenant = make_tenant("part-17")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    with tenant_session(pool, tenant) as conn:
        # Query via the partition parent table (raw_facts), not the partition child directly.
        row = conn.execute(
            "SELECT DISTINCT connector_id FROM raw_facts WHERE source=%s",
            (connector.source,),
        ).fetchone()

    assert row is not None
    assert row[0] is not None


def test_list_empty_for_tenant_with_no_connectors(pool, make_tenant):
    """Edge case 6: GET /connectors for tenant with no connectors -> empty list, 200."""
    tenant = make_tenant("ec-6")
    with tenant_session(pool, tenant) as conn:
        result = ConnectorRegistry(conn, tenant).list()
    assert result == []


def test_multiple_connector_types_each_get_own_row(pool, make_tenant):
    """Different (type, display_name) pairs create separate rows."""
    tenant = make_tenant("multi-type")
    with tenant_session(pool, tenant) as conn:
        registry = ConnectorRegistry(conn, tenant)
        c1 = registry.register(type="aws", display_name="acct-1")
        c2 = registry.register(type="aws", display_name="acct-2")
        c3 = registry.register(type="gcp", display_name="acct-1")

    # Each gets a unique connector_id.
    assert c1.connector_id != c2.connector_id
    assert c1.connector_id != c3.connector_id
    assert c2.connector_id != c3.connector_id
    assert _count_connectors(pool, tenant) == 3


def test_post_connectors_default_enabled_true(pool, make_tenant_with_key):
    """POST /connectors without explicit enabled field defaults to enabled=true."""
    _, api_key = make_tenant_with_key("api-default-en")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "default-en"},
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert resp.status_code == 201
    assert resp.json()["enabled"] is True


def test_post_connectors_with_enabled_false(pool, make_tenant_with_key):
    """POST /connectors with enabled=false creates a disabled connector."""
    _, api_key = make_tenant_with_key("api-enabled-false")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "disabled", "enabled": False},
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert resp.status_code == 201
    assert resp.json()["enabled"] is False


def test_db_exports_connector_registry_and_registered_connector():
    """AC 8: infra_twin.db exports ConnectorRegistry and RegisteredConnector in __all__."""
    from infra_twin import db

    assert "ConnectorRegistry" in db.__all__
    assert "RegisteredConnector" in db.__all__
    assert db.RegisteredConnector is not None
    # Verify it's the same class as connectors.Connector.
    from infra_twin.db.connectors import Connector as _C
    assert db.RegisteredConnector is _C
