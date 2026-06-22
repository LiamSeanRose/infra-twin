"""Connector run lifecycle, raw-fact persistence, and connector-health API tests.

Covers:
- Success path: discover_and_reconcile records a connector_runs row with status='ok',
  writes raw_facts rows, and GET /connector-health/runs reports the correct status.
- Failed-run path: connector.discover() raises -> connector_runs row with status='error'
  is persisted in a separate transaction; exception is re-raised; zero raw_facts written.
- Tenant isolation: connector_runs and raw_facts are invisible across tenants; adversarial
  cross-tenant inserts are blocked by RLS WITH CHECK.
- Edge cases from the spec: empty discovery, in-flight partial row, stale logic, multiple
  sources, no runs, large error text, observed_at consistency.
"""

from __future__ import annotations

import psycopg
import pytest
from datetime import datetime, timezone
from typing import Iterator
from uuid import UUID

from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import DiscoveredCI, DiscoveredEdge, CIRef
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.connector_health import ConnectorRunRepository, RawFactRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import discover_and_reconcile


# ---------------------------------------------------------------------------
# Minimal fake connectors used throughout
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


class _SecondSourceConnector:
    """A connector with a different source name, emitting one CI."""

    source: str = "second-source"
    ci_types: frozenset = frozenset({CIType.s3_bucket})
    edge_types: frozenset = frozenset()

    def discover(self) -> Iterator:
        yield DiscoveredCI(type=CIType.s3_bucket, external_id="bucket-1", name="b")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_runs(pool, tenant, source=None):
    """Count connector_runs rows visible to tenant (via tenant_session / RLS)."""
    with tenant_session(pool, tenant) as conn:
        if source:
            row = conn.execute(
                "SELECT count(*) FROM connector_runs WHERE source=%s", (source,)
            ).fetchone()
        else:
            row = conn.execute("SELECT count(*) FROM connector_runs").fetchone()
        return row[0]


def _count_facts(pool, tenant, source=None):
    """Count raw_facts rows visible to tenant (via tenant_session / RLS)."""
    with tenant_session(pool, tenant) as conn:
        if source:
            row = conn.execute(
                "SELECT count(*) FROM raw_facts WHERE source=%s", (source,)
            ).fetchone()
        else:
            row = conn.execute("SELECT count(*) FROM raw_facts").fetchone()
        return row[0]


def _get_run(pool, tenant, source):
    """Fetch the single latest connector_runs row for (tenant, source)."""
    with tenant_session(pool, tenant) as conn:
        row = conn.execute(
            "SELECT status, started_at, finished_at, error "
            "FROM connector_runs WHERE source=%s "
            "ORDER BY started_at DESC NULLS LAST LIMIT 1",
            (source,),
        ).fetchone()
    return row  # (status, started_at, finished_at, error)


def _get_facts(pool, tenant, source):
    """Fetch all raw_facts rows for (tenant, source)."""
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT observed_at, payload FROM raw_facts WHERE source=%s",
            (source,),
        ).fetchall()
    return rows  # list of (observed_at, payload)


# ===========================================================================
# 1. SUCCESS PATH
# ===========================================================================

def test_success_path_connector_run_row(pool, make_tenant):
    """AC 18a: successful run records status='ok', non-null started_at and finished_at."""
    tenant = make_tenant("success-a")
    connector = _FakeConnector()
    result = discover_and_reconcile(pool, tenant, connector)

    assert result.cis_created >= 0  # signature unchanged, result returned

    row = _get_run(pool, tenant, connector.source)
    assert row is not None, "expected exactly one connector_runs row"
    status, started_at, finished_at, error = row
    assert status == "ok"
    assert started_at is not None
    assert finished_at is not None
    assert error is None


def test_success_path_raw_facts_count_matches_events(pool, make_tenant):
    """AC 18a: raw_facts count equals the number of discovery events."""
    tenant = make_tenant("success-b")
    connector = _FakeConnector()
    events_expected = 3  # 2 CIs + 1 edge
    discover_and_reconcile(pool, tenant, connector)

    count = _count_facts(pool, tenant, connector.source)
    assert count == events_expected


def test_success_path_raw_facts_share_observed_at(pool, make_tenant):
    """AC 12 / edge case 14: all raw facts from one run share one observed_at."""
    tenant = make_tenant("success-c")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    rows = _get_facts(pool, tenant, connector.source)
    assert len(rows) == 3
    observed_times = {r[0] for r in rows}
    assert len(observed_times) == 1, f"expected one observed_at, got {observed_times}"


def test_success_path_api_reports_ok_not_stale(pool, make_tenant_with_key):
    """AC 18a: GET /connector-health/runs returns status='ok' and stale=false."""
    tenant, api_key = make_tenant_with_key("success-d")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {api_key}"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "sources" in body
    sources = body["sources"]
    assert len(sources) == 1
    entry = sources[0]
    assert entry["source"] == connector.source
    assert entry["status"] == "ok"
    assert entry["started_at"] is not None
    assert entry["finished_at"] is not None
    assert entry["error"] is None
    assert entry["age_seconds"] is not None
    assert entry["stale"] is False


def test_success_path_raw_fact_payload_shape(pool, make_tenant):
    """AC 11: every raw fact has shape {'kind': 'ci'|'edge', 'event': {...}}."""
    tenant = make_tenant("success-e")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    rows = _get_facts(pool, tenant, connector.source)
    for observed_at, payload in rows:
        assert "kind" in payload, f"missing 'kind' in {payload}"
        assert payload["kind"] in ("ci", "edge"), f"unexpected kind {payload['kind']}"
        assert "event" in payload, f"missing 'event' in {payload}"
        assert isinstance(payload["event"], dict)


def test_success_path_exactly_one_run_row(pool, make_tenant):
    """One run -> exactly one connector_runs row (not partial duplicates)."""
    tenant = make_tenant("success-f")
    connector = _FakeConnector()
    discover_and_reconcile(pool, tenant, connector)

    count = _count_runs(pool, tenant, connector.source)
    assert count == 1


# ===========================================================================
# 2. EMPTY DISCOVERY (edge case 3)
# ===========================================================================

def test_empty_discovery_records_ok_no_facts(pool, make_tenant):
    """Edge case 3: empty discovery -> run='ok', zero raw_facts, no crash."""
    tenant = make_tenant("empty-a")
    connector = _EmptyConnector()
    result = discover_and_reconcile(pool, tenant, connector)

    row = _get_run(pool, tenant, connector.source)
    assert row is not None
    status, started_at, finished_at, error = row
    assert status == "ok"
    assert started_at is not None
    assert finished_at is not None

    count = _count_facts(pool, tenant, connector.source)
    assert count == 0


# ===========================================================================
# 3. FAILED-RUN PATH (edge case 1)
# ===========================================================================

def test_failed_run_reraises_exception(pool, make_tenant):
    """AC 18b: discover_and_reconcile re-raises the connector exception."""
    tenant = make_tenant("fail-a")
    exc = RuntimeError("discovery exploded")
    connector = _FailingConnector(exc=exc)

    with pytest.raises(RuntimeError, match="discovery exploded"):
        discover_and_reconcile(pool, tenant, connector)


def test_failed_run_records_error_row(pool, make_tenant):
    """AC 18b: a connector_runs row with status='error' is persisted after failure."""
    tenant = make_tenant("fail-b")
    connector = _FailingConnector()

    with pytest.raises(RuntimeError):
        discover_and_reconcile(pool, tenant, connector)

    row = _get_run(pool, tenant, connector.source)
    assert row is not None, "expected a connector_runs row even after failure"
    status, started_at, finished_at, error = row
    assert status == "error"
    assert finished_at is not None
    assert error is not None
    assert len(error) > 0


def test_failed_run_error_text_is_captured(pool, make_tenant):
    """The error column contains the exception message text."""
    tenant = make_tenant("fail-c")
    connector = _FailingConnector(exc=RuntimeError("unique-boom-12345"))

    with pytest.raises(RuntimeError):
        discover_and_reconcile(pool, tenant, connector)

    row = _get_run(pool, tenant, connector.source)
    _, _, _, error = row
    assert "unique-boom-12345" in error


def test_failed_run_zero_raw_facts(pool, make_tenant):
    """AC 18b: zero raw_facts are written when discovery fails (transaction rolled back)."""
    tenant = make_tenant("fail-d")
    connector = _FailingConnector()

    with pytest.raises(RuntimeError):
        discover_and_reconcile(pool, tenant, connector)

    count = _count_facts(pool, tenant, connector.source)
    assert count == 0


def test_failed_run_empty_exc_str_uses_class_name(pool, make_tenant):
    """Edge case: when str(exc) is empty, error text falls back to type.__name__."""

    class _SilentError(Exception):
        def __str__(self):
            return ""

    tenant = make_tenant("fail-e")

    class _SilentFailing:
        source = "silent-fail"
        ci_types: frozenset = frozenset({CIType.vpc})
        edge_types: frozenset = frozenset()

        def discover(self):
            raise _SilentError()
            yield

    with pytest.raises(_SilentError):
        discover_and_reconcile(pool, tenant, _SilentFailing())

    row = _get_run(pool, tenant, "silent-fail")
    _, _, _, error = row
    assert error == "_SilentError"


def test_failed_run_large_error_text_truncated(pool, make_tenant):
    """Edge case 13: error text is truncated to 4000 chars."""
    big_msg = "x" * 10_000
    tenant = make_tenant("fail-f")

    class _BigErrorConnector:
        source = "big-err"
        ci_types: frozenset = frozenset({CIType.vpc})
        edge_types: frozenset = frozenset()

        def discover(self):
            raise RuntimeError(big_msg)
            yield

    with pytest.raises(RuntimeError):
        discover_and_reconcile(pool, tenant, _BigErrorConnector())

    row = _get_run(pool, tenant, "big-err")
    _, _, _, error = row
    assert error is not None
    assert len(error) <= 4000


# ===========================================================================
# 4. API ENDPOINT EDGE CASES
# ===========================================================================

def test_api_no_runs_returns_empty_sources(pool, make_tenant_with_key):
    """Edge case 5: tenant with no runs -> GET returns {'sources': []}."""
    _, api_key = make_tenant_with_key("norun-a")
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {api_key}"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"sources": []}


def test_api_missing_tenant_header_returns_401(pool):
    """Missing Authorization header -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/connector-health/runs")
    assert resp.status_code == 401


def test_api_bogus_api_key_returns_401(pool):
    """Bogus Bearer token -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": "Bearer itw_bogus.bogus"}
    )
    assert resp.status_code == 401


def test_api_response_has_all_required_keys(pool, make_tenant_with_key):
    """AC 16: each source entry has exactly the required keys."""
    tenant, api_key = make_tenant_with_key("keys-a")
    discover_and_reconcile(pool, tenant, _FakeConnector())

    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {api_key}"}
    )
    body = resp.json()
    required_keys = {"source", "status", "started_at", "finished_at", "error", "age_seconds", "stale"}
    for entry in body["sources"]:
        assert set(entry.keys()) == required_keys, f"unexpected keys: {set(entry.keys())}"


def test_api_in_flight_partial_row_is_stale(pool, make_tenant_with_key):
    """Edge case 6: in-flight partial run -> stale=true, age_seconds=null."""
    tenant, api_key = make_tenant_with_key("partial-a")
    # Directly insert a partial row (simulate a run that never finished).
    with tenant_session(pool, tenant) as conn:
        ConnectorRunRepository(conn, tenant).start("partial-source")
    # Note: the tenant_session block commits, so partial row is durable.

    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {api_key}"}
    )
    body = resp.json()
    assert len(body["sources"]) == 1
    entry = body["sources"][0]
    assert entry["source"] == "partial-source"
    assert entry["status"] == "partial"
    assert entry["finished_at"] is None
    assert entry["age_seconds"] is None
    assert entry["stale"] is True


def test_api_multiple_sources_ordered_ascending(pool, make_tenant_with_key):
    """Edge case 8: multiple distinct sources -> one row each, ordered by source asc."""
    tenant, api_key = make_tenant_with_key("multi-a")
    discover_and_reconcile(pool, tenant, _FakeConnector())
    discover_and_reconcile(pool, tenant, _SecondSourceConnector())

    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {api_key}"}
    )
    body = resp.json()
    sources_list = body["sources"]
    assert len(sources_list) == 2
    names = [s["source"] for s in sources_list]
    assert names == sorted(names), f"sources not in ascending order: {names}"


def test_api_multiple_runs_same_source_returns_latest(pool, make_tenant_with_key):
    """Edge case 7: multiple runs of same source -> exactly one row, the newest."""
    tenant, api_key = make_tenant_with_key("multi-run-a")
    # Run the same connector twice.
    discover_and_reconcile(pool, tenant, _FakeConnector())
    discover_and_reconcile(pool, tenant, _FakeConnector())

    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {api_key}"}
    )
    body = resp.json()
    assert len(body["sources"]) == 1
    assert body["sources"][0]["status"] == "ok"


def test_api_stale_constant_is_86400():
    """AC 14: STALE_AFTER_SECONDS == 86400 (24 * 60 * 60)."""
    from infra_twin.api.app import STALE_AFTER_SECONDS
    assert STALE_AFTER_SECONDS == 86400


def test_api_stale_false_for_recent_run(pool, make_tenant_with_key):
    """AC 17: stale=False when age_seconds is not None and <= STALE_AFTER_SECONDS."""
    tenant, api_key = make_tenant_with_key("stale-a")
    discover_and_reconcile(pool, tenant, _FakeConnector())

    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {api_key}"}
    )
    entry = resp.json()["sources"][0]
    # A run that just completed should have a small age_seconds.
    assert entry["age_seconds"] is not None
    assert entry["age_seconds"] < 86400
    assert entry["stale"] is False


# ===========================================================================
# 5. TENANT ISOLATION — connector_runs and raw_facts (AC 18c)
# ===========================================================================

def test_tenant_isolation_api_b_sees_no_a_runs(pool, make_tenant_with_key, make_tenant):
    """AC 18c: tenant B's GET /connector-health/runs returns empty even when A has runs."""
    a = make_tenant("iso-A")
    _, key_b = make_tenant_with_key("iso-B")
    discover_and_reconcile(pool, a, _FakeConnector())

    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/connector-health/runs", headers={"Authorization": f"Bearer {key_b}"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"sources": []}


def test_tenant_isolation_raw_count_connector_runs(pool, make_tenant):
    """AC 18c: raw SELECT count(*) on connector_runs under B's session sees 0 of A's rows."""
    a = make_tenant("cnt-A")
    b = make_tenant("cnt-B")
    discover_and_reconcile(pool, a, _FakeConnector())

    # Verify A sees its own row.
    assert _count_runs(pool, a) == 1

    # B's session must see nothing.
    b_count = _count_runs(pool, b)
    assert b_count == 0


def test_tenant_isolation_raw_count_raw_facts(pool, make_tenant):
    """AC 18c: raw SELECT count(*) on raw_facts under B's session sees 0 of A's facts."""
    a = make_tenant("rf-A")
    b = make_tenant("rf-B")
    discover_and_reconcile(pool, a, _FakeConnector())

    # A sees its own facts.
    assert _count_facts(pool, a) == 3

    # B sees nothing.
    assert _count_facts(pool, b) == 0


def test_tenant_isolation_no_guc_sees_zero_runs(pool, make_tenant):
    """Edge case 12: bare connection (no app.tenant_id GUC) sees zero connector_runs rows."""
    a = make_tenant("guc-A")
    discover_and_reconcile(pool, a, _FakeConnector())

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM connector_runs").fetchone()[0]
    assert count == 0


def test_tenant_isolation_no_guc_sees_zero_raw_facts(pool, make_tenant):
    """Edge case 12: bare connection (no app.tenant_id GUC) sees zero raw_facts rows."""
    a = make_tenant("guc-B")
    discover_and_reconcile(pool, a, _FakeConnector())

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM raw_facts").fetchone()[0]
    assert count == 0


def test_rls_blocks_cross_tenant_insert_connector_runs(pool, make_tenant):
    """AC 18c / edge case 11: inserting connector_runs stamped with another tenant_id
    under the current session violates the RLS WITH CHECK policy."""
    a = make_tenant("xrun-A")
    b = make_tenant("xrun-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            # Stamp B's tenant_id while under A's session — should be rejected.
            conn.execute(
                "INSERT INTO connector_runs (tenant_id, source, status, started_at) "
                "VALUES (%s, 'adversarial', 'partial', now())",
                (str(b),),
            )


def test_rls_blocks_cross_tenant_insert_raw_facts(pool, make_tenant):
    """AC 18c / edge case 11: inserting raw_facts stamped with another tenant_id
    under the current session violates the RLS WITH CHECK policy."""
    a = make_tenant("xrf-A")
    b = make_tenant("xrf-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO raw_facts (tenant_id, source, observed_at, payload) "
                "VALUES (%s, 'adversarial', now(), '{}'::jsonb)",
                (str(b),),
            )


def test_cross_tenant_update_connector_runs_affects_nothing(pool, make_tenant):
    """Tenant B cannot mutate A's connector_runs row (RLS hides it; zero rows affected)."""
    a = make_tenant("upd-A")
    b = make_tenant("upd-B")
    discover_and_reconcile(pool, a, _FakeConnector())

    # Tenant B tries to UPDATE A's rows.
    with tenant_session(pool, b) as conn:
        cur = conn.execute(
            "UPDATE connector_runs SET status='ok' WHERE source=%s",
            (_FakeConnector.source,),
        )
        assert cur.rowcount == 0


# ===========================================================================
# 6. ConnectorRunRepository direct unit tests (repository layer)
# ===========================================================================

def test_repository_start_returns_uuid(pool, make_tenant):
    """ConnectorRunRepository.start returns a UUID run_id."""
    tenant = make_tenant("repo-a")
    with tenant_session(pool, tenant) as conn:
        run_id = ConnectorRunRepository(conn, tenant).start("test-source")
    assert isinstance(run_id, UUID)


def test_repository_finish_ok_updates_status(pool, make_tenant):
    """ConnectorRunRepository.finish_ok sets status='ok' and non-null finished_at."""
    tenant = make_tenant("repo-b")
    with tenant_session(pool, tenant) as conn:
        repo = ConnectorRunRepository(conn, tenant)
        run_id = repo.start("unit-ok")
        repo.finish_ok(run_id)

    row = _get_run(pool, tenant, "unit-ok")
    status, _, finished_at, _ = row
    assert status == "ok"
    assert finished_at is not None


def test_repository_finish_error_updates_status_and_error(pool, make_tenant):
    """ConnectorRunRepository.finish_error sets status='error', error text, non-null finished_at."""
    tenant = make_tenant("repo-c")
    with tenant_session(pool, tenant) as conn:
        repo = ConnectorRunRepository(conn, tenant)
        run_id = repo.start("unit-err")
        repo.finish_error(run_id, "something went wrong")

    row = _get_run(pool, tenant, "unit-err")
    status, _, finished_at, error = row
    assert status == "error"
    assert finished_at is not None
    assert error == "something went wrong"


def test_repository_latest_per_source_empty(pool, make_tenant):
    """latest_per_source returns [] when no runs exist for tenant."""
    tenant = make_tenant("repo-d")
    with tenant_session(pool, tenant) as conn:
        summaries = ConnectorRunRepository(conn, tenant).latest_per_source()
    assert summaries == []


def test_repository_latest_per_source_returns_newest(pool, make_tenant):
    """Edge case 7: multiple runs for same source -> latest_per_source returns only newest."""
    tenant = make_tenant("repo-e")
    # Insert two runs for the same source.
    with tenant_session(pool, tenant) as conn:
        repo = ConnectorRunRepository(conn, tenant)
        r1 = repo.start("src-x")
        repo.finish_error(r1, "first")

    with tenant_session(pool, tenant) as conn:
        repo = ConnectorRunRepository(conn, tenant)
        r2 = repo.start("src-x")
        repo.finish_ok(r2)

    with tenant_session(pool, tenant) as conn:
        summaries = ConnectorRunRepository(conn, tenant).latest_per_source()

    assert len(summaries) == 1
    assert summaries[0].status == "ok"


def test_repository_latest_per_source_multiple_sources_ordered(pool, make_tenant):
    """Edge case 8: multiple sources -> one row each, ordered by source ascending."""
    tenant = make_tenant("repo-f")
    sources = ["zebra-source", "alpha-source", "middle-source"]
    for src in sources:
        with tenant_session(pool, tenant) as conn:
            repo = ConnectorRunRepository(conn, tenant)
            run_id = repo.start(src)
            repo.finish_ok(run_id)

    with tenant_session(pool, tenant) as conn:
        summaries = ConnectorRunRepository(conn, tenant).latest_per_source()

    returned_names = [s.source for s in summaries]
    assert returned_names == sorted(returned_names)
    assert set(returned_names) == set(sources)


def test_repository_latest_per_source_age_seconds_is_float_or_none(pool, make_tenant):
    """age_seconds is a float when finished_at is present, None otherwise."""
    tenant = make_tenant("repo-g")
    with tenant_session(pool, tenant) as conn:
        repo = ConnectorRunRepository(conn, tenant)
        # Partial: no finished_at
        repo.start("no-finish")
    # Separate session to finish another run.
    with tenant_session(pool, tenant) as conn:
        repo = ConnectorRunRepository(conn, tenant)
        r = repo.start("with-finish")
        repo.finish_ok(r)

    with tenant_session(pool, tenant) as conn:
        summaries = ConnectorRunRepository(conn, tenant).latest_per_source()

    by_src = {s.source: s for s in summaries}
    assert by_src["no-finish"].age_seconds is None
    assert isinstance(by_src["with-finish"].age_seconds, float)


# ===========================================================================
# 7. RawFactRepository direct unit tests
# ===========================================================================

def test_raw_fact_repo_empty_payloads_no_op(pool, make_tenant):
    """AC 6: record() with empty list is a no-op returning 0."""
    tenant = make_tenant("rf-repo-a")
    with tenant_session(pool, tenant) as conn:
        count = RawFactRepository(conn, tenant).record(
            "test", datetime.now(timezone.utc), []
        )
    assert count == 0
    assert _count_facts(pool, tenant) == 0


def test_raw_fact_repo_inserts_correct_count(pool, make_tenant):
    """AC 7: record() inserts one row per payload and returns count."""
    tenant = make_tenant("rf-repo-b")
    payloads = [{"kind": "ci", "event": {"x": i}} for i in range(5)]
    obs = datetime.now(timezone.utc)

    with tenant_session(pool, tenant) as conn:
        count = RawFactRepository(conn, tenant).record("test-src", obs, payloads)

    assert count == 5
    assert _count_facts(pool, tenant) == 5


def test_raw_fact_repo_observed_at_stored_correctly(pool, make_tenant):
    """All inserted rows carry the exact observed_at passed to record()."""
    tenant = make_tenant("rf-repo-c")
    obs = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    payloads = [{"kind": "ci", "event": {}}]

    with tenant_session(pool, tenant) as conn:
        RawFactRepository(conn, tenant).record("test-src", obs, payloads)

    rows = _get_facts(pool, tenant, "test-src")
    assert len(rows) == 1
    stored_ts = rows[0][0]
    # Strip microseconds for comparison (DB timestamp resolution).
    assert stored_ts.replace(microsecond=0, tzinfo=timezone.utc) == obs.replace(microsecond=0)
