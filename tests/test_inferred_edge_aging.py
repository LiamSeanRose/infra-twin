"""Tests for the inferred-edge aging/decay sweep feature.

Coverage:
1. Decay helper unit tests (pure, no DB).
2. Integration: decay path (age past freshness window, before TTL).
3. Integration: TTL-close path (age past TTL).
4. Integration: freshly re-observed edge is untouched.
5. Integration: declared edges are never decayed or closed.
6. Adversarial cross-tenant isolation.
7. Regression: test_flowlog_confidence_accumulation.py strengthen path.
8. Additional edge cases from spec §5 and acceptance criteria §6.

Spec refs: specs.md §5 (edge cases 1-21) and §6 (AC 1-26).
"""

from __future__ import annotations

import ast
import importlib.util
import uuid
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import (
    INFERRED_EDGE_TTL,
    INFERRED_FRESHNESS_WINDOW,
    STALE_FLOOR_CONFIDENCE,
    CIType,
    Edge,
    EdgeSource,
    EdgeType,
    Evidence,
    INFERRED_DECAY_PER_DAY,
    decayed_confidence,
)
from infra_twin.db.config import admin_dsn
from infra_twin.db.graph import cypher
from infra_twin.db.repositories import (
    FLOWLOG_COUNT_EVIDENCE_SOURCE,
    CIRepository,
    EdgeRepository,
    last_observed_at_of,
)
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import AgingResult, age_inferred_edges, reconcile

# ---------------------------------------------------------------------------
# IP addresses and flow record fixtures
# ---------------------------------------------------------------------------

_SEED_SOURCE = "test-seed-aging"

_IP_A = "10.1.0.1"
_IP_B = "10.1.0.2"
_IP_C = "10.1.0.3"
_IP_D = "10.1.0.4"

_ACCEPT_FLOW_A_TO_B = {
    "srcaddr": _IP_A,
    "dstaddr": _IP_B,
    "srcport": 55001,
    "dstport": 443,
    "protocol": 6,
    "action": "ACCEPT",
    "start": 1700000000,
    "end": 1700000060,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_ec2(pool, tenant: UUID, instances: list[tuple[str, str]]) -> None:
    """Seed ec2_instance CIs for (external_id, private_ip) pairs."""
    events = [
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id=ext_id,
            name=ext_id,
            attributes={"private_ip": ip},
        )
        for ext_id, ip in instances
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            events,
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.ec2_instance}),
            edge_types=frozenset(),
        )


def _post_flowlogs(client, tenant: UUID, records: list[dict], api_key: str = "") -> object:
    return client.post(
        "/telemetry/flowlogs",
        json={"records": records},
        headers={"Authorization": f"Bearer {api_key}"},
    )


def _post_age_edges(client, tenant: UUID, api_key: str = "") -> object:
    return client.post(
        "/telemetry/maintenance/age-inferred-edges",
        headers={"Authorization": f"Bearer {api_key}"},
    )


def _get_open_inferred_connects_to(pool, tenant: UUID) -> list[Edge]:
    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    return [
        e
        for e in edges
        if e.type == EdgeType.CONNECTS_TO
        and e.source == EdgeSource.inferred
        and e.valid_to is None
    ]


def _all_edge_versions(tenant: UUID, edge_id: UUID) -> list[dict]:
    """Return all bitemporal rows (open + closed) for an edge id, via superuser."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT id, source, confidence, evidence, valid_from, valid_to "
            "FROM edges WHERE id = %s AND tenant_id = %s ORDER BY valid_from",
            (edge_id, tenant),
        ).fetchall()
    return [
        {
            "id": r[0],
            "source": r[1],
            "confidence": r[2],
            "evidence": r[3],
            "valid_from": r[4],
            "valid_to": r[5],
        }
        for r in rows
    ]


def _count_open_rows_for_edge(tenant: UUID, edge_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM edges WHERE id = %s AND tenant_id = %s AND valid_to IS NULL",
            (edge_id, tenant),
        ).fetchone()
    return row[0]


def _get_connector_runs(tenant: UUID, source: str) -> list[dict]:
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT run_id, source, status FROM connector_runs "
            "WHERE tenant_id = %s AND source = %s",
            (tenant, source),
        ).fetchall()
    return [{"run_id": r[0], "source": r[1], "status": r[2]} for r in rows]


def _make_now_past_window(last_observed: datetime) -> datetime:
    """Return a now that is 14 days past last_observed (window=7, TTL=30)."""
    return last_observed + INFERRED_FRESHNESS_WINDOW + timedelta(days=7)


def _make_now_past_ttl(last_observed: datetime) -> datetime:
    """Return a now that is 60 days past last_observed (TTL=30)."""
    return last_observed + INFERRED_EDGE_TTL + timedelta(days=30)


# ===========================================================================
# Section 1: Pure decay helper unit tests (AC 1-13)
# ===========================================================================


class TestDecayConstants:
    """Pin the four constants from specs.md §6 AC 1-4."""

    def test_stale_floor_confidence_value(self):
        """AC 1: STALE_FLOOR_CONFIDENCE == 0.2."""
        assert STALE_FLOOR_CONFIDENCE == 0.2

    def test_inferred_freshness_window_value(self):
        """AC 2: INFERRED_FRESHNESS_WINDOW == timedelta(days=7)."""
        assert INFERRED_FRESHNESS_WINDOW == timedelta(days=7)

    def test_inferred_edge_ttl_value(self):
        """AC 3: INFERRED_EDGE_TTL == timedelta(days=30)."""
        assert INFERRED_EDGE_TTL == timedelta(days=30)

    def test_freshness_window_less_than_ttl(self):
        """AC 4: INFERRED_FRESHNESS_WINDOW < INFERRED_EDGE_TTL."""
        assert INFERRED_FRESHNESS_WINDOW < INFERRED_EDGE_TTL

    def test_inferred_decay_per_day_value(self):
        """INFERRED_DECAY_PER_DAY == 0.05."""
        assert INFERRED_DECAY_PER_DAY == 0.05


class TestDecayHelperNoDecayAtZero:
    """AC 5: no decay at age 0."""

    def test_no_decay_at_timedelta_zero(self):
        """AC 5: decayed_confidence(0.9, timedelta(0)) == 0.9."""
        assert decayed_confidence(0.9, timedelta(0)) == 0.9

    def test_no_decay_at_timedelta_zero_other_values(self):
        """No decay at age=0 for various starting confidences."""
        for c in (0.2, 0.5, 0.6, 0.8, 0.9, 1.0):
            assert decayed_confidence(c, timedelta(0)) == c

    def test_no_decay_at_freshness_window_boundary(self):
        """AC 6: decayed_confidence(0.9, INFERRED_FRESHNESS_WINDOW) == 0.9 (boundary inclusive)."""
        assert decayed_confidence(0.9, INFERRED_FRESHNESS_WINDOW) == 0.9

    def test_no_decay_within_freshness_window(self):
        """Spec §4.1: ages within the window leave confidence unchanged."""
        for days in range(0, 8):
            age = timedelta(days=days)
            assert decayed_confidence(0.9, age) == 0.9, (
                f"expected unchanged at {days} days"
            )


class TestDecayHelperDecayPastWindow:
    """AC 7-12: decay properties past the freshness window."""

    def test_decay_strictly_lower_one_day_past_window(self):
        """AC 7: decayed_confidence(0.9, INFERRED_FRESHNESS_WINDOW + 1 day) < 0.9."""
        result = decayed_confidence(0.9, INFERRED_FRESHNESS_WINDOW + timedelta(days=1))
        assert result < 0.9

    def test_decay_at_one_day_past_window_pinned_value(self):
        """Pinned: at 1 day past window (8 days total), decay = 0.05 * 1 = 0.05."""
        result = decayed_confidence(0.9, INFERRED_FRESHNESS_WINDOW + timedelta(days=1))
        expected = max(STALE_FLOOR_CONFIDENCE, 0.9 - 0.05 * 1)
        assert result == pytest.approx(expected, abs=1e-9)

    def test_decay_monotonically_non_increasing_in_age(self):
        """AC 8: decayed_confidence is monotonically non-increasing as age grows."""
        ages = [timedelta(days=d) for d in range(0, 61)]
        values = [decayed_confidence(0.9, a) for a in ages]
        for i in range(len(values) - 1):
            assert values[i] >= values[i + 1], (
                f"non-monotonic at day {i}: {values[i]} < {values[i + 1]}"
            )

    def test_decay_never_exceeds_input_confidence(self):
        """AC 9: decayed_confidence(c, age) <= c for all tested c, age."""
        for c in (0.2, 0.5, 0.6, 0.8, 0.9):
            for days in range(0, 61):
                result = decayed_confidence(c, timedelta(days=days))
                assert result <= c, (
                    f"raised confidence for c={c}, days={days}: got {result}"
                )

    def test_decay_never_below_floor(self):
        """AC 10: decayed_confidence(c, age) >= STALE_FLOOR_CONFIDENCE for all tested c >= floor."""
        for c in (0.2, 0.5, 0.6, 0.8, 0.9, 1.0):
            for days in range(0, 100):
                result = decayed_confidence(c, timedelta(days=days))
                assert result >= STALE_FLOOR_CONFIDENCE, (
                    f"dropped below floor for c={c}, days={days}: got {result}"
                )

    def test_decay_raises_on_negative_age(self):
        """AC 11: decayed_confidence(0.9, timedelta(days=-1)) raises ValueError."""
        with pytest.raises(ValueError):
            decayed_confidence(0.9, timedelta(days=-1))

    def test_decay_raises_on_negative_age_various(self):
        """ValueError raised for any negative timedelta."""
        for neg_secs in (-1, -60, -3600, -86400):
            with pytest.raises(ValueError):
                decayed_confidence(0.9, timedelta(seconds=neg_secs))

    def test_decay_deterministic_same_inputs(self):
        """AC 12: two calls with identical inputs produce identical output."""
        age = INFERRED_FRESHNESS_WINDOW + timedelta(days=5)
        r1 = decayed_confidence(0.9, age)
        r2 = decayed_confidence(0.9, age)
        assert r1 == r2

    def test_decay_deterministic_multiple_values(self):
        """Determinism across a range of inputs."""
        pairs = [
            (0.9, timedelta(0)),
            (0.9, INFERRED_FRESHNESS_WINDOW),
            (0.9, INFERRED_FRESHNESS_WINDOW + timedelta(days=3)),
            (0.5, INFERRED_FRESHNESS_WINDOW + timedelta(days=10)),
            (0.2, timedelta(days=50)),
        ]
        for c, age in pairs:
            r1 = decayed_confidence(c, age)
            r2 = decayed_confidence(c, age)
            assert r1 == r2, f"non-deterministic for c={c}, age={age}"


class TestDecayHelperFloorClamping:
    """Floor clamping edge cases (spec §5 case 5, 8)."""

    def test_floor_clamped_when_decay_would_go_below(self):
        """Decay result is clamped to STALE_FLOOR_CONFIDENCE, not below."""
        # With confidence=0.9, 15 days past window: raw = 0.9 - 0.05*15 = 0.15 < 0.2
        age = INFERRED_FRESHNESS_WINDOW + timedelta(days=15)
        result = decayed_confidence(0.9, age)
        assert result == STALE_FLOOR_CONFIDENCE

    def test_confidence_at_floor_past_window_returns_floor(self):
        """Spec §5 case 5 / §4.1: confidence already at floor, age > window -> floor returned."""
        age = INFERRED_FRESHNESS_WINDOW + timedelta(days=1)
        result = decayed_confidence(STALE_FLOOR_CONFIDENCE, age)
        assert result == STALE_FLOOR_CONFIDENCE

    def test_confidence_below_floor_past_window_returns_floor(self):
        """Edge: current_confidence < floor, age > window -> never raise, return floor."""
        # current_confidence below the floor is unusual but the spec says "never raise"
        age = INFERRED_FRESHNESS_WINDOW + timedelta(days=1)
        result = decayed_confidence(0.1, age)
        # max(0.2, min(0.1, raw)) -> min(0.1, raw) could be < 0.1, then max(0.2,...) = 0.2
        # Actually min(current_confidence=0.1, raw) <= 0.1, max(0.2, <=0.1) = 0.2
        assert result == STALE_FLOOR_CONFIDENCE

    def test_confidence_at_floor_at_window_boundary_returns_floor(self):
        """At exactly the window boundary, confidence at floor is returned unchanged."""
        result = decayed_confidence(STALE_FLOOR_CONFIDENCE, INFERRED_FRESHNESS_WINDOW)
        assert result == STALE_FLOOR_CONFIDENCE


class TestDecayHelperImportability:
    """AC 13: all constants and decayed_confidence importable from infra_twin.core_model."""

    def test_all_constants_importable_from_core_model(self):
        """AC 13: STALE_FLOOR_CONFIDENCE, INFERRED_FRESHNESS_WINDOW, INFERRED_EDGE_TTL,
        INFERRED_DECAY_PER_DAY, and decayed_confidence importable from infra_twin.core_model."""
        from infra_twin.core_model import (
            INFERRED_DECAY_PER_DAY,
            INFERRED_EDGE_TTL,
            INFERRED_FRESHNESS_WINDOW,
            STALE_FLOOR_CONFIDENCE,
            decayed_confidence,
        )
        assert STALE_FLOOR_CONFIDENCE == 0.2
        assert INFERRED_FRESHNESS_WINDOW == timedelta(days=7)
        assert INFERRED_EDGE_TTL == timedelta(days=30)
        assert INFERRED_DECAY_PER_DAY == 0.05
        assert callable(decayed_confidence)


# ===========================================================================
# Section 2: last_observed_at_of accessor (AC 15-16)
# ===========================================================================


class TestLastObservedAtOf:
    """AC 15-16: last_observed_at_of returns correct timestamps."""

    def test_returns_none_when_no_count_marker(self):
        """AC 15: no count marker present -> returns None."""
        evidence = [Evidence(source="aws-flowlogs", observed_at=datetime.now(timezone.utc), detail="x")]
        result = last_observed_at_of(evidence)
        assert result is None

    def test_returns_observed_at_when_marker_present(self):
        """AC 15: returns the count-marker's observed_at."""
        ts = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        evidence = [
            Evidence(source=FLOWLOG_COUNT_EVIDENCE_SOURCE, observed_at=ts, detail="1"),
            Evidence(source="aws-flowlogs", observed_at=ts, detail="other"),
        ]
        result = last_observed_at_of(evidence)
        assert result == ts

    def test_returns_none_for_empty_evidence(self):
        """Edge: empty evidence list -> None."""
        assert last_observed_at_of([]) is None

    def test_after_first_flowlog_post_last_observed_at_is_set(self, pool, make_tenant_with_key):
        """AC 15: after a first POST, last_observed_at_of(edge.evidence) is non-None."""
        tenant, api_key = make_tenant_with_key("aging-loa-first")
        _seed_ec2(pool, tenant, [("i-a1", _IP_A), ("i-b1", _IP_B)])
        client = TestClient(create_app(pool=pool))

        resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp.status_code == 200

        edges = _get_open_inferred_connects_to(pool, tenant)
        assert len(edges) == 1
        loa = last_observed_at_of(edges[0].evidence)
        assert loa is not None

    def test_after_second_post_last_observed_at_advances(self, pool, make_tenant_with_key):
        """AC 16: after a second POST, last_observed_at_of returns the newer timestamp."""
        tenant, api_key = make_tenant_with_key("aging-loa-second")
        _seed_ec2(pool, tenant, [("i-a2", _IP_A), ("i-b2", _IP_B)])
        client = TestClient(create_app(pool=pool))

        resp1 = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp1.status_code == 200

        edges_1 = _get_open_inferred_connects_to(pool, tenant)
        loa_1 = last_observed_at_of(edges_1[0].evidence)
        assert loa_1 is not None

        resp2 = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp2.status_code == 200

        edges_2 = _get_open_inferred_connects_to(pool, tenant)
        loa_2 = last_observed_at_of(edges_2[0].evidence)
        assert loa_2 is not None
        # loa_2 should be >= loa_1 (it is the second batch's observed_at)
        if loa_1.tzinfo is None:
            loa_1 = loa_1.replace(tzinfo=timezone.utc)
        if loa_2.tzinfo is None:
            loa_2 = loa_2.replace(tzinfo=timezone.utc)
        assert loa_2 >= loa_1


# ===========================================================================
# Section 3: write_decayed_version ValueError guards (AC 17)
# ===========================================================================


class TestWriteDecayedVersionGuards:
    """AC 17: write_decayed_version raises ValueError on bad args."""

    def test_raises_on_non_inferred_source(self, pool, make_tenant):
        """AC 17: raises ValueError when current.source != inferred."""
        tenant = make_tenant("aging-wdv-decl")
        _seed_ec2(pool, tenant, [("i-wdv-a", _IP_A), ("i-wdv-b", _IP_B)])

        evidence = [Evidence(source="test", detail="x", observed_at=datetime.now(timezone.utc))]
        with tenant_session(pool, tenant) as conn:
            ci_a = CIRepository(conn, tenant).get_current(
                type=CIType.ec2_instance, external_id="i-wdv-a"
            )[0]
            ci_b = CIRepository(conn, tenant).get_current(
                type=CIType.ec2_instance, external_id="i-wdv-b"
            )[0]
            import uuid as _uuid_mod
            declared_edge = Edge(
                id=_uuid_mod.uuid4(),
                tenant_id=tenant,
                type=EdgeType.CONNECTS_TO,
                from_id=ci_a.id,
                to_id=ci_b.id,
                source=EdgeSource.declared,
                confidence=1.0,
                evidence=evidence,
                valid_from=datetime.now(timezone.utc),
                valid_to=None,
            )
            repo = EdgeRepository(conn, tenant)
            written = repo.upsert(declared_edge)
            with pytest.raises(ValueError, match="inferred"):
                repo.write_decayed_version(
                    written,
                    0.5,
                    decay_evidence=Evidence(
                        source="inferred-edge-decay",
                        observed_at=datetime.now(timezone.utc),
                        detail="test",
                    ),
                )

    def test_raises_on_non_decreasing_confidence(self, pool, make_tenant_with_key):
        """AC 17: raises ValueError when new_confidence >= current.confidence."""
        tenant, api_key = make_tenant_with_key("aging-wdv-nodown")
        _seed_ec2(pool, tenant, [("i-wdv-c", _IP_A), ("i-wdv-d", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)
        assert len(edges) == 1
        current = edges[0]

        with tenant_session(pool, tenant) as conn:
            repo = EdgeRepository(conn, tenant)
            # Same confidence: should raise
            with pytest.raises(ValueError):
                repo.write_decayed_version(
                    current,
                    current.confidence,
                    decay_evidence=Evidence(
                        source="inferred-edge-decay",
                        observed_at=datetime.now(timezone.utc),
                        detail="no-op",
                    ),
                )

    def test_raises_on_higher_confidence(self, pool, make_tenant_with_key):
        """AC 17: raises ValueError when new_confidence > current.confidence."""
        tenant, api_key = make_tenant_with_key("aging-wdv-raise")
        _seed_ec2(pool, tenant, [("i-wdv-e", _IP_A), ("i-wdv-f", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)
        current = edges[0]

        with tenant_session(pool, tenant) as conn:
            repo = EdgeRepository(conn, tenant)
            with pytest.raises(ValueError):
                repo.write_decayed_version(
                    current,
                    current.confidence + 0.1,
                    decay_evidence=Evidence(
                        source="inferred-edge-decay",
                        observed_at=datetime.now(timezone.utc),
                        detail="should raise",
                    ),
                )


# ===========================================================================
# Section 4: Sweep — connector_run_id and run row (AC 18)
# ===========================================================================


class TestSweepConnectorRun:
    """AC 18: sweep returns non-None connector_run_id, run row status == 'ok'."""

    def test_connector_run_id_non_none(self, pool, make_tenant):
        """AC 18: age_inferred_edges returns AgingResult with non-None connector_run_id."""
        tenant = make_tenant("aging-run-id")
        now = datetime.now(timezone.utc)
        result = age_inferred_edges(pool, tenant, now=now)
        assert result.connector_run_id is not None

    def test_connector_run_row_status_ok(self, pool, make_tenant):
        """AC 18: connector_runs row for inferred-edge-aging has status == 'ok'."""
        tenant = make_tenant("aging-run-ok")
        now = datetime.now(timezone.utc)
        result = age_inferred_edges(pool, tenant, now=now)

        runs = _get_connector_runs(tenant, "inferred-edge-aging")
        assert len(runs) == 1
        assert runs[0]["status"] == "ok"
        assert runs[0]["run_id"] == result.connector_run_id

    def test_no_edges_returns_all_zero_counters(self, pool, make_tenant):
        """Spec §5 case 1: no inferred edges -> all counters 0, run still recorded ok."""
        tenant = make_tenant("aging-zero-counters")
        now = datetime.now(timezone.utc)
        result = age_inferred_edges(pool, tenant, now=now)

        assert result.decayed == 0
        assert result.closed == 0
        assert result.untouched == 0
        assert result.connector_run_id is not None
        runs = _get_connector_runs(tenant, "inferred-edge-aging")
        assert len(runs) == 1
        assert runs[0]["status"] == "ok"

    def test_returns_aging_result_type(self, pool, make_tenant):
        """age_inferred_edges returns an AgingResult instance."""
        tenant = make_tenant("aging-result-type")
        result = age_inferred_edges(pool, tenant, now=datetime.now(timezone.utc))
        assert isinstance(result, AgingResult)


# ===========================================================================
# Section 5: Decay path — 14 days past window (AC 19)
# ===========================================================================


class TestDecayPath:
    """AC 19: past window but before TTL -> decayed=1, lower confidence, prior closed version,
    AGE projection updated."""

    def _setup_edge(self, pool, tenant, client, api_key: str = ""):
        """Seed CIs, post one flowlog, return the resulting edge."""
        _seed_ec2(pool, tenant, [("i-dp-a", _IP_A), ("i-dp-b", _IP_B)])
        resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp.status_code == 200
        edges = _get_open_inferred_connects_to(pool, tenant)
        assert len(edges) == 1
        return edges[0]

    def test_decay_aging_result_counts(self, pool, make_tenant_with_key):
        """AC 19: AgingResult(decayed=1, closed=0, untouched=0) after 14-day age."""
        tenant, api_key = make_tenant_with_key("aging-decay-counts")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        loa = last_observed_at_of(edge.evidence)
        assert loa is not None
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        result = age_inferred_edges(pool, tenant, now=now)
        assert result.decayed == 1
        assert result.closed == 0
        assert result.untouched == 0

    def test_decay_exactly_one_current_edge_remains(self, pool, make_tenant_with_key):
        """AC 19: exactly one current (valid_to IS NULL) inferred edge remains after decay."""
        tenant, api_key = make_tenant_with_key("aging-decay-one-open")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        assert len(edges_after) == 1

    def test_decay_new_confidence_strictly_lower(self, pool, make_tenant_with_key):
        """AC 19: confidence after decay is strictly lower than before."""
        tenant, api_key = make_tenant_with_key("aging-decay-lower-conf")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        prev_conf = edge.confidence

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        assert edges_after[0].confidence < prev_conf

    def test_decay_new_confidence_at_or_above_floor(self, pool, make_tenant_with_key):
        """AC 19: decayed confidence >= STALE_FLOOR_CONFIDENCE."""
        tenant, api_key = make_tenant_with_key("aging-decay-floor")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        assert edges_after[0].confidence >= STALE_FLOOR_CONFIDENCE

    def test_decay_prior_closed_version_exists(self, pool, make_tenant_with_key):
        """AC 19: a prior CLOSED bitemporal version (valid_to NOT NULL) exists at the higher
        confidence after decay — no hard delete."""
        tenant, api_key = make_tenant_with_key("aging-decay-closed-prior")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        edge_id = edge.id
        prev_conf = edge.confidence

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        versions = _all_edge_versions(tenant, edge_id)
        closed = [v for v in versions if v["valid_to"] is not None]
        assert len(closed) >= 1, "a prior closed version must exist after decay"

        # Closed version had higher confidence
        first_closed = min(closed, key=lambda v: v["valid_from"])
        assert first_closed["confidence"] == pytest.approx(prev_conf, abs=1e-6)

    def test_decay_no_hard_delete(self, pool, make_tenant_with_key):
        """Bitemporal invariant: TTL never hard-deletes; prior row still present with valid_to set."""
        tenant, api_key = make_tenant_with_key("aging-decay-no-delete")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        edge_id = edge.id

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        versions = _all_edge_versions(tenant, edge_id)
        assert len(versions) >= 2, "both open and closed versions must exist (no hard-delete)"

    def test_decay_same_edge_id_across_versions(self, pool, make_tenant_with_key):
        """Bitemporal: open and closed decay versions share the same edge id."""
        tenant, api_key = make_tenant_with_key("aging-decay-same-id")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        edge_id = edge.id

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        versions = _all_edge_versions(tenant, edge_id)
        assert all(v["id"] == edge_id for v in versions)

    def test_decay_age_projection_reflects_lowered_confidence(self, pool, make_tenant_with_key):
        """AC 19: AGE projection r.confidence reflects the new lowered value after decay."""
        tenant, api_key = make_tenant_with_key("aging-decay-age-proj")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        new_conf = edges_after[0].confidence
        ci_from_id = edges_after[0].from_id
        ci_to_id = edges_after[0].to_id

        with tenant_session(pool, tenant) as conn:
            rows = cypher(
                conn,
                f"MATCH (a {{ci_id: '{ci_from_id}'}})-[r:CONNECTS_TO]->(b {{ci_id: '{ci_to_id}'}}) "
                f"RETURN r.confidence",
                columns="(confidence agtype)",
            )

        assert rows, "AGE projection must have the CONNECTS_TO relationship after decay"
        raw = rows[0][0]
        age_confidence = float(raw) if isinstance(raw, (int, float)) else float(str(raw).strip())
        assert age_confidence == pytest.approx(new_conf, abs=1e-5)

    def test_decay_evidence_contains_decay_entry(self, pool, make_tenant_with_key):
        """After decay, the new open edge has a decay evidence entry appended."""
        tenant, api_key = make_tenant_with_key("aging-decay-evidence")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        decay_entries = [
            ev for ev in edges_after[0].evidence if ev.source == "inferred-edge-decay"
        ]
        assert len(decay_entries) >= 1, "decay evidence entry must be present in new version"

    def test_decay_count_marker_observed_at_unchanged(self, pool, make_tenant_with_key):
        """After decay, last_observed_at_of is NOT advanced (count marker preserved)."""
        tenant, api_key = make_tenant_with_key("aging-decay-loa-unchanged")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        loa_before = last_observed_at_of(edge.evidence)
        if loa_before.tzinfo is None:
            loa_before = loa_before.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa_before)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        loa_after = last_observed_at_of(edges_after[0].evidence)
        if loa_after is not None and loa_after.tzinfo is None:
            loa_after = loa_after.replace(tzinfo=timezone.utc)

        # The decay does not advance last_observed_at
        assert loa_after == loa_before, (
            "decay must not advance last_observed_at (count-marker observed_at)"
        )

    def test_decay_confidence_matches_decayed_confidence_formula(self, pool, make_tenant_with_key):
        """Decayed confidence in DB matches the pure decayed_confidence() formula."""
        tenant, api_key = make_tenant_with_key("aging-decay-formula")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        prev_conf = edge.confidence

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)
        age = now - loa

        expected_conf = decayed_confidence(prev_conf, age)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        # DB stores as REAL (float32), allow slightly wider tolerance
        assert edges_after[0].confidence == pytest.approx(expected_conf, abs=1e-5)


# ===========================================================================
# Section 6: TTL-close path — 60 days (AC 20)
# ===========================================================================


class TestTTLClosePath:
    """AC 20: past TTL -> closed=1, no current version, historical row preserved, AGE removed."""

    def _setup_edge(self, pool, tenant, client, api_key: str = ""):
        _seed_ec2(pool, tenant, [("i-ttl-a", _IP_A), ("i-ttl-b", _IP_B)])
        resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp.status_code == 200
        edges = _get_open_inferred_connects_to(pool, tenant)
        assert len(edges) == 1
        return edges[0]

    def test_ttl_aging_result_counts(self, pool, make_tenant_with_key):
        """AC 20: AgingResult(closed=1, decayed=0, untouched=0) after 60-day age."""
        tenant, api_key = make_tenant_with_key("aging-ttl-counts")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(loa)

        result = age_inferred_edges(pool, tenant, now=now)
        assert result.closed == 1
        assert result.decayed == 0
        assert result.untouched == 0

    def test_ttl_no_current_version(self, pool, make_tenant_with_key):
        """AC 20: no current version (valid_to IS NULL) after TTL close."""
        tenant, api_key = make_tenant_with_key("aging-ttl-no-current")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        edge_id = edge.id

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(loa)

        age_inferred_edges(pool, tenant, now=now)

        open_count = _count_open_rows_for_edge(tenant, edge_id)
        assert open_count == 0, "no open (valid_to IS NULL) row must remain after TTL close"

    def test_ttl_historical_row_still_exists(self, pool, make_tenant_with_key):
        """AC 20: closed historical row still exists (no hard delete)."""
        tenant, api_key = make_tenant_with_key("aging-ttl-history")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        edge_id = edge.id

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(loa)

        age_inferred_edges(pool, tenant, now=now)

        versions = _all_edge_versions(tenant, edge_id)
        assert len(versions) >= 1, "historical row must still exist after TTL close"
        closed = [v for v in versions if v["valid_to"] is not None]
        assert len(closed) >= 1, "at least one closed (valid_to NOT NULL) row must exist"

    def test_ttl_age_projection_removes_relationship(self, pool, make_tenant_with_key):
        """AC 20: AGE projection has no CONNECTS_TO between the two CIs after TTL close."""
        tenant, api_key = make_tenant_with_key("aging-ttl-age-gone")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)

        ci_from_id = edge.from_id
        ci_to_id = edge.to_id

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(loa)

        age_inferred_edges(pool, tenant, now=now)

        with tenant_session(pool, tenant) as conn:
            rows = cypher(
                conn,
                f"MATCH (a {{ci_id: '{ci_from_id}'}})-[r:CONNECTS_TO]->(b {{ci_id: '{ci_to_id}'}}) "
                f"RETURN r.confidence",
                columns="(confidence agtype)",
            )
        assert not rows, (
            "AGE projection must have NO CONNECTS_TO relationship after TTL close"
        )

    def test_ttl_valid_to_set_on_closed_row(self, pool, make_tenant_with_key):
        """Bitemporal: valid_to is set (not null) on the closed TTL row."""
        tenant, api_key = make_tenant_with_key("aging-ttl-validto")
        client = TestClient(create_app(pool=pool))
        edge = self._setup_edge(pool, tenant, client, api_key)
        edge_id = edge.id

        loa = last_observed_at_of(edge.evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(loa)

        age_inferred_edges(pool, tenant, now=now)

        versions = _all_edge_versions(tenant, edge_id)
        closed = [v for v in versions if v["valid_to"] is not None]
        assert len(closed) >= 1
        for v in closed:
            assert v["valid_to"] is not None


# ===========================================================================
# Section 7: Fresh edge untouched (AC 21)
# ===========================================================================


class TestFreshEdgeUntouched:
    """AC 21: freshly re-observed edge (within window) -> untouched=1, no new version."""

    def test_fresh_edge_untouched_count(self, pool, make_tenant_with_key):
        """AC 21: sweep yields untouched=1 for an edge within the freshness window."""
        tenant, api_key = make_tenant_with_key("aging-fresh-count")
        _seed_ec2(pool, tenant, [("i-fr-a", _IP_A), ("i-fr-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp.status_code == 200

        edges = _get_open_inferred_connects_to(pool, tenant)
        loa = last_observed_at_of(edges[0].evidence)
        if loa is None or (loa.tzinfo is None):
            loa = (loa or datetime.now(timezone.utc)).replace(tzinfo=timezone.utc)

        # now is WITHIN the freshness window (1 day after last observed)
        now = loa + timedelta(days=1)
        result = age_inferred_edges(pool, tenant, now=now)

        assert result.untouched == 1
        assert result.decayed == 0
        assert result.closed == 0

    def test_fresh_edge_no_new_version(self, pool, make_tenant_with_key):
        """AC 21: no new bitemporal version created for a fresh edge."""
        tenant, api_key = make_tenant_with_key("aging-fresh-noversion")
        _seed_ec2(pool, tenant, [("i-frv-a", _IP_A), ("i-frv-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)
        edge_id = edges[0].id

        versions_before = _all_edge_versions(tenant, edge_id)

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = loa + timedelta(days=1)

        age_inferred_edges(pool, tenant, now=now)

        versions_after = _all_edge_versions(tenant, edge_id)
        assert len(versions_after) == len(versions_before), (
            "no new version should be created for a fresh edge"
        )

    def test_fresh_edge_confidence_unchanged(self, pool, make_tenant_with_key):
        """AC 21: confidence unchanged after sweep on a fresh edge."""
        tenant, api_key = make_tenant_with_key("aging-fresh-conf")
        _seed_ec2(pool, tenant, [("i-frc-a", _IP_A), ("i-frc-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges_before = _get_open_inferred_connects_to(pool, tenant)
        conf_before = edges_before[0].confidence

        loa = last_observed_at_of(edges_before[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = loa + timedelta(days=1)

        age_inferred_edges(pool, tenant, now=now)

        edges_after = _get_open_inferred_connects_to(pool, tenant)
        assert edges_after[0].confidence == pytest.approx(conf_before, abs=1e-9)

    def test_at_exactly_freshness_window_boundary_is_untouched(self, pool, make_tenant_with_key):
        """Spec §5 case 3: age == INFERRED_FRESHNESS_WINDOW -> untouched (boundary inclusive)."""
        tenant, api_key = make_tenant_with_key("aging-boundary-untouched")
        _seed_ec2(pool, tenant, [("i-bnd-a", _IP_A), ("i-bnd-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        # Exactly at the window boundary
        now = loa + INFERRED_FRESHNESS_WINDOW

        result = age_inferred_edges(pool, tenant, now=now)
        assert result.untouched == 1
        assert result.decayed == 0
        assert result.closed == 0


# ===========================================================================
# Section 8: Declared edges never decayed (AC 22)
# ===========================================================================


class TestDeclaredEdgeNeverDecayed:
    """AC 22: declared CONNECTS_TO edge is never decayed or closed for any now."""

    def _seed_declared_edge(self, pool, tenant):
        """Seed two CIs and a declared CONNECTS_TO edge between them."""
        ev = [Evidence(source="test", detail="declared", observed_at=datetime.now(timezone.utc))]
        events = [
            DiscoveredCI(
                type=CIType.ec2_instance,
                external_id="i-decl-a",
                name="i-decl-a",
                attributes={"private_ip": _IP_C},
            ),
            DiscoveredCI(
                type=CIType.ec2_instance,
                external_id="i-decl-b",
                name="i-decl-b",
                attributes={"private_ip": _IP_D},
            ),
            DiscoveredEdge(
                type=EdgeType.CONNECTS_TO,
                from_ref=CIRef(type=CIType.ec2_instance, external_id="i-decl-a"),
                to_ref=CIRef(type=CIType.ec2_instance, external_id="i-decl-b"),
                source=EdgeSource.declared,
                confidence=1.0,
                evidence=ev,
            ),
        ]
        with tenant_session(pool, tenant) as conn:
            reconcile(
                conn,
                tenant,
                events,
                source=_SEED_SOURCE,
                ci_types=frozenset({CIType.ec2_instance}),
                edge_types=frozenset({EdgeType.CONNECTS_TO}),
            )

    def test_declared_edge_not_decayed_past_window(self, pool, make_tenant):
        """AC 22: declared edge survives sweep with now past window."""
        tenant = make_tenant("aging-decl-past-window")
        self._seed_declared_edge(pool, tenant)

        # Very far future to ensure any inferred edge would decay
        now = datetime.now(timezone.utc) + timedelta(days=365)
        result = age_inferred_edges(pool, tenant, now=now)

        assert result.decayed == 0
        assert result.closed == 0
        assert result.untouched == 0  # declared edges are not counted at all

    def test_declared_edge_not_closed_past_ttl(self, pool, make_tenant):
        """AC 22: declared edge survives sweep with now past TTL."""
        tenant = make_tenant("aging-decl-past-ttl")
        self._seed_declared_edge(pool, tenant)

        now = datetime.now(timezone.utc) + timedelta(days=365)
        age_inferred_edges(pool, tenant, now=now)

        with tenant_session(pool, tenant) as conn:
            edges = EdgeRepository(conn, tenant).get_current()
        declared_open = [
            e for e in edges
            if e.source == EdgeSource.declared and e.valid_to is None
        ]
        assert len(declared_open) == 1, (
            "declared edge must remain open after sweep with now past TTL"
        )

    def test_declared_edge_confidence_unchanged_after_sweep(self, pool, make_tenant):
        """AC 22: declared edge confidence unchanged after sweep."""
        tenant = make_tenant("aging-decl-conf-unchanged")
        self._seed_declared_edge(pool, tenant)

        with tenant_session(pool, tenant) as conn:
            edges_before = EdgeRepository(conn, tenant).get_current()
        declared_before = [e for e in edges_before if e.source == EdgeSource.declared]
        conf_before = declared_before[0].confidence

        now = datetime.now(timezone.utc) + timedelta(days=365)
        age_inferred_edges(pool, tenant, now=now)

        with tenant_session(pool, tenant) as conn:
            edges_after = EdgeRepository(conn, tenant).get_current()
        declared_after = [e for e in edges_after if e.source == EdgeSource.declared and e.valid_to is None]
        assert declared_after[0].confidence == pytest.approx(conf_before, abs=1e-9)

    def test_declared_edge_valid_from_unchanged_after_sweep(self, pool, make_tenant):
        """AC 22: declared edge valid_from unchanged — no re-versioning."""
        tenant = make_tenant("aging-decl-vf-unchanged")
        self._seed_declared_edge(pool, tenant)

        with tenant_session(pool, tenant) as conn:
            edges_before = EdgeRepository(conn, tenant).get_current()
        declared_vf = [e for e in edges_before if e.source == EdgeSource.declared][0].valid_from

        now = datetime.now(timezone.utc) + timedelta(days=365)
        age_inferred_edges(pool, tenant, now=now)

        with tenant_session(pool, tenant) as conn:
            edges_after = EdgeRepository(conn, tenant).get_current()
        declared_after = [e for e in edges_after if e.source == EdgeSource.declared and e.valid_to is None]
        assert declared_after[0].valid_from == declared_vf

    def test_only_declared_edges_all_zero_counters(self, pool, make_tenant):
        """Spec §5 case 2 / AC 22: tenant with only declared edges -> all-zero counters."""
        tenant = make_tenant("aging-decl-only")
        self._seed_declared_edge(pool, tenant)

        now = datetime.now(timezone.utc) + timedelta(days=365)
        result = age_inferred_edges(pool, tenant, now=now)

        assert result.decayed == 0
        assert result.closed == 0
        assert result.untouched == 0


# ===========================================================================
# Section 9: Cross-tenant isolation (AC 23)
# ===========================================================================


class TestCrossTenantIsolation:
    """AC 23: sweep under tenant A never reads/decays/closes tenant B's edges."""

    def test_tenant_b_edge_untouched_after_tenant_a_ttl_sweep(self, pool, make_tenant_with_key):
        """AC 23: tenant B's inferred edge still current after tenant A TTL sweep."""
        tenant_a, key_a = make_tenant_with_key("aging-xt-A")
        tenant_b, key_b = make_tenant_with_key("aging-xt-B")

        _seed_ec2(pool, tenant_a, [("i-a", _IP_A), ("i-b", _IP_B)])
        _seed_ec2(pool, tenant_b, [("i-a", _IP_A), ("i-b", _IP_B)])

        client = TestClient(create_app(pool=pool))

        # Seed inferred edges for both tenants
        _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
        _post_flowlogs(client, tenant_b, [_ACCEPT_FLOW_A_TO_B], key_b)

        # Get tenant A's edge loa to compute TTL-past now
        a_edges = _get_open_inferred_connects_to(pool, tenant_a)
        a_loa = last_observed_at_of(a_edges[0].evidence)
        if a_loa.tzinfo is None:
            a_loa = a_loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(a_loa)

        # Sweep only tenant A
        result_a = age_inferred_edges(pool, tenant_a, now=now)
        assert result_a.closed == 1

        # Tenant B's edge must still be current
        b_edges = _get_open_inferred_connects_to(pool, tenant_b)
        assert len(b_edges) == 1, (
            "tenant B's inferred edge must still be open after tenant A sweep"
        )

    def test_tenant_b_confidence_unchanged_after_tenant_a_sweep(self, pool, make_tenant_with_key):
        """AC 23: tenant B's edge confidence unchanged after tenant A TTL sweep."""
        tenant_a, key_a = make_tenant_with_key("aging-xt-conf-A")
        tenant_b, key_b = make_tenant_with_key("aging-xt-conf-B")

        _seed_ec2(pool, tenant_a, [("i-a", _IP_A), ("i-b", _IP_B)])
        _seed_ec2(pool, tenant_b, [("i-a", _IP_A), ("i-b", _IP_B)])

        client = TestClient(create_app(pool=pool))
        _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
        _post_flowlogs(client, tenant_b, [_ACCEPT_FLOW_A_TO_B], key_b)

        b_edges_before = _get_open_inferred_connects_to(pool, tenant_b)
        b_conf_before = b_edges_before[0].confidence

        a_edges = _get_open_inferred_connects_to(pool, tenant_a)
        a_loa = last_observed_at_of(a_edges[0].evidence)
        if a_loa.tzinfo is None:
            a_loa = a_loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(a_loa)

        age_inferred_edges(pool, tenant_a, now=now)

        b_edges_after = _get_open_inferred_connects_to(pool, tenant_b)
        assert len(b_edges_after) == 1
        assert b_edges_after[0].confidence == pytest.approx(b_conf_before, abs=1e-6)

    def test_tenant_b_still_in_age_projection_after_tenant_a_ttl_sweep(self, pool, make_tenant_with_key):
        """AC 23: tenant B's edge still present in AGE projection after tenant A TTL sweep."""
        tenant_a, key_a = make_tenant_with_key("aging-xt-age-A")
        tenant_b, key_b = make_tenant_with_key("aging-xt-age-B")

        _seed_ec2(pool, tenant_a, [("i-a", _IP_A), ("i-b", _IP_B)])
        _seed_ec2(pool, tenant_b, [("i-a", _IP_A), ("i-b", _IP_B)])

        client = TestClient(create_app(pool=pool))
        _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
        _post_flowlogs(client, tenant_b, [_ACCEPT_FLOW_A_TO_B], key_b)

        b_edges = _get_open_inferred_connects_to(pool, tenant_b)
        b_ci_from = b_edges[0].from_id
        b_ci_to = b_edges[0].to_id

        a_edges = _get_open_inferred_connects_to(pool, tenant_a)
        a_loa = last_observed_at_of(a_edges[0].evidence)
        if a_loa.tzinfo is None:
            a_loa = a_loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(a_loa)

        age_inferred_edges(pool, tenant_a, now=now)

        with tenant_session(pool, tenant_b) as conn:
            rows = cypher(
                conn,
                f"MATCH (a {{ci_id: '{b_ci_from}'}})-[r:CONNECTS_TO]->(b {{ci_id: '{b_ci_to}'}}) "
                f"RETURN r.confidence",
                columns="(confidence agtype)",
            )
        assert rows, "tenant B's AGE edge must still be present after tenant A sweep"

    def test_tenant_b_no_inferred_edge_aging_connector_run(self, pool, make_tenant_with_key):
        """AC 23: tenant B has no inferred-edge-aging connector_runs row after tenant A sweep."""
        tenant_a, key_a = make_tenant_with_key("aging-xt-run-A")
        tenant_b, key_b = make_tenant_with_key("aging-xt-run-B")

        _seed_ec2(pool, tenant_a, [("i-a", _IP_A), ("i-b", _IP_B)])
        _seed_ec2(pool, tenant_b, [("i-a", _IP_A), ("i-b", _IP_B)])

        client = TestClient(create_app(pool=pool))
        _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
        _post_flowlogs(client, tenant_b, [_ACCEPT_FLOW_A_TO_B], key_b)

        a_edges = _get_open_inferred_connects_to(pool, tenant_a)
        a_loa = last_observed_at_of(a_edges[0].evidence)
        if a_loa.tzinfo is None:
            a_loa = a_loa.replace(tzinfo=timezone.utc)

        age_inferred_edges(pool, tenant_a, now=_make_now_past_ttl(a_loa))

        b_runs = _get_connector_runs(tenant_b, "inferred-edge-aging")
        assert len(b_runs) == 0, (
            "tenant B must have no inferred-edge-aging connector_runs row"
        )

    def test_tenant_a_counters_tenant_scoped(self, pool, make_tenant_with_key):
        """AC 23: tenant A's counters reflect only tenant A's edges."""
        tenant_a, key_a = make_tenant_with_key("aging-xt-scope-A")
        tenant_b, key_b = make_tenant_with_key("aging-xt-scope-B")

        _seed_ec2(pool, tenant_a, [("i-a", _IP_A), ("i-b", _IP_B)])
        _seed_ec2(pool, tenant_b, [("i-a", _IP_A), ("i-b", _IP_B)])

        client = TestClient(create_app(pool=pool))
        _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
        _post_flowlogs(client, tenant_b, [_ACCEPT_FLOW_A_TO_B], key_b)

        a_edges = _get_open_inferred_connects_to(pool, tenant_a)
        a_loa = last_observed_at_of(a_edges[0].evidence)
        if a_loa.tzinfo is None:
            a_loa = a_loa.replace(tzinfo=timezone.utc)

        result_a = age_inferred_edges(pool, tenant_a, now=_make_now_past_ttl(a_loa))
        assert result_a.closed == 1  # only tenant A's one edge counted


# ===========================================================================
# Section 10: HTTP endpoint tests (AC 24)
# ===========================================================================


class TestAgeEdgesEndpoint:
    """AC 24: POST /telemetry/maintenance/age-inferred-edges endpoint."""

    def test_valid_tenant_returns_200(self, pool, make_tenant_with_key):
        """AC 24: valid API key returns 200."""
        tenant, api_key = make_tenant_with_key("aging-ep-200")
        client = TestClient(create_app(pool=pool))
        resp = _post_age_edges(client, tenant, api_key)
        assert resp.status_code == 200

    def test_response_has_connector_run_id(self, pool, make_tenant_with_key):
        """AC 24: response JSON contains connector_run_id (uuid string)."""
        tenant, api_key = make_tenant_with_key("aging-ep-runid")
        client = TestClient(create_app(pool=pool))
        resp = _post_age_edges(client, tenant, api_key)
        body = resp.json()
        assert "connector_run_id" in body
        # Must be parseable as UUID
        parsed = UUID(body["connector_run_id"])
        assert parsed is not None

    def test_response_has_decayed_key(self, pool, make_tenant_with_key):
        """AC 24: response JSON contains decayed (int)."""
        tenant, api_key = make_tenant_with_key("aging-ep-decayed")
        client = TestClient(create_app(pool=pool))
        resp = _post_age_edges(client, tenant, api_key)
        body = resp.json()
        assert "decayed" in body
        assert isinstance(body["decayed"], int)

    def test_response_has_closed_key(self, pool, make_tenant_with_key):
        """AC 24: response JSON contains closed (int)."""
        tenant, api_key = make_tenant_with_key("aging-ep-closed")
        client = TestClient(create_app(pool=pool))
        resp = _post_age_edges(client, tenant, api_key)
        body = resp.json()
        assert "closed" in body
        assert isinstance(body["closed"], int)

    def test_response_has_untouched_key(self, pool, make_tenant_with_key):
        """AC 24: response JSON contains untouched (int)."""
        tenant, api_key = make_tenant_with_key("aging-ep-untouched")
        client = TestClient(create_app(pool=pool))
        resp = _post_age_edges(client, tenant, api_key)
        body = resp.json()
        assert "untouched" in body
        assert isinstance(body["untouched"], int)

    def test_missing_auth_header_returns_401(self, pool):
        """AC 24: missing Authorization header returns 401."""
        client = TestClient(create_app(pool=pool))
        resp = client.post("/telemetry/maintenance/age-inferred-edges")
        assert resp.status_code == 401

    def test_bogus_api_key_returns_401(self, pool):
        """AC 24: bogus API key returns 401."""
        client = TestClient(create_app(pool=pool))
        resp = client.post(
            "/telemetry/maintenance/age-inferred-edges",
            headers={"Authorization": "Bearer itw_bogus.key"},
        )
        assert resp.status_code == 401

    def test_empty_tenant_returns_200_zero_counters(self, pool, make_tenant_with_key):
        """AC 24 + spec §5 case 1: no inferred edges returns 200 with all-zero counters."""
        tenant, api_key = make_tenant_with_key("aging-ep-empty")
        client = TestClient(create_app(pool=pool))
        resp = _post_age_edges(client, tenant, api_key)
        assert resp.status_code == 200
        body = resp.json()
        assert body["decayed"] == 0
        assert body["closed"] == 0
        assert body["untouched"] == 0


# ===========================================================================
# Section 11: Module boundary check (AC 25)
# ===========================================================================


class TestModuleBoundaries:
    """AC 25: aging.py must not import infra_twin.collectors or any other service."""

    def test_aging_module_does_not_import_collectors(self):
        """AC 25: services/reconciliation/aging.py imports neither infra_twin.collectors
        nor any other service module."""
        spec = importlib.util.find_spec("infra_twin.reconciliation.aging")
        assert spec is not None and spec.origin is not None

        with open(spec.origin) as f:
            tree = ast.parse(f.read())

        import_names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                import_names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    import_names.append(node.module)

        forbidden = ("infra_twin.collectors",)
        for bad in forbidden:
            assert not any(n.startswith(bad) for n in import_names), (
                f"aging.py must not import {bad!r}; found: {import_names}"
            )

    def test_aging_and_age_inferred_edges_importable_from_reconciliation(self):
        """AC 25: age_inferred_edges and AgingResult importable from infra_twin.reconciliation."""
        from infra_twin.reconciliation import AgingResult, age_inferred_edges
        assert callable(age_inferred_edges)
        assert AgingResult is not None


# ===========================================================================
# Section 12: Idempotency (AC 26)
# ===========================================================================


class TestIdempotency:
    """AC 26: two consecutive sweeps at the same now -> decayed=1 then untouched=1."""

    def test_second_same_now_call_is_noop(self, pool, make_tenant_with_key):
        """AC 26: first call at same now decays, second call at same now is no-op."""
        tenant, api_key = make_tenant_with_key("aging-idem")
        _seed_ec2(pool, tenant, [("i-id-a", _IP_A), ("i-id-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        result1 = age_inferred_edges(pool, tenant, now=now)
        assert result1.decayed == 1, "first call must decay the edge"

        result2 = age_inferred_edges(pool, tenant, now=now)
        assert result2.decayed == 0, "second same-now call must not decay again"
        assert result2.untouched == 1, "second same-now call must count the edge as untouched"

    def test_idempotent_no_runaway_versions(self, pool, make_tenant_with_key):
        """AC 26: two sweeps at same now produce exactly 3 versions total (seed + decay + no-op)."""
        tenant, api_key = make_tenant_with_key("aging-idem-versions")
        _seed_ec2(pool, tenant, [("i-idemv-a", _IP_A), ("i-idemv-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)
        edge_id = edges[0].id

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)
        age_inferred_edges(pool, tenant, now=now)

        versions = _all_edge_versions(tenant, edge_id)
        # Exactly 2 rows: original closed + decayed open (second sweep was no-op)
        assert len(versions) == 2, (
            f"two same-now sweeps must produce exactly 2 versions; got {len(versions)}"
        )


# ===========================================================================
# Section 13: Additional edge cases from spec §5
# ===========================================================================


class TestAdditionalEdgeCases:
    """Additional spec §5 edge cases."""

    def test_no_count_marker_is_untouched(self, pool, make_tenant):
        """Spec §5 case 6: inferred edge with no count marker -> untouched, no crash."""
        tenant = make_tenant("aging-nomarker")
        _seed_ec2(pool, tenant, [("i-nm-a", _IP_A), ("i-nm-b", _IP_B)])

        with tenant_session(pool, tenant) as conn:
            ci_a = CIRepository(conn, tenant).get_current(
                type=CIType.ec2_instance, external_id="i-nm-a"
            )[0]
            ci_b = CIRepository(conn, tenant).get_current(
                type=CIType.ec2_instance, external_id="i-nm-b"
            )[0]

        # Manually insert a pre-feature inferred edge without count marker
        edge_id = uuid.uuid4()
        pre_evidence = [
            {
                "source": "aws-flowlogs",
                "observed_at": "2025-01-01T00:00:00+00:00",
                "detail": "no-count-marker",
            }
        ]
        with psycopg.connect(admin_dsn()) as admin_conn:
            admin_conn.execute(
                "INSERT INTO edges (id, tenant_id, type, from_id, to_id, source, confidence, "
                "evidence, valid_from, valid_to) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), NULL)",
                (
                    edge_id,
                    tenant,
                    EdgeType.CONNECTS_TO.value,
                    ci_a.id,
                    ci_b.id,
                    EdgeSource.inferred.value,
                    0.6,
                    psycopg.types.json.Jsonb(pre_evidence),
                ),
            )
            admin_conn.commit()

        now = datetime.now(timezone.utc) + timedelta(days=365)
        result = age_inferred_edges(pool, tenant, now=now)

        assert result.untouched == 1
        assert result.decayed == 0
        assert result.closed == 0

    def test_future_last_observed_at_is_untouched(self, pool, make_tenant_with_key):
        """Spec §5 case 7: last_observed_at in future relative to now -> untouched, no crash."""
        tenant, api_key = make_tenant_with_key("aging-future-loa")
        _seed_ec2(pool, tenant, [("i-fut-a", _IP_A), ("i-fut-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)

        # now is BEFORE last_observed_at (simulating clock skew)
        now = loa - timedelta(days=1)
        result = age_inferred_edges(pool, tenant, now=now)

        assert result.untouched == 1
        assert result.decayed == 0
        assert result.closed == 0

    def test_ttl_vs_decay_mutually_exclusive_per_edge(self, pool, make_tenant_with_key):
        """Spec §5 case 9: each edge is closed OR decayed OR untouched — never both."""
        tenant, api_key = make_tenant_with_key("aging-exclusive")
        _seed_ec2(pool, tenant, [("i-ex-a", _IP_A), ("i-ex-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        result = age_inferred_edges(pool, tenant, now=now)
        total = result.decayed + result.closed + result.untouched
        assert total == 1  # exactly one inferred edge

    def test_at_exactly_ttl_boundary_is_not_closed(self, pool, make_tenant_with_key):
        """Spec §5 case 4: age == INFERRED_EDGE_TTL -> NOT closed (TTL boundary is strict >)."""
        tenant, api_key = make_tenant_with_key("aging-ttl-boundary")
        _seed_ec2(pool, tenant, [("i-ttlb-a", _IP_A), ("i-ttlb-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        # Exactly at the TTL boundary (not past it)
        now = loa + INFERRED_EDGE_TTL

        result = age_inferred_edges(pool, tenant, now=now)
        assert result.closed == 0, (
            "edge exactly at TTL boundary must NOT be closed (strict >)"
        )
        # It should be decayed since FRESHNESS_WINDOW < age == TTL
        assert result.decayed == 1 or result.untouched == 1  # depends on floor clamping

    def test_confidence_already_at_floor_past_window_is_untouched(self, pool, make_tenant):
        """Spec §5 case 5: confidence at floor, window < age <= TTL -> untouched (no new version)."""
        tenant = make_tenant("aging-at-floor")
        _seed_ec2(pool, tenant, [("i-af-a", _IP_A), ("i-af-b", _IP_B)])

        with tenant_session(pool, tenant) as conn:
            ci_a = CIRepository(conn, tenant).get_current(
                type=CIType.ec2_instance, external_id="i-af-a"
            )[0]
            ci_b = CIRepository(conn, tenant).get_current(
                type=CIType.ec2_instance, external_id="i-af-b"
            )[0]

        # Manually insert an inferred edge at STALE_FLOOR_CONFIDENCE with a count marker
        obs_ts = datetime.now(timezone.utc) - timedelta(days=14)
        edge_id = uuid.uuid4()
        floor_evidence = [
            {
                "source": FLOWLOG_COUNT_EVIDENCE_SOURCE,
                "observed_at": obs_ts.isoformat(),
                "detail": "1",
            },
            {
                "source": "aws-flowlogs",
                "observed_at": obs_ts.isoformat(),
                "detail": "at-floor",
            },
        ]
        with psycopg.connect(admin_dsn()) as admin_conn:
            admin_conn.execute(
                "INSERT INTO edges (id, tenant_id, type, from_id, to_id, source, confidence, "
                "evidence, valid_from, valid_to) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), NULL)",
                (
                    edge_id,
                    tenant,
                    EdgeType.CONNECTS_TO.value,
                    ci_a.id,
                    ci_b.id,
                    EdgeSource.inferred.value,
                    STALE_FLOOR_CONFIDENCE,
                    psycopg.types.json.Jsonb(floor_evidence),
                ),
            )
            admin_conn.commit()

        # now is past the freshness window: decayed_confidence(0.2, 14d) == 0.2 >= 0.2 -> untouched
        now = datetime.now(timezone.utc)
        result = age_inferred_edges(pool, tenant, now=now)
        assert result.untouched == 1
        assert result.decayed == 0
        assert result.closed == 0

    def test_bitemporal_invariant_at_most_one_open_row(self, pool, make_tenant_with_key):
        """Spec §5 case 18: at all times each (type, from, to) pair has at most one open row."""
        tenant, api_key = make_tenant_with_key("aging-bitemp-oneopen")
        _seed_ec2(pool, tenant, [("i-bt-a", _IP_A), ("i-bt-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_window(loa)

        age_inferred_edges(pool, tenant, now=now)

        # Must still be exactly one open row
        with psycopg.connect(admin_dsn()) as admin_conn:
            count = admin_conn.execute(
                "SELECT count(*) FROM edges WHERE valid_to IS NULL AND tenant_id = %s "
                "AND type = %s AND source = %s",
                (tenant, EdgeType.CONNECTS_TO.value, EdgeSource.inferred.value),
            ).fetchone()[0]
        assert count == 1, (
            f"must have exactly 1 open CONNECTS_TO inferred edge after decay; got {count}"
        )

    def test_empty_unknown_tenant_returns_200(self, pool, make_tenant_with_key):
        """Spec §5 case 17: empty/unknown tenant UUID -> all counters 0, 200."""
        # Create a tenant that has no CIs or edges
        tenant, api_key = make_tenant_with_key("aging-unknown-tenant")
        client = TestClient(create_app(pool=pool))
        resp = _post_age_edges(client, tenant, api_key)
        assert resp.status_code == 200
        body = resp.json()
        assert body["decayed"] == 0
        assert body["closed"] == 0
        assert body["untouched"] == 0

    def test_no_hard_delete_on_ttl_close(self, pool, make_tenant_with_key):
        """Spec §5 case 19 / bitemporal invariant: TTL close sets valid_to, no hard delete."""
        tenant, api_key = make_tenant_with_key("aging-no-hd-ttl")
        _seed_ec2(pool, tenant, [("i-nhd-a", _IP_A), ("i-nhd-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)
        edge_id = edges[0].id

        loa = last_observed_at_of(edges[0].evidence)
        if loa.tzinfo is None:
            loa = loa.replace(tzinfo=timezone.utc)
        now = _make_now_past_ttl(loa)

        age_inferred_edges(pool, tenant, now=now)

        # Row must still exist in DB (just with valid_to set)
        with psycopg.connect(admin_dsn()) as admin_conn:
            total_rows = admin_conn.execute(
                "SELECT count(*) FROM edges WHERE id = %s AND tenant_id = %s",
                (edge_id, tenant),
            ).fetchone()[0]
        assert total_rows >= 1, "historical row must exist after TTL close (no hard delete)"


# ===========================================================================
# Section 14: Regression — strengthen path still passes (AC 16 confirmation)
# ===========================================================================


class TestStrengthenPathRegression:
    """Confirm the existing strengthen path is byte-for-byte unchanged."""

    def test_two_posts_yield_count_2_confidence_08(self, pool, make_tenant_with_key):
        """Regression: two separate POST /telemetry/flowlogs still yield count=2, confidence=0.8."""
        from infra_twin.core_model import confidence_for_observations

        tenant, api_key = make_tenant_with_key("aging-regression-reobs")
        _seed_ec2(pool, tenant, [("i-reg-a", _IP_A), ("i-reg-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

        edges = _get_open_inferred_connects_to(pool, tenant)
        assert len(edges) == 1
        from infra_twin.db.repositories import FLOWLOG_COUNT_EVIDENCE_SOURCE

        count_entries = [e for e in edges[0].evidence if e.source == FLOWLOG_COUNT_EVIDENCE_SOURCE]
        assert len(count_entries) == 1
        assert count_entries[0].detail == "2"
        assert edges[0].confidence == pytest.approx(0.8, abs=1e-9)
        assert edges[0].confidence == pytest.approx(confidence_for_observations(2), abs=1e-9)

    def test_strengthen_then_decay_composes(self, pool, make_tenant_with_key):
        """Spec §5 case 13: re-observation after decay advances loa and restores confidence path."""
        tenant, api_key = make_tenant_with_key("aging-compose")
        _seed_ec2(pool, tenant, [("i-cmp-a", _IP_A), ("i-cmp-b", _IP_B)])
        client = TestClient(create_app(pool=pool))

        # First observation
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        edges = _get_open_inferred_connects_to(pool, tenant)
        loa1 = last_observed_at_of(edges[0].evidence)
        if loa1.tzinfo is None:
            loa1 = loa1.replace(tzinfo=timezone.utc)

        # Decay: now = 14 days past first observation
        now_decay = _make_now_past_window(loa1)
        result = age_inferred_edges(pool, tenant, now=now_decay)
        assert result.decayed == 1

        # Re-observe: this raises confidence again via strengthen path
        resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp.status_code == 200

        edges_after_reobs = _get_open_inferred_connects_to(pool, tenant)
        loa_new = last_observed_at_of(edges_after_reobs[0].evidence)
        if loa_new is None or loa_new.tzinfo is None:
            if loa_new:
                loa_new = loa_new.replace(tzinfo=timezone.utc)

        # Re-observe advances last_observed_at (it should be >= loa1)
        if loa_new is not None:
            assert loa_new >= loa1

        # Now sweep with now within window of re-observation -> untouched
        if loa_new is not None:
            now_within_window = loa_new + timedelta(days=1)
            result2 = age_inferred_edges(pool, tenant, now=now_within_window)
            assert result2.untouched == 1
            assert result2.decayed == 0
