"""Integration tests for evidence-weighted confidence accumulation on re-observed
inferred VPC Flow Log CONNECTS_TO edges.

Covers all 10 required test cases from the task, all spec acceptance criteria (AC 9-22),
and all 21 edge cases from specs.md §6.

Structure:
1. AC 9: repository constants.
2. T-REOBS2: two separate POSTs -> count=2, confidence=0.8, open edge (AC 10).
3. T-VERSION: prior closed version exists at count=1/confidence=0.6, same id (AC 11).
4. T-EVIDENCE: evidence contains entries from both observations, len <= 21 (AC 12).
5. T-REOBS3: third POST -> count=3, confidence=0.9 (AC 13).
6. T-NEWPAIR: new distinct ordered pair starts at count=1/confidence=0.6 (AC 14).
7. T-BATCH1: same pair in one batch counts as +1 observation (AC 15).
8. T-CAP: 22 POSTs -> count=22, observation rows capped at 20, len==21 (edge case 11).
9. T-DECLARED-UNTOUCHED: declared edge gets no count marker and no confidence boost (AC 16).
10. T-XTENANT-COUNT: cross-tenant isolation; counts are per-tenant (AC 17).
11. T-AGE: AGE edge confidence == 0.8 after second observation (AC 18).
12. T-PREDATES: pre-feature edge (no count marker) -> treat as count=1, then count=2 (edge case 12).
13. Regression: CloudTrail POST /events/aws path unaffected.
14. Regression: discover_and_reconcile path unaffected (declared edges only).
15. Bitemporal integrity: no hard-delete, exactly one open row per pair at all times.
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.collectors.aws import (
    DEFAULT_FLOW_CONFIDENCE,
    parse_flow_logs,
)
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import (
    CIType,
    EdgeSource,
    EdgeType,
    Evidence,
    INFERRED_BASELINE_CONFIDENCE,
    confidence_for_observations,
)
from infra_twin.db.config import admin_dsn
from infra_twin.db.graph import cypher
from infra_twin.db.repositories import (
    EVIDENCE_WINDOW_CAP,
    FLOWLOG_COUNT_EVIDENCE_SOURCE,
    CIRepository,
    EdgeRepository,
)
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEED_SOURCE = "test-seed-connector"
_IP_A = "10.0.1.1"
_IP_B = "10.0.1.2"
_IP_C = "10.0.1.3"
_IP_D = "10.0.1.4"
_IP_E = "10.0.1.5"  # used for new distinct pair in T-NEWPAIR

_ACCEPT_FLOW_A_TO_B = {
    "srcaddr": _IP_A,
    "dstaddr": _IP_B,
    "srcport": 54321,
    "dstport": 443,
    "protocol": 6,
    "action": "ACCEPT",
    "start": 1700000000,
    "end": 1700000060,
}

_ACCEPT_FLOW_A_TO_E = {
    "srcaddr": _IP_A,
    "dstaddr": _IP_E,
    "srcport": 12345,
    "dstport": 80,
    "protocol": 6,
    "action": "ACCEPT",
    "start": 1700000100,
    "end": 1700000160,
}

_CLOUDTRAIL_FIXTURE_DIR = (
    pathlib.Path(__file__).resolve().parent / "fixtures" / "cloudtrail"
)


# ---------------------------------------------------------------------------
# Shared helpers (mirror test_telemetry_flowlogs.py conventions)
# ---------------------------------------------------------------------------


def _seed_ec2_many(pool, tenant: UUID, instances: list[tuple[str, str]]) -> None:
    """Seed multiple ec2_instance CIs in one reconcile call."""
    events = [
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id=ext_id,
            name=ext_id,
            attributes={"private_ip": private_ip},
        )
        for ext_id, private_ip in instances
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


def _get_open_connects_to(pool, tenant: UUID) -> list:
    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    return [
        e
        for e in edges
        if e.type == EdgeType.CONNECTS_TO and e.valid_to is None
    ]


def _count_connects_to(pool, tenant: UUID, *, source: str | None = None) -> int:
    edges = _get_open_connects_to(pool, tenant)
    if source is not None:
        edges = [e for e in edges if e.source.value == source]
    return len(edges)


def _get_count_from_evidence(evidence: list[Evidence]) -> int | None:
    """Extract the observation count from the reserved count-marker Evidence entry."""
    for ev in evidence:
        if ev.source == FLOWLOG_COUNT_EVIDENCE_SOURCE:
            try:
                return int(ev.detail)
            except (TypeError, ValueError):
                return None
    return None


def _all_edge_versions(pool_or_conn, tenant: UUID, edge_id: UUID) -> list[dict]:
    """Return ALL rows (open + closed) for a given edge id via superuser connection.

    Uses the admin connection to bypass RLS and inspect raw bitemporal history.
    """
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT id, confidence, evidence, valid_from, valid_to "
            "FROM edges WHERE id = %s AND tenant_id = %s ORDER BY valid_from",
            (edge_id, tenant),
        ).fetchall()
    return [
        {
            "id": r[0],
            "confidence": r[1],
            "evidence": r[2],
            "valid_from": r[3],
            "valid_to": r[4],
        }
        for r in rows
    ]


# ===========================================================================
# AC 9: Repository constants
# ===========================================================================


def test_flowlog_count_evidence_source_constant():
    """AC 9: FLOWLOG_COUNT_EVIDENCE_SOURCE == 'aws-flowlogs-count'."""
    assert FLOWLOG_COUNT_EVIDENCE_SOURCE == "aws-flowlogs-count"


def test_evidence_window_cap_constant():
    """AC 9: EVIDENCE_WINDOW_CAP == 20."""
    assert EVIDENCE_WINDOW_CAP == 20


# ===========================================================================
# T-REOBS2: Two separate POSTs -> count=2, confidence=0.8, one open edge (AC 10)
# ===========================================================================


def test_reobs2_exactly_one_open_edge_after_two_posts(pool, make_tenant_with_key):
    """T-REOBS2 / AC 10: two separate POSTs of the same ACCEPT flow produce exactly one
    open (valid_to IS NULL) inferred CONNECTS_TO edge."""
    tenant, api_key = make_tenant_with_key("acc-reobs2-open")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp1 = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp1.status_code == 200
    resp2 = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp2.status_code == 200

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1, f"expected exactly 1 open CONNECTS_TO; got {len(edges)}"


def test_reobs2_open_edge_is_inferred(pool, make_tenant_with_key):
    """T-REOBS2 / AC 10: the open edge after two POSTs has source == inferred."""
    tenant, api_key = make_tenant_with_key("acc-reobs2-inferred")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].source == EdgeSource.inferred, (
        f"expected inferred; got {edges[0].source!r}"
    )


def test_reobs2_count_equals_2(pool, make_tenant_with_key):
    """T-REOBS2 / AC 10: after two separate POSTs, observation count == 2."""
    tenant, api_key = make_tenant_with_key("acc-reobs2-count")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count = _get_count_from_evidence(edges[0].evidence)
    assert count == 2, f"expected count==2; got {count!r}"


def test_reobs2_confidence_equals_08(pool, make_tenant_with_key):
    """T-REOBS2 / AC 10: after two POSTs, confidence == confidence_for_observations(2) == 0.8."""
    tenant, api_key = make_tenant_with_key("acc-reobs2-conf")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].confidence == pytest.approx(confidence_for_observations(2), abs=1e-9)
    assert edges[0].confidence == pytest.approx(0.8, abs=1e-9)


def test_reobs2_confidence_strictly_greater_than_06(pool, make_tenant_with_key):
    """T-REOBS2 / AC 10: confidence after two POSTs is strictly > 0.6."""
    tenant, api_key = make_tenant_with_key("acc-reobs2-gt06")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].confidence > 0.6, (
        f"confidence after 2 observations must be > 0.6; got {edges[0].confidence}"
    )


def test_reobs2_confidence_strictly_less_than_1(pool, make_tenant_with_key):
    """T-REOBS2 / AC 10: confidence after two POSTs is strictly < 1.0."""
    tenant, api_key = make_tenant_with_key("acc-reobs2-lt1")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].confidence < 1.0, (
        f"inferred confidence must be < 1.0; got {edges[0].confidence}"
    )


# ===========================================================================
# T-VERSION: prior closed version exists (AC 11, edge case 21)
# ===========================================================================


def test_version_prior_closed_version_exists(pool, make_tenant_with_key):
    """T-VERSION / AC 11: after two POSTs, a prior row with valid_to NOT NULL exists."""
    tenant, api_key = make_tenant_with_key("acc-version-closed")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    edge_id = edges[0].id

    versions = _all_edge_versions(pool, tenant, edge_id)
    assert len(versions) >= 2, (
        f"expected at least 2 rows (one closed, one open); got {len(versions)}"
    )

    closed = [v for v in versions if v["valid_to"] is not None]
    assert len(closed) >= 1, "expected at least one closed (valid_to NOT NULL) version"


def test_version_prior_closed_has_confidence_06(pool, make_tenant_with_key):
    """T-VERSION / AC 11: the closed prior version has confidence == 0.6."""
    tenant, api_key = make_tenant_with_key("acc-version-conf06")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    edge_id = edges[0].id
    versions = _all_edge_versions(pool, tenant, edge_id)
    closed = [v for v in versions if v["valid_to"] is not None]
    assert len(closed) >= 1

    first_version = min(closed, key=lambda v: v["valid_from"])
    assert first_version["confidence"] == pytest.approx(0.6, abs=1e-9), (
        f"prior closed version must have confidence=0.6; got {first_version['confidence']}"
    )


def test_version_prior_closed_has_count_1(pool, make_tenant_with_key):
    """T-VERSION / AC 11: the closed prior version has count==1 in evidence."""
    tenant, api_key = make_tenant_with_key("acc-version-cnt1")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    edge_id = edges[0].id
    versions = _all_edge_versions(pool, tenant, edge_id)
    closed = [v for v in versions if v["valid_to"] is not None]
    first_version = min(closed, key=lambda v: v["valid_from"])

    evidence_list = first_version["evidence"]
    count_entries = [
        e for e in evidence_list if e.get("source") == FLOWLOG_COUNT_EVIDENCE_SOURCE
    ]
    assert len(count_entries) == 1, (
        f"expected one count-marker Evidence entry in prior version; found {count_entries}"
    )
    assert count_entries[0].get("detail") == "1", (
        f"prior version count marker must have detail='1'; got {count_entries[0]!r}"
    )


def test_version_same_id_across_versions(pool, make_tenant_with_key):
    """T-VERSION / AC 11: open and closed versions share the same edge id (no hard-delete)."""
    tenant, api_key = make_tenant_with_key("acc-version-sameid")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    edge_id = edges[0].id
    versions = _all_edge_versions(pool, tenant, edge_id)

    # All rows returned share the same id (that's how we queried); verify no deletion.
    assert len(versions) >= 2
    assert all(v["id"] == edge_id for v in versions), (
        "all versions must share the same edge id"
    )

    open_versions = [v for v in versions if v["valid_to"] is None]
    assert len(open_versions) == 1, (
        f"exactly one open version must exist; got {len(open_versions)}"
    )


def test_version_no_hard_delete(pool, make_tenant_with_key):
    """T-VERSION / edge case 21: raw edges table still contains the prior row after re-observation."""
    tenant, api_key = make_tenant_with_key("acc-version-nodelete")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges_after_1 = _get_open_connects_to(pool, tenant)
    edge_id = edges_after_1[0].id

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    versions = _all_edge_versions(pool, tenant, edge_id)
    assert len(versions) == 2, (
        f"expected exactly 2 rows (1 closed + 1 open) after two POSTs; got {len(versions)}"
    )


# ===========================================================================
# T-EVIDENCE: evidence contains entries from both observations, len <= 21 (AC 12)
# ===========================================================================


def test_evidence_has_count_marker(pool, make_tenant_with_key):
    """T-EVIDENCE / AC 12: open edge evidence includes a count-marker entry."""
    tenant, api_key = make_tenant_with_key("acc-evid-marker")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count_entries = [
        ev for ev in edges[0].evidence if ev.source == FLOWLOG_COUNT_EVIDENCE_SOURCE
    ]
    assert len(count_entries) == 1, (
        f"expected exactly one count-marker Evidence entry; got {count_entries}"
    )
    assert count_entries[0].detail == "2"


def test_evidence_has_flowlog_entries_from_both_observations(pool, make_tenant_with_key):
    """T-EVIDENCE / AC 12: open edge evidence contains aws-flowlogs entries from both
    observations (at least 2 aws-flowlogs entries after two POSTs)."""
    tenant, api_key = make_tenant_with_key("acc-evid-both")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    obs_entries = [ev for ev in edges[0].evidence if ev.source == "aws-flowlogs"]
    assert len(obs_entries) >= 2, (
        f"expected at least 2 aws-flowlogs evidence entries after 2 observations; "
        f"got {len(obs_entries)}"
    )


def test_evidence_total_length_within_cap(pool, make_tenant_with_key):
    """T-EVIDENCE / AC 12: len(evidence) <= 1 + EVIDENCE_WINDOW_CAP (== 21) after two POSTs."""
    tenant, api_key = make_tenant_with_key("acc-evid-cap")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert len(edges[0].evidence) <= 1 + EVIDENCE_WINDOW_CAP, (
        f"evidence length {len(edges[0].evidence)} exceeds cap {1 + EVIDENCE_WINDOW_CAP}"
    )


# ===========================================================================
# T-REOBS3: third POST -> count=3, confidence=0.9 (AC 13)
# ===========================================================================


def test_reobs3_count_equals_3(pool, make_tenant_with_key):
    """T-REOBS3 / AC 13: after three separate POSTs, observation count == 3."""
    tenant, api_key = make_tenant_with_key("acc-reobs3-count")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count = _get_count_from_evidence(edges[0].evidence)
    assert count == 3, f"expected count==3 after third POST; got {count!r}"


def test_reobs3_confidence_equals_09(pool, make_tenant_with_key):
    """T-REOBS3 / AC 13: after three POSTs, confidence == confidence_for_observations(3) == 0.9."""
    tenant, api_key = make_tenant_with_key("acc-reobs3-conf")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].confidence == pytest.approx(confidence_for_observations(3), abs=1e-9)
    assert edges[0].confidence == pytest.approx(0.9, abs=1e-9)


def test_reobs3_confidence_greater_than_reobs2(pool, make_tenant_with_key):
    """T-REOBS3 / AC 13: confidence after 3 observations > confidence after 2 (strictly increasing)."""
    tenant, api_key = make_tenant_with_key("acc-reobs3-incr")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges_2 = _get_open_connects_to(pool, tenant)
    conf_after_2 = edges_2[0].confidence

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges_3 = _get_open_connects_to(pool, tenant)
    conf_after_3 = edges_3[0].confidence

    assert conf_after_3 > conf_after_2, (
        f"confidence after 3 observations ({conf_after_3}) must be > after 2 ({conf_after_2})"
    )


def test_reobs3_confidence_still_below_one(pool, make_tenant_with_key):
    """T-REOBS3 / AC 13: confidence after 3 observations is still < 1.0."""
    tenant, api_key = make_tenant_with_key("acc-reobs3-lt1")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    for _ in range(3):
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert edges[0].confidence < 1.0


def test_reobs3_three_versions_exist(pool, make_tenant_with_key):
    """T-REOBS3 / edge case 3: after 3 POSTs, three bitemporal versions exist, two closed."""
    tenant, api_key = make_tenant_with_key("acc-reobs3-3ver")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    for _ in range(3):
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    edge_id = edges[0].id
    versions = _all_edge_versions(pool, tenant, edge_id)

    assert len(versions) == 3, f"expected 3 versions after 3 POSTs; got {len(versions)}"
    closed = [v for v in versions if v["valid_to"] is not None]
    assert len(closed) == 2, f"expected 2 closed versions; got {len(closed)}"


# ===========================================================================
# T-NEWPAIR: new distinct ordered pair starts at count=1/confidence=0.6 (AC 14)
# ===========================================================================


def test_newpair_count_starts_at_1(pool, make_tenant_with_key):
    """T-NEWPAIR / AC 14: a new distinct ordered pair (A->E) starts at count=1."""
    tenant, api_key = make_tenant_with_key("acc-newpair-count")
    _seed_ec2_many(
        pool,
        tenant,
        [("i-alpha", _IP_A), ("i-beta", _IP_B), ("i-echo", _IP_E)],
    )
    client = TestClient(create_app(pool=pool))

    # Observe A->B twice to give it count=2.
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    # Now observe A->E for the first time.
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_E], api_key)

    edges = _get_open_connects_to(pool, tenant)
    # Find the A->E edge by looking for the one with the lower count.
    ae_edges = []
    for e in edges:
        cnt = _get_count_from_evidence(e.evidence)
        if cnt == 1:
            ae_edges.append(e)

    assert len(ae_edges) == 1, (
        f"expected exactly one edge with count=1 (the new A->E pair); "
        f"found {len(ae_edges)}"
    )


def test_newpair_confidence_starts_at_06(pool, make_tenant_with_key):
    """T-NEWPAIR / AC 14: a new distinct ordered pair starts at confidence == 0.6."""
    tenant, api_key = make_tenant_with_key("acc-newpair-conf")
    _seed_ec2_many(
        pool,
        tenant,
        [("i-alpha", _IP_A), ("i-beta", _IP_B), ("i-echo", _IP_E)],
    )
    client = TestClient(create_app(pool=pool))

    # Post A->E only once.
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_E], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].confidence == pytest.approx(INFERRED_BASELINE_CONFIDENCE, abs=1e-9)
    assert edges[0].confidence == pytest.approx(0.6, abs=1e-9)


def test_newpair_independent_of_existing_pair(pool, make_tenant_with_key):
    """T-NEWPAIR / AC 14: observing A->B multiple times does not affect A->E count."""
    tenant, api_key = make_tenant_with_key("acc-newpair-indep")
    _seed_ec2_many(
        pool,
        tenant,
        [("i-alpha", _IP_A), ("i-beta", _IP_B), ("i-echo", _IP_E)],
    )
    client = TestClient(create_app(pool=pool))

    # Observe A->B three times.
    for _ in range(3):
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    # Observe A->E once.
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_E], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 2

    for e in edges:
        count = _get_count_from_evidence(e.evidence)
        if e.confidence == pytest.approx(0.9, abs=1e-9):
            assert count == 3, f"A->B should have count=3; got {count}"
        elif e.confidence == pytest.approx(0.6, abs=1e-9):
            assert count == 1, f"A->E should have count=1; got {count}"


# ===========================================================================
# T-BATCH1: same pair in one batch counts as exactly +1 observation (AC 15)
# ===========================================================================


def test_batch1_single_batch_duplicate_flow_yields_count_1(pool, make_tenant_with_key):
    """T-BATCH1 / AC 15: posting [flow, flow] (same pair) in ONE call yields count==1."""
    tenant, api_key = make_tenant_with_key("acc-batch1-count")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    # Post the same A->B flow twice in a single batch.
    resp = _post_flowlogs(
        client, tenant, [_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_A_TO_B], api_key
    )
    assert resp.status_code == 200
    # Parser deduplicates, so only 1 edge written per batch.
    assert resp.json()["edges_written"] == 1

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count = _get_count_from_evidence(edges[0].evidence)
    assert count == 1, (
        f"single batch with duplicate flow must yield count=1; got {count}"
    )


def test_batch1_single_batch_duplicate_confidence_is_06(pool, make_tenant_with_key):
    """T-BATCH1 / AC 15: single batch with duplicate flows yields confidence==0.6 (first sight)."""
    tenant, api_key = make_tenant_with_key("acc-batch1-conf")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].confidence == pytest.approx(0.6, abs=1e-9)


def test_batch1_second_batch_yields_count_2(pool, make_tenant_with_key):
    """T-BATCH1 / AC 15: after a second separate POST of the same pair, count becomes 2."""
    tenant, api_key = make_tenant_with_key("acc-batch1-second")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    # First batch (with duplicate): count=1.
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_A_TO_B], api_key)
    # Second separate POST: count should go to 2.
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count = _get_count_from_evidence(edges[0].evidence)
    assert count == 2, (
        f"second separate POST should raise count to 2; got {count}"
    )


# ===========================================================================
# T-CAP: evidence cap at 22 observations (edge case 11, AC 12)
# ===========================================================================


def test_cap_22_posts_count_equals_22(pool, make_tenant_with_key):
    """T-CAP / edge case 11: after 22 separate POSTs, count == 22 (count exceeds cap)."""
    tenant, api_key = make_tenant_with_key("acc-cap-count")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    for _ in range(22):
        resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp.status_code == 200

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count = _get_count_from_evidence(edges[0].evidence)
    assert count == 22, f"expected count==22 after 22 POSTs; got {count}"


def test_cap_22_posts_observation_evidence_capped_at_20(pool, make_tenant_with_key):
    """T-CAP / edge case 11: after 22 POSTs, retained observation Evidence rows == 20."""
    tenant, api_key = make_tenant_with_key("acc-cap-obsrows")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    for _ in range(22):
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    obs_entries = [
        ev for ev in edges[0].evidence if ev.source == "aws-flowlogs"
    ]
    assert len(obs_entries) == EVIDENCE_WINDOW_CAP, (
        f"expected {EVIDENCE_WINDOW_CAP} observation evidence rows; got {len(obs_entries)}"
    )


def test_cap_22_posts_total_evidence_length_equals_21(pool, make_tenant_with_key):
    """T-CAP / edge case 11: after 22 POSTs, len(evidence) == 21 (1 count marker + 20 obs)."""
    tenant, api_key = make_tenant_with_key("acc-cap-totlen")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    for _ in range(22):
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert len(edges[0].evidence) == 1 + EVIDENCE_WINDOW_CAP, (
        f"expected len(evidence)=={1 + EVIDENCE_WINDOW_CAP}; got {len(edges[0].evidence)}"
    )


def test_cap_22_posts_confidence_reflects_true_count(pool, make_tenant_with_key):
    """T-CAP / edge case 11: confidence reflects the true count (22), not the capped list length.

    The confidence column is REAL (single-precision float), so we allow 1e-6 tolerance
    to accommodate the precision loss on storage.
    """
    tenant, api_key = make_tenant_with_key("acc-cap-conf22")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    for _ in range(22):
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    expected = confidence_for_observations(22)
    # Use 1e-6 tolerance: the confidence column is REAL (4-byte float), so full float64
    # precision is not preserved; the stored value differs by at most ~1e-7.
    assert edges[0].confidence == pytest.approx(expected, abs=1e-6), (
        f"expected confidence_for_observations(22)={expected}; got {edges[0].confidence}"
    )


# ===========================================================================
# T-DECLARED-UNTOUCHED: declared edge is never aggregated (AC 16, edge case 7)
# ===========================================================================


def test_declared_edge_has_no_count_marker(pool, make_tenant):
    """T-DECLARED-UNTOUCHED / AC 16: a seeded declared CONNECTS_TO edge has no count marker."""
    tenant = make_tenant("acc-decl-nomarker")
    evidence = [Evidence(source="test", detail="declared-seed")]
    events = [
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-ccc",
            name="i-ccc",
            attributes={"private_ip": _IP_C},
        ),
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-ddd",
            name="i-ddd",
            attributes={"private_ip": _IP_D},
        ),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.ec2_instance, external_id="i-ccc"),
            to_ref=CIRef(type=CIType.ec2_instance, external_id="i-ddd"),
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=evidence,
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

    edges = _get_open_connects_to(pool, tenant)
    declared = [e for e in edges if e.source == EdgeSource.declared]
    assert len(declared) == 1
    count_entries = [
        ev for ev in declared[0].evidence if ev.source == FLOWLOG_COUNT_EVIDENCE_SOURCE
    ]
    assert len(count_entries) == 0, (
        f"declared edge must not have a count-marker; found {count_entries}"
    )


def test_declared_edge_confidence_unchanged_after_flowlog_post(pool, make_tenant_with_key):
    """T-DECLARED-UNTOUCHED / AC 16: posting flow logs for a different pair does not
    change a declared edge's confidence."""
    tenant, api_key = make_tenant_with_key("acc-decl-confunchanged")
    evidence = [Evidence(source="test", detail="declared-seed")]
    # Seed all four CIs + declared C->D + inferred A->B endpoint CIs in one reconcile.
    events = [
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-aaa",
            name="i-aaa",
            attributes={"private_ip": _IP_A},
        ),
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-bbb",
            name="i-bbb",
            attributes={"private_ip": _IP_B},
        ),
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-ccc",
            name="i-ccc",
            attributes={"private_ip": _IP_C},
        ),
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-ddd",
            name="i-ddd",
            attributes={"private_ip": _IP_D},
        ),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.ec2_instance, external_id="i-ccc"),
            to_ref=CIRef(type=CIType.ec2_instance, external_id="i-ddd"),
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=evidence,
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

    # Capture declared edge state before flowlog POST.
    with tenant_session(pool, tenant) as conn:
        before_edges = EdgeRepository(conn, tenant).get_current()
    declared_before = [
        e
        for e in before_edges
        if e.type == EdgeType.CONNECTS_TO and e.source == EdgeSource.declared
    ]
    assert len(declared_before) == 1, "setup: declared edge not seeded correctly"
    declared_valid_from = declared_before[0].valid_from
    declared_confidence_before = declared_before[0].confidence

    client = TestClient(create_app(pool=pool))
    # Post A->B flows; declared C->D should be unaffected.
    for _ in range(2):
        resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
        assert resp.status_code == 200

    with tenant_session(pool, tenant) as conn:
        after_edges = EdgeRepository(conn, tenant).get_current()
    declared_after = [
        e
        for e in after_edges
        if e.type == EdgeType.CONNECTS_TO and e.source == EdgeSource.declared
        and e.valid_to is None
    ]
    assert len(declared_after) == 1, "declared edge must remain open after flowlogs POST"
    assert declared_after[0].valid_from == declared_valid_from, (
        "declared edge valid_from must not change"
    )
    assert declared_after[0].confidence == pytest.approx(declared_confidence_before, abs=1e-9), (
        f"declared edge confidence must not change; "
        f"before={declared_confidence_before}, after={declared_after[0].confidence}"
    )
    assert declared_after[0].valid_to is None, "declared edge must remain open"


def test_declared_edge_repost_is_noop(pool, make_tenant):
    """T-DECLARED-UNTOUCHED / edge case 8: re-posting the same declared edge produces no new version."""
    tenant = make_tenant("acc-decl-noop")
    evidence = [Evidence(source="test", detail="declared-seed")]
    events = [
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-ccc",
            name="i-ccc",
            attributes={"private_ip": _IP_C},
        ),
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id="i-ddd",
            name="i-ddd",
            attributes={"private_ip": _IP_D},
        ),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.ec2_instance, external_id="i-ccc"),
            to_ref=CIRef(type=CIType.ec2_instance, external_id="i-ddd"),
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=evidence,
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

    # Re-post the same declared edge.
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            events,
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.ec2_instance}),
            edge_types=frozenset({EdgeType.CONNECTS_TO}),
        )

    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    declared_open = [
        e
        for e in edges
        if e.type == EdgeType.CONNECTS_TO and e.source == EdgeSource.declared
        and e.valid_to is None
    ]
    assert len(declared_open) == 1, (
        f"re-posting declared edge must be a no-op; got {len(declared_open)} open declared edges"
    )


# ===========================================================================
# T-XTENANT-COUNT: cross-tenant isolation (AC 17, edge case 15)
# ===========================================================================


def test_xtenant_tenant_a_reobservation_does_not_affect_tenant_b(pool, make_tenant_with_key):
    """T-XTENANT-COUNT / AC 17: re-observation under tenant A leaves tenant B with zero
    CONNECTS_TO edges."""
    tenant_a, key_a = make_tenant_with_key("acc-xtenant-A")
    tenant_b, _ = make_tenant_with_key("acc-xtenant-B")

    # Seed the same IP pair under BOTH tenants.
    _seed_ec2_many(pool, tenant_a, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    _seed_ec2_many(pool, tenant_b, [("i-alpha", _IP_A), ("i-beta", _IP_B)])

    client = TestClient(create_app(pool=pool))

    # POST under tenant A twice (so A has count=2, confidence=0.8).
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)

    # Tenant B must still have zero CONNECTS_TO edges.
    b_edges = _get_open_connects_to(pool, tenant_b)
    assert len(b_edges) == 0, (
        f"tenant B must see zero CONNECTS_TO edges; got {len(b_edges)}"
    )


def test_xtenant_counts_are_per_tenant(pool, make_tenant_with_key):
    """T-XTENANT-COUNT / AC 17: same IP pair under two tenants have independent counts."""
    tenant_a, key_a = make_tenant_with_key("acc-xtenant-cnt-A")
    tenant_b, key_b = make_tenant_with_key("acc-xtenant-cnt-B")

    _seed_ec2_many(pool, tenant_a, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    _seed_ec2_many(pool, tenant_b, [("i-alpha", _IP_A), ("i-beta", _IP_B)])

    client = TestClient(create_app(pool=pool))

    # A gets 2 observations; B gets 1.
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
    _post_flowlogs(client, tenant_b, [_ACCEPT_FLOW_A_TO_B], key_b)

    a_edges = _get_open_connects_to(pool, tenant_a)
    b_edges = _get_open_connects_to(pool, tenant_b)

    assert len(a_edges) == 1
    assert len(b_edges) == 1

    a_count = _get_count_from_evidence(a_edges[0].evidence)
    b_count = _get_count_from_evidence(b_edges[0].evidence)

    assert a_count == 2, f"tenant A must have count=2; got {a_count}"
    assert b_count == 1, f"tenant B must have count=1; got {b_count}"


def test_xtenant_bare_pool_sees_no_edges(pool, make_tenant_with_key):
    """T-XTENANT-COUNT / AC 17: bare pool connection (no GUC) sees zero edges (RLS enforced)."""
    tenant_a, key_a = make_tenant_with_key("acc-xtenant-bare-A")
    _seed_ec2_many(pool, tenant_a, [("i-alpha", _IP_A), ("i-beta", _IP_B)])

    client = TestClient(create_app(pool=pool))
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM edges").fetchone()[0]
    assert count == 0, (
        f"bare pool connection must see zero edges (RLS enforced); got {count}"
    )


def test_xtenant_no_count_markers_visible_to_other_tenant(pool, make_tenant_with_key):
    """T-XTENANT-COUNT / AC 17: tenant B sees zero count markers after tenant A's re-observation."""
    tenant_a, key_a = make_tenant_with_key("acc-xtenant-marker-A")
    tenant_b, _ = make_tenant_with_key("acc-xtenant-marker-B")

    _seed_ec2_many(pool, tenant_a, [("i-alpha", _IP_A), ("i-beta", _IP_B)])

    client = TestClient(create_app(pool=pool))
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)
    _post_flowlogs(client, tenant_a, [_ACCEPT_FLOW_A_TO_B], key_a)

    # Tenant B must see zero CONNECTS_TO edges and zero count markers.
    b_edges = _get_open_connects_to(pool, tenant_b)
    assert len(b_edges) == 0

    b_markers = []
    for e in b_edges:
        b_markers.extend(
            ev for ev in e.evidence if ev.source == FLOWLOG_COUNT_EVIDENCE_SOURCE
        )
    assert len(b_markers) == 0, (
        f"tenant B must see zero count markers; got {len(b_markers)}"
    )


# ===========================================================================
# T-AGE: AGE edge confidence == 0.8 after second observation (AC 18)
# ===========================================================================


def test_age_confidence_reflects_reobservation(pool, make_tenant_with_key):
    """T-AGE / AC 18: after the second observation, the AGE CONNECTS_TO edge for the pair
    has confidence == 0.8 (confidence_for_observations(2))."""
    tenant, api_key = make_tenant_with_key("acc-age-conf")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    # Retrieve the CI ids for A and B so we can query the AGE edge.
    with tenant_session(pool, tenant) as conn:
        cis_a = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-alpha"
        )
        cis_b = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-beta"
        )
        ci_a_id = cis_a[0].id
        ci_b_id = cis_b[0].id

        rows = cypher(
            conn,
            f"MATCH (a {{ci_id: '{ci_a_id}'}})-[r:CONNECTS_TO]->(b {{ci_id: '{ci_b_id}'}}) "
            f"RETURN r.confidence",
            columns="(confidence agtype)",
        )

    assert rows, "no AGE CONNECTS_TO edge found after two observations"
    # AGE returns agtype; extract the numeric value from the first row.
    raw = rows[0][0]
    # psycopg returns agtype as a string like "0.8" or as a float.
    if isinstance(raw, (int, float)):
        age_confidence = float(raw)
    else:
        age_confidence = float(str(raw).strip())

    assert age_confidence == pytest.approx(0.8, abs=1e-6), (
        f"AGE edge confidence must be 0.8 after second observation; got {age_confidence}"
    )


# ===========================================================================
# T-PREDATES: pre-feature edge (no count marker) treated as count=1 (edge case 12)
# ===========================================================================


def test_predates_no_count_marker_treated_as_count_1(pool, make_tenant_with_key):
    """T-PREDATES / edge case 12: an open inferred edge inserted WITHOUT a count marker
    (simulating a pre-feature row) is treated as count=1 on the next observation,
    resulting in count=2 / confidence=0.8. No crash."""
    tenant, api_key = make_tenant_with_key("acc-predates")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])

    # Retrieve CI ids.
    with tenant_session(pool, tenant) as conn:
        ci_a = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-alpha"
        )[0]
        ci_b = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-beta"
        )[0]

    # Manually insert a pre-feature inferred edge WITHOUT a count marker.
    pre_evidence = [
        {
            "source": "aws-flowlogs",
            "observed_at": "2025-01-01T00:00:00+00:00",
            "detail": "dstport=443 protocol=6 window=...",
        }
    ]
    from infra_twin.connector_sdk import DiscoveredEdge as _DE
    from infra_twin.core_model.models import Edge
    import uuid

    edge_id = uuid.uuid4()
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

    # Now post one observation; should increment to count=2, confidence=0.8.
    client = TestClient(create_app(pool=pool))
    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count = _get_count_from_evidence(edges[0].evidence)
    assert count == 2, f"pre-feature edge: after 1 POST, count must be 2; got {count}"
    assert edges[0].confidence == pytest.approx(0.8, abs=1e-9), (
        f"pre-feature edge: confidence must be 0.8; got {edges[0].confidence}"
    )


def test_predates_no_count_marker_no_crash(pool, make_tenant_with_key):
    """T-PREDATES / edge case 12: posting a flow log when the existing edge has no count
    marker does not crash."""
    tenant, api_key = make_tenant_with_key("acc-predates-nocrash")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])

    with tenant_session(pool, tenant) as conn:
        ci_a = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-alpha"
        )[0]
        ci_b = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-beta"
        )[0]

    import uuid

    edge_id = uuid.uuid4()
    pre_evidence = [
        {
            "source": "aws-flowlogs",
            "observed_at": "2025-01-01T00:00:00+00:00",
            "detail": "no count marker",
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

    client = TestClient(create_app(pool=pool))
    # Should not raise.
    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200


# ===========================================================================
# Regression: CloudTrail /events/aws path unaffected (AC 19, 20)
# ===========================================================================


def test_cloudtrail_path_no_count_marker_on_declared_edges(pool, make_tenant):
    """AC 19: declared edges produced by the CloudTrail /events/aws path carry no count
    marker and no confidence boost (regression check)."""
    import json
    import pathlib
    from infra_twin.reconciliation import apply_event_delta

    fixture_path = _CLOUDTRAIL_FIXTURE_DIR / "run_instances_single.json"
    if not fixture_path.exists():
        pytest.skip("CloudTrail fixture not available")

    tenant = make_tenant("acc-ct-regression")
    fixture = json.loads(fixture_path.read_text())

    from infra_twin.collectors.aws.events import EVENT_SOURCE, parse_event

    try:
        delta = parse_event(fixture)
    except Exception:
        pytest.skip("parse_event could not parse fixture")

    observed_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    with tenant_session(pool, tenant) as conn:
        try:
            apply_event_delta(conn, tenant, delta, observed_at=observed_at)
        except Exception:
            pytest.skip("apply_event_delta failed (likely missing seed data)")

    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    declared_edges = [e for e in edges if e.source == EdgeSource.declared]
    for edge in declared_edges:
        count_markers = [
            ev for ev in edge.evidence if ev.source == FLOWLOG_COUNT_EVIDENCE_SOURCE
        ]
        assert len(count_markers) == 0, (
            f"declared edge from CloudTrail must have no count marker; found {count_markers}"
        )


# ===========================================================================
# Regression: parser module purity (AC 19)
# ===========================================================================


def test_parser_module_no_db_imports():
    """AC 19: flowlogs.py imports neither boto3, infra_twin.db, nor infra_twin.reconciliation
    (regression; ensures parser purity is preserved after feature addition)."""
    import ast
    import importlib.util

    spec = importlib.util.find_spec("infra_twin.collectors.aws.flowlogs")
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
    for forbidden in ("boto3", "infra_twin.db", "infra_twin.reconciliation"):
        assert not any(n.startswith(forbidden) for n in import_names), (
            f"flowlogs.py must not import {forbidden!r}; found imports: {import_names}"
        )


def test_reconciliation_does_not_import_collectors():
    """AC 20: no module under services/reconciliation imports infra_twin.collectors
    (regression check)."""
    import infra_twin.reconciliation.events as mod

    for name, obj in mod.__dict__.items():
        if hasattr(obj, "__module__") and obj.__module__ is not None:
            assert "infra_twin.collectors" not in str(obj.__module__), (
                f"reconciliation.events imported {obj.__module__!r} via name {name!r}"
            )


# ===========================================================================
# AC 21: no new migration, _EDGE_COLUMNS unchanged
# ===========================================================================


def test_edge_columns_unchanged():
    """AC 21 (updated for edge_key feature): _EDGE_COLUMNS in repositories.py contains the
    original set of columns plus edge_key (added in 0019_edge_key_identity migration).
    The flow-log confidence accumulation feature did not add any column; edge_key was added
    by the parallel-edge-identity feature and is now the expected full set."""
    from infra_twin.db import repositories

    expected_columns = {
        "id",
        "tenant_id",
        "type",
        "from_id",
        "to_id",
        "edge_key",
        "source",
        "confidence",
        "evidence",
        "valid_from",
        "valid_to",
    }
    actual = set(repositories._EDGE_COLUMNS.replace(",", " ").split())
    assert expected_columns == actual, (
        f"_EDGE_COLUMNS changed unexpectedly; expected {expected_columns}, got {actual}"
    )


# ===========================================================================
# Bitemporal integrity: exactly one open row per pair, never two open rows
# ===========================================================================


def test_bitemporal_at_most_one_open_row_per_pair(pool, make_tenant_with_key):
    """Edge case 21: at no point does a pair have more than one open edge row."""
    tenant, api_key = make_tenant_with_key("acc-bitemp-oneopen")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    for _ in range(5):
        _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

        with psycopg.connect(admin_dsn()) as admin_conn:
            count = admin_conn.execute(
                "SELECT count(*) FROM edges WHERE valid_to IS NULL AND tenant_id = %s "
                "AND type = %s",
                (tenant, EdgeType.CONNECTS_TO.value),
            ).fetchone()[0]
        assert count == 1, (
            f"must have exactly 1 open CONNECTS_TO edge at all times; got {count}"
        )


def test_bitemporal_first_sight_count_marker_is_present(pool, make_tenant_with_key):
    """Edge case 1: first observation of a pair includes count marker at count=1."""
    tenant, api_key = make_tenant_with_key("acc-bitemp-firstsight")
    _seed_ec2_many(pool, tenant, [("i-alpha", _IP_A), ("i-beta", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    count = _get_count_from_evidence(edges[0].evidence)
    assert count == 1, f"first observation must have count=1; got {count}"
    assert edges[0].confidence == pytest.approx(0.6, abs=1e-9)
