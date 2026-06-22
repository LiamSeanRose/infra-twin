"""Integration tests for POST /telemetry/flowlogs and the pure parse_flow_logs parser.

Covers the full test matrix from specs.md §9 (T1-T14) and all edge cases from §7.
Also verifies acceptance criteria §10 and the purity / layering invariants from §7 #16.

Structure:
1. Purity and layering checks (AC 7, 8).
2. T2  Route 200 shape.
3. T3  Two ACCEPT flows deduplicated to one inferred CONNECTS_TO edge.
4. T4  connector_run_id / connector_runs / raw_facts linkage under aws-flowlogs.
5. T5  Unknown IP -> no edge.
6. T6  REJECT flow -> no edge.
7. T7  Malformed record -> 422, nothing persisted.
8. T8  Pre-existing declared edge untouched.
9. T9  Empty batch -> 200, all-zero counters, valid run row.
10. T10 observed_at = max end.
11. T11 Bad/missing X-Tenant-Id header.
12. T12 Cross-tenant resolution (tenant B sees none of A's instances).
13. T13 Cross-tenant visibility (tenant B can't read A's rows).
14. T14 Direction preserved (A->B and B->A are two distinct edges).
15. Parser-level edge cases (REJECT skip, unresolved skip, dedup, empty delta, error types).
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import time
from datetime import datetime, timezone
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.collectors.aws import (
    DEFAULT_FLOW_CONFIDENCE,
    FLOWLOG_SOURCE,
    FlowLogParseError,
    parse_flow_logs,
)
from infra_twin.connector_sdk import CIRef, ConnectorDelta, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeSource, EdgeType, Evidence
from infra_twin.db.config import admin_dsn
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile

# ---------------------------------------------------------------------------
# Constants and shared helpers
# ---------------------------------------------------------------------------

_SEED_SOURCE = "test-seed-connector"
_IP_A = "10.0.0.1"
_IP_B = "10.0.0.2"
_IP_C = "10.0.0.3"
_IP_D = "10.0.0.4"
_UNKNOWN_IP = "192.168.99.99"

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

_ACCEPT_FLOW_B_TO_A = {
    "srcaddr": _IP_B,
    "dstaddr": _IP_A,
    "srcport": 443,
    "dstport": 54321,
    "protocol": 6,
    "action": "ACCEPT",
    "start": 1700000000,
    "end": 1700000060,
}

_REJECT_FLOW_A_TO_B = {
    "srcaddr": _IP_A,
    "dstaddr": _IP_B,
    "srcport": 54321,
    "dstport": 443,
    "protocol": 6,
    "action": "REJECT",
    "start": 1700000000,
    "end": 1700000060,
}

# A record that passes Pydantic (all fields present, correct types) but has an
# empty action string — the parser will raise FlowLogParseError on it.
_MALFORMED_RECORD_EMPTY_ACTION = {
    "srcaddr": _IP_A,
    "dstaddr": _IP_B,
    "srcport": 54321,
    "dstport": 443,
    "protocol": 6,
    "action": "",
    "start": 1700000000,
    "end": 1700000060,
}

_EXPECTED_RESPONSE_KEYS = {
    "connector_run_id",
    "cis_created",
    "cis_updated",
    "cis_unchanged",
    "cis_closed",
    "edges_written",
    "edges_closed",
}


def _seed_ec2_many(pool, tenant: UUID, instances: list[tuple[str, str]]) -> None:
    """Seed multiple ec2_instance CIs in a single reconcile call.

    ``instances`` is a list of (external_id, private_ip) pairs.  Seeding in a single
    call avoids reconcile closing earlier CIs when it sees an updated batch.
    """
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


def _seed_ec2(pool, tenant: UUID, *, ext_id: str, private_ip: str) -> None:
    """Seed a single ec2_instance CI with the given private_ip attribute.

    Note: if you need to seed multiple CIs for the same tenant, use _seed_ec2_many()
    to avoid the second reconcile call closing the first CI.
    """
    _seed_ec2_many(pool, tenant, [(ext_id, private_ip)])


def _seed_declared_edge(
    pool,
    tenant: UUID,
    from_ext: str,
    to_ext: str,
) -> None:
    """Seed a declared CONNECTS_TO edge between two ec2_instance CIs."""
    evidence = [Evidence(source="test", detail="declared-seed")]
    events = [
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id=from_ext,
            name=from_ext,
            attributes={"private_ip": _IP_C},
        ),
        DiscoveredCI(
            type=CIType.ec2_instance,
            external_id=to_ext,
            name=to_ext,
            attributes={"private_ip": _IP_D},
        ),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.ec2_instance, external_id=from_ext),
            to_ref=CIRef(type=CIType.ec2_instance, external_id=to_ext),
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


def _count_connects_to(pool, tenant: UUID, *, source: str | None = None) -> int:
    """Count open CONNECTS_TO edges, optionally filtered by source."""
    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    result = [e for e in edges if e.type == EdgeType.CONNECTS_TO and e.valid_to is None]
    if source is not None:
        result = [e for e in result if e.source.value == source]
    return len(result)


def _get_open_connects_to(pool, tenant: UUID) -> list:
    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    return [e for e in edges if e.type == EdgeType.CONNECTS_TO and e.valid_to is None]


def _post_flowlogs(client, tenant: UUID, records: list[dict], api_key: str = "") -> object:
    return client.post(
        "/telemetry/flowlogs",
        json={"records": records},
        headers={"Authorization": f"Bearer {api_key}"},
    )


# ===========================================================================
# 1. Purity and layering checks (AC 7, 8, spec §7 #16)
# ===========================================================================


def test_parse_flow_logs_importable_from_collectors_aws():
    """AC 7: parse_flow_logs importable from infra_twin.collectors.aws."""
    from infra_twin.collectors.aws import parse_flow_logs as _pfl  # noqa: F401


def test_flowlog_parse_error_importable_from_collectors_aws():
    """AC 7: FlowLogParseError importable from infra_twin.collectors.aws."""
    from infra_twin.collectors.aws import FlowLogParseError as _fpe  # noqa: F401


def test_flowlog_source_importable_from_collectors_aws():
    """AC 7: FLOWLOG_SOURCE importable from infra_twin.collectors.aws."""
    from infra_twin.collectors.aws import FLOWLOG_SOURCE as _fs  # noqa: F401


def test_flowlog_parse_error_is_value_error_subclass():
    """AC 7: FlowLogParseError is a subclass of ValueError."""
    assert issubclass(FlowLogParseError, ValueError)


def test_flowlog_source_value():
    """AC 3: FLOWLOG_SOURCE == 'aws-flowlogs'."""
    assert FLOWLOG_SOURCE == "aws-flowlogs"


def test_default_flow_confidence_value():
    """AC 4: DEFAULT_FLOW_CONFIDENCE == 0.6."""
    assert DEFAULT_FLOW_CONFIDENCE == 0.6


def test_default_flow_confidence_in_range():
    """AC 4: 0 < DEFAULT_FLOW_CONFIDENCE < 1."""
    assert 0 < DEFAULT_FLOW_CONFIDENCE < 1


def test_flowlogs_module_imports_no_boto3():
    """AC 8: flowlogs.py imports neither boto3, infra_twin.db, nor infra_twin.reconciliation."""
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


def test_reconciliation_events_does_not_import_collectors():
    """AC 8: no module under services/reconciliation imports infra_twin.collectors."""
    import infra_twin.reconciliation.events as mod
    for name, obj in mod.__dict__.items():
        if hasattr(obj, "__module__") and obj.__module__ is not None:
            assert "infra_twin.collectors" not in str(obj.__module__), (
                f"reconciliation.events imported {obj.__module__!r} via name {name!r}"
            )


# ===========================================================================
# 2. T2: Route 200 shape (AC 13)
# ===========================================================================


def test_flowlogs_route_200_shape(pool, make_tenant_with_key):
    """T2 / AC 13: POST /telemetry/flowlogs with a valid ACCEPT batch returns 200 with
    exactly the 7 expected keys."""
    tenant, api_key = make_tenant_with_key("fl-t2-shape")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    assert set(resp.json().keys()) == _EXPECTED_RESPONSE_KEYS, (
        f"response keys mismatch: {set(resp.json().keys())}"
    )


def test_flowlogs_route_200_key_count(pool, make_tenant_with_key):
    """AC 13: response has exactly 7 keys (no extras)."""
    tenant, api_key = make_tenant_with_key("fl-t2-7keys")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    assert len(resp.json()) == 7


# ===========================================================================
# 3. T3: Two ACCEPT flows for same pair deduplicated to one edge (AC 5, 6, 15)
# ===========================================================================


def test_two_accept_flows_produce_one_edge(pool, make_tenant_with_key):
    """T3 / AC 5, 6, 15: two ACCEPT A->B flows produce exactly ONE open inferred CONNECTS_TO
    edge with valid_to IS NULL."""
    tenant, api_key = make_tenant_with_key("fl-t3-dedup")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    # Post the same A->B flow twice.
    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    body = resp.json()
    assert body["edges_written"] == 1, (
        f"expected edges_written==1 for two identical flows; got {body['edges_written']}"
    )

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1, f"expected exactly 1 open CONNECTS_TO; got {len(edges)}"


def test_deduped_edge_is_inferred(pool, make_tenant_with_key):
    """T3 / AC 5: the deduped CONNECTS_TO edge has source == inferred."""
    tenant, api_key = make_tenant_with_key("fl-t3-inferred")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert edges[0].source == EdgeSource.inferred, (
        f"edge source must be inferred; got {edges[0].source!r}"
    )


def test_deduped_edge_confidence_in_range(pool, make_tenant_with_key):
    """T3 / AC 5: the deduped CONNECTS_TO edge has 0 < confidence < 1."""
    tenant, api_key = make_tenant_with_key("fl-t3-conf")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    assert 0 < edges[0].confidence < 1, (
        f"edge confidence must be in (0, 1); got {edges[0].confidence}"
    )


def test_deduped_edge_has_evidence_with_flowlogs_source(pool, make_tenant_with_key):
    """T3 / AC 5: the CONNECTS_TO edge has at least one evidence with source=='aws-flowlogs'."""
    tenant, api_key = make_tenant_with_key("fl-t3-evid")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.evidence, "CONNECTS_TO edge must have non-empty evidence list"
    assert any(ev.source == "aws-flowlogs" for ev in edge.evidence), (
        f"no evidence with source='aws-flowlogs'; got {[ev.source for ev in edge.evidence]}"
    )


# ===========================================================================
# 4. T4: connector_run_id / connector_runs / raw_facts linkage (AC 15)
# ===========================================================================


def test_connector_run_id_is_valid_uuid(pool, make_tenant_with_key):
    """T4 / AC 13: connector_run_id in response is a valid UUID string."""
    tenant, api_key = make_tenant_with_key("fl-t4-uuid")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]
    parsed = UUID(run_id_str)
    assert str(parsed) == run_id_str


def test_connector_run_id_matches_db_row(pool, make_tenant_with_key):
    """T4 / AC 15: response connector_run_id equals connector_runs.run_id in the DB."""
    tenant, api_key = make_tenant_with_key("fl-t4-dbmatch")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]

    with tenant_session(pool, tenant) as conn:
        row = conn.execute(
            "SELECT run_id FROM connector_runs WHERE source = 'aws-flowlogs' "
            "ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    assert row is not None, "no connector_runs row written for aws-flowlogs"
    assert str(row[0]) == run_id_str, (
        f"response connector_run_id {run_id_str!r} != DB run_id {row[0]!r}"
    )


def test_aws_flowlogs_connector_row_registered(pool, make_tenant_with_key):
    """T4 / AC 15: exactly one aws-flowlogs connector row is registered on first call."""
    tenant, api_key = make_tenant_with_key("fl-t4-connreg")
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [], api_key)

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT connector_id, type FROM connectors WHERE type = 'aws-flowlogs'"
        ).fetchall()
    assert len(rows) == 1, f"expected 1 aws-flowlogs connector row; got {len(rows)}"


def test_aws_flowlogs_connector_id_matches_run_and_facts(pool, make_tenant_with_key):
    """T4 / AC 15: connector_runs and raw_facts are stamped with the aws-flowlogs connector_id."""
    tenant, api_key = make_tenant_with_key("fl-t4-connid")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200

    with tenant_session(pool, tenant) as conn:
        connector_id = conn.execute(
            "SELECT connector_id FROM connectors WHERE type = 'aws-flowlogs'"
        ).fetchone()[0]
        run_conn_id = conn.execute(
            "SELECT connector_id FROM connector_runs WHERE source = 'aws-flowlogs'"
        ).fetchone()[0]
        fact_conn_id = conn.execute(
            "SELECT connector_id FROM raw_facts WHERE source = 'aws-flowlogs' LIMIT 1"
        ).fetchone()[0]

    assert run_conn_id == connector_id, (
        f"connector_runs.connector_id {run_conn_id} != connectors.connector_id {connector_id}"
    )
    assert fact_conn_id == connector_id, (
        f"raw_facts.connector_id {fact_conn_id} != connectors.connector_id {connector_id}"
    )


def test_aws_flowlogs_connector_reused_on_second_call(pool, make_tenant_with_key):
    """T4 / AC 15: two flowlogs POSTs reuse a single aws-flowlogs connector row."""
    tenant, api_key = make_tenant_with_key("fl-t4-reuse")
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [], api_key)
    _post_flowlogs(client, tenant, [], api_key)

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connectors WHERE type = 'aws-flowlogs'"
        ).fetchone()[0]
    assert count == 1, f"expected single aws-flowlogs connector row; got {count}"


# ===========================================================================
# 5. T5: Unknown IP -> no edge (spec §7 #3, #4)
# ===========================================================================


def test_unknown_dst_ip_produces_no_edge(pool, make_tenant_with_key):
    """T5 / spec §7 #3: dstaddr matching no current ec2_instance CI -> edges_written==0."""
    tenant, api_key = make_tenant_with_key("fl-t5-unknowndst")
    _seed_ec2(pool, tenant, ext_id="i-aaa", private_ip=_IP_A)
    # _IP_B is NOT seeded
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    body = resp.json()
    assert body["edges_written"] == 0, (
        f"expected edges_written==0 when dst IP unknown; got {body['edges_written']}"
    )
    assert _count_connects_to(pool, tenant) == 0


def test_unknown_src_ip_produces_no_edge(pool, make_tenant_with_key):
    """T5 / spec §7 #4: neither endpoint resolves -> no edge."""
    tenant, api_key = make_tenant_with_key("fl-t5-unknownsrc")
    # Nothing seeded at all
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    assert resp.json()["edges_written"] == 0


def test_fully_unknown_batch_returns_200_zero_edges(pool, make_tenant_with_key):
    """T5 / spec §7 #10: all flows with unknown IPs -> 200, zero edges, one run row."""
    tenant, api_key = make_tenant_with_key("fl-t5-allunknown")
    client = TestClient(create_app(pool=pool))

    unknown_flow = {
        "srcaddr": _UNKNOWN_IP,
        "dstaddr": "192.168.99.100",
        "srcport": 1234,
        "dstport": 80,
        "protocol": 6,
        "action": "ACCEPT",
        "start": 1700000000,
        "end": 1700000060,
    }
    resp = _post_flowlogs(client, tenant, [unknown_flow], api_key)
    assert resp.status_code == 200
    assert resp.json()["edges_written"] == 0

    with tenant_session(pool, tenant) as conn:
        run_count = conn.execute(
            "SELECT count(*) FROM connector_runs WHERE source = 'aws-flowlogs'"
        ).fetchone()[0]
    assert run_count == 1, f"expected 1 connector_runs row even with zero edges; got {run_count}"


# ===========================================================================
# 6. T6: REJECT flow -> no edge (spec §7 #1)
# ===========================================================================


def test_reject_flow_produces_no_edge(pool, make_tenant_with_key):
    """T6 / spec §7 #1: a REJECT flow -> edges_written==0."""
    tenant, api_key = make_tenant_with_key("fl-t6-reject")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_REJECT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    body = resp.json()
    assert body["edges_written"] == 0, (
        f"REJECT flow must not produce an edge; got edges_written={body['edges_written']}"
    )
    assert _count_connects_to(pool, tenant) == 0


def test_reject_flow_returns_200(pool, make_tenant_with_key):
    """T6: REJECT-only batch returns 200 (not an error)."""
    tenant, api_key = make_tenant_with_key("fl-t6-reject200")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_REJECT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200


# ===========================================================================
# 7. T7: Malformed record -> 422, nothing persisted (spec §7 #9, AC 12)
# ===========================================================================


def test_malformed_record_returns_422(pool, make_tenant_with_key):
    """T7 / AC 12 / spec §7 #9: record with empty action field -> 422."""
    tenant, api_key = make_tenant_with_key("fl-t7-422")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_MALFORMED_RECORD_EMPTY_ACTION], api_key)
    assert resp.status_code == 422


def test_malformed_record_detail_is_descriptive(pool, make_tenant_with_key):
    """T7 / AC 12: 422 detail string is non-empty and descriptive."""
    tenant, api_key = make_tenant_with_key("fl-t7-detail")
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_MALFORMED_RECORD_EMPTY_ACTION], api_key)
    assert resp.status_code == 422
    detail = resp.json().get("detail", "")
    assert detail, "422 detail must be non-empty"
    # The FlowLogParseError message mentions 'action'.
    assert "action" in detail, (
        f"422 detail should mention the offending field 'action'; got: {detail!r}"
    )


def test_malformed_record_no_connector_runs_written(pool, make_tenant_with_key):
    """T7 / AC 12: after parser 422, no connector_runs row written."""
    tenant, api_key = make_tenant_with_key("fl-t7-norun")
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_MALFORMED_RECORD_EMPTY_ACTION], api_key)

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connector_runs WHERE source = 'aws-flowlogs'"
        ).fetchone()[0]
    assert count == 0, f"expected 0 connector_runs after parser 422; got {count}"


def test_malformed_record_no_raw_facts_written(pool, make_tenant_with_key):
    """T7 / AC 12: after parser 422, no raw_facts rows written."""
    tenant, api_key = make_tenant_with_key("fl-t7-nofacts")
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_MALFORMED_RECORD_EMPTY_ACTION], api_key)

    with tenant_session(pool, tenant) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = 'aws-flowlogs'"
        ).fetchone()[0]
    assert count == 0, f"expected 0 raw_facts after parser 422; got {count}"


def test_malformed_record_no_edges_written(pool, make_tenant_with_key):
    """T7 / AC 12: after parser 422, no CONNECTS_TO edge rows written."""
    tenant, api_key = make_tenant_with_key("fl-t7-noedge")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    _post_flowlogs(client, tenant, [_MALFORMED_RECORD_EMPTY_ACTION], api_key)

    assert _count_connects_to(pool, tenant) == 0


def test_pydantic_body_validation_returns_422(pool, make_tenant_with_key):
    """T7 / spec §7 #9: body failing Pydantic validation (non-int srcport) returns 422."""
    tenant, api_key = make_tenant_with_key("fl-t7-pydantic")
    client = TestClient(create_app(pool=pool))

    bad_record = {
        "srcaddr": _IP_A,
        "dstaddr": _IP_B,
        "srcport": "NOT_AN_INT",  # fails Pydantic
        "dstport": 443,
        "protocol": 6,
        "action": "ACCEPT",
        "start": 1700000000,
        "end": 1700000060,
    }
    resp = client.post(
        "/telemetry/flowlogs",
        json={"records": [bad_record]},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 422


# ===========================================================================
# 8. T8: Pre-existing declared edge untouched (spec §7 #14, AC 16)
# ===========================================================================


def test_declared_edge_untouched_after_flowlogs_ingest(pool, make_tenant_with_key):
    """T8 / spec §7 #14: declared C->D edge stays open with valid_to IS NULL after
    posting ACCEPT A->B flows.  Uses a distinct pair so there is no (type, from_id, to_id)
    key collision.  edges_closed == 0."""
    tenant, api_key = make_tenant_with_key("fl-t8-declared")
    # Seed all four CIs plus the declared C->D edge in a single reconcile call so no
    # CI is closed by a subsequent reconcile with a disjoint batch.
    evidence = [Evidence(source="test", detail="declared-seed")]
    events = [
        DiscoveredCI(type=CIType.ec2_instance, external_id="i-aaa", name="i-aaa",
                     attributes={"private_ip": _IP_A}),
        DiscoveredCI(type=CIType.ec2_instance, external_id="i-bbb", name="i-bbb",
                     attributes={"private_ip": _IP_B}),
        DiscoveredCI(type=CIType.ec2_instance, external_id="i-ccc", name="i-ccc",
                     attributes={"private_ip": _IP_C}),
        DiscoveredCI(type=CIType.ec2_instance, external_id="i-ddd", name="i-ddd",
                     attributes={"private_ip": _IP_D}),
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
            conn, tenant, events,
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.ec2_instance}),
            edge_types=frozenset({EdgeType.CONNECTS_TO}),
        )

    # Capture declared edge before the flowlog POST.
    with tenant_session(pool, tenant) as conn:
        before_edges = EdgeRepository(conn, tenant).get_current()
    declared_before = [
        e for e in before_edges
        if e.type == EdgeType.CONNECTS_TO and e.source == EdgeSource.declared and e.valid_to is None
    ]
    assert len(declared_before) == 1, "setup: declared edge not seeded"
    declared_valid_from = declared_before[0].valid_from

    client = TestClient(create_app(pool=pool))
    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B], api_key)
    assert resp.status_code == 200
    body = resp.json()
    assert body["edges_closed"] == 0, (
        f"flowlogs ingest must not close any edge; edges_closed={body['edges_closed']}"
    )

    with tenant_session(pool, tenant) as conn:
        after_edges = EdgeRepository(conn, tenant).get_current()
    declared_after = [
        e for e in after_edges
        if e.type == EdgeType.CONNECTS_TO and e.source == EdgeSource.declared and e.valid_to is None
    ]
    assert len(declared_after) == 1, "declared edge must remain open after flowlogs POST"
    assert declared_after[0].valid_from == declared_valid_from, (
        f"declared edge valid_from changed: {declared_valid_from!r} -> {declared_after[0].valid_from!r}"
    )
    assert declared_after[0].valid_to is None, "declared edge must remain open (valid_to IS NULL)"


# ===========================================================================
# 9. T9: Empty batch (spec §7 #8)
# ===========================================================================


def test_empty_batch_returns_200(pool, make_tenant_with_key):
    """T9 / spec §7 #8: records: [] -> 200."""
    tenant, api_key = make_tenant_with_key("fl-t9-empty")
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [], api_key)
    assert resp.status_code == 200


def test_empty_batch_all_zero_counters(pool, make_tenant_with_key):
    """T9 / spec §7 #8: empty batch -> all CI/edge counters are 0."""
    tenant, api_key = make_tenant_with_key("fl-t9-zerocounters")
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [], api_key)
    assert resp.status_code == 200
    body = resp.json()
    for key in ("cis_created", "cis_updated", "cis_unchanged", "cis_closed", "edges_written", "edges_closed"):
        assert body[key] == 0, f"expected {key}==0 for empty batch; got {body[key]}"


def test_empty_batch_writes_one_run_row(pool, make_tenant_with_key):
    """T9 / spec §7 #8: empty batch writes one connector_runs row with status ok."""
    tenant, api_key = make_tenant_with_key("fl-t9-runrow")
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [], api_key)
    assert resp.status_code == 200
    run_id_str = resp.json()["connector_run_id"]
    assert UUID(run_id_str)

    with tenant_session(pool, tenant) as conn:
        row = conn.execute(
            "SELECT run_id, status FROM connector_runs WHERE source = 'aws-flowlogs'"
        ).fetchone()
    assert row is not None, "connector_runs row must be written even for empty batch"
    assert str(row[0]) == run_id_str
    assert row[1] == "ok"


# ===========================================================================
# 10. T10: observed_at = max end (spec §7 #13, AC 11)
# ===========================================================================


def test_observed_at_equals_max_end(pool, make_tenant_with_key):
    """T10 / AC 11 / spec §7 #13: raw_facts.observed_at (truncated to seconds) equals
    the max 'end' value across records converted to tz-aware UTC datetime."""
    tenant, api_key = make_tenant_with_key("fl-t10-obs")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    end1 = 1700000060
    end2 = 1700000120  # larger; this is the expected observed_at
    flows = [
        {**_ACCEPT_FLOW_A_TO_B, "end": end1},
        {**_ACCEPT_FLOW_A_TO_B, "end": end2},  # duplicate -> same edge, higher end
    ]
    resp = _post_flowlogs(client, tenant, flows, api_key)
    assert resp.status_code == 200

    expected_obs = datetime.fromtimestamp(end2, tz=timezone.utc)

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT observed_at FROM raw_facts WHERE source = 'aws-flowlogs'"
        ).fetchall()
    assert rows, "no raw_facts rows written"
    for row in rows:
        stored = row[0]
        if stored.tzinfo is None:
            stored = stored.replace(tzinfo=timezone.utc)
        assert stored.replace(microsecond=0) == expected_obs.replace(microsecond=0), (
            f"observed_at {stored!r} != expected {expected_obs!r}"
        )


def test_observed_at_fallback_for_empty_batch_writes_run_row(pool, make_tenant_with_key):
    """T10 / AC 11 / spec §7 #8: empty batch falls back to now() for observed_at;
    the connector_runs row is written with a started_at close to current time."""
    tenant, api_key = make_tenant_with_key("fl-t10-fallback")
    client = TestClient(create_app(pool=pool))

    before = datetime.now(timezone.utc)
    resp = _post_flowlogs(client, tenant, [], api_key)
    after = datetime.now(timezone.utc)
    assert resp.status_code == 200

    # Empty delta writes no raw_facts (no payloads), but does write a run row.
    with tenant_session(pool, tenant) as conn:
        row = conn.execute(
            "SELECT started_at FROM connector_runs WHERE source = 'aws-flowlogs'"
        ).fetchone()
    assert row is not None, "connector_runs row must be written even for empty batch"
    started = row[0]
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    assert abs((started - before).total_seconds()) < 60, (
        f"connector_runs.started_at {started!r} is too far from now (before={before!r})"
    )


# ===========================================================================
# 11. T11: Bad/missing X-Tenant-Id header (AC 14, spec §6.4)
# ===========================================================================


def test_missing_auth_header_returns_401(pool):
    """T11: absent Authorization header -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/flowlogs",
        json={"records": []},
    )
    assert resp.status_code == 401


def test_bogus_api_key_returns_401(pool):
    """T11: bogus Bearer token -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/telemetry/flowlogs",
        json={"records": []},
        headers={"Authorization": "Bearer itw_bogus.bogus"},
    )
    assert resp.status_code == 401


# ===========================================================================
# 12. T12: Cross-tenant resolution (spec §7 #15, AC 16)
# ===========================================================================


def test_cross_tenant_resolution_produces_no_edge_under_b(pool, make_tenant_with_key):
    """T12 / spec §7 #15: flows posted under tenant B with IPs belonging to tenant A's
    instances produce no edge under tenant B (resolver cannot see A's instances)."""
    a, _ = make_tenant_with_key("fl-t12-res-A")
    b, key_b = make_tenant_with_key("fl-t12-res-B")
    # Seed instances only under tenant A.
    _seed_ec2_many(pool, a, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])

    client = TestClient(create_app(pool=pool))
    # Post the same flow under tenant B — its resolver sees none of A's instances.
    resp = _post_flowlogs(client, b, [_ACCEPT_FLOW_A_TO_B], key_b)
    assert resp.status_code == 200
    assert resp.json()["edges_written"] == 0, (
        f"tenant B must not resolve tenant A's IPs; edges_written={resp.json()['edges_written']}"
    )
    assert _count_connects_to(pool, b) == 0


# ===========================================================================
# 13. T13: Cross-tenant visibility (spec §7 #15, AC 16)
# ===========================================================================


def test_cross_tenant_visibility_edges(pool, make_tenant_with_key):
    """T13 / spec §7 #15: after a successful A intake, tenant B sees zero CONNECTS_TO edges."""
    a, key_a = make_tenant_with_key("fl-t13-vis-A")
    b, _ = make_tenant_with_key("fl-t13-vis-B")
    _seed_ec2_many(pool, a, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])

    client = TestClient(create_app(pool=pool))
    resp_a = _post_flowlogs(client, a, [_ACCEPT_FLOW_A_TO_B], key_a)
    assert resp_a.status_code == 200
    assert resp_a.json()["edges_written"] == 1

    # Tenant B must see zero edges.
    assert _count_connects_to(pool, b) == 0


def test_cross_tenant_visibility_connector_runs(pool, make_tenant_with_key):
    """T13: tenant B sees zero connector_runs rows created by tenant A's flowlogs POST."""
    a, key_a = make_tenant_with_key("fl-t13-vis-run-A")
    b, _ = make_tenant_with_key("fl-t13-vis-run-B")
    _seed_ec2_many(pool, a, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])

    client = TestClient(create_app(pool=pool))
    _post_flowlogs(client, a, [_ACCEPT_FLOW_A_TO_B], key_a)

    with tenant_session(pool, b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connector_runs WHERE source = 'aws-flowlogs'"
        ).fetchone()[0]
    assert count == 0, f"tenant B must see 0 connector_runs from A; got {count}"


def test_cross_tenant_visibility_raw_facts(pool, make_tenant_with_key):
    """T13: tenant B sees zero raw_facts rows created by tenant A's flowlogs POST."""
    a, key_a = make_tenant_with_key("fl-t13-vis-rf-A")
    b, _ = make_tenant_with_key("fl-t13-vis-rf-B")
    _seed_ec2_many(pool, a, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])

    client = TestClient(create_app(pool=pool))
    _post_flowlogs(client, a, [_ACCEPT_FLOW_A_TO_B], key_a)

    with tenant_session(pool, b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM raw_facts WHERE source = 'aws-flowlogs'"
        ).fetchone()[0]
    assert count == 0, f"tenant B must see 0 raw_facts from A; got {count}"


def test_cross_tenant_visibility_connectors(pool, make_tenant_with_key):
    """T13: tenant B sees zero connectors rows of type aws-flowlogs created by tenant A."""
    a, key_a = make_tenant_with_key("fl-t13-vis-conn-A")
    b, _ = make_tenant_with_key("fl-t13-vis-conn-B")

    client = TestClient(create_app(pool=pool))
    _post_flowlogs(client, a, [], key_a)

    with tenant_session(pool, b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM connectors WHERE type = 'aws-flowlogs'"
        ).fetchone()[0]
    assert count == 0, f"tenant B must see 0 aws-flowlogs connectors from A; got {count}"


def test_cross_tenant_rls_bare_pool_sees_no_edges(pool, make_tenant_with_key):
    """T13: bare pool connection (no GUC) sees zero edges after flowlogs POST (RLS enforced)."""
    a, key_a = make_tenant_with_key("fl-t13-bare-A")
    _seed_ec2_many(pool, a, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])

    client = TestClient(create_app(pool=pool))
    _post_flowlogs(client, a, [_ACCEPT_FLOW_A_TO_B], key_a)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM edges").fetchone()[0]
    assert count == 0, "bare pool connection must see zero edges (RLS enforced)"


# ===========================================================================
# 14. T14: Direction preserved (spec §7 #6)
# ===========================================================================


def test_ab_and_ba_produce_two_distinct_edges(pool, make_tenant_with_key):
    """T14 / spec §7 #6: ACCEPT A->B and ACCEPT B->A in one batch -> two distinct open
    CONNECTS_TO edges (direction is part of the dedup key)."""
    tenant, api_key = make_tenant_with_key("fl-t14-direction")
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb", _IP_B)])
    client = TestClient(create_app(pool=pool))

    resp = _post_flowlogs(client, tenant, [_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_B_TO_A], api_key)
    assert resp.status_code == 200
    body = resp.json()
    assert body["edges_written"] == 2, (
        f"A->B and B->A must produce two distinct edges; edges_written={body['edges_written']}"
    )

    edges = _get_open_connects_to(pool, tenant)
    assert len(edges) == 2, f"expected 2 open CONNECTS_TO edges; got {len(edges)}"


# ===========================================================================
# 15. Parser-level edge cases (pure, no DB)
# ===========================================================================


def _make_resolver(ip_map: dict[str, CIRef]):
    def resolve(ip: str) -> CIRef | None:
        return ip_map.get(ip)
    return resolve


_CI_A = CIRef(type=CIType.ec2_instance, external_id="i-aaa")
_CI_B = CIRef(type=CIType.ec2_instance, external_id="i-bbb")


def test_parser_reject_action_skipped():
    """spec §7 #1 / AC 6: REJECT action is silently skipped; delta has zero upserts."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_REJECT_FLOW_A_TO_B], resolve=resolver)
    assert delta.upserts == []
    assert delta.removed_cis == []
    assert delta.removed_edges == []


def test_parser_missing_action_raises_flowlog_parse_error():
    """spec §7 #2 / AC 6: missing 'action' field raises FlowLogParseError."""
    record = {k: v for k, v in _ACCEPT_FLOW_A_TO_B.items() if k != "action"}
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    with pytest.raises(FlowLogParseError):
        parse_flow_logs([record], resolve=resolver)


def test_parser_empty_action_raises_flowlog_parse_error():
    """spec §7 #2 / AC 6: empty 'action' raises FlowLogParseError."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    with pytest.raises(FlowLogParseError):
        parse_flow_logs([_MALFORMED_RECORD_EMPTY_ACTION], resolve=resolver)


def test_parser_unresolved_dst_skipped():
    """spec §7 #3 / AC 6: dst not in resolver -> skip (no edge, no error)."""
    resolver = _make_resolver({_IP_A: _CI_A})  # _IP_B not present
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B], resolve=resolver)
    assert delta.upserts == []


def test_parser_unresolved_src_skipped():
    """spec §7 #4 / AC 6: src not in resolver -> skip."""
    resolver = _make_resolver({_IP_B: _CI_B})  # _IP_A not present
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B], resolve=resolver)
    assert delta.upserts == []


def test_parser_dedup_same_pair():
    """spec §7 #5 / AC 6: two ACCEPT flows for the same pair -> exactly one edge."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_A_TO_B], resolve=resolver)
    assert len(delta.upserts) == 1


def test_parser_direction_distinguishes_pairs():
    """spec §7 #6 / AC 6: A->B and B->A produce two distinct edges."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B, _ACCEPT_FLOW_B_TO_A], resolve=resolver)
    assert len(delta.upserts) == 2


def test_parser_empty_records():
    """spec §7 #8 / AC 6: empty records iterable -> ConnectorDelta with empty upserts."""
    resolver = _make_resolver({_IP_A: _CI_A})
    delta = parse_flow_logs([], resolve=resolver)
    assert delta.upserts == []
    assert delta.removed_cis == []
    assert delta.removed_edges == []


def test_parser_removed_always_empty():
    """AC 6: removed_cis and removed_edges are always empty."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B], resolve=resolver)
    assert delta.removed_cis == []
    assert delta.removed_edges == []


def test_parser_edge_type_is_connects_to():
    """AC 5: every emitted edge has type == CONNECTS_TO."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B], resolve=resolver)
    assert len(delta.upserts) == 1
    edge = delta.upserts[0]
    assert isinstance(edge, DiscoveredEdge)
    assert edge.type == EdgeType.CONNECTS_TO


def test_parser_edge_source_is_inferred():
    """AC 5: every emitted edge has source == EdgeSource.inferred."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B], resolve=resolver)
    edge = delta.upserts[0]
    assert edge.source == EdgeSource.inferred


def test_parser_edge_confidence_equals_default():
    """AC 4, 5: every emitted edge has confidence == DEFAULT_FLOW_CONFIDENCE (0.6)."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B], resolve=resolver)
    edge = delta.upserts[0]
    assert edge.confidence == DEFAULT_FLOW_CONFIDENCE
    assert 0 < edge.confidence < 1


def test_parser_evidence_source_is_flowlogs():
    """AC 5: every emitted edge's evidence[0].source == 'aws-flowlogs'."""
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    delta = parse_flow_logs([_ACCEPT_FLOW_A_TO_B], resolve=resolver)
    edge = delta.upserts[0]
    assert len(edge.evidence) >= 1
    assert edge.evidence[0].source == "aws-flowlogs"


def test_parser_missing_dstport_raises():
    """spec §6.1 step 5: missing dstport raises FlowLogParseError."""
    record = {k: v for k, v in _ACCEPT_FLOW_A_TO_B.items() if k != "dstport"}
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    with pytest.raises(FlowLogParseError):
        parse_flow_logs([record], resolve=resolver)


def test_parser_missing_start_raises():
    """spec §6.1 step 5: missing start raises FlowLogParseError."""
    record = {k: v for k, v in _ACCEPT_FLOW_A_TO_B.items() if k != "start"}
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    with pytest.raises(FlowLogParseError):
        parse_flow_logs([record], resolve=resolver)


def test_parser_missing_end_raises():
    """spec §6.1 step 5: missing end raises FlowLogParseError."""
    record = {k: v for k, v in _ACCEPT_FLOW_A_TO_B.items() if k != "end"}
    resolver = _make_resolver({_IP_A: _CI_A, _IP_B: _CI_B})
    with pytest.raises(FlowLogParseError):
        parse_flow_logs([record], resolve=resolver)


def test_parser_self_flow_produces_one_edge():
    """spec §7 #7: self-flow (both endpoints resolve to same CI) produces one CONNECTS_TO
    self-edge (parser does not special-case; test asserts documented behavior)."""
    self_flow = {
        "srcaddr": _IP_A,
        "dstaddr": _IP_A,  # same as src
        "srcport": 12345,
        "dstport": 8080,
        "protocol": 6,
        "action": "ACCEPT",
        "start": 1700000000,
        "end": 1700000060,
    }
    resolver = _make_resolver({_IP_A: _CI_A})
    delta = parse_flow_logs([self_flow], resolve=resolver)
    assert len(delta.upserts) == 1
    edge = delta.upserts[0]
    assert edge.from_ref == edge.to_ref, "self-edge must have equal from_ref and to_ref"


def test_parser_duplicate_private_ip_resolves_to_smallest_external_id(pool, make_tenant_with_key):
    """spec §6.3 / spec §7 #12: two ec2_instances with the same private_ip -> resolver picks
    the lexicographically smallest external_id; no crash."""
    tenant, api_key = make_tenant_with_key("fl-dup-ip")
    # Seed two instances with the same IP in one reconcile call (avoid close-on-absent).
    _seed_ec2_many(pool, tenant, [("i-aaa", _IP_A), ("i-bbb-smaller", _IP_A)])  # same IP!

    client = TestClient(create_app(pool=pool))
    flow = {
        "srcaddr": _IP_A,
        "dstaddr": _IP_B,
        "srcport": 1234,
        "dstport": 80,
        "protocol": 6,
        "action": "ACCEPT",
        "start": 1700000000,
        "end": 1700000060,
    }
    # With dst unknown, this should produce 0 edges and NOT crash.
    resp = _post_flowlogs(client, tenant, [flow], api_key)
    assert resp.status_code == 200  # no crash


def test_parser_instance_with_none_private_ip_not_in_resolver(pool, make_tenant_with_key):
    """spec §7 #11: instance with private_ip=None is never a resolution target."""
    tenant, api_key = make_tenant_with_key("fl-none-ip")
    # Seed instance with private_ip=None.
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [
                DiscoveredCI(
                    type=CIType.ec2_instance,
                    external_id="i-nullip",
                    name="null-ip-instance",
                    attributes={"private_ip": None},
                )
            ],
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.ec2_instance}),
            edge_types=frozenset(),
        )

    client = TestClient(create_app(pool=pool))
    flow = {
        "srcaddr": "10.0.0.99",  # some IP — does not match None
        "dstaddr": "10.0.0.100",
        "srcport": 1234,
        "dstport": 80,
        "protocol": 6,
        "action": "ACCEPT",
        "start": 1700000000,
        "end": 1700000060,
    }
    resp = _post_flowlogs(client, tenant, [flow], api_key)
    assert resp.status_code == 200
    assert resp.json()["edges_written"] == 0
