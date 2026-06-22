"""Integration tests for the CloudTrail event-intake path (apply_event_delta).

Covers acceptance criteria AC 14-21 from specs.md §9, and all edge cases
E-INTAKE-1 through E-INTAKE-7 from specs.md §6.

Structure:
1. Module export checks (AC 14, 15).
2. No forbidden import from collectors in reconciliation/events.py (AC 14).
3. Connector resolve-or-register idempotency (E-INTAKE-1).
4. Create delta: CI and edges added, sibling untouched (E-INTAKE-3, AC 17, 18).
5. Unresolved edge endpoint raises and rolls back (E-INTAKE-2).
6. Terminate/revoke: bitemporal close, no hard-delete, no sibling closed (E-INTAKE-4, AC 19).
7. connector_runs + raw_facts stamped correctly (E-INTAKE-5, AC 17).
8. Revoke non-existent edge is no-op (E-INTAKE-6).
9. Adversarial tenant isolation (E-INTAKE-7, AC 21).

Seeding helpers mirror the pattern in test_apply_delta.py/_seed_vpc_and_subnet.
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from uuid import UUID

import psycopg
import pytest

from infra_twin.connector_sdk import (
    CIRef,
    ConnectorDelta,
    DiscoveredCI,
    DiscoveredEdge,
    EdgeEndpointRef,
)
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.config import admin_dsn
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import apply_event_delta, reconcile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OBS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_SEED_SOURCE = "test-seed-connector"

_FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "cloudtrail"


def _load(name: str) -> dict:
    return json.loads((_FIXTURE_DIR / name).read_text())


# ---------------------------------------------------------------------------
# Seeding helpers (mirrors _seed_vpc_and_subnet from test_apply_delta.py)
# ---------------------------------------------------------------------------


def _evidence() -> list[Evidence]:
    return [Evidence(source="test", detail="seed")]


def _seed_vpc_subnet_and_sg(pool, tenant: UUID) -> None:
    """Seed vpc-1, subnet-0aaa1111, sg-0ccc3333, and required edges."""
    events = [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-0bbb2222", name="net"),
        DiscoveredCI(type=CIType.subnet, external_id="subnet-0aaa1111", name="subnet-a"),
        DiscoveredCI(type=CIType.security_group, external_id="sg-0ccc3333", name="default"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-0bbb2222"),
            to_ref=CIRef(type=CIType.subnet, external_id="subnet-0aaa1111"),
            evidence=_evidence(),
        ),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-0bbb2222"),
            to_ref=CIRef(type=CIType.security_group, external_id="sg-0ccc3333"),
            evidence=_evidence(),
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


def _seed_two_sgs(pool, tenant: UUID, sg_source: str, sg_target: str, vpc_id: str) -> None:
    """Seed two security groups and an edge between them (for authorize/revoke tests)."""
    events = [
        DiscoveredCI(type=CIType.vpc, external_id=vpc_id, name="net"),
        DiscoveredCI(type=CIType.security_group, external_id=sg_source, name="source-sg"),
        DiscoveredCI(type=CIType.security_group, external_id=sg_target, name="target-sg"),
        DiscoveredEdge(
            type=EdgeType.CONNECTS_TO,
            from_ref=CIRef(type=CIType.security_group, external_id=sg_source),
            to_ref=CIRef(type=CIType.security_group, external_id=sg_target),
            evidence=_evidence(),
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


def _seed_ec2_for_terminate(pool, tenant: UUID) -> None:
    """Seed an ec2_instance CI for termination tests."""
    events = [
        DiscoveredCI(type=CIType.ec2_instance, external_id="i-0abc123def456", name="inst"),
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


def _count_rows(pool, tenant: UUID, table: str) -> int:
    with tenant_session(pool, tenant) as conn:
        return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def _count_rows_source(pool, tenant: UUID, table: str, source: str) -> int:
    with tenant_session(pool, tenant) as conn:
        return conn.execute(
            f"SELECT count(*) FROM {table} WHERE source = %s", (source,)
        ).fetchone()[0]


def _get_connector_rows(pool, tenant: UUID, conn_type: str) -> list[dict]:
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT connector_id, type, display_name FROM connectors WHERE type = %s",
            (conn_type,),
        ).fetchall()
    return [{"connector_id": r[0], "type": r[1], "display_name": r[2]} for r in rows]


def _get_run_rows(pool, tenant: UUID, source: str) -> list[dict]:
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT status, connector_id, source FROM connector_runs WHERE source = %s "
            "ORDER BY started_at DESC NULLS LAST",
            (source,),
        ).fetchall()
    return [{"status": r[0], "connector_id": r[1], "source": r[2]} for r in rows]


def _get_fact_rows(pool, tenant: UUID, source: str) -> list[dict]:
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT connector_id, observed_at FROM raw_facts WHERE source = %s",
            (source,),
        ).fetchall()
    return [{"connector_id": r[0], "observed_at": r[1]} for r in rows]


# ===========================================================================
# 1. MODULE EXPORT CHECKS (AC 14, 15)
# ===========================================================================


def test_apply_event_delta_importable_from_reconciliation_package():
    """AC 15: apply_event_delta importable from infra_twin.reconciliation."""
    from infra_twin.reconciliation import apply_event_delta  # noqa: F401


def test_apply_event_delta_in_reconciliation_all():
    """AC 15: 'apply_event_delta' is in infra_twin.reconciliation.__all__."""
    from infra_twin import reconciliation
    assert "apply_event_delta" in reconciliation.__all__


def test_apply_event_delta_importable_from_events_module():
    """AC 14: apply_event_delta importable from infra_twin.reconciliation.events."""
    from infra_twin.reconciliation.events import apply_event_delta  # noqa: F401


def test_reconciliation_events_does_not_import_collectors():
    """AC 14: reconciliation/events.py must NOT import from infra_twin.collectors."""
    import infra_twin.reconciliation.events as mod
    # collectors should NOT appear in the module's namespace
    for name, obj in mod.__dict__.items():
        if hasattr(obj, "__module__") and obj.__module__ is not None:
            assert "infra_twin.collectors" not in str(obj.__module__), (
                f"reconciliation.events imported {obj.__module__} via {name}"
            )


def test_event_source_in_reconciliation_events():
    """AC 14: EVENT_SOURCE == 'aws-events' in reconciliation.events."""
    from infra_twin.reconciliation.events import EVENT_SOURCE
    assert EVENT_SOURCE == "aws-events"


# ===========================================================================
# 2. CONNECTOR RESOLVE-OR-REGISTER IDEMPOTENCY (E-INTAKE-1, AC 20)
# ===========================================================================


def test_first_call_registers_aws_events_connector(pool, make_tenant):
    """E-INTAKE-1: first apply_event_delta call registers exactly one aws-events connector."""
    tenant = make_tenant("intake-reg-1")

    delta = ConnectorDelta()
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    rows = _get_connector_rows(pool, tenant, "aws-events")
    assert len(rows) == 1
    assert rows[0]["type"] == "aws-events"
    assert rows[0]["display_name"] == "aws-events"


def test_second_call_reuses_same_connector_row(pool, make_tenant):
    """E-INTAKE-1 / AC 20: two successive calls reuse a single aws-events connector row."""
    tenant = make_tenant("intake-reg-2")

    apply_event_delta(pool, tenant, ConnectorDelta(), observed_at=_OBS)
    apply_event_delta(pool, tenant, ConnectorDelta(), observed_at=_OBS)

    rows = _get_connector_rows(pool, tenant, "aws-events")
    assert len(rows) == 1, "must reuse same connector row on second call"


def test_connector_id_is_stable_across_calls(pool, make_tenant):
    """AC 20: the connector_id returned by resolve_or_register is stable across calls."""
    tenant = make_tenant("intake-reg-3")

    apply_event_delta(pool, tenant, ConnectorDelta(), observed_at=_OBS)
    apply_event_delta(pool, tenant, ConnectorDelta(), observed_at=_OBS)

    rows = _get_connector_rows(pool, tenant, "aws-events")
    assert len(rows) == 1  # only one row, confirmed stable id


# ===========================================================================
# 3. CREATE DELTA: CI AND EDGES ADDED, SIBLING UNTOUCHED (E-INTAKE-3, AC 17, 18)
# ===========================================================================


def test_run_instances_create_adds_ec2_instance_ci(pool, make_tenant):
    """E-INTAKE-3 / AC 17: apply_event_delta with RunInstances delta adds the ec2_instance CI."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-create-1")
    _seed_vpc_subnet_and_sg(pool, tenant)

    delta = parse_event(_load("run_instances.json"))
    result = apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    assert result.cis_created == 1
    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-0abc123def456"
        )
    assert len(cis) == 1
    assert cis[0].valid_to is None


def test_run_instances_create_adds_contains_edge(pool, make_tenant):
    """E-INTAKE-3 / AC 17: apply_event_delta with RunInstances adds CONTAINS edge."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-create-2")
    _seed_vpc_subnet_and_sg(pool, tenant)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    types = {e.type for e in edges if e.valid_to is None}
    assert EdgeType.CONTAINS in types


def test_run_instances_create_adds_member_of_edge(pool, make_tenant):
    """E-INTAKE-3 / AC 17: apply_event_delta with RunInstances adds MEMBER_OF edge."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-create-3")
    _seed_vpc_subnet_and_sg(pool, tenant)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    types = {e.type for e in edges if e.valid_to is None}
    assert EdgeType.MEMBER_OF in types


def test_run_instances_sibling_ci_untouched(pool, make_tenant):
    """AC 18 / E-INTAKE-3: after RunInstances intake, sibling subnet CI retains original valid_from and valid_to IS NULL."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-sibling-1")
    _seed_vpc_subnet_and_sg(pool, tenant)

    # Capture the subnet's original valid_from before the event delta.
    with tenant_session(pool, tenant) as conn:
        subnet_before = CIRepository(conn, tenant).get_current(
            type=CIType.subnet, external_id="subnet-0aaa1111"
        )
    assert subnet_before, "setup failed: subnet not seeded"
    original_valid_from = subnet_before[0].valid_from

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    with tenant_session(pool, tenant) as conn:
        subnet_after = CIRepository(conn, tenant).get_current(
            type=CIType.subnet, external_id="subnet-0aaa1111"
        )
    assert len(subnet_after) == 1
    assert subnet_after[0].valid_from == original_valid_from
    assert subnet_after[0].valid_to is None


# ===========================================================================
# 4. UNRESOLVED EDGE ENDPOINT RAISES AND ROLLS BACK (E-INTAKE-2)
# ===========================================================================


def test_run_instances_unresolved_subnet_endpoint_raises(pool, make_tenant):
    """E-INTAKE-2: RunInstances delta without pre-seeded subnet raises ValueError('unresolved edge endpoint')."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-unresolved-1")
    # Do NOT seed the subnet/sg — edges will be unresolvable

    delta = parse_event(_load("run_instances.json"))
    with pytest.raises(ValueError, match="unresolved edge endpoint"):
        apply_event_delta(pool, tenant, delta, observed_at=_OBS)


def test_run_instances_unresolved_rolls_back_no_ci(pool, make_tenant):
    """E-INTAKE-2: when endpoint unresolved, the entire transaction rolls back — no CI written."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-unresolved-2")
    delta = parse_event(_load("run_instances.json"))

    with pytest.raises(ValueError):
        apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    with tenant_session(pool, tenant) as conn:
        cis = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-0abc123def456"
        )
    assert cis == [], "CI must not be written when transaction rolls back"


def test_run_instances_unresolved_rolls_back_no_run_row(pool, make_tenant):
    """E-INTAKE-2: when endpoint unresolved, no connector_runs row is written."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-unresolved-3")
    delta = parse_event(_load("run_instances.json"))

    with pytest.raises(ValueError):
        apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    assert _count_rows_source(pool, tenant, "connector_runs", "aws-events") == 0


def test_run_instances_unresolved_rolls_back_no_raw_facts(pool, make_tenant):
    """E-INTAKE-2: when endpoint unresolved, no raw_facts rows are written."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-unresolved-4")
    delta = parse_event(_load("run_instances.json"))

    with pytest.raises(ValueError):
        apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    assert _count_rows_source(pool, tenant, "raw_facts", "aws-events") == 0


# ===========================================================================
# 5. TERMINATE: BITEMPORAL CLOSE, NO SIBLING CLOSED (E-INTAKE-4, AC 19)
# ===========================================================================


def test_terminate_closes_named_ci_valid_to_set(pool, make_tenant):
    """E-INTAKE-4 / AC 19: terminate event sets valid_to on the named ec2_instance CI."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-term-1")
    _seed_ec2_for_terminate(pool, tenant)

    delta = parse_event(_load("terminate_instances.json"))
    result = apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    assert result.cis_closed == 1

    # Via admin (bypasses RLS) confirm row still physically present with valid_to set.
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM cis WHERE type = 'ec2_instance' "
            "AND external_id = %s AND tenant_id = %s",
            ("i-0abc123def456", tenant),
        ).fetchone()
    assert row is not None, "ci row must physically exist (no hard-delete)"
    assert row[0] is not None, "valid_to must be set (not null) after terminate"


def test_terminate_ci_not_hard_deleted(pool, make_tenant):
    """E-INTAKE-4: after terminate, ec2_instance row is still physically present in DB."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-term-2")
    _seed_ec2_for_terminate(pool, tenant)

    delta = parse_event(_load("terminate_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    # RLS-scoped view should return nothing (CI closed).
    with tenant_session(pool, tenant) as conn:
        current = CIRepository(conn, tenant).get_current(
            type=CIType.ec2_instance, external_id="i-0abc123def456"
        )
    assert current == []

    # But admin connection must still see the row.
    with psycopg.connect(admin_dsn()) as admin_conn:
        count = admin_conn.execute(
            "SELECT count(*) FROM cis WHERE type = 'ec2_instance' "
            "AND external_id = %s AND tenant_id = %s",
            ("i-0abc123def456", tenant),
        ).fetchone()[0]
    assert count >= 1


def test_terminate_does_not_close_sibling_ci(pool, make_tenant):
    """E-INTAKE-4 / AC 19: terminating one ec2_instance does not close sibling VPC CI."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-term-3")
    _seed_ec2_for_terminate(pool, tenant)
    # Also seed a sibling VPC to check it stays open.
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [DiscoveredCI(type=CIType.vpc, external_id="vpc-sibling", name="v")],
            source=_SEED_SOURCE,
            ci_types=frozenset({CIType.vpc}),
            edge_types=frozenset(),
        )

    delta = parse_event(_load("terminate_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    with tenant_session(pool, tenant) as conn:
        vpc = CIRepository(conn, tenant).get_current(
            type=CIType.vpc, external_id="vpc-sibling"
        )
    assert len(vpc) == 1
    assert vpc[0].valid_to is None, "sibling VPC must remain open after terminate"


# ===========================================================================
# 6. REVOKE: BITEMPORAL CLOSE, NO SIBLING CLOSED (E-INTAKE-4, AC 19)
# ===========================================================================


def test_revoke_closes_named_edge_via_admin(pool, make_tenant):
    """E-INTAKE-4 / AC 19: revoke sets valid_to on the named CONNECTS_TO edge (verified via admin)."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-revoke-1")
    _seed_two_sgs(pool, tenant, "sg-0source", "sg-0target", "vpc-0test")

    delta = parse_event(_load("revoke_sg_ingress_sg_source.json"))
    result = apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    assert result.edges_closed == 1

    # Verify via admin that the row still exists with valid_to set.
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM edges WHERE type = 'CONNECTS_TO' AND tenant_id = %s",
            (tenant,),
        ).fetchone()
    assert row is not None, "edge row must physically exist"
    assert row[0] is not None, "valid_to must be set (not null) after revoke"


def test_revoke_edge_not_hard_deleted(pool, make_tenant):
    """E-INTAKE-4: after revoke, CONNECTS_TO edge row is still present in DB."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-revoke-2")
    _seed_two_sgs(pool, tenant, "sg-0source", "sg-0target", "vpc-0test2")

    delta = parse_event(_load("revoke_sg_ingress_sg_source.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    # RLS-scoped view: no open CONNECTS_TO edges.
    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    open_connects = [e for e in edges if e.type == EdgeType.CONNECTS_TO]
    assert open_connects == [], "CONNECTS_TO edge should be closed after revoke"

    # Admin view: still physically present.
    with psycopg.connect(admin_dsn()) as admin_conn:
        count = admin_conn.execute(
            "SELECT count(*) FROM edges WHERE type = 'CONNECTS_TO' AND tenant_id = %s",
            (tenant,),
        ).fetchone()[0]
    assert count >= 1


def test_revoke_does_not_close_sibling_edge(pool, make_tenant):
    """E-INTAKE-4 / AC 19: revoking one CONNECTS_TO edge does not close a different CONTAINS edge."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-revoke-3")
    _seed_two_sgs(pool, tenant, "sg-0source", "sg-0target", "vpc-0test3")
    # Seed an extra CONTAINS edge that should remain open.
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [
                DiscoveredEdge(
                    type=EdgeType.CONTAINS,
                    from_ref=CIRef(type=CIType.vpc, external_id="vpc-0test3"),
                    to_ref=CIRef(type=CIType.security_group, external_id="sg-0source"),
                    evidence=_evidence(),
                )
            ],
            source=_SEED_SOURCE,
            ci_types=frozenset(),
            edge_types=frozenset({EdgeType.CONTAINS}),
        )

    delta = parse_event(_load("revoke_sg_ingress_sg_source.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    open_contains = [e for e in edges if e.type == EdgeType.CONTAINS and e.valid_to is None]
    assert len(open_contains) >= 1, "CONTAINS sibling edge must remain open after revoke"


# ===========================================================================
# 7. CONNECTOR_RUNS + RAW_FACTS STAMPED CORRECTLY (E-INTAKE-5, AC 17)
# ===========================================================================


def test_run_row_has_status_ok(pool, make_tenant):
    """E-INTAKE-5 / AC 17: connector_runs row has status='ok' after apply_event_delta."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-run-1")
    _seed_vpc_subnet_and_sg(pool, tenant)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    rows = _get_run_rows(pool, tenant, "aws-events")
    assert len(rows) == 1
    assert rows[0]["status"] == "ok"


def test_run_row_connector_id_matches_resolved(pool, make_tenant):
    """E-INTAKE-5 / AC 17: connector_runs connector_id matches the resolved aws-events connector."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-run-2")
    _seed_vpc_subnet_and_sg(pool, tenant)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    connector_rows = _get_connector_rows(pool, tenant, "aws-events")
    run_rows = _get_run_rows(pool, tenant, "aws-events")
    assert len(connector_rows) == 1
    assert len(run_rows) == 1
    assert run_rows[0]["connector_id"] == connector_rows[0]["connector_id"]


def test_raw_facts_carry_connector_id(pool, make_tenant):
    """E-INTAKE-5 / AC 17: all raw_facts rows carry the aws-events connector_id."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-facts-1")
    _seed_vpc_subnet_and_sg(pool, tenant)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    connector_rows = _get_connector_rows(pool, tenant, "aws-events")
    fact_rows = _get_fact_rows(pool, tenant, "aws-events")

    assert len(fact_rows) > 0
    expected_cid = connector_rows[0]["connector_id"]
    for fr in fact_rows:
        assert fr["connector_id"] == expected_cid


def test_raw_facts_carry_observed_at(pool, make_tenant):
    """E-INTAKE-5 / AC 17: raw_facts rows carry the passed observed_at timestamp."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-facts-2")
    _seed_vpc_subnet_and_sg(pool, tenant)

    fixed_obs = datetime(2025, 11, 15, 9, 0, 0, tzinfo=timezone.utc)
    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, tenant, delta, observed_at=fixed_obs)

    fact_rows = _get_fact_rows(pool, tenant, "aws-events")
    assert len(fact_rows) > 0
    for fr in fact_rows:
        stored = fr["observed_at"]
        # Compare truncated to seconds
        if hasattr(stored, "tzinfo"):
            stored = stored.replace(tzinfo=timezone.utc) if stored.tzinfo is None else stored
        assert stored.replace(microsecond=0) == fixed_obs.replace(microsecond=0)


def test_each_call_writes_exactly_one_run_row(pool, make_tenant):
    """E-INTAKE-5: each apply_event_delta call writes exactly one connector_runs row."""
    tenant = make_tenant("intake-one-run-1")

    apply_event_delta(pool, tenant, ConnectorDelta(), observed_at=_OBS)
    apply_event_delta(pool, tenant, ConnectorDelta(), observed_at=_OBS)

    count = _count_rows_source(pool, tenant, "connector_runs", "aws-events")
    assert count == 2


# ===========================================================================
# 8. REVOKE NON-EXISTENT EDGE IS NO-OP (E-INTAKE-6)
# ===========================================================================


def test_revoke_non_existent_edge_is_noop(pool, make_tenant):
    """E-INTAKE-6: revoking an edge that does not exist is a no-op (edges_closed==0, no exception)."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-revoke-noop-1")
    # Do NOT seed the SGs or edges — no CONNECTS_TO edge exists

    delta = parse_event(_load("revoke_sg_ingress_sg_source.json"))
    result = apply_event_delta(pool, tenant, delta, observed_at=_OBS)

    assert result.edges_closed == 0


def test_revoke_already_closed_edge_is_noop(pool, make_tenant):
    """E-INTAKE-6: revoking an already-closed edge is a no-op (edges_closed==0)."""
    from infra_twin.collectors.aws.events import parse_event

    tenant = make_tenant("intake-revoke-closed-1")
    _seed_two_sgs(pool, tenant, "sg-0source", "sg-0target", "vpc-0test4")

    delta = parse_event(_load("revoke_sg_ingress_sg_source.json"))
    first = apply_event_delta(pool, tenant, delta, observed_at=_OBS)
    assert first.edges_closed == 1

    second = apply_event_delta(pool, tenant, delta, observed_at=_OBS)
    assert second.edges_closed == 0


# ===========================================================================
# 9. ADVERSARIAL TENANT ISOLATION (E-INTAKE-7, AC 21)
# ===========================================================================


def test_tenant_b_sees_zero_cis_of_tenant_a(pool, make_tenant):
    """E-INTAKE-7 / AC 21: tenant B's RLS-scoped session sees zero of tenant A's CIs."""
    from infra_twin.collectors.aws.events import parse_event

    a = make_tenant("intake-iso-ci-A")
    b = make_tenant("intake-iso-ci-B")
    _seed_vpc_subnet_and_sg(pool, a)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, a, delta, observed_at=_OBS)

    with tenant_session(pool, b) as conn:
        b_cis = CIRepository(conn, b).get_current()
    assert b_cis == [], "tenant B must see zero of tenant A's CIs"


def test_tenant_b_sees_zero_edges_of_tenant_a(pool, make_tenant):
    """E-INTAKE-7 / AC 21: tenant B's session sees zero of tenant A's edges."""
    from infra_twin.collectors.aws.events import parse_event

    a = make_tenant("intake-iso-edge-A")
    b = make_tenant("intake-iso-edge-B")
    _seed_vpc_subnet_and_sg(pool, a)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, a, delta, observed_at=_OBS)

    with tenant_session(pool, b) as conn:
        b_edges = EdgeRepository(conn, b).get_current()
    assert b_edges == [], "tenant B must see zero of tenant A's edges"


def test_tenant_b_sees_zero_connector_runs_of_tenant_a(pool, make_tenant):
    """E-INTAKE-7 / AC 21: tenant B sees zero connector_runs rows that belong to tenant A."""
    a = make_tenant("intake-iso-run-A")
    b = make_tenant("intake-iso-run-B")

    apply_event_delta(pool, a, ConnectorDelta(), observed_at=_OBS)

    assert _count_rows(pool, a, "connector_runs") == 1
    assert _count_rows(pool, b, "connector_runs") == 0


def test_tenant_b_sees_zero_raw_facts_of_tenant_a(pool, make_tenant):
    """E-INTAKE-7 / AC 21: tenant B sees zero raw_facts rows that belong to tenant A."""
    from infra_twin.collectors.aws.events import parse_event

    a = make_tenant("intake-iso-rf-A")
    b = make_tenant("intake-iso-rf-B")
    _seed_vpc_subnet_and_sg(pool, a)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, a, delta, observed_at=_OBS)

    assert _count_rows(pool, a, "raw_facts") > 0
    assert _count_rows(pool, b, "raw_facts") == 0


def test_tenant_b_sees_zero_connectors_of_tenant_a(pool, make_tenant):
    """E-INTAKE-7 / AC 21: tenant B sees zero connectors rows that belong to tenant A."""
    a = make_tenant("intake-iso-conn-A")
    b = make_tenant("intake-iso-conn-B")

    apply_event_delta(pool, a, ConnectorDelta(), observed_at=_OBS)

    a_connectors = _get_connector_rows(pool, a, "aws-events")
    assert len(a_connectors) == 1

    b_connectors = _get_connector_rows(pool, b, "aws-events")
    assert b_connectors == [], "tenant B must see zero of tenant A's connectors"


def test_bare_pool_connection_sees_zero_cis_after_event_intake(pool, make_tenant):
    """E-INTAKE-7 / AC 21: bare pool connection (no GUC) sees zero cis rows."""
    from infra_twin.collectors.aws.events import parse_event

    a = make_tenant("intake-bare-ci-A")
    _seed_vpc_subnet_and_sg(pool, a)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, a, delta, observed_at=_OBS)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM cis").fetchone()[0]
    assert count == 0, "bare connection must see zero cis (RLS enforced)"


def test_bare_pool_connection_sees_zero_connector_runs_after_event_intake(pool, make_tenant):
    """E-INTAKE-7 / AC 21: bare pool connection sees zero connector_runs rows."""
    a = make_tenant("intake-bare-run-A")

    apply_event_delta(pool, a, ConnectorDelta(), observed_at=_OBS)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM connector_runs").fetchone()[0]
    assert count == 0, "bare connection must see zero connector_runs (RLS enforced)"


def test_bare_pool_connection_sees_zero_raw_facts_after_event_intake(pool, make_tenant):
    """E-INTAKE-7 / AC 21: bare pool connection sees zero raw_facts rows."""
    from infra_twin.collectors.aws.events import parse_event

    a = make_tenant("intake-bare-rf-A")
    _seed_vpc_subnet_and_sg(pool, a)

    delta = parse_event(_load("run_instances.json"))
    apply_event_delta(pool, a, delta, observed_at=_OBS)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM raw_facts").fetchone()[0]
    assert count == 0, "bare connection must see zero raw_facts (RLS enforced)"


def test_cross_tenant_rls_blocks_event_intake_ci_stamp(pool, make_tenant):
    """E-INTAKE-7: adversarial insert into cis stamped with another tenant_id raises psycopg.Error."""
    a = make_tenant("intake-xstamp-ci-A")
    b = make_tenant("intake-xstamp-ci-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO cis (tenant_id, type, external_id, name, attributes, confidence, "
                "first_seen, last_seen, valid_from) "
                "VALUES (%s, 'ec2_instance', 'i-adversarial', 'adv', '{}', 1.0, now(), now(), now())",
                (str(b),),
            )


def test_cross_tenant_rls_blocks_event_intake_connector_runs_stamp(pool, make_tenant):
    """E-INTAKE-7: adversarial insert into connector_runs stamped with another tenant_id raises psycopg.Error."""
    a = make_tenant("intake-xstamp-run-A")
    b = make_tenant("intake-xstamp-run-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO connector_runs (tenant_id, source, status, started_at) "
                "VALUES (%s, 'aws-events', 'partial', now())",
                (str(b),),
            )
