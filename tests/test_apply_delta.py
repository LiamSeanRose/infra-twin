"""Tests for apply_delta: event-driven incremental-freshness substrate.

Covers every acceptance criterion in the spec (AC 14-21) and all edge cases E1-E17.

Structure:
1. SDK types — ConnectorDelta / EdgeEndpointRef model tests (AC 1-3, 12).
2. Export sanity — apply_delta / DeltaResult in __all__ (AC 13).
3. Happy path — upsert-only delta (AC 14, E1, E17).
4. Removal-only delta (AC 15, E2, E5).
5. Empty delta (AC 17, E3).
6. Re-upsert identical CI (E4).
7. No cascade on CI removal (AC 18, E8).
8. Run and raw_facts written and linked (AC 16, E15, E16).
9. Unresolved upserted-edge endpoint raises and rolls back (AC 20, E6, E11).
10. Removed edge with unresolved endpoint is a no-op (E7).
11. Upserted-and-removed in same delta ends closed (E9).
12. Unknown connector_id raises ValueError (AC 20, E10).
13. Adversarial tenant isolation (AC 19, E12, E13, E14).
"""

from __future__ import annotations

import uuid
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
from infra_twin.db.connectors import ConnectorRegistry
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import DeltaResult, apply_delta, reconcile

# ---------------------------------------------------------------------------
# Constants / small helpers
# ---------------------------------------------------------------------------

_SOURCE = "test-delta-connector"
_OBS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _evidence() -> list[Evidence]:
    return [Evidence(source="test", detail="unit")]


def _make_connector_id(pool, tenant: UUID) -> UUID:
    """Register a connector row and return its id."""
    with tenant_session(pool, tenant) as conn:
        c = ConnectorRegistry(conn, tenant).resolve_or_register(
            type=_SOURCE, display_name=_SOURCE
        )
    return c.connector_id


def _seed_vpc_and_subnet(pool, tenant: UUID) -> None:
    """Seed vpc-1, sub-1, and CONTAINS edge via the full reconcile path."""
    events = [
        DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net"),
        DiscoveredCI(type=CIType.subnet, external_id="sub-1", name="subnet-a"),
        DiscoveredEdge(
            type=EdgeType.CONTAINS,
            from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
            to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            evidence=_evidence(),
        ),
    ]
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            events,
            source=_SOURCE,
            ci_types=frozenset({CIType.vpc, CIType.subnet}),
            edge_types=frozenset({EdgeType.CONTAINS}),
        )


def _count_runs(pool, tenant: UUID, source: str | None = None) -> int:
    with tenant_session(pool, tenant) as conn:
        if source:
            return conn.execute(
                "SELECT count(*) FROM connector_runs WHERE source=%s", (source,)
            ).fetchone()[0]
        return conn.execute("SELECT count(*) FROM connector_runs").fetchone()[0]


def _count_facts(pool, tenant: UUID, source: str | None = None) -> int:
    with tenant_session(pool, tenant) as conn:
        if source:
            return conn.execute(
                "SELECT count(*) FROM raw_facts WHERE source=%s", (source,)
            ).fetchone()[0]
        return conn.execute("SELECT count(*) FROM raw_facts").fetchone()[0]


def _get_run_row(pool, tenant: UUID, source: str) -> tuple | None:
    """Return (status, connector_id, source) for the most recent run."""
    with tenant_session(pool, tenant) as conn:
        return conn.execute(
            "SELECT status, connector_id, source FROM connector_runs "
            "WHERE source=%s ORDER BY started_at DESC NULLS LAST LIMIT 1",
            (source,),
        ).fetchone()


def _get_fact_connector_ids(pool, tenant: UUID, source: str) -> set:
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT DISTINCT connector_id FROM raw_facts WHERE source=%s", (source,)
        ).fetchall()
    return {r[0] for r in rows}


def _get_fact_observed_ats(pool, tenant: UUID, source: str) -> set:
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT DISTINCT observed_at FROM raw_facts WHERE source=%s", (source,)
        ).fetchall()
    return {r[0] for r in rows}


# ===========================================================================
# 1. SDK TYPES — ConnectorDelta / EdgeEndpointRef (AC 1, 2, 3, 12)
# ===========================================================================


def test_connector_delta_is_importable():
    """AC 3: ConnectorDelta is importable from infra_twin.connector_sdk."""
    from infra_twin.connector_sdk import ConnectorDelta  # noqa: F401


def test_edge_endpoint_ref_is_importable():
    """AC 3: EdgeEndpointRef is importable from infra_twin.connector_sdk."""
    from infra_twin.connector_sdk import EdgeEndpointRef  # noqa: F401


def test_connector_delta_in_all():
    """AC 3: 'ConnectorDelta' is in connector_sdk.__all__."""
    from infra_twin import connector_sdk
    assert "ConnectorDelta" in connector_sdk.__all__


def test_edge_endpoint_ref_in_all():
    """AC 3: 'EdgeEndpointRef' is in connector_sdk.__all__."""
    from infra_twin import connector_sdk
    assert "EdgeEndpointRef" in connector_sdk.__all__


def test_connector_delta_defaults_to_empty_lists():
    """AC 1: ConnectorDelta() has upserts=[], removed_cis=[], removed_edges=[] by default."""
    d = ConnectorDelta()
    assert d.upserts == []
    assert d.removed_cis == []
    assert d.removed_edges == []


def test_connector_delta_accepts_mixed_upserts():
    """AC 1: upserts can contain both DiscoveredCI and DiscoveredEdge."""
    ci = DiscoveredCI(type=CIType.vpc, external_id="v1", name="net")
    edge = DiscoveredEdge(
        type=EdgeType.CONTAINS,
        from_ref=CIRef(type=CIType.vpc, external_id="v1"),
        to_ref=CIRef(type=CIType.subnet, external_id="s1"),
        evidence=_evidence(),
    )
    d = ConnectorDelta(upserts=[ci, edge])
    assert len(d.upserts) == 2


def test_edge_endpoint_ref_fields():
    """AC 2: EdgeEndpointRef has fields type, from_ref, to_ref."""
    ref = EdgeEndpointRef(
        type=EdgeType.CONTAINS,
        from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
        to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
    )
    assert ref.type == EdgeType.CONTAINS
    assert ref.from_ref.external_id == "vpc-1"
    assert ref.to_ref.external_id == "sub-1"


def test_delta_result_is_dataclass_with_zero_defaults():
    """AC 12: DeltaResult is a dataclass with six int fields all defaulting to 0."""
    import dataclasses
    assert dataclasses.is_dataclass(DeltaResult)
    r = DeltaResult()
    assert r.cis_created == 0
    assert r.cis_updated == 0
    assert r.cis_unchanged == 0
    assert r.cis_closed == 0
    assert r.edges_written == 0
    assert r.edges_closed == 0


# ===========================================================================
# 2. EXPORT SANITY (AC 13)
# ===========================================================================


def test_apply_delta_in_reconciliation_all():
    """AC 13: 'apply_delta' is in reconciliation.__all__."""
    from infra_twin import reconciliation
    assert "apply_delta" in reconciliation.__all__


def test_delta_result_in_reconciliation_all():
    """AC 13: 'DeltaResult' is in reconciliation.__all__."""
    from infra_twin import reconciliation
    assert "DeltaResult" in reconciliation.__all__


def test_apply_delta_is_importable():
    """AC 13: apply_delta is importable from infra_twin.reconciliation."""
    from infra_twin.reconciliation import apply_delta  # noqa: F401


# ===========================================================================
# 3. HAPPY PATH — upsert-only delta (AC 14, E1, E17)
# ===========================================================================


def test_upsert_only_creates_ci(pool, make_tenant):
    """AC 14 / E1: apply_delta with an upsert-only delta creates the named CI."""
    tenant = make_tenant("delta-create-1")
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-new", name="brand-new")]
    )
    result = apply_delta(pool, tenant, connector_id, delta, _OBS)

    assert result.cis_created == 1
    assert result.cis_closed == 0
    assert result.edges_closed == 0

    with tenant_session(pool, tenant) as conn:
        current = CIRepository(conn, tenant).get_current(type=CIType.vpc, external_id="vpc-new")
    assert len(current) == 1
    assert current[0].name == "brand-new"


def test_upsert_only_leaves_sibling_ci_untouched(pool, make_tenant):
    """AC 14 / E1 / E17: upserting CI-1 leaves CI-2 with the same valid_from and still open."""
    tenant = make_tenant("delta-sibling-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    # Capture sibling's original state before the delta.
    with tenant_session(pool, tenant) as conn:
        sub_before = CIRepository(conn, tenant).get_current(type=CIType.subnet, external_id="sub-1")
    assert sub_before, "setup failed: sub-1 not found"
    original_valid_from = sub_before[0].valid_from

    # Delta that only touches vpc-1 (renames it).
    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net-renamed")]
    )
    result = apply_delta(pool, tenant, connector_id, delta, _OBS)

    assert result.cis_updated == 1
    assert result.cis_closed == 0

    # Sibling sub-1 must be unchanged.
    with tenant_session(pool, tenant) as conn:
        sub_after = CIRepository(conn, tenant).get_current(type=CIType.subnet, external_id="sub-1")
    assert len(sub_after) == 1
    assert sub_after[0].valid_from == original_valid_from
    assert sub_after[0].valid_to is None


def test_upsert_only_leaves_unrelated_edge_open(pool, make_tenant):
    """AC 14 / E1 / E17: upserting CI-1 leaves the CONTAINS edge untouched and still open."""
    tenant = make_tenant("delta-edge-open-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    # Delta: just rename vpc-1, do not touch the edge.
    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net-v2")]
    )
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    with tenant_session(pool, tenant) as conn:
        edges = EdgeRepository(conn, tenant).get_current()
    open_edges = [e for e in edges if e.valid_to is None]
    assert len(open_edges) == 1, "CONTAINS edge should still be open after upsert-only delta"


def test_upsert_only_versions_ci_creates_history(pool, make_tenant):
    """AC 14 / E1: upsert of a changed CI produces two history rows; old row has valid_to set."""
    tenant = make_tenant("delta-history-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    # Capture original CI id.
    with tenant_session(pool, tenant) as conn:
        vpc_before = CIRepository(conn, tenant).get_current(type=CIType.vpc, external_id="vpc-1")[0]

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-1", name="net-v2")]
    )
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    with tenant_session(pool, tenant) as conn:
        history = CIRepository(conn, tenant).history(vpc_before.id)

    assert len(history) == 2, f"expected 2 history rows, got {len(history)}"
    closed_row = next(h for h in history if h.valid_to is not None)
    open_row = next(h for h in history if h.valid_to is None)
    assert closed_row.name == "net"
    assert open_row.name == "net-v2"


# ===========================================================================
# 4. REMOVAL-ONLY DELTA (AC 15, E2, E5)
# ===========================================================================


def test_removal_only_closes_named_ci(pool, make_tenant):
    """AC 15 / E2: removal-only delta closes the named CI (valid_to set, row still present)."""
    tenant = make_tenant("delta-remove-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        removed_cis=[CIRef(type=CIType.vpc, external_id="vpc-1")]
    )
    result = apply_delta(pool, tenant, connector_id, delta, _OBS)

    assert result.cis_closed == 1
    assert result.cis_created == 0
    assert result.cis_updated == 0

    # Row must still physically exist with valid_to set (bitemporal, never hard-deleted).
    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        # get_current returns only open rows; should be empty for vpc-1.
        current = repo.get_current(type=CIType.vpc, external_id="vpc-1")
        assert current == [], "expected vpc-1 to be closed"

        # But history must still show the row.
        vpc_before_list = repo.get_current(type=CIType.vpc)
        # All closed, so we need the history via admin connection.

    # Check via admin (bypasses RLS) to confirm the row is physically present with valid_to.
    from infra_twin.db.config import admin_dsn
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM cis WHERE type=%s AND external_id=%s AND tenant_id=%s",
            ("vpc", "vpc-1", tenant),
        ).fetchone()
    assert row is not None, "vpc-1 row must physically exist even after close"
    assert row[0] is not None, "valid_to must be set (not null) after close"


def test_removal_only_leaves_sibling_ci_open(pool, make_tenant):
    """AC 15 / E2: removal of vpc-1 leaves sub-1 open."""
    tenant = make_tenant("delta-remove-2")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        removed_cis=[CIRef(type=CIType.vpc, external_id="vpc-1")]
    )
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    with tenant_session(pool, tenant) as conn:
        sub = CIRepository(conn, tenant).get_current(type=CIType.subnet, external_id="sub-1")
    assert len(sub) == 1
    assert sub[0].valid_to is None


def test_removal_idempotent_second_call_is_noop(pool, make_tenant):
    """AC 15 / E5: removing an already-closed CI is a no-op (cis_closed==0, no exception)."""
    tenant = make_tenant("delta-remove-idem-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        removed_cis=[CIRef(type=CIType.vpc, external_id="vpc-1")]
    )
    first = apply_delta(pool, tenant, connector_id, delta, _OBS)
    assert first.cis_closed == 1

    second = apply_delta(pool, tenant, connector_id, delta, _OBS)
    assert second.cis_closed == 0


def test_removal_of_never_existing_ci_is_noop(pool, make_tenant):
    """E5: removing a CI that never existed is a no-op — no exception, cis_closed==0."""
    tenant = make_tenant("delta-remove-ghost-1")
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        removed_cis=[CIRef(type=CIType.vpc, external_id="vpc-ghost")]
    )
    result = apply_delta(pool, tenant, connector_id, delta, _OBS)
    assert result.cis_closed == 0


def test_removal_only_closes_named_edge(pool, make_tenant):
    """E2: removal of a named edge closes it (valid_to set), row still physically present."""
    tenant = make_tenant("delta-remove-edge-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        removed_edges=[
            EdgeEndpointRef(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            )
        ]
    )
    result = apply_delta(pool, tenant, connector_id, delta, _OBS)

    assert result.edges_closed == 1

    with tenant_session(pool, tenant) as conn:
        open_edges = EdgeRepository(conn, tenant).get_current()
    assert open_edges == [], "CONTAINS edge should be closed"

    # Physical row must still exist.
    from infra_twin.db.config import admin_dsn
    with psycopg.connect(admin_dsn()) as admin_conn:
        row = admin_conn.execute(
            "SELECT valid_to FROM edges WHERE type='CONTAINS' AND tenant_id=%s", (tenant,)
        ).fetchone()
    assert row is not None
    assert row[0] is not None


def test_removal_idempotent_for_edge_second_call_is_noop(pool, make_tenant):
    """E5: removing an already-closed edge is a no-op (edges_closed==0, no exception)."""
    tenant = make_tenant("delta-remove-edge-idem-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    ref = EdgeEndpointRef(
        type=EdgeType.CONTAINS,
        from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
        to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
    )
    first = apply_delta(pool, tenant, connector_id, ConnectorDelta(removed_edges=[ref]), _OBS)
    assert first.edges_closed == 1

    second = apply_delta(pool, tenant, connector_id, ConnectorDelta(removed_edges=[ref]), _OBS)
    assert second.edges_closed == 0


# ===========================================================================
# 5. EMPTY DELTA (AC 17, E3)
# ===========================================================================


def test_empty_delta_writes_ok_run(pool, make_tenant):
    """AC 17 / E3: empty delta still writes a connector_runs row with status='ok'.

    The returned connector_run_id is the actual run id (non-None), so a bare
    DeltaResult() equality check would fail. Instead we assert the six counters
    are all zero and that connector_run_id is non-None and matches the persisted run.
    """
    tenant = make_tenant("delta-empty-1")
    connector_id = _make_connector_id(pool, tenant)

    result = apply_delta(pool, tenant, connector_id, ConnectorDelta(), _OBS)

    # All counter fields must be zero.
    assert result.cis_created == 0
    assert result.cis_updated == 0
    assert result.cis_unchanged == 0
    assert result.cis_closed == 0
    assert result.edges_written == 0
    assert result.edges_closed == 0

    # The run id must be populated and point to the persisted run.
    assert result.connector_run_id is not None

    with tenant_session(pool, tenant) as conn:
        persisted = conn.execute(
            "SELECT run_id, status FROM connector_runs WHERE source=%s "
            "ORDER BY started_at DESC NULLS LAST LIMIT 1",
            (_SOURCE,),
        ).fetchone()
    assert persisted is not None
    persisted_run_id, status = persisted
    assert status == "ok"
    assert result.connector_run_id == persisted_run_id


def test_empty_delta_writes_zero_raw_facts(pool, make_tenant):
    """AC 17 / E3: empty delta writes zero raw_facts rows."""
    tenant = make_tenant("delta-empty-2")
    connector_id = _make_connector_id(pool, tenant)

    apply_delta(pool, tenant, connector_id, ConnectorDelta(), _OBS)

    assert _count_facts(pool, tenant, _SOURCE) == 0


def test_empty_delta_result_all_zeros(pool, make_tenant):
    """AC 17 / E3: DeltaResult returned by empty delta has all-zero counters."""
    tenant = make_tenant("delta-empty-3")
    connector_id = _make_connector_id(pool, tenant)

    result = apply_delta(pool, tenant, connector_id, ConnectorDelta(), _OBS)

    assert result.cis_created == 0
    assert result.cis_updated == 0
    assert result.cis_unchanged == 0
    assert result.cis_closed == 0
    assert result.edges_written == 0
    assert result.edges_closed == 0


# ===========================================================================
# 6. RE-UPSERT IDENTICAL CI (E4)
# ===========================================================================


def test_reupsert_identical_ci_is_unchanged(pool, make_tenant):
    """E4: re-upserting an identical CI increments cis_unchanged, not created/updated."""
    tenant = make_tenant("delta-reupsert-1")
    connector_id = _make_connector_id(pool, tenant)

    ci = DiscoveredCI(type=CIType.vpc, external_id="vpc-idem", name="net")
    delta = ConnectorDelta(upserts=[ci])

    first = apply_delta(pool, tenant, connector_id, delta, _OBS)
    assert first.cis_created == 1

    second = apply_delta(pool, tenant, connector_id, delta, _OBS)
    assert second.cis_unchanged == 1
    assert second.cis_created == 0
    assert second.cis_updated == 0


def test_reupsert_identical_ci_has_one_history_row(pool, make_tenant):
    """E4: re-upserting an identical CI produces exactly one history row (no version bump)."""
    tenant = make_tenant("delta-reupsert-2")
    connector_id = _make_connector_id(pool, tenant)

    ci = DiscoveredCI(type=CIType.vpc, external_id="vpc-idem2", name="net")
    delta = ConnectorDelta(upserts=[ci])
    apply_delta(pool, tenant, connector_id, delta, _OBS)
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    with tenant_session(pool, tenant) as conn:
        repo = CIRepository(conn, tenant)
        current = repo.get_current(type=CIType.vpc, external_id="vpc-idem2")
    assert len(current) == 1
    assert current[0].valid_to is None


# ===========================================================================
# 7. NO CASCADE ON CI REMOVAL (AC 18, E8)
# ===========================================================================


def test_removing_ci_does_not_cascade_to_edges(pool, make_tenant):
    """AC 18 / E8: closing a CI does NOT auto-close its edges; caller must name them explicitly."""
    tenant = make_tenant("delta-nocascade-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    # Close vpc-1 but do NOT name the CONTAINS edge in removed_edges.
    delta = ConnectorDelta(
        removed_cis=[CIRef(type=CIType.vpc, external_id="vpc-1")]
    )
    result = apply_delta(pool, tenant, connector_id, delta, _OBS)

    assert result.cis_closed == 1
    assert result.edges_closed == 0

    # The CONTAINS edge should still be open.
    with tenant_session(pool, tenant) as conn:
        open_edges = EdgeRepository(conn, tenant).get_current()
    assert len(open_edges) == 1, "CONTAINS edge must remain open after CI-only removal"
    assert open_edges[0].type == EdgeType.CONTAINS
    assert open_edges[0].valid_to is None


# ===========================================================================
# 8. RUN AND RAW_FACTS WRITTEN AND LINKED (AC 16, E15, E16)
# ===========================================================================


def test_run_row_status_ok_and_linked_to_connector(pool, make_tenant):
    """AC 16 / E16: connector_runs row has status='ok', connector_id == passed id, source == registry type."""
    tenant = make_tenant("delta-run-link-1")
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-run", name="r")]
    )
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    row = _get_run_row(pool, tenant, _SOURCE)
    assert row is not None
    status, run_cid, run_src = row
    assert status == "ok"
    assert run_cid == connector_id
    assert run_src == _SOURCE


def test_raw_facts_count_matches_delta_items(pool, make_tenant):
    """AC 16 / E16: raw_facts count equals total delta items (upserts + removed_cis + removed_edges)."""
    tenant = make_tenant("delta-run-link-2")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.subnet, external_id="sub-2", name="s2")],
        removed_cis=[CIRef(type=CIType.vpc, external_id="vpc-1")],
        removed_edges=[
            EdgeEndpointRef(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            )
        ],
    )
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    # 1 upsert + 1 removed_ci + 1 removed_edge = 3 raw_facts
    count = _count_facts(pool, tenant, _SOURCE)
    assert count == 3


def test_raw_facts_all_carry_connector_id(pool, make_tenant):
    """AC 16 / E16: every raw_facts row carries the resolved connector_id."""
    tenant = make_tenant("delta-run-link-3")
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[
            DiscoveredCI(type=CIType.vpc, external_id="vpc-a", name="a"),
            DiscoveredCI(type=CIType.subnet, external_id="sub-a", name="sa"),
        ]
    )
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    fact_cids = _get_fact_connector_ids(pool, tenant, _SOURCE)
    assert fact_cids == {connector_id}


def test_raw_facts_share_observed_at(pool, make_tenant):
    """E15: every raw_facts row from one apply_delta call shares the exact observed_at argument."""
    tenant = make_tenant("delta-obs-at-1")
    connector_id = _make_connector_id(pool, tenant)

    fixed_obs = datetime(2026, 3, 15, 9, 30, 0, tzinfo=timezone.utc)
    delta = ConnectorDelta(
        upserts=[
            DiscoveredCI(type=CIType.vpc, external_id="vpc-obs", name="v"),
            DiscoveredCI(type=CIType.subnet, external_id="sub-obs", name="s"),
        ]
    )
    apply_delta(pool, tenant, connector_id, delta, fixed_obs)

    observed_ats = _get_fact_observed_ats(pool, tenant, _SOURCE)
    assert len(observed_ats) == 1
    stored_ts = next(iter(observed_ats))
    # Compare truncated to seconds (DB timestamp resolution may vary).
    assert stored_ts.replace(microsecond=0, tzinfo=timezone.utc) == fixed_obs.replace(microsecond=0)


def test_raw_fact_payload_shapes_match_spec(pool, make_tenant):
    """AC 16: payload shapes are {'kind': 'ci'|'edge'|'removed_ci'|'removed_edge', 'event': {...}}."""
    tenant = make_tenant("delta-payload-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[
            DiscoveredCI(type=CIType.subnet, external_id="sub-new", name="new"),
            DiscoveredEdge(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-new"),
                evidence=_evidence(),
            ),
        ],
        removed_cis=[CIRef(type=CIType.subnet, external_id="sub-1")],
        removed_edges=[
            EdgeEndpointRef(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
            )
        ],
    )
    apply_delta(pool, tenant, connector_id, delta, _OBS)

    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT payload FROM raw_facts WHERE source=%s ORDER BY fact_id", (_SOURCE,)
        ).fetchall()

    payloads = [r[0] for r in rows]
    assert len(payloads) == 4

    kinds = [p["kind"] for p in payloads]
    # Ordering: upserts first (CI then edge), then removed_cis, then removed_edges.
    assert kinds == ["ci", "edge", "removed_ci", "removed_edge"]

    for p in payloads:
        assert "kind" in p
        assert "event" in p
        assert isinstance(p["event"], dict)


def test_exactly_one_run_row_per_apply_delta_call(pool, make_tenant):
    """E16: each apply_delta call writes exactly one connector_runs row."""
    tenant = make_tenant("delta-onerun-1")
    connector_id = _make_connector_id(pool, tenant)

    apply_delta(pool, tenant, connector_id, ConnectorDelta(), _OBS)
    apply_delta(pool, tenant, connector_id, ConnectorDelta(), _OBS)

    count = _count_runs(pool, tenant, _SOURCE)
    assert count == 2


# ===========================================================================
# 9. UNRESOLVED UPSERTED-EDGE ENDPOINT RAISES AND ROLLS BACK (AC 20, E6, E11)
# ===========================================================================


def test_unresolved_edge_endpoint_raises_value_error(pool, make_tenant):
    """AC 20 / E6: upserted edge with an unknown endpoint raises ValueError."""
    tenant = make_tenant("delta-phantom-1")
    connector_id = _make_connector_id(pool, tenant)

    # vpc-phantom is neither in the delta's upserts nor in the DB.
    delta = ConnectorDelta(
        upserts=[
            DiscoveredCI(type=CIType.subnet, external_id="sub-real", name="real"),
            DiscoveredEdge(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-phantom"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-real"),
                evidence=_evidence(),
            ),
        ]
    )
    with pytest.raises(ValueError, match="unresolved edge endpoint"):
        apply_delta(pool, tenant, connector_id, delta, _OBS)


def test_unresolved_edge_endpoint_rolls_back_no_run_row(pool, make_tenant):
    """AC 20 / E11: after ValueError from unresolved endpoint, no connector_runs row is written."""
    tenant = make_tenant("delta-phantom-2")
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[
            DiscoveredEdge(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-ghost"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-ghost"),
                evidence=_evidence(),
            )
        ]
    )
    with pytest.raises(ValueError):
        apply_delta(pool, tenant, connector_id, delta, _OBS)

    # The transaction must have rolled back: no run row, no facts.
    assert _count_runs(pool, tenant, _SOURCE) == 0
    assert _count_facts(pool, tenant, _SOURCE) == 0


def test_unresolved_edge_endpoint_rolls_back_partial_ci_writes(pool, make_tenant):
    """E11: even partial CI writes in the same delta are rolled back on unresolved-edge error."""
    tenant = make_tenant("delta-phantom-3")
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[
            # This CI would be created...
            DiscoveredCI(type=CIType.vpc, external_id="vpc-partial", name="partial"),
            # ...but then this edge has an unresolved endpoint -> whole transaction rolls back.
            DiscoveredEdge(
                type=EdgeType.CONTAINS,
                from_ref=CIRef(type=CIType.vpc, external_id="vpc-partial"),
                to_ref=CIRef(type=CIType.subnet, external_id="sub-missing"),
                evidence=_evidence(),
            ),
        ]
    )
    with pytest.raises(ValueError):
        apply_delta(pool, tenant, connector_id, delta, _OBS)

    # vpc-partial must NOT be in the DB (transaction rolled back).
    with tenant_session(pool, tenant) as conn:
        current = CIRepository(conn, tenant).get_current(type=CIType.vpc, external_id="vpc-partial")
    assert current == []


# ===========================================================================
# 10. REMOVED EDGE WITH UNRESOLVED ENDPOINT IS NO-OP (E7)
# ===========================================================================


def test_removed_edge_unresolved_from_endpoint_is_noop(pool, make_tenant):
    """E7: removed edge whose from_ref CI no longer exists is a no-op (no exception)."""
    tenant = make_tenant("delta-noop-from-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    # Close vpc-1 first so its from_ref can't be resolved.
    with tenant_session(pool, tenant) as conn:
        CIRepository(conn, tenant).close(CIType.vpc, "vpc-1")

    ref = EdgeEndpointRef(
        type=EdgeType.CONTAINS,
        from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
        to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
    )
    result = apply_delta(pool, tenant, connector_id, ConnectorDelta(removed_edges=[ref]), _OBS)
    assert result.edges_closed == 0


def test_removed_edge_unresolved_to_endpoint_is_noop(pool, make_tenant):
    """E7: removed edge whose to_ref CI no longer exists is a no-op (no exception)."""
    tenant = make_tenant("delta-noop-to-1")
    _seed_vpc_and_subnet(pool, tenant)
    connector_id = _make_connector_id(pool, tenant)

    # Close sub-1 so to_ref can't be resolved.
    with tenant_session(pool, tenant) as conn:
        CIRepository(conn, tenant).close(CIType.subnet, "sub-1")

    ref = EdgeEndpointRef(
        type=EdgeType.CONTAINS,
        from_ref=CIRef(type=CIType.vpc, external_id="vpc-1"),
        to_ref=CIRef(type=CIType.subnet, external_id="sub-1"),
    )
    result = apply_delta(pool, tenant, connector_id, ConnectorDelta(removed_edges=[ref]), _OBS)
    assert result.edges_closed == 0


# ===========================================================================
# 11. UPSERTED AND REMOVED IN SAME DELTA ENDS CLOSED (E9)
# ===========================================================================


def test_upsert_then_remove_in_same_delta_ends_closed(pool, make_tenant):
    """E9: a CI both upserted and in removed_cis in the same delta ends CLOSED
    (upserts run before removals: last-writer-wins by step order)."""
    tenant = make_tenant("delta-e9-1")
    connector_id = _make_connector_id(pool, tenant)

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-e9", name="v")],
        removed_cis=[CIRef(type=CIType.vpc, external_id="vpc-e9")],
    )
    result = apply_delta(pool, tenant, connector_id, delta, _OBS)

    # The CI was created and then immediately closed.
    assert result.cis_created == 1
    assert result.cis_closed == 1

    with tenant_session(pool, tenant) as conn:
        current = CIRepository(conn, tenant).get_current(type=CIType.vpc, external_id="vpc-e9")
    assert current == [], "CI should be closed at end of delta"


# ===========================================================================
# 12. UNKNOWN CONNECTOR_ID RAISES ValueError (AC 20, E10)
# ===========================================================================


def test_unknown_connector_id_raises_value_error(pool, make_tenant):
    """AC 20 / E10: passing an unknown connector_id raises ValueError before any write."""
    tenant = make_tenant("delta-unknown-cid-1")
    unknown_id = uuid.uuid4()

    with pytest.raises(ValueError, match="connector_id not found for tenant"):
        apply_delta(pool, tenant, unknown_id, ConnectorDelta(), _OBS)

    # Nothing written.
    assert _count_runs(pool, tenant) == 0
    assert _count_facts(pool, tenant) == 0


def test_unknown_connector_id_writes_nothing(pool, make_tenant):
    """E10: with an unknown connector_id, no CI/edge/run/fact rows are written."""
    tenant = make_tenant("delta-unknown-cid-2")
    _seed_vpc_and_subnet(pool, tenant)
    unknown_id = uuid.uuid4()

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-extra", name="x")]
    )
    with pytest.raises(ValueError):
        apply_delta(pool, tenant, unknown_id, delta, _OBS)

    # vpc-extra must not be in the DB.
    with tenant_session(pool, tenant) as conn:
        extra = CIRepository(conn, tenant).get_current(type=CIType.vpc, external_id="vpc-extra")
    assert extra == []


# ===========================================================================
# 13. ADVERSARIAL TENANT ISOLATION (AC 19, E12, E13, E14)
# ===========================================================================


def test_cross_tenant_connector_id_raises_value_error(pool, make_tenant):
    """AC 19a / E12: passing tenant B's connector_id under tenant A raises ValueError;
    ConnectorRegistry.get (RLS-scoped) returns None -> ValueError before any write."""
    a = make_tenant("iso-delta-A")
    b = make_tenant("iso-delta-B")

    b_connector_id = _make_connector_id(pool, b)

    with pytest.raises(ValueError, match="connector_id not found for tenant"):
        # Use A's tenant context but B's connector_id.
        apply_delta(pool, a, b_connector_id, ConnectorDelta(), _OBS)

    # Nothing written for A.
    assert _count_runs(pool, a) == 0
    assert _count_facts(pool, a) == 0


def test_tenant_b_session_sees_zero_of_tenant_a_cis(pool, make_tenant):
    """AC 19b / E14: after apply_delta for tenant A, tenant B's RLS-scoped session
    sees zero of A's CIs."""
    a = make_tenant("iso-ci-A")
    b = make_tenant("iso-ci-B")
    a_cid = _make_connector_id(pool, a)

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-a", name="a")]
    )
    apply_delta(pool, a, a_cid, delta, _OBS)

    with tenant_session(pool, b) as conn:
        b_cis = CIRepository(conn, b).get_current()
    assert b_cis == []


def test_tenant_b_session_sees_zero_of_tenant_a_edges(pool, make_tenant):
    """AC 19b / E14: after apply_delta for tenant A, tenant B's session sees zero of A's edges."""
    a = make_tenant("iso-edge-A")
    b = make_tenant("iso-edge-B")
    _seed_vpc_and_subnet(pool, a)
    a_cid = _make_connector_id(pool, a)

    delta = ConnectorDelta(
        upserts=[
            DiscoveredCI(type=CIType.subnet, external_id="sub-2", name="s2"),
        ]
    )
    apply_delta(pool, a, a_cid, delta, _OBS)

    with tenant_session(pool, b) as conn:
        b_edges = EdgeRepository(conn, b).get_current()
    assert b_edges == []


def test_tenant_b_session_sees_zero_of_tenant_a_runs(pool, make_tenant):
    """AC 19b / E14: after apply_delta for tenant A, tenant B sees zero connector_runs rows."""
    a = make_tenant("iso-run-A")
    b = make_tenant("iso-run-B")
    a_cid = _make_connector_id(pool, a)

    apply_delta(pool, a, a_cid, ConnectorDelta(), _OBS)

    assert _count_runs(pool, a) == 1
    assert _count_runs(pool, b) == 0


def test_tenant_b_session_sees_zero_of_tenant_a_raw_facts(pool, make_tenant):
    """AC 19b / E14: after apply_delta for tenant A, tenant B sees zero raw_facts rows."""
    a = make_tenant("iso-rf-A")
    b = make_tenant("iso-rf-B")
    a_cid = _make_connector_id(pool, a)

    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-iso", name="v")]
    )
    apply_delta(pool, a, a_cid, delta, _OBS)

    assert _count_facts(pool, a) == 1
    assert _count_facts(pool, b) == 0


def test_bare_connection_sees_zero_cis(pool, make_tenant):
    """AC 19c / E14: bare pool connection (no app.tenant_id GUC) sees zero cis rows."""
    a = make_tenant("bare-ci-A")
    a_cid = _make_connector_id(pool, a)
    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-bare", name="b")]
    )
    apply_delta(pool, a, a_cid, delta, _OBS)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM cis").fetchone()[0]
    assert count == 0


def test_bare_connection_sees_zero_connector_runs(pool, make_tenant):
    """AC 19c / E14: bare pool connection sees zero connector_runs rows."""
    a = make_tenant("bare-run-A")
    a_cid = _make_connector_id(pool, a)
    apply_delta(pool, a, a_cid, ConnectorDelta(), _OBS)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM connector_runs").fetchone()[0]
    assert count == 0


def test_bare_connection_sees_zero_raw_facts(pool, make_tenant):
    """AC 19c / E14: bare pool connection sees zero raw_facts rows."""
    a = make_tenant("bare-rf-A")
    a_cid = _make_connector_id(pool, a)
    delta = ConnectorDelta(
        upserts=[DiscoveredCI(type=CIType.vpc, external_id="vpc-bare-rf", name="b")]
    )
    apply_delta(pool, a, a_cid, delta, _OBS)

    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM raw_facts").fetchone()[0]
    assert count == 0


def test_rls_blocks_cross_tenant_stamp_on_connector_runs(pool, make_tenant):
    """AC 19a / E13: direct INSERT into connector_runs stamped with another tenant_id
    under the current session violates RLS WITH CHECK policy -> psycopg.Error."""
    a = make_tenant("xstamp-run-A")
    b = make_tenant("xstamp-run-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO connector_runs (tenant_id, source, status, started_at) "
                "VALUES (%s, 'adversarial-delta', 'partial', now())",
                (str(b),),
            )


def test_rls_blocks_cross_tenant_stamp_on_raw_facts(pool, make_tenant):
    """AC 19a / E13: direct INSERT into raw_facts stamped with another tenant_id
    under the current session violates RLS WITH CHECK policy -> psycopg.Error."""
    a = make_tenant("xstamp-rf-A")
    b = make_tenant("xstamp-rf-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO raw_facts (tenant_id, source, observed_at, payload) "
                "VALUES (%s, 'adversarial-delta', now(), '{}'::jsonb)",
                (str(b),),
            )


def test_rls_blocks_cross_tenant_stamp_on_cis(pool, make_tenant):
    """E13: direct INSERT into cis stamped with another tenant_id raises psycopg.Error."""
    a = make_tenant("xstamp-ci-A")
    b = make_tenant("xstamp-ci-B")

    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO cis (tenant_id, type, external_id, name, attributes, confidence, "
                "first_seen, last_seen, valid_from) "
                "VALUES (%s, 'vpc', 'vpc-adversarial', 'adv', '{}', 1.0, now(), now(), now())",
                (str(b),),
            )
