"""Tests for canonical bitemporal edge identity with edge_key discriminator.

Covers §8 (required test cases) from the spec:
  1. test_two_declared_edges_distinct_edge_key_two_open_rows
  2. test_reupsert_same_tuple_noops_in_place
  3. test_changed_declared_edge_versions_not_duplicates
  4. test_two_inferred_same_pair_aggregate_one_edge
  5. test_declared_and_inferred_same_pair_coexist
  6. test_close_targets_specific_edge_key

E2E (DB connector, §5.9):
  7. test_e2e_two_fks_same_pair_two_depends_on_edges — two FK constraints reconcile
     to two distinct DEPENDS_ON edges; both projected into AGE; adversarial isolation.

Migration ordering:
  8. test_migration_0019_exists_and_is_highest — 0001-0018 exist; 0019 is highest;
     body has idempotent guards and the 5-column unique index.
"""

from __future__ import annotations

import os
from uuid import UUID, uuid4

import psycopg
import pytest

from infra_twin.core_model import (
    CI,
    CIType,
    Edge,
    EdgeSource,
    EdgeType,
    Evidence,
    INFERRED_BASELINE_CONFIDENCE,
    confidence_for_observations,
)
from infra_twin.db.config import admin_dsn
from infra_twin.db.graph import cypher
from infra_twin.db.repositories import (
    FLOWLOG_COUNT_EVIDENCE_SOURCE,
    CIRepository,
    EdgeRepository,
)
from infra_twin.db.session import tenant_session

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DB_MIGRATIONS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "migrations")
)


def _evidence(detail: str) -> list[Evidence]:
    return [Evidence(source="test", detail=detail)]


def _seed_ci(conn: psycopg.Connection, tenant: UUID, ci_type: CIType, ext_id: str) -> CI:
    repo = CIRepository(conn, tenant)
    ci = CI(
        tenant_id=tenant,
        type=ci_type,
        external_id=ext_id,
        name=ext_id,
        attributes={},
        confidence=1.0,
    )
    return repo.upsert(ci)


def _make_edge(
    tenant: UUID,
    from_id: UUID,
    to_id: UUID,
    *,
    edge_key: str = "",
    source: EdgeSource = EdgeSource.declared,
    confidence: float = 1.0,
    evidence_detail: str = "test-evidence",
) -> Edge:
    return Edge(
        tenant_id=tenant,
        type=EdgeType.DEPENDS_ON,
        from_id=from_id,
        to_id=to_id,
        edge_key=edge_key,
        source=source,
        confidence=confidence,
        evidence=_evidence(evidence_detail),
    )


def _make_inferred_edge(
    tenant: UUID, from_id: UUID, to_id: UUID, *, evidence_detail: str = "flow-obs-1"
) -> Edge:
    return Edge(
        tenant_id=tenant,
        type=EdgeType.CONNECTS_TO,
        from_id=from_id,
        to_id=to_id,
        edge_key="",
        source=EdgeSource.inferred,
        confidence=INFERRED_BASELINE_CONFIDENCE,
        evidence=_evidence(evidence_detail),
    )


def _open_edges(conn: psycopg.Connection, tenant: UUID) -> list[Edge]:
    return EdgeRepository(conn, tenant).get_current()


def _all_edge_versions_by_id(edge_id: UUID, tenant: UUID) -> list[dict]:
    """Bypass RLS via admin connection to inspect all bitemporal versions."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT id, edge_key, source, confidence, evidence, valid_from, valid_to "
            "FROM edges WHERE id = %s AND tenant_id = %s ORDER BY valid_from",
            (edge_id, tenant),
        ).fetchall()
    return [
        {
            "id": r[0],
            "edge_key": r[1],
            "source": r[2],
            "confidence": r[3],
            "evidence": r[4],
            "valid_from": r[5],
            "valid_to": r[6],
        }
        for r in rows
    ]


# ===========================================================================
# Test 1 (§8.1): Two declared edges with distinct edge_key create two open rows
# ===========================================================================


def test_two_declared_edges_distinct_edge_key_two_open_rows(pool, make_tenant):
    """§5 edge case 1 / §8.1: two DEPENDS_ON with same (type, from_id, to_id) but
    different edge_key values produce two open edge rows — no UniqueViolation on
    edges_current_identity or edges_pkey."""
    tenant = make_tenant("eid-two-declared")

    with tenant_session(pool, tenant) as conn:
        from_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-from-1")
        to_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-to-1")

        edge_repo = EdgeRepository(conn, tenant)
        edge_k1 = _make_edge(
            tenant, from_ci.id, to_ci.id, edge_key="k1", evidence_detail="constraint-k1"
        )
        edge_k2 = _make_edge(
            tenant, from_ci.id, to_ci.id, edge_key="k2", evidence_detail="constraint-k2"
        )

        result_k1 = edge_repo.upsert(edge_k1)
        result_k2 = edge_repo.upsert(edge_k2)  # must not raise

        open_edges = _open_edges(conn, tenant)

    # Exactly two open DEPENDS_ON edges for this pair
    depends_on = [e for e in open_edges if e.type == EdgeType.DEPENDS_ON]
    assert len(depends_on) == 2, (
        f"Expected 2 open DEPENDS_ON edges, got {len(depends_on)}"
    )

    # Each row retains its own edge_key
    keys = {e.edge_key for e in depends_on}
    assert keys == {"k1", "k2"}, f"Expected edge_keys {{'k1','k2'}}; got {keys}"

    # Each row has the correct source and evidence
    for e in depends_on:
        assert e.source == EdgeSource.declared, f"source wrong on {e.edge_key}: {e.source}"
        assert e.confidence == 1.0, f"confidence wrong on {e.edge_key}: {e.confidence}"
        assert e.evidence, f"evidence empty on {e.edge_key}"

    # Evidence is distinct per edge_key
    ev_by_key = {e.edge_key: e.evidence[0].detail for e in depends_on}
    assert ev_by_key["k1"] == "constraint-k1", f"k1 evidence detail wrong: {ev_by_key}"
    assert ev_by_key["k2"] == "constraint-k2", f"k2 evidence detail wrong: {ev_by_key}"


# ===========================================================================
# Test 2 (§8.2): Re-upsert same (type, from, to, edge_key) is idempotent
# ===========================================================================


def test_reupsert_same_tuple_noops_in_place(pool, make_tenant):
    """§5 edge case 2+3 / §8.2: re-upserting an identical declared edge no-ops (idempotent
    re-discovery): exactly one open row, no new version, no hard-delete of prior history."""
    tenant = make_tenant("eid-reupsert")

    with tenant_session(pool, tenant) as conn:
        from_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-from-2")
        to_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-to-2")

        edge_repo = EdgeRepository(conn, tenant)
        edge = _make_edge(
            tenant, from_ci.id, to_ci.id, edge_key="fk_dup", evidence_detail="original-ev"
        )
        first = edge_repo.upsert(edge)
        second = edge_repo.upsert(edge)  # same object, should no-op

        open_edges = _open_edges(conn, tenant)

    # Only one open row for this 4-tuple
    depends_on = [e for e in open_edges if e.type == EdgeType.DEPENDS_ON]
    assert len(depends_on) == 1, (
        f"Re-upsert of identical edge must yield exactly 1 open row; got {len(depends_on)}"
    )
    assert depends_on[0].edge_key == "fk_dup"

    # No hard delete: prior history intact (1 version, still open)
    versions = _all_edge_versions_by_id(first.id, tenant)
    assert len(versions) == 1, (
        f"No-op re-upsert must not create new bitemporal version; got {len(versions)} versions"
    )
    assert versions[0]["valid_to"] is None, "Open row must not be closed by a no-op re-upsert"


# ===========================================================================
# Test 3 (§8.3): Changed declared edge versions (not duplicates)
# ===========================================================================


def test_changed_declared_edge_versions_not_duplicates(pool, make_tenant):
    """§5 edge case 3 / §8.3: changing confidence/evidence on an edge with non-empty edge_key
    creates exactly one open row (new version), closes the prior row (valid_to set) — no
    hard-delete, no duplicate open rows."""
    tenant = make_tenant("eid-version")

    with tenant_session(pool, tenant) as conn:
        from_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-from-3")
        to_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-to-3")

        edge_repo = EdgeRepository(conn, tenant)
        edge_v1 = _make_edge(
            tenant, from_ci.id, to_ci.id, edge_key="fk_versioned",
            confidence=1.0, evidence_detail="ev-v1"
        )
        first = edge_repo.upsert(edge_v1)

    # Now update with changed evidence in a fresh transaction
    with tenant_session(pool, tenant) as conn:
        edge_repo = EdgeRepository(conn, tenant)
        edge_v2 = Edge(
            id=first.id,
            tenant_id=tenant,
            type=EdgeType.DEPENDS_ON,
            from_id=first.from_id,
            to_id=first.to_id,
            edge_key="fk_versioned",
            source=EdgeSource.declared,
            confidence=0.9,  # changed
            evidence=_evidence("ev-v2"),  # changed
        )
        edge_repo.upsert(edge_v2)
        open_edges = _open_edges(conn, tenant)

    depends_on = [e for e in open_edges if e.type == EdgeType.DEPENDS_ON]
    assert len(depends_on) == 1, (
        f"After version, exactly 1 open row; got {len(depends_on)}"
    )
    assert depends_on[0].edge_key == "fk_versioned"
    assert depends_on[0].confidence == pytest.approx(0.9, abs=1e-9), (
        f"Open row should carry new confidence; got {depends_on[0].confidence}"
    )

    # Old row closed via valid_to, not physically deleted
    versions = _all_edge_versions_by_id(first.id, tenant)
    assert len(versions) == 2, (
        f"Versioned edge must have exactly 2 bitemporal rows (v1 closed, v2 open); got {len(versions)}"
    )
    closed = [v for v in versions if v["valid_to"] is not None]
    open_ = [v for v in versions if v["valid_to"] is None]
    assert len(closed) == 1, f"Exactly 1 closed version expected; got {len(closed)}"
    assert len(open_) == 1, f"Exactly 1 open version expected; got {len(open_)}"


# ===========================================================================
# Test 4 (§8.4): Two inferred CONNECTS_TO for same pair aggregate into ONE edge
# ===========================================================================


def test_two_inferred_same_pair_aggregate_one_edge(pool, make_tenant):
    """§5 edge case 4 / §8.4: inferred CONNECTS_TO regression — two re-observations for the
    same (type, from_id, to_id, edge_key='') produce exactly ONE open inferred edge
    with accumulating confidence and count marker reflecting 2 observations."""
    tenant = make_tenant("eid-inferred")

    with tenant_session(pool, tenant) as conn:
        from_ci = _seed_ci(conn, tenant, CIType.ec2_instance, "ec2-inferred-from")
        to_ci = _seed_ci(conn, tenant, CIType.ec2_instance, "ec2-inferred-to")

    # First observation
    with tenant_session(pool, tenant) as conn:
        edge_repo = EdgeRepository(conn, tenant)
        inferred1 = _make_inferred_edge(
            tenant, from_ci.id, to_ci.id, evidence_detail="obs-1"
        )
        edge_repo.upsert(inferred1)

    # Second observation (same pair, same edge_key="")
    with tenant_session(pool, tenant) as conn:
        edge_repo = EdgeRepository(conn, tenant)
        inferred2 = _make_inferred_edge(
            tenant, from_ci.id, to_ci.id, evidence_detail="obs-2"
        )
        edge_repo.upsert(inferred2)

    with tenant_session(pool, tenant) as conn:
        open_edges = _open_edges(conn, tenant)

    # Exactly one open inferred CONNECTS_TO edge
    inferred_edges = [
        e for e in open_edges
        if e.type == EdgeType.CONNECTS_TO and e.source == EdgeSource.inferred
    ]
    assert len(inferred_edges) == 1, (
        f"Two inferred observations must aggregate into exactly 1 open edge; got {len(inferred_edges)}"
    )

    edge = inferred_edges[0]
    assert edge.edge_key == "", f"Inferred edges must use edge_key=''; got {edge.edge_key!r}"

    # Confidence strictly increased per confidence_for_observations
    expected_conf = confidence_for_observations(2)
    assert edge.confidence == pytest.approx(expected_conf, abs=1e-9), (
        f"After 2 observations, confidence should be {expected_conf}; got {edge.confidence}"
    )
    assert edge.confidence > INFERRED_BASELINE_CONFIDENCE, (
        f"Confidence must be > baseline {INFERRED_BASELINE_CONFIDENCE} after 2 observations"
    )

    # Count marker reflects 2 observations
    count_marker = next(
        (ev for ev in edge.evidence if ev.source == FLOWLOG_COUNT_EVIDENCE_SOURCE), None
    )
    assert count_marker is not None, "Inferred edge must have a count marker evidence entry"
    assert count_marker.detail == "2", (
        f"Count marker must reflect 2 observations; got {count_marker.detail!r}"
    )


# ===========================================================================
# Test 5 (§8.5): Declared and inferred edges for same pair coexist
# ===========================================================================


def test_declared_and_inferred_same_pair_coexist(pool, make_tenant):
    """§5 edge case 5 / §8.5: declared edge with edge_key='fk_a' and inferred edge
    with edge_key='' between the same (type, from_id, to_id) coexist as two open rows."""
    tenant = make_tenant("eid-coexist")

    with tenant_session(pool, tenant) as conn:
        from_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-coexist-from")
        to_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-coexist-to")

        edge_repo = EdgeRepository(conn, tenant)

        # Declared edge with non-empty edge_key
        declared_edge = Edge(
            tenant_id=tenant,
            type=EdgeType.DEPENDS_ON,
            from_id=from_ci.id,
            to_id=to_ci.id,
            edge_key="fk_a",
            source=EdgeSource.declared,
            confidence=1.0,
            evidence=_evidence("fk_a_constraint"),
        )
        edge_repo.upsert(declared_edge)

        # Inferred edge with default edge_key=""
        inferred_edge = Edge(
            tenant_id=tenant,
            type=EdgeType.DEPENDS_ON,
            from_id=from_ci.id,
            to_id=to_ci.id,
            edge_key="",
            source=EdgeSource.inferred,
            confidence=INFERRED_BASELINE_CONFIDENCE,
            evidence=_evidence("flow-observation"),
        )
        edge_repo.upsert(inferred_edge)

        open_edges = _open_edges(conn, tenant)

    depends_on = [e for e in open_edges if e.type == EdgeType.DEPENDS_ON]
    assert len(depends_on) == 2, (
        f"Declared + inferred with different edge_key must coexist as 2 open rows; got {len(depends_on)}"
    )

    keys = {e.edge_key for e in depends_on}
    assert keys == {"fk_a", ""}, f"Expected edge_keys {{'fk_a', ''}}; got {keys}"

    declared = next(e for e in depends_on if e.edge_key == "fk_a")
    inferred = next(e for e in depends_on if e.edge_key == "")
    assert declared.source == EdgeSource.declared
    assert inferred.source == EdgeSource.inferred


# ===========================================================================
# Test 6 (§8.6): close() targets a specific edge_key only
# ===========================================================================


def test_close_targets_specific_edge_key(pool, make_tenant):
    """§5 edge case 12 / §8.6: with two parallel declared edges (k1, k2), calling
    close(type, from, to, 'k1') closes only the k1 edge — k2 remains open."""
    tenant = make_tenant("eid-close-specific")

    with tenant_session(pool, tenant) as conn:
        from_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-close-from")
        to_ci = _seed_ci(conn, tenant, CIType.db_table, "tbl-close-to")

        edge_repo = EdgeRepository(conn, tenant)
        edge_k1 = _make_edge(
            tenant, from_ci.id, to_ci.id, edge_key="k1", evidence_detail="ev-k1"
        )
        edge_k2 = _make_edge(
            tenant, from_ci.id, to_ci.id, edge_key="k2", evidence_detail="ev-k2"
        )
        edge_repo.upsert(edge_k1)
        edge_repo.upsert(edge_k2)

        # Close only k1
        closed = edge_repo.close(EdgeType.DEPENDS_ON, from_ci.id, to_ci.id, "k1")
        assert closed is True, "close() must return True when an open row is closed"

        open_edges = _open_edges(conn, tenant)

    depends_on = [e for e in open_edges if e.type == EdgeType.DEPENDS_ON]
    assert len(depends_on) == 1, (
        f"After closing k1, exactly 1 open DEPENDS_ON expected; got {len(depends_on)}"
    )
    assert depends_on[0].edge_key == "k2", (
        f"The surviving open edge must be k2; got {depends_on[0].edge_key!r}"
    )

    # Closing a non-existent (already closed) k1 returns False
    with tenant_session(pool, tenant) as conn:
        edge_repo = EdgeRepository(conn, tenant)
        already_closed = edge_repo.close(EdgeType.DEPENDS_ON, from_ci.id, to_ci.id, "k1")
    assert already_closed is False, (
        "close() must return False when no open row exists for the 4-tuple"
    )


# ===========================================================================
# Test 7 (E2E §5.9): DB connector — two FKs between same table pair -> two edges
# ===========================================================================

# Re-use seeded constants from the DB connector test module
_HOST = "db.example.com"
_PORT = 5432
_INSTANCE_NAME = "prod-db"
_DB1 = "appdb"
_SCHEMA1 = "public"
_TABLE_FROM = "orders"
_TABLE_TO = "users"

_FK1_CONSTRAINT = "fk_orders_user"
_FK1_FROM_COLS = ["user_id"]
_FK1_TO_COLS = ["id"]

_FK2_CONSTRAINT = "fk_orders_approver"
_FK2_FROM_COLS = ["approver_id"]
_FK2_TO_COLS = ["id"]


class _TwoFkDbClient:
    """Minimal fake DB client with TWO FK constraints between orders->users (§5.9)."""

    def list_databases(self) -> list[dict]:
        return [{"name": _DB1, "owner": "postgres", "encoding": "UTF8"}]

    def list_schemas(self) -> list[dict]:
        return [{"database": _DB1, "name": _SCHEMA1, "owner": "postgres"}]

    def list_tables(self) -> list[dict]:
        return [
            {"database": _DB1, "schema": _SCHEMA1, "name": _TABLE_TO, "kind": "table", "estimated_rows": 10000},
            {"database": _DB1, "schema": _SCHEMA1, "name": _TABLE_FROM, "kind": "table", "estimated_rows": 50000},
        ]

    def list_foreign_keys(self) -> list[dict]:
        return [
            {
                "constraint_name": _FK1_CONSTRAINT,
                "database": _DB1,
                "from_schema": _SCHEMA1,
                "from_table": _TABLE_FROM,
                "from_columns": _FK1_FROM_COLS,
                "to_schema": _SCHEMA1,
                "to_table": _TABLE_TO,
                "to_columns": _FK1_TO_COLS,
            },
            {
                "constraint_name": _FK2_CONSTRAINT,
                "database": _DB1,
                "from_schema": _SCHEMA1,
                "from_table": _TABLE_FROM,
                "from_columns": _FK2_FROM_COLS,
                "to_schema": _SCHEMA1,
                "to_table": _TABLE_TO,
                "to_columns": _FK2_TO_COLS,
            },
        ]


def _make_two_fk_connector():
    from infra_twin.collectors.db import DbIntrospectionConnector
    return DbIntrospectionConnector(
        _TwoFkDbClient(), host=_HOST, port=_PORT, instance_name=_INSTANCE_NAME
    )


def test_e2e_two_fks_same_pair_two_depends_on_edges(pool, make_tenant):
    """§5.9 E2E / AC 18 (restored): two FK constraints between orders->users reconcile
    to exactly two distinct open DEPENDS_ON edges.

    Asserts:
    - exactly 2 open DEPENDS_ON edges between the orders and users db_table CIs
    - each has source='declared', confidence set, non-empty evidence
    - evidence on each names its own constraint (FK1_CONSTRAINT / FK2_CONSTRAINT)
    - each carries the correct edge_key equal to the constraint name
    - AGE: MATCH (:db_table)-[r:DEPENDS_ON]->(:db_table) WHERE r.tenant_id=... RETURN r
      returns exactly 2 distinct relationships
    """
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("eid-e2e-two-fk")
    discover_and_reconcile(pool, tenant, _make_two_fk_connector())

    # --- Postgres layer ---
    with tenant_session(pool, tenant) as conn:
        rows = conn.execute(
            "SELECT type, source, confidence, evidence, edge_key "
            "FROM edges WHERE valid_to IS NULL AND type = %s",
            ("DEPENDS_ON",),
        ).fetchall()

    depends_on = [
        {"type": r[0], "source": r[1], "confidence": r[2], "evidence": r[3], "edge_key": r[4]}
        for r in rows
    ]

    assert len(depends_on) == 2, (
        f"Two FK constraints must reconcile to exactly 2 open DEPENDS_ON edges; got {len(depends_on)}"
    )

    for row in depends_on:
        assert row["source"] == "declared", f"DEPENDS_ON source must be 'declared'; got {row['source']!r}"
        assert row["confidence"] is not None, "DEPENDS_ON confidence must be set"
        assert row["confidence"] > 0, f"DEPENDS_ON confidence must be > 0; got {row['confidence']}"
        assert row["evidence"], "DEPENDS_ON evidence must be non-empty"
        for ev in row["evidence"]:
            assert ev.get("detail"), f"Evidence entry must have non-empty detail; got {ev!r}"

    # Each edge names its own constraint in the evidence
    all_details = " ".join(
        ev.get("detail", "") for row in depends_on for ev in row["evidence"]
    )
    assert _FK1_CONSTRAINT in all_details, (
        f"{_FK1_CONSTRAINT!r} must appear in combined evidence details"
    )
    assert _FK2_CONSTRAINT in all_details, (
        f"{_FK2_CONSTRAINT!r} must appear in combined evidence details"
    )

    # Per-edge evidence: each edge's evidence names its own constraint
    fk1_edge = [
        row for row in depends_on
        if any(_FK1_CONSTRAINT in ev.get("detail", "") for ev in row["evidence"])
    ]
    fk2_edge = [
        row for row in depends_on
        if any(_FK2_CONSTRAINT in ev.get("detail", "") for ev in row["evidence"])
    ]
    assert len(fk1_edge) == 1, f"Exactly 1 edge must name {_FK1_CONSTRAINT!r}; got {len(fk1_edge)}"
    assert len(fk2_edge) == 1, f"Exactly 1 edge must name {_FK2_CONSTRAINT!r}; got {len(fk2_edge)}"

    # Distinct edge_key values equal to the constraint names
    edge_keys = {row["edge_key"] for row in depends_on}
    assert _FK1_CONSTRAINT in edge_keys, (
        f"edge_key for FK1 must be {_FK1_CONSTRAINT!r}; found edge_keys={edge_keys}"
    )
    assert _FK2_CONSTRAINT in edge_keys, (
        f"edge_key for FK2 must be {_FK2_CONSTRAINT!r}; found edge_keys={edge_keys}"
    )
    assert len(edge_keys) == 2, f"Two distinct edge_key values expected; got {edge_keys}"


def test_e2e_two_fks_age_projects_two_depends_on_relationships(pool, make_tenant):
    """§5.9 E2E AGE: MATCH (:db_table)-[r:DEPENDS_ON]->(:db_table) WHERE r.tenant_id=...
    returns exactly 2 distinct relationships in the AGE graph."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant = make_tenant("eid-e2e-age")
    discover_and_reconcile(pool, tenant, _make_two_fk_connector())

    with tenant_session(pool, tenant) as conn:
        rows = cypher(
            conn,
            f"MATCH (:db_table)-[r:DEPENDS_ON]->(:db_table) "
            f"WHERE r.tenant_id = '{tenant}' RETURN r",
        )

    assert len(rows) == 2, (
        f"AGE must project exactly 2 DEPENDS_ON relationships for two FKs; got {len(rows)}"
    )


def test_e2e_two_fks_adversarial_cross_tenant_isolation(pool, make_tenant):
    """§5 edge case 15 / §5.9 adversarial: parallel edges in tenant A are invisible to
    tenant B — both via Postgres RLS and AGE tenant_id filter."""
    from infra_twin.reconciliation import discover_and_reconcile

    tenant_a = make_tenant("eid-e2e-iso-a")
    tenant_b = make_tenant("eid-e2e-iso-b")

    discover_and_reconcile(pool, tenant_a, _make_two_fk_connector())

    # Postgres: tenant B sees zero DEPENDS_ON edges
    with tenant_session(pool, tenant_b) as conn:
        count = conn.execute(
            "SELECT count(*) FROM edges WHERE valid_to IS NULL AND type = %s",
            ("DEPENDS_ON",),
        ).fetchone()[0]
    assert count == 0, (
        f"Tenant B must see 0 DEPENDS_ON edges belonging to A; got {count}"
    )

    # AGE: same cypher query for tenant B returns zero relationships
    with tenant_session(pool, tenant_b) as conn:
        rows = cypher(
            conn,
            f"MATCH (:db_table)-[r:DEPENDS_ON]->(:db_table) "
            f"WHERE r.tenant_id = '{tenant_b}' RETURN r",
        )
    assert len(rows) == 0, (
        f"AGE must return 0 DEPENDS_ON for tenant B; got {len(rows)}"
    )


# ===========================================================================
# Test 8 (§8 migration ordering): 0001-0018 exist; 0019 is the highest
# ===========================================================================


def test_migration_0019_exists_and_is_highest():
    """AC 3+4 / §8 migration ordering: 0001-0019 exist unchanged; 0024 is now the highest
    migration (freshness_slo); 0019 body contains the idempotent guards and 5-column unique index."""
    migrations_dir = _DB_MIGRATIONS_DIR
    all_files = os.listdir(migrations_dir)

    # 0001 through 0024 all exist
    for n in range(1, 25):
        pattern = f"{n:04d}_"
        matches = [f for f in all_files if f.startswith(pattern)]
        assert matches, f"Migration {pattern}* not found in {migrations_dir}"

    # 0024 must exist (freshness_slo)
    assert any(f.startswith("0024") for f in all_files), (
        "Migration 0024_* must exist (freshness_slo)"
    )

    # 0025 must exist (history_retention)
    assert any(f.startswith("0025") for f in all_files), (
        "Migration 0025_* must exist (history_retention)"
    )

    # 0025 is now the highest — no 0026 or above
    higher = [
        f for f in all_files
        if len(f) >= 4 and f[:4].isdigit() and int(f[:4]) > 25
    ]
    assert not higher, f"Unexpected migration(s) higher than 0025 found: {higher}"

    # Content of 0019
    migration_0019 = os.path.join(migrations_dir, "0019_edge_key_identity.sql")
    assert os.path.isfile(migration_0019), f"0019_edge_key_identity.sql not found"
    content = open(migration_0019).read()

    assert "ADD COLUMN IF NOT EXISTS edge_key TEXT NOT NULL DEFAULT ''" in content, (
        "0019 must contain 'ADD COLUMN IF NOT EXISTS edge_key TEXT NOT NULL DEFAULT \'\''"
    )
    assert "DROP INDEX IF EXISTS edges_current_identity" in content, (
        "0019 must contain 'DROP INDEX IF EXISTS edges_current_identity'"
    )
    assert "edges_current_identity" in content and "edge_key" in content, (
        "0019 must define the 5-column unique index including edge_key"
    )
    assert "CREATE UNIQUE INDEX IF NOT EXISTS edges_current_identity" in content, (
        "0019 must use IF NOT EXISTS guard on index creation"
    )
    assert "(tenant_id, type, from_id, to_id, edge_key)" in content, (
        "0019 unique index must include all 5 columns: tenant_id, type, from_id, to_id, edge_key"
    )
    assert "WHERE valid_to IS NULL" in content, (
        "0019 unique index must be a partial index on WHERE valid_to IS NULL"
    )
    # Must not create tables or call AGE label functions (check non-comment lines only)
    non_comment_lines = [
        line for line in content.splitlines()
        if not line.strip().startswith("--")
    ]
    non_comment_body = "\n".join(non_comment_lines)
    assert "CREATE TABLE" not in non_comment_body, "0019 must not create tables"
    assert "create_vlabel" not in non_comment_body, "0019 must not call create_vlabel"
    assert "create_elabel" not in non_comment_body, "0019 must not call create_elabel"
