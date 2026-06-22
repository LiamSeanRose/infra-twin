"""E2E tests for the deterministic cross-source entity-resolution merge engine.

Exercises the real reconcile() path under tenant_session against the local Postgres + AGE
stack.  No mocking of the engine, the database, or AGE.

Six independent scenarios, each starting from a clean state (enforced by the autouse
_clean fixture in conftest.py that truncates all data tables before every test):

  Scenario 1 -- Cross-source fusion (happy path)
  Scenario 2 -- Backward compat (no alias_keys => no merge)
  Scenario 3 -- No over-merge on ambiguity (>=2 candidates)
  Scenario 4 -- Idempotent re-discovery (graph-level no-op after a merge)
  Scenario 5 -- Edge endpoint resolution across the merge
  Scenario 6 -- Adversarial cross-tenant isolation (RLS)
"""

from __future__ import annotations

from uuid import UUID

from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

ALIAS = "alias:shared-1"
EXT_A = "a-ext-1"
EXT_B = "b-ext-1"
CI_TYPE = CIType.s3_bucket
SOURCE_A = "srcA"
SOURCE_B = "srcB"

# Narrow scope: every reconcile() call is authoritative only for s3_bucket CIs
# and DEPENDS_ON edges, so it never closes facts it did not observe.
CI_SCOPE = frozenset({CIType.s3_bucket})
EDGE_SCOPE = frozenset({EdgeType.DEPENDS_ON})


def _ev() -> list[Evidence]:
    return [Evidence(source=SOURCE_A, detail="test")]


def _run(pool, tenant: UUID, events, *, source: str) -> object:
    """Run reconcile() under a tenant-scoped connection."""
    with tenant_session(pool, tenant) as conn:
        return reconcile(
            conn,
            tenant,
            events,
            source=source,
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )


# ===========================================================================
# Scenario 1 -- Cross-source fusion (happy path)
# ===========================================================================
#
# Two runs from different sources share one alias key.  The second run must
# merge into the canonical CI created by the first run.  Exactly one canonical
# CI survives; both source external_ids resolve to it; provenance rows are
# correct.


def test_scenario1_cross_source_fusion(pool, make_tenant):
    tenant = make_tenant("er-s1")

    # Run 1: source A emits EXT_A with ALIAS.
    _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[ALIAS])],
        source=SOURCE_A,
    )

    # Run 2: source B emits EXT_B with the same ALIAS -> must merge.
    r2 = _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[ALIAS])],
        source=SOURCE_B,
    )

    with tenant_session(pool, tenant) as conn:
        ci_repo = CIRepository(conn, tenant)

        # AC 6.1: exactly one current CI of CI_TYPE; its external_id is EXT_A (canonical).
        current = ci_repo.get_current(type=CI_TYPE)
        assert len(current) == 1, (
            f"Expected exactly 1 current CI after merge, got {len(current)}: "
            f"{[c.external_id for c in current]}"
        )
        canonical = current[0]
        assert canonical.external_id == EXT_A, (
            f"Canonical CI should have external_id={EXT_A!r}, got {canonical.external_id!r}"
        )

        # AC 6.2: both source native_ids resolve to the single canonical ci_id.
        sk_rows = conn.execute(
            "SELECT source, native_id, ci_id FROM source_keys ORDER BY source, native_id"
        ).fetchall()
        sk_by_native = {(r[0], r[1]): r[2] for r in sk_rows}
        assert (SOURCE_A, EXT_A) in sk_by_native, (
            f"source_keys missing (srcA, {EXT_A}); keys: {list(sk_by_native)}"
        )
        assert (SOURCE_B, EXT_B) in sk_by_native, (
            f"source_keys missing (srcB, {EXT_B}); keys: {list(sk_by_native)}"
        )
        assert sk_by_native[(SOURCE_A, EXT_A)] == canonical.id, (
            "srcA source_key ci_id does not match canonical CI id"
        )
        assert sk_by_native[(SOURCE_B, EXT_B)] == canonical.id, (
            "srcB source_key ci_id does not match canonical CI id"
        )

        # AC 6.3: ci_alias_keys has exactly one row for ALIAS; it points at canonical id.
        alias_rows = conn.execute(
            "SELECT alias_key, ci_id, ci_type FROM ci_alias_keys"
        ).fetchall()
        assert len(alias_rows) == 1, (
            f"Expected 1 ci_alias_keys row, got {len(alias_rows)}: {alias_rows}"
        )
        assert alias_rows[0][0] == ALIAS, f"alias_key should be {ALIAS!r}, got {alias_rows[0][0]!r}"
        assert alias_rows[0][1] == canonical.id, "ci_alias_keys.ci_id must equal canonical CI id"
        assert alias_rows[0][2] == CI_TYPE.value, (
            f"ci_alias_keys.ci_type should be {CI_TYPE.value!r}, got {alias_rows[0][2]!r}"
        )

        # AC 6.4: ci_merges has exactly one row; fields match spec.
        merge_rows = conn.execute(
            "SELECT canonical_ci_id, merged_source, merged_external_id, "
            "       matched_alias_key, evidence "
            "FROM ci_merges"
        ).fetchall()
        assert len(merge_rows) == 1, (
            f"Expected 1 ci_merges row, got {len(merge_rows)}: {merge_rows}"
        )
        m = merge_rows[0]
        assert m[0] == canonical.id, "ci_merges.canonical_ci_id must equal canonical CI id"
        assert m[1] == SOURCE_B, f"ci_merges.merged_source must be {SOURCE_B!r}, got {m[1]!r}"
        assert m[2] == EXT_B, f"ci_merges.merged_external_id must be {EXT_B!r}, got {m[2]!r}"
        assert m[3] == ALIAS, f"ci_merges.matched_alias_key must be {ALIAS!r}, got {m[3]!r}"
        assert m[4], "ci_merges.evidence must be non-empty"
        assert "via alias_key=alias:shared-1" in m[4], (
            f"evidence must contain 'via alias_key=alias:shared-1'; got {m[4]!r}"
        )

    # AC 6.5: run 2 did not create a new CI (it merged).
    assert r2.cis_created == 0, (
        f"Run 2 cis_created must be 0 (merge, not create); got {r2.cis_created}"
    )


# ===========================================================================
# Scenario 2 -- Backward compat (no alias_keys => no merge)
# ===========================================================================
#
# When neither source supplies alias_keys, the two CIs remain disjoint.
# No ci_alias_keys or ci_merges rows are written.


def test_scenario2_no_alias_keys_no_merge(pool, make_tenant):
    tenant = make_tenant("er-s2")

    _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[])],
        source=SOURCE_A,
    )
    r2 = _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[])],
        source=SOURCE_B,
    )

    with tenant_session(pool, tenant) as conn:
        ci_repo = CIRepository(conn, tenant)

        # AC 7.1: exactly two disjoint current CIs with distinct external_ids.
        current = ci_repo.get_current(type=CI_TYPE)
        assert len(current) == 2, (
            f"Expected 2 current CIs when no alias_keys, got {len(current)}"
        )
        ext_ids = {c.external_id for c in current}
        assert ext_ids == {EXT_A, EXT_B}, f"Expected {{EXT_A, EXT_B}}, got {ext_ids}"
        ids = {c.id for c in current}
        assert len(ids) == 2, "Two CIs must have distinct ids"

        # AC 7.2: no ci_alias_keys rows.
        alias_count = conn.execute("SELECT count(*) FROM ci_alias_keys").fetchone()[0]
        assert alias_count == 0, f"Expected 0 ci_alias_keys rows, got {alias_count}"

        # AC 7.3: no ci_merges rows.
        merge_count = conn.execute("SELECT count(*) FROM ci_merges").fetchone()[0]
        assert merge_count == 0, f"Expected 0 ci_merges rows, got {merge_count}"

    # AC 7.4: run 2 created a new CI (not a merge).
    assert r2.cis_created == 1, (
        f"Run 2 cis_created must be 1 (no alias -> new CI); got {r2.cis_created}"
    )


# ===========================================================================
# Scenario 3 -- No over-merge on ambiguity (alias resolves to >=2 ci_ids)
# ===========================================================================
#
# Exercises the len(candidates) != 1 -> no merge branch.
#
# Construction: run A produces two canonical CIs bound to alias keys "k1" and
# "k2" respectively.  The incoming SOURCE_B CI carries BOTH "k1" and "k2",
# making the lookup return 2 distinct ci_ids (ambiguous).  The engine must
# NOT merge; it creates a brand-new third CI.


def test_scenario3_no_over_merge_on_ambiguity(pool, make_tenant):
    # This test exercises the len(candidates) != 1 -> no merge branch.
    tenant = make_tenant("er-s3")

    # Run A: two CIs bound to distinct alias keys.
    _run(
        pool,
        tenant,
        [
            DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=["k1"]),
            DiscoveredCI(type=CI_TYPE, external_id="a-ext-2", alias_keys=["k2"]),
        ],
        source=SOURCE_A,
    )

    # Run B: one CI that matches BOTH k1 and k2 -> len(candidates)==2 -> ambiguous.
    r_b = _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=["k1", "k2"])],
        source=SOURCE_B,
    )

    with tenant_session(pool, tenant) as conn:
        ci_repo = CIRepository(conn, tenant)

        # AC 8.1: three current CIs (EXT_A, a-ext-2, EXT_B). Ambiguous run did not merge.
        current = ci_repo.get_current(type=CI_TYPE)
        assert len(current) == 3, (
            f"Expected 3 current CIs after ambiguous run, got {len(current)}: "
            f"{[c.external_id for c in current]}"
        )
        ext_ids = {c.external_id for c in current}
        assert EXT_A in ext_ids, f"EXT_A missing from current CIs: {ext_ids}"
        assert "a-ext-2" in ext_ids, f"a-ext-2 missing from current CIs: {ext_ids}"
        assert EXT_B in ext_ids, f"EXT_B missing from current CIs: {ext_ids}"

        # AC 8.2: no ci_merges rows (ambiguous run must not write a merge row).
        merge_count = conn.execute("SELECT count(*) FROM ci_merges").fetchone()[0]
        assert merge_count == 0, (
            f"Expected 0 ci_merges rows after ambiguous run, got {merge_count}"
        )

    # AC 8.3: the ambiguous SOURCE_B run created a new CI.
    assert r_b.cis_created == 1, (
        f"Ambiguous run cis_created must be 1, got {r_b.cis_created}"
    )


# ===========================================================================
# Scenario 4 -- Idempotent re-discovery (no-op after a merge)
# ===========================================================================
#
# After reaching the merged state, re-running both emissions must not:
#   - create a new CI
#   - add a new bitemporal version to the canonical CI
#   - add a new ci_alias_keys row
#
# PROVENANCE NOTE (append-only): ci_merges is append-only.  SOURCE_B's
# external_id (EXT_B) never has a native cis row (the canonical row's
# external_id is EXT_A).  Therefore the re-run of SOURCE_B takes the merge
# branch AGAIN and appends a second ci_merges row.  This is expected
# behaviour, not a defect.  Assert count(ci_merges) == 2 after the idempotent
# re-run.  Graph-level idempotency is still preserved: no new cis version, no
# new ci_alias_keys row.
#
# IMPORTANT: DiscoveredCI objects omit name= so CIRepository.upsert does not
# see an attribute change and does not create a new bitemporal version.


def test_scenario4_idempotent_rediscovery(pool, make_tenant):
    tenant = make_tenant("er-s4")

    # Reach the merged state (Scenario 1 setup).
    _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[ALIAS])],
        source=SOURCE_A,
    )
    _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[ALIAS])],
        source=SOURCE_B,
    )

    # Capture pre-rerun state.
    with tenant_session(pool, tenant) as conn:
        ci_repo = CIRepository(conn, tenant)
        pre_current = ci_repo.get_current(type=CI_TYPE)
        assert len(pre_current) == 1, "Precondition: exactly 1 CI before re-run"
        canonical_id = pre_current[0].id
        pre_valid_from = pre_current[0].valid_from
        pre_valid_to = pre_current[0].valid_to
        pre_history_len = len(ci_repo.history(canonical_id))
        pre_alias_count = conn.execute("SELECT count(*) FROM ci_alias_keys").fetchone()[0]

    # Re-run both sources.  Attributes are kept identical (no name) so upsert
    # does not version the CI.
    r1_prime = _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[ALIAS])],
        source=SOURCE_A,
    )
    r2_prime = _run(
        pool,
        tenant,
        [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[ALIAS])],
        source=SOURCE_B,
    )

    with tenant_session(pool, tenant) as conn:
        ci_repo = CIRepository(conn, tenant)

        # AC 9.1: still exactly one current CI with the same id.
        post_current = ci_repo.get_current(type=CI_TYPE)
        assert len(post_current) == 1, (
            f"Expected 1 current CI after re-run, got {len(post_current)}"
        )
        assert post_current[0].id == canonical_id, (
            "Canonical CI id must be unchanged after re-run"
        )

        # AC 9.2: no extra bitemporal version; the open row's valid_from is unchanged
        # and valid_to is still NULL (never hard-deleted).
        post_history = ci_repo.history(canonical_id)
        assert len(post_history) == pre_history_len, (
            f"history() length should be {pre_history_len} after idempotent re-run, "
            f"got {len(post_history)}"
        )
        open_count = conn.execute(
            "SELECT count(*) FROM cis WHERE id = %s AND valid_to IS NULL",
            (canonical_id,),
        ).fetchone()[0]
        assert open_count == 1, (
            f"Exactly 1 open (valid_to IS NULL) cis row expected, got {open_count}"
        )
        assert post_current[0].valid_from == pre_valid_from, (
            "valid_from of canonical CI must be unchanged after idempotent re-run"
        )
        assert post_current[0].valid_to is None, (
            "valid_to of canonical CI must remain NULL (no hard-delete)"
        )

        # AC 9.3: ci_alias_keys count is unchanged (ON CONFLICT DO UPDATE only
        # refreshes observed_at; it never inserts a duplicate row).
        post_alias_count = conn.execute("SELECT count(*) FROM ci_alias_keys").fetchone()[0]
        assert post_alias_count == pre_alias_count, (
            f"ci_alias_keys count should be {pre_alias_count} after re-run, got {post_alias_count}"
        )

        # AC 9.5 (PROVENANCE NOTE): ci_merges is append-only.  SOURCE_B's EXT_B has no
        # native cis row, so the re-run of SOURCE_B takes the merge branch again and
        # appends a second ci_merges row.  This is expected; the graph-level identifiers
        # (cis row, ci_alias_keys) remain unchanged, so idempotency is preserved for the
        # graph.  Asserting count == 2 documents the append-only design.
        merge_count = conn.execute("SELECT count(*) FROM ci_merges").fetchone()[0]
        assert merge_count == 2, (
            f"ci_merges count should be 2 after idempotent re-run (append-only provenance); "
            f"got {merge_count}"
        )

    # AC 9.4: re-run ReconcileResult shows no new creations or closures.
    assert r1_prime.cis_created == 0, (
        f"Re-run1 cis_created must be 0 (idempotent), got {r1_prime.cis_created}"
    )
    assert r1_prime.cis_closed == 0, (
        f"Re-run1 cis_closed must be 0, got {r1_prime.cis_closed}"
    )
    assert r2_prime.cis_created == 0, (
        f"Re-run2 cis_created must be 0 (idempotent merge), got {r2_prime.cis_created}"
    )
    assert r2_prime.cis_closed == 0, (
        f"Re-run2 cis_closed must be 0, got {r2_prime.cis_closed}"
    )


# ===========================================================================
# Scenario 5 -- Edge endpoint resolution across the merge
# ===========================================================================
#
# Edges whose from_ref carries the merged-away EXT_B identity must resolve to
# the canonical CI id.  Also confirms the source_keys fallback (_resolve) works
# for an edge-only batch referencing EXT_B after the merge is committed.


def test_scenario5_edge_endpoint_resolution_across_merge(pool, make_tenant):
    tenant = make_tenant("er-s5")
    EXT_T = "t-ext"

    # Run 1 (SOURCE_A): canonical CI EXT_A with alias, target CI, and an edge.
    _run(
        pool,
        tenant,
        [
            DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[ALIAS]),
            DiscoveredCI(type=CI_TYPE, external_id=EXT_T),
            DiscoveredEdge(
                type=EdgeType.DEPENDS_ON,
                from_ref=CIRef(type=CI_TYPE, external_id=EXT_A),
                to_ref=CIRef(type=CI_TYPE, external_id=EXT_T),
                evidence=_ev(),
            ),
        ],
        source=SOURCE_A,
    )

    # Run 2 (SOURCE_B): merging CI EXT_B with alias, target (re-emitted to stay in scope),
    # and an edge from the merged-away EXT_B identity.
    _run(
        pool,
        tenant,
        [
            DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[ALIAS]),
            DiscoveredCI(type=CI_TYPE, external_id=EXT_T),
            DiscoveredEdge(
                type=EdgeType.DEPENDS_ON,
                from_ref=CIRef(type=CI_TYPE, external_id=EXT_B),
                to_ref=CIRef(type=CI_TYPE, external_id=EXT_T),
                evidence=_ev(),
            ),
        ],
        source=SOURCE_B,
    )

    with tenant_session(pool, tenant) as conn:
        ci_repo = CIRepository(conn, tenant)
        edge_repo = EdgeRepository(conn, tenant)

        # Determine canonical CI id (EXT_A).
        canonical_cis = ci_repo.get_current(type=CI_TYPE, external_id=EXT_A)
        assert canonical_cis, f"Canonical CI {EXT_A!r} not found"
        canonical_id = canonical_cis[0].id

        # AC 10.1: every current DEPENDS_ON edge's from_id equals the canonical CI id.
        all_edges = edge_repo.get_current()
        depends_on_edges = [e for e in all_edges if e.type == EdgeType.DEPENDS_ON]
        assert depends_on_edges, "No DEPENDS_ON edges found after both runs"
        for edge in depends_on_edges:
            assert edge.from_id == canonical_id, (
                f"DEPENDS_ON edge from_id {edge.from_id} != canonical_id {canonical_id}; "
                "merged-away EXT_B from_ref must resolve to the canonical CI"
            )

        # AC 10.3: canonical CI is NOT wrongly closed.
        canonical_ci = ci_repo.get_current_by_id(canonical_id)
        assert canonical_ci is not None, (
            f"Canonical CI {canonical_id} was wrongly closed (get_current_by_id returned None)"
        )
        assert canonical_ci.valid_to is None, (
            f"Canonical CI valid_to must be NULL (still open), got {canonical_ci.valid_to}"
        )

    # AC 10.2: edge-only batch referencing the merged-away EXT_B resolves via source_keys.
    # We emit ONLY a DiscoveredEdge (no CIs in the batch); the _resolve fallback must find
    # EXT_B in source_keys and return the canonical CI id.
    # ci_types=frozenset() so the CI sweep is a no-op (no CIs to close) and the canonical
    # CI is not inadvertently retired by an edge-only emission from SOURCE_A.
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [
                DiscoveredEdge(
                    type=EdgeType.DEPENDS_ON,
                    from_ref=CIRef(type=CI_TYPE, external_id=EXT_B),
                    to_ref=CIRef(type=CI_TYPE, external_id=EXT_T),
                    evidence=_ev(),
                )
            ],
            source=SOURCE_A,
            ci_types=frozenset(),
            edge_types=EDGE_SCOPE,
        )

    with tenant_session(pool, tenant) as conn:
        ci_repo = CIRepository(conn, tenant)
        edge_repo = EdgeRepository(conn, tenant)

        canonical_id_check = ci_repo.get_current(type=CI_TYPE, external_id=EXT_A)[0].id

        all_edges = edge_repo.get_current()
        dep_edges = [e for e in all_edges if e.type == EdgeType.DEPENDS_ON]
        assert dep_edges, "DEPENDS_ON edges must still exist after edge-only batch"
        for edge in dep_edges:
            assert edge.from_id == canonical_id_check, (
                f"After edge-only batch, from_id {edge.from_id} must equal canonical_id "
                f"{canonical_id_check} (source_keys fallback must resolve EXT_B)"
            )

        # Confirm canonical CI is still open after the edge-only run.
        canonical_after = ci_repo.get_current_by_id(canonical_id_check)
        assert canonical_after is not None, "Canonical CI was wrongly closed after edge-only run"
        assert canonical_after.valid_to is None, (
            "Canonical CI valid_to must be NULL after edge-only run"
        )


# ===========================================================================
# Scenario 6 -- Adversarial cross-tenant isolation (RLS)
# ===========================================================================
#
# Merge under tenant A; then verify tenant B sees none of A's merge data.
# A further merge under tenant B must produce a distinct canonical CI id and
# must not reference tenant A's canonical CI in any way.


def test_scenario6_adversarial_cross_tenant_isolation(pool, make_tenant):
    tenant_a = make_tenant("er-iso-a")
    tenant_b = make_tenant("er-iso-b")

    # Merge under tenant A.
    with tenant_session(pool, tenant_a) as conn:
        reconcile(
            conn,
            tenant_a,
            [DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[ALIAS])],
            source=SOURCE_A,
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )
    with tenant_session(pool, tenant_a) as conn:
        reconcile(
            conn,
            tenant_a,
            [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[ALIAS])],
            source=SOURCE_B,
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )

    # Capture tenant A's canonical CI id.
    with tenant_session(pool, tenant_a) as conn:
        a_ci_repo = CIRepository(conn, tenant_a)
        a_cis = a_ci_repo.get_current(type=CI_TYPE)
        assert len(a_cis) == 1, f"Precondition: tenant A should have 1 CI, got {len(a_cis)}"
        a_canonical_id = a_cis[0].id

    # AC 11.1-11.3: under tenant B's session, A's data is invisible (RLS).
    with tenant_session(pool, tenant_b) as conn:
        b_ci_repo = CIRepository(conn, tenant_b)

        alias_count_b = conn.execute("SELECT count(*) FROM ci_alias_keys").fetchone()[0]
        assert alias_count_b == 0, (
            f"Tenant B must see 0 ci_alias_keys rows (RLS hides A's); got {alias_count_b}"
        )

        merge_count_b = conn.execute("SELECT count(*) FROM ci_merges").fetchone()[0]
        assert merge_count_b == 0, (
            f"Tenant B must see 0 ci_merges rows (RLS hides A's); got {merge_count_b}"
        )

        b_cis = b_ci_repo.get_current(type=CI_TYPE)
        assert b_cis == [], (
            f"Tenant B must see no CIs from tenant A; got {b_cis}"
        )

    # Now run the same alias collision under tenant B.
    with tenant_session(pool, tenant_b) as conn:
        reconcile(
            conn,
            tenant_b,
            [DiscoveredCI(type=CI_TYPE, external_id=EXT_A, alias_keys=[ALIAS])],
            source=SOURCE_A,
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )
    with tenant_session(pool, tenant_b) as conn:
        reconcile(
            conn,
            tenant_b,
            [DiscoveredCI(type=CI_TYPE, external_id=EXT_B, alias_keys=[ALIAS])],
            source=SOURCE_B,
            ci_types=CI_SCOPE,
            edge_types=EDGE_SCOPE,
        )

    # AC 11.4: B's canonical CI has a different id from A's.
    with tenant_session(pool, tenant_b) as conn:
        b_ci_repo = CIRepository(conn, tenant_b)

        b_cis_after = b_ci_repo.get_current(type=CI_TYPE)
        assert len(b_cis_after) == 1, (
            f"Tenant B should have exactly 1 canonical CI after merge, got {len(b_cis_after)}"
        )
        b_canonical_id = b_cis_after[0].id
        assert b_canonical_id != a_canonical_id, (
            f"Tenant B's canonical CI id {b_canonical_id} must differ from "
            f"tenant A's {a_canonical_id} (no cross-tenant merge)"
        )

        # AC 11.5: B's ci_merges and ci_alias_keys reference only B's canonical CI, never A's.
        b_merge_rows = conn.execute(
            "SELECT canonical_ci_id FROM ci_merges"
        ).fetchall()
        assert len(b_merge_rows) == 1, (
            f"Tenant B should have 1 ci_merges row, got {len(b_merge_rows)}"
        )
        assert b_merge_rows[0][0] == b_canonical_id, (
            f"Tenant B's ci_merges.canonical_ci_id must be B's canonical CI id {b_canonical_id}, "
            f"got {b_merge_rows[0][0]}"
        )
        assert b_merge_rows[0][0] != a_canonical_id, (
            "Tenant B's ci_merges must not reference tenant A's canonical CI id"
        )

        b_alias_rows = conn.execute(
            "SELECT ci_id FROM ci_alias_keys"
        ).fetchall()
        assert len(b_alias_rows) == 1, (
            f"Tenant B should have 1 ci_alias_keys row, got {len(b_alias_rows)}"
        )
        assert b_alias_rows[0][0] == b_canonical_id, (
            f"Tenant B's ci_alias_keys.ci_id must be B's canonical CI id {b_canonical_id}, "
            f"got {b_alias_rows[0][0]}"
        )
        assert b_alias_rows[0][0] != a_canonical_id, (
            "Tenant B's ci_alias_keys.ci_id must not reference tenant A's canonical CI id"
        )
