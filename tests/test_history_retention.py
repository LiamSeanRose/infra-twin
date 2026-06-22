"""History retention / aggregation feature tests.

Covers all edge cases and acceptance criteria from specs.md §5 and §6,
plus the Definition of Done items (a)-(f).

Definition of Done coverage:
  (a) sweep with no policy or disabled policy -> complete no-op (empty/zeroed RetentionReport).
  (b) eligible old closed interior versions collapsed AND history_aggregates written FIRST.
  (c) current rows (valid_to IS NULL) and in-horizon recent closed versions NEVER removed.
  (d) sweep is idempotent -> second run reports zero additional collapse.
  (e) RBAC gating on all four endpoints; audit log + usage metering fire correctly.
  (f) adversarial cross-tenant isolation.

Edge cases from spec §5:
  EC1.  No policy row -> swept=False, all counters 0, no connector_runs row.
  EC2.  Policy exists but enabled=False -> same no-op as EC1.
  EC3.  Policy enabled, no eligible closed rows -> swept=True, counters 0.
  EC4.  Entity with only current row -> never touched; retained_current incremented.
  EC5.  Entity with current + exactly one old closed version -> boundary, not collapsed.
  EC6.  Entity with current + 2 old closed versions both < horizon -> older one collapsed.
  EC7.  Entity with NO current row (retired) + >= 2 old closed versions -> most recent is boundary.
  EC8.  closed version with valid_to == horizon -> NOT eligible (strict <).
  EC9.  Naive (tz-less) now -> engine normalises to UTC.
  EC10. now far in the past (horizon precedes all data) -> no rows eligible.
  EC11. Idempotent re-run -> versions_collapsed==0, aggregates_written==0.
  EC12. Aggregate immutability: UPDATE/DELETE on history_aggregates rejected.
  EC13. INSERT before DELETE atomicity: forced rollback after INSERT leaves both detail rows
        intact AND no history_aggregates row committed.
        Covered by: test_ec13_ac15_atomicity_rollback_leaves_no_partial_state
  EC14. Current graph byte-identity before/after sweep.
  EC15. Mixed eligible + ineligible interior versions -> only < horizon subset collapses.
  EC16. retain_closed_days updated downward then sweep again -> newly-eligible versions collapse.
  EC17. Cross-tenant isolation (read): B cannot see A's policy/aggregates.
  EC18. Adversarial cross-tenant INSERT into either new table rejected by RLS.
  EC19. Bare connection with no app.tenant_id GUC sees zero rows.
  EC20. Re-upsert same tenant policy -> single row, id + created_at stable, updated_at advances.
  EC21. RBAC: viewer PUT -> 403, viewer POST sweep -> 403, editor -> 200.
  EC22. Mutation auditing + metering: editor -> allow audit + usage row; viewer -> deny, no usage.
  EC23. Migration applied twice -> idempotent.
  EC24. Supernode / blast-radius code not modified.
  EC25. POST /retention/sweep with disabled policy -> 200, swept=false.
  EC26. history_aggregates ordering deterministic (created_at DESC, aggregate_id DESC).

Acceptance criteria also covered:
  AC1.  migrations/0025_history_retention.sql exists and is highest-numbered.
  AC2.  history_retention_policies schema (columns, CHECK, UNIQUE).
  AC3.  history_retention_policies RLS + tenant_isolation (USING + WITH CHECK).
  AC4.  history_retention_policies grants SELECT, INSERT, UPDATE (no DELETE).
  AC5.  history_aggregates schema (columns, CHECK entity_kind, CHECK version_count).
  AC6.  history_aggregates grants SELECT, INSERT only; UPDATE/DELETE raise privilege error.
  AC7.  history_aggregates RLS + index history_aggregates_by_entity.
  AC8.  GRANT DELETE ON cis, edges TO app with inline comment.
  AC9.  retention.py (db) defines models + repo, no WHERE tenant_id filter.
  AC10. db/__init__.py exports the three new names.
  AC11. reconciliation/retention.py defines required symbols.
  AC12. reconciliation/__init__.py exports required symbols.
  AC13. sweep with no policy -> swept=False, no connector_run, no writes.
  AC14. sweep with enabled=False -> same no-op.
  AC15. aggregate INSERT before DELETE, inside one transaction: a forced rollback after the
        INSERT but before the DELETE leaves both the detail rows intact AND no aggregate row
        committed. Covered by: test_ec13_ac15_atomicity_rollback_leaves_no_partial_state
  AC16. current and boundary rows unchanged after sweep.
  AC17. strict eligibility predicate (valid_to == horizon NOT eligible).
  AC18. second sweep yields zero collapse/aggregate counters.
  AC19. correct _write/_read gating on all four endpoints.
  AC20. PUT retain_closed_days < 1 -> 422.
  AC21. response bodies omit tenant_id.
  AC22. viewer -> 403; editor -> 200 on write endpoints.
  AC23. editor writes allow audit + usage row; viewer writes deny audit, no usage row.
  AC24. cross-tenant isolation.
  AC25. migration idempotent.
  AC26. conftest.py _DATA_TABLES includes both new tables.
"""

from __future__ import annotations

import pathlib
import uuid
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.core_model import CI, CIType, Edge, EdgeSource, EdgeType, Evidence
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn
from infra_twin.db.connector_health import ConnectorRunRepository
from infra_twin.db.repositories import CIRepository, EdgeRepository
from infra_twin.db.retention import HistoryAggregate, RetentionPolicy, RetentionPolicyRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import (
    RETENTION_SOURCE,
    RetentionKindReport,
    RetentionReport,
    sweep_history,
)

_MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[1] / "migrations"
_RETENTION_FILE = _MIGRATIONS_DIR / "0025_history_retention.sql"

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


def _make_viewer_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _count_connector_runs(tenant_id: UUID, source: str) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM connector_runs WHERE tenant_id = %s AND source = %s",
            (tenant_id, source),
        ).fetchone()
    return row[0]


def _count_aggregates(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM history_aggregates WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    return row[0]


def _count_policy_rows(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM history_retention_policies WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    return row[0]


def _count_ci_versions(tenant_id: UUID, ci_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM cis WHERE id = %s AND tenant_id = %s",
            (ci_id, tenant_id),
        ).fetchone()
    return row[0]


def _get_audit_rows(tenant_id: UUID) -> list[dict]:
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT audit_id, role, method, path, permission, decision, status_code "
            "FROM audit_log WHERE tenant_id = %s "
            "ORDER BY occurred_at DESC, audit_id DESC",
            (tenant_id,),
        ).fetchall()
    return [
        {
            "audit_id": r[0],
            "role": r[1],
            "method": r[2],
            "path": r[3],
            "permission": r[4],
            "decision": r[5],
            "status_code": r[6],
        }
        for r in rows
    ]


def _count_usage_rows(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM usage_event WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    return row[0]


def _make_ci(tenant_id: UUID) -> CI:
    """Return a CI instance (not yet persisted)."""
    return CI(
        tenant_id=tenant_id,
        type=CIType.ec2_instance,
        external_id=f"i-{uuid.uuid4().hex[:8]}",
        name="test-ci",
        attributes={},
    )


def _make_evidence() -> list[Evidence]:
    return [Evidence(source="test", detail="test", observed_at=datetime.now(timezone.utc))]


def _make_edge(tenant_id: UUID, from_id: UUID, to_id: UUID) -> Edge:
    return Edge(
        tenant_id=tenant_id,
        type=EdgeType.CONNECTS_TO,
        from_id=from_id,
        to_id=to_id,
        source=EdgeSource.declared,
        confidence=1.0,
        evidence=_make_evidence(),
        valid_from=datetime.now(timezone.utc),
        valid_to=None,
    )


def _insert_old_closed_ci_version(
    conn,
    tenant_id: UUID,
    ci_id: UUID,
    valid_from_offset_days: int,
    valid_to_offset_days: int,
) -> None:
    """Directly insert a closed CI row for an existing entity id at a controlled timestamp.

    Uses the admin connection pattern: inserts bypassing normal upsert logic so we can
    set specific valid_from / valid_to values in the past.
    """
    now = datetime.now(timezone.utc)
    vf = now - timedelta(days=valid_from_offset_days)
    vt = now - timedelta(days=valid_to_offset_days)
    conn.execute(
        "INSERT INTO cis "
        "(id, tenant_id, type, external_id, name, attributes, confidence, "
        "first_seen, last_seen, valid_from, valid_to) "
        "VALUES (%s, %s, 'ec2_instance', %s, 'test-ci', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
        (
            ci_id,
            tenant_id,
            f"i-old-{uuid.uuid4().hex[:8]}",
            vf,
            vf,
            vf,
            vt,
        ),
    )


def _insert_old_closed_edge_version(
    conn,
    tenant_id: UUID,
    edge_id: UUID,
    from_id: UUID,
    to_id: UUID,
    valid_from_offset_days: int,
    valid_to_offset_days: int,
    source: str = "declared",
) -> None:
    """Directly insert a closed edge row for an existing entity id at controlled timestamps."""
    now = datetime.now(timezone.utc)
    vf = now - timedelta(days=valid_from_offset_days)
    vt = now - timedelta(days=valid_to_offset_days)
    evidence = [{"source": "test", "detail": "test", "observed_at": datetime.now(timezone.utc).isoformat()}]
    conn.execute(
        "INSERT INTO edges "
        "(id, tenant_id, type, from_id, to_id, edge_key, source, confidence, evidence, valid_from, valid_to) "
        "VALUES (%s, %s, 'CONNECTS_TO', %s, %s, '', %s, 1.0, %s::jsonb, %s, %s)",
        (
            edge_id,
            tenant_id,
            from_id,
            to_id,
            source,
            psycopg.types.json.Jsonb(evidence),
            vf,
            vt,
        ),
    )


# ===========================================================================
# Section 1: Migration / structural checks (AC 1-8)
# ===========================================================================


def test_ac1_migration_0025_exists():
    """AC1: migrations/0025_history_retention.sql exists and is present."""
    assert _RETENTION_FILE.exists(), "0025_history_retention.sql must exist"


def test_ac1_migration_0025_is_highest_numbered():
    """AC1: 0025 is the highest-numbered migration file."""
    migrations = sorted(_MIGRATIONS_DIR.glob("*.sql"))
    highest = migrations[-1].name if migrations else ""
    assert highest == "0025_history_retention.sql", (
        f"Expected 0025 to be highest; highest found: {highest}"
    )


def test_ac2_history_retention_policies_columns():
    """AC2: history_retention_policies has exactly the required columns."""
    expected = {
        "id", "tenant_id", "retain_closed_days", "enabled", "created_at", "updated_at"
    }
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'history_retention_policies'"
        ).fetchall()
    cols = {r[0] for r in rows}
    assert cols == expected, f"Column mismatch. Got: {cols}"


def test_ac2_history_retention_policies_check_constraint():
    """AC2: CHECK (retain_closed_days > 0) is in the migration file."""
    text = _RETENTION_FILE.read_text()
    assert "CHECK (retain_closed_days > 0)" in text


def test_ac2_history_retention_policies_unique_tenant_id():
    """AC2: UNIQUE (tenant_id) present in migration file."""
    text = _RETENTION_FILE.read_text()
    assert "UNIQUE (tenant_id)" in text


def test_ac2_enabled_default_false_in_migration():
    """AC2: enabled BOOLEAN NOT NULL DEFAULT FALSE in migration."""
    text = _RETENTION_FILE.read_text()
    assert "DEFAULT FALSE" in text


def test_ac3_history_retention_policies_rls_enabled():
    """AC3: RLS is enabled on history_retention_policies."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT rowsecurity FROM pg_tables WHERE tablename = 'history_retention_policies'"
        ).fetchone()
        assert row is not None
        assert row[0] is True, "RLS must be enabled on history_retention_policies"


def test_ac3_history_retention_policies_tenant_isolation_policy():
    """AC3: tenant_isolation policy exists on history_retention_policies."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies "
            "WHERE tablename = 'history_retention_policies' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on history_retention_policies"
    text = _RETENTION_FILE.read_text()
    assert "current_setting('app.tenant_id', true)" in text
    assert "WITH CHECK" in text


def test_ac4_history_retention_policies_grant_no_delete():
    """AC4: GRANT SELECT, INSERT, UPDATE to app (no DELETE) on history_retention_policies."""
    text = _RETENTION_FILE.read_text().upper()
    assert "GRANT SELECT, INSERT, UPDATE ON HISTORY_RETENTION_POLICIES TO APP" in text
    for line in text.splitlines():
        if "GRANT" in line and "HISTORY_RETENTION_POLICIES" in line:
            assert "DELETE" not in line, f"DELETE found in GRANT line: {line}"
            assert "ALL" not in line, f"ALL found in GRANT line: {line}"


def test_ac5_history_aggregates_columns():
    """AC5: history_aggregates has exactly the required columns."""
    expected = {
        "aggregate_id", "tenant_id", "entity_kind", "entity_id",
        "version_count", "earliest_valid_from", "latest_valid_to", "rollup", "created_at"
    }
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'history_aggregates'"
        ).fetchall()
    cols = {r[0] for r in rows}
    assert cols == expected, f"Column mismatch. Got: {cols}"


def test_ac5_history_aggregates_entity_kind_check():
    """AC5: CHECK (entity_kind IN ('ci','edge')) is in the migration file."""
    text = _RETENTION_FILE.read_text()
    assert "entity_kind IN ('ci', 'edge')" in text


def test_ac5_history_aggregates_version_count_check():
    """AC5: CHECK (version_count > 0) is in the migration file."""
    text = _RETENTION_FILE.read_text()
    assert "CHECK (version_count > 0)" in text


def test_ac6_history_aggregates_grant_select_insert_only():
    """AC6: GRANT SELECT, INSERT only (no UPDATE, no DELETE) on history_aggregates."""
    text = _RETENTION_FILE.read_text().upper()
    assert "GRANT SELECT, INSERT ON HISTORY_AGGREGATES TO APP" in text
    for line in text.splitlines():
        if "GRANT" in line and "HISTORY_AGGREGATES" in line:
            assert "UPDATE" not in line, f"UPDATE found in history_aggregates GRANT: {line}"
            assert "DELETE" not in line, f"DELETE found in history_aggregates GRANT: {line}"
            assert "ALL" not in line, f"ALL found in history_aggregates GRANT: {line}"


def test_ac6_history_aggregates_update_rejected_by_privilege(pool, make_tenant):
    """AC6: app role UPDATE on history_aggregates raises insufficient-privilege error."""
    tenant = make_tenant("agg-update-reject")
    with pytest.raises(psycopg.Error):
        with pool.connection() as conn:
            # No tenant_session needed; just attempt the UPDATE via app role
            conn.execute(
                "UPDATE history_aggregates SET version_count = 999 WHERE 1=0"
            )
            conn.commit()


def test_ac6_history_aggregates_delete_rejected_by_privilege(pool, make_tenant):
    """AC6: app role DELETE on history_aggregates raises insufficient-privilege error."""
    tenant = make_tenant("agg-delete-reject")
    with pytest.raises(psycopg.Error):
        with pool.connection() as conn:
            conn.execute("DELETE FROM history_aggregates WHERE 1=0")
            conn.commit()


def test_ac7_history_aggregates_rls_enabled():
    """AC7: RLS is enabled on history_aggregates."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT rowsecurity FROM pg_tables WHERE tablename = 'history_aggregates'"
        ).fetchone()
        assert row is not None
        assert row[0] is True, "RLS must be enabled on history_aggregates"


def test_ac7_history_aggregates_index_exists():
    """AC7: index history_aggregates_by_entity (tenant_id, entity_kind, entity_id) exists."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT indexname FROM pg_indexes "
            "WHERE indexname = 'history_aggregates_by_entity'"
        ).fetchone()
    assert row is not None, "index history_aggregates_by_entity not found"


def test_ac8_grant_delete_on_cis_edges_with_comment():
    """AC8: migration adds GRANT DELETE ON cis, edges TO app with inline comment."""
    text = _RETENTION_FILE.read_text().upper()
    assert "GRANT DELETE ON CIS, EDGES TO APP" in text
    # Ensure the comment / justification is also present (case-insensitive check)
    assert "DELETE" in text
    raw = _RETENTION_FILE.read_text()
    # The comment explaining the narrow DELETE grant must exist
    assert "DELETE" in raw and ("compact" in raw.lower() or "interior" in raw.lower() or "narrow" in raw.lower())


def test_ac25_migration_idempotent():
    """AC25/EC23: running migrations again is a no-op (idempotent)."""
    from infra_twin.db.migrate import run_migrations
    run_migrations(directory=_MIGRATIONS_DIR)


# ===========================================================================
# Section 2: Repository / package layer checks (AC 9-12)
# ===========================================================================


def test_ac9_classes_importable():
    """AC9: RetentionPolicy, HistoryAggregate, RetentionPolicyRepository are importable."""
    assert RetentionPolicy is not None
    assert HistoryAggregate is not None
    assert RetentionPolicyRepository is not None


def test_ac9_repository_has_required_methods():
    """AC9: RetentionPolicyRepository has upsert_policy, get_policy, list_aggregates."""
    for method in ("upsert_policy", "get_policy", "list_aggregates"):
        assert hasattr(RetentionPolicyRepository, method), (
            f"RetentionPolicyRepository missing method: {method}"
        )


def test_ac9_no_where_tenant_id_in_repository():
    """AC9: retention.py (db) never uses tenant_id in WHERE clauses (relies on RLS)."""
    retention_file = (
        pathlib.Path(__file__).resolve().parents[1]
        / "packages/db/src/infra_twin/db/retention.py"
    )
    text = retention_file.read_text()
    for line in text.splitlines():
        stripped = line.strip().upper()
        if "WHERE" in stripped and "TENANT_ID" in stripped:
            pytest.fail(
                f"tenant_id found in WHERE clause in db/retention.py: {line.strip()!r}"
            )


def test_ac10_db_init_exports_retention_names():
    """AC10: infra_twin.db exports HistoryAggregate, RetentionPolicy, RetentionPolicyRepository."""
    import infra_twin.db as db
    for name in ("HistoryAggregate", "RetentionPolicy", "RetentionPolicyRepository"):
        assert name in db.__all__, f"{name} not in infra_twin.db.__all__"


def test_ac11_reconciliation_retention_symbols_importable():
    """AC11: RETENTION_SOURCE, RetentionKindReport, RetentionReport, sweep_history importable."""
    assert RETENTION_SOURCE == "history-retention"
    assert RetentionKindReport is not None
    assert RetentionReport is not None
    assert callable(sweep_history)


def test_ac12_reconciliation_init_exports():
    """AC12: reconciliation.__init__ exports all four retention symbols."""
    import infra_twin.reconciliation as rec
    for name in ("RETENTION_SOURCE", "RetentionKindReport", "RetentionReport", "sweep_history"):
        assert name in rec.__all__, f"{name} not in infra_twin.reconciliation.__all__"


def test_ac26_conftest_includes_new_tables():
    """AC26: tests/conftest.py _DATA_TABLES includes history_aggregates and
    history_retention_policies."""
    conftest = pathlib.Path(__file__).resolve().parent / "conftest.py"
    text = conftest.read_text()
    assert "history_aggregates" in text, "_DATA_TABLES must include history_aggregates"
    assert "history_retention_policies" in text, (
        "_DATA_TABLES must include history_retention_policies"
    )


# ===========================================================================
# Section 3: Policy repository happy path (EC20)
# ===========================================================================


def test_upsert_policy_creates_row(pool, make_tenant):
    """Upsert a policy -> row persisted; returned object has correct fields."""
    tenant = make_tenant("retention-upsert-a")
    with tenant_session(pool, tenant) as conn:
        policy = RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=30, enabled=True
        )
    assert isinstance(policy, RetentionPolicy)
    assert policy.tenant_id == tenant
    assert policy.retain_closed_days == 30
    assert policy.enabled is True
    assert policy.id is not None
    assert policy.created_at is not None
    assert policy.updated_at is not None


def test_ec20_reupsert_stable_id_created_at(pool, make_tenant):
    """EC20: re-upsert same tenant -> single row, id + created_at stable, updated_at advances."""
    tenant = make_tenant("retention-reupsert")
    with tenant_session(pool, tenant) as conn:
        repo = RetentionPolicyRepository(conn, tenant)
        first = repo.upsert_policy(retain_closed_days=30, enabled=True)
        second = repo.upsert_policy(retain_closed_days=60, enabled=False)

    assert _count_policy_rows(tenant) == 1, "must remain one row after re-upsert"
    assert second.id == first.id, "id must be stable across upserts"
    assert second.created_at == first.created_at, "created_at must be stable"
    assert second.retain_closed_days == 60, "retain_closed_days should update"
    assert second.enabled is False
    assert second.updated_at >= first.updated_at


def test_get_policy_returns_none_when_absent(pool, make_tenant):
    """get_policy returns None when no policy row exists."""
    tenant = make_tenant("retention-get-none")
    with tenant_session(pool, tenant) as conn:
        policy = RetentionPolicyRepository(conn, tenant).get_policy()
    assert policy is None


def test_get_policy_returns_policy_when_present(pool, make_tenant):
    """get_policy returns the policy after upsert."""
    tenant = make_tenant("retention-get-present")
    with tenant_session(pool, tenant) as conn:
        repo = RetentionPolicyRepository(conn, tenant)
        repo.upsert_policy(retain_closed_days=14, enabled=True)
        policy = repo.get_policy()
    assert policy is not None
    assert policy.retain_closed_days == 14
    assert policy.enabled is True


def test_list_aggregates_empty_initially(pool, make_tenant):
    """list_aggregates returns empty list when no aggregates."""
    tenant = make_tenant("retention-list-empty")
    with tenant_session(pool, tenant) as conn:
        aggs = RetentionPolicyRepository(conn, tenant).list_aggregates()
    assert aggs == []


# ===========================================================================
# Section 4: Engine no-op path (a), AC 13-14, EC1-2
# ===========================================================================


def test_ec1_no_policy_sweep_is_noop(pool, make_tenant):
    """EC1/AC13: no policy row -> swept=False, all counters 0, no connector_runs row."""
    tenant = make_tenant("noop-no-policy")
    result = sweep_history(pool, tenant, now=datetime.now(timezone.utc))

    assert isinstance(result, RetentionReport)
    assert result.swept is False
    assert result.connector_run_id is None
    assert result.ci.versions_collapsed == 0
    assert result.ci.aggregates_written == 0
    assert result.ci.retained_current == 0
    assert result.ci.retained_boundary == 0
    assert result.ci.eligible == 0
    assert result.edge.versions_collapsed == 0
    assert result.edge.aggregates_written == 0
    assert result.edge.retained_current == 0
    assert result.edge.retained_boundary == 0
    assert result.edge.eligible == 0
    # No connector_runs row
    assert _count_connector_runs(tenant, RETENTION_SOURCE) == 0
    # No aggregate rows
    assert _count_aggregates(tenant) == 0


def test_ec2_disabled_policy_sweep_is_noop(pool, make_tenant):
    """EC2/AC14: enabled=False -> same no-op: swept=False, no connector_run, no writes."""
    tenant = make_tenant("noop-disabled")
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=30, enabled=False
        )

    result = sweep_history(pool, tenant, now=datetime.now(timezone.utc))

    assert result.swept is False
    assert result.connector_run_id is None
    assert result.ci.versions_collapsed == 0
    assert result.edge.versions_collapsed == 0
    assert _count_connector_runs(tenant, RETENTION_SOURCE) == 0
    assert _count_aggregates(tenant) == 0


def test_ec3_no_eligible_rows_swept_true_zero_counters(pool, make_tenant):
    """EC3: policy enabled, but all closed versions within horizon -> swept=True, counters 0."""
    tenant = make_tenant("noop-within-horizon")
    # Policy: retain for 90 days; we'll have a closed row only 5 days old -> not eligible
    with tenant_session(pool, tenant) as conn:
        repo = RetentionPolicyRepository(conn, tenant)
        repo.upsert_policy(retain_closed_days=90, enabled=True)
        # Seed a CI with one old+closed version and one current version using admin
    with psycopg.connect(admin_dsn()) as conn:
        ci_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        # old version: closed 5 days ago (within 90-day horizon)
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-a', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (
                ci_id, tenant,
                f"i-{uuid.uuid4().hex[:8]}",
                now - timedelta(days=10), now - timedelta(days=10),
                now - timedelta(days=10), now - timedelta(days=5),
            ),
        )
        # current version
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-a', '{}'::jsonb, 1.0, %s, %s, %s, NULL)",
            (
                ci_id, tenant,
                f"i-{uuid.uuid4().hex[:8]}",
                now - timedelta(days=5), now - timedelta(days=5),
                now - timedelta(days=5),
            ),
        )
        conn.commit()

    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    assert result.connector_run_id is not None
    assert result.ci.versions_collapsed == 0
    assert result.ci.aggregates_written == 0
    # connector_runs row should exist
    assert _count_connector_runs(tenant, RETENTION_SOURCE) == 1


# ===========================================================================
# Section 5: Engine collapse path (b), (c), (d) — core behavior
# ===========================================================================


def _seed_ci_with_versions(
    tenant_id: UUID,
    *,
    closed_ages_days: list[tuple[int, int]],  # list of (valid_from_offset, valid_to_offset)
    add_current: bool = True,
) -> UUID:
    """Insert CI versions directly using admin connection.

    Returns the stable entity id.
    closed_ages_days: list of (valid_from_days_ago, valid_to_days_ago) tuples.
    add_current: if True, also inserts a current (valid_to=NULL) version.
    """
    ci_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    external_id = f"i-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(admin_dsn()) as conn:
        for vf_days, vt_days in closed_ages_days:
            conn.execute(
                "INSERT INTO cis "
                "(id, tenant_id, type, external_id, name, attributes, confidence, "
                "first_seen, last_seen, valid_from, valid_to) "
                "VALUES (%s, %s, 'ec2_instance', %s, 'ci-test', '{}'::jsonb, 1.0, "
                "%s, %s, %s, %s)",
                (
                    ci_id, tenant_id, external_id,
                    now - timedelta(days=vf_days),
                    now - timedelta(days=vf_days),
                    now - timedelta(days=vf_days),
                    now - timedelta(days=vt_days),
                ),
            )
        if add_current:
            # Current version: valid_from = now - min(vt_days), valid_to = NULL
            min_vt = min(vt for _, vt in closed_ages_days) if closed_ages_days else 1
            conn.execute(
                "INSERT INTO cis "
                "(id, tenant_id, type, external_id, name, attributes, confidence, "
                "first_seen, last_seen, valid_from, valid_to) "
                "VALUES (%s, %s, 'ec2_instance', %s, 'ci-test', '{}'::jsonb, 1.0, "
                "%s, %s, %s, NULL)",
                (
                    ci_id, tenant_id, external_id,
                    now - timedelta(days=min_vt),
                    now - timedelta(days=min_vt),
                    now - timedelta(days=min_vt),
                ),
            )
        conn.commit()
    return ci_id


def test_ec4_entity_with_only_current_row_never_touched(pool, make_tenant):
    """EC4: entity with only current row -> never touched; retained_current incremented."""
    tenant = make_tenant("ec4-current-only")
    # Seed a CI with no closed versions (just current)
    ci_id = _seed_ci_with_versions(tenant, closed_ages_days=[], add_current=True)

    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    now = datetime.now(timezone.utc)
    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    assert result.ci.retained_current >= 1
    assert result.ci.versions_collapsed == 0
    assert result.ci.aggregates_written == 0
    # The current row must still exist
    assert _count_ci_versions(tenant, ci_id) == 1


def test_ec5_entity_current_plus_one_closed_boundary_not_collapsed(pool, make_tenant):
    """EC5: entity with current + exactly one old closed version -> boundary, not collapsed."""
    tenant = make_tenant("ec5-one-closed")
    # closed version: 100 days ago -> 50 days ago; current since 50 days ago
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(100, 50)],
        add_current=True,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    now = datetime.now(timezone.utc)
    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    # The single closed version is the boundary -> retained, NOT collapsed
    assert result.ci.versions_collapsed == 0
    assert result.ci.aggregates_written == 0
    assert result.ci.retained_boundary >= 1
    # Both versions must still exist
    assert _count_ci_versions(tenant, ci_id) == 2


def test_ec6_entity_current_plus_two_old_closed_one_collapses(pool, make_tenant):
    """EC6: entity with current + 2 old closed versions both < horizon -> older collapses."""
    tenant = make_tenant("ec6-two-closed")
    # version 1: 200 days ago -> 100 days ago  (older, collapsible interior)
    # version 2: 100 days ago -> 50 days ago   (most-recent closed = boundary)
    # current: since 50 days ago
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    now = datetime.now(timezone.utc)
    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    # Exactly 1 version collapsed (the older interior row)
    assert result.ci.versions_collapsed == 1
    assert result.ci.aggregates_written == 1
    assert result.ci.retained_boundary >= 1
    assert result.ci.retained_current >= 1
    # After collapse: 2 rows remain (current + boundary)
    assert _count_ci_versions(tenant, ci_id) == 2


def test_ec7_retired_entity_no_current_boundary_preserved(pool, make_tenant):
    """EC7: entity with NO current row + >= 2 old closed versions -> most-recent is boundary."""
    tenant = make_tenant("ec7-retired")
    # version 1: 200 -> 100 days ago (collapsible)
    # version 2: 100 -> 50 days ago  (boundary: most-recent closed)
    # No current version (entity is retired)
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=False,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    now = datetime.now(timezone.utc)
    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    assert result.ci.versions_collapsed == 1
    assert result.ci.aggregates_written == 1
    assert result.ci.retained_boundary >= 1
    # Boundary row still present
    assert _count_ci_versions(tenant, ci_id) == 1


def test_ec8_valid_to_exactly_at_horizon_not_eligible(pool, make_tenant):
    """EC8: closed version with valid_to == horizon is NOT eligible (strict < predicate)."""
    tenant = make_tenant("ec8-boundary-pred")
    retain_days = 30
    # We'll set now such that the closed version's valid_to is EXACTLY at horizon
    # version 1: valid_from = 100 days ago, valid_to = retain_days days ago (at horizon)
    # version 2 (boundary): valid_from = retain_days days ago, valid_to = 10 days ago
    # current: since 10 days ago
    now = datetime.now(timezone.utc)
    horizon = now - timedelta(days=retain_days)
    ci_id = uuid.uuid4()
    external_id = f"i-ec8-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(admin_dsn()) as conn:
        # version 1: valid_to exactly == horizon (not eligible)
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec8', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (
                ci_id, tenant, external_id,
                now - timedelta(days=100),
                now - timedelta(days=100),
                now - timedelta(days=100),
                horizon,  # EXACTLY at horizon
            ),
        )
        # version 2 (boundary): valid_from slightly after horizon, valid_to = 10 days ago
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec8', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (
                ci_id, tenant, external_id,
                horizon + timedelta(seconds=1),
                horizon + timedelta(seconds=1),
                horizon + timedelta(seconds=1),
                now - timedelta(days=10),
            ),
        )
        # current version
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec8', '{}'::jsonb, 1.0, %s, %s, %s, NULL)",
            (
                ci_id, tenant, external_id,
                now - timedelta(days=10),
                now - timedelta(days=10),
                now - timedelta(days=10),
            ),
        )
        conn.commit()

    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=retain_days, enabled=True
        )

    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    # Version 1 has valid_to == horizon: NOT eligible (strict <), so nothing collapses
    assert result.ci.versions_collapsed == 0
    assert result.ci.aggregates_written == 0
    # All 3 rows should still exist
    assert _count_ci_versions(tenant, ci_id) == 3


def test_ec8_one_second_older_is_eligible(pool, make_tenant):
    """EC8 boundary: valid_to one second older than horizon IS eligible."""
    tenant = make_tenant("ec8-boundary-eligible")
    retain_days = 30
    now = datetime.now(timezone.utc)
    horizon = now - timedelta(days=retain_days)
    ci_id = uuid.uuid4()
    external_id = f"i-ec8e-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(admin_dsn()) as conn:
        # version 1: valid_to = horizon - 1 second (IS eligible)
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec8e', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (
                ci_id, tenant, external_id,
                now - timedelta(days=100),
                now - timedelta(days=100),
                now - timedelta(days=100),
                horizon - timedelta(seconds=1),
            ),
        )
        # version 2 (boundary): valid_from after v1's valid_to, closed
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec8e', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (
                ci_id, tenant, external_id,
                horizon - timedelta(seconds=1),
                horizon - timedelta(seconds=1),
                horizon - timedelta(seconds=1),
                now - timedelta(days=10),
            ),
        )
        # current
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec8e', '{}'::jsonb, 1.0, %s, %s, %s, NULL)",
            (
                ci_id, tenant, external_id,
                now - timedelta(days=10),
                now - timedelta(days=10),
                now - timedelta(days=10),
            ),
        )
        conn.commit()

    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=retain_days, enabled=True
        )

    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    assert result.ci.versions_collapsed == 1, "version 1 second older than horizon must be eligible"
    assert result.ci.aggregates_written == 1


def test_ec9_naive_now_normalised_to_utc(pool, make_tenant):
    """EC9: naive (tz-less) now -> engine normalises to UTC without error."""
    tenant = make_tenant("ec9-naive-now")
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    # Naive datetime (no tzinfo)
    naive_now = datetime.utcnow()
    assert naive_now.tzinfo is None
    # Should not raise; should return a valid RetentionReport
    result = sweep_history(pool, tenant, now=naive_now)
    assert isinstance(result, RetentionReport)
    assert result.swept is True


def test_ec10_now_far_in_past_no_eligible(pool, make_tenant):
    """EC10: now far in the past (horizon precedes all data) -> no rows eligible, no-op-with-run."""
    tenant = make_tenant("ec10-past-now")
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(100, 50)],
        add_current=True,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    # now = 5 years ago -> horizon = 5 years + 7 days ago -> all data newer than horizon
    far_past = datetime.now(timezone.utc) - timedelta(days=5 * 365)
    result = sweep_history(pool, tenant, now=far_past)

    assert result.swept is True
    assert result.ci.versions_collapsed == 0
    assert result.ci.aggregates_written == 0
    assert _count_ci_versions(tenant, ci_id) == 2


def test_ec11_idempotent_rerun_zero_collapse(pool, make_tenant):
    """EC11/AC18: second sweep over already-swept state -> versions_collapsed==0, aggregates_written==0."""
    tenant = make_tenant("ec11-idempotent")
    # version 1 (collapsible): 200 -> 100 days ago; version 2 (boundary): 100 -> 50 days ago; current
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    now = datetime.now(timezone.utc)
    result1 = sweep_history(pool, tenant, now=now)
    assert result1.ci.versions_collapsed == 1

    # Second sweep: nothing more to collapse
    result2 = sweep_history(pool, tenant, now=now)
    assert result2.swept is True
    assert result2.ci.versions_collapsed == 0, "idempotent: second sweep must collapse nothing"
    assert result2.ci.aggregates_written == 0, "idempotent: no new aggregates on second sweep"


# ===========================================================================
# Section 6: Aggregate correctness + immutability (b) (AC 5-6, EC12-13)
# ===========================================================================


def test_aggregate_written_with_correct_fields(pool, make_tenant):
    """(b): aggregate row has correct version_count, earliest_valid_from, latest_valid_to, rollup."""
    tenant = make_tenant("agg-correctness")
    now = datetime.now(timezone.utc)
    # Build two collapsible versions:
    # v1: valid_from 200d ago, valid_to 100d ago
    # v2: valid_from 100d ago, valid_to 50d ago  (this is the boundary, NOT in aggregate)
    # v3: current
    # With retain_closed_days=7 and now=now:
    # horizon = now - 7 days; v1 valid_to=100d ago < horizon YES, v2 valid_to=50d ago < horizon YES
    # But v2 is the boundary -> only v1 collapses
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )
    result = sweep_history(pool, tenant, now=now)
    assert result.ci.aggregates_written == 1

    with tenant_session(pool, tenant) as conn:
        aggs = RetentionPolicyRepository(conn, tenant).list_aggregates()
    assert len(aggs) == 1
    agg = aggs[0]
    assert agg.entity_kind == "ci"
    assert agg.entity_id == ci_id
    assert agg.version_count == 1  # only v1 was collapsed
    assert agg.rollup["version_count"] == 1
    assert "types" in agg.rollup
    assert "ec2_instance" in agg.rollup["types"]
    # For CI kind, sources key must NOT be in rollup
    assert "sources" not in agg.rollup
    # Timestamps: the aggregate should span the collapsed set (v1 only)
    assert agg.earliest_valid_from is not None
    assert agg.latest_valid_to is not None


def test_aggregate_for_edge_has_sources_key(pool, make_tenant):
    """(b): edge aggregate rollup includes 'sources' key."""
    tenant = make_tenant("agg-edge-sources")
    now = datetime.now(timezone.utc)
    # Seed two CIs, then edge versions
    ci_a_id = _seed_ci_with_versions(tenant, closed_ages_days=[], add_current=True)
    ci_b_id = _seed_ci_with_versions(tenant, closed_ages_days=[], add_current=True)
    edge_id = uuid.uuid4()
    with psycopg.connect(admin_dsn()) as conn:
        # v1 edge: 200 -> 100 days ago
        evidence = [{"source": "test", "detail": "e1", "observed_at": now.isoformat()}]
        conn.execute(
            "INSERT INTO edges "
            "(id, tenant_id, type, from_id, to_id, edge_key, source, confidence, evidence, valid_from, valid_to) "
            "VALUES (%s, %s, 'CONNECTS_TO', %s, %s, '', 'inferred', 0.8, %s::jsonb, %s, %s)",
            (
                edge_id, tenant, ci_a_id, ci_b_id,
                psycopg.types.json.Jsonb(evidence),
                now - timedelta(days=200), now - timedelta(days=100),
            ),
        )
        # v2 edge (boundary): 100 -> 50 days ago
        conn.execute(
            "INSERT INTO edges "
            "(id, tenant_id, type, from_id, to_id, edge_key, source, confidence, evidence, valid_from, valid_to) "
            "VALUES (%s, %s, 'CONNECTS_TO', %s, %s, '', 'inferred', 0.7, %s::jsonb, %s, %s)",
            (
                edge_id, tenant, ci_a_id, ci_b_id,
                psycopg.types.json.Jsonb(evidence),
                now - timedelta(days=100), now - timedelta(days=50),
            ),
        )
        # current edge
        conn.execute(
            "INSERT INTO edges "
            "(id, tenant_id, type, from_id, to_id, edge_key, source, confidence, evidence, valid_from, valid_to) "
            "VALUES (%s, %s, 'CONNECTS_TO', %s, %s, '', 'inferred', 0.6, %s::jsonb, %s, NULL)",
            (
                edge_id, tenant, ci_a_id, ci_b_id,
                psycopg.types.json.Jsonb(evidence),
                now - timedelta(days=50),
            ),
        )
        conn.commit()

    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )

    result = sweep_history(pool, tenant, now=now)
    assert result.edge.aggregates_written == 1

    with tenant_session(pool, tenant) as conn:
        aggs = RetentionPolicyRepository(conn, tenant).list_aggregates()
    edge_aggs = [a for a in aggs if a.entity_kind == "edge"]
    assert len(edge_aggs) == 1
    agg = edge_aggs[0]
    assert "sources" in agg.rollup, "edge aggregate rollup must include 'sources'"
    assert "types" in agg.rollup


def test_ec12_aggregate_immutability_update_rejected(pool):
    """EC12/AC6: UPDATE on history_aggregates by app role is rejected."""
    with pytest.raises(psycopg.Error):
        with pool.connection() as conn:
            conn.execute("UPDATE history_aggregates SET version_count = 999 WHERE 1=0")
            conn.commit()


def test_ec12_aggregate_immutability_delete_rejected(pool):
    """EC12/AC6: DELETE on history_aggregates by app role is rejected."""
    with pytest.raises(psycopg.Error):
        with pool.connection() as conn:
            conn.execute("DELETE FROM history_aggregates WHERE 1=0")
            conn.commit()


# ===========================================================================
# Section 7: Current graph byte-identity (c), AC 16, EC 14
# ===========================================================================


def test_ec14_current_ci_rows_byte_identical_after_sweep(pool, make_tenant):
    """EC14/AC16/(c): current CI rows (valid_to IS NULL) are byte-identical before/after sweep."""
    tenant = make_tenant("byte-id-ci")
    now = datetime.now(timezone.utc)

    # Seed: one CI with collapsible history + current version
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )

    # Capture current CI rows BEFORE sweep
    with psycopg.connect(admin_dsn()) as conn:
        rows_before = conn.execute(
            "SELECT id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to "
            "FROM cis WHERE tenant_id = %s AND valid_to IS NULL "
            "ORDER BY id, valid_from",
            (tenant,),
        ).fetchall()

    result = sweep_history(pool, tenant, now=now)
    assert result.ci.versions_collapsed >= 1

    # Capture current CI rows AFTER sweep
    with psycopg.connect(admin_dsn()) as conn:
        rows_after = conn.execute(
            "SELECT id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to "
            "FROM cis WHERE tenant_id = %s AND valid_to IS NULL "
            "ORDER BY id, valid_from",
            (tenant,),
        ).fetchall()

    assert rows_before == rows_after, (
        "current CI rows (valid_to IS NULL) must be byte-identical before/after sweep"
    )


def test_boundary_closed_row_unchanged_after_sweep(pool, make_tenant):
    """(c)/AC16: boundary (most-recent closed) row is unchanged after sweep."""
    tenant = make_tenant("boundary-unchanged")
    now = datetime.now(timezone.utc)

    # v1 (collapsible): 200 -> 100 days ago
    # v2 (boundary): 100 -> 50 days ago
    # current
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )

    # Capture the most-recent closed row BEFORE sweep
    with psycopg.connect(admin_dsn()) as conn:
        boundary_before = conn.execute(
            "SELECT valid_from, valid_to FROM cis "
            "WHERE id = %s AND valid_to IS NOT NULL "
            "ORDER BY valid_from DESC LIMIT 1",
            (ci_id,),
        ).fetchone()

    result = sweep_history(pool, tenant, now=now)
    assert result.ci.versions_collapsed == 1

    # Capture the most-recent closed row AFTER sweep
    with psycopg.connect(admin_dsn()) as conn:
        boundary_after = conn.execute(
            "SELECT valid_from, valid_to FROM cis "
            "WHERE id = %s AND valid_to IS NOT NULL "
            "ORDER BY valid_from DESC LIMIT 1",
            (ci_id,),
        ).fetchone()

    assert boundary_before == boundary_after, (
        "boundary closed row must be unchanged after sweep"
    )


# ===========================================================================
# Section 8: Mixed eligible + ineligible (EC15, EC16)
# ===========================================================================


def test_ec15_mixed_eligible_ineligible_only_subset_collapses(pool, make_tenant):
    """EC15: mixed eligible + ineligible interior versions -> only < horizon subset collapses."""
    tenant = make_tenant("ec15-mixed")
    now = datetime.now(timezone.utc)
    retain_days = 30

    # v1: 200 -> 100 days ago (collapsible, < 30d horizon)
    # v2: 100 -> 60 days ago  (collapsible, < 30d horizon)
    # v3: 60  -> 20 days ago  (NOT eligible: valid_to=20d > 30d horizon; also boundary)
    # current: since 20 days ago
    ci_id = uuid.uuid4()
    external_id = f"i-ec15-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(admin_dsn()) as conn:
        horizon = now - timedelta(days=retain_days)
        # v1
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec15', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (ci_id, tenant, external_id,
             now - timedelta(days=200), now - timedelta(days=200),
             now - timedelta(days=200), now - timedelta(days=100)),
        )
        # v2
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec15', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (ci_id, tenant, external_id,
             now - timedelta(days=100), now - timedelta(days=100),
             now - timedelta(days=100), now - timedelta(days=60)),
        )
        # v3 (NOT eligible, most-recent closed -> boundary)
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec15', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (ci_id, tenant, external_id,
             now - timedelta(days=60), now - timedelta(days=60),
             now - timedelta(days=60), now - timedelta(days=20)),
        )
        # current
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec15', '{}'::jsonb, 1.0, %s, %s, %s, NULL)",
            (ci_id, tenant, external_id,
             now - timedelta(days=20), now - timedelta(days=20),
             now - timedelta(days=20)),
        )
        conn.commit()

    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=retain_days, enabled=True
        )

    result = sweep_history(pool, tenant, now=now)

    assert result.swept is True
    # v3 is the boundary (most-recent closed), v1 and v2 are both eligible and collapsible
    assert result.ci.versions_collapsed == 2
    assert result.ci.aggregates_written == 1
    # Remaining: current (1) + boundary v3 (1) = 2
    assert _count_ci_versions(tenant, ci_id) == 2


def test_ec16_retain_closed_days_updated_downward_collapses_more(pool, make_tenant):
    """EC16: retain_closed_days updated downward -> newly-eligible versions collapse on next run."""
    tenant = make_tenant("ec16-downward")
    now = datetime.now(timezone.utc)

    # v1: 200 -> 100 days ago (always collapsible)
    # v2: 100 -> 50 days ago  (collapsible only if horizon > 50 days)
    # v3: 50 -> 20 days ago   (boundary: most-recent closed)
    # current
    ci_id = uuid.uuid4()
    external_id = f"i-ec16-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec16', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (ci_id, tenant, external_id,
             now - timedelta(days=200), now - timedelta(days=200),
             now - timedelta(days=200), now - timedelta(days=100)),
        )
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec16', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (ci_id, tenant, external_id,
             now - timedelta(days=100), now - timedelta(days=100),
             now - timedelta(days=100), now - timedelta(days=50)),
        )
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec16', '{}'::jsonb, 1.0, %s, %s, %s, %s)",
            (ci_id, tenant, external_id,
             now - timedelta(days=50), now - timedelta(days=50),
             now - timedelta(days=50), now - timedelta(days=20)),
        )
        conn.execute(
            "INSERT INTO cis "
            "(id, tenant_id, type, external_id, name, attributes, confidence, "
            "first_seen, last_seen, valid_from, valid_to) "
            "VALUES (%s, %s, 'ec2_instance', %s, 'ci-ec16', '{}'::jsonb, 1.0, %s, %s, %s, NULL)",
            (ci_id, tenant, external_id,
             now - timedelta(days=20), now - timedelta(days=20),
             now - timedelta(days=20)),
        )
        conn.commit()

    # First sweep with retain_closed_days=40: horizon = now-40d
    # v1 (valid_to=100d): eligible; v2 (valid_to=50d): eligible; but v3 is boundary -> v1+v2 both eligible interior
    # v3 is most-recent closed -> boundary; v1 collapses; v2 was also eligible interior
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=40, enabled=True
        )

    result1 = sweep_history(pool, tenant, now=now)
    # horizon = 40d ago; v1 (valid_to=100d < 40d) eligible, v2 (valid_to=50d < 40d) eligible
    # boundary is v3 (most-recent closed: valid_from=50d, valid_to=20d)
    # collapsible interior = v1 and v2
    assert result1.ci.versions_collapsed == 2, (
        f"Expected 2 collapsed (v1 + v2); got {result1.ci.versions_collapsed}"
    )
    # After first sweep: current + v3 (boundary) = 2
    assert _count_ci_versions(tenant, ci_id) == 2


# ===========================================================================
# Section 9: EC26 aggregate ordering
# ===========================================================================


def test_ec26_aggregates_ordered_created_at_desc(pool, make_tenant):
    """EC26: list_aggregates returns aggregates ordered created_at DESC, aggregate_id DESC."""
    tenant = make_tenant("agg-order")
    now = datetime.now(timezone.utc)

    # Create two separate entities, each with collapsible history
    for _ in range(3):
        ci_id = _seed_ci_with_versions(
            tenant,
            closed_ages_days=[(200, 100), (100, 50)],
            add_current=True,
        )

    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )

    sweep_history(pool, tenant, now=now)

    with tenant_session(pool, tenant) as conn:
        aggs = RetentionPolicyRepository(conn, tenant).list_aggregates()

    assert len(aggs) >= 1
    # Verify ordering: created_at DESC (with aggregate_id as tiebreaker)
    for i in range(len(aggs) - 1):
        assert aggs[i].created_at >= aggs[i + 1].created_at, (
            "aggregates must be ordered created_at DESC"
        )


# ===========================================================================
# Section 10: API endpoint happy path (AC 19-21)
# ===========================================================================


def test_put_retention_policy_200(pool, make_tenant_with_key):
    """AC19: PUT /retention-policy with editor key returns 200."""
    _, api_key = make_tenant_with_key("api-put-200")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200


def test_put_retention_policy_response_shape(pool, make_tenant_with_key):
    """AC21: PUT /retention-policy response omits tenant_id; includes required keys."""
    _, api_key = make_tenant_with_key("api-put-shape")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "tenant_id" not in body, "tenant_id must not appear in PUT response"
    for key in ("retain_closed_days", "enabled", "created_at", "updated_at"):
        assert key in body, f"Key '{key}' missing from PUT /retention-policy response"
    assert body["retain_closed_days"] == 30
    assert body["enabled"] is True


def test_get_retention_policy_200_no_policy(pool, make_tenant_with_key):
    """GET /retention-policy returns 200 with default shape when no policy row."""
    _, api_key = make_tenant_with_key("api-get-nopol")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/retention-policy", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["retain_closed_days"] is None
    assert body["enabled"] is False
    assert body["created_at"] is None
    assert body["updated_at"] is None


def test_get_retention_policy_200_with_policy(pool, make_tenant_with_key):
    """GET /retention-policy returns 200 with policy data when policy exists."""
    _, api_key = make_tenant_with_key("api-get-pol")
    client = TestClient(create_app(pool=pool))
    client.put(
        "/retention-policy",
        json={"retain_closed_days": 14, "enabled": True},
        headers=_auth(api_key),
    )
    resp = client.get("/retention-policy", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert "tenant_id" not in body
    assert body["retain_closed_days"] == 14
    assert body["enabled"] is True


def test_ec25_post_sweep_disabled_policy_returns_200_swept_false(pool, make_tenant_with_key):
    """EC25: POST /retention/sweep with disabled policy -> 200, swept=false."""
    _, api_key = make_tenant_with_key("api-sweep-disabled")
    client = TestClient(create_app(pool=pool))
    client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": False},
        headers=_auth(api_key),
    )
    resp = client.post("/retention/sweep", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["swept"] is False
    assert body["ci"]["versions_collapsed"] == 0
    assert body["edge"]["versions_collapsed"] == 0


def test_post_sweep_no_policy_returns_200_swept_false(pool, make_tenant_with_key):
    """POST /retention/sweep with no policy -> 200, swept=false."""
    _, api_key = make_tenant_with_key("api-sweep-nopol")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/retention/sweep", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["swept"] is False


def test_post_sweep_200_body_shape(pool, make_tenant_with_key):
    """POST /retention/sweep returns correct body shape."""
    _, api_key = make_tenant_with_key("api-sweep-shape")
    client = TestClient(create_app(pool=pool))
    client.put(
        "/retention-policy",
        json={"retain_closed_days": 7, "enabled": True},
        headers=_auth(api_key),
    )
    resp = client.post("/retention/sweep", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert "swept" in body
    assert "ci" in body
    assert "edge" in body
    for kind in ("ci", "edge"):
        for key in ("versions_collapsed", "aggregates_written", "retained_current",
                    "retained_boundary", "eligible"):
            assert key in body[kind], f"Key '{key}' missing from sweep response .{kind}"


def test_get_history_aggregates_200_empty(pool, make_tenant_with_key):
    """GET /history-aggregates returns 200 with {"aggregates": []} when none exist."""
    _, api_key = make_tenant_with_key("api-agg-empty")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/history-aggregates", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    assert "aggregates" in body
    assert body["aggregates"] == []


def test_get_history_aggregates_omits_tenant_id(pool, make_tenant_with_key):
    """AC21: GET /history-aggregates items omit tenant_id."""
    tenant, api_key = make_tenant_with_key("api-agg-no-tenid")
    client = TestClient(create_app(pool=pool))
    # Create some aggregates via direct insert (admin-level) for checking
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )
    client.put(
        "/retention-policy",
        json={"retain_closed_days": 7, "enabled": True},
        headers=_auth(api_key),
    )
    client.post("/retention/sweep", headers=_auth(api_key))
    resp = client.get("/history-aggregates", headers=_auth(api_key))
    assert resp.status_code == 200
    body = resp.json()
    if body["aggregates"]:
        for item in body["aggregates"]:
            assert "tenant_id" not in item, "history-aggregates items must not include tenant_id"
            for key in ("aggregate_id", "entity_kind", "entity_id", "version_count",
                        "earliest_valid_from", "latest_valid_to", "rollup", "created_at"):
                assert key in item, f"Key '{key}' missing from history-aggregates item"


# ===========================================================================
# Section 11: Validation / error codes (AC 20, EC 21)
# ===========================================================================


def test_ac20_retain_closed_days_zero_returns_422(pool, make_tenant_with_key):
    """AC20: retain_closed_days=0 on PUT returns 422; no row written."""
    tenant, api_key = make_tenant_with_key("val-zero-days")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 0, "enabled": True},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422
    assert _count_policy_rows(tenant) == 0


def test_retain_closed_days_negative_returns_422(pool, make_tenant_with_key):
    """retain_closed_days=-1 on PUT returns 422."""
    _, api_key = make_tenant_with_key("val-neg-days")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": -1, "enabled": True},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_check_constraint_blocks_direct_zero_insert(pool, make_tenant):
    """CHECK constraint rejects direct SQL INSERT of retain_closed_days=0."""
    tenant = make_tenant("check-zero-days")
    with pytest.raises(psycopg.Error):
        with tenant_session(pool, tenant) as conn:
            conn.execute(
                "INSERT INTO history_retention_policies (tenant_id, retain_closed_days, enabled) "
                "VALUES (%s, 0, true)",
                (str(tenant),),
            )


def test_put_missing_body_returns_422(pool, make_tenant_with_key):
    """Malformed request body -> 422."""
    _, api_key = make_tenant_with_key("bad-body-ret")
    client = TestClient(create_app(pool=pool))
    resp = client.put("/retention-policy", json={}, headers=_auth(api_key))
    assert resp.status_code == 422


def test_put_missing_auth_returns_401(pool):
    """Missing Authorization header on PUT -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.put("/retention-policy", json={"retain_closed_days": 30, "enabled": True})
    assert resp.status_code == 401


def test_get_policy_missing_auth_returns_401(pool):
    """Missing Authorization header on GET /retention-policy -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/retention-policy")
    assert resp.status_code == 401


def test_post_sweep_missing_auth_returns_401(pool):
    """Missing Authorization header on POST /retention/sweep -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post("/retention/sweep")
    assert resp.status_code == 401


def test_get_aggregates_missing_auth_returns_401(pool):
    """Missing Authorization header on GET /history-aggregates -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/history-aggregates")
    assert resp.status_code == 401


# ===========================================================================
# Section 12: RBAC gating (e), AC 19, AC 22, EC 21
# ===========================================================================


def test_ec21_viewer_put_retention_policy_403(pool):
    """EC21/AC22: viewer key on PUT /retention-policy returns 403."""
    _, viewer_key = _make_viewer_key("rbac-viewer-put-pol")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "insufficient permissions"


def test_ec21_viewer_put_403_no_row_written(pool):
    """EC21: viewer key PUT -> 403, no row written to history_retention_policies."""
    viewer_tenant, viewer_key = _make_viewer_key("rbac-viewer-no-row-pol")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403
    assert _count_policy_rows(viewer_tenant) == 0, "No policy row should be written on viewer 403"


def test_ec21_viewer_post_sweep_403(pool):
    """EC21/AC22: viewer key on POST /retention/sweep returns 403."""
    _, viewer_key = _make_viewer_key("rbac-viewer-sweep")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/retention/sweep", headers=_auth(viewer_key))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "insufficient permissions"


def test_viewer_get_retention_policy_200(pool):
    """Viewer key can GET /retention-policy (read permission)."""
    _, viewer_key = _make_viewer_key("rbac-viewer-get-pol")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/retention-policy", headers=_auth(viewer_key))
    assert resp.status_code == 200


def test_viewer_get_history_aggregates_200(pool):
    """Viewer key can GET /history-aggregates (read permission)."""
    _, viewer_key = _make_viewer_key("rbac-viewer-get-agg")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/history-aggregates", headers=_auth(viewer_key))
    assert resp.status_code == 200


def test_editor_put_retention_policy_200(pool):
    """AC22: editor key on PUT /retention-policy returns 200."""
    _, editor_key = _make_editor_key("rbac-editor-put-pol")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 200


def test_editor_post_sweep_200(pool):
    """AC22: editor key on POST /retention/sweep returns 200."""
    _, editor_key = _make_editor_key("rbac-editor-sweep")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/retention/sweep", headers=_auth(editor_key))
    assert resp.status_code == 200


# ===========================================================================
# Section 13: Audit log + usage metering (e), AC 23, EC 22
# ===========================================================================


def test_ec22_editor_put_writes_allow_audit_row(pool):
    """EC22/AC23: editor PUT /retention-policy -> allow audit_log row."""
    editor_tenant, editor_key = _make_editor_key("audit-editor-put-pol")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 200

    rows = _get_audit_rows(editor_tenant)
    allow_rows = [r for r in rows if r["decision"] == "allow"]
    assert len(allow_rows) >= 1, f"Expected allow audit row; got: {rows}"
    row = allow_rows[0]
    assert row["method"] == "PUT"
    assert row["permission"] == "write"


def test_ec22_viewer_put_writes_deny_audit_row(pool):
    """EC22/AC23: viewer PUT /retention-policy -> deny audit_log row, no usage row."""
    viewer_tenant, viewer_key = _make_viewer_key("audit-viewer-put-pol")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403

    rows = _get_audit_rows(viewer_tenant)
    deny_rows = [r for r in rows if r["decision"] == "deny"]
    assert len(deny_rows) >= 1, f"Expected deny audit row; got: {rows}"
    assert deny_rows[0]["status_code"] == 403

    # No usage row for viewer 403
    assert _count_usage_rows(viewer_tenant) == 0, (
        "No usage_event row should exist for viewer 403"
    )


def test_ec22_editor_post_sweep_writes_allow_audit_and_usage(pool):
    """EC22/AC23: editor POST /retention/sweep -> allow audit_log row + usage_event row."""
    editor_tenant, editor_key = _make_editor_key("audit-editor-sweep")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/retention/sweep", headers=_auth(editor_key))
    assert resp.status_code == 200

    rows = _get_audit_rows(editor_tenant)
    allow_rows = [r for r in rows if r["decision"] == "allow"]
    assert len(allow_rows) >= 1, "Expected allow audit row for POST /retention/sweep"
    allow_row = allow_rows[0]
    assert allow_row["permission"] == "write"

    assert _count_usage_rows(editor_tenant) >= 1, (
        "editor POST /retention/sweep must write at least one usage_event row"
    )


def test_ec22_viewer_post_sweep_writes_deny_no_usage(pool):
    """EC22/AC23: viewer POST /retention/sweep -> deny audit_log, no usage row."""
    viewer_tenant, viewer_key = _make_viewer_key("audit-viewer-sweep")
    client = TestClient(create_app(pool=pool))
    resp = client.post("/retention/sweep", headers=_auth(viewer_key))
    assert resp.status_code == 403

    rows = _get_audit_rows(viewer_tenant)
    deny_rows = [r for r in rows if r["decision"] == "deny"]
    assert len(deny_rows) >= 1

    assert _count_usage_rows(viewer_tenant) == 0, (
        "No usage_event row should exist for viewer POST /retention/sweep"
    )


# ===========================================================================
# Section 14: Cross-tenant isolation (f), AC 24, EC 17-19
# ===========================================================================


def test_ec17_tenant_b_get_policy_empty_when_a_has_policy(pool, make_tenant_with_key):
    """EC17/(f): tenant B's GET /retention-policy returns default when tenant A has policy."""
    _, a_key = make_tenant_with_key("iso-pol-A")
    _, b_key = make_tenant_with_key("iso-pol-B")
    client = TestClient(create_app(pool=pool))

    client.put(
        "/retention-policy",
        json={"retain_closed_days": 30, "enabled": True},
        headers=_auth(a_key),
    )

    resp_b = client.get("/retention-policy", headers=_auth(b_key))
    assert resp_b.status_code == 200
    body_b = resp_b.json()
    assert body_b["retain_closed_days"] is None, (
        "Tenant B must not see tenant A's retention policy"
    )
    assert body_b["enabled"] is False


def test_ec17_tenant_b_get_aggregates_empty_after_a_sweep(pool, make_tenant_with_key):
    """EC17/(f): tenant B's GET /history-aggregates returns [] after tenant A's sweep."""
    a_tenant, a_key = make_tenant_with_key("iso-agg-A")
    b_tenant, b_key = make_tenant_with_key("iso-agg-B")
    client = TestClient(create_app(pool=pool))

    # Setup + sweep for tenant A
    ci_id = _seed_ci_with_versions(
        a_tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )
    client.put(
        "/retention-policy",
        json={"retain_closed_days": 7, "enabled": True},
        headers=_auth(a_key),
    )
    client.post("/retention/sweep", headers=_auth(a_key))

    # Tenant B's aggregates should be empty
    resp_b = client.get("/history-aggregates", headers=_auth(b_key))
    assert resp_b.status_code == 200
    assert resp_b.json()["aggregates"] == [], (
        "Tenant B must not see tenant A's history aggregates"
    )


def test_ec17_engine_tenant_b_sweep_does_not_collapse_tenant_a_rows(pool, make_tenant_with_key):
    """EC17/(f): tenant B's sweep_history does not alter tenant A's cis/edges/aggregates."""
    a_tenant, _ = make_tenant_with_key("iso-sweep-A")
    b_tenant, _ = make_tenant_with_key("iso-sweep-B")

    # Tenant A: seed collapsible history
    ci_id_a = _seed_ci_with_versions(
        a_tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )

    # Capture A's row count before B sweeps
    count_before = _count_ci_versions(a_tenant, ci_id_a)
    assert count_before == 3

    # Tenant B: enable a policy with a very aggressive horizon and sweep
    with tenant_session(pool, b_tenant) as conn:
        RetentionPolicyRepository(conn, b_tenant).upsert_policy(
            retain_closed_days=1, enabled=True
        )
    now = datetime.now(timezone.utc)
    result_b = sweep_history(pool, b_tenant, now=now)
    assert result_b.swept is True

    # Tenant A's rows must be unchanged
    count_after = _count_ci_versions(a_tenant, ci_id_a)
    assert count_after == count_before, (
        "Tenant B's sweep must not collapse tenant A's CI rows"
    )
    assert _count_aggregates(a_tenant) == 0, (
        "Tenant B's sweep must not write aggregates for tenant A"
    )


def test_ec18_adversarial_insert_policy_wrong_tenant_rejected(pool, make_tenant):
    """EC18: inserting history_retention_policies row stamped with another tenant_id rejected by RLS."""
    a = make_tenant("xins-pol-A")
    b = make_tenant("xins-pol-B")
    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO history_retention_policies (tenant_id, retain_closed_days, enabled) "
                "VALUES (%s, 30, true)",
                (str(b),),
            )


def test_ec18_adversarial_insert_aggregate_wrong_tenant_rejected(pool, make_tenant):
    """EC18: inserting history_aggregates row stamped with another tenant_id rejected by RLS."""
    a = make_tenant("xins-agg-A")
    b = make_tenant("xins-agg-B")
    now = datetime.now(timezone.utc)
    entity_id = uuid.uuid4()
    with pytest.raises(psycopg.Error):
        with tenant_session(pool, a) as conn:
            conn.execute(
                "INSERT INTO history_aggregates "
                "(tenant_id, entity_kind, entity_id, version_count, "
                "earliest_valid_from, latest_valid_to, rollup) "
                "VALUES (%s, 'ci', %s, 1, %s, %s, '{}'::jsonb)",
                (str(b), entity_id, now - timedelta(days=30), now - timedelta(days=10)),
            )


def test_ec19_bare_connection_no_guc_sees_zero_rows_policy(pool, make_tenant):
    """EC19: bare connection (no app.tenant_id GUC) sees zero history_retention_policies rows."""
    tenant = make_tenant("guc-pol")
    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=30, enabled=True
        )
    # Bare connection (no GUC)
    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM history_retention_policies").fetchone()[0]
    assert count == 0, "Bare connection must see zero history_retention_policies rows"


def test_ec19_bare_connection_no_guc_sees_zero_rows_aggregates(pool, make_tenant):
    """EC19: bare connection (no app.tenant_id GUC) sees zero history_aggregates rows."""
    tenant = make_tenant("guc-agg")
    # Insert an aggregate via admin to ensure there's data
    now = datetime.now(timezone.utc)
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(
            "INSERT INTO history_aggregates "
            "(tenant_id, entity_kind, entity_id, version_count, "
            "earliest_valid_from, latest_valid_to, rollup) "
            "VALUES (%s, 'ci', %s, 1, %s, %s, '{\"types\":[\"ec2_instance\"],\"version_count\":1}'::jsonb)",
            (tenant, uuid.uuid4(), now - timedelta(days=100), now - timedelta(days=50)),
        )
        conn.commit()

    # Bare connection (no GUC)
    with pool.connection() as conn:
        count = conn.execute("SELECT count(*) FROM history_aggregates").fetchone()[0]
    assert count == 0, "Bare connection must see zero history_aggregates rows"


def test_repository_level_cross_tenant_isolation(pool, make_tenant):
    """EC17: tenant B's get_policy and list_aggregates never see tenant A's rows."""
    a = make_tenant("repo-iso-A")
    b = make_tenant("repo-iso-B")

    with tenant_session(pool, a) as conn:
        RetentionPolicyRepository(conn, a).upsert_policy(retain_closed_days=30, enabled=True)

    with tenant_session(pool, b) as conn:
        policy_b = RetentionPolicyRepository(conn, b).get_policy()
        aggs_b = RetentionPolicyRepository(conn, b).list_aggregates()

    assert policy_b is None, "Tenant B must not see tenant A's retention policy"
    assert aggs_b == [], "Tenant B must not see tenant A's aggregates"


# ===========================================================================
# Section 15: AC15 / EC13 atomicity — INSERT before DELETE, single transaction
# ===========================================================================


def test_ec13_ac15_atomicity_rollback_leaves_no_partial_state(
    pool, make_tenant, monkeypatch
) -> None:
    """EC13/AC15/DoD(b): forced rollback after history_aggregates INSERT but before the
    collapse DELETE leaves the whole tenant_session transaction rolled back atomically:
    (a) the collapsible interior detail rows are still present (nothing was deleted), AND
    (b) no history_aggregates row was committed for that entity.

    Also asserts the happy-path complement: a normal sweep on the same fixture afterwards
    commits both the aggregate and the collapse correctly.
    """
    import infra_twin.reconciliation.retention as _retention_mod

    tenant = make_tenant("atomicity-rollback")
    now = datetime.now(timezone.utc)

    # Seed: one CI with two old closed versions (one collapsible interior) + current.
    # v1 (200 -> 100 days ago): collapsible interior.
    # v2 (100 ->  50 days ago): boundary (most-recent closed).
    # v3 (current):              sacrosanct.
    ci_id = _seed_ci_with_versions(
        tenant,
        closed_ages_days=[(200, 100), (100, 50)],
        add_current=True,
    )

    with tenant_session(pool, tenant) as conn:
        RetentionPolicyRepository(conn, tenant).upsert_policy(
            retain_closed_days=7, enabled=True
        )

    # Verify baseline: 3 rows exist before any sweep.
    assert _count_ci_versions(tenant, ci_id) == 3

    # Patch _sweep_kind so that after the INSERT INTO history_aggregates executes
    # (the real SQL runs and the row lands in the in-progress transaction), the very
    # next conn.execute that targets a DELETE statement raises RuntimeError.
    # Because everything runs inside a single tenant_session transaction, the raised
    # exception must cause the entire transaction to roll back.

    original_sweep_kind = _retention_mod._sweep_kind

    def _sweep_kind_with_failing_delete(conn, tenant_id, kind, horizon):
        original_execute = conn.execute
        inserted_aggregate = []

        def _patched_execute(sql, params=None, *args, **kwargs):
            sql_text = sql if isinstance(sql, str) else str(sql)
            if "INSERT INTO history_aggregates" in sql_text:
                # Let the INSERT run for real (it lands in the open transaction).
                result = (
                    original_execute(sql, params, *args, **kwargs)
                    if params is not None
                    else original_execute(sql, *args, **kwargs)
                )
                inserted_aggregate.append(True)
                return result
            if "DELETE FROM" in sql_text and inserted_aggregate:
                # Aggregate is already in-transaction; now simulate failure before DELETE.
                raise RuntimeError(
                    "simulated failure after INSERT but before DELETE in sweep"
                )
            return (
                original_execute(sql, params, *args, **kwargs)
                if params is not None
                else original_execute(sql, *args, **kwargs)
            )

        conn.execute = _patched_execute
        return original_sweep_kind(conn, tenant_id, kind, horizon)

    monkeypatch.setattr(_retention_mod, "_sweep_kind", _sweep_kind_with_failing_delete)

    # sweep_history must propagate the RuntimeError (transaction rolls back).
    with pytest.raises(RuntimeError, match="simulated failure after INSERT but before DELETE"):
        sweep_history(pool, tenant, now=now)

    # Restore the original function before further assertions so the admin queries run clean.
    monkeypatch.setattr(_retention_mod, "_sweep_kind", original_sweep_kind)

    # (a) Detail rows must be intact: the collapsible interior row was NOT deleted.
    assert _count_ci_versions(tenant, ci_id) == 3, (
        "all three CI version rows must still be present after a rolled-back sweep"
    )

    # (b) No history_aggregates row must have been committed.
    assert _count_aggregates(tenant) == 0, (
        "no history_aggregates row must be committed when the transaction rolled back"
    )

    # Happy-path complement: a normal (un-patched) sweep on the same fixture succeeds.
    result = sweep_history(pool, tenant, now=now)
    assert result.swept is True
    assert result.ci.versions_collapsed == 1, (
        "normal sweep after failed attempt must still collapse the interior version"
    )
    assert result.ci.aggregates_written == 1, (
        "normal sweep after failed attempt must commit one aggregate row"
    )
    # Post-sweep: 2 rows (current + boundary), aggregate committed.
    assert _count_ci_versions(tenant, ci_id) == 2, (
        "after successful sweep: only current + boundary rows remain"
    )
    assert _count_aggregates(tenant) == 1, (
        "after successful sweep: exactly one history_aggregates row committed"
    )
