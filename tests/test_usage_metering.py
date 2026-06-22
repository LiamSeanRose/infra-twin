"""Usage metering tests: per-tenant quota enforcement with append-only usage_event store.

Covers every acceptance criterion and edge case from the spec:

  Schema / migration structural checks (AC 1-10):
  - migration file 0010_usage_quota.sql exists with all required columns
  - ALTER TABLE tenants ADD COLUMN monthly_request_quota INTEGER NOT NULL DEFAULT 100000
  - CREATE TABLE usage_event with correct columns and constraints
  - RLS + tenant_isolation policy present on usage_event
  - GRANT SELECT, INSERT only (no UPDATE/DELETE)
  - expand-only (no DROP statements)
  - migration idempotency

  DB module / exports (AC 11-15):
  - record_usage, count_usage_in_window, current_calendar_month_start in __all__
  - record_usage returns UUID, inserts exactly one row per call
  - record_usage SQL omits occurred_at from column list (uses DEFAULT)
  - current_calendar_month_start() returns tz-aware UTC with day=1, h/m/s/us=0
  - count_usage_in_window returns correct int, RLS-scoped

  API behavior (AC 16-21):
  - GET /usage without key -> 401
  - GET /usage with viewer key -> 200, correct JSON shape
  - Default quota tenant: quota==100000, remaining==quota-used_this_month
  - POST /tenants with monthly_request_quota=5 stores 5
  - POST /tenants with quota 0 or negative -> 422
  - POST /tenants without quota -> DB default 100000

  Adversarial (AC 22-26 / prompt requirements):
  (a) each allowed request appends exactly one usage_event row; remaining decreases by N
  (b) after Q requests with quota Q, next request returns 429 with deny audit row and NO usage row
  (c) viewer 403 on write endpoint does NOT consume quota (zero usage_event rows)
  (d) cross-tenant isolation: tenant A's count and GET /usage unaffected by tenant B's rows
  (e) app role cannot UPDATE or DELETE usage_event rows (permission denied 42501)

  Edge cases:
  EC 3  quota boundary used==quota-1: allowed, becomes the quota-th row
  EC 4  quota boundary used==quota: 429, deny audit, no usage row
  EC 5  quota=1: first request allowed, second gets 429
  EC 6  default quota 100000 applied to pre-existing tenants
  EC 7  GET /usage self-metering: used_this_month includes the row for the call itself
  EC 8  exactly-once: single allowed request inserts exactly one row
  EC 9  atomicity: usage row and allow audit row in one committed transaction
  EC 10 deny-429 audit durability: committed before raise
  EC 11 cross-tenant isolation via RLS
  EC 12 app role cannot UPDATE usage_event
  EC 13 app role cannot DELETE usage_event
  EC 14 calendar-month boundary: only current-month rows counted
  EC 16 POST /tenants with monthly_request_quota:0 -> 422
  EC 17 POST /tenants with negative quota -> 422
  EC 19 usage_event not in conftest _DATA_TABLES would leak rows (verified by isolation)
  EC 20 migration idempotency: 0010 not re-applied
  EC 21 permission value on usage rows is the gate's perm ("read" or "write"), not NULL
  EC 22 non-gated routes (GET /health, POST /tenants) write zero usage rows

  Wiring / non-regression:
  - provision_tenant(conn, name) unchanged; None quota omits column => DB default
  - existing RBAC 403 rows still have status_code=403 (not 429)
  - 403 denial does NOT write any usage_event row
"""

from __future__ import annotations

import pathlib
from datetime import datetime, timezone
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.db import (
    count_usage_in_window,
    current_calendar_month_start,
    record_usage,
)
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn, app_dsn
from infra_twin.db.session import tenant_session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[1] / "migrations"
_BOOTSTRAP_TOKEN = "test-bootstrap-secret-metering-xyz"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _admin_headers() -> dict:
    return {"Authorization": f"Bearer {_BOOTSTRAP_TOKEN}"}


def _make_viewer_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _make_editor_key_with_quota(name: str, quota: int) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(
            conn, name, role=Role.editor, monthly_request_quota=quota
        )
    return issued.tenant_id, issued.plaintext


def _count_usage_rows(tenant_id: UUID) -> int:
    """Count usage_event rows for a tenant bypassing RLS (admin connection)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM usage_event WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
    return row[0]


def _count_audit_rows(tenant_id: UUID) -> int:
    """Count audit_log rows for a tenant bypassing RLS (admin connection)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM audit_log WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
    return row[0]


def _get_audit_rows(tenant_id: UUID) -> list[dict]:
    """Fetch all audit_log rows for a tenant (admin connection, bypasses RLS)."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT audit_id, decision, status_code, permission, method, path "
            "FROM audit_log WHERE tenant_id = %s "
            "ORDER BY occurred_at DESC, audit_id DESC",
            (tenant_id,),
        ).fetchall()
    return [
        {
            "audit_id": r[0],
            "decision": r[1],
            "status_code": r[2],
            "permission": r[3],
            "method": r[4],
            "path": r[5],
        }
        for r in rows
    ]


def _get_stored_quota(tenant_id: UUID) -> int:
    """Read the stored monthly_request_quota for a tenant via admin connection."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT monthly_request_quota FROM tenants WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    return row[0]


# ===========================================================================
# Migration structural checks (AC 1-10)
# ===========================================================================


def test_migration_0010_file_exists():
    """AC 1: migrations/0010_usage_quota.sql exists."""
    assert (_MIGRATIONS_DIR / "0010_usage_quota.sql").exists()


def test_migration_0010_alter_table_tenants_add_quota_column():
    """AC 2: migration contains ALTER TABLE tenants ADD COLUMN monthly_request_quota INTEGER NOT NULL DEFAULT 100000."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    assert "ALTER TABLE tenants" in text
    assert "ADD COLUMN" in text.upper()
    assert "monthly_request_quota" in text
    assert "INTEGER" in text.upper()
    assert "NOT NULL" in text.upper()
    assert "100000" in text


def test_migration_0010_has_create_table_usage_event():
    """AC 3: migration contains CREATE TABLE usage_event."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    assert "CREATE TABLE usage_event" in text


def test_migration_0010_usage_event_has_all_required_columns():
    """AC 3: migration defines all required columns in usage_event."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    for col in ("usage_id", "tenant_id", "api_key_id", "method", "path", "permission", "occurred_at"):
        assert col in text, f"Column '{col}' not found in 0010_usage_quota.sql"


def test_migration_0010_usage_id_primary_key_default():
    """AC 4: usage_id is PRIMARY KEY DEFAULT gen_random_uuid()."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    assert "PRIMARY KEY" in text
    assert "gen_random_uuid()" in text


def test_migration_0010_tenant_id_not_null_references_tenants():
    """AC 4: tenant_id is NOT NULL REFERENCES tenants."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    assert "NOT NULL REFERENCES tenants" in text


def test_migration_0010_occurred_at_timestamptz_not_null_default_now():
    """AC 5: occurred_at is TIMESTAMPTZ NOT NULL DEFAULT now()."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    assert "occurred_at" in text
    assert "TIMESTAMPTZ" in text.upper()
    assert "NOT NULL" in text.upper()
    assert "DEFAULT now()" in text or "DEFAULT NOW()" in text.upper()


def test_migration_0010_rls_enabled():
    """AC 6: ALTER TABLE usage_event ENABLE ROW LEVEL SECURITY."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    assert "ENABLE ROW LEVEL SECURITY" in text.upper()


def test_migration_0010_tenant_isolation_policy_using_and_with_check():
    """AC 6: tenant_isolation policy uses current_setting in both USING and WITH CHECK."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    assert "tenant_isolation" in text
    assert "current_setting" in text
    assert "USING" in text.upper()
    assert "WITH CHECK" in text.upper()
    assert "app.tenant_id" in text


def test_migration_0010_grant_select_insert_only_no_update_delete():
    """AC 7: GRANT on usage_event contains SELECT and INSERT but NOT UPDATE or DELETE."""
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    grant_lines = [
        line for line in text.splitlines()
        if line.upper().strip().startswith("GRANT") and "usage_event" in line.lower()
    ]
    assert grant_lines, "No GRANT statement targeting usage_event found in 0010_usage_quota.sql"
    for line in grant_lines:
        upper = line.upper()
        assert "UPDATE" not in upper, f"GRANT must not include UPDATE: {line!r}"
        assert "DELETE" not in upper, f"GRANT must not include DELETE: {line!r}"


def test_migration_0010_is_expand_only_no_drop_statements():
    """AC 8: migration contains no DROP TABLE, DROP COLUMN, or DROP DEFAULT as SQL statements.

    Comments may mention these phrases (e.g. '-- NO DROP TABLE'), so we check
    for the phrases only on non-comment lines.
    """
    text = (_MIGRATIONS_DIR / "0010_usage_quota.sql").read_text()
    # Strip comment lines before checking
    non_comment_lines = [
        line for line in text.splitlines()
        if not line.strip().startswith("--")
    ]
    non_comment_text = "\n".join(non_comment_lines).upper()
    assert "DROP TABLE" not in non_comment_text, "0010 must not DROP TABLE (as a statement)"
    assert "DROP COLUMN" not in non_comment_text, "0010 must not DROP COLUMN (as a statement)"
    assert "DROP DEFAULT" not in non_comment_text, "0010 must not DROP DEFAULT (as a statement)"


def test_migration_0010_idempotent_rerun():
    """AC 9: re-running migrations after 0010 is a no-op (ledger-guarded)."""
    from infra_twin.db.migrate import run_migrations
    applied = run_migrations(directory=_MIGRATIONS_DIR)
    names = [m for m in (applied or []) if "0010" in str(m)]
    assert names == [], f"0010 was re-applied: {names}"


def test_migration_0010_occurred_at_schema_not_null_default_now():
    """AC 5: information_schema confirms occurred_at is NOT NULL and default contains 'now'."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'usage_event' AND column_name = 'occurred_at'"
        ).fetchone()
    assert row is not None, "usage_event.occurred_at column not found in information_schema"
    assert row[0] == "NO", f"occurred_at must be NOT NULL; got is_nullable={row[0]}"
    assert row[1] is not None and "now" in row[1].lower(), (
        f"occurred_at default should contain 'now'; got: {row[1]}"
    )


def test_usage_event_has_no_bitemporal_columns():
    """AC 10: usage_event must NOT have valid_from or valid_to columns."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'usage_event' AND column_name IN ('valid_from', 'valid_to')"
        ).fetchall()
    cols = [r[0] for r in rows]
    assert cols == [], f"usage_event must not have bitemporal columns; found: {cols}"


# ===========================================================================
# DB module / exports (AC 11-15)
# ===========================================================================


def test_record_usage_in_db_all():
    """AC 11: record_usage is in infra_twin.db.__all__."""
    import infra_twin.db as db_pkg
    assert "record_usage" in db_pkg.__all__


def test_count_usage_in_window_in_db_all():
    """AC 11: count_usage_in_window is in infra_twin.db.__all__."""
    import infra_twin.db as db_pkg
    assert "count_usage_in_window" in db_pkg.__all__


def test_current_calendar_month_start_in_db_all():
    """AC 11: current_calendar_month_start is in infra_twin.db.__all__."""
    import infra_twin.db as db_pkg
    assert "current_calendar_month_start" in db_pkg.__all__


def test_current_calendar_month_start_returns_tz_aware_utc():
    """AC 14: current_calendar_month_start() returns a tz-aware datetime with tzinfo==timezone.utc."""
    result = current_calendar_month_start()
    assert result.tzinfo is not None, "return value must be tz-aware"
    assert result.tzinfo == timezone.utc, f"tzinfo must be timezone.utc; got {result.tzinfo}"


def test_current_calendar_month_start_day_1():
    """AC 14: current_calendar_month_start() returns day=1."""
    result = current_calendar_month_start()
    assert result.day == 1, f"day must be 1; got {result.day}"


def test_current_calendar_month_start_zero_time():
    """AC 14: current_calendar_month_start() returns hour=minute=second=microsecond=0."""
    result = current_calendar_month_start()
    assert result.hour == 0, f"hour must be 0; got {result.hour}"
    assert result.minute == 0, f"minute must be 0; got {result.minute}"
    assert result.second == 0, f"second must be 0; got {result.second}"
    assert result.microsecond == 0, f"microsecond must be 0; got {result.microsecond}"


def test_current_calendar_month_start_custom_now():
    """AC 14: current_calendar_month_start(now) uses the provided datetime."""
    now = datetime(2025, 7, 15, 14, 30, 0, tzinfo=timezone.utc)
    result = current_calendar_month_start(now)
    assert result == datetime(2025, 7, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_current_calendar_month_start_naive_input_returns_utc():
    """AC 14: naive input still produces tz-aware UTC output (tzinfo forced to utc)."""
    naive_now = datetime(2025, 3, 20, 10, 0, 0)
    result = current_calendar_month_start(naive_now)
    assert result.tzinfo == timezone.utc


def test_record_usage_returns_uuid(pool):
    """AC 12: record_usage returns a UUID."""
    tenant_id, _ = _make_editor_key("ru-returns-uuid")
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (tenant_id,)
        ).fetchone()
    api_key_id = row[0]

    with tenant_session(pool, tenant_id) as conn:
        result = record_usage(
            conn,
            tenant_id,
            api_key_id=api_key_id,
            method="GET",
            path="/cis",
            permission="read",
        )
    assert isinstance(result, UUID), f"record_usage must return UUID; got {type(result)}"


def test_record_usage_inserts_exactly_one_row(pool):
    """AC 12: record_usage inserts exactly one row per call."""
    tenant_id, _ = _make_editor_key("ru-one-row")
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (tenant_id,)
        ).fetchone()
    api_key_id = row[0]

    before = _count_usage_rows(tenant_id)
    with tenant_session(pool, tenant_id) as conn:
        record_usage(
            conn,
            tenant_id,
            api_key_id=api_key_id,
            method="POST",
            path="/connectors",
            permission="write",
        )
    after = _count_usage_rows(tenant_id)
    assert after - before == 1, f"record_usage must insert exactly 1 row; got {after - before}"


def test_record_usage_sql_omits_occurred_at_from_column_list():
    """AC 13: record_usage SQL does not name occurred_at in the INSERT column list (uses DEFAULT)."""
    import inspect
    import infra_twin.db.usage as usage_module
    src = inspect.getsource(usage_module.record_usage)
    # Find the INSERT INTO ... column list section
    lines = src.splitlines()
    in_insert = False
    column_section = []
    for line in lines:
        stripped = line.strip().strip('"').strip("'")
        if "INSERT INTO" in stripped.upper():
            in_insert = True
        if in_insert:
            column_section.append(stripped)
            if "VALUES" in stripped.upper():
                break
    column_list_text = " ".join(column_section)
    if "(" in column_list_text and "VALUES" in column_list_text.upper():
        col_part = column_list_text.split("VALUES")[0]
        assert "occurred_at" not in col_part, (
            "record_usage must not name occurred_at in the INSERT column list (uses DEFAULT); "
            f"found in: {col_part!r}"
        )


def test_count_usage_in_window_returns_correct_int(pool):
    """AC 15: count_usage_in_window returns int equal to number of usage rows >= since."""
    tenant_id, _ = _make_editor_key("count-window")
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (tenant_id,)
        ).fetchone()
    api_key_id = row[0]

    since = current_calendar_month_start()

    # Insert 3 rows
    for _ in range(3):
        with tenant_session(pool, tenant_id) as conn:
            record_usage(
                conn,
                tenant_id,
                api_key_id=api_key_id,
                method="GET",
                path="/cis",
                permission="read",
            )

    with tenant_session(pool, tenant_id) as conn:
        count = count_usage_in_window(conn, tenant_id, since)

    assert isinstance(count, int), f"count_usage_in_window must return int; got {type(count)}"
    assert count == 3, f"Expected 3 usage rows; got {count}"


def test_count_usage_in_window_excludes_prior_month_rows(pool):
    """EC 14: count_usage_in_window does not count rows with occurred_at before the window."""
    tenant_id, _ = _make_editor_key("count-prior-month")
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (tenant_id,)
        ).fetchone()
    api_key_id = row[0]

    # Insert a row with occurred_at in the prior month via admin (bypassing DEFAULT)
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(
            "INSERT INTO usage_event (tenant_id, api_key_id, method, path, permission, occurred_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (
                tenant_id,
                api_key_id,
                "GET",
                "/cis",
                "read",
                datetime(2020, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
            ),
        )
        conn.commit()

    since = current_calendar_month_start()
    with tenant_session(pool, tenant_id) as conn:
        count = count_usage_in_window(conn, tenant_id, since)

    # The row from 2020 should not be counted
    assert count == 0, (
        f"count_usage_in_window must exclude rows before window start; got {count}"
    )


# ===========================================================================
# API behavior (AC 16-21)
# ===========================================================================


def test_get_usage_without_key_returns_401(pool):
    """AC 16: GET /usage without an API key returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/usage")
    assert resp.status_code == 401


def test_get_usage_with_viewer_key_returns_200(pool):
    """AC 17: GET /usage with a valid viewer key returns 200."""
    _, viewer_key = _make_viewer_key("usage-viewer-200")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/usage", headers=_auth(viewer_key))
    assert resp.status_code == 200


def test_get_usage_returns_correct_json_keys(pool):
    """AC 17: GET /usage returns JSON with exactly the keys {quota, used_this_month, remaining, period_start}."""
    _, viewer_key = _make_viewer_key("usage-keys")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/usage", headers=_auth(viewer_key))
    assert resp.status_code == 200
    body = resp.json()
    expected_keys = {"quota", "used_this_month", "remaining", "period_start"}
    assert set(body.keys()) == expected_keys, (
        f"GET /usage response keys mismatch; expected {expected_keys}, got {set(body.keys())}"
    )


def test_get_usage_default_quota_is_100000(pool):
    """AC 18: fresh tenant with default quota returns quota==100000."""
    _, viewer_key = _make_viewer_key("usage-default-quota")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/usage", headers=_auth(viewer_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["quota"] == 100000, f"Expected default quota 100000; got {body['quota']}"


def test_get_usage_remaining_equals_quota_minus_used(pool):
    """AC 18: remaining == quota - used_this_month (never negative)."""
    _, viewer_key = _make_viewer_key("usage-remaining-calc")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/usage", headers=_auth(viewer_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["remaining"] == max(0, body["quota"] - body["used_this_month"]), (
        f"remaining must equal max(0, quota - used_this_month); got {body}"
    )


def test_get_usage_period_start_is_first_of_month(pool):
    """AC 17: period_start is an ISO 8601 string for the first of the current month."""
    _, viewer_key = _make_viewer_key("usage-period-start")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/usage", headers=_auth(viewer_key))
    assert resp.status_code == 200
    period_start_str = resp.json()["period_start"]
    period_start = datetime.fromisoformat(period_start_str)
    assert period_start.day == 1, f"period_start must be day=1; got {period_start}"
    assert period_start.hour == 0
    assert period_start.minute == 0
    assert period_start.second == 0


def test_post_tenants_with_quota_5_stores_quota(pool, monkeypatch):
    """AC 19: POST /tenants with monthly_request_quota=5 stores 5 in DB."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "quota-5-tenant", "monthly_request_quota": 5},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    tenant_id_str = resp.json().get("tenant_id")
    # Verify via admin connection that the stored quota is 5
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT monthly_request_quota FROM tenants WHERE tenant_id = %s",
            (UUID(tenant_id_str),),
        ).fetchone()
    assert row is not None, "Tenant row not found after POST /tenants"
    assert row[0] == 5, f"Expected stored quota=5; got {row[0]}"


def test_post_tenants_with_quota_zero_returns_422(pool, monkeypatch):
    """AC 20 / EC 16: POST /tenants with monthly_request_quota=0 returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "quota-zero", "monthly_request_quota": 0},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_post_tenants_with_quota_zero_no_rows_written(pool, monkeypatch):
    """AC 20 / EC 16: quota=0 -> 422 -> no tenants or api_keys rows written."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    client.post(
        "/tenants",
        json={"name": "quota-zero-norow", "monthly_request_quota": 0},
        headers=_admin_headers(),
    )
    with psycopg.connect(admin_dsn()) as conn:
        t_count = conn.execute(
            "SELECT count(*) FROM tenants WHERE name = 'quota-zero-norow'"
        ).fetchone()[0]
    assert t_count == 0, "No tenant row should be written when 422 is returned"


def test_post_tenants_with_negative_quota_returns_422(pool, monkeypatch):
    """AC 20 / EC 17: POST /tenants with monthly_request_quota=-1 returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "quota-neg", "monthly_request_quota": -1},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_post_tenants_with_negative_quota_no_rows_written(pool, monkeypatch):
    """EC 17: negative quota -> 422 -> no rows written."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    client.post(
        "/tenants",
        json={"name": "quota-neg-norow", "monthly_request_quota": -99},
        headers=_admin_headers(),
    )
    with psycopg.connect(admin_dsn()) as conn:
        t_count = conn.execute(
            "SELECT count(*) FROM tenants WHERE name = 'quota-neg-norow'"
        ).fetchone()[0]
    assert t_count == 0, "No tenant row should be written when 422 is returned (negative quota)"


def test_post_tenants_without_quota_yields_db_default(pool, monkeypatch):
    """AC 21: POST /tenants without monthly_request_quota stores 100000 (DB default)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "quota-omitted"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    tenant_id_str = resp.json().get("tenant_id")
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT monthly_request_quota FROM tenants WHERE tenant_id = %s",
            (UUID(tenant_id_str),),
        ).fetchone()
    assert row[0] == 100000, f"Expected DB default quota 100000; got {row[0]}"


def test_post_tenants_string_quota_returns_422(pool, monkeypatch):
    """AC 20: non-integer monthly_request_quota returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/tenants",
        json={"name": "quota-string", "monthly_request_quota": "five"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


# ===========================================================================
# Adversarial (a): each allowed request appends exactly one usage_event row (AC 22)
# ===========================================================================


def test_allowed_read_appends_exactly_one_usage_row(pool):
    """AC 22 / adversarial (a): GET /cis (viewer) appends exactly one usage_event row."""
    tenant_id, viewer_key = _make_viewer_key("adv-a-read")
    client = TestClient(create_app(pool=pool))

    before = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_auth(viewer_key))
    after = _count_usage_rows(tenant_id)

    assert resp.status_code == 200
    assert after - before == 1, (
        f"Expected exactly 1 new usage_event row; got {after - before}"
    )


def test_allowed_write_appends_exactly_one_usage_row(pool):
    """AC 22 / adversarial (a): POST /connectors (editor) appends exactly one usage_event row."""
    tenant_id, editor_key = _make_editor_key("adv-a-write")
    client = TestClient(create_app(pool=pool))

    before = _count_usage_rows(tenant_id)
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "adv-a-write"},
        headers=_auth(editor_key),
    )
    after = _count_usage_rows(tenant_id)

    assert resp.status_code == 201
    assert after - before == 1, (
        f"Expected exactly 1 new usage_event row; got {after - before}"
    )


def test_n_allowed_requests_append_exactly_n_usage_rows(pool):
    """AC 22 / adversarial (a): N allowed requests produce exactly N usage_event rows."""
    tenant_id, viewer_key = _make_viewer_key("adv-a-n-rows")
    client = TestClient(create_app(pool=pool))

    n = 3
    before = _count_usage_rows(tenant_id)
    for _ in range(n):
        resp = client.get("/cis", headers=_auth(viewer_key))
        assert resp.status_code == 200
    after = _count_usage_rows(tenant_id)

    assert after - before == n, (
        f"Expected exactly {n} new usage_event rows; got {after - before}"
    )


def test_allowed_requests_remaining_decreases(pool):
    """AC 22 / adversarial (a): after N requests, GET /usage remaining decreased by N (+1 for self)."""
    tenant_id, editor_key = _make_editor_key("adv-a-remaining")
    client = TestClient(create_app(pool=pool))

    # Get baseline remaining
    resp0 = client.get("/usage", headers=_auth(editor_key))
    assert resp0.status_code == 200
    remaining_0 = resp0.json()["remaining"]

    # Make 3 more requests
    n = 3
    for _ in range(n):
        client.get("/cis", headers=_auth(editor_key))

    # GET /usage is itself a metered request (+1), so after (n+1) total requests since baseline call
    # (1 baseline + n CIs + 1 final = n+2 total but we started AFTER baseline),
    # remaining should have decreased by n (CIs) + 1 (this GET /usage) = n+1
    resp_final = client.get("/usage", headers=_auth(editor_key))
    assert resp_final.status_code == 200
    remaining_final = resp_final.json()["remaining"]

    # We made: 1 baseline /usage + n CIs + 1 final /usage = n+2 total requests
    # remaining decreases by n+2 (but baseline was recorded too)
    # More precisely: from remaining_0 baseline, we used n+1 more requests (n CIs + final /usage)
    expected_remaining = remaining_0 - (n + 1)
    assert remaining_final == expected_remaining, (
        f"remaining should have decreased by {n+1} (n={n} CIs + 1 final /usage); "
        f"baseline={remaining_0}, final={remaining_final}, expected={expected_remaining}"
    )


# ===========================================================================
# Adversarial (b): quota exhaustion returns 429 with deny audit and NO usage row (AC 23)
# ===========================================================================


def test_quota_exhaustion_returns_429(pool):
    """AC 23 / adversarial (b): after Q allowed requests with quota Q, next returns 429."""
    quota = 2
    tenant_id, editor_key = _make_editor_key_with_quota("adv-b-429", quota)
    client = TestClient(create_app(pool=pool))

    # Use up the quota
    for i in range(quota):
        resp = client.get("/cis", headers=_auth(editor_key))
        assert resp.status_code == 200, f"Request {i+1} of {quota} should be allowed"

    # This one should be rejected
    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 429, (
        f"After {quota} requests with quota {quota}, next should be 429; got {resp.status_code}"
    )


def test_quota_exhaustion_returns_correct_body(pool):
    """AC 23 / adversarial (b): 429 response body is {detail: 'monthly request quota exceeded'}."""
    quota = 1
    _, editor_key = _make_editor_key_with_quota("adv-b-body", quota)
    client = TestClient(create_app(pool=pool))

    # Use up quota
    client.get("/cis", headers=_auth(editor_key))

    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 429
    assert resp.json() == {"detail": "monthly request quota exceeded"}, (
        f"429 body mismatch: {resp.json()}"
    )


def test_quota_exhaustion_writes_deny_audit_row_with_status_429(pool):
    """AC 23 / adversarial (b): 429 writes exactly one deny audit row with status_code=429."""
    quota = 1
    tenant_id, editor_key = _make_editor_key_with_quota("adv-b-audit", quota)
    client = TestClient(create_app(pool=pool))

    # Use up quota
    client.get("/cis", headers=_auth(editor_key))

    before_audit = _count_audit_rows(tenant_id)
    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 429
    after_audit = _count_audit_rows(tenant_id)

    assert after_audit - before_audit == 1, (
        f"Exactly 1 new audit row should be written on 429; got {after_audit - before_audit}"
    )
    rows = _get_audit_rows(tenant_id)
    deny_rows = [r for r in rows if r["decision"] == "deny" and r["status_code"] == 429]
    assert len(deny_rows) >= 1, (
        f"Expected at least 1 deny audit row with status_code=429; got {deny_rows}"
    )


def test_quota_exhaustion_writes_no_usage_row(pool):
    """AC 23 / adversarial (b): 429 writes NO new usage_event row."""
    quota = 1
    tenant_id, editor_key = _make_editor_key_with_quota("adv-b-no-usage", quota)
    client = TestClient(create_app(pool=pool))

    # Use up quota
    client.get("/cis", headers=_auth(editor_key))

    before_usage = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 429
    after_usage = _count_usage_rows(tenant_id)

    assert after_usage == before_usage, (
        f"429 must not write any usage_event row; before={before_usage}, after={after_usage}"
    )


def test_deny_429_audit_row_committed_before_raise(pool):
    """EC 10 / AC 30: deny-429 audit row committed even though request raises 429."""
    quota = 1
    tenant_id, editor_key = _make_editor_key_with_quota("adv-b-committed", quota)
    client = TestClient(create_app(pool=pool))

    # Use up quota
    client.get("/cis", headers=_auth(editor_key))

    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 429

    # Row must be immediately present in DB after the 429 response
    rows = _get_audit_rows(tenant_id)
    deny429_rows = [r for r in rows if r["decision"] == "deny" and r["status_code"] == 429]
    assert len(deny429_rows) >= 1, (
        "deny-429 audit row must be committed to DB before the exception propagates"
    )


# ===========================================================================
# EC 3 and EC 4 — quota boundary tests
# ===========================================================================


def test_quota_boundary_last_request_is_allowed(pool):
    """EC 3: used==quota-1 -> allowed; becomes the quota-th row (exactly one usage row added)."""
    quota = 3
    tenant_id, editor_key = _make_editor_key_with_quota("ec3-boundary", quota)
    client = TestClient(create_app(pool=pool))

    # Use quota-1 requests
    for _ in range(quota - 1):
        resp = client.get("/cis", headers=_auth(editor_key))
        assert resp.status_code == 200

    # This is the quota-th request (used was quota-1 < quota) -> should be allowed
    before = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_auth(editor_key))
    after = _count_usage_rows(tenant_id)

    assert resp.status_code == 200, (
        f"The {quota}-th request (last allowed) should be 200; got {resp.status_code}"
    )
    assert after - before == 1, f"One usage row should be written for the boundary request"


def test_quota_boundary_first_over_quota_is_429(pool):
    """EC 4: used==quota -> 429, deny audit (429), no usage row."""
    quota = 2
    tenant_id, editor_key = _make_editor_key_with_quota("ec4-over-quota", quota)
    client = TestClient(create_app(pool=pool))

    # Exhaust quota
    for _ in range(quota):
        resp = client.get("/cis", headers=_auth(editor_key))
        assert resp.status_code == 200

    # Next one is the (quota+1)-th -> 429
    before_usage = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_auth(editor_key))
    after_usage = _count_usage_rows(tenant_id)

    assert resp.status_code == 429, f"Request at used==quota should be 429; got {resp.status_code}"
    assert after_usage == before_usage, "No usage row should be written on 429"


def test_quota_1_first_request_allowed_second_is_429(pool):
    """EC 5: quota=1 -> first request allowed (writes row), second gets 429."""
    tenant_id, editor_key = _make_editor_key_with_quota("ec5-quota-1", 1)
    client = TestClient(create_app(pool=pool))

    resp1 = client.get("/cis", headers=_auth(editor_key))
    assert resp1.status_code == 200, f"First request should be allowed; got {resp1.status_code}"

    resp2 = client.get("/cis", headers=_auth(editor_key))
    assert resp2.status_code == 429, f"Second request should be 429; got {resp2.status_code}"


# ===========================================================================
# Adversarial (c): 403 RBAC denial does NOT consume quota (AC 24)
# ===========================================================================


def test_viewer_403_on_write_does_not_consume_quota(pool):
    """AC 24 / adversarial (c): viewer POST /connectors returns 403 and writes ZERO usage rows."""
    tenant_id, viewer_key = _make_viewer_key("adv-c-viewer-403")
    client = TestClient(create_app(pool=pool))

    before = _count_usage_rows(tenant_id)
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "adv-c-test"},
        headers=_auth(viewer_key),
    )
    after = _count_usage_rows(tenant_id)

    assert resp.status_code == 403
    assert after == before, (
        f"403 RBAC denial must write zero usage_event rows; before={before}, after={after}"
    )


def test_viewer_403_writes_deny_audit_row_with_status_403(pool):
    """AC 24 / adversarial (c): viewer 403 writes deny audit row with status_code=403 (not 429)."""
    tenant_id, viewer_key = _make_viewer_key("adv-c-audit-403")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "c-audit-test"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403

    rows = _get_audit_rows(tenant_id)
    deny403_rows = [r for r in rows if r["decision"] == "deny" and r["status_code"] == 403]
    assert len(deny403_rows) >= 1, (
        "Expected at least one deny audit row with status_code=403; "
        f"got rows: {rows}"
    )


def test_rbac_403_deny_audit_row_is_403_not_429(pool):
    """AC 29: existing 403 deny rows remain status_code=403, never 429."""
    tenant_id, viewer_key = _make_viewer_key("adv-c-not-429")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "not-429-check"},
        headers=_auth(viewer_key),
    )

    rows = _get_audit_rows(tenant_id)
    deny_rows = [r for r in rows if r["decision"] == "deny"]
    for row in deny_rows:
        assert row["status_code"] == 403, (
            f"RBAC deny row should have status_code=403, not 429; got {row}"
        )


def test_rbac_403_no_usage_row_multiple_denials(pool):
    """AC 24: multiple RBAC 403 denials accumulate zero usage rows."""
    tenant_id, viewer_key = _make_viewer_key("adv-c-multi-deny")
    client = TestClient(create_app(pool=pool))

    for _ in range(5):
        resp = client.post(
            "/connectors",
            json={"type": "aws", "display_name": "multi-deny"},
            headers=_auth(viewer_key),
        )
        assert resp.status_code == 403

    usage_count = _count_usage_rows(tenant_id)
    assert usage_count == 0, (
        f"Multiple 403 RBAC denials must write zero usage rows; got {usage_count}"
    )


# ===========================================================================
# Adversarial (d): cross-tenant isolation (AC 25)
# ===========================================================================


def test_cross_tenant_usage_count_isolation(pool):
    """AC 25 / adversarial (d): tenant A's count_usage_in_window is unaffected by tenant B's rows."""
    tenant_a, key_a = _make_editor_key("adv-d-tenant-a")
    tenant_b, key_b = _make_editor_key("adv-d-tenant-b")
    client = TestClient(create_app(pool=pool))

    # Tenant B makes many requests
    for _ in range(10):
        client.get("/cis", headers=_auth(key_b))

    # Tenant A makes k requests
    k = 2
    for _ in range(k):
        client.get("/cis", headers=_auth(key_a))

    # Tenant A's count should be exactly k
    since = current_calendar_month_start()
    with tenant_session(pool, tenant_a) as conn:
        count_a = count_usage_in_window(conn, tenant_a, since)

    assert count_a == k, (
        f"Tenant A's count should be {k}; got {count_a} "
        f"(tenant B's rows must not be visible via RLS)"
    )


def test_cross_tenant_get_usage_isolation(pool):
    """AC 25 / adversarial (d): tenant A's GET /usage used_this_month is unaffected by tenant B."""
    tenant_a, key_a = _make_editor_key("adv-d-get-usage-a")
    tenant_b, key_b = _make_editor_key("adv-d-get-usage-b")
    client = TestClient(create_app(pool=pool))

    # Tenant B makes many requests
    for _ in range(20):
        client.get("/cis", headers=_auth(key_b))

    # Tenant A makes 1 allowed request before checking /usage
    client.get("/cis", headers=_auth(key_a))

    # GET /usage for tenant A
    resp_a = client.get("/usage", headers=_auth(key_a))
    assert resp_a.status_code == 200
    body_a = resp_a.json()

    # used_this_month for A should include:
    # 1 GET /cis + 1 GET /usage = 2 rows
    # and NOT include any of tenant B's 20 rows
    assert body_a["used_this_month"] == 2, (
        f"Tenant A's used_this_month should be 2 (1 CIS + 1 /usage); got {body_a['used_this_month']}. "
        f"Tenant B's rows must not be counted."
    )


def test_cross_tenant_admin_row_count_isolation():
    """AC 25 / adversarial (d): admin count confirms each tenant's usage rows are separate."""
    tenant_a, _ = _make_editor_key("adv-d-admin-a")
    tenant_b, _ = _make_editor_key("adv-d-admin-b")

    # Insert usage rows for B via admin
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (tenant_b,)
        ).fetchone()
        api_key_id_b = row[0]
        for _ in range(5):
            conn.execute(
                "INSERT INTO usage_event (tenant_id, api_key_id, method, path, permission) "
                "VALUES (%s, %s, %s, %s, %s)",
                (tenant_b, api_key_id_b, "GET", "/cis", "read"),
            )
        conn.commit()

    # Tenant A's usage count must remain 0
    count_a = _count_usage_rows(tenant_a)
    assert count_a == 0, (
        f"Tenant A should have 0 usage rows; got {count_a} "
        f"(tenant B's rows must not bleed into A's count)"
    )


def test_cross_tenant_remaining_unaffected_by_other_tenant(pool):
    """AC 25 / adversarial (d): tenant A's remaining is unaffected by tenant B's usage.

    Since GET /usage is self-metered, the first call already reflects 1 consumed slot
    (used_this_month=1 in the response body, because the metered insert commits before
    the handler reads the count). The second GET /usage call consumes 1 more slot, so
    the final remaining == initial_remaining - 1.
    """
    tenant_a, key_a = _make_editor_key("adv-d-remaining-a")
    tenant_b, key_b = _make_editor_key("adv-d-remaining-b")
    client = TestClient(create_app(pool=pool))

    # Check tenant A's initial remaining.
    # This call is self-metered: the row is already counted in the response.
    resp_a0 = client.get("/usage", headers=_auth(key_a))
    assert resp_a0.status_code == 200
    initial_remaining = resp_a0.json()["remaining"]

    # Tenant B uses many requests (not A)
    for _ in range(50):
        client.get("/cis", headers=_auth(key_b))

    # Tenant A checks remaining again — this second /usage call consumes 1 more slot
    resp_a1 = client.get("/usage", headers=_auth(key_a))
    body_a1 = resp_a1.json()

    # A's remaining decreased only by 1 more (this second /usage call).
    # The first call already "consumed itself" so initial_remaining already reflects that.
    expected = initial_remaining - 1
    assert body_a1["remaining"] == expected, (
        f"Tenant A's remaining should be {expected} (decreased only by A's own second request); "
        f"got {body_a1['remaining']}. Tenant B's 50 requests must not affect A."
    )
    # Additional assertion: B's 50 rows must not appear in A's count
    assert body_a1["used_this_month"] == 2, (
        f"Tenant A's used_this_month should be 2 (2 /usage calls); "
        f"got {body_a1['used_this_month']}. B's rows must not be counted."
    )


# ===========================================================================
# Adversarial (e): app role cannot UPDATE or DELETE usage_event rows (AC 26)
# ===========================================================================


def test_app_role_cannot_update_usage_event_row(pool):
    """AC 26 / adversarial (e): UPDATE usage_event as app role raises permission-denied (42501)."""
    tenant_id, editor_key = _make_editor_key("adv-e-update")
    client = TestClient(create_app(pool=pool))

    # Generate a usage row via a real request
    client.get("/cis", headers=_auth(editor_key))
    assert _count_usage_rows(tenant_id) >= 1, "Expected at least one usage row to UPDATE"

    # Attempt UPDATE as app role
    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "UPDATE usage_event SET path = '/tampered' WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()

    err_msg = str(exc_info.value).lower()
    assert (
        "permission denied" in err_msg
        or "insufficient privilege" in err_msg
        or "42501" in err_msg
    ), f"Expected permission-denied error (42501); got: {exc_info.value}"


def test_app_role_update_usage_event_row_unchanged():
    """AC 26 / adversarial (e): after failed UPDATE, usage_event row is unchanged."""
    tenant_id, _ = _make_editor_key("adv-e-update-unchanged")
    # Insert a usage row via admin
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (tenant_id,)
        ).fetchone()
        api_key_id = row[0]
        usage_row = conn.execute(
            "INSERT INTO usage_event (tenant_id, api_key_id, method, path, permission) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING usage_id, path",
            (tenant_id, api_key_id, "GET", "/original-path", "read"),
        ).fetchone()
        conn.commit()
    usage_id = usage_row[0]
    original_path = usage_row[1]

    # Attempt UPDATE (will fail)
    try:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "UPDATE usage_event SET path = '/tampered' WHERE usage_id = %s",
                (usage_id,),
            )
            conn.commit()
    except psycopg.Error:
        pass  # expected

    # Row should be unchanged
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT path FROM usage_event WHERE usage_id = %s", (usage_id,)
        ).fetchone()
    assert row is not None, "Usage row should still exist"
    assert row[0] == original_path, (
        f"Row should be unchanged; expected '{original_path}', got '{row[0]}'"
    )


def test_app_role_cannot_delete_usage_event_row(pool):
    """AC 26 / adversarial (e): DELETE FROM usage_event as app role raises permission-denied (42501)."""
    tenant_id, editor_key = _make_editor_key("adv-e-delete")
    client = TestClient(create_app(pool=pool))

    # Generate a usage row
    client.get("/cis", headers=_auth(editor_key))
    assert _count_usage_rows(tenant_id) >= 1, "Expected at least one usage row to DELETE"

    # Attempt DELETE as app role
    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "DELETE FROM usage_event WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()

    err_msg = str(exc_info.value).lower()
    assert (
        "permission denied" in err_msg
        or "insufficient privilege" in err_msg
        or "42501" in err_msg
    ), f"Expected permission-denied error (42501); got: {exc_info.value}"


def test_app_role_delete_usage_event_row_still_exists():
    """AC 26 / adversarial (e): after failed DELETE, usage_event row still exists (verified via admin)."""
    tenant_id, _ = _make_editor_key("adv-e-delete-exists")
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (tenant_id,)
        ).fetchone()
        api_key_id = row[0]
        usage_row = conn.execute(
            "INSERT INTO usage_event (tenant_id, api_key_id, method, path, permission) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING usage_id",
            (tenant_id, api_key_id, "GET", "/to-delete", "read"),
        ).fetchone()
        conn.commit()
    usage_id = usage_row[0]

    # Attempt DELETE (will fail)
    try:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "DELETE FROM usage_event WHERE usage_id = %s", (usage_id,)
            )
            conn.commit()
    except psycopg.Error:
        pass  # expected

    # Row must still exist
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM usage_event WHERE usage_id = %s", (usage_id,)
        ).fetchone()
    assert row[0] == 1, "Usage row should still exist after failed DELETE"


# ===========================================================================
# EC 6 — default quota 100000 applied to pre-existing tenants
# ===========================================================================


def test_existing_tenant_gets_default_quota():
    """EC 6: a tenant inserted before migration 0010 gets quota=100000 via NOT NULL DEFAULT."""
    # Insert a tenant directly (simulating pre-migration row)
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id",
            ("pre-migration-tenant",),
        ).fetchone()
        tenant_id = row[0]
        conn.commit()

    quota = _get_stored_quota(tenant_id)
    assert quota == 100000, (
        f"Tenant inserted without quota should get DB default 100000; got {quota}"
    )


# ===========================================================================
# EC 7 — GET /usage self-metering
# ===========================================================================


def test_get_usage_self_metering(pool):
    """EC 7 / AC 22: GET /usage itself is metered; used_this_month includes the row for that call."""
    tenant_id, viewer_key = _make_viewer_key("ec7-self-meter")
    client = TestClient(create_app(pool=pool))

    # No usage rows yet
    before = _count_usage_rows(tenant_id)
    assert before == 0, "Expected zero usage rows before first call"

    resp = client.get("/usage", headers=_auth(viewer_key))
    assert resp.status_code == 200
    body = resp.json()

    # The row for the GET /usage call itself should be committed before handler reads count
    assert body["used_this_month"] == 1, (
        f"used_this_month should be 1 (includes the self-row); got {body['used_this_month']}"
    )
    after = _count_usage_rows(tenant_id)
    assert after == 1, f"Expected exactly 1 usage row after GET /usage; got {after}"


def test_get_usage_self_metering_decrements_remaining(pool):
    """EC 7: GET /usage remaining accounts for the row recorded for that very request."""
    _, viewer_key = _make_viewer_key("ec7-remaining")
    client = TestClient(create_app(pool=pool))

    resp = client.get("/usage", headers=_auth(viewer_key))
    assert resp.status_code == 200
    body = resp.json()
    quota = body["quota"]
    used = body["used_this_month"]
    remaining = body["remaining"]

    assert used >= 1, "used_this_month must be at least 1 (the self-row)"
    assert remaining == max(0, quota - used)


# ===========================================================================
# EC 8 — exactly-once insertion per allowed request
# ===========================================================================


def test_exactly_one_usage_row_per_allowed_request(pool):
    """EC 8: two allowed requests produce exactly two usage_event rows (one each)."""
    tenant_id, viewer_key = _make_viewer_key("ec8-exact-once")
    client = TestClient(create_app(pool=pool))

    before = _count_usage_rows(tenant_id)
    client.get("/cis", headers=_auth(viewer_key))
    client.get("/cis", headers=_auth(viewer_key))
    after = _count_usage_rows(tenant_id)

    assert after - before == 2, (
        f"Two allowed requests must produce exactly 2 usage rows; got {after - before}"
    )


# ===========================================================================
# EC 9 — atomicity: usage row and allow audit row commit together
# ===========================================================================


def test_allow_path_writes_usage_and_audit_atomically(pool):
    """EC 9: an allowed request writes exactly one usage row AND one allow audit row (both or neither)."""
    tenant_id, viewer_key = _make_viewer_key("ec9-atomic")
    client = TestClient(create_app(pool=pool))

    before_usage = _count_usage_rows(tenant_id)
    before_audit = _count_audit_rows(tenant_id)

    resp = client.get("/cis", headers=_auth(viewer_key))
    assert resp.status_code == 200

    after_usage = _count_usage_rows(tenant_id)
    after_audit = _count_audit_rows(tenant_id)

    assert after_usage - before_usage == 1, (
        f"Expected 1 new usage row; got {after_usage - before_usage}"
    )
    assert after_audit - before_audit == 1, (
        f"Expected 1 new audit row; got {after_audit - before_audit}"
    )
    rows = _get_audit_rows(tenant_id)
    allow_rows = [r for r in rows if r["decision"] == "allow"]
    assert len(allow_rows) >= 1, "Expected at least one allow audit row"


# ===========================================================================
# EC 21 — permission value on usage rows
# ===========================================================================


def test_usage_row_permission_is_read_for_read_request(pool):
    """EC 21: usage row for a GET request has permission='read', not NULL."""
    tenant_id, viewer_key = _make_viewer_key("ec21-perm-read")
    client = TestClient(create_app(pool=pool))

    client.get("/cis", headers=_auth(viewer_key))

    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT permission FROM usage_event WHERE tenant_id = %s "
            "AND path = '/cis' AND method = 'GET'",
            (tenant_id,),
        ).fetchall()
    assert len(rows) >= 1, "Expected at least one usage row for /cis GET"
    for row in rows:
        assert row[0] == "read", f"permission should be 'read'; got {row[0]}"


def test_usage_row_permission_is_write_for_write_request(pool):
    """EC 21: usage row for a POST /connectors request has permission='write', not NULL."""
    tenant_id, editor_key = _make_editor_key("ec21-perm-write")
    client = TestClient(create_app(pool=pool))

    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ec21-write"},
        headers=_auth(editor_key),
    )

    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT permission FROM usage_event WHERE tenant_id = %s "
            "AND path = '/connectors' AND method = 'POST'",
            (tenant_id,),
        ).fetchall()
    assert len(rows) >= 1, "Expected at least one usage row for POST /connectors"
    for row in rows:
        assert row[0] == "write", f"permission should be 'write'; got {row[0]}"


# ===========================================================================
# EC 22 — non-gated routes write zero usage rows
# ===========================================================================


def test_get_health_writes_no_usage_rows(pool, monkeypatch):
    """EC 22: GET /health is not gated; writes zero usage rows."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    client.get("/health")
    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM usage_event").fetchone()[0]
    assert total == 0, f"GET /health must not write usage rows; got {total}"


def test_post_tenants_writes_no_usage_rows(pool, monkeypatch):
    """EC 22: POST /tenants (bootstrap-admin gated) writes zero usage rows."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    client = TestClient(create_app(pool=pool))
    client.post(
        "/tenants",
        json={"name": "ec22-unmetered"},
        headers=_admin_headers(),
    )
    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM usage_event").fetchone()[0]
    assert total == 0, f"POST /tenants must not write usage rows; got {total}"


# ===========================================================================
# Wiring / non-regression (AC 27-30)
# ===========================================================================


def test_provision_tenant_without_quota_uses_db_default():
    """AC 27: provision_tenant(conn, name) omits monthly_request_quota column, DB default applies."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "prov-no-quota")
    quota = _get_stored_quota(issued.tenant_id)
    assert quota == 100000, (
        f"provision_tenant without quota should use DB default 100000; got {quota}"
    )


def test_provision_tenant_with_none_quota_uses_db_default():
    """AC 27: provision_tenant(conn, name, monthly_request_quota=None) uses DB default."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "prov-none-quota", monthly_request_quota=None)
    quota = _get_stored_quota(issued.tenant_id)
    assert quota == 100000, (
        f"provision_tenant with None quota should use DB default 100000; got {quota}"
    )


def test_provision_tenant_with_viewer_role_still_works():
    """AC 27: provision_tenant(conn, name, role=Role.viewer) still works unchanged."""
    with psycopg.connect(admin_dsn()) as conn:
        issued = provision_tenant(conn, "prov-viewer", role=Role.viewer)
    assert issued.role == Role.viewer


def test_usage_event_in_data_tables_conftest():
    """AC 28: _DATA_TABLES in conftest.py includes 'usage_event'."""
    conftest_path = pathlib.Path(__file__).parent / "conftest.py"
    text = conftest_path.read_text()
    assert "usage_event" in text, (
        "_DATA_TABLES in conftest.py must include 'usage_event' for per-test truncation"
    )


def test_401_writes_no_usage_rows(pool):
    """AC 29: unauthenticated request (401) writes zero usage rows."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis")
    assert resp.status_code == 401

    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM usage_event").fetchone()[0]
    assert total == 0, f"401 must not write any usage rows; got {total}"


def test_401_invalid_key_writes_no_usage_rows(pool):
    """AC 29: invalid key (401) writes zero usage rows."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer itw_bogus.invalidsecret"})
    assert resp.status_code == 401

    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM usage_event").fetchone()[0]
    assert total == 0, f"401 (invalid key) must not write any usage rows; got {total}"


def test_existing_rbac_tests_unaffected_by_metering_403_not_429(pool):
    """AC 29: existing RBAC 403 deny remains 403 (not 429) after metering addition."""
    tenant_id, viewer_key = _make_viewer_key("ac29-rbac-unaffected")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "rbac-check"},
        headers=_auth(viewer_key),
    )
    # Must still be 403, never 429
    assert resp.status_code == 403, (
        f"Viewer write must still return 403 (not 429); got {resp.status_code}"
    )
    assert resp.json() == {"detail": "insufficient permissions"}


def test_allow_audit_row_has_correct_status_code(pool):
    """AC 29: allow audit row for GET /cis still has status_code=200 after metering."""
    tenant_id, viewer_key = _make_viewer_key("ac29-allow-status")
    client = TestClient(create_app(pool=pool))

    resp = client.get("/cis", headers=_auth(viewer_key))
    assert resp.status_code == 200

    rows = _get_audit_rows(tenant_id)
    allow_rows = [r for r in rows if r["decision"] == "allow" and r["path"] == "/cis"]
    assert len(allow_rows) >= 1, "Expected at least one allow audit row for GET /cis"
    for row in allow_rows:
        assert row["status_code"] == 200, (
            f"Allow audit row for GET /cis should have status_code=200; got {row['status_code']}"
        )


def test_deny_429_audit_row_has_correct_detail(pool):
    """AC 30: 429 deny audit row committed before raise; body includes correct detail."""
    quota = 1
    tenant_id, editor_key = _make_editor_key_with_quota("ac30-audit-detail", quota)
    client = TestClient(create_app(pool=pool))

    # Exhaust quota
    client.get("/cis", headers=_auth(editor_key))
    # Next request -> 429
    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 429

    # Check deny row is immediately in DB (committed before raise)
    rows = _get_audit_rows(tenant_id)
    deny429_rows = [r for r in rows if r["decision"] == "deny" and r["status_code"] == 429]
    assert len(deny429_rows) >= 1, (
        "deny-429 audit row must be in DB immediately after 429 response "
        "(committed before exception propagated)"
    )
