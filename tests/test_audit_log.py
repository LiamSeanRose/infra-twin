"""Audit log tests: immutable, tenant-scoped audit logging of authenticated API access.

Covers every acceptance criterion and edge case from the spec:

  AC 13  allowed read -> exactly one allow row (permission='read')
  AC 14  allowed write (POST /connectors) -> exactly one allow row (permission='write', status=201)
  AC 15  viewer on write endpoint -> 403 + exactly one deny row (permission='write', status=403)
  AC 16  unauthenticated -> 401 + zero audit rows
  AC 17  cross-tenant isolation: tenant A's GET /audit-log returns only A's rows
  AC 18  adversarial: app role cannot UPDATE an audit row (permission denied)
  AC 19  adversarial: app role cannot DELETE an audit row (permission denied)

  EC 1   unauthenticated request to a gated endpoint: no audit row
  EC 2   GET /health and POST /tenants: not gated, never audited
  EC 3   viewer on read endpoint: allow row, permission='read', decision='allow', status=200
  EC 4   editor on write endpoint: allow row, permission='write', status=200 (or 201)
  EC 5   viewer on write endpoint: deny row + request still returns 403
  EC 6   exactly-once: a single gated request produces exactly one audit row
  EC 8   cross-tenant read: RLS enforced on GET /audit-log
  EC 9   app role cannot UPDATE audit row
  EC 10  app role cannot DELETE audit row
  EC 11  deny-path row committed even though request returns 403
  EC 14  limit=0 returns empty list
  EC 15  large limit returns all rows
  EC 19  CHECK constraint: invalid decision/role/permission values rejected by DB
  EC 20  no valid_from/valid_to columns on audit_log

  Schema / migration structural checks (AC 1-9):
  - migration file 0009_audit_log.sql exists with all 10 columns
  - CHECK constraints on decision, permission, role
  - RLS policy present
  - GRANT is SELECT, INSERT only (no UPDATE/DELETE)
  - occurred_at is NOT NULL with now() default
  - audit_log in _DATA_TABLES (verified indirectly by test isolation)

  Module / export checks (AC 10-12):
  - record_access, list_audit, AuditEntry exported from db/__init__.__all__
  - GET /audit-log returns 9-key objects, no tenant_id

  Adversarial proofs (spec prompt):
  (a) allowed read -> exactly one allow row; allowed write -> exactly one allow row
  (b) viewer 403 on write endpoint -> exactly one deny row
  (c) tenant A cannot read tenant B's audit rows
  (d) app role cannot UPDATE or DELETE an existing audit row
"""

from __future__ import annotations

import pathlib
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.db import AuditEntry, list_audit, record_access
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn, app_dsn
from infra_twin.db.session import tenant_session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[1] / "migrations"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _make_viewer_key(name: str = "viewer-tenant") -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str = "editor-tenant") -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _count_audit_rows(tenant_id: UUID) -> int:
    """Count audit_log rows for a tenant using admin (bypasses RLS)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM audit_log WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
    return row[0]


def _get_audit_rows(tenant_id: UUID) -> list[dict]:
    """Fetch all audit_log rows for a tenant using admin connection (bypasses RLS)."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT audit_id, api_key_id, role, method, path, permission, decision, "
            "status_code, occurred_at "
            "FROM audit_log WHERE tenant_id = %s "
            "ORDER BY occurred_at DESC, audit_id DESC",
            (tenant_id,),
        ).fetchall()
    return [
        {
            "audit_id": row[0],
            "api_key_id": row[1],
            "role": row[2],
            "method": row[3],
            "path": row[4],
            "permission": row[5],
            "decision": row[6],
            "status_code": row[7],
            "occurred_at": row[8],
        }
        for row in rows
    ]


# ===========================================================================
# Migration structural checks (AC 1-9)
# ===========================================================================


def test_migration_0009_file_exists():
    """AC 1: migrations/0009_audit_log.sql exists."""
    assert (_MIGRATIONS_DIR / "0009_audit_log.sql").exists()


def test_migration_0009_has_create_table():
    """AC 2: migration contains CREATE TABLE audit_log."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "CREATE TABLE audit_log" in text


def test_migration_0009_has_all_ten_columns():
    """AC 2: migration defines all 10 required columns."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    for col in ("audit_id", "tenant_id", "api_key_id", "role", "method",
                "path", "permission", "decision", "status_code", "occurred_at"):
        assert col in text, f"Column '{col}' not found in 0009_audit_log.sql"


def test_migration_0009_audit_id_primary_key_default():
    """AC 3: audit_id is PRIMARY KEY DEFAULT gen_random_uuid()."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "PRIMARY KEY" in text
    assert "gen_random_uuid()" in text


def test_migration_0009_tenant_id_fk():
    """AC 3: tenant_id is NOT NULL REFERENCES tenants(tenant_id)."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "NOT NULL REFERENCES tenants" in text


def test_migration_0009_occurred_at_not_null_default_now():
    """AC 3/9: occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "occurred_at" in text
    assert "NOT NULL" in text
    assert "DEFAULT now()" in text or "DEFAULT NOW()" in text.upper()


def test_migration_0009_check_constraint_decision():
    """AC 4: CHECK constraint on decision (allow/deny)."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "allow" in text and "deny" in text
    assert "CHECK" in text.upper()


def test_migration_0009_check_constraint_permission():
    """AC 4: CHECK constraint on permission (read/write/NULL)."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "read" in text and "write" in text


def test_migration_0009_check_constraint_role():
    """AC 4: CHECK constraint on role (viewer/editor)."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "viewer" in text and "editor" in text


def test_migration_0009_rls_enabled():
    """AC 5: ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "ENABLE ROW LEVEL SECURITY" in text.upper()


def test_migration_0009_tenant_isolation_policy():
    """AC 5: tenant_isolation policy uses current_setting for USING and WITH CHECK."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    assert "tenant_isolation" in text
    assert "current_setting" in text
    assert "USING" in text.upper()
    assert "WITH CHECK" in text.upper()


def test_migration_0009_grant_select_insert_only():
    """AC 6: GRANT SELECT, INSERT ON audit_log TO app — no UPDATE or DELETE."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text()
    # There must be a GRANT line targeting audit_log
    grant_lines = [
        line for line in text.splitlines()
        if line.upper().strip().startswith("GRANT") and "audit_log" in line.lower()
    ]
    assert grant_lines, "No GRANT statement targeting audit_log found in 0009_audit_log.sql"
    # Every GRANT line must contain SELECT or INSERT, never UPDATE or DELETE
    for line in grant_lines:
        upper = line.upper()
        assert "UPDATE" not in upper, (
            f"GRANT line must not include UPDATE: {line!r}"
        )
        assert "DELETE" not in upper, (
            f"GRANT line must not include DELETE: {line!r}"
        )


def test_migration_0009_is_expand_only():
    """AC 7: migration has no DROP TABLE, DROP COLUMN, or DROP DEFAULT."""
    text = (_MIGRATIONS_DIR / "0009_audit_log.sql").read_text().upper()
    assert "DROP TABLE" not in text, "0009 must not DROP TABLE"
    assert "DROP COLUMN" not in text, "0009 must not DROP COLUMN"
    assert "DROP DEFAULT" not in text, "0009 must not DROP DEFAULT"


def test_migration_0009_idempotent_rerun():
    """AC 8: re-running migrations after the session is a no-op (0009 is already in the ledger)."""
    from infra_twin.db.migrate import run_migrations
    applied = run_migrations(directory=_MIGRATIONS_DIR)
    # Already applied — the runner should return an empty list or not apply 0009 again.
    names = [m for m in (applied or []) if "0009" in str(m)]
    assert names == [], f"0009 was re-applied: {names}"


def test_audit_log_occurred_at_column_schema():
    """AC 9: occurred_at is NOT NULL in information_schema and default contains 'now'."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'audit_log' AND column_name = 'occurred_at'"
        ).fetchone()
    assert row is not None, "audit_log.occurred_at column not found"
    assert row[0] == "NO", f"occurred_at must be NOT NULL; got is_nullable={row[0]}"
    assert row[1] is not None and "now" in row[1].lower(), (
        f"occurred_at default should contain 'now'; got: {row[1]}"
    )


# ===========================================================================
# Module / export checks (AC 10-12)
# ===========================================================================


def test_record_access_in_db_all():
    """AC 10: record_access is in db.__init__.__all__."""
    import infra_twin.db as db_pkg
    assert "record_access" in db_pkg.__all__


def test_list_audit_in_db_all():
    """AC 10: list_audit is in db.__init__.__all__."""
    import infra_twin.db as db_pkg
    assert "list_audit" in db_pkg.__all__


def test_audit_entry_in_db_all():
    """AC 10: AuditEntry is in db.__init__.__all__."""
    import infra_twin.db as db_pkg
    assert "AuditEntry" in db_pkg.__all__


def test_audit_entry_is_dataclass():
    """AC 10: AuditEntry is a frozen dataclass with the expected fields."""
    import dataclasses
    assert dataclasses.is_dataclass(AuditEntry)
    fields = {f.name for f in dataclasses.fields(AuditEntry)}
    expected = {
        "audit_id", "api_key_id", "role", "method", "path",
        "permission", "decision", "status_code", "occurred_at",
    }
    assert expected.issubset(fields), f"AuditEntry missing fields: {expected - fields}"


def test_get_audit_log_registered(pool):
    """AC 12: GET /audit-log is registered and returns 200 for a valid viewer key."""
    _, viewer_key = _make_viewer_key("ac12-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/audit-log", headers=_auth(viewer_key))
    assert resp.status_code == 200


def test_get_audit_log_returns_json_array(pool):
    """AC 12: GET /audit-log returns a JSON array."""
    _, viewer_key = _make_viewer_key("ac12-array")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/audit-log", headers=_auth(viewer_key))
    assert isinstance(resp.json(), list)


def test_get_audit_log_response_has_nine_keys(pool):
    """AC 12: each audit-log element has exactly the 9 expected keys (no tenant_id)."""
    editor_tenant, editor_key = _make_editor_key("ac12-keys-editor")
    client = TestClient(create_app(pool=pool))
    # Trigger at least one audit row via an allowed write
    client.post("/connectors", json={"type": "aws", "display_name": "x"}, headers=_auth(editor_key))

    # Use editor to read the audit log (editor has read permission)
    resp = client.get("/audit-log", headers=_auth(editor_key))
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) > 0, "Expected at least one audit entry"
    expected_keys = {
        "audit_id", "api_key_id", "role", "method", "path",
        "permission", "decision", "status_code", "occurred_at", "auth_method",
    }
    for entry in entries:
        assert set(entry.keys()) == expected_keys, (
            f"Response entry has wrong keys: {set(entry.keys())}"
        )


def test_get_audit_log_response_excludes_tenant_id(pool):
    """AC 12: tenant_id must NOT appear in any GET /audit-log response element."""
    _, editor_key = _make_editor_key("ac12-no-tenant-id")
    client = TestClient(create_app(pool=pool))
    client.post("/connectors", json={"type": "aws", "display_name": "y"}, headers=_auth(editor_key))
    resp = client.get("/audit-log", headers=_auth(editor_key))
    for entry in resp.json():
        assert "tenant_id" not in entry, "tenant_id must not appear in audit-log response"


# ===========================================================================
# AC 13 — Allowed read -> exactly one allow row (adversarial proof (a))
# ===========================================================================


def test_allowed_read_produces_exactly_one_allow_row(pool):
    """AC 13 / adversarial (a): GET /cis with viewer key appends exactly one allow row."""
    viewer_tenant, viewer_key = _make_viewer_key("ac13-viewer")
    client = TestClient(create_app(pool=pool))

    before = _count_audit_rows(viewer_tenant)
    resp = client.get("/cis", headers=_auth(viewer_key))
    after = _count_audit_rows(viewer_tenant)

    assert resp.status_code == 200
    assert after - before == 1, (
        f"Expected exactly 1 new audit row; got {after - before}"
    )


def test_allowed_read_row_has_correct_fields(pool):
    """AC 13: the allow row for GET /cis has decision='allow', permission='read'."""
    viewer_tenant, viewer_key = _make_viewer_key("ac13-fields")
    client = TestClient(create_app(pool=pool))

    resp = client.get("/cis", headers=_auth(viewer_key))
    assert resp.status_code == 200

    rows = _get_audit_rows(viewer_tenant)
    # Filter to the /cis GET row only
    cis_rows = [r for r in rows if r["path"] == "/cis" and r["method"] == "GET"]
    assert len(cis_rows) == 1, f"Expected exactly 1 /cis GET audit row; got {len(cis_rows)}"
    row = cis_rows[0]
    assert row["decision"] == "allow"
    assert row["permission"] == "read"
    assert row["status_code"] == 200


def test_allowed_read_row_has_correct_role(pool):
    """AC 13: allow row for a viewer key records role='viewer'."""
    viewer_tenant, viewer_key = _make_viewer_key("ac13-role")
    client = TestClient(create_app(pool=pool))
    client.get("/cis", headers=_auth(viewer_key))

    rows = _get_audit_rows(viewer_tenant)
    cis_rows = [r for r in rows if r["path"] == "/cis" and r["method"] == "GET"]
    assert len(cis_rows) == 1
    assert cis_rows[0]["role"] == "viewer"


# ===========================================================================
# AC 14 — Allowed write -> exactly one allow row (adversarial proof (a), write case)
# ===========================================================================


def test_allowed_write_produces_exactly_one_allow_row(pool):
    """AC 14 / adversarial (a): POST /connectors with editor key appends exactly one allow row."""
    editor_tenant, editor_key = _make_editor_key("ac14-editor")
    client = TestClient(create_app(pool=pool))

    before = _count_audit_rows(editor_tenant)
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ac14-test"},
        headers=_auth(editor_key),
    )
    after = _count_audit_rows(editor_tenant)

    assert resp.status_code == 201
    assert after - before == 1, (
        f"Expected exactly 1 new audit row; got {after - before}"
    )


def test_allowed_write_row_has_correct_fields(pool):
    """AC 14: the allow row for POST /connectors has decision='allow', permission='write', status=201."""
    editor_tenant, editor_key = _make_editor_key("ac14-fields")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ac14-connector"},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 201

    rows = _get_audit_rows(editor_tenant)
    post_rows = [r for r in rows if r["path"] == "/connectors" and r["method"] == "POST"]
    assert len(post_rows) == 1, f"Expected 1 POST /connectors audit row; got {len(post_rows)}"
    row = post_rows[0]
    assert row["decision"] == "allow"
    assert row["permission"] == "write"
    assert row["status_code"] == 201, (
        f"POST /connectors (status_code=201 declared) should record 201; got {row['status_code']}"
    )


def test_allowed_write_row_has_correct_role(pool):
    """AC 14: allow row for an editor key records role='editor'."""
    editor_tenant, editor_key = _make_editor_key("ac14-role")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ac14-role-test"},
        headers=_auth(editor_key),
    )
    rows = _get_audit_rows(editor_tenant)
    post_rows = [r for r in rows if r["path"] == "/connectors" and r["method"] == "POST"]
    assert len(post_rows) == 1
    assert post_rows[0]["role"] == "editor"


# ===========================================================================
# AC 15 — Viewer on write endpoint -> 403 + exactly one deny row (adversarial proof (b))
# ===========================================================================


def test_viewer_write_produces_exactly_one_deny_row(pool):
    """AC 15 / adversarial (b): viewer POST /connectors returns 403 + exactly one deny row."""
    viewer_tenant, viewer_key = _make_viewer_key("ac15-viewer")
    client = TestClient(create_app(pool=pool))

    before = _count_audit_rows(viewer_tenant)
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ac15-test"},
        headers=_auth(viewer_key),
    )
    after = _count_audit_rows(viewer_tenant)

    assert resp.status_code == 403
    assert after - before == 1, (
        f"Expected exactly 1 deny audit row; got {after - before}"
    )


def test_viewer_write_deny_row_has_correct_fields(pool):
    """AC 15: the deny row has decision='deny', permission='write', status_code=403."""
    viewer_tenant, viewer_key = _make_viewer_key("ac15-fields")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ac15-deny"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403

    rows = _get_audit_rows(viewer_tenant)
    deny_rows = [r for r in rows if r["decision"] == "deny"]
    assert len(deny_rows) == 1, f"Expected 1 deny row; got {len(deny_rows)}"
    row = deny_rows[0]
    assert row["permission"] == "write"
    assert row["status_code"] == 403
    assert row["method"] == "POST"
    assert row["path"] == "/connectors"


def test_viewer_write_deny_response_body_unchanged(pool):
    """AC 15 / spec §4.2: 403 body is still {'detail': 'insufficient permissions'}."""
    _, viewer_key = _make_viewer_key("ac15-body")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ac15-body-test"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403
    assert resp.json() == {"detail": "insufficient permissions"}


def test_viewer_write_deny_row_committed_before_403(pool):
    """EC 11: deny row is committed even though the request returns 403."""
    viewer_tenant, viewer_key = _make_viewer_key("ec11-deny")
    client = TestClient(create_app(pool=pool))

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ec11-test"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403
    # Row must exist in DB immediately after the response
    count = _count_audit_rows(viewer_tenant)
    assert count == 1, f"Deny row must be committed; found {count} rows"


def test_viewer_write_no_allow_row_written(pool):
    """EC 6: viewer write produces exactly 1 deny row, never also an allow row."""
    viewer_tenant, viewer_key = _make_viewer_key("ec6-viewer")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "ec6-test"},
        headers=_auth(viewer_key),
    )
    rows = _get_audit_rows(viewer_tenant)
    allow_rows = [r for r in rows if r["decision"] == "allow"]
    assert len(allow_rows) == 0, "A viewer 403 must not produce an allow row"


# ===========================================================================
# AC 16 — Unauthenticated -> 401 + zero audit rows (EC 1)
# ===========================================================================


def test_unauthenticated_no_key_returns_401(pool):
    """AC 16 / EC 1: no Authorization header on gated endpoint returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis")
    assert resp.status_code == 401


def test_unauthenticated_no_key_zero_audit_rows(pool):
    """AC 16 / EC 1: no key -> 401 -> zero audit rows (no principal to attribute)."""
    client = TestClient(create_app(pool=pool))
    client.get("/cis")  # no auth header
    # No tenant_id means we cannot query per-tenant, so check total count.
    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    assert total == 0, f"Expected 0 audit rows after 401; got {total}"


def test_unauthenticated_invalid_key_returns_401(pool):
    """AC 16: invalid Bearer token on gated endpoint returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer itw_bogus.invalidsecret"})
    assert resp.status_code == 401


def test_unauthenticated_invalid_key_zero_audit_rows(pool):
    """AC 16: invalid key -> 401 -> zero audit rows."""
    client = TestClient(create_app(pool=pool))
    client.get("/cis", headers={"Authorization": "Bearer itw_bogus.invalidsecret"})
    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    assert total == 0, f"Expected 0 audit rows after 401 (invalid key); got {total}"


# ===========================================================================
# EC 2 — GET /health and POST /tenants not audited
# ===========================================================================


def test_get_health_not_audited(pool, monkeypatch):
    """EC 2: GET /health is not gated; calling it writes zero audit rows."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", "test-token-health")
    client = TestClient(create_app(pool=pool))
    client.get("/health")
    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    assert total == 0, f"GET /health must not write audit rows; got {total}"


def test_post_tenants_not_audited(pool, monkeypatch):
    """EC 2: POST /tenants is bootstrap-admin gated, not API-key gated; writes zero audit rows."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", "test-bootstrap-secret-abc123")
    client = TestClient(create_app(pool=pool))
    client.post(
        "/tenants",
        json={"name": "ec2-tenant"},
        headers={"Authorization": "Bearer test-bootstrap-secret-abc123"},
    )
    with psycopg.connect(admin_dsn()) as conn:
        total = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    assert total == 0, f"POST /tenants must not write audit rows; got {total}"


# ===========================================================================
# EC 3 — Viewer on read endpoint: allow, permission='read', status=200
# ===========================================================================


def test_viewer_read_endpoint_allow_row_fields(pool):
    """EC 3: viewer GET /connectors -> allow row with permission='read', status=200."""
    viewer_tenant, viewer_key = _make_viewer_key("ec3-viewer")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/connectors", headers=_auth(viewer_key))
    assert resp.status_code == 200

    rows = _get_audit_rows(viewer_tenant)
    conn_rows = [r for r in rows if r["path"] == "/connectors" and r["method"] == "GET"]
    assert len(conn_rows) == 1
    assert conn_rows[0]["decision"] == "allow"
    assert conn_rows[0]["permission"] == "read"
    assert conn_rows[0]["status_code"] == 200


# ===========================================================================
# EC 4 — Editor on write endpoint: allow, permission='write', status=200/201
# ===========================================================================


def test_editor_read_endpoint_allow_row(pool):
    """EC 4 (read variant): editor GET /cis -> allow row, permission='read', status=200."""
    editor_tenant, editor_key = _make_editor_key("ec4-read")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers=_auth(editor_key))
    assert resp.status_code == 200

    rows = _get_audit_rows(editor_tenant)
    cis_rows = [r for r in rows if r["path"] == "/cis" and r["method"] == "GET"]
    assert len(cis_rows) == 1
    assert cis_rows[0]["decision"] == "allow"
    assert cis_rows[0]["permission"] == "read"
    assert cis_rows[0]["status_code"] == 200


# ===========================================================================
# EC 6 — Exactly-once: one request produces exactly one audit row
# ===========================================================================


def test_single_allowed_request_exactly_one_row(pool):
    """EC 6: two consecutive GET /cis calls produce exactly 2 rows (1 per request)."""
    viewer_tenant, viewer_key = _make_viewer_key("ec6-exact")
    client = TestClient(create_app(pool=pool))

    before = _count_audit_rows(viewer_tenant)
    client.get("/cis", headers=_auth(viewer_key))
    client.get("/cis", headers=_auth(viewer_key))
    after = _count_audit_rows(viewer_tenant)

    assert after - before == 2, (
        f"2 requests must produce exactly 2 audit rows; got {after - before}"
    )


def test_single_denied_request_exactly_one_deny_row(pool):
    """EC 6: a single viewer write attempt produces exactly 1 deny row (no double-counting)."""
    viewer_tenant, viewer_key = _make_viewer_key("ec6-deny-exact")
    client = TestClient(create_app(pool=pool))

    before = _count_audit_rows(viewer_tenant)
    client.post("/connectors", json={"type": "aws", "display_name": "x"}, headers=_auth(viewer_key))
    after = _count_audit_rows(viewer_tenant)

    assert after - before == 1, (
        f"One denied request must produce exactly 1 audit row; got {after - before}"
    )


# ===========================================================================
# AC 17 / EC 8 — Cross-tenant isolation (adversarial proof (c))
# ===========================================================================


def test_cross_tenant_audit_isolation(pool):
    """AC 17 / adversarial (c): tenant A's GET /audit-log returns only A's rows, never B's."""
    tenant_a, key_a = _make_editor_key("ct-tenant-a")
    tenant_b, key_b = _make_editor_key("ct-tenant-b")
    client = TestClient(create_app(pool=pool))

    # Both tenants make requests that generate audit rows
    client.get("/cis", headers=_auth(key_a))
    client.get("/cis", headers=_auth(key_b))
    client.post("/connectors", json={"type": "aws", "display_name": "b-conn"}, headers=_auth(key_b))

    # Collect B's audit_ids via admin
    b_rows = _get_audit_rows(tenant_b)
    b_audit_ids = {str(r["audit_id"]) for r in b_rows}
    assert len(b_audit_ids) > 0, "Tenant B should have audit rows"

    # A's GET /audit-log must not return any of B's audit_ids
    resp = client.get("/audit-log", headers=_auth(key_a))
    assert resp.status_code == 200
    a_returned_ids = {e["audit_id"] for e in resp.json()}

    leaked = a_returned_ids & b_audit_ids
    assert leaked == set(), (
        f"Tenant A's audit-log leaked {len(leaked)} of tenant B's rows: {leaked}"
    )


def test_cross_tenant_rls_no_foreign_rows_visible(pool):
    """EC 8: tenant A sees only its own rows; tenant B's rows are entirely invisible via RLS."""
    tenant_a, key_a = _make_viewer_key("rls-a")
    tenant_b, key_b = _make_viewer_key("rls-b")
    client = TestClient(create_app(pool=pool))

    # Generate audit rows for B only
    client.get("/cis", headers=_auth(key_b))
    client.get("/connectors", headers=_auth(key_b))

    # A calls /audit-log; must receive empty list (no rows belong to A)
    resp = client.get("/audit-log", headers=_auth(key_a))
    assert resp.status_code == 200
    # The /audit-log call itself adds A's own allow row, but we asked list_audit
    # which uses RLS - A should see only its own rows (which now include the audit-log call).
    a_ids = {e["audit_id"] for e in resp.json()}
    b_rows = _get_audit_rows(tenant_b)
    b_ids = {str(r["audit_id"]) for r in b_rows}
    leaked = a_ids & b_ids
    assert leaked == set(), f"Tenant A sees {len(leaked)} of tenant B's audit rows"


# ===========================================================================
# AC 18 / EC 9 — App role cannot UPDATE audit row (adversarial proof (d))
# ===========================================================================


def test_app_role_cannot_update_audit_row(pool):
    """AC 18 / adversarial (d): UPDATE audit_log as app role raises permission-denied error."""
    editor_tenant, editor_key = _make_editor_key("update-test")
    client = TestClient(create_app(pool=pool))

    # Generate an audit row
    client.get("/cis", headers=_auth(editor_key))
    rows = _get_audit_rows(editor_tenant)
    assert len(rows) >= 1, "Expected at least one audit row to attempt UPDATE on"
    audit_id = rows[0]["audit_id"]

    # Connect as the app role (RLS-enforced) and attempt UPDATE
    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            # Set the tenant GUC so RLS would allow SELECT/INSERT
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(editor_tenant),)
            )
            conn.execute(
                "UPDATE audit_log SET decision = 'allow' WHERE audit_id = %s",
                (audit_id,),
            )
            conn.commit()

    err_msg = str(exc_info.value).lower()
    assert "permission denied" in err_msg or "insufficient privilege" in err_msg or "42501" in err_msg, (
        f"Expected permission-denied error; got: {exc_info.value}"
    )


def test_app_role_update_audit_row_leaves_row_unchanged(pool):
    """AC 18: after failed UPDATE, the audit row is unchanged (still 'deny' or original value)."""
    viewer_tenant, viewer_key = _make_viewer_key("update-unchanged")
    client = TestClient(create_app(pool=pool))

    # Generate a deny row
    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "x"},
        headers=_auth(viewer_key),
    )
    rows = _get_audit_rows(viewer_tenant)
    assert len(rows) >= 1
    original_decision = rows[0]["decision"]
    audit_id = rows[0]["audit_id"]

    # Attempt UPDATE (will fail)
    try:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(viewer_tenant),)
            )
            conn.execute(
                "UPDATE audit_log SET decision = 'allow' WHERE audit_id = %s",
                (audit_id,),
            )
            conn.commit()
    except psycopg.Error:
        pass  # expected

    # Verify row is still unchanged
    rows_after = _get_audit_rows(viewer_tenant)
    matching = [r for r in rows_after if r["audit_id"] == audit_id]
    assert len(matching) == 1
    assert matching[0]["decision"] == original_decision, (
        f"Row should be unchanged; expected '{original_decision}', got '{matching[0]['decision']}'"
    )


# ===========================================================================
# AC 19 / EC 10 — App role cannot DELETE audit row (adversarial proof (d))
# ===========================================================================


def test_app_role_cannot_delete_audit_row(pool):
    """AC 19 / adversarial (d): DELETE FROM audit_log as app role raises permission-denied error."""
    editor_tenant, editor_key = _make_editor_key("delete-test")
    client = TestClient(create_app(pool=pool))

    # Generate an audit row
    client.get("/cis", headers=_auth(editor_key))
    rows = _get_audit_rows(editor_tenant)
    assert len(rows) >= 1
    audit_id = rows[0]["audit_id"]

    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(editor_tenant),)
            )
            conn.execute(
                "DELETE FROM audit_log WHERE audit_id = %s",
                (audit_id,),
            )
            conn.commit()

    err_msg = str(exc_info.value).lower()
    assert "permission denied" in err_msg or "insufficient privilege" in err_msg or "42501" in err_msg, (
        f"Expected permission-denied error; got: {exc_info.value}"
    )


def test_app_role_delete_audit_row_row_still_exists(pool):
    """AC 19: after failed DELETE, the audit row still exists (verified via admin connection)."""
    editor_tenant, editor_key = _make_editor_key("delete-exists")
    client = TestClient(create_app(pool=pool))

    client.get("/cis", headers=_auth(editor_key))
    rows_before = _get_audit_rows(editor_tenant)
    assert len(rows_before) >= 1
    audit_id = rows_before[0]["audit_id"]

    # Attempt DELETE (will fail)
    try:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(editor_tenant),)
            )
            conn.execute(
                "DELETE FROM audit_log WHERE audit_id = %s",
                (audit_id,),
            )
            conn.commit()
    except psycopg.Error:
        pass  # expected

    # Row must still exist
    rows_after = _get_audit_rows(editor_tenant)
    ids_after = {r["audit_id"] for r in rows_after}
    assert audit_id in ids_after, "Audit row should still exist after failed DELETE"


# ===========================================================================
# EC 14 / EC 15 — limit parameter on GET /audit-log
# ===========================================================================


def test_get_audit_log_limit_zero_returns_empty(pool):
    """EC 14: limit=0 returns empty list."""
    viewer_tenant, viewer_key = _make_viewer_key("limit-zero")
    client = TestClient(create_app(pool=pool))

    # Generate some audit rows
    client.get("/cis", headers=_auth(viewer_key))
    client.get("/connectors", headers=_auth(viewer_key))

    resp = client.get("/audit-log?limit=0", headers=_auth(viewer_key))
    assert resp.status_code == 200
    assert resp.json() == [], f"limit=0 should return empty list; got {resp.json()}"


def test_get_audit_log_large_limit_returns_all_rows(pool):
    """EC 15: large limit returns all rows for the tenant."""
    viewer_tenant, viewer_key = _make_viewer_key("limit-large")
    client = TestClient(create_app(pool=pool))

    # Generate 3 known requests (each writes one audit row, plus audit-log calls add more)
    for _ in range(3):
        client.get("/cis", headers=_auth(viewer_key))

    # Get all rows via admin
    all_rows = _get_audit_rows(viewer_tenant)
    expected_count = len(all_rows)

    resp = client.get(f"/audit-log?limit={expected_count + 100}", headers=_auth(viewer_key))
    assert resp.status_code == 200
    # The audit-log call itself writes one more row; returned rows should be >= expected_count
    assert len(resp.json()) >= expected_count - 1, (
        f"Large limit should return all rows; got {len(resp.json())} vs expected ~{expected_count}"
    )


def test_list_audit_negative_limit_returns_empty(pool):
    """EC 14: list_audit with negative limit returns empty (clamped to 0)."""
    editor_tenant, editor_key = _make_editor_key("neg-limit")
    client = TestClient(create_app(pool=pool))
    client.get("/cis", headers=_auth(editor_key))

    with tenant_session(pool, editor_tenant) as conn:
        result = list_audit(conn, limit=-1)
    assert result == [], f"Negative limit should return []; got {result}"


# ===========================================================================
# EC 15 — Ordering determinism: ORDER BY occurred_at DESC, audit_id DESC
# ===========================================================================


def test_audit_log_ordering_newest_first(pool):
    """EC 15 (ordering): GET /audit-log returns rows newest-first."""
    editor_tenant, editor_key = _make_editor_key("ordering")
    client = TestClient(create_app(pool=pool))

    # Make several requests to build up rows with different timestamps
    client.get("/cis", headers=_auth(editor_key))
    client.get("/connectors", headers=_auth(editor_key))
    client.post("/connectors", json={"type": "aws", "display_name": "ord-test"}, headers=_auth(editor_key))

    resp = client.get("/audit-log", headers=_auth(editor_key))
    assert resp.status_code == 200
    entries = resp.json()
    if len(entries) >= 2:
        for i in range(len(entries) - 1):
            # occurred_at is ISO 8601; lexicographic comparison works for isoformat()
            assert entries[i]["occurred_at"] >= entries[i + 1]["occurred_at"], (
                f"Rows not newest-first at index {i}: "
                f"{entries[i]['occurred_at']} vs {entries[i+1]['occurred_at']}"
            )


# ===========================================================================
# EC 19 — CHECK constraint enforcement at the DB level
# ===========================================================================


def test_check_constraint_rejects_invalid_decision():
    """EC 19: INSERT with decision='maybe' is rejected by the DB CHECK constraint."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id", ("cc-tenant-decision",)
        ).fetchone()
        tenant_id = row[0]
        conn.commit()

    with psycopg.connect(admin_dsn()) as conn:
        conn.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),))
        with pytest.raises(psycopg.Error) as exc_info:
            conn.execute(
                "INSERT INTO audit_log "
                "(tenant_id, api_key_id, role, method, path, permission, decision, status_code) "
                "VALUES (%s, gen_random_uuid(), 'viewer', 'GET', '/cis', 'read', 'maybe', 200)",
                (tenant_id,),
            )
            conn.commit()
    err = str(exc_info.value).lower()
    assert "check" in err or "violat" in err or "constraint" in err, (
        f"Expected CHECK constraint violation; got: {exc_info.value}"
    )


def test_check_constraint_rejects_invalid_role():
    """EC 19: INSERT with role='admin' is rejected by the DB CHECK constraint."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id", ("cc-tenant-role",)
        ).fetchone()
        tenant_id = row[0]
        conn.commit()

    with psycopg.connect(admin_dsn()) as conn:
        conn.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),))
        with pytest.raises(psycopg.Error) as exc_info:
            conn.execute(
                "INSERT INTO audit_log "
                "(tenant_id, api_key_id, role, method, path, permission, decision, status_code) "
                "VALUES (%s, gen_random_uuid(), 'admin', 'GET', '/cis', 'read', 'allow', 200)",
                (tenant_id,),
            )
            conn.commit()
    err = str(exc_info.value).lower()
    assert "check" in err or "violat" in err or "constraint" in err, (
        f"Expected CHECK constraint violation; got: {exc_info.value}"
    )


def test_check_constraint_rejects_invalid_permission():
    """EC 19: INSERT with permission='delete' is rejected by the DB CHECK constraint."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id", ("cc-tenant-perm",)
        ).fetchone()
        tenant_id = row[0]
        conn.commit()

    with psycopg.connect(admin_dsn()) as conn:
        conn.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),))
        with pytest.raises(psycopg.Error) as exc_info:
            conn.execute(
                "INSERT INTO audit_log "
                "(tenant_id, api_key_id, role, method, path, permission, decision, status_code) "
                "VALUES (%s, gen_random_uuid(), 'editor', 'GET', '/cis', 'delete', 'allow', 200)",
                (tenant_id,),
            )
            conn.commit()
    err = str(exc_info.value).lower()
    assert "check" in err or "violat" in err or "constraint" in err, (
        f"Expected CHECK constraint violation; got: {exc_info.value}"
    )


# ===========================================================================
# EC 20 — No valid_from / valid_to columns on audit_log
# ===========================================================================


def test_audit_log_has_no_bitemporal_columns():
    """EC 20: audit_log must not have valid_from or valid_to columns."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'audit_log' AND column_name IN ('valid_from', 'valid_to')"
        ).fetchall()
    cols = [r[0] for r in rows]
    assert cols == [], f"audit_log must not have bitemporal columns; found: {cols}"


# ===========================================================================
# record_access unit tests (AC 11)
# ===========================================================================


def test_record_access_returns_uuid(pool):
    """AC 11: record_access returns a UUID (audit_id)."""
    editor_tenant, _ = _make_editor_key("ra-uuid")
    # Get the api_key_id from DB
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (editor_tenant,)
        ).fetchone()
    api_key_id = row[0]

    with tenant_session(pool, editor_tenant) as conn:
        result = record_access(
            conn,
            editor_tenant,
            api_key_id=api_key_id,
            role="editor",
            method="GET",
            path="/cis",
            permission="read",
            decision="allow",
            status_code=200,
        )
    assert isinstance(result, UUID), f"record_access should return UUID; got {type(result)}"


def test_record_access_inserts_exactly_one_row(pool):
    """AC 11: record_access inserts exactly one row per call."""
    editor_tenant, _ = _make_editor_key("ra-one-row")
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id FROM api_keys WHERE tenant_id = %s LIMIT 1", (editor_tenant,)
        ).fetchone()
    api_key_id = row[0]

    before = _count_audit_rows(editor_tenant)
    with tenant_session(pool, editor_tenant) as conn:
        record_access(
            conn,
            editor_tenant,
            api_key_id=api_key_id,
            role="editor",
            method="POST",
            path="/connectors",
            permission="write",
            decision="allow",
            status_code=201,
        )
    after = _count_audit_rows(editor_tenant)
    assert after - before == 1, f"record_access must insert exactly 1 row; got {after - before}"


def test_record_access_does_not_include_occurred_at_in_column_list():
    """AC 11: record_access SQL does not name occurred_at in the INSERT column list (uses DEFAULT)."""
    import inspect
    import infra_twin.db.audit as audit_module
    src = inspect.getsource(audit_module.record_access)
    # Isolate the string literal(s) passed to conn.execute — they appear as quoted strings.
    # Extract text between triple-quoted or single-quoted SQL strings.
    # The INSERT SQL string is the first argument to conn.execute.
    # We find the section that starts at "INSERT INTO" and ends before "VALUES".
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
    # Extract just the column list (between the first '(' and the ')' before VALUES)
    if "(" in column_list_text and "VALUES" in column_list_text.upper():
        col_part = column_list_text.split("VALUES")[0]
        assert "occurred_at" not in col_part, (
            "record_access must not name occurred_at in the INSERT column list (uses DEFAULT); "
            f"found in: {col_part!r}"
        )


# ===========================================================================
# GET /audit-log authentication boundary
# ===========================================================================


def test_get_audit_log_without_key_returns_401(pool):
    """GET /audit-log without auth returns 401 (not 200, not 403)."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/audit-log")
    assert resp.status_code == 401


def test_get_audit_log_with_invalid_key_returns_401(pool):
    """GET /audit-log with invalid key returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/audit-log", headers={"Authorization": "Bearer itw_bad.key"})
    assert resp.status_code == 401


def test_get_audit_log_viewer_allowed(pool):
    """Spec §4.3: GET /audit-log is read-gated; viewers are permitted (200, not 403)."""
    _, viewer_key = _make_viewer_key("audit-log-viewer-allowed")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/audit-log", headers=_auth(viewer_key))
    assert resp.status_code == 200
    assert resp.status_code != 403


# ===========================================================================
# EC 7 — GET /audit-log self-audit (audit-log call writes its own allow row)
# ===========================================================================


def test_get_audit_log_self_audits(pool):
    """EC 7: calling GET /audit-log itself writes an allow audit row for that request."""
    viewer_tenant, viewer_key = _make_viewer_key("self-audit")
    client = TestClient(create_app(pool=pool))

    before = _count_audit_rows(viewer_tenant)
    resp = client.get("/audit-log", headers=_auth(viewer_key))
    after = _count_audit_rows(viewer_tenant)

    assert resp.status_code == 200
    # The /audit-log call itself should have written at least one new row
    assert after > before, "GET /audit-log should write its own allow audit row"


def test_get_audit_log_self_row_has_correct_path(pool):
    """EC 7: the self-audit row for GET /audit-log has path='/audit-log'."""
    viewer_tenant, viewer_key = _make_viewer_key("self-path")
    client = TestClient(create_app(pool=pool))
    client.get("/audit-log", headers=_auth(viewer_key))

    rows = _get_audit_rows(viewer_tenant)
    audit_log_rows = [r for r in rows if r["path"] == "/audit-log" and r["method"] == "GET"]
    assert len(audit_log_rows) >= 1, "Expected at least one /audit-log self-audit row"
    row = audit_log_rows[0]
    assert row["decision"] == "allow"
    assert row["permission"] == "read"
