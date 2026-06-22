"""Adversarial API-key authentication tests.

Covers:
  AC 11 — X-Tenant-Id header dependency is removed; grep finds no matches.
  AC 12 — All 14 endpoints use the API-key dependency (no X-Tenant-Id accepted).
  AC 13 — No Authorization header -> 401 (not 422).
  AC 14 — Bearer itw_bogus.bogus -> 401.
  AC 15 — Valid key_id, tampered secret -> 401.
  AC 16 — Adversarial read isolation: A's key sees A's rows; B's key sees [].
  AC 17 — Adversarial write isolation: POST with A's key stamps only A's tenant_id.

  Edge cases §6:
  EC 1  — Missing Authorization -> 401 "missing API key".
  EC 2  — Authorization present but not "Bearer " -> 401.
  EC 3  — "Bearer " with empty token -> 401.
  EC 4  — Key without itw_ prefix -> 401.
  EC 5  — Key with no '.' separator or empty id/secret -> 401.
  EC 6  — Valid key_id, wrong secret -> 401.
  EC 7  — Unknown key_id -> 401.
  EC 8  — Revoked key -> 401.
  EC 9  — A's key cannot read or write B's data; no X-Tenant-Id accepted.
"""

from __future__ import annotations

from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.connector_sdk import CIRef, DiscoveredCI, DiscoveredEdge
from infra_twin.core_model import CIType, EdgeType, Evidence
from infra_twin.db.api_keys import parse_key
from infra_twin.db.config import admin_dsn
from infra_twin.db.repositories import CIRepository
from infra_twin.db.session import tenant_session
from infra_twin.reconciliation import reconcile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _tenant_for_key(api_key: str) -> UUID:
    """Look up the tenant_id for an API key directly from the DB."""
    parsed = parse_key(api_key)
    assert parsed is not None
    key_id, _ = parsed
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT tenant_id FROM api_keys WHERE key_id = %s", (key_id,)
        ).fetchone()
    assert row is not None
    return row[0]


def _seed_vpc(pool, tenant: UUID, external_id: str = "vpc-seed-01") -> None:
    with tenant_session(pool, tenant) as conn:
        reconcile(
            conn,
            tenant,
            [DiscoveredCI(type=CIType.vpc, external_id=external_id, name="seed-net")],
            source="test",
            ci_types=frozenset({CIType.vpc}),
            edge_types=frozenset(),
        )


# ---------------------------------------------------------------------------
# AC 13 / EC 1 — Missing Authorization header -> 401 "missing API key"
# ---------------------------------------------------------------------------


def test_no_auth_header_get_cis_returns_401(pool):
    """AC 13 / EC 1: GET /cis with no Authorization header returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis")
    assert resp.status_code == 401


def test_no_auth_header_detail_is_missing_api_key(pool):
    """EC 1: 401 detail is 'missing API key' when header absent."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis")
    assert resp.json()["detail"] == "missing API key"


def test_no_auth_header_has_www_authenticate_bearer(pool):
    """Spec §5 rule 1: WWW-Authenticate: Bearer header is present on 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis")
    assert "www-authenticate" in {k.lower() for k in resp.headers}
    assert "Bearer" in resp.headers.get("www-authenticate", resp.headers.get("WWW-Authenticate", ""))


def test_no_auth_header_not_422(pool):
    """AC 13: missing Authorization returns 401, not 422 (not a Pydantic validation error)."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis")
    assert resp.status_code != 422


def test_no_auth_header_graph_returns_401(pool):
    """AC 13: GET /graph with no Authorization header returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/graph")
    assert resp.status_code == 401


def test_no_auth_header_changes_returns_401(pool):
    """AC 13: GET /changes with no Authorization header returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/changes")
    assert resp.status_code == 401


def test_no_auth_header_connectors_returns_401(pool):
    """AC 12 / AC 13: POST /connectors with no Authorization header returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post("/connectors", json={"type": "aws", "display_name": "x"})
    assert resp.status_code == 401


def test_no_auth_header_get_connectors_returns_401(pool):
    """AC 12 / AC 13: GET /connectors with no Authorization header returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/connectors")
    assert resp.status_code == 401


def test_no_auth_header_connector_health_returns_401(pool):
    """AC 12 / AC 13: GET /connector-health/runs with no Authorization header returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/connector-health/runs")
    assert resp.status_code == 401


def test_no_auth_header_flowlogs_returns_401(pool):
    """AC 12 / AC 13: POST /telemetry/flowlogs with no Authorization header returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post("/telemetry/flowlogs", json={"records": []})
    assert resp.status_code == 401


def test_no_auth_header_age_edges_returns_401(pool):
    """AC 12 / AC 13: POST /telemetry/maintenance/age-inferred-edges with no auth returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.post("/telemetry/maintenance/age-inferred-edges")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# EC 2 — Authorization present but not "Bearer " -> 401
# ---------------------------------------------------------------------------


def test_basic_auth_scheme_returns_401(pool):
    """EC 2: 'Basic ...' Authorization returns 401 (prefix match is case-sensitive 'Bearer ')."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp.status_code == 401


def test_lowercase_bearer_returns_401(pool):
    """EC 2: 'bearer ...' (lowercase) returns 401 (prefix match is case-sensitive)."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "bearer itw_key.secret"})
    assert resp.status_code == 401


def test_token_only_no_bearer_prefix_returns_401(pool):
    """EC 2: just a token with no 'Bearer ' prefix returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "itw_key.secret"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# EC 3 — "Bearer " with empty token -> 401
# ---------------------------------------------------------------------------


def test_bearer_empty_token_returns_401(pool):
    """EC 3: 'Bearer ' with empty token (just the prefix) returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# AC 14 / EC 4 — Key without itw_ prefix -> 401
# ---------------------------------------------------------------------------


def test_bogus_key_returns_401(pool):
    """AC 14: Bearer itw_bogus.bogus -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer itw_bogus.bogus"})
    assert resp.status_code == 401


def test_no_prefix_key_returns_401(pool):
    """EC 4: key without 'itw_' prefix returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer noprefixkey.secret"})
    assert resp.status_code == 401


def test_key_wrong_prefix_returns_401(pool):
    """EC 4: key with wrong prefix (e.g. 'xtz_...') returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer xtz_key.secret"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# EC 5 — No '.' separator or empty id/secret -> 401
# ---------------------------------------------------------------------------


def test_key_no_dot_separator_returns_401(pool):
    """EC 5: 'itw_keyidsecret' (no '.') returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer itw_keyidsecret"})
    assert resp.status_code == 401


def test_key_empty_key_id_returns_401(pool):
    """EC 5: 'itw_.' (empty key_id) returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer itw_.somesecret"})
    assert resp.status_code == 401


def test_key_empty_secret_returns_401(pool):
    """EC 5: 'itw_keyid.' (empty secret) returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer itw_keyid."})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# EC 6 / AC 15 — Valid key_id but wrong secret -> 401
# ---------------------------------------------------------------------------


def test_tampered_secret_returns_401(pool, make_tenant_with_key):
    """AC 15 / EC 6: valid key_id but tampered secret returns 401."""
    tenant, api_key = make_tenant_with_key("tamper-secret")
    parsed = parse_key(api_key)
    assert parsed is not None
    key_id, _ = parsed
    # Construct a key with the correct key_id but wrong secret.
    tampered = f"itw_{key_id}.wrongsecretvalue"

    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


def test_tampered_secret_detail_is_invalid_api_key(pool, make_tenant_with_key):
    """EC 6: tampered secret returns 401 with detail 'invalid API key'."""
    tenant, api_key = make_tenant_with_key("tamper-detail")
    parsed = parse_key(api_key)
    assert parsed is not None
    key_id, _ = parsed
    tampered = f"itw_{key_id}.wrongsecretvalue"

    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.json()["detail"] == "invalid API key"


# ---------------------------------------------------------------------------
# EC 7 — Unknown key_id -> 401
# ---------------------------------------------------------------------------


def test_unknown_key_id_returns_401(pool):
    """EC 7: a well-formatted key with an unknown key_id returns 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/cis", headers={"Authorization": "Bearer itw_unknownkeyid.somesecret"}
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# EC 8 — Revoked key -> 401
# ---------------------------------------------------------------------------


def test_revoked_key_returns_401(pool, make_tenant_with_key):
    """EC 8: a key with revoked_at set is rejected with 401."""
    tenant, api_key = make_tenant_with_key("revoked-key-test")
    parsed = parse_key(api_key)
    assert parsed is not None
    key_id, _ = parsed

    # Revoke the key by setting revoked_at.
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(
            "UPDATE api_keys SET revoked_at = now() WHERE key_id = %s", (key_id,)
        )
        conn.commit()

    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers=_auth(api_key))
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# AC 16 / EC 9 — Adversarial read isolation
# ---------------------------------------------------------------------------


def test_tenant_a_key_returns_own_cis(pool, make_tenant_with_key):
    """AC 16: GET /cis with tenant A's key returns A's rows."""
    tenant_a, key_a = make_tenant_with_key("adv-read-A")
    _seed_vpc(pool, tenant_a, "vpc-a-01")
    client = TestClient(create_app(pool=pool))

    resp = client.get("/cis", headers=_auth(key_a))
    assert resp.status_code == 200
    external_ids = [c["external_id"] for c in resp.json()]
    assert "vpc-a-01" in external_ids


def test_tenant_b_key_cannot_read_tenant_a_cis(pool, make_tenant_with_key):
    """AC 16 / EC 9: GET /cis with B's key returns [] when only A has data."""
    tenant_a, key_a = make_tenant_with_key("adv-read-iso-A")
    _, key_b = make_tenant_with_key("adv-read-iso-B")
    _seed_vpc(pool, tenant_a, "vpc-a-only")

    client = TestClient(create_app(pool=pool))
    resp_b = client.get("/cis", headers=_auth(key_b))
    assert resp_b.status_code == 200
    assert resp_b.json() == [], (
        "tenant B should see no CIs from tenant A"
    )


def test_x_tenant_id_header_is_not_accepted(pool, make_tenant_with_key):
    """AC 11 / AC 16 / EC 9: X-Tenant-Id header is not accepted; without a valid Bearer key returns 401."""
    tenant_a, key_a = make_tenant_with_key("adv-xhdr-A")
    _, key_b = make_tenant_with_key("adv-xhdr-B")
    tenant_a_id = _tenant_for_key(key_a)
    _seed_vpc(pool, tenant_a, "vpc-a-xhdr")

    client = TestClient(create_app(pool=pool))
    # Pass X-Tenant-Id with tenant A's UUID but no Bearer token.
    resp = client.get(
        "/cis", headers={"X-Tenant-Id": str(tenant_a_id)}
    )
    # Without a valid Bearer token the request must be rejected.
    assert resp.status_code == 401, (
        "X-Tenant-Id alone should not grant access; must use Bearer token"
    )


def test_x_tenant_id_cannot_override_bearer_auth(pool, make_tenant_with_key):
    """AC 16 / EC 9: X-Tenant-Id header with B's key + A's tenant id still resolves to B."""
    tenant_a, key_a = make_tenant_with_key("adv-xhdr-override-A")
    tenant_b, key_b = make_tenant_with_key("adv-xhdr-override-B")
    _seed_vpc(pool, tenant_a, "vpc-a-override")

    client = TestClient(create_app(pool=pool))
    # B's key + X-Tenant-Id set to A's UUID; the resolved tenant should still be B.
    resp = client.get(
        "/cis",
        headers={
            "Authorization": f"Bearer {key_b}",
            "X-Tenant-Id": str(tenant_a),
        },
    )
    assert resp.status_code == 200
    # B sees [] because only A has data; X-Tenant-Id does not override Bearer.
    assert resp.json() == []


# ---------------------------------------------------------------------------
# AC 17 — Adversarial write isolation (POST /connectors stamps only tenant A)
# ---------------------------------------------------------------------------


def test_write_with_tenant_a_key_stamps_only_tenant_a(pool, make_tenant_with_key):
    """AC 17: POST /connectors with A's key creates a connectors row only visible to A."""
    tenant_a, key_a = make_tenant_with_key("adv-write-A")
    _, key_b = make_tenant_with_key("adv-write-B")

    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "My AWS", "config": {}, "enabled": True},
        headers=_auth(key_a),
    )
    assert resp.status_code == 201

    # Count connectors rows by tenant as superuser.
    with psycopg.connect(admin_dsn()) as conn:
        a_count = conn.execute(
            "SELECT count(*) FROM connectors WHERE tenant_id = %s", (tenant_a,)
        ).fetchone()[0]
        b_count = conn.execute(
            "SELECT count(*) FROM connectors WHERE tenant_id = %s",
            (_tenant_for_key(key_b),),
        ).fetchone()[0]

    assert a_count == 1, f"tenant A should have 1 connector row, got {a_count}"
    assert b_count == 0, f"tenant B should have 0 connector rows, got {b_count}"


def test_tenant_b_sees_zero_connectors_after_tenant_a_write(pool, make_tenant_with_key):
    """AC 17: GET /connectors with B's key returns empty list after A's write."""
    tenant_a, key_a = make_tenant_with_key("adv-write-vis-A")
    _, key_b = make_tenant_with_key("adv-write-vis-B")

    client = TestClient(create_app(pool=pool))
    client.post(
        "/connectors",
        json={"type": "aws", "display_name": "A's Connector"},
        headers=_auth(key_a),
    )

    resp_b = client.get("/connectors", headers=_auth(key_b))
    assert resp_b.status_code == 200
    assert resp_b.json()["connectors"] == []


# ---------------------------------------------------------------------------
# AC 11 — X-Tenant-Id is removed from source code (grep-based structural test)
# ---------------------------------------------------------------------------


def test_x_tenant_id_not_in_app_py():
    """AC 11: 'X-Tenant-Id' does not appear in apps/api source code."""
    import pathlib
    api_dir = pathlib.Path(__file__).resolve().parents[1] / "apps" / "api" / "src"
    for py_file in api_dir.rglob("*.py"):
        text = py_file.read_text()
        assert "X-Tenant-Id" not in text, (
            f"'X-Tenant-Id' found in {py_file} — should be fully removed"
        )


# ---------------------------------------------------------------------------
# AC 12 — Health endpoint stays unauthenticated
# ---------------------------------------------------------------------------


def test_health_endpoint_requires_no_auth(pool):
    """Spec §3.5: GET /health does not require authentication (no Bearer token needed)."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# AC 11 / AC 12 — All 14 tenant-scoped endpoints reject missing auth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/cis", None),
        ("GET", "/graph", None),
        ("GET", "/changes", None),
        ("GET", "/connector-health/runs", None),
        ("GET", "/connectors", None),
        ("POST", "/connectors", {"type": "aws", "display_name": "x"}),
        ("POST", "/events/aws", {"record": {}}),
        ("POST", "/telemetry/flowlogs", {"records": []}),
        ("POST", "/telemetry/maintenance/age-inferred-edges", None),
    ],
)
def test_tenant_endpoint_rejects_missing_auth(pool, method, path, body):
    """AC 12 / AC 13: all tenant-scoped endpoints return 401 when Authorization is absent."""
    client = TestClient(create_app(pool=pool))
    if method == "GET":
        resp = client.get(path)
    else:
        resp = client.post(path, json=body)
    assert resp.status_code == 401, (
        f"{method} {path} expected 401 without auth, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# AC 18 — web client sends Authorization: Bearer (structural)
# ---------------------------------------------------------------------------


def test_web_api_ts_uses_authorization_bearer():
    """AC 18: apps/web/src/api.ts sends Authorization: Bearer header."""
    import pathlib
    api_ts = pathlib.Path(__file__).resolve().parents[1] / "apps" / "web" / "src" / "api.ts"
    text = api_ts.read_text()
    assert "Authorization" in text
    assert "Bearer" in text


def test_web_api_ts_no_x_tenant_id():
    """AC 18: apps/web/src/api.ts does not send X-Tenant-Id."""
    import pathlib
    api_ts = pathlib.Path(__file__).resolve().parents[1] / "apps" / "web" / "src" / "api.ts"
    text = api_ts.read_text()
    assert "X-Tenant-Id" not in text


# ---------------------------------------------------------------------------
# AC 19 — .env.example documents INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN
# ---------------------------------------------------------------------------


def test_env_example_documents_bootstrap_token():
    """AC 19: .env.example contains INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN."""
    import pathlib
    env_example = pathlib.Path(__file__).resolve().parents[1] / ".env.example"
    text = env_example.read_text()
    assert "INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN" in text


# ---------------------------------------------------------------------------
# AC 1 / AC 2 / AC 3 / AC 4 — Migration schema structural tests
# ---------------------------------------------------------------------------


def test_api_keys_table_exists_with_required_columns():
    """AC 1: api_keys table exists with all 8 required columns."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'api_keys' ORDER BY ordinal_position"
        ).fetchall()
    columns = {r[0] for r in rows}
    required = {
        "api_key_id", "tenant_id", "key_id", "secret_hash",
        "salt", "name", "created_at", "revoked_at", "role",
    }
    assert required == columns, f"column mismatch: {columns}"


def test_api_keys_tenant_id_fk_references_tenants():
    """AC 2: api_keys.tenant_id references tenants(tenant_id)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            """
            SELECT tc.constraint_type, ccu.table_name AS foreign_table
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.referential_constraints rc
              ON tc.constraint_name = rc.constraint_name
            JOIN information_schema.constraint_column_usage ccu
              ON rc.unique_constraint_name = ccu.constraint_name
            WHERE tc.table_name = 'api_keys'
              AND kcu.column_name = 'tenant_id'
            """
        ).fetchone()
    assert row is not None, "FK constraint on api_keys.tenant_id not found"
    assert row[0] == "FOREIGN KEY"
    assert row[1] == "tenants"


def test_api_keys_rls_enabled():
    """AC 2: api_keys table has ROW LEVEL SECURITY enabled."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT relrowsecurity FROM pg_class WHERE relname = 'api_keys'"
        ).fetchone()
    assert row is not None
    assert row[0] is True, "RLS should be enabled on api_keys"


def test_api_keys_rls_policy_exists():
    """AC 2: tenant_isolation policy exists on api_keys."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies WHERE tablename = 'api_keys' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on api_keys"


def test_api_keys_unique_index_on_key_id():
    """AC 4: UNIQUE INDEX api_keys_key_id on api_keys(key_id) exists."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE tablename = 'api_keys' AND indexname = 'api_keys_key_id'"
        ).fetchone()
    assert row is not None, "unique index api_keys_key_id not found"
    assert "UNIQUE" in row[1].upper(), f"index should be UNIQUE: {row[1]}"


def test_app_role_has_select_on_api_keys_not_insert():
    """AC 3: app role has SELECT on api_keys but NOT INSERT (verified via privilege catalog)."""
    with psycopg.connect(admin_dsn()) as conn:
        privs = conn.execute(
            """
            SELECT privilege_type
            FROM information_schema.role_table_grants
            WHERE table_name = 'api_keys' AND grantee = 'app'
            """
        ).fetchall()
    priv_types = {r[0] for r in privs}
    assert "SELECT" in priv_types, "app role should have SELECT on api_keys"
    assert "INSERT" not in priv_types, "app role must NOT have INSERT on api_keys"
    assert "UPDATE" not in priv_types, "app role must NOT have UPDATE on api_keys"
    assert "DELETE" not in priv_types, "app role must NOT have DELETE on api_keys"
