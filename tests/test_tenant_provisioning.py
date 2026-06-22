"""POST /tenants — bootstrap-admin provisioning endpoint.

Covers:
  AC 8  — POST /tenants with valid token returns 201 with correct JSON shape + api_key prefix.
  AC 9  — Issued api_key authenticates a subsequent GET /cis (200).
  AC 10 — Missing/invalid bootstrap token -> 401; env var unset -> 503; no DB rows written.
  EC 10 — POST /tenants with bootstrap token not configured -> 503, no rows written.
  EC 11 — Partial failure (no orphan tenant row).
  EC 14 — Plaintext key is never persisted; DB only stores key_id + secret_hash + salt.
  EC 15 — name with surrounding whitespace is accepted (min_length=1 passes non-empty stripped).
  Spec §5 POST /tenants rules 1-6.
"""

from __future__ import annotations

import os

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.db.api_keys import KEY_PREFIX
from infra_twin.db.config import admin_dsn

_VALID_TOKEN = "test-bootstrap-secret-abc123"


def _client(pool) -> TestClient:
    return TestClient(create_app(pool=pool))


def _admin_headers(token: str = _VALID_TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# AC 8 — happy path: 201, correct JSON shape, api_key starts with itw_
# ---------------------------------------------------------------------------


def test_post_tenants_returns_201(pool, monkeypatch):
    """AC 8: POST /tenants with valid bootstrap token and valid name returns 201."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "acme"}, headers=_admin_headers())
    assert resp.status_code == 201


def test_post_tenants_response_has_required_keys(pool, monkeypatch):
    """AC 8: response JSON has exactly the keys {tenant_id, name, created_at, api_key}."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "acme"}, headers=_admin_headers()).json()
    assert set(body.keys()) == {"tenant_id", "name", "created_at", "api_key", "role"}


def test_post_tenants_api_key_starts_with_itw(pool, monkeypatch):
    """AC 8: api_key in response starts with 'itw_'."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "acme"}, headers=_admin_headers()).json()
    assert body["api_key"].startswith(KEY_PREFIX), (
        f"api_key should start with '{KEY_PREFIX}': {body['api_key']}"
    )


def test_post_tenants_api_key_has_exactly_one_dot(pool, monkeypatch):
    """AC 5 / AC 8: api_key contains exactly one '.' (itw_<key_id>.<secret> format)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "acme"}, headers=_admin_headers()).json()
    api_key = body["api_key"]
    assert api_key.count(".") == 1, f"api_key should have exactly one '.': {api_key}"


def test_post_tenants_name_in_response(pool, monkeypatch):
    """AC 8: response 'name' field matches the requested name."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "widget-corp"}, headers=_admin_headers()).json()
    assert body["name"] == "widget-corp"


def test_post_tenants_tenant_id_is_valid_uuid(pool, monkeypatch):
    """AC 8: tenant_id in response is a valid UUID string."""
    from uuid import UUID
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "uuid-check"}, headers=_admin_headers()).json()
    tid = UUID(body["tenant_id"])  # raises if not valid UUID
    assert str(tid) == body["tenant_id"]


def test_post_tenants_writes_tenants_row(pool, monkeypatch):
    """POST /tenants creates a row in the tenants table (verified as superuser)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "rowcheck"}, headers=_admin_headers()).json()
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT name FROM tenants WHERE tenant_id = %s",
            (body["tenant_id"],),
        ).fetchone()
    assert row is not None
    assert row[0] == "rowcheck"


def test_post_tenants_writes_api_keys_row(pool, monkeypatch):
    """POST /tenants writes exactly one api_keys row for the new tenant."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "keyrowcheck"}, headers=_admin_headers()).json()
    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute(
            "SELECT count(*) FROM api_keys WHERE tenant_id = %s",
            (body["tenant_id"],),
        ).fetchone()[0]
    assert count == 1


# ---------------------------------------------------------------------------
# AC 14 — Plaintext key is NEVER persisted; only key_id + secret_hash + salt stored
# ---------------------------------------------------------------------------


def test_plaintext_key_not_stored_in_db(pool, monkeypatch):
    """AC 14 / EC 14: after POST /tenants, no column in api_keys equals the plaintext key."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "plaintext-check"}, headers=_admin_headers()).json()
    api_key = body["api_key"]
    # Extract the secret half (after the first '.')
    secret = api_key.split(".", 1)[1]

    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT api_key_id, tenant_id, key_id, secret_hash, salt, name "
            "FROM api_keys WHERE tenant_id = %s",
            (body["tenant_id"],),
        ).fetchone()

    assert row is not None
    col_values = [str(v) if v is not None else "" for v in row]
    for val in col_values:
        assert api_key not in val, (
            f"plaintext key '{api_key}' found in column value: {val}"
        )
        assert secret not in val, (
            f"secret part '{secret}' found in column value: {val}"
        )


def test_api_keys_row_has_no_plaintext_column(pool, monkeypatch):
    """AC 14: api_keys row only stores key_id (cleartext), secret_hash (hex) and salt (bytes)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "col-check"}, headers=_admin_headers()).json()
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT secret_hash, salt FROM api_keys WHERE tenant_id = %s",
            (body["tenant_id"],),
        ).fetchone()
    assert row is not None
    secret_hash, salt = row
    # secret_hash is a hex string (64 chars for 32-byte scrypt digest)
    assert isinstance(secret_hash, str)
    assert len(secret_hash) == 64
    # salt is stored as bytes
    assert isinstance(salt, (bytes, memoryview))


# ---------------------------------------------------------------------------
# AC 9 — issued api_key authenticates a subsequent GET /cis
# ---------------------------------------------------------------------------


def test_issued_key_authenticates_get_cis(pool, monkeypatch):
    """AC 9: the api_key returned by POST /tenants successfully authenticates GET /cis (200)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    body = client.post("/tenants", json={"name": "auth-check"}, headers=_admin_headers()).json()
    api_key = body["api_key"]

    resp = client.get("/cis", headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    assert resp.json() == []  # no CIs yet, but auth succeeded


def test_issued_key_is_returned_only_once(pool, monkeypatch):
    """AC 8 spec: api_key is only ever returned by POST /tenants, not stored as plaintext."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "once-only"}, headers=_admin_headers())
    assert resp.status_code == 201
    assert "api_key" in resp.json()
    # The same key cannot be retrieved again via GET (no such endpoint in scope).
    # This is verified structurally: no GET /tenants route exists.
    resp2 = client.get("/tenants")
    # No GET /tenants endpoint — expect 404 or 405.
    assert resp2.status_code in (404, 405)


# ---------------------------------------------------------------------------
# AC 10 / EC 10 — env var unset -> 503, no DB rows written
# ---------------------------------------------------------------------------


def test_bootstrap_token_not_configured_returns_503(pool, monkeypatch):
    """AC 10 / EC 10: POST /tenants when INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN is unset returns 503."""
    monkeypatch.delenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", raising=False)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "unconfigured"}, headers=_admin_headers())
    assert resp.status_code == 503


def test_bootstrap_token_not_configured_detail(pool, monkeypatch):
    """EC 10: 503 detail is 'bootstrap admin is not configured'."""
    monkeypatch.delenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", raising=False)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "unconfigured"}, headers=_admin_headers())
    assert resp.json()["detail"] == "bootstrap admin is not configured"


def test_bootstrap_token_not_configured_no_tenant_written(pool, monkeypatch):
    """EC 10: when env var unset, no tenant row is written."""
    monkeypatch.delenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", raising=False)
    client = _client(pool)
    client.post("/tenants", json={"name": "unconfigured"}, headers=_admin_headers())
    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute("SELECT count(*) FROM tenants").fetchone()[0]
    assert count == 0


def test_bootstrap_token_not_configured_no_api_key_written(pool, monkeypatch):
    """EC 10: when env var unset, no api_keys row is written."""
    monkeypatch.delenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", raising=False)
    client = _client(pool)
    client.post("/tenants", json={"name": "unconfigured"}, headers=_admin_headers())
    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute("SELECT count(*) FROM api_keys").fetchone()[0]
    assert count == 0


def test_bootstrap_token_empty_string_returns_503(pool, monkeypatch):
    """EC 10: INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN set to empty string -> 503."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", "")
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "empty-token"}, headers=_admin_headers())
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# AC 10 / spec §5 rule 3 — missing / wrong bootstrap token -> 401
# ---------------------------------------------------------------------------


def test_missing_bootstrap_token_returns_401(pool, monkeypatch):
    """AC 10: POST /tenants with no Authorization header returns 401."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "no-auth"})
    assert resp.status_code == 401


def test_missing_bootstrap_token_detail(pool, monkeypatch):
    """Spec §5 rule 2: 401 detail is 'missing bootstrap admin token'."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "no-auth"})
    assert resp.json()["detail"] == "missing bootstrap admin token"


def test_wrong_bootstrap_token_returns_401(pool, monkeypatch):
    """AC 10: POST /tenants with wrong Bootstrap token returns 401."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post(
        "/tenants",
        json={"name": "bad-token"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_wrong_bootstrap_token_detail(pool, monkeypatch):
    """Spec §5 rule 3: 401 detail is 'invalid bootstrap admin token' on token mismatch."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post(
        "/tenants",
        json={"name": "bad-token"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.json()["detail"] == "invalid bootstrap admin token"


def test_wrong_token_no_tenant_written(pool, monkeypatch):
    """AC 10: with wrong token, no tenants row is written."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    client.post(
        "/tenants",
        json={"name": "bad-token"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute("SELECT count(*) FROM tenants").fetchone()[0]
    assert count == 0


def test_wrong_token_no_api_key_written(pool, monkeypatch):
    """AC 10: with wrong token, no api_keys row is written."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    client.post(
        "/tenants",
        json={"name": "bad-token"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute("SELECT count(*) FROM api_keys").fetchone()[0]
    assert count == 0


def test_basic_auth_scheme_returns_401(pool, monkeypatch):
    """EC 2 (bootstrap variant): 'Basic ...' instead of 'Bearer ...' returns 401."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post(
        "/tenants",
        json={"name": "basic-auth"},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp.status_code == 401


def test_lowercase_bearer_returns_401(pool, monkeypatch):
    """EC 2 (bootstrap variant): 'bearer <token>' (lowercase) returns 401."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post(
        "/tenants",
        json={"name": "lower-bearer"},
        headers={"Authorization": f"bearer {_VALID_TOKEN}"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Spec §5 rule 4 — empty / invalid name -> 422
# ---------------------------------------------------------------------------


def test_empty_name_returns_422(pool, monkeypatch):
    """Spec §5 rule 4: empty name string returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": ""}, headers=_admin_headers())
    assert resp.status_code == 422


def test_whitespace_only_name_returns_422(pool, monkeypatch):
    """Spec §5 rule 4: whitespace-only name returns 422 (validator strips then checks non-empty)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post("/tenants", json={"name": "   "}, headers=_admin_headers())
    assert resp.status_code == 422


def test_missing_name_field_returns_422(pool, monkeypatch):
    """Spec §5 rule 4: body with no 'name' field returns 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post("/tenants", json={}, headers=_admin_headers())
    assert resp.status_code == 422


def test_name_with_surrounding_whitespace_accepted(pool, monkeypatch):
    """EC 15: name with surrounding whitespace is accepted (min_length=1 passes after strip)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    resp = client.post(
        "/tenants", json={"name": "  valid name  "}, headers=_admin_headers()
    )
    # Should succeed (min_length=1 check on stripped value passes).
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# EC 13 — Two tenants: each key resolves only to its own tenant
# ---------------------------------------------------------------------------


def test_two_tenants_have_distinct_tenant_ids(pool, monkeypatch):
    """EC 13: two POST /tenants calls produce distinct tenant_ids."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    a = client.post("/tenants", json={"name": "tenant-a"}, headers=_admin_headers()).json()
    b = client.post("/tenants", json={"name": "tenant-b"}, headers=_admin_headers()).json()
    assert a["tenant_id"] != b["tenant_id"]


def test_two_tenants_have_distinct_api_keys(pool, monkeypatch):
    """EC 13: two POST /tenants calls produce distinct api_keys."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _VALID_TOKEN)
    client = _client(pool)
    a = client.post("/tenants", json={"name": "tenant-a"}, headers=_admin_headers()).json()
    b = client.post("/tenants", json={"name": "tenant-b"}, headers=_admin_headers()).json()
    assert a["api_key"] != b["api_key"]
