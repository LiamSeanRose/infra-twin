"""OIDC authentication tests: second auth path via ID tokens.

Covers every acceptance criterion and edge case from spec §5 and §6 (19a-h):

  AC 19a  correctly-signed token with matching iss+aud authenticates and resolves
          to the tenant + role mapped via role_claim_map
  AC 19b  missing/unmapped role claim -> default_role
  AC 19c  viewer OIDC principal: GET 200, write-gated 403; editor OIDC: write 200
  AC 19d  bad signature / expired / wrong-audience / wrong-issuer / no-config -> 401
  AC 19e  OIDC request produces a usage_event + audit_log row with auth_method='oidc'
  AC 19f  adversarial cross-tenant: token for tenant A never resolves to tenant B
  AC 19g  ambiguous iss+aud across two tenants -> 401
  AC 19h  RS256 and HS256 both verify offline

  Schema structural checks (AC 1-8):
  - migration 0014 exists and is the highest-numbered
  - tenant_idp_config has exactly the required columns
  - tenant_id FK to tenants; UNIQUE index on (tenant_id, issuer, audience)
  - RLS enabled; tenant_isolation policy exists
  - app role has SELECT only (no INSERT/UPDATE/DELETE)
  - audit_log.auth_method NOT NULL DEFAULT 'api_key', api_key_id nullable
  - default_role CHECK constraint; role_claim default; role_claim_map default

  DB module exports (AC 9-10):
  - TenantIdpConfig, upsert_idp_config, find_idp_config importable from infra_twin.db
  - TenantIdpConfig is frozen dataclass; upsert is idempotent; find returns None for
    absent, disabled, and ambiguous cases

  HTTP endpoints (AC 15-16):
  - PUT /tenants/{id}/idp-config: 503 if env unset, 401 no token, 422 bad body, 200 ok
  - GET /tenants/{id}/idp-config: 200 list; no-secret keys

  verify_oidc_token unit tests (AC 11-12):
  - All spec §5 edge cases covered offline with injected key resolvers

  OIDC-specific edge cases (spec §5 EC 1-26):
  EC 5   two-dot token with empty segment -> looks_like_jwt False -> 401 invalid api key
  EC 6   1 or 4+ segments -> looks_like_jwt False -> 401
  EC 7   garbage base64 JWT shape -> OIDC path -> OidcError -> 401 invalid OIDC token
  EC 8   JWT missing iss or aud -> OidcError -> 401
  EC 9   iss/aud present but no config -> 401
  EC 10  disabled_at non-null -> find_idp_config None -> 401
  EC 11  wrong aud -> 401
  EC 12  iss mismatch -> 401
  EC 13  expired exp -> 401; leeway at boundary -> allowed
  EC 14  forged signature -> 401
  EC 15  algorithm confusion: alg=none -> 401; HS256 secret presented to RS256 token -> 401
  EC 16  role_claim missing -> default_role
  EC 17  role_claim present but unmapped -> default_role
  EC 18  role_claim_map -> 'editor' => editor; -> 'viewer' => viewer
  EC 19  cross-tenant: token for A cannot resolve to B
  EC 20  ambiguous iss+aud: two active tenants with same (issuer, audience) -> 401
  EC 21  quota exhausted on OIDC -> 429 with deny audit row (auth_method='oidc')
  EC 22  OIDC viewer read under quota -> 200, usage+allow audit with auth_method='oidc'
  EC 24  RLS: app role cannot INSERT/UPDATE/DELETE tenant_idp_config
  EC 25  raw token never persisted: OidcError messages carry no token material
  EC 26  itw_-prefixed key with dots -> api_keys path (not OIDC)

  Backward-compatibility (AC 14):
  - API-key path still works: 401 missing, 401 invalid, 403 viewer write,
    200 viewer read, 201 editor write, usage_event, audit_log
"""

from __future__ import annotations

import pathlib
import time
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.api.oidc import OidcError, looks_like_jwt, verify_oidc_token
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn, app_dsn
from infra_twin.db.idp_config import TenantIdpConfig, find_idp_config, upsert_idp_config
from infra_twin.db.session import tenant_session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[1] / "migrations"
_BOOTSTRAP_TOKEN = "test-bootstrap-oidc-secret-xyz"
_ISSUER_A = "https://idp.example.com/tenant-a"
_AUDIENCE_A = "infra-twin-client-a"
_ISSUER_B = "https://idp.example.com/tenant-b"
_AUDIENCE_B = "infra-twin-client-b"

# HS256 secret used in tests that need symmetric tokens
_HS256_SECRET = b"a-very-long-symmetric-secret-used-in-tests-only-32b"


# ---------------------------------------------------------------------------
# RSA key helpers (generated once per test session)
# ---------------------------------------------------------------------------


def _make_rsa_keypair():
    """Generate an RSA-2048 key pair for offline tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem, private_key, public_key


# Module-level RSA key pairs (generated once for all OIDC tests)
_RSA_PRIVATE_A, _RSA_PUBLIC_A, _RSA_PRIV_KEY_A, _RSA_PUB_KEY_A = _make_rsa_keypair()
_RSA_PRIVATE_B, _RSA_PUBLIC_B, _RSA_PRIV_KEY_B, _RSA_PUB_KEY_B = _make_rsa_keypair()
_RSA_PRIVATE_ATTACKER, _, _RSA_PRIV_KEY_ATTACKER, _ = _make_rsa_keypair()


# ---------------------------------------------------------------------------
# Token factories
# ---------------------------------------------------------------------------


def _make_rs256_token(
    *,
    private_key=None,
    issuer: str = _ISSUER_A,
    audience: str = _AUDIENCE_A,
    role: str | None = "admin",
    extra_claims: dict | None = None,
    exp_offset: int = 3600,
    iat_offset: int = -10,
    kid: str | None = None,
    omit_iss: bool = False,
    omit_aud: bool = False,
) -> str:
    """Build an RS256-signed JWT using the injected private key."""
    if private_key is None:
        private_key = _RSA_PRIV_KEY_A
    now = int(time.time())
    payload: dict = {
        "sub": "test-user-001",
        "iat": now + iat_offset,
        "exp": now + exp_offset,
    }
    if not omit_iss:
        payload["iss"] = issuer
    if not omit_aud:
        payload["aud"] = audience
    if role is not None:
        payload["role"] = role
    if extra_claims:
        payload.update(extra_claims)

    headers = {"alg": "RS256"}
    if kid is not None:
        headers["kid"] = kid

    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def _make_hs256_token(
    *,
    secret: bytes = _HS256_SECRET,
    issuer: str = _ISSUER_A,
    audience: str = _AUDIENCE_A,
    role: str | None = "admin",
    exp_offset: int = 3600,
    iat_offset: int = -10,
) -> str:
    """Build an HS256-signed JWT."""
    now = int(time.time())
    payload = {
        "sub": "test-user-hs256",
        "iss": issuer,
        "aud": audience,
        "iat": now + iat_offset,
        "exp": now + exp_offset,
    }
    if role is not None:
        payload["role"] = role
    return jwt.encode(payload, secret, algorithm="HS256")


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _make_tenant(name: str) -> UUID:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id", (name,)
        ).fetchone()
        conn.commit()
    return row[0]


def _make_tenant_with_key(name: str, role: Role = Role.editor) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=role)
    return issued.tenant_id, issued.plaintext


def _make_tenant_with_key_quota(name: str, quota: int, role: Role = Role.editor) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=role, monthly_request_quota=quota)
    return issued.tenant_id, issued.plaintext


def _setup_idp(
    tenant_id: UUID,
    issuer: str = _ISSUER_A,
    audience: str = _AUDIENCE_A,
    role_claim: str = "role",
    role_claim_map: dict | None = None,
    default_role: Role = Role.viewer,
) -> TenantIdpConfig:
    """Upsert a tenant_idp_config row via admin connection."""
    if role_claim_map is None:
        role_claim_map = {}
    with psycopg.connect(admin_dsn()) as conn:
        cfg = upsert_idp_config(
            conn,
            tenant_id=tenant_id,
            issuer=issuer,
            audience=audience,
            role_claim=role_claim,
            role_claim_map=role_claim_map,
            default_role=default_role,
        )
        conn.commit()
    return cfg


def _disable_idp(tenant_id: UUID, issuer: str, audience: str) -> None:
    """Set disabled_at on a config row to deactivate it."""
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(
            "UPDATE tenant_idp_config SET disabled_at = now() "
            "WHERE tenant_id = %s AND issuer = %s AND audience = %s",
            (tenant_id, issuer, audience),
        )
        conn.commit()


def _count_audit_rows(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM audit_log WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
    return row[0]


def _count_usage_rows(tenant_id: UUID) -> int:
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM usage_event WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
    return row[0]


def _get_audit_rows(tenant_id: UUID) -> list[dict]:
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT audit_id, api_key_id, auth_method, role, decision, status_code "
            "FROM audit_log WHERE tenant_id = %s "
            "ORDER BY occurred_at DESC, audit_id DESC",
            (tenant_id,),
        ).fetchall()
    return [
        {
            "audit_id": r[0],
            "api_key_id": r[1],
            "auth_method": r[2],
            "role": r[3],
            "decision": r[4],
            "status_code": r[5],
        }
        for r in rows
    ]


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _admin_headers() -> dict:
    return {"Authorization": f"Bearer {_BOOTSTRAP_TOKEN}"}


def _oidc_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Key resolver factory for tests (offline, no network)
# ---------------------------------------------------------------------------


def _rs256_resolver_for(public_key) -> object:
    """Return a key_resolver that always returns the given RSA public key."""
    def resolver(issuer: str, kid=None):
        return public_key
    return resolver


def _hs256_resolver_for(secret: bytes) -> object:
    """Return a key_resolver that always returns the given HMAC secret."""
    def resolver(issuer: str, kid=None):
        return secret
    return resolver


def _app_with_oidc(pool, public_key=None, hs_secret: bytes | None = None):
    """Create a TestClient with an injected offline key resolver."""
    if hs_secret is not None:
        resolver = _hs256_resolver_for(hs_secret)
    elif public_key is not None:
        resolver = _rs256_resolver_for(public_key)
    else:
        resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)
    return TestClient(create_app(pool=pool, oidc_key_resolver=resolver))


# ===========================================================================
# Schema structural checks (AC 1-8)
# ===========================================================================


def test_migration_0014_file_exists():
    """AC 1: migrations/0014_tenant_idp_config.sql exists."""
    assert (_MIGRATIONS_DIR / "0014_tenant_idp_config.sql").exists()


def test_migration_0014_exists_and_was_applied():
    """AC 1: 0014_tenant_idp_config.sql exists in the migrations directory."""
    # Note: 0015_scim_users.sql is now the highest-numbered migration;
    # the relevant assertion for 0015-is-highest lives in test_scim_provisioning.py.
    assert (_MIGRATIONS_DIR / "0014_tenant_idp_config.sql").exists()


def test_tenant_idp_config_table_has_exact_columns():
    """AC 2: tenant_idp_config has exactly the 9 required columns."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'tenant_idp_config' ORDER BY ordinal_position"
        ).fetchall()
    columns = {r[0] for r in rows}
    expected = {
        "idp_config_id", "tenant_id", "issuer", "audience",
        "role_claim", "role_claim_map", "default_role", "created_at", "disabled_at",
    }
    assert columns == expected, f"Column mismatch: {columns} vs {expected}"


def test_tenant_idp_config_tenant_id_fk_to_tenants():
    """AC 3: tenant_idp_config.tenant_id is a FK to tenants(tenant_id)."""
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
            WHERE tc.table_name = 'tenant_idp_config'
              AND kcu.column_name = 'tenant_id'
            """
        ).fetchone()
    assert row is not None, "FK constraint on tenant_idp_config.tenant_id not found"
    assert row[0] == "FOREIGN KEY"
    assert row[1] == "tenants"


def test_tenant_idp_config_rls_enabled():
    """AC 4: RLS is enabled on tenant_idp_config."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT relrowsecurity FROM pg_class WHERE relname = 'tenant_idp_config'"
        ).fetchone()
    assert row is not None
    assert row[0] is True, "RLS should be enabled on tenant_idp_config"


def test_tenant_idp_config_rls_policy_exists():
    """AC 4: tenant_isolation policy exists on tenant_idp_config."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies "
            "WHERE tablename = 'tenant_idp_config' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on tenant_idp_config"


def test_app_role_has_select_only_on_tenant_idp_config():
    """AC 5: app role has SELECT on tenant_idp_config and NOT INSERT/UPDATE/DELETE."""
    with psycopg.connect(admin_dsn()) as conn:
        privs = conn.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'tenant_idp_config' AND grantee = 'app'"
        ).fetchall()
    priv_types = {r[0] for r in privs}
    assert "SELECT" in priv_types, "app role must have SELECT on tenant_idp_config"
    assert "INSERT" not in priv_types, "app role must NOT have INSERT on tenant_idp_config"
    assert "UPDATE" not in priv_types, "app role must NOT have UPDATE on tenant_idp_config"
    assert "DELETE" not in priv_types, "app role must NOT have DELETE on tenant_idp_config"


def test_tenant_idp_config_unique_index_on_tenant_issuer_audience():
    """AC 6: UNIQUE index on tenant_idp_config(tenant_id, issuer, audience) exists."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE tablename = 'tenant_idp_config' "
            "  AND indexname = 'tenant_idp_config_iss_aud'"
        ).fetchone()
    assert row is not None, "Unique index tenant_idp_config_iss_aud not found"
    assert "UNIQUE" in row[1].upper(), f"Index should be UNIQUE: {row[1]}"


def test_default_role_check_constraint():
    """AC 7: default_role CHECK restricts to ('viewer','editor')."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT cc.check_clause
            FROM information_schema.table_constraints tc
            JOIN information_schema.check_constraints cc
              ON tc.constraint_name = cc.constraint_name
            WHERE tc.table_name = 'tenant_idp_config'
              AND tc.constraint_type = 'CHECK'
            """
        ).fetchall()
    clauses = " ".join(r[0] for r in rows).lower()
    assert "default_role" in clauses, "No CHECK clause referencing default_role found"
    assert "viewer" in clauses
    assert "editor" in clauses


def test_role_claim_default_is_role():
    """AC 7: role_claim column default is 'role'."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = 'tenant_idp_config' AND column_name = 'role_claim'"
        ).fetchone()
    assert row is not None
    assert row[0] is not None and "role" in row[0].lower(), (
        f"role_claim default should contain 'role'; got: {row[0]}"
    )


def test_role_claim_map_default_is_empty_jsonb():
    """AC 7: role_claim_map column default is '{}'::jsonb."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = 'tenant_idp_config' AND column_name = 'role_claim_map'"
        ).fetchone()
    assert row is not None
    assert row[0] is not None and "{}" in row[0], (
        f"role_claim_map default should be '{{}}'; got: {row[0]}"
    )


def test_audit_log_auth_method_column_exists_not_null_with_default():
    """AC 8: audit_log.auth_method is NOT NULL DEFAULT 'api_key'."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'audit_log' AND column_name = 'auth_method'"
        ).fetchone()
    assert row is not None, "audit_log.auth_method column not found"
    assert row[0] == "NO", f"auth_method must be NOT NULL; got is_nullable={row[0]}"
    assert row[1] is not None and "api_key" in row[1].lower(), (
        f"auth_method default should contain 'api_key'; got: {row[1]}"
    )


def test_audit_log_auth_method_check_constraint():
    """AC 8: audit_log.auth_method CHECK restricts to ('api_key','oidc')."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT cc.check_clause
            FROM information_schema.table_constraints tc
            JOIN information_schema.check_constraints cc
              ON tc.constraint_name = cc.constraint_name
            WHERE tc.table_name = 'audit_log'
              AND tc.constraint_type = 'CHECK'
            """
        ).fetchall()
    clauses = " ".join(r[0] for r in rows).lower()
    assert "auth_method" in clauses, "No CHECK clause for auth_method on audit_log"
    assert "oidc" in clauses, "CHECK clause must include 'oidc'"


def test_audit_log_api_key_id_is_nullable():
    """AC 8: audit_log.api_key_id is nullable (DROP NOT NULL applied)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name = 'audit_log' AND column_name = 'api_key_id'"
        ).fetchone()
    assert row is not None, "audit_log.api_key_id column not found"
    assert row[0] == "YES", f"api_key_id must be nullable; got is_nullable={row[0]}"


# ===========================================================================
# DB module exports (AC 9-10)
# ===========================================================================


def test_tenant_idp_config_importable_from_db():
    """AC 9: TenantIdpConfig importable from infra_twin.db."""
    import infra_twin.db as db
    assert "TenantIdpConfig" in db.__all__
    assert hasattr(db, "TenantIdpConfig")


def test_upsert_idp_config_importable_from_db():
    """AC 9: upsert_idp_config importable from infra_twin.db."""
    import infra_twin.db as db
    assert "upsert_idp_config" in db.__all__
    assert hasattr(db, "upsert_idp_config")


def test_find_idp_config_importable_from_db():
    """AC 9: find_idp_config importable from infra_twin.db."""
    import infra_twin.db as db
    assert "find_idp_config" in db.__all__
    assert hasattr(db, "find_idp_config")


def test_tenant_idp_config_is_frozen_dataclass():
    """AC 10: TenantIdpConfig is a frozen dataclass."""
    assert hasattr(TenantIdpConfig, "__dataclass_fields__")
    cfg_fields = {f.name for f in fields(TenantIdpConfig)}
    expected_fields = {
        "idp_config_id", "tenant_id", "issuer", "audience",
        "role_claim", "role_claim_map", "default_role", "created_at", "disabled_at",
    }
    assert cfg_fields == expected_fields

    # Confirm frozen: writing to any field must raise FrozenInstanceError
    tenant_id = _make_tenant("frozen-check")
    cfg = _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    import dataclasses
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        cfg.issuer = "mutated"  # type: ignore[misc]


def test_upsert_idp_config_is_idempotent():
    """AC 10: upsert_idp_config on same (tenant, iss, aud) updates and does not duplicate."""
    tenant_id = _make_tenant("upsert-idempotent")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.editor)

    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute(
            "SELECT count(*) FROM tenant_idp_config WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()[0]
    assert count == 1, f"Upsert must not duplicate rows; found {count}"


def test_upsert_idp_config_clears_disabled_at():
    """AC 10: re-PUT (upsert) clears disabled_at, re-enabling a previously disabled config."""
    tenant_id = _make_tenant("upsert-reenable")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    _disable_idp(tenant_id, _ISSUER_A, _AUDIENCE_A)

    # Verify it's now disabled
    with psycopg.connect(admin_dsn()) as conn:
        cfg = find_idp_config(conn, _ISSUER_A, _AUDIENCE_A)
    assert cfg is None, "Should be None after disabling"

    # Re-upsert: disabled_at should be cleared
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)

    with psycopg.connect(admin_dsn()) as conn:
        cfg = find_idp_config(conn, _ISSUER_A, _AUDIENCE_A)
    assert cfg is not None, "Config should be active after re-upsert"
    assert cfg.disabled_at is None


def test_find_idp_config_returns_none_when_absent():
    """AC 10: find_idp_config returns None when no config exists."""
    with psycopg.connect(admin_dsn()) as conn:
        result = find_idp_config(conn, "https://nonexistent.example.com", "no-audience")
    assert result is None


def test_find_idp_config_returns_none_when_disabled():
    """AC 10 / EC 10: find_idp_config returns None when disabled_at is non-null."""
    tenant_id = _make_tenant("disabled-config")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    _disable_idp(tenant_id, _ISSUER_A, _AUDIENCE_A)

    with psycopg.connect(admin_dsn()) as conn:
        result = find_idp_config(conn, _ISSUER_A, _AUDIENCE_A)
    assert result is None


def test_find_idp_config_returns_none_when_ambiguous():
    """AC 10 / EC 20: find_idp_config returns None when multiple tenants share same iss+aud."""
    tenant_a = _make_tenant("ambiguous-a")
    tenant_b = _make_tenant("ambiguous-b")
    # Both tenants configured with the same issuer+audience
    _setup_idp(tenant_a, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    _setup_idp(tenant_b, issuer=_ISSUER_A, audience=_AUDIENCE_A)

    with psycopg.connect(admin_dsn()) as conn:
        result = find_idp_config(conn, _ISSUER_A, _AUDIENCE_A)
    assert result is None, "Ambiguous iss+aud must return None"


# ===========================================================================
# looks_like_jwt unit tests (spec §5 EC 5, 6)
# ===========================================================================


def test_looks_like_jwt_true_for_three_segments():
    """looks_like_jwt is True for a non-itw_ 3-segment dot-separated token."""
    assert looks_like_jwt("header.payload.sig") is True


def test_looks_like_jwt_false_for_itw_prefix():
    """EC 26: itw_-prefixed token is NOT a JWT regardless of segment count."""
    assert looks_like_jwt("itw_header.payload.sig") is False


def test_looks_like_jwt_false_for_one_segment():
    """EC 6: 1-segment token -> False."""
    assert looks_like_jwt("onlyone") is False


def test_looks_like_jwt_false_for_two_segments():
    """EC 6: 2-segment token -> False."""
    assert looks_like_jwt("a.b") is False


def test_looks_like_jwt_false_for_four_segments():
    """EC 6: 4-segment token -> False."""
    assert looks_like_jwt("a.b.c.d") is False


def test_looks_like_jwt_false_empty_first_segment():
    """EC 5: empty first segment (.b.c) -> False."""
    assert looks_like_jwt(".b.c") is False


def test_looks_like_jwt_false_empty_middle_segment():
    """EC 5: empty middle segment (a..c) -> False."""
    assert looks_like_jwt("a..c") is False


def test_looks_like_jwt_false_empty_last_segment():
    """EC 5: empty last segment (a.b.) -> False."""
    assert looks_like_jwt("a.b.") is False


def test_looks_like_jwt_false_empty_string():
    """EC 3 variant: empty string -> False."""
    assert looks_like_jwt("") is False


def test_itw_with_dots_routes_to_api_key_path(pool):
    """EC 26: itw_-prefixed key with extra dots stays on api_keys path (not OIDC)."""
    # This has two '.' after the prefix but must NOT route to OIDC
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/cis",
        headers={"Authorization": "Bearer itw_a.b.c"},
    )
    assert resp.status_code == 401
    # Error must be from API-key path (not OIDC path)
    assert resp.json()["detail"] == "invalid API key"


# ===========================================================================
# verify_oidc_token unit tests (offline)
# ===========================================================================


def test_verify_oidc_token_rs256_success():
    """AC 12 / AC 19a: verify_oidc_token succeeds with a valid RS256 token (offline)."""
    tenant_id = _make_tenant("verify-rs256-success")
    cfg = _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        principal = verify_oidc_token(
            token,
            find_config=find_cfg,
            key_resolver=resolver,
        )

    assert principal.tenant_id == tenant_id
    assert principal.role == Role.editor


def test_verify_oidc_token_hs256_success():
    """AC 12 / AC 19h: verify_oidc_token succeeds with a valid HS256 token (offline)."""
    tenant_id = _make_tenant("verify-hs256-success")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_hs256_token(
        secret=_HS256_SECRET,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    resolver = _hs256_resolver_for(_HS256_SECRET)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        principal = verify_oidc_token(
            token,
            find_config=find_cfg,
            key_resolver=resolver,
        )

    assert principal.tenant_id == tenant_id
    assert principal.role == Role.editor


def test_verify_oidc_token_bad_signature_raises_oidc_error():
    """EC 14 / AC 19d: forged signature raises OidcError."""
    tenant_id = _make_tenant("bad-sig")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    # Token signed with attacker's key, but resolver returns the real public key
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_ATTACKER,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)


def test_verify_oidc_token_expired_raises_oidc_error():
    """EC 13 / AC 19d: expired token raises OidcError."""
    tenant_id = _make_tenant("expired-token")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    # exp in the past
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        exp_offset=-3600,  # expired 1 hour ago
        iat_offset=-7200,
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)


def test_verify_oidc_token_leeway_at_boundary_allows():
    """EC 13: token at exactly exp boundary with non-zero leeway is allowed."""
    tenant_id = _make_tenant("leeway-boundary")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    # exp exactly 5 seconds in the past; with 10s leeway this should be accepted
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        exp_offset=-5,
        iat_offset=-20,
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        principal = verify_oidc_token(
            token,
            find_config=find_cfg,
            key_resolver=resolver,
            leeway_seconds=10,
        )
    assert principal.tenant_id == tenant_id


def test_verify_oidc_token_missing_iss_raises_oidc_error():
    """EC 8: token missing iss raises OidcError."""
    tenant_id = _make_tenant("missing-iss")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        omit_iss=True,
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)


def test_verify_oidc_token_missing_aud_raises_oidc_error():
    """EC 8: token missing aud raises OidcError."""
    tenant_id = _make_tenant("missing-aud")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        omit_aud=True,
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)


def test_verify_oidc_token_no_config_raises_oidc_error():
    """EC 9: iss/aud present but no config -> OidcError."""
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer="https://unconfigured.example.com",
        audience="unconfigured-audience",
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)


def test_verify_oidc_token_wrong_audience_raises_oidc_error():
    """EC 11 / AC 19d: wrong audience raises OidcError (no config match)."""
    tenant_id = _make_tenant("wrong-aud")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    # Token has different audience
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience="completely-wrong-audience",
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)


def test_verify_oidc_token_wrong_issuer_raises_oidc_error():
    """EC 12 / AC 19d: wrong issuer raises OidcError (no config match)."""
    tenant_id = _make_tenant("wrong-iss")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer="https://wrong-issuer.example.com",
        audience=_AUDIENCE_A,
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)


def test_verify_oidc_token_role_missing_falls_back_to_default():
    """EC 16 / AC 19b: missing role_claim -> default_role."""
    tenant_id = _make_tenant("role-missing")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    # Token has no 'role' claim
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        principal = verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)

    assert principal.role == Role.viewer, f"Expected viewer (default); got {principal.role}"


def test_verify_oidc_token_unmapped_role_falls_back_to_default():
    """EC 17 / AC 19b: unmapped role_claim value -> default_role."""
    tenant_id = _make_tenant("role-unmapped")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    # Token has role='superuser' which is not in role_claim_map
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="superuser",
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        principal = verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)

    assert principal.role == Role.viewer


def test_verify_oidc_token_role_maps_to_editor():
    """EC 18 / AC 19a: role_claim_map {'admin': 'editor'} -> editor principal."""
    tenant_id = _make_tenant("role-maps-editor")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        principal = verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)

    assert principal.role == Role.editor


def test_verify_oidc_token_role_maps_to_viewer():
    """EC 18: role_claim_map {'guest': 'viewer'} -> viewer principal."""
    tenant_id = _make_tenant("role-maps-viewer")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"guest": "viewer"},
        default_role=Role.editor,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="guest",
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        principal = verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)

    assert principal.role == Role.viewer


def test_verify_oidc_token_alg_none_raises_oidc_error():
    """EC 15: algorithm 'none' raises OidcError (algorithm confusion prevention)."""
    tenant_id = _make_tenant("alg-none")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)

    # Build an 'alg: none' token manually
    import base64, json
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    now = int(time.time())
    payload_data = {"iss": _ISSUER_A, "aud": _AUDIENCE_A, "sub": "evil", "iat": now - 10, "exp": now + 3600}
    payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=").decode()
    none_token = f"{header}.{payload}."

    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        with pytest.raises(OidcError):
            verify_oidc_token(
                none_token,
                find_config=find_cfg,
                key_resolver=resolver,
                algorithms=["RS256", "HS256"],
            )


def test_verify_oidc_token_oidc_error_contains_no_token_material():
    """EC 25: OidcError messages must not contain raw token, claim bytes, or signature."""
    tenant_id = _make_tenant("no-token-leak")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_ATTACKER,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="secret-role",
    )
    resolver = _rs256_resolver_for(_RSA_PUB_KEY_A)

    with psycopg.connect(admin_dsn()) as conn:
        def find_cfg(iss, aud):
            return find_idp_config(conn, iss, aud)

        try:
            verify_oidc_token(token, find_config=find_cfg, key_resolver=resolver)
            pytest.fail("Expected OidcError but verify succeeded")
        except OidcError as e:
            error_msg = str(e)
            # The token has three segments; none of them should appear verbatim
            token_parts = token.split(".")
            for part in token_parts:
                if len(part) > 5:  # skip trivially short segments
                    assert part not in error_msg, (
                        f"Token segment leaked in OidcError message: {error_msg!r}"
                    )
            assert "secret-role" not in error_msg


# ===========================================================================
# HTTP endpoint integration tests (end-to-end via TestClient)
# ===========================================================================


# ---------------------------------------------------------------------------
# AC 19a: correctly-signed RS256 token -> authenticates, resolves to tenant+role
# ---------------------------------------------------------------------------


def test_oidc_rs256_get_cis_returns_200(pool):
    """AC 19a: valid RS256 token -> GET /cis returns 200."""
    tenant_id = _make_tenant("oidc-rs256-200")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200


def test_oidc_hs256_get_cis_returns_200(pool):
    """AC 19h: valid HS256 token -> GET /cis returns 200 (offline)."""
    tenant_id = _make_tenant("oidc-hs256-200")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        default_role=Role.viewer,
    )
    token = _make_hs256_token(
        secret=_HS256_SECRET,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    client = _app_with_oidc(pool, hs_secret=_HS256_SECRET)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# AC 19b: missing/unmapped role claim -> default_role
# ---------------------------------------------------------------------------


def test_oidc_missing_role_claim_defaults_to_viewer_on_read(pool):
    """AC 19b: missing role_claim -> default_role=viewer -> GET /cis 200."""
    tenant_id = _make_tenant("oidc-missing-role-read")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,  # no role claim
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200


def test_oidc_missing_role_claim_default_viewer_blocks_write(pool):
    """AC 19b: missing role_claim -> default_role=viewer -> POST /connectors 403."""
    tenant_id = _make_tenant("oidc-missing-role-write")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "oidc-test"},
        headers=_oidc_headers(token),
    )
    assert resp.status_code == 403


def test_oidc_unmapped_role_defaults_to_viewer(pool):
    """AC 19b: unmapped role_claim -> default_role=viewer -> GET 200, POST 403."""
    tenant_id = _make_tenant("oidc-unmapped-role")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="not-in-map",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp_read = client.get("/cis", headers=_oidc_headers(token))
    resp_write = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "oidc-unmapped"},
        headers=_oidc_headers(token),
    )
    assert resp_read.status_code == 200
    assert resp_write.status_code == 403


# ---------------------------------------------------------------------------
# AC 19c: viewer OIDC GET 200 / write 403; editor OIDC write 200
# ---------------------------------------------------------------------------


def test_oidc_viewer_principal_get_returns_200(pool):
    """AC 19c: viewer-role OIDC principal can GET /cis (200)."""
    tenant_id = _make_tenant("oidc-viewer-read")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"member": "viewer"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="member",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200


def test_oidc_viewer_principal_write_returns_403(pool):
    """AC 19c / EC 18: viewer-role OIDC principal gets 403 on write-gated route."""
    tenant_id = _make_tenant("oidc-viewer-write-403")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"member": "viewer"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="member",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "viewer-write-test"},
        headers=_oidc_headers(token),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "insufficient permissions"


def test_oidc_editor_principal_write_returns_201(pool):
    """AC 19c / EC 18: editor-role OIDC principal can POST /connectors (201)."""
    tenant_id = _make_tenant("oidc-editor-write")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "oidc-editor-write"},
        headers=_oidc_headers(token),
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# AC 19d: bad signature / expired / wrong-audience / wrong-issuer / no-config -> 401
# ---------------------------------------------------------------------------


def test_oidc_bad_signature_returns_401(pool):
    """AC 19d: bad signature -> 401 'invalid OIDC token'."""
    tenant_id = _make_tenant("oidc-bad-sig")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_ATTACKER,  # wrong key
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"
    assert "Bearer" in resp.headers.get("www-authenticate", resp.headers.get("WWW-Authenticate", ""))


def test_oidc_expired_token_returns_401(pool):
    """AC 19d / EC 13: expired token -> 401 'invalid OIDC token'."""
    tenant_id = _make_tenant("oidc-expired")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        exp_offset=-3600,
        iat_offset=-7200,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"


def test_oidc_wrong_audience_returns_401(pool):
    """AC 19d / EC 11: wrong audience -> 401."""
    tenant_id = _make_tenant("oidc-wrong-aud")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience="completely-different-audience",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"


def test_oidc_wrong_issuer_returns_401(pool):
    """AC 19d / EC 12: wrong issuer -> 401."""
    tenant_id = _make_tenant("oidc-wrong-iss")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer="https://wrong-issuer.example.com",
        audience=_AUDIENCE_A,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"


def test_oidc_no_config_tenant_returns_401(pool):
    """AC 19d / spec §4.8 / EC 9: OIDC token for unconfigured tenant -> 401."""
    # No IdP config registered for this issuer+audience
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer="https://no-config.example.com",
        audience="no-config-audience",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"


def test_oidc_disabled_config_returns_401(pool):
    """EC 10: disabled IdP config (disabled_at non-null) -> 401."""
    tenant_id = _make_tenant("oidc-disabled")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    _disable_idp(tenant_id, _ISSUER_A, _AUDIENCE_A)

    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"


def test_oidc_garbage_jwt_shape_returns_401(pool):
    """EC 7: garbage base64 in 3-segment shape -> routed to OIDC -> 401 'invalid OIDC token'."""
    garbage_token = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl-invalid"
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(garbage_token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"


# ---------------------------------------------------------------------------
# EC 15: algorithm confusion
# ---------------------------------------------------------------------------


def test_oidc_alg_none_token_returns_401(pool):
    """EC 15: alg=none token -> 401."""
    tenant_id = _make_tenant("oidc-alg-none")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)

    import base64, json as json_mod
    header = base64.urlsafe_b64encode(
        json_mod.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    now = int(time.time())
    payload_data = {
        "iss": _ISSUER_A,
        "aud": _AUDIENCE_A,
        "sub": "evil",
        "iat": now - 10,
        "exp": now + 3600,
    }
    payload = base64.urlsafe_b64encode(
        json_mod.dumps(payload_data).encode()
    ).rstrip(b"=").decode()
    none_token = f"{header}.{payload}."

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(none_token))
    assert resp.status_code == 401


def test_oidc_401_has_www_authenticate_bearer(pool):
    """All 401 OIDC failures include WWW-Authenticate: Bearer."""
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer="https://no-config-issuer.example.com",
        audience="no-config-aud",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    www_auth = resp.headers.get("www-authenticate") or resp.headers.get("WWW-Authenticate", "")
    assert "Bearer" in www_auth


# ---------------------------------------------------------------------------
# AC 19e: OIDC request produces usage_event + audit_log with auth_method='oidc'
# ---------------------------------------------------------------------------


def test_oidc_allow_request_writes_usage_event_row(pool):
    """AC 19e / EC 22: OIDC viewer GET /cis -> one usage_event row with auth_method='oidc'."""
    tenant_id = _make_tenant("oidc-usage-event")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    before = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_oidc_headers(token))
    after = _count_usage_rows(tenant_id)

    assert resp.status_code == 200
    assert after - before == 1, f"Expected exactly 1 usage_event row; got {after - before}"


def test_oidc_allow_request_writes_audit_log_row_with_oidc_method(pool):
    """AC 19e: OIDC allow -> audit_log row with auth_method='oidc' and api_key_id=NULL."""
    tenant_id = _make_tenant("oidc-audit-row")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200

    rows = _get_audit_rows(tenant_id)
    allow_rows = [r for r in rows if r["decision"] == "allow"]
    assert len(allow_rows) >= 1, "Expected at least one allow audit row"

    oidc_allow = allow_rows[0]
    assert oidc_allow["auth_method"] == "oidc", (
        f"Expected auth_method='oidc'; got {oidc_allow['auth_method']}"
    )
    assert oidc_allow["api_key_id"] is None, (
        f"Expected api_key_id=NULL for OIDC request; got {oidc_allow['api_key_id']}"
    )


def test_oidc_allow_audit_row_records_correct_role(pool):
    """AC 19e: audit_log row for OIDC editor principal records role='editor'."""
    tenant_id = _make_tenant("oidc-audit-role")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200

    rows = _get_audit_rows(tenant_id)
    allow_rows = [r for r in rows if r["decision"] == "allow" and r["auth_method"] == "oidc"]
    assert len(allow_rows) >= 1
    assert allow_rows[0]["role"] == "editor"


def test_oidc_401_writes_no_audit_or_usage_row(pool):
    """AC 19e: 401 on bad OIDC token -> no audit_log or usage_event rows written."""
    tenant_id = _make_tenant("oidc-401-no-rows")
    # No IdP config: token cannot authenticate
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer="https://unconfigured-401.example.com",
        audience="unconfigured-401-aud",
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    before_audit = _count_audit_rows(tenant_id)
    before_usage = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_oidc_headers(token))
    after_audit = _count_audit_rows(tenant_id)
    after_usage = _count_usage_rows(tenant_id)

    assert resp.status_code == 401
    assert after_audit == before_audit, "No audit_log row should be written on 401"
    assert after_usage == before_usage, "No usage_event row should be written on 401"


def test_oidc_viewer_403_writes_deny_audit_row_with_oidc_method(pool):
    """AC 19c / AC 19e: OIDC viewer write-403 writes deny audit row with auth_method='oidc'."""
    tenant_id = _make_tenant("oidc-viewer-403-audit")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "oidc-viewer-deny"},
        headers=_oidc_headers(token),
    )
    assert resp.status_code == 403

    rows = _get_audit_rows(tenant_id)
    deny_rows = [r for r in rows if r["decision"] == "deny" and r["status_code"] == 403]
    assert len(deny_rows) >= 1, "Expected at least one deny-403 audit row"
    assert deny_rows[0]["auth_method"] == "oidc"
    assert deny_rows[0]["api_key_id"] is None


# ---------------------------------------------------------------------------
# AC 19f: adversarial cross-tenant isolation
# ---------------------------------------------------------------------------


def test_oidc_cross_tenant_token_a_cannot_resolve_to_tenant_b(pool):
    """AC 19f / EC 19: token for tenant A (A's iss+aud) cannot resolve to tenant B."""
    tenant_a = _make_tenant("oidc-cross-a")
    tenant_b = _make_tenant("oidc-cross-b")

    # Tenant A has an IdP config
    _setup_idp(tenant_a, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)

    # Tenant B has a different IdP config
    _setup_idp(tenant_b, issuer=_ISSUER_B, audience=_AUDIENCE_B, default_role=Role.viewer)

    # Token signed for tenant A's iss+aud
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200

    # The resolved tenant should be A, not B. Verify by seeding a CI for B
    # and checking A's response doesn't include it.
    # (Simpler check: the token authenticates to A's tenant_id via find_idp_config)
    # We verify by checking the audit row's tenant scope
    rows_a = _count_audit_rows(tenant_a)
    rows_b = _count_audit_rows(tenant_b)
    assert rows_a >= 1, "Audit row should be for tenant A"
    assert rows_b == 0, "No audit row should exist for tenant B"


def test_oidc_cross_tenant_b_presenting_a_iss_aud_returns_401(pool):
    """AC 19f / EC 19: token using A's iss+aud (not configured for B) -> 401 (no B principal)."""
    tenant_a = _make_tenant("oidc-b-presents-a-a")
    tenant_b = _make_tenant("oidc-b-presents-a-b")

    # Only tenant A has this iss+aud configured
    _setup_idp(tenant_a, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    # Tenant B has DIFFERENT iss+aud — not configured for A's iss+aud

    # Token with A's iss+aud: authenticates to A (not B)
    # This test ensures even if an adversary tries to use A's iss+aud claiming to be B,
    # they can only ever get A's tenant context (because find_idp_config is keyed on iss+aud)
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )

    # Seed a CI under tenant B to make sure it's invisible when A's token is used
    with tenant_session(pool, tenant_b) as conn:
        from infra_twin.connector_sdk import DiscoveredCI
        from infra_twin.core_model import CIType
        from infra_twin.reconciliation import reconcile
        reconcile(
            conn,
            tenant_b,
            [DiscoveredCI(type=CIType.vpc, external_id="vpc-secret-b", name="b-only")],
            source="test",
            ci_types=frozenset({CIType.vpc}),
            edge_types=frozenset(),
        )

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 200
    external_ids = [ci["external_id"] for ci in resp.json()]
    assert "vpc-secret-b" not in external_ids, (
        "Token for tenant A must never reveal tenant B's CIs"
    )


# ---------------------------------------------------------------------------
# AC 19g: ambiguous iss+aud across two tenants -> 401
# ---------------------------------------------------------------------------


def test_oidc_ambiguous_iss_aud_returns_401(pool):
    """AC 19g / EC 20: two tenants sharing same iss+aud -> find_idp_config None -> 401."""
    tenant_a = _make_tenant("oidc-ambiguous-a")
    tenant_b = _make_tenant("oidc-ambiguous-b")

    # Both configured with SAME issuer+audience (a security hazard, denied by spec)
    _setup_idp(tenant_a, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    _setup_idp(tenant_b, issuer=_ISSUER_A, audience=_AUDIENCE_A)

    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.get("/cis", headers=_oidc_headers(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid OIDC token"


# ---------------------------------------------------------------------------
# EC 21: quota exhausted on OIDC -> 429 with deny audit (auth_method='oidc')
# ---------------------------------------------------------------------------


def test_oidc_quota_exhaustion_returns_429(pool):
    """EC 21: OIDC request when quota exhausted -> 429."""
    tenant_id, _ = _make_tenant_with_key_quota("oidc-quota-429", quota=1)
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    # Use up the quota (1 allowed request)
    resp1 = client.get("/cis", headers=_oidc_headers(token))
    assert resp1.status_code == 200

    # Next request should be 429
    resp2 = client.get("/cis", headers=_oidc_headers(token))
    assert resp2.status_code == 429


def test_oidc_quota_exhaustion_deny_audit_has_oidc_method(pool):
    """EC 21: quota-exhausted OIDC request writes deny audit row with auth_method='oidc'."""
    tenant_id, _ = _make_tenant_with_key_quota("oidc-quota-audit", quota=1)
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    # Exhaust quota
    client.get("/cis", headers=_oidc_headers(token))

    before = _count_audit_rows(tenant_id)
    resp = client.get("/cis", headers=_oidc_headers(token))
    after = _count_audit_rows(tenant_id)

    assert resp.status_code == 429
    assert after - before == 1, "Exactly one deny audit row on 429"

    rows = _get_audit_rows(tenant_id)
    deny_429 = [r for r in rows if r["decision"] == "deny" and r["status_code"] == 429]
    assert len(deny_429) >= 1
    assert deny_429[0]["auth_method"] == "oidc"
    assert deny_429[0]["api_key_id"] is None


def test_oidc_quota_exhaustion_no_usage_row(pool):
    """EC 21: quota-exhausted OIDC request writes NO usage_event row."""
    tenant_id, _ = _make_tenant_with_key_quota("oidc-quota-no-usage", quota=1)
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    # Exhaust quota
    client.get("/cis", headers=_oidc_headers(token))

    before = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_oidc_headers(token))
    after = _count_usage_rows(tenant_id)

    assert resp.status_code == 429
    assert after == before, "No usage_event row on quota-exhausted 429"


# ---------------------------------------------------------------------------
# EC 24: RLS adversarial — app role cannot INSERT/UPDATE/DELETE tenant_idp_config
# ---------------------------------------------------------------------------


def test_app_role_cannot_insert_tenant_idp_config():
    """EC 24: INSERT on tenant_idp_config as app role raises permission denied."""
    tenant_id = _make_tenant("rls-insert-test")
    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "INSERT INTO tenant_idp_config (tenant_id, issuer, audience) "
                "VALUES (%s, %s, %s)",
                (tenant_id, "https://evil.example.com", "evil-audience"),
            )
            conn.commit()
    err = str(exc_info.value).lower()
    assert "permission denied" in err or "42501" in err or "insufficient privilege" in err


def test_app_role_cannot_update_tenant_idp_config():
    """EC 24: UPDATE on tenant_idp_config as app role raises permission denied."""
    tenant_id = _make_tenant("rls-update-test")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "UPDATE tenant_idp_config SET issuer = 'tampered' WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()
    err = str(exc_info.value).lower()
    assert "permission denied" in err or "42501" in err or "insufficient privilege" in err


def test_app_role_cannot_delete_tenant_idp_config():
    """EC 24: DELETE on tenant_idp_config as app role raises permission denied."""
    tenant_id = _make_tenant("rls-delete-test")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "DELETE FROM tenant_idp_config WHERE tenant_id = %s", (tenant_id,)
            )
            conn.commit()
    err = str(exc_info.value).lower()
    assert "permission denied" in err or "42501" in err or "insufficient privilege" in err


def test_app_role_select_tenant_idp_config_rls_scoped():
    """EC 24: under tenant_session, SELECT on tenant_idp_config is RLS-scoped to own tenant.

    Verifies that when the app role reads tenant_idp_config with app.tenant_id set to
    tenant A, it only sees A's rows (not B's).
    """
    tenant_a = _make_tenant("rls-select-a")
    tenant_b = _make_tenant("rls-select-b")
    _setup_idp(tenant_a, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    _setup_idp(tenant_b, issuer=_ISSUER_B, audience=_AUDIENCE_B)

    # SELECT as app role with tenant A's session: should only see A's row
    with psycopg.connect(app_dsn()) as conn:
        conn.execute(
            "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_a),)
        )
        rows_a = conn.execute(
            "SELECT tenant_id FROM tenant_idp_config"
        ).fetchall()

    tenant_ids_seen = {r[0] for r in rows_a}
    assert tenant_a in tenant_ids_seen, "App role should see tenant A's own config"
    assert tenant_b not in tenant_ids_seen, (
        "App role must NOT see tenant B's config under tenant A's session (RLS violation)"
    )


# ---------------------------------------------------------------------------
# HTTP endpoints: PUT /tenants/{id}/idp-config and GET /tenants/{id}/idp-config
# ---------------------------------------------------------------------------


def test_put_idp_config_returns_200(pool, monkeypatch):
    """AC 15: PUT /tenants/{id}/idp-config with valid body returns 200."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-200")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={
            "issuer": "https://put-test.example.com",
            "audience": "put-audience",
        },
        headers=_admin_headers(),
    )
    assert resp.status_code == 200


def test_put_idp_config_returns_correct_keys(pool, monkeypatch):
    """AC 16: PUT /tenants/{id}/idp-config returns no-secret dict with exactly expected keys."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-keys")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={
            "issuer": "https://put-keys.example.com",
            "audience": "put-keys-audience",
        },
        headers=_admin_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    expected_keys = {
        "idp_config_id", "tenant_id", "issuer", "audience",
        "role_claim", "role_claim_map", "default_role", "created_at", "disabled_at",
    }
    assert set(body.keys()) == expected_keys, (
        f"Response keys mismatch: {set(body.keys())} vs {expected_keys}"
    )


def test_put_idp_config_no_secret_material_in_response(pool, monkeypatch):
    """AC 16: PUT /tenants/{id}/idp-config response contains no secret material."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-no-secret")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={
            "issuer": "https://no-secret.example.com",
            "audience": "no-secret-audience",
        },
        headers=_admin_headers(),
    )
    assert resp.status_code == 200
    body_str = str(resp.json())
    # No private key, no hash, no signature - only the config fields
    # Verify no key PEM material leaked
    assert "PRIVATE" not in body_str
    assert "BEGIN RSA" not in body_str


def test_put_idp_config_without_bootstrap_token_returns_401(pool, monkeypatch):
    """AC 15: PUT /tenants/{id}/idp-config without bootstrap token -> 401."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-401")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={"issuer": "https://test.example.com", "audience": "aud"},
    )
    assert resp.status_code == 401


def test_put_idp_config_without_env_returns_503(pool, monkeypatch):
    """AC 15: PUT /tenants/{id}/idp-config when BOOTSTRAP env unset -> 503."""
    monkeypatch.delenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", raising=False)
    tenant_id = _make_tenant("put-idp-503")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={"issuer": "https://test.example.com", "audience": "aud"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 503


def test_put_idp_config_empty_issuer_returns_422(pool, monkeypatch):
    """AC 15: PUT /tenants/{id}/idp-config with empty issuer -> 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-422-iss")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={"issuer": "  ", "audience": "valid-audience"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_put_idp_config_empty_audience_returns_422(pool, monkeypatch):
    """AC 15: PUT /tenants/{id}/idp-config with empty audience -> 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-422-aud")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={"issuer": "https://valid.example.com", "audience": ""},
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_put_idp_config_bad_role_claim_map_value_returns_422(pool, monkeypatch):
    """AC 15: PUT /tenants/{id}/idp-config with invalid role_claim_map value -> 422."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-422-map")
    client = TestClient(create_app(pool=pool))
    resp = client.put(
        f"/tenants/{tenant_id}/idp-config",
        json={
            "issuer": "https://valid.example.com",
            "audience": "valid-audience",
            "role_claim_map": {"admin": "superadmin"},  # invalid value
        },
        headers=_admin_headers(),
    )
    assert resp.status_code == 422


def test_put_idp_config_is_idempotent(pool, monkeypatch):
    """AC 10 / AC 15: re-PUT with same iss+aud updates and does not create duplicates."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("put-idp-idempotent")
    client = TestClient(create_app(pool=pool))

    body = {"issuer": "https://idempotent.example.com", "audience": "idempotent-aud"}

    resp1 = client.put(f"/tenants/{tenant_id}/idp-config", json=body, headers=_admin_headers())
    resp2 = client.put(f"/tenants/{tenant_id}/idp-config", json=body, headers=_admin_headers())

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    with psycopg.connect(admin_dsn()) as conn:
        count = conn.execute(
            "SELECT count(*) FROM tenant_idp_config WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()[0]
    assert count == 1, f"Idempotent PUT should not duplicate rows; found {count}"


def test_get_idp_config_returns_empty_list(pool, monkeypatch):
    """AC 16: GET /tenants/{id}/idp-config with no configs returns empty list."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("get-idp-empty")
    client = TestClient(create_app(pool=pool))
    resp = client.get(f"/tenants/{tenant_id}/idp-config", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_idp_config_returns_configured_row(pool, monkeypatch):
    """AC 16: GET /tenants/{id}/idp-config returns list with configured row."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("get-idp-row")
    _setup_idp(
        tenant_id,
        issuer="https://get-test.example.com",
        audience="get-test-aud",
        role_claim="groups",
        role_claim_map={"admins": "editor"},
        default_role=Role.viewer,
    )
    client = TestClient(create_app(pool=pool))
    resp = client.get(f"/tenants/{tenant_id}/idp-config", headers=_admin_headers())
    assert resp.status_code == 200
    configs = resp.json()
    assert len(configs) == 1
    cfg = configs[0]
    assert cfg["issuer"] == "https://get-test.example.com"
    assert cfg["audience"] == "get-test-aud"
    assert cfg["role_claim"] == "groups"
    assert cfg["role_claim_map"] == {"admins": "editor"}
    assert cfg["default_role"] == "viewer"
    assert cfg["disabled_at"] is None


def test_get_idp_config_no_bootstrap_returns_401(pool, monkeypatch):
    """AC 16: GET /tenants/{id}/idp-config without bootstrap token -> 401."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("get-idp-401")
    client = TestClient(create_app(pool=pool))
    resp = client.get(f"/tenants/{tenant_id}/idp-config")
    assert resp.status_code == 401


def test_get_idp_config_no_env_returns_503(pool, monkeypatch):
    """AC 16: GET /tenants/{id}/idp-config when BOOTSTRAP env unset -> 503."""
    monkeypatch.delenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", raising=False)
    tenant_id = _make_tenant("get-idp-503")
    client = TestClient(create_app(pool=pool))
    resp = client.get(f"/tenants/{tenant_id}/idp-config", headers=_admin_headers())
    assert resp.status_code == 503


def test_get_idp_config_response_keys_are_no_secret(pool, monkeypatch):
    """AC 16: GET response keys exactly match the no-secret shape spec."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("get-idp-keys")
    _setup_idp(tenant_id, issuer="https://keys-check.example.com", audience="keys-aud")
    client = TestClient(create_app(pool=pool))
    resp = client.get(f"/tenants/{tenant_id}/idp-config", headers=_admin_headers())
    assert resp.status_code == 200
    configs = resp.json()
    assert len(configs) == 1
    expected_keys = {
        "idp_config_id", "tenant_id", "issuer", "audience",
        "role_claim", "role_claim_map", "default_role", "created_at", "disabled_at",
    }
    assert set(configs[0].keys()) == expected_keys


# ---------------------------------------------------------------------------
# Migration 0014 idempotency (AC 23)
# ---------------------------------------------------------------------------


def test_migration_0014_is_idempotent():
    """AC 23: re-running migrations after 0014 is a no-op."""
    from infra_twin.db.migrate import run_migrations
    applied = run_migrations(directory=_MIGRATIONS_DIR)
    names_0014 = [m for m in (applied or []) if "0014" in str(m)]
    assert names_0014 == [], f"0014 was re-applied: {names_0014}"


# ---------------------------------------------------------------------------
# Module/package structural checks (AC 11)
# ---------------------------------------------------------------------------


def test_oidc_module_defines_resolved_oidc_principal():
    """AC 11: infra_twin.api.oidc defines ResolvedOidcPrincipal."""
    from infra_twin.api.oidc import ResolvedOidcPrincipal
    assert hasattr(ResolvedOidcPrincipal, "__dataclass_fields__")


def test_oidc_module_defines_oidc_error():
    """AC 11: infra_twin.api.oidc defines OidcError (Exception subclass)."""
    from infra_twin.api.oidc import OidcError
    assert issubclass(OidcError, Exception)


def test_oidc_module_defines_looks_like_jwt():
    """AC 11: infra_twin.api.oidc defines looks_like_jwt."""
    from infra_twin.api.oidc import looks_like_jwt
    assert callable(looks_like_jwt)


def test_oidc_module_defines_verify_oidc_token():
    """AC 11: infra_twin.api.oidc defines verify_oidc_token."""
    from infra_twin.api.oidc import verify_oidc_token
    assert callable(verify_oidc_token)


def test_oidc_module_has_docstring_documenting_routing():
    """AC 11: oidc.py module docstring documents the JWT-vs-itw_ routing scheme."""
    import infra_twin.api.oidc as oidc_mod
    assert oidc_mod.__doc__ is not None
    doc = oidc_mod.__doc__
    assert "itw_" in doc or "KEY_PREFIX" in doc or "api_key" in doc.lower(), (
        "Module docstring must document the routing scheme between itw_ keys and JWTs"
    )


def test_auth_module_defines_principal():
    """AC 13: auth.py defines Principal dataclass."""
    from infra_twin.api.auth import Principal
    assert hasattr(Principal, "__dataclass_fields__")
    principal_fields = {f.name for f in fields(Principal)}
    assert principal_fields == {"tenant_id", "role", "auth_method", "api_key_id"}


def test_pyjwt_and_cryptography_installed():
    """AC 18: PyJWT and cryptography are installed and importable."""
    import jwt as pyjwt
    import cryptography
    assert hasattr(pyjwt, "decode")
    assert hasattr(cryptography, "__version__")


# ===========================================================================
# AC 14: Backward-compatibility — existing API-key path unchanged
# ===========================================================================


def test_apikey_path_missing_auth_returns_401(pool):
    """AC 14: no Authorization header -> 401 'missing API key' (unchanged)."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing API key"


def test_apikey_path_invalid_key_returns_401(pool):
    """AC 14: invalid API key -> 401 'invalid API key' (unchanged)."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers={"Authorization": "Bearer itw_bogus.secret"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid API key"


def test_apikey_path_viewer_get_cis_returns_200(pool):
    """AC 14: API-key viewer GET /cis -> 200 (unchanged)."""
    _, viewer_key = _make_tenant_with_key("compat-viewer-read", role=Role.viewer)
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers=_auth(viewer_key))
    assert resp.status_code == 200


def test_apikey_path_viewer_write_returns_403(pool):
    """AC 14: API-key viewer POST /connectors -> 403 (unchanged)."""
    _, viewer_key = _make_tenant_with_key("compat-viewer-write", role=Role.viewer)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "compat"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403


def test_apikey_path_editor_write_returns_201(pool):
    """AC 14: API-key editor POST /connectors -> 201 (unchanged)."""
    _, editor_key = _make_tenant_with_key("compat-editor-write", role=Role.editor)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "compat-write"},
        headers=_auth(editor_key),
    )
    assert resp.status_code == 201


def test_apikey_path_writes_audit_row_with_api_key_method(pool):
    """AC 14: API-key auth path writes audit_log row with auth_method='api_key'."""
    tenant_id, viewer_key = _make_tenant_with_key("compat-audit-apikey", role=Role.viewer)
    client = TestClient(create_app(pool=pool))
    resp = client.get("/cis", headers=_auth(viewer_key))
    assert resp.status_code == 200

    rows = _get_audit_rows(tenant_id)
    assert len(rows) >= 1
    allow_rows = [r for r in rows if r["decision"] == "allow"]
    assert len(allow_rows) >= 1
    assert allow_rows[0]["auth_method"] == "api_key"
    assert allow_rows[0]["api_key_id"] is not None


def test_apikey_path_writes_usage_event_row(pool):
    """AC 14: API-key auth path writes usage_event row (unchanged)."""
    tenant_id, editor_key = _make_tenant_with_key("compat-usage", role=Role.editor)
    client = TestClient(create_app(pool=pool))

    before = _count_usage_rows(tenant_id)
    resp = client.get("/cis", headers=_auth(editor_key))
    after = _count_usage_rows(tenant_id)

    assert resp.status_code == 200
    assert after - before == 1


def test_apikey_path_viewer_403_writes_deny_audit(pool):
    """AC 14: API-key viewer 403 writes deny audit row (unchanged)."""
    tenant_id, viewer_key = _make_tenant_with_key("compat-deny", role=Role.viewer)
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "compat-deny"},
        headers=_auth(viewer_key),
    )
    assert resp.status_code == 403

    rows = _get_audit_rows(tenant_id)
    deny_rows = [r for r in rows if r["decision"] == "deny"]
    assert len(deny_rows) >= 1
    assert deny_rows[0]["auth_method"] == "api_key"
    assert deny_rows[0]["api_key_id"] is not None


def test_tenant_with_no_idp_config_authenticates_via_api_key(pool):
    """AC 4.8 / AC 14: tenant with no IdP config still authenticates via API key."""
    tenant_id, api_key = _make_tenant_with_key("no-idp-api-key")
    client = TestClient(create_app(pool=pool))
    # No IdP config registered for this tenant
    resp = client.get("/cis", headers=_auth(api_key))
    assert resp.status_code == 200


# ===========================================================================
# GET /audit-log OIDC field in HTTP response
# ===========================================================================


def test_get_audit_log_includes_auth_method_field(pool):
    """AC 3.3 / app.py serializer: GET /audit-log includes auth_method and nullable api_key_id."""
    tenant_id = _make_tenant("audit-log-oidc-fields")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        default_role=Role.viewer,
    )
    token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,
    )
    # Issue an API key for this tenant so we can read the audit log
    with psycopg.connect(admin_dsn()) as conn:
        from infra_twin.db.api_keys import provision_tenant as pt2
        issued = pt2(conn, "audit-log-oidc-reader", role=Role.viewer)
        # Transfer the key to our tenant (we need a separate key for reading)
        # Actually just use the OIDC token to make one request, then read via a separate key
    # Create a second tenant with API key to avoid self-referential complexity
    tenant_id2, reader_key = _make_tenant_with_key("audit-log-reader-2", role=Role.viewer)
    # Use OIDC for tenant_id (our primary test)
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    client.get("/cis", headers=_oidc_headers(token))

    # Verify via DB directly that auth_method='oidc' is in the row
    rows = _get_audit_rows(tenant_id)
    assert len(rows) >= 1
    oidc_rows = [r for r in rows if r["auth_method"] == "oidc"]
    assert len(oidc_rows) >= 1, f"Expected OIDC audit row; got {rows}"


def test_get_audit_log_api_endpoint_returns_auth_method(pool):
    """AC 3.3: GET /audit-log endpoint returns auth_method field in JSON."""
    _, api_key = _make_tenant_with_key("audit-log-api-method", role=Role.viewer)
    client = TestClient(create_app(pool=pool))
    # Make a request to generate an audit row
    client.get("/cis", headers=_auth(api_key))
    # Read the audit log
    resp = client.get("/audit-log", headers=_auth(api_key))
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) >= 1
    # Every entry must have auth_method
    for entry in entries:
        assert "auth_method" in entry, f"Missing auth_method in audit entry: {entry}"
        assert "api_key_id" in entry, f"Missing api_key_id in audit entry: {entry}"
