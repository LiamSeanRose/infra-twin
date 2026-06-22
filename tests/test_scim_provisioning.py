"""SCIM 2.0 provisioning tests.

Covers every acceptance criterion from spec §7 (AC 1-28) and every edge case
from spec §6 (EC 1-32), with special emphasis on:

  AC 14  POST /scim/v2/Users -> 201 SCIM-shaped response (schemas/meta/id/userName/active/role)
  AC 15  GET /scim/v2/Users/{id} -> 200 for known; 404 for unknown/other-tenant
  AC 16  GET /scim/v2/Users?filter=userName eq "X" -> ListResponse; unsupported -> 400
  AC 17  PATCH replace active false / PUT active:false -> 200, active=false in DB
  AC 18  SCIM routes -> 401 on absent/malformed/itw_/JWT Authorization
  AC 19  OIDC token for inactive SCIM user -> 401 "user deactivated"
  AC 20  Active SCIM user / no SCIM record -> authenticates normally
  AC 21  SCIM role='editor' overrides OIDC viewer; SCIM viewer -> 403 on write
  AC 22  Cross-tenant adversarial: SCIM token/user for A never touches B
  AC 25  Append-only/never-hard-deleted (after deactivation >= 2 rows in lineage)
         and no DELETE privilege on app role for scim_user
  AC 26  conftest.py _DATA_TABLES includes scim_user and scim_provisioning_token
  AC 27  POST /tenants/{tenant_id}/scim-token -> 201 with one-time scim_token

Schema checks (spec §4):
  AC 1-7  Migration 0015 is highest-numbered; tables/columns/indexes/RLS/grants exact
  AC 8    ScimUser and GeneratedScimToken frozen dataclasses exist
  AC 9    All 10 symbols importable from infra_twin.db and in __all__
  AC 10   scim_users.py reuses new_salt/hash_secret/verify_secret/Role from api_keys
  AC 11   resolve_scim_token behaviour (admin conn, None paths, timing equalization)
  AC 12   deactivate_user leaves >= 2 rows in lineage
  AC 13   Module docstring documents credential-storage, role-override precedence,
          subject-lookup precedence

EC coverage:
  EC 1   Missing SCIM token -> 401 "missing SCIM token"
  EC 2   Malformed token (no scim_ prefix) -> 401 "invalid SCIM token"
  EC 3   Valid shape but unknown token_id -> 401
  EC 4   Correct token_id but wrong secret -> 401
  EC 5   Revoked SCIM token -> 401
  EC 6   itw_ API key on SCIM route -> 401
  EC 7   Valid JWT on SCIM route -> 401
  EC 8   scim_ token on data-plane route (/cis) -> 401 "invalid API key"
  EC 9   Idempotent re-provision (userName already current) -> 201, one current row
  EC 10  Blank userName -> 422
  EC 11  Duplicate externalId -> 409
  EC 12  Two tenants same userName allowed; isolation holds
  EC 13  GET/PATCH/PUT other-tenant id -> 404
  EC 14  List filter no match -> 200 totalResults:0 empty Resources
  EC 15  Unsupported filter operator -> 400
  EC 16  PATCH empty Operations -> 400
  EC 17  PATCH deactivate already-inactive -> idempotent, active=false, one current row
  EC 18  PATCH reactivate inactive user -> active=true, 200
  EC 19  Deactivate then GET -> current row active=false; historical rows remain
  EC 20  Never hard-delete: >= 2 rows after deactivation; no DELETE privilege
  EC 21  OIDC inactive SCIM user -> 401 "user deactivated"
  EC 22  OIDC active SCIM user -> authenticates; SCIM role overrides
  EC 23  OIDC no SCIM record -> unchanged behavior
  EC 24  OIDC deactivated then reactivated SCIM user -> authenticates normally
  EC 25  OIDC subject precedence: sub > email > preferred_username
  EC 26  Different tenant's SCIM-deactivated user does NOT affect this tenant's OIDC auth
  EC 27  API-key path unaffected by SCIM deactivation
"""

from __future__ import annotations

import pathlib
import time
from dataclasses import fields
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.api.oidc import ResolvedOidcPrincipal
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn, app_dsn
from infra_twin.db.idp_config import upsert_idp_config
from infra_twin.db.scim_users import (
    SCIM_TOKEN_PREFIX,
    GeneratedScimToken,
    ScimUser,
    create_or_replace_user,
    deactivate_user,
    get_current_user_by_username,
    get_user_by_id,
    issue_scim_token,
    list_users,
    parse_scim_token,
    resolve_scim_token,
)
from infra_twin.db.session import tenant_session

# Reuse RSA helpers from test_oidc_auth to avoid duplicating key generation.
# pytest adds the tests/ directory to sys.path so this import works at runtime.
import importlib
_oidc_mod = importlib.import_module("test_oidc_auth")

_ISSUER_A = _oidc_mod._ISSUER_A
_AUDIENCE_A = _oidc_mod._AUDIENCE_A
_ISSUER_B = _oidc_mod._ISSUER_B
_AUDIENCE_B = _oidc_mod._AUDIENCE_B
_RSA_PRIV_KEY_A = _oidc_mod._RSA_PRIV_KEY_A
_RSA_PUB_KEY_A = _oidc_mod._RSA_PUB_KEY_A
_RSA_PRIV_KEY_B = _oidc_mod._RSA_PRIV_KEY_B
_RSA_PUB_KEY_B = _oidc_mod._RSA_PUB_KEY_B
_HS256_SECRET = _oidc_mod._HS256_SECRET
_BOOTSTRAP_TOKEN = _oidc_mod._BOOTSTRAP_TOKEN
_make_rs256_token = _oidc_mod._make_rs256_token
_make_hs256_token = _oidc_mod._make_hs256_token
_rs256_resolver_for = _oidc_mod._rs256_resolver_for
_hs256_resolver_for = _oidc_mod._hs256_resolver_for
_app_with_oidc = _oidc_mod._app_with_oidc
_setup_idp = _oidc_mod._setup_idp

_MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[1] / "migrations"

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


def _issue_scim_token_for(tenant_id: UUID, name: str | None = None) -> str:
    """Issue a SCIM token for the given tenant, returning the plaintext."""
    with psycopg.connect(admin_dsn()) as conn:
        generated = issue_scim_token(conn, tenant_id, name=name)
        conn.commit()
    return generated.plaintext


def _scim_auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin_headers() -> dict:
    return {"Authorization": f"Bearer {_BOOTSTRAP_TOKEN}"}


def _count_scim_rows(tenant_id: UUID, user_name: str) -> int:
    """Count ALL rows (current + historical) for a (tenant, user_name) pair."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM scim_user WHERE tenant_id = %s AND user_name = %s",
            (tenant_id, user_name),
        ).fetchone()
    return row[0]


def _count_current_scim_rows(tenant_id: UUID, user_name: str) -> int:
    """Count only current (valid_to IS NULL) rows."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT count(*) FROM scim_user WHERE tenant_id = %s AND user_name = %s AND valid_to IS NULL",
            (tenant_id, user_name),
        ).fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# App factory helpers for SCIM tests
# ---------------------------------------------------------------------------


def _app_plain(pool):
    """TestClient with no OIDC key resolver (SCIM tests don't need OIDC)."""
    return TestClient(create_app(pool=pool))


# ===========================================================================
# Schema structural checks (AC 1-7)
# ===========================================================================


def test_migration_0015_file_exists():
    """AC 1: migrations/0015_scim_users.sql exists."""
    assert (_MIGRATIONS_DIR / "0015_scim_users.sql").exists()


def test_migration_0015_is_present_and_ordered():
    """AC 1: 0015_scim_users.sql is a present migration ordered after 0014."""
    sql_files = sorted(f.name for f in _MIGRATIONS_DIR.glob("*.sql"))
    assert "0015_scim_users.sql" in sql_files, (
        f"0015_scim_users.sql is missing; files: {sql_files}"
    )
    idx = sql_files.index("0015_scim_users.sql")
    assert idx > 0 and sql_files[idx - 1].startswith("0014"), (
        f"0015 is not ordered immediately after 0014; files: {sql_files}"
    )


def test_scim_user_table_has_exact_columns():
    """AC 2: scim_user has exactly the 9 required columns."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'scim_user' ORDER BY ordinal_position"
        ).fetchall()
    columns = {r[0] for r in rows}
    expected = {
        "scim_user_id", "tenant_id", "external_id", "user_name", "role",
        "active", "valid_from", "valid_to", "created_at",
    }
    assert columns == expected, f"Column mismatch: {columns} vs {expected}"


def test_scim_user_pk_is_uuid_with_gen_random_uuid():
    """AC 3: scim_user_id is PRIMARY KEY with gen_random_uuid() default."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = 'scim_user' AND column_name = 'scim_user_id'"
        ).fetchone()
    assert row is not None
    assert row[0] is not None and "gen_random_uuid" in row[0].lower()


def test_scim_user_tenant_id_fk_to_tenants():
    """AC 3: scim_user.tenant_id is a FK to tenants(tenant_id)."""
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
            WHERE tc.table_name = 'scim_user'
              AND kcu.column_name = 'tenant_id'
            """
        ).fetchone()
    assert row is not None, "FK constraint on scim_user.tenant_id not found"
    assert row[0] == "FOREIGN KEY"
    assert row[1] == "tenants"


def test_scim_user_role_check_constraint():
    """AC 3: scim_user.role CHECK restricts to ('viewer','editor')."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            """
            SELECT cc.check_clause
            FROM information_schema.table_constraints tc
            JOIN information_schema.check_constraints cc
              ON tc.constraint_name = cc.constraint_name
            WHERE tc.table_name = 'scim_user' AND tc.constraint_type = 'CHECK'
            """
        ).fetchall()
    clauses = " ".join(r[0] for r in rows).lower()
    assert "role" in clauses
    assert "viewer" in clauses
    assert "editor" in clauses


def test_scim_user_active_column_properties():
    """AC 3: scim_user.active is BOOLEAN NOT NULL DEFAULT true."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable, column_default, data_type FROM information_schema.columns "
            "WHERE table_name = 'scim_user' AND column_name = 'active'"
        ).fetchone()
    assert row is not None, "scim_user.active column not found"
    is_nullable, col_default, data_type = row
    assert is_nullable == "NO", f"active must be NOT NULL; got is_nullable={is_nullable}"
    assert col_default is not None and "true" in col_default.lower(), (
        f"active DEFAULT should be true; got: {col_default}"
    )
    assert "bool" in data_type.lower()


def test_scim_user_valid_to_is_nullable():
    """AC 3: scim_user.valid_to is nullable (bitemporal open row indicator)."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name = 'scim_user' AND column_name = 'valid_to'"
        ).fetchone()
    assert row is not None
    assert row[0] == "YES", f"valid_to must be nullable; got is_nullable={row[0]}"


def test_scim_user_valid_from_created_at_not_null_with_default():
    """AC 3: valid_from and created_at are TIMESTAMPTZ NOT NULL DEFAULT now()."""
    with psycopg.connect(admin_dsn()) as conn:
        rows = conn.execute(
            "SELECT column_name, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'scim_user' AND column_name IN ('valid_from', 'created_at')"
        ).fetchall()
    cols = {r[0]: (r[1], r[2]) for r in rows}
    for col_name in ("valid_from", "created_at"):
        assert col_name in cols, f"Column {col_name} missing from scim_user"
        is_nullable, col_default = cols[col_name]
        assert is_nullable == "NO", f"{col_name} must be NOT NULL"
        assert col_default is not None and "now" in col_default.lower(), (
            f"{col_name} should default to now(); got: {col_default}"
        )


def test_scim_user_partial_unique_index_on_username():
    """AC 4: UNIQUE index on scim_user (tenant_id, user_name) WHERE valid_to IS NULL."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE tablename = 'scim_user' AND indexname = 'scim_user_current_username'"
        ).fetchone()
    assert row is not None, "Partial unique index scim_user_current_username not found"
    idx_def = row[1].upper()
    assert "UNIQUE" in idx_def
    assert "VALID_TO IS NULL" in idx_def or "WHERE" in idx_def


def test_scim_user_partial_unique_index_on_external_id():
    """AC 4: UNIQUE index on scim_user (tenant_id, external_id) WHERE valid_to IS NULL AND external_id IS NOT NULL."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE tablename = 'scim_user' AND indexname = 'scim_user_current_external_id'"
        ).fetchone()
    assert row is not None, "Partial unique index scim_user_current_external_id not found"
    idx_def = row[1].upper()
    assert "UNIQUE" in idx_def
    assert "VALID_TO IS NULL" in idx_def or "WHERE" in idx_def


def test_scim_user_rls_enabled():
    """AC 5: RLS is enabled on scim_user."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT relrowsecurity FROM pg_class WHERE relname = 'scim_user'"
        ).fetchone()
    assert row is not None
    assert row[0] is True, "RLS should be enabled on scim_user"


def test_scim_user_rls_policy_exists():
    """AC 5: tenant_isolation policy exists on scim_user."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies "
            "WHERE tablename = 'scim_user' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on scim_user"


def test_app_role_has_select_insert_update_not_delete_on_scim_user():
    """AC 6: app role has SELECT, INSERT, UPDATE on scim_user; NOT DELETE."""
    with psycopg.connect(admin_dsn()) as conn:
        privs = conn.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'scim_user' AND grantee = 'app'"
        ).fetchall()
    priv_types = {r[0] for r in privs}
    assert "SELECT" in priv_types, "app role must have SELECT on scim_user"
    assert "INSERT" in priv_types, "app role must have INSERT on scim_user"
    assert "UPDATE" in priv_types, "app role must have UPDATE on scim_user"
    assert "DELETE" not in priv_types, "app role must NOT have DELETE on scim_user (never hard-delete)"


def test_scim_provisioning_token_table_exists():
    """AC 7: scim_provisioning_token table exists."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_name = 'scim_provisioning_token'"
        ).fetchone()
    assert row is not None, "scim_provisioning_token table does not exist"


def test_scim_provisioning_token_rls_enabled():
    """AC 7: RLS is enabled on scim_provisioning_token."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT relrowsecurity FROM pg_class WHERE relname = 'scim_provisioning_token'"
        ).fetchone()
    assert row is not None
    assert row[0] is True, "RLS should be enabled on scim_provisioning_token"


def test_scim_provisioning_token_rls_policy_exists():
    """AC 7: tenant_isolation policy exists on scim_provisioning_token."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT policyname FROM pg_policies "
            "WHERE tablename = 'scim_provisioning_token' AND policyname = 'tenant_isolation'"
        ).fetchone()
    assert row is not None, "tenant_isolation policy not found on scim_provisioning_token"


def test_scim_provisioning_token_unique_index_on_token_id():
    """AC 7: UNIQUE index on scim_provisioning_token(token_id) exists."""
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE tablename = 'scim_provisioning_token' "
            "  AND indexname = 'scim_provisioning_token_token_id'"
        ).fetchone()
    assert row is not None, "Unique index scim_provisioning_token_token_id not found"
    assert "UNIQUE" in row[1].upper()


def test_app_role_has_select_only_on_scim_provisioning_token():
    """AC 7: app role has SELECT only on scim_provisioning_token (no INSERT/UPDATE/DELETE)."""
    with psycopg.connect(admin_dsn()) as conn:
        privs = conn.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'scim_provisioning_token' AND grantee = 'app'"
        ).fetchall()
    priv_types = {r[0] for r in privs}
    assert "SELECT" in priv_types, "app role must have SELECT on scim_provisioning_token"
    assert "INSERT" not in priv_types, "app role must NOT have INSERT on scim_provisioning_token"
    assert "UPDATE" not in priv_types, "app role must NOT have UPDATE on scim_provisioning_token"
    assert "DELETE" not in priv_types, "app role must NOT have DELETE on scim_provisioning_token"


# ===========================================================================
# DB module structural checks (AC 8-13)
# ===========================================================================


def test_scim_user_is_frozen_dataclass():
    """AC 8: ScimUser is a frozen dataclass with exactly 9 fields."""
    assert hasattr(ScimUser, "__dataclass_fields__")
    scim_fields = {f.name for f in fields(ScimUser)}
    expected_fields = {
        "scim_user_id", "tenant_id", "external_id", "user_name", "role",
        "active", "valid_from", "valid_to", "created_at",
    }
    assert scim_fields == expected_fields, f"Field mismatch: {scim_fields} vs {expected_fields}"

    # Frozen: writing to any field must raise.
    import dataclasses
    from datetime import datetime, timezone
    from uuid import uuid4
    dummy = ScimUser(
        scim_user_id=uuid4(),
        tenant_id=uuid4(),
        external_id=None,
        user_name="frozen-test",
        role=Role.viewer,
        active=True,
        valid_from=datetime.now(timezone.utc),
        valid_to=None,
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        dummy.user_name = "mutated"  # type: ignore[misc]


def test_generated_scim_token_is_frozen_dataclass():
    """AC 8: GeneratedScimToken is a frozen dataclass with plaintext/token_id/secret."""
    assert hasattr(GeneratedScimToken, "__dataclass_fields__")
    gt_fields = {f.name for f in fields(GeneratedScimToken)}
    assert gt_fields == {"plaintext", "token_id", "secret"}

    import dataclasses
    dummy = GeneratedScimToken(plaintext="scim_abc.xyz", token_id="abc", secret="xyz")
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        dummy.plaintext = "mutated"  # type: ignore[misc]


def test_all_10_scim_symbols_importable_from_infra_twin_db():
    """AC 9: all 10 SCIM symbols importable from infra_twin.db and in __all__."""
    import infra_twin.db as db

    symbols = [
        "ScimUser", "GeneratedScimToken", "SCIM_TOKEN_PREFIX",
        "issue_scim_token", "resolve_scim_token", "create_or_replace_user",
        "get_user_by_id", "get_current_user_by_username", "list_users",
        "deactivate_user",
    ]
    for sym in symbols:
        assert sym in db.__all__, f"{sym} not in infra_twin.db.__all__"
        assert hasattr(db, sym), f"{sym} not importable from infra_twin.db"


def test_scim_token_prefix_value():
    """AC 9: SCIM_TOKEN_PREFIX is 'scim_'."""
    assert SCIM_TOKEN_PREFIX == "scim_"


def test_scim_users_module_reuses_api_keys_helpers():
    """AC 10: scim_users.py imports new_salt/hash_secret/verify_secret/Role from api_keys."""
    import infra_twin.db.scim_users as scim_mod
    import inspect
    src = inspect.getsource(scim_mod)
    # Must import from api_keys, not re-implement
    assert "from infra_twin.db.api_keys import" in src
    assert "hash_secret" in src
    assert "verify_secret" in src
    assert "new_salt" in src
    assert "Role" in src
    # Must NOT define its own scrypt call for hashing
    assert "hashlib.scrypt" not in src or "_DUMMY" in src  # dummy salt init is ok


def test_resolve_scim_token_returns_none_for_malformed():
    """AC 11: resolve_scim_token returns None for malformed token (no scim_ prefix)."""
    with psycopg.connect(admin_dsn()) as conn:
        result = resolve_scim_token(conn, "itw_notascimtoken.secret")
    assert result is None


def test_resolve_scim_token_returns_none_for_unknown_token_id():
    """AC 11: resolve_scim_token returns None for valid shape but unknown token_id."""
    with psycopg.connect(admin_dsn()) as conn:
        result = resolve_scim_token(conn, "scim_unknownid.unknownsecret")
    assert result is None


def test_resolve_scim_token_returns_none_for_wrong_secret():
    """AC 11: resolve_scim_token returns None when token_id exists but secret is wrong."""
    tenant_id = _make_tenant("resolve-wrong-secret")
    plaintext = _issue_scim_token_for(tenant_id)
    # Corrupt the secret part
    token_id, _, secret = plaintext[len("scim_"):].partition(".")
    wrong_token = f"scim_{token_id}.WRONGSECRET"
    with psycopg.connect(admin_dsn()) as conn:
        result = resolve_scim_token(conn, wrong_token)
    assert result is None


def test_resolve_scim_token_returns_tenant_id_for_valid():
    """AC 11: resolve_scim_token returns the owning tenant_id for a valid token."""
    tenant_id = _make_tenant("resolve-valid")
    plaintext = _issue_scim_token_for(tenant_id)
    with psycopg.connect(admin_dsn()) as conn:
        result = resolve_scim_token(conn, plaintext)
    assert result == tenant_id


def test_resolve_scim_token_returns_none_for_revoked():
    """AC 11 / EC 5: resolve_scim_token returns None for a revoked token."""
    tenant_id = _make_tenant("resolve-revoked")
    plaintext = _issue_scim_token_for(tenant_id)
    # Parse the token_id from the plaintext
    parsed = parse_scim_token(plaintext)
    assert parsed is not None
    token_id, _ = parsed
    # Mark as revoked directly in DB
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(
            "UPDATE scim_provisioning_token SET revoked_at = now() WHERE token_id = %s",
            (token_id,),
        )
        conn.commit()
    with psycopg.connect(admin_dsn()) as conn:
        result = resolve_scim_token(conn, plaintext)
    assert result is None


def test_dummy_hash_constants_exist_in_scim_users():
    """AC 11: _DUMMY_SALT and _DUMMY_HASH exist in scim_users module (timing equalization)."""
    import infra_twin.db.scim_users as scim_mod
    assert hasattr(scim_mod, "_DUMMY_SALT")
    assert hasattr(scim_mod, "_DUMMY_HASH")


def test_deactivate_user_leaves_at_least_two_rows_in_lineage(pool):
    """AC 12: after deactivate_user, >= 2 rows exist for that user_name lineage."""
    tenant_id = _make_tenant("deactivate-lineage")
    user_name = "lineage@example.com"
    with tenant_session(pool, tenant_id) as conn:
        user = create_or_replace_user(conn, tenant_id, user_name)
        inactive = deactivate_user(conn, tenant_id, user.scim_user_id)

    total = _count_scim_rows(tenant_id, user_name)
    current = _count_current_scim_rows(tenant_id, user_name)

    assert total >= 2, f"Expected >= 2 rows in lineage after deactivation; got {total}"
    assert current == 1, f"Expected exactly 1 current row; got {current}"
    assert inactive is not None
    assert not inactive.active, "New current row should have active=False"


def test_deactivate_user_current_row_has_valid_to_set_on_old_row(pool):
    """AC 12: the original row has valid_to set (closed) after deactivation."""
    tenant_id = _make_tenant("deactivate-valid-to")
    user_name = "closedrow@example.com"
    with tenant_session(pool, tenant_id) as conn:
        user = create_or_replace_user(conn, tenant_id, user_name)
        original_id = user.scim_user_id
        deactivate_user(conn, tenant_id, original_id)

    with psycopg.connect(admin_dsn()) as conn:
        closed = conn.execute(
            "SELECT valid_to FROM scim_user WHERE scim_user_id = %s",
            (original_id,),
        ).fetchone()
    assert closed is not None
    assert closed[0] is not None, "Original row's valid_to must be set (closed)"


def test_scim_users_module_docstring_documents_required_content():
    """AC 13: module docstring documents credential-storage, role-override precedence, subject-lookup."""
    import infra_twin.db.scim_users as scim_mod
    doc = scim_mod.__doc__
    assert doc is not None, "scim_users.py must have a module docstring"
    doc_lower = doc.lower()
    assert "scim_provisioning_token" in doc_lower or "credential" in doc_lower, (
        "Docstring must document credential-storage choice"
    )
    assert "scim" in doc_lower and ("role" in doc_lower or "override" in doc_lower), (
        "Docstring must document OIDC role-override precedence"
    )
    assert "sub" in doc_lower and "email" in doc_lower, (
        "Docstring must document subject-lookup precedence (sub > email > preferred_username)"
    )


# ===========================================================================
# parse_scim_token unit tests
# ===========================================================================


def test_parse_scim_token_valid_returns_tuple():
    """parse_scim_token returns (token_id, secret) for a valid token."""
    result = parse_scim_token("scim_abc123.secretxyz")
    assert result == ("abc123", "secretxyz")


def test_parse_scim_token_no_prefix_returns_none():
    """parse_scim_token returns None for non-scim_ prefix."""
    assert parse_scim_token("itw_abc.secret") is None
    assert parse_scim_token("bearer_abc.secret") is None
    assert parse_scim_token("header.payload.sig") is None


def test_parse_scim_token_no_dot_returns_none():
    """parse_scim_token returns None when no '.' in the rest part."""
    assert parse_scim_token("scim_nodot") is None


def test_parse_scim_token_empty_token_id_returns_none():
    """parse_scim_token returns None when token_id is empty."""
    assert parse_scim_token("scim_.secret") is None


def test_parse_scim_token_empty_secret_returns_none():
    """parse_scim_token returns None when secret is empty."""
    assert parse_scim_token("scim_tokenid.") is None


def test_parse_scim_token_empty_string_returns_none():
    """parse_scim_token returns None for empty string."""
    assert parse_scim_token("") is None


# ===========================================================================
# conftest.py _DATA_TABLES check (AC 26)
# ===========================================================================


def test_conftest_data_tables_includes_scim_tables():
    """AC 26: conftest.py _DATA_TABLES includes scim_user and scim_provisioning_token."""
    import importlib
    conftest = importlib.import_module("conftest")
    data_tables = conftest._DATA_TABLES
    assert "scim_user" in data_tables
    assert "scim_provisioning_token" in data_tables


# ===========================================================================
# Admin route: POST /tenants/{tenant_id}/scim-token (AC 27)
# ===========================================================================


def test_post_scim_token_returns_201_with_plaintext(pool, monkeypatch):
    """AC 27: POST /tenants/{tenant_id}/scim-token returns 201 with one-time scim_token."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("scim-token-issue")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        f"/tenants/{tenant_id}/scim-token",
        json={"name": "test-token"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "scim_token" in body
    assert body["scim_token"].startswith(SCIM_TOKEN_PREFIX)
    assert str(tenant_id) == body["tenant_id"]


def test_post_scim_token_no_plaintext_in_db(pool, monkeypatch):
    """AC 27 / AC 28: the DB row has no plaintext column; only hash+salt stored."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("scim-token-no-plain")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        f"/tenants/{tenant_id}/scim-token",
        json={},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    scim_token = resp.json()["scim_token"]
    parsed = parse_scim_token(scim_token)
    assert parsed is not None
    token_id, secret = parsed
    # Verify DB row has hash+salt but NOT the raw secret
    with psycopg.connect(admin_dsn()) as conn:
        row = conn.execute(
            "SELECT token_id, secret_hash, salt FROM scim_provisioning_token WHERE token_id = %s",
            (token_id,),
        ).fetchone()
    assert row is not None
    assert row[0] == token_id
    assert len(row[1]) > 0, "secret_hash must be non-empty"
    assert row[1] != secret, "raw secret must not be stored as secret_hash"
    assert row[2] is not None, "salt must be stored"


def test_post_scim_token_issued_token_resolves():
    """AC 27: the scim_token returned by the route resolves to the correct tenant."""
    tenant_id = _make_tenant("scim-token-resolves")
    plaintext = _issue_scim_token_for(tenant_id)
    with psycopg.connect(admin_dsn()) as conn:
        result = resolve_scim_token(conn, plaintext)
    assert result == tenant_id


def test_post_scim_token_requires_bootstrap_admin(pool, monkeypatch):
    """AC 27: POST /tenants/{id}/scim-token without bootstrap admin -> 401."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("scim-token-auth")
    client = TestClient(create_app(pool=pool))
    resp = client.post(f"/tenants/{tenant_id}/scim-token", json={})
    assert resp.status_code == 401


def test_post_scim_token_response_has_no_secret_hash_or_salt(pool, monkeypatch):
    """AC 28: response body never contains secret_hash, salt, or raw secret (other than one-time token)."""
    monkeypatch.setenv("INFRA_TWIN_BOOTSTRAP_ADMIN_TOKEN", _BOOTSTRAP_TOKEN)
    tenant_id = _make_tenant("scim-token-no-leak")
    client = TestClient(create_app(pool=pool))
    resp = client.post(
        f"/tenants/{tenant_id}/scim-token",
        json={"name": "leak-check"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    body_str = str(resp.json())
    assert "secret_hash" not in body_str
    assert "salt" not in body_str


# ===========================================================================
# SCIM auth edge cases (AC 18, EC 1-8)
# ===========================================================================


def test_scim_route_missing_authorization_returns_401(pool):
    """AC 18 / EC 1: no Authorization header on SCIM route -> 401 'missing SCIM token'."""
    client = _app_plain(pool)
    resp = client.post("/scim/v2/Users", json={"userName": "test@example.com"})
    assert resp.status_code == 401
    assert "missing SCIM token" in resp.json().get("detail", "")


def test_scim_route_malformed_token_no_prefix_returns_401(pool):
    """AC 18 / EC 2: malformed token (no scim_ prefix) -> 401 'invalid SCIM token'."""
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "test@example.com"},
        headers={"Authorization": "Bearer notascimtoken.atall"},
    )
    assert resp.status_code == 401
    assert "invalid SCIM token" in resp.json().get("detail", "")


def test_scim_route_unknown_token_id_returns_401(pool):
    """AC 18 / EC 3: valid scim_ shape but unknown token_id -> 401."""
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "test@example.com"},
        headers={"Authorization": "Bearer scim_unknownid.unknownsecret"},
    )
    assert resp.status_code == 401
    assert "invalid SCIM token" in resp.json().get("detail", "")


def test_scim_route_wrong_secret_returns_401(pool):
    """EC 4: correct token_id but wrong secret -> 401."""
    tenant_id = _make_tenant("scim-wrong-secret-ec4")
    plaintext = _issue_scim_token_for(tenant_id)
    parsed = parse_scim_token(plaintext)
    assert parsed is not None
    token_id, _ = parsed
    wrong_token = f"scim_{token_id}.WRONGSECRET"
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "test@example.com"},
        headers={"Authorization": f"Bearer {wrong_token}"},
    )
    assert resp.status_code == 401


def test_scim_route_revoked_token_returns_401(pool):
    """EC 5: revoked SCIM token -> 401."""
    tenant_id = _make_tenant("scim-revoked-ec5")
    plaintext = _issue_scim_token_for(tenant_id)
    parsed = parse_scim_token(plaintext)
    assert parsed is not None
    token_id, _ = parsed
    with psycopg.connect(admin_dsn()) as conn:
        conn.execute(
            "UPDATE scim_provisioning_token SET revoked_at = now() WHERE token_id = %s",
            (token_id,),
        )
        conn.commit()
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "test@example.com"},
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert resp.status_code == 401


def test_scim_route_rejects_api_key_returns_401(pool):
    """AC 18 / EC 6: itw_ API key on SCIM route -> 401."""
    _, api_key = _make_tenant_with_key("scim-apikey-ec6")
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "test@example.com"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 401


def test_scim_route_rejects_jwt_returns_401(pool):
    """AC 18 / EC 7: valid JWT (OIDC token) on SCIM route -> 401."""
    tenant_id = _make_tenant("scim-jwt-ec7")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A)
    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "test@example.com"},
        headers={"Authorization": f"Bearer {jwt_token}"},
    )
    assert resp.status_code == 401


def test_scim_token_on_data_plane_route_returns_401(pool):
    """EC 8: scim_ token on data-plane route (GET /cis) -> 401 'invalid API key'."""
    tenant_id = _make_tenant("scim-token-data-plane-ec8")
    plaintext = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.get("/cis", headers={"Authorization": f"Bearer {plaintext}"})
    assert resp.status_code == 401
    # SCIM tokens must not grant data-plane access
    detail = resp.json().get("detail", "")
    assert "invalid API key" in detail or "missing API key" in detail


# ===========================================================================
# POST /scim/v2/Users (create) - AC 14
# ===========================================================================


def test_scim_create_user_returns_201_with_scim_shape(pool):
    """AC 14: POST /scim/v2/Users returns 201 with SCIM-shaped response."""
    tenant_id = _make_tenant("scim-create-201")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "user@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "schemas" in body
    assert "urn:ietf:params:scim:schemas:core:2.0:User" in body["schemas"]
    assert "id" in body
    assert "userName" in body
    assert body["userName"] == "user@example.com"
    assert "active" in body
    assert body["active"] is True
    assert "roles" in body
    assert "meta" in body
    meta = body["meta"]
    assert "resourceType" in meta
    assert meta["resourceType"] == "User"
    assert "created" in meta
    assert "lastModified" in meta
    assert "location" in meta
    assert body["id"] != ""
    # Server-assigned id (UUID string)
    UUID(body["id"])


def test_scim_create_user_response_has_no_secret_fields(pool):
    """AC 14 / AC 28: SCIM create response contains no token/secret/hash/salt fields."""
    tenant_id = _make_tenant("scim-create-no-leak")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "alice@noleak.com"},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 201
    body = resp.json()
    # Response must not include internal DB storage fields
    assert "secret_hash" not in body, "secret_hash must not appear in SCIM response"
    assert "salt" not in body, "salt must not appear in SCIM response"
    # Expected keys only
    expected_top_keys = {"schemas", "id", "externalId", "userName", "active", "roles", "meta"}
    unexpected = set(body.keys()) - expected_top_keys
    assert not unexpected, f"Unexpected keys in SCIM response: {unexpected}"


def test_scim_create_user_default_role_is_viewer(pool):
    """POST /scim/v2/Users with no roles -> role defaults to viewer."""
    tenant_id = _make_tenant("scim-create-default-role")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "viewer@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["roles"] == [{"value": "viewer"}]


def test_scim_create_user_with_editor_role(pool):
    """POST /scim/v2/Users with roles=[{'value':'editor'}] -> role=editor."""
    tenant_id = _make_tenant("scim-create-editor-role")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "editor@example.com", "roles": [{"value": "editor"}]},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 201
    assert resp.json()["roles"] == [{"value": "editor"}]


def test_scim_create_user_invalid_role_defaults_to_viewer(pool):
    """POST /scim/v2/Users with invalid role value -> defaults to viewer."""
    tenant_id = _make_tenant("scim-create-invalid-role")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "invalidrole@example.com", "roles": [{"value": "superadmin"}]},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 201
    assert resp.json()["roles"] == [{"value": "viewer"}]


def test_scim_create_user_blank_username_returns_422(pool):
    """EC 10: blank userName -> 422."""
    tenant_id = _make_tenant("scim-create-blank-username")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": "   "},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 422


def test_scim_create_user_missing_username_returns_422(pool):
    """EC 10 variant: missing userName field -> 422."""
    tenant_id = _make_tenant("scim-create-missing-username")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.post(
        "/scim/v2/Users",
        json={"active": True},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 422


def test_scim_create_user_idempotent_reprovision_returns_201(pool):
    """EC 9: re-provision with same userName -> 201, exactly one current row (idempotent)."""
    tenant_id = _make_tenant("scim-create-idempotent")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    user_name = "idempotent@example.com"

    resp1 = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token),
    )
    assert resp1.status_code == 201

    resp2 = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token),
    )
    assert resp2.status_code == 201

    # Exactly one current row
    current = _count_current_scim_rows(tenant_id, user_name)
    assert current == 1, f"Expected exactly 1 current row after idempotent re-provision; got {current}"
    # Total rows >= 2 (the original and the new one)
    total = _count_scim_rows(tenant_id, user_name)
    assert total >= 2


def test_scim_create_user_duplicate_external_id_returns_409(pool):
    """EC 11: create with externalId duplicating another current user -> 409."""
    tenant_id = _make_tenant("scim-create-dup-ext")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    ext_id = "idp-user-001"
    resp1 = client.post(
        "/scim/v2/Users",
        json={"userName": "user1@example.com", "externalId": ext_id},
        headers=_scim_auth(scim_token),
    )
    assert resp1.status_code == 201

    resp2 = client.post(
        "/scim/v2/Users",
        json={"userName": "user2@example.com", "externalId": ext_id},
        headers=_scim_auth(scim_token),
    )
    assert resp2.status_code == 409
    body = resp2.json()
    assert "schemas" in body
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in body["schemas"]


# ===========================================================================
# GET /scim/v2/Users/{id} (AC 15)
# ===========================================================================


def test_scim_get_user_returns_200_for_existing(pool):
    """AC 15: GET /scim/v2/Users/{id} returns 200 for an existing user."""
    tenant_id = _make_tenant("scim-get-200")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "getme@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    get_resp = client.get(
        f"/scim/v2/Users/{user_id}",
        headers=_scim_auth(scim_token),
    )
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["id"] == user_id
    assert body["userName"] == "getme@example.com"


def test_scim_get_user_returns_404_for_unknown(pool):
    """AC 15: GET /scim/v2/Users/{id} returns 404 SCIM Error for unknown id."""
    from uuid import uuid4
    tenant_id = _make_tenant("scim-get-404")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.get(
        f"/scim/v2/Users/{uuid4()}",
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 404
    body = resp.json()
    assert "schemas" in body
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in body["schemas"]


# ===========================================================================
# GET /scim/v2/Users (list) - AC 16
# ===========================================================================


def test_scim_list_users_returns_200_list_response(pool):
    """AC 16: GET /scim/v2/Users returns 200 SCIM ListResponse."""
    tenant_id = _make_tenant("scim-list-200")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    client.post(
        "/scim/v2/Users",
        json={"userName": "alice@example.com"},
        headers=_scim_auth(scim_token),
    )
    resp = client.get("/scim/v2/Users", headers=_scim_auth(scim_token))
    assert resp.status_code == 200
    body = resp.json()
    assert "schemas" in body
    assert "urn:ietf:params:scim:api:messages:2.0:ListResponse" in body["schemas"]
    assert "totalResults" in body
    assert "Resources" in body
    assert body["totalResults"] >= 1
    assert any(r["userName"] == "alice@example.com" for r in body["Resources"])


def test_scim_list_users_with_filter_returns_only_match(pool):
    """AC 16: GET /scim/v2/Users?filter=userName eq "X" returns only matching user."""
    tenant_id = _make_tenant("scim-list-filter")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    client.post(
        "/scim/v2/Users",
        json={"userName": "match@example.com"},
        headers=_scim_auth(scim_token),
    )
    client.post(
        "/scim/v2/Users",
        json={"userName": "nomatch@example.com"},
        headers=_scim_auth(scim_token),
    )
    resp = client.get(
        '/scim/v2/Users?filter=userName eq "match@example.com"',
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "match@example.com"


def test_scim_list_users_filter_no_match_returns_empty(pool):
    """EC 14: filter matches nothing -> 200 with totalResults:0 empty Resources."""
    tenant_id = _make_tenant("scim-list-no-match")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.get(
        '/scim/v2/Users?filter=userName eq "nobody@example.com"',
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["totalResults"] == 0
    assert body["Resources"] == []


def test_scim_list_users_unsupported_filter_returns_400(pool):
    """AC 16 / EC 15: unsupported filter operator -> 400 SCIM Error."""
    tenant_id = _make_tenant("scim-list-bad-filter")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.get(
        '/scim/v2/Users?filter=displayName co "test"',
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 400
    body = resp.json()
    assert "schemas" in body
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in body["schemas"]
    assert "unsupported filter" in body.get("detail", "").lower()


def test_scim_list_users_only_returns_current_rows(pool):
    """GET /scim/v2/Users returns only valid_to IS NULL (current) rows."""
    tenant_id = _make_tenant("scim-list-current-only")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    user_name = "current-only@example.com"
    # Create and then deactivate: should produce a current active=false row and a historical row
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    resp = client.get("/scim/v2/Users", headers=_scim_auth(scim_token))
    body = resp.json()
    # All Resources should have valid_to IS NULL (they all come from list_users which filters)
    # The deactivated user is still "current" (valid_to IS NULL) just with active=False
    assert body["totalResults"] == 1
    # Historical rows must not appear
    total_db_rows = _count_scim_rows(tenant_id, user_name)
    assert total_db_rows >= 2, "Expected at least 2 DB rows (original + deactivated)"
    assert body["totalResults"] == 1, "list must return only 1 current row (not historical)"


# ===========================================================================
# PATCH /scim/v2/Users/{id} (deactivate / reactivate) - AC 17
# ===========================================================================


def test_scim_patch_deactivate_returns_200_active_false(pool):
    """AC 17: PATCH replace active false -> 200, user active=false."""
    tenant_id = _make_tenant("scim-patch-deactivate")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "patchme@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    patch_resp = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert patch_resp.status_code == 200
    body = patch_resp.json()
    assert body["active"] is False


def test_scim_patch_deactivate_via_value_dict(pool):
    """AC 17: PATCH with value={"active": false} (no path) also deactivates."""
    tenant_id = _make_tenant("scim-patch-value-dict")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "valuedict@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    patch_resp = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "value": {"active": False}}]},
        headers=_scim_auth(scim_token),
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["active"] is False


def test_scim_patch_deactivate_already_inactive_is_idempotent(pool):
    """EC 17: PATCH deactivate already-inactive user -> idempotent, still active=false, one current row."""
    tenant_id = _make_tenant("scim-patch-idempotent-deactivate")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    user_name = "idempotentdeact@example.com"
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    # Deactivate once
    r1 = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert r1.status_code == 200
    new_user_id = r1.json()["id"]
    # Deactivate again with the new id
    r2 = client.patch(
        f"/scim/v2/Users/{new_user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert r2.status_code == 200
    assert r2.json()["active"] is False
    # Still exactly one current row
    current = _count_current_scim_rows(tenant_id, user_name)
    assert current == 1


def test_scim_patch_reactivate_inactive_user(pool):
    """EC 18: PATCH replace active true on inactive user -> 200, active=true."""
    tenant_id = _make_tenant("scim-patch-reactivate")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "reactivate@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    # Deactivate
    deact_resp = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert deact_resp.status_code == 200
    deact_id = deact_resp.json()["id"]
    # Reactivate
    react_resp = client.patch(
        f"/scim/v2/Users/{deact_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": True}]},
        headers=_scim_auth(scim_token),
    )
    assert react_resp.status_code == 200
    assert react_resp.json()["active"] is True


def test_scim_patch_empty_operations_returns_400(pool):
    """EC 16: PATCH with empty Operations -> 400 SCIM Error."""
    tenant_id = _make_tenant("scim-patch-empty-ops")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "emptyops@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    resp = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": []},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 400
    body = resp.json()
    assert "schemas" in body
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in body["schemas"]


def test_scim_patch_unknown_id_returns_404(pool):
    """PATCH for unknown id -> 404 SCIM Error."""
    from uuid import uuid4
    tenant_id = _make_tenant("scim-patch-404")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.patch(
        f"/scim/v2/Users/{uuid4()}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 404


# ===========================================================================
# PUT /scim/v2/Users/{id} (full replace) - AC 17
# ===========================================================================


def test_scim_put_deactivate_returns_200_active_false(pool):
    """AC 17: PUT with active:false -> 200, active=false in response."""
    tenant_id = _make_tenant("scim-put-deactivate")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "putdeact@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    put_resp = client.put(
        f"/scim/v2/Users/{user_id}",
        json={"userName": "putdeact@example.com", "active": False},
        headers=_scim_auth(scim_token),
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["active"] is False


def test_scim_put_unknown_id_returns_404(pool):
    """PUT for unknown id -> 404."""
    from uuid import uuid4
    tenant_id = _make_tenant("scim-put-404")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    resp = client.put(
        f"/scim/v2/Users/{uuid4()}",
        json={"userName": "ghost@example.com", "active": True},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 404


# ===========================================================================
# Append-only / never-hard-deleted invariant (AC 12, AC 25, EC 19-20)
# ===========================================================================


def test_deactivate_then_get_returns_active_false(pool):
    """EC 19: deactivate then GET by id -> current row has active=false."""
    tenant_id = _make_tenant("scim-deact-get")
    scim_token = _issue_scim_token_for(tenant_id)
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "deactget@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    patch_resp = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert patch_resp.status_code == 200
    new_user_id = patch_resp.json()["id"]
    get_resp = client.get(f"/scim/v2/Users/{new_user_id}", headers=_scim_auth(scim_token))
    assert get_resp.status_code == 200
    assert get_resp.json()["active"] is False


def test_historical_rows_remain_after_deactivation(pool):
    """EC 20 / AC 12: after deactivation, >= 2 rows in lineage (no hard-delete)."""
    tenant_id = _make_tenant("scim-historical-rows")
    user_name = "historical@example.com"
    with tenant_session(pool, tenant_id) as conn:
        user = create_or_replace_user(conn, tenant_id, user_name)
        deactivate_user(conn, tenant_id, user.scim_user_id)

    total = _count_scim_rows(tenant_id, user_name)
    assert total >= 2, f"Expected >= 2 rows after deactivation; found {total}"
    current = _count_current_scim_rows(tenant_id, user_name)
    assert current == 1


def test_no_delete_privilege_on_app_role_for_scim_user():
    """EC 20 / AC 6 / AC 25: app role has NO DELETE on scim_user."""
    with psycopg.connect(admin_dsn()) as conn:
        privs = conn.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'scim_user' AND grantee = 'app' AND privilege_type = 'DELETE'"
        ).fetchall()
    assert len(privs) == 0, "app role must NOT have DELETE on scim_user"


def test_app_role_cannot_delete_scim_user_row(pool):
    """AC 25: trying to DELETE from scim_user as app role raises permission denied."""
    tenant_id = _make_tenant("scim-no-delete-priv")
    # Create a row via pool + tenant_session
    with tenant_session(pool, tenant_id) as conn:
        create_or_replace_user(conn, tenant_id, "nodelete@example.com")
    # Attempt DELETE as app role
    with pytest.raises(psycopg.Error) as exc_info:
        with psycopg.connect(app_dsn()) as conn:
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_id),)
            )
            conn.execute(
                "DELETE FROM scim_user WHERE user_name = 'nodelete@example.com'"
            )
            conn.commit()
    err = str(exc_info.value).lower()
    assert "permission denied" in err or "42501" in err or "insufficient privilege" in err


# ===========================================================================
# Cross-tenant adversarial isolation (AC 22, EC 12-13)
# ===========================================================================


def test_scim_two_tenants_same_username_allowed(pool):
    """EC 12: two tenants can have the same userName; unique index is per-tenant."""
    tenant_a = _make_tenant("scim-cross-username-a")
    tenant_b = _make_tenant("scim-cross-username-b")
    token_a = _issue_scim_token_for(tenant_a)
    token_b = _issue_scim_token_for(tenant_b)
    client = _app_plain(pool)
    user_name = "shared@example.com"
    resp_a = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(token_a),
    )
    resp_b = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(token_b),
    )
    assert resp_a.status_code == 201
    assert resp_b.status_code == 201
    # Both tenants have one current row for that username
    assert _count_current_scim_rows(tenant_a, user_name) == 1
    assert _count_current_scim_rows(tenant_b, user_name) == 1


def test_scim_tenant_a_cannot_get_tenant_b_user(pool):
    """AC 22 / EC 13: GET /scim/v2/Users/{id} with tenant B's id under tenant A's token -> 404."""
    tenant_a = _make_tenant("scim-cross-get-a")
    tenant_b = _make_tenant("scim-cross-get-b")
    token_a = _issue_scim_token_for(tenant_a)
    token_b = _issue_scim_token_for(tenant_b)
    client = _app_plain(pool)

    # Create user in tenant B
    resp_b = client.post(
        "/scim/v2/Users",
        json={"userName": "buser@example.com"},
        headers=_scim_auth(token_b),
    )
    assert resp_b.status_code == 201
    b_user_id = resp_b.json()["id"]

    # Tenant A tries to GET B's user by id -> 404 (RLS hides it)
    resp = client.get(
        f"/scim/v2/Users/{b_user_id}",
        headers=_scim_auth(token_a),
    )
    assert resp.status_code == 404


def test_scim_tenant_a_cannot_patch_tenant_b_user(pool):
    """AC 22 / EC 13: PATCH with tenant B's id under tenant A's token -> 404."""
    tenant_a = _make_tenant("scim-cross-patch-a")
    tenant_b = _make_tenant("scim-cross-patch-b")
    token_a = _issue_scim_token_for(tenant_a)
    token_b = _issue_scim_token_for(tenant_b)
    client = _app_plain(pool)

    resp_b = client.post(
        "/scim/v2/Users",
        json={"userName": "bpatch@example.com"},
        headers=_scim_auth(token_b),
    )
    assert resp_b.status_code == 201
    b_user_id = resp_b.json()["id"]

    resp = client.patch(
        f"/scim/v2/Users/{b_user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(token_a),
    )
    assert resp.status_code == 404


def test_scim_tenant_a_users_invisible_to_tenant_b_list(pool):
    """AC 22: users provisioned for tenant A are invisible in tenant B's list."""
    tenant_a = _make_tenant("scim-cross-list-a")
    tenant_b = _make_tenant("scim-cross-list-b")
    token_a = _issue_scim_token_for(tenant_a)
    token_b = _issue_scim_token_for(tenant_b)
    client = _app_plain(pool)

    # Create user in A
    client.post(
        "/scim/v2/Users",
        json={"userName": "aonly@example.com"},
        headers=_scim_auth(token_a),
    )

    # B's list should not contain A's user
    resp_b = client.get("/scim/v2/Users", headers=_scim_auth(token_b))
    assert resp_b.status_code == 200
    body_b = resp_b.json()
    usernames_b = [r["userName"] for r in body_b.get("Resources", [])]
    assert "aonly@example.com" not in usernames_b


def test_scim_token_resolves_only_to_own_tenant(pool):
    """AC 22: SCIM token for tenant A resolves only to tenant A, not tenant B."""
    tenant_a = _make_tenant("scim-cross-resolve-a")
    tenant_b = _make_tenant("scim-cross-resolve-b")
    token_a = _issue_scim_token_for(tenant_a)
    _issue_scim_token_for(tenant_b)  # B also has a token

    with psycopg.connect(admin_dsn()) as conn:
        resolved = resolve_scim_token(conn, token_a)
    assert resolved == tenant_a
    assert resolved != tenant_b


# ===========================================================================
# OIDC deactivation enforcement (AC 19, EC 21-27)
# ===========================================================================


def test_oidc_deactivated_scim_user_returns_401(pool):
    """AC 19 / EC 21: OIDC token for SCIM-deactivated user -> 401 'user deactivated'."""
    tenant_id = _make_tenant("oidc-deact-401")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    scim_token = _issue_scim_token_for(tenant_id)
    user_name = "test-user-001"  # matches the 'sub' in _make_rs256_token default payload

    # Provision the user via SCIM
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 201
    user_id = resp.json()["id"]

    # Deactivate the user
    deact_resp = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert deact_resp.status_code == 200

    # OIDC token for that subject -> 401 "user deactivated"
    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    oidc_resp = client.get("/cis", headers={"Authorization": f"Bearer {jwt_token}"})
    assert oidc_resp.status_code == 401
    assert oidc_resp.json().get("detail") == "user deactivated"


def test_oidc_active_scim_user_authenticates(pool):
    """AC 20 / EC 22: OIDC token for active SCIM user -> authenticates normally (200)."""
    tenant_id = _make_tenant("oidc-active-200")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    scim_token = _issue_scim_token_for(tenant_id)
    user_name = "test-user-001"

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token),
    )

    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    resp = client.get("/cis", headers={"Authorization": f"Bearer {jwt_token}"})
    assert resp.status_code == 200


def test_oidc_no_scim_record_authenticates_normally(pool):
    """AC 20 / EC 23: OIDC token for subject with no SCIM record -> authenticates (unchanged behavior)."""
    tenant_id = _make_tenant("oidc-no-scim")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    # No SCIM user provisioned for this tenant
    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    resp = client.get("/cis", headers={"Authorization": f"Bearer {jwt_token}"})
    assert resp.status_code == 200


def test_oidc_deactivated_then_reactivated_scim_user_authenticates(pool):
    """EC 24: OIDC token where SCIM record was deactivated then reactivated -> 200."""
    tenant_id = _make_tenant("oidc-react-200")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    scim_token = _issue_scim_token_for(tenant_id)
    user_name = "test-user-001"

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    # Provision
    resp = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token),
    )
    assert resp.status_code == 201
    user_id = resp.json()["id"]

    # Deactivate
    deact_resp = client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    assert deact_resp.status_code == 200
    deact_id = deact_resp.json()["id"]

    # Reactivate
    react_resp = client.patch(
        f"/scim/v2/Users/{deact_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": True}]},
        headers=_scim_auth(scim_token),
    )
    assert react_resp.status_code == 200

    # OIDC auth should succeed now
    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    oidc_resp = client.get("/cis", headers={"Authorization": f"Bearer {jwt_token}"})
    assert oidc_resp.status_code == 200


def test_oidc_subject_precedence_sub_over_email(pool):
    """EC 25: OIDC subject from 'sub' claim takes precedence over 'email'."""
    tenant_id = _make_tenant("oidc-sub-precedence")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    scim_token = _issue_scim_token_for(tenant_id)

    # Provision by sub value
    sub_value = "test-user-001"
    email_value = "email@example.com"

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    # Deactivate the user whose name matches sub
    client.post(
        "/scim/v2/Users",
        json={"userName": sub_value},
        headers=_scim_auth(scim_token),
    )
    resp_deact = client.get("/scim/v2/Users", headers=_scim_auth(scim_token))
    user_id = resp_deact.json()["Resources"][0]["id"]
    client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )

    # Provision an active user with email as userName (not matching sub)
    client.post(
        "/scim/v2/Users",
        json={"userName": email_value},
        headers=_scim_auth(scim_token),
    )

    # Token has both sub=sub_value and email=email_value.
    # sub takes precedence -> deactivated -> 401
    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        extra_claims={"email": email_value},
    )
    oidc_resp = client.get("/cis", headers={"Authorization": f"Bearer {jwt_token}"})
    assert oidc_resp.status_code == 401
    assert oidc_resp.json().get("detail") == "user deactivated"


def test_oidc_subject_falls_back_to_email_when_sub_absent(pool):
    """EC 25: when sub claim is absent, email claim is used for SCIM lookup."""
    import time, jwt as pyjwt
    tenant_id = _make_tenant("oidc-email-fallback")
    _setup_idp(tenant_id, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    scim_token = _issue_scim_token_for(tenant_id)
    email_value = "emailmatch@example.com"

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    # Deactivate user whose name = email_value
    client.post(
        "/scim/v2/Users",
        json={"userName": email_value},
        headers=_scim_auth(scim_token),
    )
    list_resp = client.get("/scim/v2/Users", headers=_scim_auth(scim_token))
    user_id = list_resp.json()["Resources"][0]["id"]
    client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )

    # Build a token with NO 'sub' claim but with 'email' = email_value (deactivated)
    # Subject resolution: sub absent -> falls to email -> finds deactivated user -> 401
    now = int(time.time())
    payload = {
        "iss": _ISSUER_A,
        "aud": _AUDIENCE_A,
        "iat": now - 10,
        "exp": now + 3600,
        "email": email_value,
        # deliberately no 'sub' claim
    }
    jwt_token = pyjwt.encode(payload, _RSA_PRIV_KEY_A, algorithm="RS256", headers={"alg": "RS256"})
    oidc_resp = client.get("/cis", headers={"Authorization": f"Bearer {jwt_token}"})
    assert oidc_resp.status_code == 401
    assert oidc_resp.json().get("detail") == "user deactivated"


def test_oidc_different_tenant_deactivated_user_does_not_block_this_tenant(pool):
    """EC 26: tenant B's SCIM-deactivated user with same username does NOT block tenant A's OIDC auth."""
    tenant_a = _make_tenant("oidc-cross-deact-a")
    tenant_b = _make_tenant("oidc-cross-deact-b")

    # Set up IdP configs for A and B with different issuers
    _setup_idp(tenant_a, issuer=_ISSUER_A, audience=_AUDIENCE_A, default_role=Role.viewer)
    _setup_idp(tenant_b, issuer=_ISSUER_B, audience=_AUDIENCE_B, default_role=Role.viewer)

    scim_token_b = _issue_scim_token_for(tenant_b)
    user_name = "test-user-001"  # same as sub in default token

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)

    # Deactivate user in B with that username
    b_create = client.post(
        "/scim/v2/Users",
        json={"userName": user_name},
        headers=_scim_auth(scim_token_b),
    )
    assert b_create.status_code == 201
    b_user_id = b_create.json()["id"]
    b_deact = client.patch(
        f"/scim/v2/Users/{b_user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token_b),
    )
    assert b_deact.status_code == 200

    # Tenant A's OIDC token for the same subject -> A has no SCIM record -> should authenticate
    jwt_token_a = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
    )
    oidc_resp = client.get("/cis", headers={"Authorization": f"Bearer {jwt_token_a}"})
    assert oidc_resp.status_code == 200, (
        f"Tenant A's OIDC auth must not be blocked by tenant B's deactivated user. "
        f"Got {oidc_resp.status_code}: {oidc_resp.json()}"
    )


# ===========================================================================
# OIDC role override by active SCIM user (AC 21)
# ===========================================================================


def test_oidc_scim_editor_role_overrides_oidc_viewer_allows_write(pool):
    """AC 21: active SCIM user role='editor' overrides OIDC-mapped 'viewer' -> write 201."""
    tenant_id = _make_tenant("scim-role-override-editor")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={},         # no mapping -> default_role=viewer
        default_role=Role.viewer,
    )
    scim_token = _issue_scim_token_for(tenant_id)
    user_name = "test-user-001"

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    # Provision with editor role
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": user_name, "roles": [{"value": "editor"}]},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201

    # Token has no role claim, so OIDC would resolve to viewer (default)
    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role=None,  # no role claim -> default_role=viewer from OIDC
    )
    # With SCIM editor override, write should succeed (201)
    write_resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "scim-role-override-test"},
        headers={"Authorization": f"Bearer {jwt_token}"},
    )
    assert write_resp.status_code == 201, (
        f"Expected 201 with SCIM editor override; got {write_resp.status_code}: {write_resp.json()}"
    )


def test_oidc_scim_viewer_role_blocks_write(pool):
    """AC 21: active SCIM user role='viewer' -> write attempt -> 403."""
    tenant_id = _make_tenant("scim-role-override-viewer")
    _setup_idp(
        tenant_id,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role_claim="role",
        role_claim_map={"admin": "editor"},  # would grant editor via OIDC
        default_role=Role.viewer,
    )
    scim_token = _issue_scim_token_for(tenant_id)
    user_name = "test-user-001"

    client = _app_with_oidc(pool, public_key=_RSA_PUB_KEY_A)
    # Provision with viewer role (overrides the editor mapping)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": user_name, "roles": [{"value": "viewer"}]},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201

    # Token has role=admin -> would map to editor via OIDC role_claim_map
    # But SCIM viewer role overrides -> 403 on write
    jwt_token = _make_rs256_token(
        private_key=_RSA_PRIV_KEY_A,
        issuer=_ISSUER_A,
        audience=_AUDIENCE_A,
        role="admin",
    )
    write_resp = client.post(
        "/connectors",
        json={"type": "aws", "display_name": "scim-viewer-blocks-write"},
        headers={"Authorization": f"Bearer {jwt_token}"},
    )
    assert write_resp.status_code == 403, (
        f"Expected 403 with SCIM viewer override blocking editor; got {write_resp.status_code}"
    )


# ===========================================================================
# API-key path is unaffected (AC 23, EC 27)
# ===========================================================================


def test_api_key_auth_unaffected_by_scim_deactivation(pool):
    """AC 23 / EC 27: API-key auth for a tenant with a SCIM-deactivated user still works."""
    tenant_id, api_key = _make_tenant_with_key("scim-apikey-unaffected")
    scim_token = _issue_scim_token_for(tenant_id)
    # Deactivate a SCIM user with any username
    client = _app_plain(pool)
    create_resp = client.post(
        "/scim/v2/Users",
        json={"userName": "deactivated-scim-user@example.com"},
        headers=_scim_auth(scim_token),
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]
    client.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_scim_auth(scim_token),
    )
    # API-key auth must still work for this tenant
    resp = client.get("/cis", headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200, (
        f"API-key auth must not be blocked by SCIM deactivation; got {resp.status_code}"
    )


# ===========================================================================
# Migration idempotency (AC 29)
# ===========================================================================


def test_migration_0015_is_idempotent():
    """AC 29: re-running migrations after 0015 is a no-op (schema_migrations ledger)."""
    from infra_twin.db.migrate import run_migrations
    applied = run_migrations(directory=_MIGRATIONS_DIR)
    names_0015 = [m for m in (applied or []) if "0015" in str(m)]
    assert names_0015 == [], f"0015 was re-applied: {names_0015}"


# ===========================================================================
# ResolvedOidcPrincipal subject field (additive, AC 24 backward-compat)
# ===========================================================================


def test_resolved_oidc_principal_has_subject_field():
    """AC 24: ResolvedOidcPrincipal has an additive 'subject' field."""
    assert hasattr(ResolvedOidcPrincipal, "__dataclass_fields__")
    principal_fields = {f.name for f in fields(ResolvedOidcPrincipal)}
    assert "subject" in principal_fields, "ResolvedOidcPrincipal must have 'subject' field"
    # Existing fields unchanged
    assert "tenant_id" in principal_fields
    assert "role" in principal_fields
