"""SCIM 2.0 user provisioning repository.

Design decisions (documented here per spec §3.3 requirement):

Credential storage
------------------
The SCIM bearer token is a new admin-issued credential stored in its own table
``scim_provisioning_token``, issued on the admin (BYPASSRLS) connection via
``issue_scim_token``, rather than extending ``provision_tenant``.  Rationale:
SCIM tokens have a different lifecycle from data-plane API keys (issued/rotated
independently per tenant for the IdP integration), and keeping them in a
separate table avoids overloading ``api_keys`` (which feeds the data-plane auth
dispatch keyed on the ``itw_`` prefix) and keeps the ``scim_`` prefix routing
clean.

OIDC role-override precedence (highest to lowest)
--------------------------------------------------
1. Active SCIM user ``role`` — if the OIDC subject matches a current, active
   scim_user row for the tenant, that row's role is authoritative.
2. OIDC ``role_claim_map`` mapping — the tenant_idp_config mapping of the raw
   claim value to a Role.
3. Tenant ``default_role`` from tenant_idp_config.

OIDC subject-lookup precedence (first present non-empty value wins)
-------------------------------------------------------------------
``sub`` claim → ``email`` claim → ``preferred_username`` claim.

The value resolved by this precedence chain is matched against ``scim_user.user_name``
for the tenant to determine deactivation status and role override.

Scrypt hashing
--------------
``new_salt``, ``hash_secret``, and ``verify_secret`` are imported from
``infra_twin.db.api_keys`` and are NOT re-implemented here.  The same
parameters (n=2**14, r=8, p=1, dklen=32) apply.

Never-hard-delete invariant
---------------------------
``deactivate_user`` and ``create_or_replace_user`` close the current row
(set ``valid_to = now()``) and open a new one.  No DELETE is ever issued.
The ``app`` role is granted SELECT, INSERT, UPDATE on ``scim_user`` but
never DELETE.  The repository is the only writer and only ever sets
``valid_to`` on close; it never mutates immutable identity columns.

Concurrent close+open race
---------------------------
The partial unique index ``scim_user_current_username`` on
(tenant_id, user_name) WHERE valid_to IS NULL guarantees at most one
current row.  On a concurrent close+open for the same (tenant_id,
user_name) pair, the second writer receives a unique-violation.  The
repository retries once; if the retry also fails, the exception propagates
to the caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from secrets import token_urlsafe
from uuid import UUID

from infra_twin.db.api_keys import Role, hash_secret, new_salt, verify_secret

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCIM_TOKEN_PREFIX: str = "scim_"
SCIM_TOKEN_ID_BYTES: int = 8
SCIM_TOKEN_SECRET_BYTES: int = 32

# Dummy values used to equalize timing on unknown token_id lookups.
_DUMMY_SALT: bytes = b"\x00" * 16
_DUMMY_HASH: str = hashlib.scrypt(
    b"dummy", salt=_DUMMY_SALT, n=2**14, r=8, p=1, dklen=32
).hex()

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScimUser:
    scim_user_id: UUID
    tenant_id: UUID
    external_id: str | None
    user_name: str
    role: Role
    active: bool
    valid_from: datetime
    valid_to: datetime | None  # None => current row
    created_at: datetime


@dataclass(frozen=True)
class GeneratedScimToken:
    plaintext: str   # full token shown ONCE: f"{SCIM_TOKEN_PREFIX}{token_id}.{secret}"
    token_id: str    # public lookup id (cleartext)
    secret: str      # never stored


# ---------------------------------------------------------------------------
# Pure helpers (no DB)
# ---------------------------------------------------------------------------


def generate_scim_token() -> GeneratedScimToken:
    """Generate a new SCIM bearer token with a random token_id and secret."""
    token_id = token_urlsafe(SCIM_TOKEN_ID_BYTES)
    secret = token_urlsafe(SCIM_TOKEN_SECRET_BYTES)
    plaintext = f"{SCIM_TOKEN_PREFIX}{token_id}.{secret}"
    return GeneratedScimToken(plaintext=plaintext, token_id=token_id, secret=secret)


def parse_scim_token(plaintext: str) -> tuple[str, str] | None:
    """Return (token_id, secret) if plaintext is a validly-formatted SCIM token, else None.

    A valid token starts with SCIM_TOKEN_PREFIX and has exactly one '.' separating
    a non-empty token_id from a non-empty secret.
    """
    if not plaintext.startswith(SCIM_TOKEN_PREFIX):
        return None
    rest = plaintext[len(SCIM_TOKEN_PREFIX):]
    if "." not in rest:
        return None
    token_id, _, secret = rest.partition(".")
    if not token_id or not secret:
        return None
    return token_id, secret


# ---------------------------------------------------------------------------
# Row conversion helper
# ---------------------------------------------------------------------------


def _row_to_user(row) -> ScimUser:
    """Convert a DB row tuple to ScimUser.

    Column order: scim_user_id, tenant_id, external_id, user_name, role,
                  active, valid_from, valid_to, created_at
    """
    return ScimUser(
        scim_user_id=row[0],
        tenant_id=row[1],
        external_id=row[2],
        user_name=row[3],
        role=Role(row[4]),
        active=row[5],
        valid_from=row[6],
        valid_to=row[7],
        created_at=row[8],
    )


_SELECT_COLS = (
    "scim_user_id, tenant_id, external_id, user_name, role,"
    " active, valid_from, valid_to, created_at"
)

# ---------------------------------------------------------------------------
# Admin-connection (BYPASSRLS) functions
# ---------------------------------------------------------------------------


def issue_scim_token(
    admin_conn,
    tenant_id: UUID,
    name: str | None = None,
) -> GeneratedScimToken:
    """Insert a scim_provisioning_token row for tenant_id; return the one-time plaintext.

    Only the hash + salt are persisted; the plaintext and raw secret are never
    stored.  The caller owns any surrounding transaction (matches idp_config style).
    """
    generated = generate_scim_token()
    salt = new_salt()
    secret_hash = hash_secret(generated.secret, salt)

    admin_conn.execute(
        "INSERT INTO scim_provisioning_token"
        " (tenant_id, token_id, secret_hash, salt, name)"
        " VALUES (%s, %s, %s, %s, %s)",
        (tenant_id, generated.token_id, secret_hash, salt, name),
    )

    return generated


def resolve_scim_token(admin_conn, presented_token: str) -> UUID | None:
    """Map a presented SCIM bearer token to its owning tenant_id.

    Runs on a BYPASSRLS admin connection (mirrors api_keys.resolve).  Always
    computes a scrypt hash even on no-row / parse-failure to equalize timing.
    Returns None on any failure (malformed, unknown, wrong secret, revoked).
    """
    parsed = parse_scim_token(presented_token)
    if parsed is None:
        # Equalize timing: run a dummy hash.
        verify_secret("dummy", _DUMMY_SALT, _DUMMY_HASH)
        return None

    token_id, secret = parsed

    row = admin_conn.execute(
        "SELECT tenant_id, secret_hash, salt"
        " FROM scim_provisioning_token"
        " WHERE token_id = %s AND revoked_at IS NULL",
        (token_id,),
    ).fetchone()

    if row is None:
        # Equalize timing against real hash.
        verify_secret(secret, _DUMMY_SALT, _DUMMY_HASH)
        return None

    tenant_id: UUID = row[0]
    secret_hash: str = row[1]
    salt: bytes = bytes(row[2])

    if not verify_secret(secret, salt, secret_hash):
        return None

    return tenant_id


# ---------------------------------------------------------------------------
# Tenant-scoped functions (conn already bound by tenant_session; RLS applies)
# ---------------------------------------------------------------------------


def create_or_replace_user(
    conn,
    tenant_id: UUID,
    user_name: str,
    external_id: str | None = None,
    role: Role = Role.viewer,
    active: bool = True,
) -> ScimUser:
    """SCIM create/PUT semantics: close any existing current row and open a new one.

    If a current row (valid_to IS NULL) exists for (tenant_id, user_name), it is
    closed by setting valid_to = now() before the new row is inserted.  This is
    the append-only bitemporal write pattern; no row is ever deleted.

    On concurrent writes for the same (tenant_id, user_name) a unique-violation
    may occur.  This function retries once; if the retry also fails, the
    exception propagates to the caller.
    """
    import psycopg

    def _do(conn) -> ScimUser:
        # Close the existing current row if one exists.
        conn.execute(
            "UPDATE scim_user SET valid_to = now()"
            " WHERE tenant_id = %s AND user_name = %s AND valid_to IS NULL",
            (tenant_id, user_name),
        )
        # Open a new current row.
        row = conn.execute(
            f"INSERT INTO scim_user"
            f" (tenant_id, external_id, user_name, role, active)"
            f" VALUES (%s, %s, %s, %s, %s)"
            f" RETURNING {_SELECT_COLS}",
            (tenant_id, external_id, user_name, role.value, active),
        ).fetchone()
        return _row_to_user(row)

    try:
        conn.execute("SAVEPOINT scim_create_or_replace")
        result = _do(conn)
        conn.execute("RELEASE SAVEPOINT scim_create_or_replace")
        return result
    except psycopg.errors.UniqueViolation:
        # Roll back to the savepoint so the transaction is still usable,
        # then retry once for the concurrent close+open race on scim_user_current_username.
        conn.execute("ROLLBACK TO SAVEPOINT scim_create_or_replace")
        conn.execute("RELEASE SAVEPOINT scim_create_or_replace")
        return _do(conn)


def get_user_by_id(conn, tenant_id: UUID, scim_user_id: UUID) -> ScimUser | None:
    """Return the row with this primary key (current or historical), or None.

    RLS restricts the result to rows belonging to the session's tenant; a
    scim_user_id belonging to another tenant returns None (no existence leak).
    """
    row = conn.execute(
        f"SELECT {_SELECT_COLS} FROM scim_user WHERE scim_user_id = %s",
        (scim_user_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_user(row)


def get_current_user_by_username(conn, tenant_id: UUID, user_name: str) -> ScimUser | None:
    """Return the current (valid_to IS NULL) row for user_name, or None."""
    row = conn.execute(
        f"SELECT {_SELECT_COLS} FROM scim_user"
        " WHERE user_name = %s AND valid_to IS NULL",
        (user_name,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_user(row)


def list_users(conn, tenant_id: UUID, user_name: str | None = None) -> list[ScimUser]:
    """List current (valid_to IS NULL) users, optionally filtered by exact user_name."""
    if user_name is not None:
        rows = conn.execute(
            f"SELECT {_SELECT_COLS} FROM scim_user"
            " WHERE valid_to IS NULL AND user_name = %s"
            " ORDER BY created_at ASC",
            (user_name,),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {_SELECT_COLS} FROM scim_user"
            " WHERE valid_to IS NULL"
            " ORDER BY created_at ASC",
        ).fetchall()
    return [_row_to_user(r) for r in rows]


def deactivate_user(conn, tenant_id: UUID, scim_user_id: UUID) -> ScimUser | None:
    """Deactivate: close the current row and open a new row with active=false.

    Never issues DELETE.  Returns the new current row, or None if no current
    row exists for that scim_user_id.
    """
    import psycopg

    # Fetch the current row for this id.
    current = conn.execute(
        f"SELECT {_SELECT_COLS} FROM scim_user"
        " WHERE scim_user_id = %s AND valid_to IS NULL",
        (scim_user_id,),
    ).fetchone()

    if current is None:
        return None

    current_user = _row_to_user(current)

    def _do(conn) -> ScimUser:
        # Close the current row.
        conn.execute(
            "UPDATE scim_user SET valid_to = now()"
            " WHERE scim_user_id = %s AND valid_to IS NULL",
            (scim_user_id,),
        )
        # Open a new current row with active=false, preserving other attributes.
        row = conn.execute(
            f"INSERT INTO scim_user"
            f" (tenant_id, external_id, user_name, role, active)"
            f" VALUES (%s, %s, %s, %s, %s)"
            f" RETURNING {_SELECT_COLS}",
            (
                current_user.tenant_id,
                current_user.external_id,
                current_user.user_name,
                current_user.role.value,
                False,
            ),
        ).fetchone()
        return _row_to_user(row)

    try:
        conn.execute("SAVEPOINT scim_deactivate")
        result = _do(conn)
        conn.execute("RELEASE SAVEPOINT scim_deactivate")
        return result
    except psycopg.errors.UniqueViolation:
        # Roll back to the savepoint so the transaction is still usable,
        # then retry once for the concurrent close+open race.
        conn.execute("ROLLBACK TO SAVEPOINT scim_deactivate")
        conn.execute("RELEASE SAVEPOINT scim_deactivate")
        return _do(conn)
