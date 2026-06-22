"""API key generation, hashing, and repository.

Pure helpers (generate_key, parse_key, hash_secret, new_salt, verify_secret) have no
side effects beyond RNG and are safe to import from tests without a database.

ApiKeyRepository wraps the two database operations (provision_tenant, resolve) that
require an explicit admin/superuser connection; the caller controls pooling.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from secrets import token_urlsafe
from uuid import UUID

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_PREFIX: str = "itw_"
KEY_SECRET_BYTES: int = 32
KEY_ID_BYTES: int = 8

# Dummy values used to equalize timing on unknown key_id lookups.
_DUMMY_SALT: bytes = b"\x00" * 16
_DUMMY_HASH: str = hashlib.scrypt(
    b"dummy", salt=_DUMMY_SALT, n=2**14, r=8, p=1, dklen=32
).hex()

# ---------------------------------------------------------------------------
# Role enum
# ---------------------------------------------------------------------------


class Role(str, Enum):
    viewer = "viewer"   # read-only
    editor = "editor"   # read + write (default; backward compatible)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GeneratedKey:
    plaintext: str  # full key shown ONCE: f"{KEY_PREFIX}{key_id}.{secret}"
    key_id: str     # public, stored in cleartext, used for O(1) lookup
    secret: str     # never stored


def generate_key() -> GeneratedKey:
    """Generate a new API key with a random key_id and secret."""
    key_id = token_urlsafe(KEY_ID_BYTES)
    secret = token_urlsafe(KEY_SECRET_BYTES)
    plaintext = f"{KEY_PREFIX}{key_id}.{secret}"
    return GeneratedKey(plaintext=plaintext, key_id=key_id, secret=secret)


def parse_key(plaintext: str) -> tuple[str, str] | None:
    """Return (key_id, secret) if plaintext is a validly-formatted API key, else None.

    A valid key starts with KEY_PREFIX and has exactly one '.' separating a
    non-empty key_id from a non-empty secret.  The split is on the FIRST '.'
    only so that token_urlsafe output (which may contain '_' but not '.') does
    not collide with the separator.
    """
    if not plaintext.startswith(KEY_PREFIX):
        return None
    rest = plaintext[len(KEY_PREFIX):]
    if "." not in rest:
        return None
    key_id, _, secret = rest.partition(".")
    if not key_id or not secret:
        return None
    return key_id, secret


def new_salt() -> bytes:
    """Return 16 random bytes suitable as a per-key scrypt salt."""
    return os.urandom(16)


def hash_secret(secret: str, salt: bytes) -> str:
    """Return the hex-encoded scrypt digest of secret with the given salt."""
    digest = hashlib.scrypt(
        secret.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    return digest.hex()


def verify_secret(secret: str, salt: bytes, expected_hash_hex: str) -> bool:
    """Constant-time comparison of hash_secret(secret, salt) against expected_hash_hex."""
    return hmac.compare_digest(hash_secret(secret, salt), expected_hash_hex)


# ---------------------------------------------------------------------------
# Repository dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IssuedKey:
    tenant_id: UUID
    key_id: str
    name: str | None
    created_at: datetime
    plaintext: str  # only populated at issuance time; never persisted
    role: Role


@dataclass(frozen=True)
class ResolvedKey:
    api_key_id: UUID
    tenant_id: UUID
    key_id: str
    role: Role


# ---------------------------------------------------------------------------
# Repository functions (require an explicit admin/superuser connection)
# ---------------------------------------------------------------------------


def provision_tenant(
    admin_conn,
    name: str,
    role: Role = Role.editor,
    monthly_request_quota: int | None = None,
) -> IssuedKey:
    """Insert a new tenant and its first API key in a single transaction.

    Runs on an ADMIN (superuser) connection so it can INSERT into tenants
    (the app role has no INSERT on tenants) and into api_keys without RLS.
    Both inserts share one transaction; partial failure rolls back entirely.

    When ``monthly_request_quota`` is ``None``, the column is omitted from the
    INSERT so the DB DEFAULT (100 000) applies.  When provided, the value is
    stored as the tenant's quota ceiling.
    """
    with admin_conn.transaction():
        if monthly_request_quota is None:
            row = admin_conn.execute(
                "INSERT INTO tenants (name) VALUES (%s) RETURNING tenant_id, name, created_at",
                (name,),
            ).fetchone()
        else:
            row = admin_conn.execute(
                "INSERT INTO tenants (name, monthly_request_quota) VALUES (%s, %s)"
                " RETURNING tenant_id, name, created_at",
                (name, monthly_request_quota),
            ).fetchone()
        tenant_id: UUID = row[0]
        created_at: datetime = row[2]

        generated = generate_key()
        salt = new_salt()
        secret_hash = hash_secret(generated.secret, salt)

        admin_conn.execute(
            "INSERT INTO api_keys (tenant_id, key_id, secret_hash, salt, name, role)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (tenant_id, generated.key_id, secret_hash, salt, None, role.value),
        )

    return IssuedKey(
        tenant_id=tenant_id,
        key_id=generated.key_id,
        name=None,
        created_at=created_at,
        plaintext=generated.plaintext,
        role=role,
    )


def resolve(admin_conn, plaintext: str) -> ResolvedKey | None:
    """Verify an API key and return its ResolvedKey, or None on any failure.

    Runs on an ADMIN (BYPASSRLS) connection because lookup spans all tenants.
    Always computes a hash (even on no-row) to reduce timing oracle.
    """
    parsed = parse_key(plaintext)
    if parsed is None:
        # Still run a dummy hash to equalize timing.
        verify_secret("dummy", _DUMMY_SALT, _DUMMY_HASH)
        return None

    key_id, secret = parsed

    row = admin_conn.execute(
        "SELECT api_key_id, tenant_id, secret_hash, salt, role"
        " FROM api_keys"
        " WHERE key_id = %s AND revoked_at IS NULL",
        (key_id,),
    ).fetchone()

    if row is None:
        # Equalize timing: compute a real scrypt hash against dummy values.
        verify_secret(secret, _DUMMY_SALT, _DUMMY_HASH)
        return None

    api_key_id: UUID = row[0]
    tenant_id: UUID = row[1]
    secret_hash: str = row[2]
    salt: bytes = bytes(row[3])
    row_role: str = row[4]

    if not verify_secret(secret, salt, secret_hash):
        return None

    return ResolvedKey(
        api_key_id=api_key_id,
        tenant_id=tenant_id,
        key_id=key_id,
        role=Role(row_role),
    )
