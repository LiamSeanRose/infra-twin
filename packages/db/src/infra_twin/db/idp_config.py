"""OIDC IdP configuration repository.

Mirrors the structure and style of api_keys.py: frozen dataclasses, admin-connection
functions that span all tenants on a BYPASSRLS connection.  The caller controls
pooling; the caller provides an open admin connection.

No INSERT/UPDATE is granted to the app role for this table; all writes run on the
admin (BYPASSRLS superuser) connection via upsert_idp_config.  Cross-tenant lookup
in find_idp_config also uses the admin connection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from infra_twin.db.api_keys import Role


@dataclass(frozen=True)
class TenantIdpConfig:
    idp_config_id: UUID
    tenant_id: UUID
    issuer: str
    audience: str
    role_claim: str
    role_claim_map: dict[str, str]  # raw claim value -> "viewer" | "editor"
    default_role: Role
    created_at: datetime
    disabled_at: datetime | None    # non-null => inactive; never hard-delete


def upsert_idp_config(
    admin_conn,
    tenant_id: UUID,
    issuer: str,
    audience: str,
    role_claim: str = "role",
    role_claim_map: dict[str, str] | None = None,
    default_role: Role = Role.viewer,
) -> TenantIdpConfig:
    """Insert or update the IdP config for (tenant_id, issuer, audience).

    INSERT ... ON CONFLICT (tenant_id, issuer, audience) DO UPDATE clears
    disabled_at (re-enabling a previously disabled config) and refreshes all
    mutable fields.  Runs on the ADMIN connection; the app role has no
    INSERT/UPDATE on tenant_idp_config.

    The caller owns any surrounding transaction; this function does NOT open
    one itself (matching the style of resolve() in api_keys.py).
    """
    if role_claim_map is None:
        role_claim_map = {}

    import json
    import psycopg.types.json as _pj  # noqa: F401 — ensure JSON adapter registered

    row = admin_conn.execute(
        """
        INSERT INTO tenant_idp_config
            (tenant_id, issuer, audience, role_claim, role_claim_map, default_role)
        VALUES (%s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (tenant_id, issuer, audience) DO UPDATE
            SET role_claim     = EXCLUDED.role_claim,
                role_claim_map = EXCLUDED.role_claim_map,
                default_role   = EXCLUDED.default_role,
                disabled_at    = NULL
        RETURNING
            idp_config_id, tenant_id, issuer, audience,
            role_claim, role_claim_map, default_role, created_at, disabled_at
        """,
        (
            tenant_id,
            issuer,
            audience,
            role_claim,
            json.dumps(role_claim_map),
            default_role.value,
        ),
    ).fetchone()

    return _row_to_config(row)


def find_idp_config(
    admin_conn,
    issuer: str,
    audience: str,
) -> TenantIdpConfig | None:
    """Return the single active IdP config for (issuer, audience) across all tenants.

    Uses the BYPASSRLS admin connection so it spans all tenants — exactly like
    api_keys.resolve() for cross-tenant key lookup.

    Returns None when:
    - No row matches (issuer, audience).
    - The matching row has disabled_at IS NOT NULL (inactive).
    - More than one ACTIVE row matches the same (issuer, audience) across
      different tenants — ambiguous; returning one arbitrarily would be a
      security hazard (see spec §5.20).
    """
    rows = admin_conn.execute(
        """
        SELECT
            idp_config_id, tenant_id, issuer, audience,
            role_claim, role_claim_map, default_role, created_at, disabled_at
        FROM tenant_idp_config
        WHERE issuer = %s
          AND audience = %s
          AND disabled_at IS NULL
        """,
        (issuer, audience),
    ).fetchall()

    if len(rows) != 1:
        return None

    return _row_to_config(rows[0])


def _row_to_config(row) -> TenantIdpConfig:
    """Convert a DB row tuple to TenantIdpConfig."""
    role_claim_map_raw = row[5]
    # psycopg returns JSONB as a dict; coerce to dict[str, str] defensively.
    if isinstance(role_claim_map_raw, dict):
        role_claim_map: dict[str, str] = {str(k): str(v) for k, v in role_claim_map_raw.items()}
    else:
        role_claim_map = {}

    return TenantIdpConfig(
        idp_config_id=row[0],
        tenant_id=row[1],
        issuer=row[2],
        audience=row[3],
        role_claim=row[4],
        role_claim_map=role_claim_map,
        default_role=Role(row[6]),
        created_at=row[7],
        disabled_at=row[8],
    )
