-- SCIM 2.0 user provisioning tables.
-- Expand-only: no existing column, table, or index is altered or dropped.
-- Two new tables:
--   scim_user             -- tenant-scoped, bitemporal, never hard-deleted user records
--   scim_provisioning_token -- per-tenant SCIM bearer credential (hash+salt only; admin-issued)

-- ---------------------------------------------------------------------------
-- scim_user
-- ---------------------------------------------------------------------------

CREATE TABLE scim_user (
    scim_user_id UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants (tenant_id),
    external_id  TEXT,                                  -- IdP-side id (SCIM externalId)
    user_name    TEXT        NOT NULL,                  -- SCIM userName; the OIDC subject/email
    role         TEXT        NOT NULL DEFAULT 'viewer'
                              CHECK (role IN ('viewer','editor')),
    active       BOOLEAN     NOT NULL DEFAULT true,
    valid_from   TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to     TIMESTAMPTZ,                           -- NULL = current row (bitemporal close, never DELETE)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one current row per (tenant, userName).
CREATE UNIQUE INDEX scim_user_current_username
    ON scim_user (tenant_id, user_name) WHERE valid_to IS NULL;

-- At most one current row per (tenant, externalId) when externalId is not NULL.
CREATE UNIQUE INDEX scim_user_current_external_id
    ON scim_user (tenant_id, external_id) WHERE valid_to IS NULL AND external_id IS NOT NULL;

CREATE INDEX scim_user_by_tenant ON scim_user (tenant_id);

ALTER TABLE scim_user ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON scim_user
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- App role: SELECT, INSERT, UPDATE (for closing bitemporal rows via valid_to).
-- DELETE is intentionally omitted — rows are never physically removed.
GRANT SELECT, INSERT, UPDATE ON scim_user TO app;

-- ---------------------------------------------------------------------------
-- scim_provisioning_token
-- ---------------------------------------------------------------------------

CREATE TABLE scim_provisioning_token (
    scim_token_id UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants (tenant_id),
    token_id      TEXT        NOT NULL,            -- public lookup id (cleartext)
    secret_hash   TEXT        NOT NULL,            -- scrypt hex digest
    salt          BYTEA       NOT NULL,            -- per-token random salt
    name          TEXT,                            -- optional human label
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at    TIMESTAMPTZ                      -- NULL = active (revocation seam; no route yet)
);

CREATE UNIQUE INDEX scim_provisioning_token_token_id ON scim_provisioning_token (token_id);
CREATE INDEX scim_provisioning_token_by_tenant ON scim_provisioning_token (tenant_id);

ALTER TABLE scim_provisioning_token ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON scim_provisioning_token
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- App role: SELECT only; issuance is admin-only; resolution uses the BYPASSRLS connection.
GRANT SELECT ON scim_provisioning_token TO app;
