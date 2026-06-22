-- OIDC / IdP configuration per tenant.
-- New table: tenant_idp_config.
-- Expand-only changes to audit_log: add auth_method column, relax api_key_id to nullable.

-- ---------------------------------------------------------------------------
-- tenant_idp_config
-- ---------------------------------------------------------------------------

CREATE TABLE tenant_idp_config (
    idp_config_id  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants (tenant_id),
    issuer         TEXT        NOT NULL,
    audience       TEXT        NOT NULL,
    role_claim     TEXT        NOT NULL DEFAULT 'role',
    role_claim_map JSONB       NOT NULL DEFAULT '{}'::jsonb,
    default_role   TEXT        NOT NULL DEFAULT 'viewer' CHECK (default_role IN ('viewer', 'editor')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at    TIMESTAMPTZ
);

-- Unique per (tenant, issuer, audience): idempotent upsert target.
CREATE UNIQUE INDEX tenant_idp_config_iss_aud
    ON tenant_idp_config (tenant_id, issuer, audience);

-- Supports cross-tenant find_idp_config lookup by (issuer, audience).
CREATE INDEX tenant_idp_config_by_issuer_audience
    ON tenant_idp_config (issuer, audience);

ALTER TABLE tenant_idp_config ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenant_idp_config
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- App role: SELECT only; INSERT/UPDATE/DELETE are admin-only.
-- Cross-tenant lookup runs on the BYPASSRLS admin connection.
GRANT SELECT ON tenant_idp_config TO app;

-- ---------------------------------------------------------------------------
-- audit_log: expand-only changes
-- ---------------------------------------------------------------------------

-- Relax api_key_id to nullable so OIDC audit rows can omit it.
ALTER TABLE audit_log ALTER COLUMN api_key_id DROP NOT NULL;

-- Add auth_method column; existing rows default to 'api_key'.
ALTER TABLE audit_log
    ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'api_key'
        CHECK (auth_method IN ('api_key', 'oidc'));

-- ---------------------------------------------------------------------------
-- usage_event: expand-only change
-- ---------------------------------------------------------------------------

-- Relax api_key_id to nullable so OIDC usage rows can omit it.
ALTER TABLE usage_event ALTER COLUMN api_key_id DROP NOT NULL;
