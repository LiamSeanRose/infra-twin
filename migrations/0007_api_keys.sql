-- Authenticated tenant provisioning: API key table for Bearer-token auth.
-- Keys are issued one-time; only a salted scrypt hash is stored.  Revocation
-- is a future path (revoked_at column is a seam; no route exposes it yet).
--
-- Expand-contract note: this is a pure expand step.  No existing columns are
-- removed or altered.

CREATE TABLE api_keys (
    api_key_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants (tenant_id),
    key_id      TEXT NOT NULL,            -- public lookup id (cleartext)
    secret_hash TEXT NOT NULL,            -- scrypt hex digest of the secret
    salt        BYTEA NOT NULL,           -- per-key random salt
    name        TEXT,                     -- optional human label
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ              -- NULL = active (revocation seam; no route yet)
);

CREATE UNIQUE INDEX api_keys_key_id ON api_keys (key_id);
CREATE INDEX api_keys_by_tenant ON api_keys (tenant_id);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON api_keys
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- App role may read its own keys (RLS-scoped) but NOT insert: issuance is admin-only,
-- and cross-tenant lookup during auth runs on the BYPASSRLS superuser connection.
GRANT SELECT ON api_keys TO app;
