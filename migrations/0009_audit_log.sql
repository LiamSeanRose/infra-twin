-- Immutable, tenant-scoped audit log for authenticated API access.
-- Append-only: the app role receives INSERT + SELECT only; no UPDATE or DELETE.
-- Not bitemporal: audit entries are never versioned, only accumulated.

CREATE TABLE audit_log (
    audit_id    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (tenant_id),
    api_key_id  UUID        NOT NULL,
    role        TEXT        NOT NULL CHECK (role IN ('viewer', 'editor')),
    method      TEXT        NOT NULL,
    path        TEXT        NOT NULL,
    permission  TEXT        CHECK (permission IS NULL OR permission IN ('read', 'write')),
    decision    TEXT        NOT NULL CHECK (decision IN ('allow', 'deny')),
    status_code INTEGER     NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_by_tenant_time ON audit_log (tenant_id, occurred_at DESC);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON audit_log
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Append-only grant: INSERT and SELECT only, never UPDATE or DELETE.
GRANT SELECT, INSERT ON audit_log TO app;
