-- Expand-only migration: per-tenant monthly request quota and append-only usage event store.
-- NOT NULL DEFAULT 100000 backfills every existing tenant to the default ceiling.
-- No columns removed or altered; no DROP TABLE, DROP COLUMN, or DROP DEFAULT.

ALTER TABLE tenants
    ADD COLUMN monthly_request_quota INTEGER NOT NULL DEFAULT 100000;

CREATE TABLE usage_event (
    usage_id    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (tenant_id),
    api_key_id  UUID        NOT NULL,
    method      TEXT        NOT NULL,
    path        TEXT        NOT NULL,
    permission  TEXT        CHECK (permission IS NULL OR permission IN ('read', 'write')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX usage_event_by_tenant_time ON usage_event (tenant_id, occurred_at DESC);

ALTER TABLE usage_event ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON usage_event
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Append-only grant: INSERT and SELECT only, never UPDATE or DELETE.
GRANT SELECT, INSERT ON usage_event TO app;
