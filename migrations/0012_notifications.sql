-- Expand-only migration: tenant-scoped, RLS-enforced, append-only notification tables.
-- Append-only: the app role receives INSERT + SELECT only; no UPDATE or DELETE.
-- Not bitemporal: notification records accumulate; they are never versioned or closed.

CREATE TABLE notification_subscription (
    subscription_id UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants (tenant_id),
    url             TEXT        NOT NULL CHECK (url <> ''),
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fast lookup of enabled subscriptions per tenant (used by the evaluator emit path).
CREATE INDEX notification_subscription_enabled
    ON notification_subscription (tenant_id) WHERE enabled IS TRUE;

-- List subscriptions newest-first per tenant.
CREATE INDEX notification_subscription_by_tenant_time
    ON notification_subscription (tenant_id, created_at DESC);

ALTER TABLE notification_subscription ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON notification_subscription
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Append-only grant: SELECT and INSERT only, never UPDATE or DELETE.
GRANT SELECT, INSERT ON notification_subscription TO app;


CREATE TABLE notification_delivery (
    delivery_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants (tenant_id),
    subscription_id UUID        NOT NULL REFERENCES notification_subscription (subscription_id),
    finding_id      UUID        NOT NULL,
    payload         JSONB       NOT NULL DEFAULT '{}',
    status_code     INTEGER,
    outcome         TEXT        NOT NULL CHECK (outcome IN ('delivered','failed')),
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- List deliveries newest-first per tenant.
CREATE INDEX notification_delivery_by_tenant_time
    ON notification_delivery (tenant_id, attempted_at DESC);

-- Look up deliveries for a specific finding.
CREATE INDEX notification_delivery_by_finding
    ON notification_delivery (tenant_id, finding_id);

ALTER TABLE notification_delivery ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON notification_delivery
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Append-only grant: SELECT and INSERT only, never UPDATE or DELETE.
GRANT SELECT, INSERT ON notification_delivery TO app;
