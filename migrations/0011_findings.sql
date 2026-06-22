-- Expand-only migration: tenant-scoped, RLS-enforced, append-only, bitemporal risk findings.
-- Never hard-delete: a re-evaluation closes a finding via valid_to + status='resolved'.
-- The app role is granted SELECT/INSERT/UPDATE but NOT DELETE.

CREATE TABLE finding (
    id            UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants (tenant_id),
    rule_id       TEXT        NOT NULL,
    severity      TEXT        NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    subject_ci_id UUID        NOT NULL,
    title         TEXT        NOT NULL,
    description   TEXT        NOT NULL,
    evidence      JSONB       NOT NULL DEFAULT '{}',
    status        TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from    TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to      TIMESTAMPTZ,
    PRIMARY KEY (id, valid_from)
);

-- At most one currently-open finding per (tenant, rule, subject): idempotency at the storage layer.
CREATE UNIQUE INDEX finding_open_identity
    ON finding (tenant_id, rule_id, subject_ci_id) WHERE valid_to IS NULL;

-- Read path: open findings newest-first per tenant.
CREATE INDEX finding_open_by_tenant_time
    ON finding (tenant_id, detected_at DESC) WHERE valid_to IS NULL;

CREATE INDEX finding_evidence_gin ON finding USING GIN (evidence);

ALTER TABLE finding ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON finding
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Bitemporal grant: SELECT/INSERT/UPDATE (to close via valid_to/status), never DELETE.
GRANT SELECT, INSERT, UPDATE ON finding TO app;
