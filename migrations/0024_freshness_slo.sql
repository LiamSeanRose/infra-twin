-- Freshness SLO configuration table: tenant-scoped, mutable in place (no bitemporal
-- rows), following the connectors convention from 0005_connector_registry.sql.
-- One SLO per (tenant, source): configures how long a connector source may be
-- idle before it is considered breaching.  No warn_after_seconds column (two-state
-- model: fresh / breaching only).  No DELETE grant.

CREATE TABLE IF NOT EXISTS freshness_slos (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID        NOT NULL REFERENCES tenants (tenant_id),
    source                   TEXT        NOT NULL,
    expected_interval_seconds INT        NOT NULL CHECK (expected_interval_seconds > 0),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source)
);

CREATE INDEX IF NOT EXISTS freshness_slos_by_tenant_source
    ON freshness_slos (tenant_id, source);

ALTER TABLE freshness_slos ENABLE ROW LEVEL SECURITY;

-- Guard the policy creation so the migration is safely re-runnable (CREATE POLICY
-- has no IF NOT EXISTS clause).
DROP POLICY IF EXISTS tenant_isolation ON freshness_slos;

CREATE POLICY tenant_isolation ON freshness_slos
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- No DELETE grant: SLOs are updated in place, never deleted.
GRANT SELECT, INSERT, UPDATE ON freshness_slos TO app;
