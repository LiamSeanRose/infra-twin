-- Bitemporal history retention: tenant-scoped retention policies and append-only
-- aggregate rollups.  One policy per tenant (opt-in; no policy row means infinite
-- retention).  history_aggregates is audit-immutable (SELECT, INSERT only).
--
-- DELETE grant on cis and edges is added here because the retention sweep must
-- physically remove collapsed interior closed-history rows.  The sweep's SQL
-- predicate enforces that valid_to IS NULL rows (current state) and the single
-- most-recent closed boundary row are NEVER deleted; the grant is required
-- only to compact old low-value interior detail rows.

-- ---------------------------------------------------------------------------
-- history_retention_policies: one policy per tenant
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS history_retention_policies (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants (tenant_id),
    retain_closed_days INT         NOT NULL CHECK (retain_closed_days > 0),
    enabled            BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id)
);

ALTER TABLE history_retention_policies ENABLE ROW LEVEL SECURITY;

-- Guard the policy creation so the migration is safely re-runnable (CREATE POLICY
-- has no IF NOT EXISTS clause).
DROP POLICY IF EXISTS tenant_isolation ON history_retention_policies;

CREATE POLICY tenant_isolation ON history_retention_policies
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- No DELETE grant: policies are updated in place, never deleted.
GRANT SELECT, INSERT, UPDATE ON history_retention_policies TO app;

-- ---------------------------------------------------------------------------
-- history_aggregates: append-only, immutable audit rollup of collapsed versions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS history_aggregates (
    aggregate_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants (tenant_id),
    entity_kind         TEXT        NOT NULL CHECK (entity_kind IN ('ci', 'edge')),
    entity_id           UUID        NOT NULL,
    version_count       INT         NOT NULL CHECK (version_count > 0),
    earliest_valid_from TIMESTAMPTZ NOT NULL,
    latest_valid_to     TIMESTAMPTZ NOT NULL,
    rollup              JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS history_aggregates_by_entity
    ON history_aggregates (tenant_id, entity_kind, entity_id);

ALTER TABLE history_aggregates ENABLE ROW LEVEL SECURITY;

-- Guard the policy creation so the migration is safely re-runnable.
DROP POLICY IF EXISTS tenant_isolation ON history_aggregates;

CREATE POLICY tenant_isolation ON history_aggregates
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Audit-immutable: SELECT and INSERT only.  No UPDATE, no DELETE.
-- Mirrors the "no DELETE on bitemporal tables" precedent in 0001_init.sql.
GRANT SELECT, INSERT ON history_aggregates TO app;

-- ---------------------------------------------------------------------------
-- Narrow DELETE grant on cis and edges for the retention sweep.
-- Justification: the sweep must physically compact interior closed-history rows
-- (valid_to IS NOT NULL, older than the retention horizon, and not the single
-- most-recent closed boundary).  The sweep predicate enforces that
-- valid_to IS NULL rows and boundary rows are never touched; this grant is the
-- minimum required to perform that compaction.
-- ---------------------------------------------------------------------------
GRANT DELETE ON cis, edges TO app;
