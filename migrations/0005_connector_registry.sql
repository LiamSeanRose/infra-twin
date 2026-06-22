-- Expand-contract migration (expand step): add the connectors registry table,
-- enable RLS on it, and add nullable connector_id FK columns to connector_runs
-- and raw_facts so runs and facts can be linked back to the registry.
--
-- Existing rows are unaffected: the two new FK columns are NULLABLE, so
-- pre-existing connector_runs and raw_facts rows remain valid. The CONTRACT step
-- (making the columns NOT NULL after backfill) is a future migration.

-- ---------------------------------------------------------------------------
-- Connector registry table
-- ---------------------------------------------------------------------------
CREATE TABLE connectors (
    connector_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants (tenant_id),
    type         TEXT NOT NULL,
    display_name TEXT NOT NULL,
    config       JSONB NOT NULL DEFAULT '{}',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one connector per (tenant, type, display_name): the resolve-or-register key.
CREATE UNIQUE INDEX connectors_identity ON connectors (tenant_id, type, display_name);
CREATE INDEX connectors_by_tenant_type ON connectors (tenant_id, type);

-- ---------------------------------------------------------------------------
-- Row-Level Security: mirrors the pattern established in 0001 for every
-- other tenant-scoped table.  Missing GUC -> NULL -> no rows match.
-- ---------------------------------------------------------------------------
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON connectors
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- No DELETE grant: connectors are disabled, never deleted.
GRANT SELECT, INSERT, UPDATE ON connectors TO app;

-- ---------------------------------------------------------------------------
-- Link connector_runs and raw_facts to the registry (nullable FK, expand step).
-- raw_facts is range-partitioned; ALTER TABLE propagates to raw_facts_default.
-- ---------------------------------------------------------------------------
ALTER TABLE connector_runs ADD COLUMN connector_id UUID REFERENCES connectors (connector_id);
ALTER TABLE raw_facts      ADD COLUMN connector_id UUID REFERENCES connectors (connector_id);

CREATE INDEX connector_runs_by_connector ON connector_runs (connector_id);
CREATE INDEX raw_facts_by_connector      ON raw_facts (connector_id);
