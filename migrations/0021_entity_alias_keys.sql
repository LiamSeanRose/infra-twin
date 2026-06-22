-- Cross-source entity resolution: alias-key -> canonical CI mapping and merge provenance.
-- Append-only provenance table (ci_merges) mirrors the audit_log grant style: INSERT+SELECT only.
-- Neither table carries a DELETE grant; ci_merges has no UPDATE grant either.
-- No existing table, migration, or AGE label is touched.

-- ---------------------------------------------------------------------------
-- ci_alias_keys: stable cross-source alias -> canonical CI mapping
-- PK (tenant_id, alias_key) makes re-binding idempotent via ON CONFLICT DO UPDATE.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ci_alias_keys (
    tenant_id   UUID NOT NULL REFERENCES tenants (tenant_id),
    alias_key   TEXT NOT NULL,
    ci_id       UUID NOT NULL,
    ci_type     TEXT NOT NULL,
    source      TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, alias_key)
);

ALTER TABLE ci_alias_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON ci_alias_keys
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON ci_alias_keys TO app;

-- ---------------------------------------------------------------------------
-- ci_merges: append-only merge provenance for reversibility-in-principle
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ci_merges (
    merge_id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants (tenant_id),
    canonical_ci_id    UUID        NOT NULL,
    merged_source      TEXT        NOT NULL,
    merged_external_id TEXT        NOT NULL,
    matched_alias_key  TEXT        NOT NULL,
    evidence           TEXT        NOT NULL,
    merged_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ci_merges_by_tenant_canonical
    ON ci_merges (tenant_id, canonical_ci_id);

ALTER TABLE ci_merges ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON ci_merges
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT ON ci_merges TO app;
