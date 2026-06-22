-- Un-merge provenance table. Records each reversal of a cross-source entity-resolution
-- merge. Append-only (SELECT + INSERT only; no UPDATE, no DELETE grant).
-- No existing table, migration, or AGE label is touched.

CREATE TABLE IF NOT EXISTS ci_unmerges (
    unmerge_id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL REFERENCES tenants (tenant_id),
    original_merge_id    UUID        NOT NULL,
    canonical_ci_id      UUID        NOT NULL,
    restored_ci_id       UUID        NOT NULL,
    restored_source      TEXT        NOT NULL,
    restored_external_id TEXT        NOT NULL,
    evidence             TEXT        NOT NULL,
    unmerged_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ci_unmerges_by_tenant_merge
    ON ci_unmerges (tenant_id, original_merge_id);

ALTER TABLE ci_unmerges ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON ci_unmerges
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT ON ci_unmerges TO app;
