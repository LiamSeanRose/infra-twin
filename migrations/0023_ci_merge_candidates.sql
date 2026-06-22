-- Probabilistic/fuzzy merge candidates for the ambiguous tail (plan §24.1).
-- Append-only suggestion table: generation INSERTs/refreshes pending rows; accept/dismiss
-- UPDATE status. No DELETE grant. No existing table, migration, or AGE label is touched.

CREATE TABLE IF NOT EXISTS ci_merge_candidates (
    candidate_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants (tenant_id),
    ci_id_a           UUID        NOT NULL,
    ci_id_b           UUID        NOT NULL,
    ci_type           TEXT        NOT NULL,
    confidence        DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence          TEXT        NOT NULL CHECK (length(btrim(evidence)) > 0),
    status            TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'accepted', 'dismissed')),
    resolved_merge_id UUID,
    generated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ,
    CHECK (ci_id_a < ci_id_b),
    UNIQUE (tenant_id, ci_id_a, ci_id_b)
);

CREATE INDEX IF NOT EXISTS ci_merge_candidates_by_tenant_status
    ON ci_merge_candidates (tenant_id, status, generated_at DESC);

ALTER TABLE ci_merge_candidates ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON ci_merge_candidates
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON ci_merge_candidates TO app;
