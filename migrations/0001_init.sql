-- Foundation schema: tenancy, bitemporal CI/edge store, raw facts, connector health,
-- Apache AGE graph projection, and Row-Level Security tenant isolation.
--
-- Run by the migration runner as a superuser (it creates extensions and roles).

-- ---------------------------------------------------------------------------
-- Application role. RLS is enforced against this non-superuser login; the
-- access layer and tests connect as `app`, never as the superuser.
-- ---------------------------------------------------------------------------
CREATE ROLE app LOGIN PASSWORD 'app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- ---------------------------------------------------------------------------
-- Tenancy registry (not tenant-scoped — this is the list of tenants).
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    tenant_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Configuration Items. Bitemporal: a change closes the current row
-- (sets valid_to) and opens a new version sharing the same id.
-- ---------------------------------------------------------------------------
CREATE TABLE cis (
    id          UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants (tenant_id),
    type        TEXT NOT NULL,
    external_id TEXT NOT NULL,
    name        TEXT,
    attributes  JSONB NOT NULL DEFAULT '{}',
    confidence  REAL NOT NULL DEFAULT 1.0,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    valid_from  TIMESTAMPTZ NOT NULL,
    valid_to    TIMESTAMPTZ,
    PRIMARY KEY (id, valid_from)
);
-- At most one current version per (tenant, type, external_id).
CREATE UNIQUE INDEX cis_current_identity
    ON cis (tenant_id, type, external_id) WHERE valid_to IS NULL;
CREATE INDEX cis_current_by_type
    ON cis (tenant_id, type) WHERE valid_to IS NULL;
CREATE INDEX cis_attributes_gin ON cis USING GIN (attributes);

-- ---------------------------------------------------------------------------
-- External identity -> internal CI mapping (entity-resolution seam).
-- ---------------------------------------------------------------------------
CREATE TABLE source_keys (
    tenant_id   UUID NOT NULL REFERENCES tenants (tenant_id),
    source      TEXT NOT NULL,
    native_id   TEXT NOT NULL,
    ci_id       UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, source, native_id)
);

-- ---------------------------------------------------------------------------
-- Edges. Bitemporal like CIs; provenance (source/confidence/evidence) required.
-- ---------------------------------------------------------------------------
CREATE TABLE edges (
    id         UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants (tenant_id),
    type       TEXT NOT NULL,
    from_id    UUID NOT NULL,
    to_id      UUID NOT NULL,
    source     TEXT NOT NULL CHECK (source IN ('declared', 'inferred')),
    confidence REAL NOT NULL,
    evidence   JSONB NOT NULL CHECK (jsonb_typeof(evidence) = 'array'
                                     AND jsonb_array_length(evidence) > 0),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to   TIMESTAMPTZ,
    PRIMARY KEY (id, valid_from)
);
CREATE UNIQUE INDEX edges_current_identity
    ON edges (tenant_id, type, from_id, to_id) WHERE valid_to IS NULL;
CREATE INDEX edges_current_from ON edges (tenant_id, from_id) WHERE valid_to IS NULL;
CREATE INDEX edges_current_to   ON edges (tenant_id, to_id)   WHERE valid_to IS NULL;

-- ---------------------------------------------------------------------------
-- Immutable raw observations (audit + debugging + replay). Range-partitioned.
-- ---------------------------------------------------------------------------
CREATE TABLE raw_facts (
    fact_id     BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id   UUID NOT NULL REFERENCES tenants (tenant_id),
    source      TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    payload     JSONB NOT NULL,
    PRIMARY KEY (fact_id, observed_at)
) PARTITION BY RANGE (observed_at);
CREATE TABLE raw_facts_default PARTITION OF raw_facts DEFAULT;

-- ---------------------------------------------------------------------------
-- Connector run health (surfaced to users — a silent failure = a wrong graph).
-- ---------------------------------------------------------------------------
CREATE TABLE connector_runs (
    run_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants (tenant_id),
    source      TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('ok', 'error', 'partial')),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error       TEXT
);
CREATE INDEX connector_runs_by_tenant ON connector_runs (tenant_id, source);

-- ---------------------------------------------------------------------------
-- Apache AGE graph projection. The relational tables above remain the source
-- of truth; this graph is derived for traversal queries (blast radius, paths).
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS age;
-- AGE needs its shared library loaded and ag_catalog on the search path. Preload it for
-- every future connection to this database (incl. the non-superuser app role) so cypher()
-- works without each session having privilege to LOAD it.
ALTER DATABASE infra_twin SET session_preload_libraries = 'age';
LOAD 'age';
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_graph('infra_twin');

-- Pre-create vertex and edge labels as the graph owner. Creating a label alters AGE's parent
-- label tables, which the app role may not do; pre-creating means the app role only ever
-- INSERTs into existing label tables. Labels mirror the canonical CIType / EdgeType values.
SELECT ag_catalog.create_vlabel('infra_twin', 'cloud_account');
SELECT ag_catalog.create_vlabel('infra_twin', 'region');
SELECT ag_catalog.create_vlabel('infra_twin', 'vpc');
SELECT ag_catalog.create_vlabel('infra_twin', 'subnet');
SELECT ag_catalog.create_vlabel('infra_twin', 'security_group');
SELECT ag_catalog.create_vlabel('infra_twin', 'ec2_instance');
SELECT ag_catalog.create_vlabel('infra_twin', 'elb');
SELECT ag_catalog.create_vlabel('infra_twin', 'rds');
SELECT ag_catalog.create_vlabel('infra_twin', 's3_bucket');
SELECT ag_catalog.create_vlabel('infra_twin', 'iam_role');
SELECT ag_catalog.create_vlabel('infra_twin', 'iam_user');
SELECT ag_catalog.create_vlabel('infra_twin', 'eks_cluster');
SELECT ag_catalog.create_elabel('infra_twin', 'CONTAINS');
SELECT ag_catalog.create_elabel('infra_twin', 'RUNS_ON');
SELECT ag_catalog.create_elabel('infra_twin', 'CONNECTS_TO');
SELECT ag_catalog.create_elabel('infra_twin', 'DEPENDS_ON');
SELECT ag_catalog.create_elabel('infra_twin', 'ROUTES_TO');
SELECT ag_catalog.create_elabel('infra_twin', 'HAS_ACCESS_TO');
SELECT ag_catalog.create_elabel('infra_twin', 'OWNS');
SELECT ag_catalog.create_elabel('infra_twin', 'EXPOSES');
SELECT ag_catalog.create_elabel('infra_twin', 'MEMBER_OF');
SELECT ag_catalog.create_elabel('infra_twin', 'RESOLVES_TO');

-- ---------------------------------------------------------------------------
-- Row-Level Security: tenant isolation enforced at the storage layer.
-- Policies key on the per-transaction GUC app.tenant_id (set via SET LOCAL).
-- Missing GUC -> NULL -> no rows match (read denied, write denied).
-- ---------------------------------------------------------------------------
ALTER TABLE cis            ENABLE ROW LEVEL SECURITY;
ALTER TABLE edges          ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_keys    ENABLE ROW LEVEL SECURITY;
ALTER TABLE raw_facts      ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON cis
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON edges
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON source_keys
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON raw_facts
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON connector_runs
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Grants for the app role. Deliberately no DELETE on bitemporal tables:
-- facts are closed (valid_to), never physically removed.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO app;
GRANT SELECT ON tenants TO app;
GRANT SELECT, INSERT, UPDATE ON cis, edges, source_keys, raw_facts, connector_runs TO app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app;

-- AGE graph access for the app role.
GRANT USAGE ON SCHEMA ag_catalog TO app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ag_catalog TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA ag_catalog TO app;
-- Graph schema: app inserts/reads pre-created label tables (no DDL, no DELETE).
GRANT USAGE ON SCHEMA infra_twin TO app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
