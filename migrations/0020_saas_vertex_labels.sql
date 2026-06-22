-- Add SaaS vertex labels for the sixth discovery source (SaaS connector).
-- All required edge labels (CONTAINS, HAS_ACCESS_TO, DEPENDS_ON) already exist
-- (0001_init.sql); do not recreate them. Re-apply grants so new label tables are writable
-- by the app role.
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_vlabel('infra_twin', 'saas_app');
SELECT ag_catalog.create_vlabel('infra_twin', 'saas_account');
SELECT ag_catalog.create_vlabel('infra_twin', 'saas_resource');
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
