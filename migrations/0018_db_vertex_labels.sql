-- Add DB-introspection vertex labels for the fifth discovery source (DB connector).
-- All required edge labels (CONTAINS, DEPENDS_ON) already exist (0001_init.sql);
-- do not recreate them. Re-apply grants so new label tables are writable by the app role.
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_vlabel('infra_twin', 'db_instance');
SELECT ag_catalog.create_vlabel('infra_twin', 'db_database');
SELECT ag_catalog.create_vlabel('infra_twin', 'db_schema');
SELECT ag_catalog.create_vlabel('infra_twin', 'db_table');
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
