-- Add Azure vertex labels for the third discovery source (Azure connector).
-- All required edge labels (CONTAINS, RUNS_ON, CONNECTS_TO) already exist (0001_init.sql);
-- do not recreate them. Re-apply grants so new label tables are writable by the app role.
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_vlabel('infra_twin', 'azure_subscription');
SELECT ag_catalog.create_vlabel('infra_twin', 'azure_resource_group');
SELECT ag_catalog.create_vlabel('infra_twin', 'azure_vnet');
SELECT ag_catalog.create_vlabel('infra_twin', 'azure_subnet');
SELECT ag_catalog.create_vlabel('infra_twin', 'azure_nsg');
SELECT ag_catalog.create_vlabel('infra_twin', 'azure_vm');
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
