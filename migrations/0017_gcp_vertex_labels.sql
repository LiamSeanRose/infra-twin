-- Add GCP vertex labels for the fourth discovery source (GCP connector).
-- All required edge labels (CONTAINS, RUNS_ON, CONNECTS_TO) already exist (0001_init.sql);
-- do not recreate them. Re-apply grants so new label tables are writable by the app role.
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_vlabel('infra_twin', 'gcp_project');
SELECT ag_catalog.create_vlabel('infra_twin', 'gcp_network');
SELECT ag_catalog.create_vlabel('infra_twin', 'gcp_subnetwork');
SELECT ag_catalog.create_vlabel('infra_twin', 'gcp_firewall');
SELECT ag_catalog.create_vlabel('infra_twin', 'gcp_instance');
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
