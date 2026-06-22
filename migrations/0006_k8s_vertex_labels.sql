-- Add Kubernetes vertex labels for the second cloud source (Kubernetes connector).
-- All required edge labels (CONTAINS, MEMBER_OF, RUNS_ON, ROUTES_TO, EXPOSES) already exist
-- (created in 0001_init.sql); do not recreate them.
-- Re-apply schema-wide grants so the newly created label tables are writable by the app role.
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_vlabel('infra_twin', 'k8s_cluster');
SELECT ag_catalog.create_vlabel('infra_twin', 'k8s_namespace');
SELECT ag_catalog.create_vlabel('infra_twin', 'k8s_node');
SELECT ag_catalog.create_vlabel('infra_twin', 'k8s_workload');
SELECT ag_catalog.create_vlabel('infra_twin', 'k8s_pod');
SELECT ag_catalog.create_vlabel('infra_twin', 'k8s_service');
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
