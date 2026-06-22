-- Add the `dns_name` vertex label for DNS-name CIs (e.g. ELB DNS names).
-- The RESOLVES_TO and EXPOSES edge labels already exist (created in 0001_init.sql); do not recreate them.
-- Re-apply schema-wide grants so the newly created label table is writable by the app role.
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_vlabel('infra_twin', 'dns_name');
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
