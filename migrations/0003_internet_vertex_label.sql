-- Add the `internet` vertex label for the singleton internet pseudo-CI.
-- The CONNECTS_TO edge label already exists (created in 0001_init.sql); do not recreate it.
-- Re-apply schema-wide grants so the newly created label table is writable by the app role
-- (prior migrations only granted on tables existing at that time).
SET search_path = ag_catalog, "$user", public;
SELECT ag_catalog.create_vlabel('infra_twin', 'internet');
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA infra_twin TO app;
