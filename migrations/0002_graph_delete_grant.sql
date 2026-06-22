-- The AGE graph is a derived projection of *current* state, so closed (removed) CIs and
-- edges must be deletable from it — unlike the append-only relational tables. Grant the app
-- role DELETE on the graph schema only.
GRANT DELETE ON ALL TABLES IN SCHEMA infra_twin TO app;
