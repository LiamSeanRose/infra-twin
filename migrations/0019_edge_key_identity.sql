-- Expand-only migration: add edge_key discriminator to support parallel same-type edges.
-- Append-only: no DROP TABLE, no DROP COLUMN, no create_vlabel, no create_elabel.
-- Replaces edges_current_identity to widen the uniqueness key from 4 to 5 columns.
-- All statements are idempotent; safe to replay.

-- 1. Add edge_key column; NOT NULL DEFAULT '' backfills existing rows atomically.
ALTER TABLE edges ADD COLUMN IF NOT EXISTS edge_key TEXT NOT NULL DEFAULT '';

-- 2. Defensive backfill for any NULLs (no-op given the default, but keeps the migration
--    safe if the column pre-exists nullable from a partial prior apply).
UPDATE edges SET edge_key = '' WHERE edge_key IS NULL;

-- 3. Drop the old 4-column unique index so the new one can be created.
DROP INDEX IF EXISTS edges_current_identity;

-- 4. Recreate the open-row identity index with edge_key included (5 columns).
CREATE UNIQUE INDEX IF NOT EXISTS edges_current_identity
    ON edges (tenant_id, type, from_id, to_id, edge_key) WHERE valid_to IS NULL;
