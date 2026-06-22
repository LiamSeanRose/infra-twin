-- Expand-only migration: add a role (viewer|editor) to api_keys.
-- NOT NULL with DEFAULT 'editor' backfills every existing key to 'editor',
-- preserving current behavior (all pre-existing keys keep full read+write).
-- No columns removed or altered; a CONTRACT step is not required.

ALTER TABLE api_keys
    ADD COLUMN role TEXT NOT NULL DEFAULT 'editor'
        CHECK (role IN ('viewer', 'editor'));
