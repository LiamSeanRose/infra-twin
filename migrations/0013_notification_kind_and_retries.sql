-- Expand-only migration: add subscription kind and delivery attempt; widen outcome CHECK.
-- Append-only: no DROP TABLE, no DROP COLUMN, no DROP DEFAULT, no DELETE.
-- One DROP CONSTRAINT is permitted: the outcome CHECK is strictly widened (more values allowed).
-- RLS and grants on both tables remain unchanged from 0012.

-- 3.1 Add kind column to notification_subscription.
-- Defaults existing rows to 'webhook', preserving current semantics.
ALTER TABLE notification_subscription
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'webhook'
        CHECK (kind IN ('webhook', 'slack'));

-- 3.2a Add attempt column to notification_delivery.
ALTER TABLE notification_delivery
    ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1;

-- 3.2b Widen outcome CHECK: drop old two-value constraint, add three-value named constraint.
-- The old constraint name was generated as notification_delivery_outcome_check by 0012.
ALTER TABLE notification_delivery
    DROP CONSTRAINT notification_delivery_outcome_check;

ALTER TABLE notification_delivery
    ADD CONSTRAINT notification_delivery_outcome_check
        CHECK (outcome IN ('delivered', 'failed', 'dead_letter'));
