ALTER TABLE eventbridge_rules ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';

-- Archive ownership remains separate from the service's managed-rule identity.
-- Targetless and orphaned archive rules retain the same public restrictions.
UPDATE eventbridge_rules SET managed_by='prod.vhs.events.aws.internal' WHERE archive_id<>'';
