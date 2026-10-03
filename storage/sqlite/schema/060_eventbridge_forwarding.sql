ALTER TABLE eventbridge_rules ADD COLUMN role_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_targets ADD COLUMN role_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_deliveries ADD COLUMN role_arn TEXT NOT NULL DEFAULT '';

-- An admission remains unique even when forwarding preserves the native ID.
ALTER TABLE eventbridge_events ADD COLUMN wire_id TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_events ADD COLUMN wire_region TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_events ADD COLUMN same_region_hop BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE eventbridge_events ADD COLUMN cross_region_hop BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE eventbridge_events SET wire_id=id,wire_region=region;
