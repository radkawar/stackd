ALTER TABLE cloudtrail_trails ADD COLUMN organization_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudtrail_deliveries ADD COLUMN organization_id TEXT NOT NULL DEFAULT '';
CREATE INDEX cloudtrail_delivery_account_batch ON cloudtrail_deliveries(trail_id, account_id, region, destination, sealed, due, id);
