-- No public marker backfill: existing permission rows and receipts are unclaimed.
ALTER TABLE ram_permissions ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE ram_receipts ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE ram_permissions ADD COLUMN object_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ram_receipts ADD COLUMN object_id TEXT NOT NULL DEFAULT '';
