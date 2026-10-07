ALTER TABLE msk_configurations ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE msk_configurations ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE msk_configurations ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
