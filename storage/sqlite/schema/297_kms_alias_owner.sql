ALTER TABLE kms_aliases ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_aliases ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_aliases ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
