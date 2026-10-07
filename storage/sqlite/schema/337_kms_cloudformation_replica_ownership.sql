ALTER TABLE kms_keys ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX kms_keys_resource_owner
ON kms_keys (partition, account, region, owner_stack_id, owner_logical_id, owner_token)
WHERE owner_stack_id <> '' AND owner_logical_id <> '' AND owner_token <> '';
