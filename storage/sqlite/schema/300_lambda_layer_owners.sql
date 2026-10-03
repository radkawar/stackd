ALTER TABLE lambda_layer_versions ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_layer_versions ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_layer_versions ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX lambda_layer_version_owner
ON lambda_layer_versions(partition, account, region, layer_name, owner_stack_id, owner_logical_id, owner_token)
WHERE owner_stack_id <> '' AND owner_logical_id <> '' AND owner_token <> '';
