ALTER TABLE lambda_event_source_mappings ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_source_mappings ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_source_mappings ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX lambda_event_source_mapping_owner
ON lambda_event_source_mappings(partition,account,region,owner_stack_id,owner_logical_id,owner_token)
WHERE owner_stack_id<>'' AND owner_logical_id<>'' AND owner_token<>'';
