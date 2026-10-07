-- Legacy/native configurations remain unowned. Claims are private typed owner
-- state, never inferred from public tags, and survive controller recovery.
ALTER TABLE lambda_event_invoke_configs ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_invoke_configs ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_invoke_configs ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_urls ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_urls ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_urls ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_code_signing_configs ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_code_signing_configs ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_code_signing_configs ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_capacity_providers ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_capacity_providers ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_capacity_providers ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
