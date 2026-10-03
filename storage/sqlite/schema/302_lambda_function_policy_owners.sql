ALTER TABLE lambda_function_policies ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_policies ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_policies ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
