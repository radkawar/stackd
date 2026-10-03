-- Retain the SSM value admitted with each parameter key. NULL means the
-- parameter is not an SSM value type; an empty resolved string remains a value.
ALTER TABLE cloudformation_stacks_parameters ADD COLUMN resolved_value TEXT;
ALTER TABLE cloudformation_operations_parameters ADD COLUMN resolved_value TEXT;
ALTER TABLE cloudformation_change_sets_parameters ADD COLUMN resolved_value TEXT;
ALTER TABLE cloudformation_change_sets ADD COLUMN disable_rollback BOOLEAN NOT NULL DEFAULT FALSE;
