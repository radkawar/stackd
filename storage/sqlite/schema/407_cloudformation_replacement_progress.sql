ALTER TABLE cloudformation_steps ADD COLUMN before_delete_started BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cloudformation_steps ADD COLUMN before_deleted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cloudformation_steps ADD COLUMN admission_pending BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cloudformation_steps ADD COLUMN restore_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_type TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_physical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_token TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cloudformation_steps ADD COLUMN restore_current BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cloudformation_steps ADD COLUMN restore_status TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_status_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_deletion_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_update_replace_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudformation_steps ADD COLUMN restore_properties TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(restore_properties));
ALTER TABLE cloudformation_steps ADD COLUMN restore_event_properties TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(restore_event_properties));
ALTER TABLE cloudformation_steps ADD COLUMN restore_dynamic_references TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(restore_dynamic_references));
ALTER TABLE cloudformation_steps ADD COLUMN restore_attributes TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(restore_attributes));
ALTER TABLE cloudformation_steps ADD COLUMN restore_updated DATETIME NOT NULL DEFAULT '0001-01-01T00:00:00Z';

-- Recover only deletion facts evidenced by the old retained state machine.
-- Other RUNNING steps must still observe the authoritative owner during recovery.
UPDATE cloudformation_steps SET before_delete_started = TRUE
WHERE state IN ('BEFORE_DELETE_RUNNING', 'BEFORE_DELETE_STABILIZING', 'BEFORE_DELETED');
UPDATE cloudformation_steps SET before_deleted = TRUE WHERE state = 'BEFORE_DELETED';
