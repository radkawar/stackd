ALTER TABLE ebs_snapshot_public_access ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshot_public_access ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshot_public_access ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
