ALTER TABLE ebs_volumes ADD COLUMN native_path TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_volumes ADD COLUMN service_grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_volumes ADD COLUMN infrastructure_grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_volumes ADD COLUMN modification_status_message TEXT NOT NULL DEFAULT '';
