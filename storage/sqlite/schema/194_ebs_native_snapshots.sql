ALTER TABLE ebs_snapshots ADD COLUMN native_backup_path TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN native_backup_ready BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ebs_snapshots ADD COLUMN native_work_at DATETIME;
CREATE INDEX ebs_snapshots_native_work ON ebs_snapshots(native_work_at) WHERE native_backup_path <> '' AND native_work_at IS NOT NULL;
