ALTER TABLE ebs_snapshots ADD COLUMN volume_size INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ebs_snapshots ADD COLUMN description TEXT NOT NULL DEFAULT '';

UPDATE ebs_snapshots
SET volume_size = COALESCE(initial_volume_size, 0),
 description = COALESCE(initial_description, '');

-- Copy provenance is metadata, not a foreign-key dependency on source payloads.
ALTER TABLE ebs_snapshots ADD COLUMN copy_source_partition TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_source_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_source_region TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_source_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_incremental BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE ebs_snapshots ADD COLUMN copy_completion_duration_minutes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ebs_snapshots ADD COLUMN copy_request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_parent_event_id TEXT NOT NULL DEFAULT '';

-- Logical writes survive physical copy/re-encryption and source deletion.
ALTER TABLE ebs_blocks ADD COLUMN written_snapshot_id TEXT NOT NULL DEFAULT '';
UPDATE ebs_blocks SET written_snapshot_id = snapshot_id;
