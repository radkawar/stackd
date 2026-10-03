ALTER TABLE ebs_snapshots ADD COLUMN volume_source_partition TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN volume_source_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN volume_source_region TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN volume_source_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN volume_request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN volume_parent_event_id TEXT NOT NULL DEFAULT '';

ALTER TABLE ebs_blocks ADD COLUMN encryption_origin_partition TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_blocks ADD COLUMN encryption_origin_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_blocks ADD COLUMN encryption_origin_region TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_blocks ADD COLUMN encryption_origin_id TEXT NOT NULL DEFAULT '';
UPDATE ebs_blocks SET encryption_origin_partition = partition,
 encryption_origin_account_id = account_id, encryption_origin_region = region,
 encryption_origin_id = snapshot_id;

-- Creation input preserves admitted request identity only. All mutable disk,
-- encryption and scheduler state is represented by typed columns below.
CREATE TABLE ebs_volumes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 size INTEGER NOT NULL,
 volume_type TEXT NOT NULL,
 iops INTEGER NOT NULL,
 throughput INTEGER NOT NULL,
 multi_attach BOOLEAN NOT NULL,
 zone_name TEXT NOT NULL,
 zone_id TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 lineage_id TEXT NOT NULL,
 created DATETIME NOT NULL,
 transition_at DATETIME,
 snapshot_at DATETIME,
 status TEXT NOT NULL,
 state_message TEXT NOT NULL,
 auto_enable_io BOOLEAN NOT NULL,
 initialization_rate INTEGER NOT NULL,
 tags_present BOOLEAN NOT NULL,
 encrypted BOOLEAN NOT NULL,
 kms_key_arn TEXT NOT NULL,
 wrapped_key BLOB,
 creation_input TEXT NOT NULL,
 client_token TEXT,
 request_id TEXT NOT NULL,
 parent_event_id TEXT NOT NULL,
 modification_present BOOLEAN NOT NULL,
 modification_original_size INTEGER NOT NULL,
 modification_original_type TEXT NOT NULL,
 modification_original_iops INTEGER NOT NULL,
 modification_original_throughput INTEGER NOT NULL,
 modification_original_multi_attach BOOLEAN NOT NULL,
 modification_target_size INTEGER NOT NULL,
 modification_target_type TEXT NOT NULL,
 modification_target_iops INTEGER NOT NULL,
 modification_target_throughput INTEGER NOT NULL,
 modification_target_multi_attach BOOLEAN NOT NULL,
 modification_started DATETIME,
 modification_optimizing_at DATETIME,
 modification_completed_at DATETIME,
 modification_state TEXT NOT NULL,
 modification_request_id TEXT NOT NULL,
 modification_parent_event_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, id),
 UNIQUE (partition, account_id, region, client_token)
);

CREATE INDEX ebs_volumes_transition ON ebs_volumes (transition_at, partition, account_id, region, id)
 WHERE status <> 'deleted' AND transition_at IS NOT NULL;
CREATE INDEX ebs_volumes_optimizing ON ebs_volumes (modification_optimizing_at, partition, account_id, region, id)
 WHERE status <> 'deleted' AND modification_present = 1 AND modification_state = 'modifying';
CREATE INDEX ebs_volumes_completion ON ebs_volumes (modification_completed_at, partition, account_id, region, id)
 WHERE status <> 'deleted' AND modification_present = 1 AND modification_state = 'optimizing';

CREATE TABLE ebs_volume_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 volume_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, volume_id, key),
 FOREIGN KEY (partition, account_id, region, volume_id)
  REFERENCES ebs_volumes (partition, account_id, region, id) ON DELETE CASCADE
);

-- Physical volume bytes do not reference snapshot rows or source payloads.
-- Metadata-only block listing never loads customer disk contents.
CREATE TABLE ebs_volume_blocks (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 volume_id TEXT NOT NULL,
 block_index INTEGER NOT NULL,
 checksum BLOB NOT NULL CHECK (length(checksum) = 32),
 written_snapshot_id TEXT NOT NULL,
 encryption_origin_partition TEXT NOT NULL,
 encryption_origin_account_id TEXT NOT NULL,
 encryption_origin_region TEXT NOT NULL,
 encryption_origin_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, volume_id, block_index),
 FOREIGN KEY (partition, account_id, region, volume_id)
  REFERENCES ebs_volumes (partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE ebs_volume_block_payloads (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 volume_id TEXT NOT NULL,
 block_index INTEGER NOT NULL,
 data BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, volume_id, block_index),
 FOREIGN KEY (partition, account_id, region, volume_id, block_index)
  REFERENCES ebs_volume_blocks (partition, account_id, region, volume_id, block_index) ON DELETE CASCADE
);

-- Admission retains only modification start times needed by the rolling window,
-- independently of the single latest modification exposed by Describe.
CREATE TABLE ebs_volume_modification_starts (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 volume_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 started DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, volume_id, position),
 FOREIGN KEY (partition, account_id, region, volume_id)
  REFERENCES ebs_volumes (partition, account_id, region, id) ON DELETE CASCADE
);
