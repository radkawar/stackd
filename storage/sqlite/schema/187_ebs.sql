CREATE TABLE ebs_snapshots (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 lineage_id TEXT NOT NULL,
 initial_client_token TEXT,
 initial_description TEXT,
 initial_encrypted BOOLEAN,
 initial_kms_key_arn TEXT,
 initial_parent_snapshot_id TEXT,
 initial_timeout INTEGER,
 initial_volume_size INTEGER,
 initial_tags_present BOOLEAN NOT NULL,
 created DATETIME NOT NULL,
 status TEXT NOT NULL,
 sealed BOOLEAN NOT NULL,
 readable BOOLEAN NOT NULL,
 deleted BOOLEAN NOT NULL,
 complete_at DATETIME,
 readable_at DATETIME,
 timeout_at DATETIME,
 delete_at DATETIME,
 state_message TEXT NOT NULL,
 tags_present BOOLEAN NOT NULL,
 kms_key_arn TEXT NOT NULL,
 wrapped_key BLOB,
 token_key BLOB,
 PRIMARY KEY (partition, account_id, region, id),
 UNIQUE (partition, account_id, region, initial_client_token)
);

CREATE INDEX ebs_snapshots_counts ON ebs_snapshots (partition, account_id, region, deleted, status);
CREATE INDEX ebs_snapshots_completion ON ebs_snapshots (complete_at, partition, account_id, region, id)
 WHERE deleted = 0 AND status = 'pending' AND sealed = 1;
CREATE INDEX ebs_snapshots_readiness ON ebs_snapshots (readable_at, partition, account_id, region, id)
 WHERE deleted = 0 AND status = 'completed' AND readable = 0;
CREATE INDEX ebs_snapshots_timeout ON ebs_snapshots (timeout_at, partition, account_id, region, id)
 WHERE deleted = 0 AND status = 'pending' AND sealed = 0;
CREATE INDEX ebs_snapshots_deletion ON ebs_snapshots (delete_at, partition, account_id, region, id)
 WHERE deleted = 1;

CREATE TABLE ebs_initial_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, snapshot_id, position),
 FOREIGN KEY (partition, account_id, region, snapshot_id)
  REFERENCES ebs_snapshots (partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE ebs_snapshot_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, snapshot_id, key),
 FOREIGN KEY (partition, account_id, region, snapshot_id)
  REFERENCES ebs_snapshots (partition, account_id, region, id) ON DELETE CASCADE
);

-- Metadata and payloads have separate tables so listing and completion never
-- load customer block contents. Parent-layer resolution belongs to the service.
CREATE TABLE ebs_blocks (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 block_index INTEGER NOT NULL,
 checksum BLOB NOT NULL CHECK (length(checksum) = 32),
 PRIMARY KEY (partition, account_id, region, snapshot_id, block_index),
 FOREIGN KEY (partition, account_id, region, snapshot_id)
  REFERENCES ebs_snapshots (partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE ebs_block_payloads (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 block_index INTEGER NOT NULL,
 data BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, snapshot_id, block_index),
 FOREIGN KEY (partition, account_id, region, snapshot_id, block_index)
  REFERENCES ebs_blocks (partition, account_id, region, snapshot_id, block_index) ON DELETE CASCADE
);

CREATE TABLE ebs_encryption_defaults (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 enabled BOOLEAN NOT NULL,
 kms_key_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region)
);

CREATE TABLE ebs_sequences (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 sequence BLOB NOT NULL CHECK (length(sequence) = 8),
 PRIMARY KEY (partition, account_id, region)
);
