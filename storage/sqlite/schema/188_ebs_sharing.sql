ALTER TABLE ebs_snapshots ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE ebs_snapshots ADD COLUMN sharing_at DATETIME;

CREATE INDEX ebs_snapshots_sharing ON ebs_snapshots (sharing_at, partition, account_id, region, id)
 WHERE deleted = 0 AND sharing_at IS NOT NULL;
CREATE INDEX ebs_snapshots_regional_id ON ebs_snapshots (partition, region, id);

CREATE TABLE ebs_snapshot_shares (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 recipient_account_id TEXT NOT NULL,
 granted BOOLEAN NOT NULL,
 readable BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, snapshot_id, recipient_account_id),
 FOREIGN KEY (partition, account_id, region, snapshot_id)
  REFERENCES ebs_snapshots (partition, account_id, region, id) ON DELETE CASCADE
);
CREATE INDEX ebs_snapshot_shares_recipient ON ebs_snapshot_shares (partition, region, recipient_account_id, snapshot_id);

CREATE TABLE ebs_snapshot_shared_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 recipient_account_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, snapshot_id, recipient_account_id, key),
 FOREIGN KEY (partition, account_id, region, snapshot_id)
  REFERENCES ebs_snapshots (partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE ebs_snapshot_public_access (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 state TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region)
);
