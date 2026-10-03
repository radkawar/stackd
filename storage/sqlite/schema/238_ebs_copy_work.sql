ALTER TABLE ebs_snapshots ADD COLUMN copy_work_at TIMESTAMP;
ALTER TABLE ebs_snapshots ADD COLUMN copy_key_source_partition TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_key_source_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_key_source_region TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_key_source_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_source_grant_token TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_destination_grant_token TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN copy_destination_encrypt_grant_token TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_snapshots ADD COLUMN blocks_work_at TIMESTAMP;

ALTER TABLE ebs_volumes ADD COLUMN creation_source_partition TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_volumes ADD COLUMN creation_source_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_volumes ADD COLUMN creation_source_region TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_volumes ADD COLUMN creation_source_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ebs_volumes ADD COLUMN creation_source_wrapped_key BLOB;
ALTER TABLE ebs_volumes ADD COLUMN creation_reuse_source_ciphertext BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ebs_volumes ADD COLUMN creation_retire_grant BOOLEAN NOT NULL DEFAULT FALSE;
