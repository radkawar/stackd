ALTER TABLE s3_buckets ADD COLUMN encryption_algorithm TEXT NOT NULL DEFAULT 'AES256';
ALTER TABLE s3_buckets ADD COLUMN kms_key_id TEXT NOT NULL DEFAULT '';

ALTER TABLE s3_object_versions ADD COLUMN encryption_algorithm TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_object_versions ADD COLUMN kms_key_arn TEXT NOT NULL DEFAULT '';
UPDATE s3_object_versions SET encryption_algorithm = 'AES256' WHERE NOT delete_marker;

CREATE TABLE s3_object_version_encryption_context (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
