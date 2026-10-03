-- Legacy ownership is captured before any subsequent bucket ownership changes.
-- Canonical IDs for these implicit ACLs are derived in Go; ciphertext is untouched.
ALTER TABLE s3_buckets ADD COLUMN owner_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN acl_legacy BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE s3_buckets ADD COLUMN bucket_key_enabled BOOLEAN NOT NULL DEFAULT false;
UPDATE s3_buckets SET owner_account_id = account_id;

ALTER TABLE s3_object_versions ADD COLUMN owner_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_object_versions ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_object_versions ADD COLUMN acl_legacy BOOLEAN NOT NULL DEFAULT true;
UPDATE s3_object_versions SET owner_account_id = (
    SELECT b.account_id FROM s3_buckets AS b
    WHERE b.partition = s3_object_versions.partition AND b.name = s3_object_versions.bucket_name
);

ALTER TABLE s3_multipart_uploads ADD COLUMN owner_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_multipart_uploads ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_multipart_uploads ADD COLUMN acl_legacy BOOLEAN NOT NULL DEFAULT true;
UPDATE s3_multipart_uploads SET owner_account_id = (
    SELECT b.account_id FROM s3_buckets AS b
    WHERE b.partition = s3_multipart_uploads.partition AND b.name = s3_multipart_uploads.bucket_name
);

CREATE TABLE s3_bucket_acl_grants (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    grantee_type TEXT NOT NULL, grantee_id TEXT NOT NULL, grantee_uri TEXT NOT NULL, permission TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, position),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE TABLE s3_object_version_acl_grants (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    grantee_type TEXT NOT NULL, grantee_id TEXT NOT NULL, grantee_uri TEXT NOT NULL, permission TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, position),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
CREATE TABLE s3_multipart_upload_acl_grants (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, upload_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    grantee_type TEXT NOT NULL, grantee_id TEXT NOT NULL, grantee_uri TEXT NOT NULL, permission TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, upload_id, position),
    FOREIGN KEY (partition, bucket_name, object_name, upload_id) REFERENCES s3_multipart_uploads(partition, bucket_name, object_name, upload_id) ON DELETE CASCADE
);
