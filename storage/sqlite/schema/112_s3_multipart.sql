ALTER TABLE s3_object_versions ADD COLUMN created_order INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3_object_versions ADD COLUMN upload_id TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_object_versions ADD COLUMN checksum_type TEXT NOT NULL DEFAULT '';
UPDATE s3_object_versions SET created_order = sequence,
    checksum_type = CASE WHEN checksum <> '' THEN 'FULL_OBJECT' ELSE '' END;
DROP INDEX s3_object_versions_history;
CREATE INDEX s3_object_versions_history ON s3_object_versions(partition, bucket_name, name COLLATE BINARY, created_order DESC);
CREATE UNIQUE INDEX s3_object_versions_upload ON s3_object_versions(partition, bucket_name, name, upload_id) WHERE upload_id <> '';

CREATE TABLE s3_multipart_uploads (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    object_name TEXT NOT NULL COLLATE BINARY, upload_id TEXT NOT NULL CHECK (upload_id <> ''),
    created_order INTEGER NOT NULL UNIQUE CHECK (created_order > 0),
    modified TIMESTAMP NOT NULL,
    initiator TEXT NOT NULL, superseded BOOLEAN NOT NULL,
    size INTEGER NOT NULL, etag TEXT NOT NULL,
    checksum_algorithm TEXT NOT NULL, checksum TEXT NOT NULL, checksum_type TEXT NOT NULL,
    content_type TEXT NOT NULL, content_encoding TEXT NOT NULL, content_language TEXT NOT NULL,
    content_disposition TEXT NOT NULL, cache_control TEXT NOT NULL, expires TIMESTAMP,
    website_redirect_location TEXT NOT NULL,
    encryption_algorithm TEXT NOT NULL, kms_key_arn TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, upload_id),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE INDEX s3_multipart_uploads_listing ON s3_multipart_uploads(partition, bucket_name, object_name COLLATE BINARY, created_order);

CREATE TABLE s3_multipart_upload_metadata (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, upload_id TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, upload_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, upload_id) REFERENCES s3_multipart_uploads(partition, bucket_name, object_name, upload_id) ON DELETE CASCADE
);
CREATE TABLE s3_multipart_upload_tags (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, upload_id TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, upload_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, upload_id) REFERENCES s3_multipart_uploads(partition, bucket_name, object_name, upload_id) ON DELETE CASCADE
);
CREATE TABLE s3_multipart_upload_encryption_context (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, upload_id TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, upload_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, upload_id) REFERENCES s3_multipart_uploads(partition, bucket_name, object_name, upload_id) ON DELETE CASCADE
);
CREATE TABLE s3_multipart_upload_encryption_keys (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, upload_id TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, upload_id),
    FOREIGN KEY (partition, bucket_name, object_name, upload_id) REFERENCES s3_multipart_uploads(partition, bucket_name, object_name, upload_id) ON DELETE CASCADE
);

-- A part belongs exclusively to its active upload or to a retained version.
-- Publication changes only these ownership columns, never the ciphertext.
CREATE TABLE s3_encrypted_parts (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL,
    upload_id TEXT, version_id TEXT,
    number INTEGER NOT NULL CHECK (number BETWEEN 1 AND 10000),
    modified TIMESTAMP NOT NULL, size INTEGER NOT NULL,
    etag TEXT NOT NULL, checksum TEXT NOT NULL, ciphertext BLOB NOT NULL,
    CHECK ((upload_id IS NOT NULL AND version_id IS NULL) OR (upload_id IS NULL AND version_id IS NOT NULL)),
    UNIQUE (partition, bucket_name, object_name, upload_id, number),
    UNIQUE (partition, bucket_name, object_name, version_id, number),
    FOREIGN KEY (partition, bucket_name, object_name, upload_id) REFERENCES s3_multipart_uploads(partition, bucket_name, object_name, upload_id) ON DELETE CASCADE,
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
