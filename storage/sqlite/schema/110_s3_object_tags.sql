CREATE TABLE s3_object_version_tags (
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    object_name TEXT NOT NULL COLLATE BINARY,
    version_id TEXT NOT NULL,
    key TEXT NOT NULL COLLATE BINARY,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, version_id)
        REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
