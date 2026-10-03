CREATE TABLE s3_bucket_logging (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    target_bucket TEXT NOT NULL, target_prefix TEXT NOT NULL,
    key_format TEXT NOT NULL, has_grants BOOLEAN NOT NULL,
    PRIMARY KEY (partition, bucket_name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE TABLE s3_bucket_logging_grants (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, position INTEGER NOT NULL,
    grantee_type TEXT NOT NULL, grantee_id TEXT NOT NULL,
    grantee_uri TEXT NOT NULL, permission TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, position),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_bucket_logging(partition, bucket_name) ON DELETE CASCADE
);
