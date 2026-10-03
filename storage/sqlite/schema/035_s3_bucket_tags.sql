CREATE TABLE s3_bucket_tags (
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    key TEXT NOT NULL COLLATE BINARY,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, key),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
