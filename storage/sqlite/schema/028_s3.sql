CREATE TABLE s3_buckets (
    partition TEXT NOT NULL,
    name TEXT NOT NULL COLLATE BINARY,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    policy_document TEXT NOT NULL,
    policy_trust BOOLEAN NOT NULL,
    ownership TEXT NOT NULL,
    PRIMARY KEY (partition, name)
);
CREATE INDEX s3_buckets_owner ON s3_buckets(partition, account_id, name);

CREATE TABLE s3_bucket_policy_principals (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    principal TEXT NOT NULL, principal_id TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, principal),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE TABLE s3_bucket_public_access (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    block_public_acls BOOLEAN NOT NULL,
    ignore_public_acls BOOLEAN NOT NULL,
    block_public_policy BOOLEAN NOT NULL,
    restrict_public_buckets BOOLEAN NOT NULL,
    PRIMARY KEY (partition, bucket_name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);

CREATE TABLE s3_objects (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    name TEXT NOT NULL COLLATE BINARY,
    modified TIMESTAMP NOT NULL,
    size INTEGER NOT NULL,
    etag TEXT NOT NULL,
    checksum_algorithm TEXT NOT NULL, checksum TEXT NOT NULL,
    content_type TEXT NOT NULL, content_encoding TEXT NOT NULL, content_language TEXT NOT NULL,
    content_disposition TEXT NOT NULL, cache_control TEXT NOT NULL,
    expires TIMESTAMP,
    PRIMARY KEY (partition, bucket_name, name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE TABLE s3_object_metadata (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, key),
    FOREIGN KEY (partition, bucket_name, object_name) REFERENCES s3_objects(partition, bucket_name, name) ON DELETE CASCADE
);
CREATE TABLE s3_object_data (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name),
    FOREIGN KEY (partition, bucket_name, object_name) REFERENCES s3_objects(partition, bucket_name, name) ON DELETE CASCADE
);
