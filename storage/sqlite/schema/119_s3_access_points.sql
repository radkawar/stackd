-- Access points can outlive foreign-owned buckets; bucket identity has no foreign key.
CREATE TABLE s3_access_points (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL COLLATE BINARY,
    alias TEXT NOT NULL COLLATE BINARY,
    bucket_partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    bucket_account_id TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    vpc_id TEXT NOT NULL,
    block_public_acls BOOLEAN NOT NULL,
    ignore_public_acls BOOLEAN NOT NULL,
    block_public_policy BOOLEAN NOT NULL,
    restrict_public_buckets BOOLEAN NOT NULL,
    policy_document TEXT NOT NULL,
    policy_trust BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, name),
    UNIQUE (partition, alias)
);
CREATE INDEX s3_access_points_bucket ON s3_access_points(partition, account_id, region, bucket_name, name);

CREATE TABLE s3_access_point_policy_principals (
    partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, access_point_name TEXT NOT NULL,
    principal TEXT NOT NULL, principal_id TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region, access_point_name, principal),
    FOREIGN KEY (partition, account_id, region, access_point_name)
        REFERENCES s3_access_points(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE s3_access_point_tags (
    partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, access_point_name TEXT NOT NULL,
    key TEXT NOT NULL COLLATE BINARY, value TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region, access_point_name, key),
    FOREIGN KEY (partition, account_id, region, access_point_name)
        REFERENCES s3_access_points(partition, account_id, region, name) ON DELETE CASCADE
);
