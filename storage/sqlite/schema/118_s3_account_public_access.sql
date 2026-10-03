-- Account settings are partition-wide and retained independently of buckets.
CREATE TABLE s3_account_public_access (
    partition TEXT NOT NULL, account_id TEXT NOT NULL,
    block_public_acls BOOLEAN NOT NULL,
    ignore_public_acls BOOLEAN NOT NULL,
    block_public_policy BOOLEAN NOT NULL,
    restrict_public_buckets BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id)
);
