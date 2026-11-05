CREATE TABLE s3tables_buckets (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 arn TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, id TEXT NOT NULL, created DATETIME NOT NULL,
 UNIQUE(partition,account_id,region,name)
);
CREATE TABLE s3tables_namespaces (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 bucket_arn TEXT NOT NULL, name TEXT NOT NULL, id TEXT NOT NULL, created DATETIME NOT NULL,
 PRIMARY KEY(partition,account_id,region,bucket_arn,name),
 FOREIGN KEY(bucket_arn) REFERENCES s3tables_buckets(arn)
);
-- Deleted rows are private ownership tombstones and durable physical cleanup
-- intents. They survive bucket deletion and never appear in public catalog lists.
CREATE TABLE s3tables_tables (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 arn TEXT NOT NULL PRIMARY KEY, bucket_arn TEXT NOT NULL, namespace TEXT NOT NULL, name TEXT NOT NULL,
 id TEXT NOT NULL, version_token TEXT NOT NULL, warehouse TEXT NOT NULL UNIQUE,
 metadata_location TEXT NOT NULL, created DATETIME NOT NULL, modified DATETIME NOT NULL,
 deleted BOOLEAN NOT NULL, purged BOOLEAN NOT NULL, cleanup_at DATETIME NOT NULL
);
CREATE UNIQUE INDEX s3tables_current_table ON s3tables_tables(partition,account_id,region,bucket_arn,namespace,name) WHERE deleted=0;
CREATE INDEX s3tables_pending_cleanup ON s3tables_tables(cleanup_at,arn) WHERE deleted=1 AND purged=0;
