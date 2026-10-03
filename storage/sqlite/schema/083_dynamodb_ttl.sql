CREATE TABLE dynamodb_ttl_deletions (
 database_id TEXT NOT NULL PRIMARY KEY,
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 table_name TEXT NOT NULL, physical_name TEXT NOT NULL,
 stream_arn TEXT NOT NULL, native_arn TEXT NOT NULL,
 keys_data BLOB NOT NULL, attribute_name TEXT NOT NULL, expiry TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 FOREIGN KEY(database_id) REFERENCES dynamodb_databases(id) ON DELETE CASCADE
);
