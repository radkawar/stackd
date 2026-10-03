CREATE TABLE dynamodb_streams (
 stream_arn TEXT NOT NULL PRIMARY KEY,
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 table_name TEXT NOT NULL, database_id TEXT NOT NULL, physical_name TEXT NOT NULL,
 native_arn TEXT NOT NULL, label TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, closed_at TIMESTAMP NOT NULL,
 view_type TEXT NOT NULL, key_schema BLOB NOT NULL
);
CREATE INDEX dynamodb_streams_database ON dynamodb_streams(database_id);
CREATE TABLE dynamodb_stream_shards (
 stream_arn TEXT NOT NULL, shard_id TEXT NOT NULL, parent_id TEXT NOT NULL,
 start_sequence TEXT NOT NULL, end_sequence TEXT NOT NULL,
 checkpoint TEXT NOT NULL, trimmed_through TEXT NOT NULL, drained BOOLEAN NOT NULL,
 PRIMARY KEY(stream_arn, shard_id),
 FOREIGN KEY(stream_arn) REFERENCES dynamodb_streams(stream_arn) ON DELETE CASCADE
);
CREATE TABLE dynamodb_stream_entries (
 stream_arn TEXT NOT NULL, shard_id TEXT NOT NULL, sequence TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 event_id TEXT, event_name TEXT, event_source TEXT, event_version TEXT, aws_region TEXT,
 identity_type TEXT, identity_principal TEXT,
 size_bytes INTEGER, view_type TEXT,
 keys_data BLOB NOT NULL, new_image BLOB NOT NULL, old_image BLOB NOT NULL,
 PRIMARY KEY(stream_arn, shard_id, sequence),
 FOREIGN KEY(stream_arn) REFERENCES dynamodb_streams(stream_arn) ON DELETE CASCADE
);
CREATE INDEX dynamodb_stream_entries_sequence ON dynamodb_stream_entries(
 stream_arn, shard_id, length(ltrim(sequence, '0')), ltrim(sequence, '0'), sequence, size_bytes
);
CREATE INDEX dynamodb_stream_entries_expiry ON dynamodb_stream_entries(stream_arn, created_at, shard_id);
CREATE INDEX dynamodb_stream_entries_shard_expiry ON dynamodb_stream_entries(stream_arn, shard_id, created_at, sequence);
