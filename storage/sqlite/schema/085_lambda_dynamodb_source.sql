-- Source checkpoints advance only with retained records in the same transaction.
CREATE TABLE lambda_dynamodb_shards (
 mapping_arn TEXT NOT NULL, shard_id TEXT NOT NULL,
 parent_id TEXT NOT NULL, checkpoint TEXT NOT NULL,
 read_complete BOOLEAN NOT NULL, complete BOOLEAN NOT NULL,
 PRIMARY KEY(mapping_arn,shard_id)
);
CREATE TABLE lambda_dynamodb_lanes (
 mapping_arn TEXT NOT NULL, shard_id TEXT NOT NULL, lane INTEGER NOT NULL,
 window_start TIMESTAMP NOT NULL, window_end TIMESTAMP NOT NULL,
 window_state BLOB NOT NULL, window_final BOOLEAN NOT NULL, window_early BOOLEAN NOT NULL,
 PRIMARY KEY(mapping_arn,shard_id,lane),
 FOREIGN KEY(mapping_arn,shard_id) REFERENCES lambda_dynamodb_shards(mapping_arn,shard_id) ON DELETE CASCADE
);
CREATE TABLE lambda_dynamodb_records (
 mapping_arn TEXT NOT NULL, shard_id TEXT NOT NULL, lane INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 record_id TEXT NOT NULL, sequence_number TEXT NOT NULL, item_key TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, captured_at TIMESTAMP NOT NULL, payload BLOB NOT NULL,
 PRIMARY KEY(mapping_arn,shard_id,lane,ordinal),
 FOREIGN KEY(mapping_arn,shard_id,lane) REFERENCES lambda_dynamodb_lanes(mapping_arn,shard_id,lane) ON DELETE CASCADE
);
CREATE TABLE lambda_dynamodb_batches (
 mapping_arn TEXT NOT NULL, shard_id TEXT NOT NULL, lane INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 record_count INTEGER NOT NULL, attempts INTEGER NOT NULL,
 due TIMESTAMP NOT NULL,
 last_event_id TEXT NOT NULL, last_request_id TEXT NOT NULL, executed_version TEXT NOT NULL, function_error TEXT NOT NULL, invoke_count INTEGER NOT NULL,
 PRIMARY KEY(mapping_arn,shard_id,lane,ordinal),
 FOREIGN KEY(mapping_arn,shard_id,lane) REFERENCES lambda_dynamodb_lanes(mapping_arn,shard_id,lane) ON DELETE CASCADE
);
-- No mapping FK: accepted destination work survives control/function deletion.
CREATE TABLE lambda_dynamodb_failures (
 id TEXT PRIMARY KEY,
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, mapping_uuid TEXT NOT NULL,
 function_name TEXT NOT NULL, function_qualifier TEXT NOT NULL, role_arn TEXT NOT NULL, destination_arn TEXT NOT NULL,
 shard_id TEXT NOT NULL, record_count INTEGER NOT NULL, created_at TIMESTAMP NOT NULL, parent_event_id TEXT NOT NULL, payload BLOB NOT NULL
);
