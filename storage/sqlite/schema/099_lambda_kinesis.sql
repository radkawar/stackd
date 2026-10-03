-- Both DynamoDB and Kinesis mappings retain work in the shared stream engine.
ALTER TABLE lambda_event_source_mappings RENAME COLUMN dynamodb_starting_position TO stream_starting_position;
ALTER TABLE lambda_event_source_mappings RENAME COLUMN dynamodb_parallelization_factor TO stream_parallelization_factor;
ALTER TABLE lambda_event_source_mappings RENAME COLUMN dynamodb_maximum_retry_attempts TO stream_maximum_retry_attempts;
ALTER TABLE lambda_event_source_mappings RENAME COLUMN dynamodb_maximum_record_age_seconds TO stream_maximum_record_age_seconds;
ALTER TABLE lambda_event_source_mappings RENAME COLUMN dynamodb_bisect_batch_on_function_error TO stream_bisect_batch_on_function_error;
ALTER TABLE lambda_event_source_mappings RENAME COLUMN dynamodb_tumbling_window_seconds TO stream_tumbling_window_seconds;
ALTER TABLE lambda_event_source_mappings RENAME COLUMN dynamodb_on_failure TO stream_on_failure;
ALTER TABLE lambda_event_source_mappings ADD COLUMN stream_starting_position_timestamp TIMESTAMP;

-- Renames preserve checkpoints, queued work, and accepted failure destinations.
ALTER TABLE lambda_dynamodb_shards RENAME TO lambda_stream_shards;
ALTER TABLE lambda_dynamodb_lanes RENAME TO lambda_stream_lanes;
ALTER TABLE lambda_dynamodb_records RENAME TO lambda_stream_records;
ALTER TABLE lambda_dynamodb_batches RENAME TO lambda_stream_batches;
ALTER TABLE lambda_dynamodb_failures RENAME TO lambda_stream_failures;
ALTER TABLE lambda_stream_shards ADD COLUMN adjacent_parent_id TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_stream_shards ADD COLUMN starting_position_timestamp TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
-- Existing DynamoDB shards have a 24-hour retention period; preserve duration precision.
ALTER TABLE lambda_stream_shards ADD COLUMN retention_nanoseconds INTEGER NOT NULL DEFAULT 86400000000000;
