CREATE TABLE dynamodb_kinesis_destinations (
 id TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 table_name TEXT NOT NULL,
 physical_name TEXT NOT NULL,
 stream_arn TEXT NOT NULL,
 status TEXT NOT NULL,
 description TEXT NOT NULL,
 precision TEXT NOT NULL,
 pending_precision TEXT NOT NULL,
 admission_failure TEXT NOT NULL,
 superseded BOOLEAN NOT NULL,
 due TIMESTAMP NOT NULL,
 capture_until TIMESTAMP NOT NULL
);
CREATE INDEX dynamodb_kinesis_destinations_source ON dynamodb_kinesis_destinations(physical_name, superseded);
CREATE INDEX dynamodb_kinesis_destinations_due ON dynamodb_kinesis_destinations(due);
CREATE TABLE dynamodb_kinesis_deliveries (
 id TEXT PRIMARY KEY,
 destination_id TEXT NOT NULL REFERENCES dynamodb_kinesis_destinations(id),
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 table_name TEXT NOT NULL,
 stream_arn TEXT NOT NULL,
 partition_key TEXT NOT NULL,
 data BLOB NOT NULL,
 parent_event_id TEXT NOT NULL,
 due TIMESTAMP NOT NULL,
 attempts INTEGER NOT NULL,
 last_error TEXT NOT NULL
);
CREATE INDEX dynamodb_kinesis_deliveries_due ON dynamodb_kinesis_deliveries(due,id);
ALTER TABLE dynamodb_mutation_captures ADD COLUMN parent_event_id TEXT NOT NULL DEFAULT '';
ALTER TABLE dynamodb_mutation_captures ADD COLUMN transactional BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE dynamodb_mutation_captures ADD COLUMN ttl BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE dynamodb_mutation_kinesis_consumers (
 database_id TEXT NOT NULL,
 source_position INTEGER NOT NULL,
 destination_id TEXT NOT NULL,
 stream_arn TEXT NOT NULL,
 precision TEXT NOT NULL,
 capture_until TIMESTAMP NOT NULL,
 PRIMARY KEY(database_id,source_position,destination_id),
 FOREIGN KEY(database_id,source_position) REFERENCES dynamodb_mutation_sources(database_id,position) ON DELETE CASCADE
);
