CREATE TABLE lambda_documentdb_mappings (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 database_name TEXT NOT NULL,
 collection_name TEXT NOT NULL,
 full_document TEXT NOT NULL,
 secret_arn TEXT NOT NULL,
 starting_position TEXT NOT NULL,
 starting_position_timestamp TIMESTAMP NOT NULL,
 batching_window_ns INTEGER NOT NULL,
 incarnation TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
CREATE TABLE lambda_documentdb_checkpoints (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 resume_token BLOB NOT NULL,
 start_seconds INTEGER NOT NULL,
 start_increment INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,uuid),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
