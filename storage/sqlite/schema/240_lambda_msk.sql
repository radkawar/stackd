CREATE TABLE lambda_kafka_mappings (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 topic TEXT NOT NULL,
 consumer_group_id TEXT NOT NULL,
 starting_position TEXT NOT NULL,
 starting_position_timestamp TIMESTAMP NOT NULL,
 batching_window_ns INTEGER NOT NULL,
 authentication TEXT NOT NULL,
 secret_arn TEXT NOT NULL,
 cluster_id TEXT NOT NULL,
 topic_id TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
