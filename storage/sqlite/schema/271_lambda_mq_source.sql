CREATE TABLE lambda_mq_mappings (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 queue_name TEXT NOT NULL,
 virtual_host TEXT NOT NULL,
 secret_arn TEXT NOT NULL,
 broker_id TEXT NOT NULL,
 engine TEXT NOT NULL,
 batching_window_ns INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,uuid),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
