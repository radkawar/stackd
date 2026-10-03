-- Mappings outlive both functions and aliases: deliberately no function foreign key.
CREATE TABLE lambda_event_source_mappings (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 function_partition TEXT NOT NULL, function_account TEXT NOT NULL, function_region TEXT NOT NULL,
 function_name TEXT NOT NULL, function_qualifier TEXT NOT NULL,
 event_source_arn TEXT NOT NULL, version INTEGER NOT NULL,
 state TEXT NOT NULL, state_transition_reason TEXT NOT NULL, last_processing_result TEXT NOT NULL,
 last_modified TIMESTAMP NOT NULL, transition_at TIMESTAMP NOT NULL,
 batch_size INTEGER NOT NULL, batching_window_seconds INTEGER NOT NULL,
 report_batch_item_failures BOOLEAN NOT NULL,
 maximum_concurrency INTEGER, minimum_pollers INTEGER, maximum_pollers INTEGER,
 PRIMARY KEY(partition,account,region,uuid),
 UNIQUE(partition,account,region,event_source_arn,function_partition,function_account,function_region,function_name,function_qualifier)
);
CREATE TABLE lambda_event_source_mapping_filters (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 position INTEGER NOT NULL, pattern TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,position),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
CREATE TABLE lambda_event_source_mapping_metrics (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 position INTEGER NOT NULL, metric TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,position),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
CREATE TABLE lambda_event_source_mapping_tags (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,key),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
