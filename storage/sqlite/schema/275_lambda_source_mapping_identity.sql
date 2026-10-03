-- Source uniqueness is enforced transactionally by Lambda using source-specific
-- identities (database/collection, queue/vhost, topic/brokers), not ARN alone.
-- Rebuild descendants before dropping their parents, preserving all retained
-- checkpoints, credentials and placement with foreign keys enabled.

CREATE TABLE lambda_event_source_mappings_replacement (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 function_partition TEXT NOT NULL, function_account TEXT NOT NULL, function_region TEXT NOT NULL,
 function_name TEXT NOT NULL, function_qualifier TEXT NOT NULL,
 event_source_arn TEXT NOT NULL, version INTEGER NOT NULL,
 state TEXT NOT NULL, state_transition_reason TEXT NOT NULL, last_modified TIMESTAMP NOT NULL, transition_at TIMESTAMP NOT NULL,
 batch_size INTEGER NOT NULL, batching_window_seconds INTEGER NOT NULL,
 report_batch_item_failures BOOLEAN NOT NULL,
 maximum_concurrency INTEGER, minimum_pollers INTEGER, maximum_pollers INTEGER, transition_state TEXT NOT NULL DEFAULT '', last_processing_result TEXT, stream_starting_position TEXT, stream_parallelization_factor INTEGER, stream_maximum_retry_attempts INTEGER, stream_maximum_record_age_seconds INTEGER, stream_bisect_batch_on_function_error BOOLEAN, stream_tumbling_window_seconds INTEGER, stream_on_failure TEXT, stream_starting_position_timestamp TIMESTAMP,
 PRIMARY KEY(partition,account,region,uuid)
);
INSERT INTO lambda_event_source_mappings_replacement SELECT * FROM lambda_event_source_mappings;

CREATE TABLE lambda_documentdb_checkpoints_replacement (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 resume_token BLOB NOT NULL,
 start_seconds INTEGER NOT NULL,
 start_increment INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,uuid),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_documentdb_checkpoints_replacement SELECT * FROM lambda_documentdb_checkpoints;

CREATE TABLE lambda_documentdb_mappings_replacement (
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
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_documentdb_mappings_replacement SELECT * FROM lambda_documentdb_mappings;

CREATE TABLE lambda_event_source_filter_encryption_replacement (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    uuid TEXT NOT NULL,
    key_arn TEXT NOT NULL,
    function_arn TEXT NOT NULL,
    content BLOB NOT NULL,
    data_key BLOB NOT NULL,
    PRIMARY KEY (partition, account, region, uuid),
    FOREIGN KEY (partition, account, region, uuid)
        REFERENCES lambda_event_source_mappings_replacement(partition, account, region, uuid) ON DELETE CASCADE
);
INSERT INTO lambda_event_source_filter_encryption_replacement SELECT * FROM lambda_event_source_filter_encryption;

CREATE TABLE lambda_event_source_mapping_filters_replacement (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 position INTEGER NOT NULL, pattern TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,position),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_event_source_mapping_filters_replacement SELECT * FROM lambda_event_source_mapping_filters;

CREATE TABLE lambda_event_source_mapping_metrics_replacement (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 position INTEGER NOT NULL, metric TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,position),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_event_source_mapping_metrics_replacement SELECT * FROM lambda_event_source_mapping_metrics;

CREATE TABLE lambda_event_source_mapping_tags_replacement (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, uuid TEXT NOT NULL,
 key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,key),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_event_source_mapping_tags_replacement SELECT * FROM lambda_event_source_mapping_tags;

CREATE TABLE lambda_kafka_mappings_replacement (
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
 topic_id TEXT NOT NULL, root_ca_secret_arn TEXT NOT NULL DEFAULT '', network_role_arn TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(partition,account,region,uuid),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_kafka_mappings_replacement SELECT * FROM lambda_kafka_mappings;

CREATE TABLE lambda_mq_mappings_replacement (
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
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_event_source_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_mq_mappings_replacement SELECT * FROM lambda_mq_mappings;

CREATE TABLE lambda_kafka_bootstrap_servers_replacement (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 position INTEGER NOT NULL,
 endpoint TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,position),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_kafka_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_kafka_bootstrap_servers_replacement SELECT * FROM lambda_kafka_bootstrap_servers;

CREATE TABLE lambda_kafka_network_components_replacement (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('subnet','security_group')),
 resource_id TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,kind,resource_id),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_kafka_mappings_replacement(partition,account,region,uuid) ON DELETE CASCADE
);
INSERT INTO lambda_kafka_network_components_replacement SELECT * FROM lambda_kafka_network_components;

DROP TABLE lambda_kafka_network_components;
DROP TABLE lambda_kafka_bootstrap_servers;
DROP TABLE lambda_mq_mappings;
DROP TABLE lambda_kafka_mappings;
DROP TABLE lambda_event_source_mapping_tags;
DROP TABLE lambda_event_source_mapping_metrics;
DROP TABLE lambda_event_source_mapping_filters;
DROP TABLE lambda_event_source_filter_encryption;
DROP TABLE lambda_documentdb_mappings;
DROP TABLE lambda_documentdb_checkpoints;
DROP TABLE lambda_event_source_mappings;

ALTER TABLE lambda_event_source_mappings_replacement RENAME TO lambda_event_source_mappings;
ALTER TABLE lambda_documentdb_checkpoints_replacement RENAME TO lambda_documentdb_checkpoints;
ALTER TABLE lambda_documentdb_mappings_replacement RENAME TO lambda_documentdb_mappings;
ALTER TABLE lambda_event_source_filter_encryption_replacement RENAME TO lambda_event_source_filter_encryption;
ALTER TABLE lambda_event_source_mapping_filters_replacement RENAME TO lambda_event_source_mapping_filters;
ALTER TABLE lambda_event_source_mapping_metrics_replacement RENAME TO lambda_event_source_mapping_metrics;
ALTER TABLE lambda_event_source_mapping_tags_replacement RENAME TO lambda_event_source_mapping_tags;
ALTER TABLE lambda_kafka_mappings_replacement RENAME TO lambda_kafka_mappings;
ALTER TABLE lambda_mq_mappings_replacement RENAME TO lambda_mq_mappings;
ALTER TABLE lambda_kafka_bootstrap_servers_replacement RENAME TO lambda_kafka_bootstrap_servers;
ALTER TABLE lambda_kafka_network_components_replacement RENAME TO lambda_kafka_network_components;
CREATE INDEX lambda_event_source_mappings_source ON lambda_event_source_mappings(partition,account,region,event_source_arn,function_partition,function_account,function_region,function_name,function_qualifier);
