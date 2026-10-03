-- DynamoDB control metadata only; item and transaction data belongs to the external engine.
CREATE TABLE dynamodb_databases (
 id TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 retiring BOOLEAN NOT NULL,
 PRIMARY KEY (id)
);
CREATE TABLE dynamodb_tables (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 database_id TEXT NOT NULL,
 physical_name TEXT NOT NULL,
 archival_summary BLOB NOT NULL,
 attribute_definitions BLOB NOT NULL,
 billing_mode_summary BLOB NOT NULL,
 creation_date_time TIMESTAMP,
 deletion_protection_enabled BOOLEAN,
 global_secondary_indexes BLOB NOT NULL,
 global_table_settings_replication_mode TEXT,
 global_table_version TEXT,
 global_table_witnesses BLOB NOT NULL,
 item_count INTEGER,
 key_schema BLOB NOT NULL,
 latest_stream_arn TEXT,
 latest_stream_label TEXT,
 local_secondary_indexes BLOB NOT NULL,
 multi_region_consistency TEXT,
 on_demand_throughput BLOB NOT NULL,
 provisioned_throughput BLOB NOT NULL,
 replicas BLOB NOT NULL,
 restore_summary BLOB NOT NULL,
 sse_description BLOB NOT NULL,
 stream_specification BLOB NOT NULL,
 table_arn TEXT,
 table_class_summary BLOB NOT NULL,
 table_id TEXT,
 table_name TEXT,
 table_size_bytes INTEGER,
 table_status TEXT,
 vector_indexes BLOB NOT NULL,
 warm_throughput BLOB NOT NULL,
 ttl_attribute_name TEXT,
 ttl_status TEXT,
 ttl_changed_at TIMESTAMP NOT NULL,
 ttl_next_scan TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);
CREATE TABLE dynamodb_pending_creates (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 attribute_definitions BLOB NOT NULL,
 billing_mode TEXT,
 deletion_protection_enabled BOOLEAN,
 global_secondary_indexes BLOB NOT NULL,
 global_table_settings_replication_mode TEXT,
 global_table_source_arn TEXT,
 key_schema BLOB NOT NULL,
 local_secondary_indexes BLOB NOT NULL,
 on_demand_throughput BLOB NOT NULL,
 provisioned_throughput BLOB NOT NULL,
 resource_policy TEXT,
 sse_specification BLOB NOT NULL,
 stream_specification BLOB NOT NULL,
 table_class TEXT,
 table_name TEXT,
 vector_indexes BLOB NOT NULL,
 warm_throughput BLOB NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, name),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES dynamodb_tables(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE TABLE dynamodb_pending_updates (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 attribute_definitions BLOB NOT NULL,
 billing_mode TEXT,
 deletion_protection_enabled BOOLEAN,
 global_secondary_index_updates BLOB NOT NULL,
 global_table_settings_replication_mode TEXT,
 global_table_witness_updates BLOB NOT NULL,
 multi_region_consistency TEXT,
 on_demand_throughput BLOB NOT NULL,
 provisioned_throughput BLOB NOT NULL,
 replica_updates BLOB NOT NULL,
 sse_specification BLOB NOT NULL,
 stream_specification BLOB NOT NULL,
 table_class TEXT,
 table_name TEXT,
 vector_index_updates BLOB NOT NULL,
 warm_throughput BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, name),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES dynamodb_tables(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE TABLE dynamodb_tag_sets (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);
CREATE TABLE dynamodb_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, name, position),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES dynamodb_tag_sets(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE TABLE dynamodb_create_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, name, position),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES dynamodb_pending_creates(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE TABLE dynamodb_policies (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_arn TEXT NOT NULL,
 document TEXT NOT NULL,
 revision TEXT NOT NULL,
 principals_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_arn)
);
CREATE TABLE dynamodb_policy_principals (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, resource_arn TEXT NOT NULL,
 principal_arn TEXT NOT NULL, principal_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_arn, principal_arn),
 FOREIGN KEY (partition, account_id, region, resource_arn) REFERENCES dynamodb_policies(partition, account_id, region, resource_arn) ON DELETE CASCADE
);
CREATE UNIQUE INDEX dynamodb_databases_active_scope ON dynamodb_databases(partition, account_id, region) WHERE retiring = 0;
CREATE INDEX dynamodb_tables_pending ON dynamodb_tables(partition, account_id, region, name) WHERE table_status IN ('CREATING', 'UPDATING', 'DELETING');
