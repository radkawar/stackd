-- Backup item data remains in private tables in the retained native database.
CREATE TABLE dynamodb_backups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 table_name TEXT NOT NULL,
 backup_id TEXT NOT NULL,
 backup_arn TEXT NOT NULL,
 database_id TEXT NOT NULL,
 physical_name TEXT NOT NULL,
 source_physical_name TEXT NOT NULL,
 backup_name TEXT NOT NULL,
 backup_created_at TIMESTAMP NOT NULL,
 backup_status TEXT NOT NULL,
 backup_size_bytes INTEGER,
 source_table_id TEXT NOT NULL,
 source_created_at TIMESTAMP NOT NULL,
 source_billing_mode TEXT,
 source_item_count INTEGER,
 source_size_bytes INTEGER,
 attribute_definitions BLOB NOT NULL,
 source_key_schema BLOB NOT NULL,
 source_provisioned_throughput BLOB NOT NULL,
 source_on_demand_throughput BLOB NOT NULL,
 source_global_secondary_indexes BLOB NOT NULL,
 source_local_secondary_indexes BLOB NOT NULL,
 source_stream_description BLOB NOT NULL,
 source_ttl_attribute_name TEXT,
 source_ttl_status TEXT,
 PRIMARY KEY (partition, account_id, region, table_name, backup_id)
);
CREATE INDEX dynamodb_backups_scope_arn ON dynamodb_backups(partition, account_id, region, backup_arn);
CREATE INDEX dynamodb_backups_status_database ON dynamodb_backups(backup_status, database_id);
