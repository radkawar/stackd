ALTER TABLE dynamodb_tables ADD COLUMN replica_group_id TEXT NOT NULL DEFAULT '';
ALTER TABLE dynamodb_tables ADD COLUMN replica_cursor INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dynamodb_tables ADD COLUMN replica_last_source_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
ALTER TABLE dynamodb_tables ADD COLUMN replica_unauthorized_at TIMESTAMP;
ALTER TABLE dynamodb_tables ADD COLUMN replica_settings_pending BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX dynamodb_tables_replica_group ON dynamodb_tables(replica_group_id);

CREATE TABLE dynamodb_mutation_captures (
 version INTEGER PRIMARY KEY AUTOINCREMENT,
 database_id TEXT NOT NULL UNIQUE,
 at TIMESTAMP NOT NULL
);
CREATE TABLE dynamodb_mutation_sources (
 database_id TEXT NOT NULL REFERENCES dynamodb_mutation_captures(database_id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 table_name TEXT NOT NULL,
 physical_name TEXT NOT NULL,
 key_schema BLOB NOT NULL,
 recovery_id TEXT NOT NULL,
 replication_group_id TEXT NOT NULL,
 PRIMARY KEY (database_id, position)
);
CREATE INDEX dynamodb_mutation_sources_group ON dynamodb_mutation_sources(replication_group_id, database_id);
CREATE TABLE dynamodb_mutation_items (
 database_id TEXT NOT NULL,
 source_position INTEGER NOT NULL,
 position INTEGER NOT NULL,
 key_data BLOB NOT NULL,
 before_data BLOB,
 replica_sequence INTEGER NOT NULL,
 PRIMARY KEY (database_id, source_position, position),
 FOREIGN KEY (database_id, source_position) REFERENCES dynamodb_mutation_sources(database_id, position) ON DELETE CASCADE
);

-- Preserve every unresolved native effect. Scalar lookups deliberately fail the
-- migration's NOT NULL constraints if retained recovery ownership is missing.
INSERT INTO dynamodb_mutation_captures (database_id, at)
SELECT database_id, at FROM dynamodb_recovery_captures ORDER BY at, database_id;
INSERT INTO dynamodb_mutation_sources (
 database_id, position, partition, account_id, region, table_name, physical_name,
 key_schema, recovery_id, replication_group_id
)
SELECT i.database_id, MIN(i.position),
 (SELECT partition FROM dynamodb_recoveries WHERE id = i.recovery_id),
 (SELECT account_id FROM dynamodb_recoveries WHERE id = i.recovery_id),
 (SELECT region FROM dynamodb_recoveries WHERE id = i.recovery_id),
 (SELECT table_name FROM dynamodb_recoveries WHERE id = i.recovery_id),
 (SELECT source_physical_name FROM dynamodb_recoveries WHERE id = i.recovery_id),
 (SELECT key_schema FROM dynamodb_recoveries WHERE id = i.recovery_id),
 i.recovery_id, ''
FROM dynamodb_recovery_capture_items i GROUP BY i.database_id, i.recovery_id;
INSERT INTO dynamodb_mutation_items (
 database_id, source_position, position, key_data, before_data, replica_sequence
)
SELECT i.database_id, s.position, i.position, i.key_data, NULL, 0
FROM dynamodb_recovery_capture_items i
JOIN dynamodb_mutation_sources s ON s.database_id = i.database_id AND s.recovery_id = i.recovery_id;
DROP TABLE dynamodb_recovery_capture_items;
DROP TABLE dynamodb_recovery_captures;

CREATE TABLE dynamodb_replica_changes (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 group_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 at TIMESTAMP NOT NULL,
 origin_partition TEXT NOT NULL,
 origin_account_id TEXT NOT NULL,
 origin_region TEXT NOT NULL,
 origin_table_name TEXT NOT NULL,
 origin_physical_name TEXT NOT NULL,
 key_id TEXT NOT NULL,
 key_data BLOB NOT NULL,
 item_data BLOB
);
CREATE INDEX dynamodb_replica_changes_group ON dynamodb_replica_changes(group_id, sequence);
CREATE TABLE dynamodb_replica_versions (
 physical_name TEXT NOT NULL,
 key_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 PRIMARY KEY (physical_name, key_id)
);
CREATE TABLE dynamodb_replica_bootstraps (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 table_name TEXT NOT NULL,
 source_partition TEXT NOT NULL,
 source_account_id TEXT NOT NULL,
 source_region TEXT NOT NULL,
 source_table_name TEXT NOT NULL,
 source_database_id TEXT NOT NULL,
 source_physical_name TEXT NOT NULL,
 snapshot_physical_name TEXT NOT NULL,
 key_schema BLOB NOT NULL,
 attribute_definitions BLOB NOT NULL,
 ready BOOLEAN NOT NULL,
 copied BOOLEAN NOT NULL,
 cursor INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, table_name)
);
CREATE INDEX dynamodb_replica_bootstraps_source ON dynamodb_replica_bootstraps(source_database_id);
CREATE TABLE dynamodb_replica_pinned_versions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 table_name TEXT NOT NULL,
 key_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, table_name, key_id),
 FOREIGN KEY (partition, account_id, region, table_name) REFERENCES dynamodb_replica_bootstraps(partition, account_id, region, table_name) ON DELETE CASCADE
);
