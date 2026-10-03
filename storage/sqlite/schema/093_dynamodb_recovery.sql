ALTER TABLE dynamodb_tables ADD COLUMN recovery_id TEXT NOT NULL DEFAULT '';
ALTER TABLE dynamodb_tables ADD COLUMN restore_recovery_id TEXT NOT NULL DEFAULT '';
ALTER TABLE dynamodb_tables ADD COLUMN restore_recovery_sequence INTEGER NOT NULL DEFAULT 0;

-- An interval owns its schema and private native baseline independently of the
-- source table, which may be disabled or deleted while a restore is pending.
CREATE TABLE dynamodb_recoveries (
 id TEXT PRIMARY KEY NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 table_name TEXT NOT NULL,
 database_id TEXT NOT NULL,
 source_physical_name TEXT NOT NULL,
 physical_name TEXT NOT NULL,
 key_schema BLOB NOT NULL,
 attribute_definitions BLOB NOT NULL,
 recovery_period_in_days INTEGER NOT NULL,
 earliest_at TIMESTAMP NOT NULL,
 snapshot_at TIMESTAMP,
 compact_through TIMESTAMP
);
CREATE INDEX dynamodb_recoveries_database ON dynamodb_recoveries(database_id, id);

CREATE TABLE dynamodb_recovery_changes (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 recovery_id TEXT NOT NULL REFERENCES dynamodb_recoveries(id) ON DELETE CASCADE,
 at TIMESTAMP NOT NULL,
 key_data BLOB NOT NULL,
 item_data BLOB
);
CREATE INDEX dynamodb_recovery_changes_sequence ON dynamodb_recovery_changes(recovery_id, sequence);
CREATE INDEX dynamodb_recovery_changes_time ON dynamodb_recovery_changes(recovery_id, at);

CREATE TABLE dynamodb_recovery_captures (
 database_id TEXT PRIMARY KEY NOT NULL,
 at TIMESTAMP NOT NULL
);
CREATE TABLE dynamodb_recovery_capture_items (
 database_id TEXT NOT NULL REFERENCES dynamodb_recovery_captures(database_id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 recovery_id TEXT NOT NULL,
 key_data BLOB NOT NULL,
 PRIMARY KEY (database_id, position)
);
