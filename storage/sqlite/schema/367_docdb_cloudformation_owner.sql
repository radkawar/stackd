ALTER TABLE docdb_cluster ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE docdb_cluster ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE docdb_cluster ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';

ALTER TABLE docdb_instance ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE docdb_instance ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE docdb_instance ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';

ALTER TABLE docdb_snapshot ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE docdb_snapshot ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE docdb_snapshot ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
