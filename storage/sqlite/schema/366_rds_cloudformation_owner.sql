ALTER TABLE rds_database ADD COLUMN resource_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_database ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_database ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_database ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
UPDATE rds_database SET resource_id = runtime_id;

ALTER TABLE rds_snapshot ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_snapshot ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_snapshot ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';

ALTER TABLE rds_parameter_group ADD COLUMN resource_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_parameter_group ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_parameter_group ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_parameter_group ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
UPDATE rds_parameter_group SET resource_id = lower(hex(randomblob(16)));

ALTER TABLE rds_subnet_group ADD COLUMN resource_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_subnet_group ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_subnet_group ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rds_subnet_group ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
UPDATE rds_subnet_group SET resource_id = lower(hex(randomblob(16)));
