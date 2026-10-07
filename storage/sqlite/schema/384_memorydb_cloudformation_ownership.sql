-- Private CloudFormation incarnation claims for native MemoryDB rows. Public
-- tags never carry ownership; empty is the unowned direct-API scope.
ALTER TABLE memorydb_clusters ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE memorydb_users ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE memorydb_acls ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE memorydb_parameter_groups ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE memorydb_subnet_groups ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE memorydb_snapshots ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
