-- Private CloudFormation incarnation claims for native ElastiCache rows. Public
-- tags never carry ownership; empty is the unowned direct-API scope.
ALTER TABLE elasticache_cluster ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE elasticache_user ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE elasticache_user_group ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE elasticache_parameter_group ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE elasticache_subnet_group ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
