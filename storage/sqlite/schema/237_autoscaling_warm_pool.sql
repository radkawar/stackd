ALTER TABLE asg_groups ADD COLUMN has_data_warm_pool_configuration BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE asg_groups ADD COLUMN data_warm_pool_configuration_min_size INTEGER;
ALTER TABLE asg_groups ADD COLUMN data_warm_pool_configuration_max_group_prepared_capacity INTEGER;
ALTER TABLE asg_groups ADD COLUMN data_warm_pool_configuration_pool_state TEXT;
ALTER TABLE asg_groups ADD COLUMN data_warm_pool_configuration_status TEXT;
ALTER TABLE asg_groups ADD COLUMN has_data_warm_pool_configuration_instance_reuse_policy BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE asg_groups ADD COLUMN data_warm_pool_configuration_instance_reuse_policy_reuse_on_scale_in BOOLEAN;
ALTER TABLE asg_activities ADD COLUMN warm_pool_state TEXT NOT NULL DEFAULT '';
