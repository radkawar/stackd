-- EC2 Auto Scaling authoritative configuration and durable work. Public optional
-- fields remain nullable; ordered typed children preserve collection presence.
-- Activity history deliberately has no group foreign key: deletion and name reuse
-- must not destroy historical incarnations or frozen launch recovery intent.
CREATE TABLE asg_groups (
 group_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 native_id TEXT NOT NULL,
 origin_event_id TEXT NOT NULL,
 deleting BOOLEAN NOT NULL,
 reconcile_at TIMESTAMP,
 reconcile_cause TEXT NOT NULL,
 pending_instance_warmup INTEGER,
 metric_at TIMESTAMP,
 version BLOB NOT NULL,
 data_auto_scaling_group_arn TEXT,
 data_auto_scaling_group_name TEXT,
 has_data_availability_zone_distribution BOOLEAN NOT NULL,
 data_availability_zone_distribution_capacity_distribution_strategy TEXT,
 has_data_availability_zone_ids BOOLEAN NOT NULL,
 has_data_availability_zones BOOLEAN NOT NULL,
 data_capacity_rebalance BOOLEAN,
 has_data_capacity_reservation_specification BOOLEAN NOT NULL,
 data_capacity_reservation_specification_capacity_reservation_preference TEXT,
 has_data_capacity_reservation_specification_capacity_reservation_target BOOLEAN NOT NULL,
 has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_ids BOOLEAN NOT NULL,
 has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_resource_group_arns BOOLEAN NOT NULL,
 data_context TEXT,
 data_created_time TIMESTAMP,
 data_default_cooldown INTEGER,
 data_default_instance_warmup INTEGER,
 data_deletion_protection TEXT,
 data_desired_capacity INTEGER,
 data_desired_capacity_type TEXT,
 has_data_enabled_metrics BOOLEAN NOT NULL,
 data_health_check_grace_period INTEGER,
 data_health_check_type TEXT,
 has_data_instance_lifecycle_policy BOOLEAN NOT NULL,
 has_data_instance_lifecycle_policy_retention_triggers BOOLEAN NOT NULL,
 data_instance_lifecycle_policy_retention_triggers_terminate_hook_abandon TEXT,
 data_launch_configuration_name TEXT,
 has_data_launch_template BOOLEAN NOT NULL,
 data_launch_template_launch_template_id TEXT,
 data_launch_template_launch_template_name TEXT,
 data_launch_template_version TEXT,
 has_data_load_balancer_names BOOLEAN NOT NULL,
 data_max_instance_lifetime INTEGER,
 data_max_size INTEGER,
 data_min_size INTEGER,
 data_new_instances_protected_from_scale_in BOOLEAN,
 data_placement_group TEXT,
 data_predicted_capacity INTEGER,
 data_service_linked_role_arn TEXT,
 data_status TEXT,
 has_data_suspended_processes BOOLEAN NOT NULL,
 has_data_tags BOOLEAN NOT NULL,
 has_data_target_group_arns BOOLEAN NOT NULL,
 has_data_termination_policies BOOLEAN NOT NULL,
 has_data_traffic_sources BOOLEAN NOT NULL,
 data_vpc_zone_identifier TEXT,
 data_warm_pool_size INTEGER,
 UNIQUE(partition, account_id, region, name)
);
CREATE TABLE asg_groups_availability_zone_ids (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_availability_zones (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_capacity_reservation_ids (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_capacity_reservation_resource_group_arns (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_enabled_metrics (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_granularity TEXT,
 item_metric TEXT,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_load_balancer_names (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_suspended_processes (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_process_name TEXT,
 item_suspension_reason TEXT,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_tags (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_key TEXT,
 item_propagate_at_launch BOOLEAN,
 item_resource_id TEXT,
 item_resource_type TEXT,
 item_value TEXT,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_target_group_arns (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_termination_policies (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_groups_traffic_sources (
 group_pk INTEGER NOT NULL REFERENCES asg_groups(group_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_identifier TEXT,
 item_type TEXT,
 PRIMARY KEY(group_pk, position)
);
CREATE TABLE asg_instances (
 instance_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 group_name TEXT NOT NULL,
 group_id TEXT NOT NULL,
 joined_at TIMESTAMP,
 in_service_at TIMESTAMP,
 warm_until TIMESTAMP,
 activity_id TEXT NOT NULL,
 termination_requested BOOLEAN NOT NULL,
 detach_requested BOOLEAN NOT NULL,
 health_check_grace_ignored BOOLEAN NOT NULL,
 data_availability_zone TEXT,
 data_availability_zone_id TEXT,
 data_health_status TEXT,
 data_image_id TEXT,
 data_instance_id TEXT,
 data_instance_type TEXT,
 data_launch_configuration_name TEXT,
 has_data_launch_template BOOLEAN NOT NULL,
 data_launch_template_launch_template_id TEXT,
 data_launch_template_launch_template_name TEXT,
 data_launch_template_version TEXT,
 data_lifecycle_state TEXT,
 data_protected_from_scale_in BOOLEAN,
 data_weighted_capacity TEXT,
 UNIQUE(partition, account_id, region, instance_id)
);
CREATE TABLE asg_activities (
 activity_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 activity_id TEXT NOT NULL,
 group_partition TEXT NOT NULL,
 group_account_id TEXT NOT NULL,
 group_region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 group_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 subnet_id TEXT NOT NULL,
 origin_event_id TEXT NOT NULL,
 retry_at TIMESTAMP,
 instance_warmup INTEGER,
 has_launch_tags BOOLEAN NOT NULL,
 protected_from_scale_in BOOLEAN NOT NULL,
 data_activity_id TEXT,
 data_auto_scaling_group_arn TEXT,
 data_auto_scaling_group_name TEXT,
 data_auto_scaling_group_state TEXT,
 data_cause TEXT,
 data_description TEXT,
 data_details TEXT,
 data_end_time TIMESTAMP,
 data_progress INTEGER,
 data_start_time TIMESTAMP,
 data_status_code TEXT,
 data_status_message TEXT,
 launch_template_launch_template_id TEXT,
 launch_template_launch_template_name TEXT,
 launch_template_version TEXT,
 UNIQUE(partition, account_id, region, activity_id)
);
CREATE TABLE asg_activity_launch_tags (
 activity_pk INTEGER NOT NULL REFERENCES asg_activities(activity_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 resource_id TEXT,
 resource_type TEXT,
 propagate_at_launch BOOLEAN,
 PRIMARY KEY(activity_pk, position)
);
CREATE TABLE asg_policies (
 policy_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 name TEXT NOT NULL,
 group_id TEXT NOT NULL,
 last_scale_at TIMESTAMP,
 data_adjustment_type TEXT,
 has_data_alarms BOOLEAN NOT NULL,
 data_auto_scaling_group_name TEXT,
 data_cooldown INTEGER,
 data_enabled BOOLEAN,
 data_estimated_instance_warmup INTEGER,
 data_metric_aggregation_type TEXT,
 data_min_adjustment_magnitude INTEGER,
 data_min_adjustment_step INTEGER,
 data_policy_arn TEXT,
 data_policy_name TEXT,
 data_policy_type TEXT,
 data_scaling_adjustment INTEGER,
 has_data_step_adjustments BOOLEAN NOT NULL,
 has_data_target_tracking_configuration BOOLEAN NOT NULL,
 has_data_target_tracking_configuration_customized_metric_specification BOOLEAN NOT NULL,
 has_data_target_tracking_configuration_customized_metric_specification_dimensions BOOLEAN NOT NULL,
 data_target_tracking_configuration_customized_metric_specification_metric_name TEXT,
 has_data_target_tracking_configuration_customized_metric_specification_metrics BOOLEAN NOT NULL,
 data_target_tracking_configuration_customized_metric_specification_namespace TEXT,
 data_target_tracking_configuration_customized_metric_specification_period INTEGER,
 data_target_tracking_configuration_customized_metric_specification_statistic TEXT,
 data_target_tracking_configuration_customized_metric_specification_unit TEXT,
 data_target_tracking_configuration_disable_scale_in BOOLEAN,
 has_data_target_tracking_configuration_predefined_metric_specification BOOLEAN NOT NULL,
 data_target_tracking_configuration_predefined_metric_specification_predefined_metric_type TEXT,
 data_target_tracking_configuration_predefined_metric_specification_resource_label TEXT,
 data_target_tracking_configuration_target_value REAL,
 UNIQUE(partition, account_id, region, group_name, name)
);
CREATE TABLE asg_policies_alarms (
 policy_pk INTEGER NOT NULL REFERENCES asg_policies(policy_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_alarm_arn TEXT,
 item_alarm_name TEXT,
 PRIMARY KEY(policy_pk, position)
);
CREATE TABLE asg_policies_step_adjustments (
 policy_pk INTEGER NOT NULL REFERENCES asg_policies(policy_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_metric_interval_lower_bound REAL,
 item_metric_interval_upper_bound REAL,
 item_scaling_adjustment INTEGER,
 PRIMARY KEY(policy_pk, position)
);
CREATE TABLE asg_policies_dimensions (
 policy_pk INTEGER NOT NULL REFERENCES asg_policies(policy_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_name TEXT,
 item_value TEXT,
 PRIMARY KEY(policy_pk, position)
);
CREATE TABLE asg_policies_metrics (
 item_pk INTEGER PRIMARY KEY,
 policy_pk INTEGER NOT NULL REFERENCES asg_policies(policy_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_expression TEXT,
 item_id TEXT,
 item_label TEXT,
 has_item_metric_stat BOOLEAN NOT NULL,
 has_item_metric_stat_metric BOOLEAN NOT NULL,
 has_item_metric_stat_metric_dimensions BOOLEAN NOT NULL,
 item_metric_stat_metric_metric_name TEXT,
 item_metric_stat_metric_namespace TEXT,
 item_metric_stat_period INTEGER,
 item_metric_stat_stat TEXT,
 item_metric_stat_unit TEXT,
 item_period INTEGER,
 item_return_data BOOLEAN,
 UNIQUE(policy_pk, position)
);
CREATE TABLE asg_policies_metrics_dimensions (
 item_pk INTEGER NOT NULL REFERENCES asg_policies_metrics(item_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 item_name TEXT,
 item_value TEXT,
 PRIMARY KEY(item_pk, position)
);
CREATE TABLE asg_schedules (
 schedule_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 name TEXT NOT NULL,
 group_id TEXT NOT NULL,
 next_due TIMESTAMP,
 origin_event_id TEXT NOT NULL,
 data_auto_scaling_group_name TEXT,
 data_desired_capacity INTEGER,
 data_end_time TIMESTAMP,
 data_max_size INTEGER,
 data_min_size INTEGER,
 data_recurrence TEXT,
 data_scheduled_action_arn TEXT,
 data_scheduled_action_name TEXT,
 data_start_time TIMESTAMP,
 data_time TIMESTAMP,
 data_time_zone TEXT,
 UNIQUE(partition, account_id, region, group_name, name)
);
CREATE TABLE asg_hooks (
 hook_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 name TEXT NOT NULL,
 group_id TEXT NOT NULL,
 data_auto_scaling_group_name TEXT,
 data_default_result TEXT,
 data_global_timeout INTEGER,
 data_heartbeat_timeout INTEGER,
 data_lifecycle_hook_name TEXT,
 data_lifecycle_transition TEXT,
 data_notification_metadata TEXT,
 data_notification_target_arn TEXT,
 data_role_arn TEXT,
 UNIQUE(partition, account_id, region, group_name, name)
);
CREATE TABLE asg_lifecycle_actions (
 action_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 token TEXT NOT NULL,
 group_id TEXT NOT NULL,
 hook_name TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 transition TEXT NOT NULL,
 default_result TEXT NOT NULL,
 heartbeat_timeout INTEGER NOT NULL,
 deadline TIMESTAMP,
 global_deadline TIMESTAMP,
 origin_event_id TEXT NOT NULL,
 UNIQUE(partition, account_id, region, group_name, token)
);
CREATE INDEX asg_groups_due ON asg_groups(reconcile_at, partition, account_id, region, name) WHERE reconcile_at IS NOT NULL;
CREATE INDEX asg_instances_group ON asg_instances(partition, account_id, region, group_name, instance_id);
CREATE INDEX asg_activities_group ON asg_activities(partition, account_id, region, group_name, data_start_time DESC, activity_id);
CREATE INDEX asg_activities_expiry ON asg_activities(partition, account_id, region, data_end_time) WHERE data_end_time IS NOT NULL;
CREATE INDEX asg_schedules_due ON asg_schedules(next_due, partition, account_id, region, group_name, name) WHERE next_due IS NOT NULL;
CREATE INDEX asg_lifecycle_actions_due ON asg_lifecycle_actions(deadline, global_deadline, partition, account_id, region, group_name, token);
