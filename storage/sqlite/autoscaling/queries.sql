-- name: PutGroup :one
INSERT INTO asg_groups (
 partition, account_id, region, name, native_id, origin_event_id, deleting, reconcile_at, version, data_auto_scaling_group_arn, data_auto_scaling_group_name, has_data_availability_zone_distribution, data_availability_zone_distribution_capacity_distribution_strategy, has_data_availability_zone_ids, has_data_availability_zones, data_capacity_rebalance, has_data_capacity_reservation_specification, data_capacity_reservation_specification_capacity_reservation_preference, has_data_capacity_reservation_specification_capacity_reservation_target, has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_ids, has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_resource_group_arns, data_context, data_created_time, data_default_cooldown, data_default_instance_warmup, data_deletion_protection, data_desired_capacity, data_desired_capacity_type, has_data_enabled_metrics, data_health_check_grace_period, data_health_check_type, has_data_instance_lifecycle_policy, has_data_instance_lifecycle_policy_retention_triggers, data_instance_lifecycle_policy_retention_triggers_terminate_hook_abandon, data_launch_configuration_name, has_data_launch_template, data_launch_template_launch_template_id, data_launch_template_launch_template_name, data_launch_template_version, has_data_load_balancer_names, data_max_instance_lifetime, data_max_size, data_min_size, data_new_instances_protected_from_scale_in, data_placement_group, data_predicted_capacity, data_service_linked_role_arn, data_status, has_data_suspended_processes, has_data_tags, has_data_target_group_arns, has_data_termination_policies, has_data_traffic_sources, data_vpc_zone_identifier, data_warm_pool_size
 , reconcile_cause, pending_instance_warmup, metric_at
 , scale_up_version
 , has_data_warm_pool_configuration, data_warm_pool_configuration_min_size, data_warm_pool_configuration_max_group_prepared_capacity, data_warm_pool_configuration_pool_state, data_warm_pool_configuration_status, has_data_warm_pool_configuration_instance_reuse_policy, data_warm_pool_configuration_instance_reuse_policy_reuse_on_scale_in
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(native_id), sqlc.arg(origin_event_id), sqlc.arg(deleting), sqlc.arg(reconcile_at), sqlc.arg(version), sqlc.arg(data_auto_scaling_group_arn), sqlc.arg(data_auto_scaling_group_name), sqlc.arg(has_data_availability_zone_distribution), sqlc.arg(data_availability_zone_distribution_capacity_distribution_strategy), sqlc.arg(has_data_availability_zone_ids), sqlc.arg(has_data_availability_zones), sqlc.arg(data_capacity_rebalance), sqlc.arg(has_data_capacity_reservation_specification), sqlc.arg(data_capacity_reservation_specification_capacity_reservation_preference), sqlc.arg(has_data_capacity_reservation_specification_capacity_reservation_target), sqlc.arg(has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_ids), sqlc.arg(has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_resource_group_arns), sqlc.arg(data_context), sqlc.arg(data_created_time), sqlc.arg(data_default_cooldown), sqlc.arg(data_default_instance_warmup), sqlc.arg(data_deletion_protection), sqlc.arg(data_desired_capacity), sqlc.arg(data_desired_capacity_type), sqlc.arg(has_data_enabled_metrics), sqlc.arg(data_health_check_grace_period), sqlc.arg(data_health_check_type), sqlc.arg(has_data_instance_lifecycle_policy), sqlc.arg(has_data_instance_lifecycle_policy_retention_triggers), sqlc.arg(data_instance_lifecycle_policy_retention_triggers_terminate_hook_abandon), sqlc.arg(data_launch_configuration_name), sqlc.arg(has_data_launch_template), sqlc.arg(data_launch_template_launch_template_id), sqlc.arg(data_launch_template_launch_template_name), sqlc.arg(data_launch_template_version), sqlc.arg(has_data_load_balancer_names), sqlc.arg(data_max_instance_lifetime), sqlc.arg(data_max_size), sqlc.arg(data_min_size), sqlc.arg(data_new_instances_protected_from_scale_in), sqlc.arg(data_placement_group), sqlc.arg(data_predicted_capacity), sqlc.arg(data_service_linked_role_arn), sqlc.arg(data_status), sqlc.arg(has_data_suspended_processes), sqlc.arg(has_data_tags), sqlc.arg(has_data_target_group_arns), sqlc.arg(has_data_termination_policies), sqlc.arg(has_data_traffic_sources), sqlc.arg(data_vpc_zone_identifier), sqlc.arg(data_warm_pool_size)
 , sqlc.arg(reconcile_cause), sqlc.arg(pending_instance_warmup), sqlc.arg(metric_at)
 , sqlc.arg(scale_up_version)
 , sqlc.arg(has_data_warm_pool_configuration), sqlc.arg(data_warm_pool_configuration_min_size), sqlc.arg(data_warm_pool_configuration_max_group_prepared_capacity), sqlc.arg(data_warm_pool_configuration_pool_state), sqlc.arg(data_warm_pool_configuration_status), sqlc.arg(has_data_warm_pool_configuration_instance_reuse_policy), sqlc.arg(data_warm_pool_configuration_instance_reuse_policy_reuse_on_scale_in)
)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
 native_id = excluded.native_id,
 origin_event_id = excluded.origin_event_id,
 deleting = excluded.deleting,
 reconcile_at = excluded.reconcile_at,
 reconcile_cause = excluded.reconcile_cause,
 pending_instance_warmup = excluded.pending_instance_warmup,
 metric_at = excluded.metric_at,
 has_data_warm_pool_configuration = excluded.has_data_warm_pool_configuration,
 data_warm_pool_configuration_min_size = excluded.data_warm_pool_configuration_min_size,
 data_warm_pool_configuration_max_group_prepared_capacity = excluded.data_warm_pool_configuration_max_group_prepared_capacity,
 data_warm_pool_configuration_pool_state = excluded.data_warm_pool_configuration_pool_state,
 data_warm_pool_configuration_status = excluded.data_warm_pool_configuration_status,
 has_data_warm_pool_configuration_instance_reuse_policy = excluded.has_data_warm_pool_configuration_instance_reuse_policy,
 data_warm_pool_configuration_instance_reuse_policy_reuse_on_scale_in = excluded.data_warm_pool_configuration_instance_reuse_policy_reuse_on_scale_in,
 version = excluded.version,
 scale_up_version = excluded.scale_up_version,
 data_auto_scaling_group_arn = excluded.data_auto_scaling_group_arn,
 data_auto_scaling_group_name = excluded.data_auto_scaling_group_name,
 has_data_availability_zone_distribution = excluded.has_data_availability_zone_distribution,
 data_availability_zone_distribution_capacity_distribution_strategy = excluded.data_availability_zone_distribution_capacity_distribution_strategy,
 has_data_availability_zone_ids = excluded.has_data_availability_zone_ids,
 has_data_availability_zones = excluded.has_data_availability_zones,
 data_capacity_rebalance = excluded.data_capacity_rebalance,
 has_data_capacity_reservation_specification = excluded.has_data_capacity_reservation_specification,
 data_capacity_reservation_specification_capacity_reservation_preference = excluded.data_capacity_reservation_specification_capacity_reservation_preference,
 has_data_capacity_reservation_specification_capacity_reservation_target = excluded.has_data_capacity_reservation_specification_capacity_reservation_target,
 has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_ids = excluded.has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_ids,
 has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_resource_group_arns = excluded.has_data_capacity_reservation_specification_capacity_reservation_target_capacity_reservation_resource_group_arns,
 data_context = excluded.data_context,
 data_created_time = excluded.data_created_time,
 data_default_cooldown = excluded.data_default_cooldown,
 data_default_instance_warmup = excluded.data_default_instance_warmup,
 data_deletion_protection = excluded.data_deletion_protection,
 data_desired_capacity = excluded.data_desired_capacity,
 data_desired_capacity_type = excluded.data_desired_capacity_type,
 has_data_enabled_metrics = excluded.has_data_enabled_metrics,
 data_health_check_grace_period = excluded.data_health_check_grace_period,
 data_health_check_type = excluded.data_health_check_type,
 has_data_instance_lifecycle_policy = excluded.has_data_instance_lifecycle_policy,
 has_data_instance_lifecycle_policy_retention_triggers = excluded.has_data_instance_lifecycle_policy_retention_triggers,
 data_instance_lifecycle_policy_retention_triggers_terminate_hook_abandon = excluded.data_instance_lifecycle_policy_retention_triggers_terminate_hook_abandon,
 data_launch_configuration_name = excluded.data_launch_configuration_name,
 has_data_launch_template = excluded.has_data_launch_template,
 data_launch_template_launch_template_id = excluded.data_launch_template_launch_template_id,
 data_launch_template_launch_template_name = excluded.data_launch_template_launch_template_name,
 data_launch_template_version = excluded.data_launch_template_version,
 has_data_load_balancer_names = excluded.has_data_load_balancer_names,
 data_max_instance_lifetime = excluded.data_max_instance_lifetime,
 data_max_size = excluded.data_max_size,
 data_min_size = excluded.data_min_size,
 data_new_instances_protected_from_scale_in = excluded.data_new_instances_protected_from_scale_in,
 data_placement_group = excluded.data_placement_group,
 data_predicted_capacity = excluded.data_predicted_capacity,
 data_service_linked_role_arn = excluded.data_service_linked_role_arn,
 data_status = excluded.data_status,
 has_data_suspended_processes = excluded.has_data_suspended_processes,
 has_data_tags = excluded.has_data_tags,
 has_data_target_group_arns = excluded.has_data_target_group_arns,
 has_data_termination_policies = excluded.has_data_termination_policies,
 has_data_traffic_sources = excluded.has_data_traffic_sources,
 data_vpc_zone_identifier = excluded.data_vpc_zone_identifier,
 data_warm_pool_size = excluded.data_warm_pool_size
RETURNING group_pk;

-- name: GetGroup :one
SELECT * FROM asg_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: DeleteGroup :exec
DELETE FROM asg_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: InsertGroupsAvailabilityZoneIds :exec
INSERT INTO asg_groups_availability_zone_ids (
 group_pk, position, value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(value)
);

-- name: ListGroupsAvailabilityZoneIds :many
SELECT * FROM asg_groups_availability_zone_ids WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsAvailabilityZoneIds :exec
DELETE FROM asg_groups_availability_zone_ids WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsAvailabilityZones :exec
INSERT INTO asg_groups_availability_zones (
 group_pk, position, value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(value)
);

-- name: ListGroupsAvailabilityZones :many
SELECT * FROM asg_groups_availability_zones WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsAvailabilityZones :exec
DELETE FROM asg_groups_availability_zones WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsCapacityReservationIds :exec
INSERT INTO asg_groups_capacity_reservation_ids (
 group_pk, position, value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(value)
);

-- name: ListGroupsCapacityReservationIds :many
SELECT * FROM asg_groups_capacity_reservation_ids WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsCapacityReservationIds :exec
DELETE FROM asg_groups_capacity_reservation_ids WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsCapacityReservationResourceGroupArns :exec
INSERT INTO asg_groups_capacity_reservation_resource_group_arns (
 group_pk, position, value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(value)
);

-- name: ListGroupsCapacityReservationResourceGroupArns :many
SELECT * FROM asg_groups_capacity_reservation_resource_group_arns WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsCapacityReservationResourceGroupArns :exec
DELETE FROM asg_groups_capacity_reservation_resource_group_arns WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsEnabledMetrics :exec
INSERT INTO asg_groups_enabled_metrics (
 group_pk, position, item_granularity, item_metric
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(item_granularity), sqlc.arg(item_metric)
);

-- name: ListGroupsEnabledMetrics :many
SELECT * FROM asg_groups_enabled_metrics WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsEnabledMetrics :exec
DELETE FROM asg_groups_enabled_metrics WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsLoadBalancerNames :exec
INSERT INTO asg_groups_load_balancer_names (
 group_pk, position, value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(value)
);

-- name: ListGroupsLoadBalancerNames :many
SELECT * FROM asg_groups_load_balancer_names WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsLoadBalancerNames :exec
DELETE FROM asg_groups_load_balancer_names WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsSuspendedProcesses :exec
INSERT INTO asg_groups_suspended_processes (
 group_pk, position, item_process_name, item_suspension_reason
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(item_process_name), sqlc.arg(item_suspension_reason)
);

-- name: ListGroupsSuspendedProcesses :many
SELECT * FROM asg_groups_suspended_processes WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsSuspendedProcesses :exec
DELETE FROM asg_groups_suspended_processes WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsTags :exec
INSERT INTO asg_groups_tags (
 group_pk, position, item_key, item_propagate_at_launch, item_resource_id, item_resource_type, item_value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(item_key), sqlc.arg(item_propagate_at_launch), sqlc.arg(item_resource_id), sqlc.arg(item_resource_type), sqlc.arg(item_value)
);

-- name: ListGroupsTags :many
SELECT * FROM asg_groups_tags WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsTags :exec
DELETE FROM asg_groups_tags WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsTargetGroupArns :exec
INSERT INTO asg_groups_target_group_arns (
 group_pk, position, value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(value)
);

-- name: ListGroupsTargetGroupArns :many
SELECT * FROM asg_groups_target_group_arns WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsTargetGroupArns :exec
DELETE FROM asg_groups_target_group_arns WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsTerminationPolicies :exec
INSERT INTO asg_groups_termination_policies (
 group_pk, position, value
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(value)
);

-- name: ListGroupsTerminationPolicies :many
SELECT * FROM asg_groups_termination_policies WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsTerminationPolicies :exec
DELETE FROM asg_groups_termination_policies WHERE group_pk = sqlc.arg(group_pk);

-- name: InsertGroupsTrafficSources :exec
INSERT INTO asg_groups_traffic_sources (
 group_pk, position, item_identifier, item_type
) VALUES (
 sqlc.arg(group_pk), sqlc.arg(position), sqlc.arg(item_identifier), sqlc.arg(item_type)
);

-- name: ListGroupsTrafficSources :many
SELECT * FROM asg_groups_traffic_sources WHERE group_pk = sqlc.arg(group_pk) ORDER BY position;

-- name: DeleteGroupsTrafficSources :exec
DELETE FROM asg_groups_traffic_sources WHERE group_pk = sqlc.arg(group_pk);

-- name: PutInstance :exec
INSERT INTO asg_instances (
 partition, account_id, region, instance_id, group_name, group_id, joined_at, in_service_at, warm_until, activity_id, termination_requested, detach_requested, data_availability_zone, data_availability_zone_id, data_health_status, data_image_id, data_instance_id, data_instance_type, data_launch_configuration_name, has_data_launch_template, data_launch_template_launch_template_id, data_launch_template_launch_template_name, data_launch_template_version, data_lifecycle_state, data_protected_from_scale_in, data_weighted_capacity
 , health_check_grace_ignored
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(instance_id), sqlc.arg(group_name), sqlc.arg(group_id), sqlc.arg(joined_at), sqlc.arg(in_service_at), sqlc.arg(warm_until), sqlc.arg(activity_id), sqlc.arg(termination_requested), sqlc.arg(detach_requested), sqlc.arg(data_availability_zone), sqlc.arg(data_availability_zone_id), sqlc.arg(data_health_status), sqlc.arg(data_image_id), sqlc.arg(data_instance_id), sqlc.arg(data_instance_type), sqlc.arg(data_launch_configuration_name), sqlc.arg(has_data_launch_template), sqlc.arg(data_launch_template_launch_template_id), sqlc.arg(data_launch_template_launch_template_name), sqlc.arg(data_launch_template_version), sqlc.arg(data_lifecycle_state), sqlc.arg(data_protected_from_scale_in), sqlc.arg(data_weighted_capacity)
 , sqlc.arg(health_check_grace_ignored)
)
ON CONFLICT(partition, account_id, region, instance_id) DO UPDATE SET
 group_name = excluded.group_name,
 group_id = excluded.group_id,
 joined_at = excluded.joined_at,
 in_service_at = excluded.in_service_at,
 warm_until = excluded.warm_until,
 activity_id = excluded.activity_id,
 termination_requested = excluded.termination_requested,
 detach_requested = excluded.detach_requested,
 health_check_grace_ignored = excluded.health_check_grace_ignored,
 data_availability_zone = excluded.data_availability_zone,
 data_availability_zone_id = excluded.data_availability_zone_id,
 data_health_status = excluded.data_health_status,
 data_image_id = excluded.data_image_id,
 data_instance_id = excluded.data_instance_id,
 data_instance_type = excluded.data_instance_type,
 data_launch_configuration_name = excluded.data_launch_configuration_name,
 has_data_launch_template = excluded.has_data_launch_template,
 data_launch_template_launch_template_id = excluded.data_launch_template_launch_template_id,
 data_launch_template_launch_template_name = excluded.data_launch_template_launch_template_name,
 data_launch_template_version = excluded.data_launch_template_version,
 data_lifecycle_state = excluded.data_lifecycle_state,
 data_protected_from_scale_in = excluded.data_protected_from_scale_in,
 data_weighted_capacity = excluded.data_weighted_capacity;

-- name: GetInstance :one
SELECT * FROM asg_instances WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND instance_id = sqlc.arg(instance_id);

-- name: DeleteInstance :exec
DELETE FROM asg_instances WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND instance_id = sqlc.arg(instance_id);

-- name: PutActivity :one
INSERT INTO asg_activities (
 partition, account_id, region, activity_id, group_partition, group_account_id, group_region, group_name, group_id, kind, instance_id, subnet_id, origin_event_id, retry_at, data_activity_id, data_auto_scaling_group_arn, data_auto_scaling_group_name, data_auto_scaling_group_state, data_cause, data_description, data_details, data_end_time, data_progress, data_start_time, data_status_code, data_status_message, launch_template_launch_template_id, launch_template_launch_template_name, launch_template_version
 , instance_warmup, has_launch_tags, protected_from_scale_in
 , warm_pool_state
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(activity_id), sqlc.arg(group_partition), sqlc.arg(group_account_id), sqlc.arg(group_region), sqlc.arg(group_name), sqlc.arg(group_id), sqlc.arg(kind), sqlc.arg(instance_id), sqlc.arg(subnet_id), sqlc.arg(origin_event_id), sqlc.arg(retry_at), sqlc.arg(data_activity_id), sqlc.arg(data_auto_scaling_group_arn), sqlc.arg(data_auto_scaling_group_name), sqlc.arg(data_auto_scaling_group_state), sqlc.arg(data_cause), sqlc.arg(data_description), sqlc.arg(data_details), sqlc.arg(data_end_time), sqlc.arg(data_progress), sqlc.arg(data_start_time), sqlc.arg(data_status_code), sqlc.arg(data_status_message), sqlc.arg(launch_template_launch_template_id), sqlc.arg(launch_template_launch_template_name), sqlc.arg(launch_template_version)
 , sqlc.arg(instance_warmup), sqlc.arg(has_launch_tags), sqlc.arg(protected_from_scale_in)
 , sqlc.arg(warm_pool_state)
)
ON CONFLICT(partition, account_id, region, activity_id) DO UPDATE SET
 group_partition = excluded.group_partition,
 group_account_id = excluded.group_account_id,
 group_region = excluded.group_region,
 group_name = excluded.group_name,
 group_id = excluded.group_id,
 kind = excluded.kind,
 instance_id = excluded.instance_id,
 subnet_id = excluded.subnet_id,
 origin_event_id = excluded.origin_event_id,
 retry_at = excluded.retry_at,
 instance_warmup = excluded.instance_warmup,
 has_launch_tags = excluded.has_launch_tags,
 protected_from_scale_in = excluded.protected_from_scale_in,
 warm_pool_state = excluded.warm_pool_state,
 data_activity_id = excluded.data_activity_id,
 data_auto_scaling_group_arn = excluded.data_auto_scaling_group_arn,
 data_auto_scaling_group_name = excluded.data_auto_scaling_group_name,
 data_auto_scaling_group_state = excluded.data_auto_scaling_group_state,
 data_cause = excluded.data_cause,
 data_description = excluded.data_description,
 data_details = excluded.data_details,
 data_end_time = excluded.data_end_time,
 data_progress = excluded.data_progress,
 data_start_time = excluded.data_start_time,
 data_status_code = excluded.data_status_code,
 data_status_message = excluded.data_status_message,
 launch_template_launch_template_id = excluded.launch_template_launch_template_id,
 launch_template_launch_template_name = excluded.launch_template_launch_template_name,
 launch_template_version = excluded.launch_template_version
RETURNING activity_pk;

-- name: GetActivity :one
SELECT * FROM asg_activities WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND activity_id = sqlc.arg(activity_id);

-- name: InsertActivityLaunchTag :exec
INSERT INTO asg_activity_launch_tags (activity_pk, position, key, value, resource_id, resource_type, propagate_at_launch)
VALUES (sqlc.arg(activity_pk), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value), sqlc.arg(resource_id), sqlc.arg(resource_type), sqlc.arg(propagate_at_launch));

-- name: ListActivityLaunchTags :many
SELECT * FROM asg_activity_launch_tags WHERE activity_pk = sqlc.arg(activity_pk) ORDER BY position;

-- name: DeleteActivityLaunchTags :exec
DELETE FROM asg_activity_launch_tags WHERE activity_pk = sqlc.arg(activity_pk);

-- name: PutPolicy :one
INSERT INTO asg_policies (
 partition, account_id, region, group_name, name, group_id, last_scale_at, data_adjustment_type, has_data_alarms, data_auto_scaling_group_name, data_cooldown, data_enabled, data_estimated_instance_warmup, data_metric_aggregation_type, data_min_adjustment_magnitude, data_min_adjustment_step, data_policy_arn, data_policy_name, data_policy_type, data_scaling_adjustment, has_data_step_adjustments, has_data_target_tracking_configuration, has_data_target_tracking_configuration_customized_metric_specification, has_data_target_tracking_configuration_customized_metric_specification_dimensions, data_target_tracking_configuration_customized_metric_specification_metric_name, has_data_target_tracking_configuration_customized_metric_specification_metrics, data_target_tracking_configuration_customized_metric_specification_namespace, data_target_tracking_configuration_customized_metric_specification_period, data_target_tracking_configuration_customized_metric_specification_statistic, data_target_tracking_configuration_customized_metric_specification_unit, data_target_tracking_configuration_disable_scale_in, has_data_target_tracking_configuration_predefined_metric_specification, data_target_tracking_configuration_predefined_metric_specification_predefined_metric_type, data_target_tracking_configuration_predefined_metric_specification_resource_label, data_target_tracking_configuration_target_value
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(group_name), sqlc.arg(name), sqlc.arg(group_id), sqlc.arg(last_scale_at), sqlc.arg(data_adjustment_type), sqlc.arg(has_data_alarms), sqlc.arg(data_auto_scaling_group_name), sqlc.arg(data_cooldown), sqlc.arg(data_enabled), sqlc.arg(data_estimated_instance_warmup), sqlc.arg(data_metric_aggregation_type), sqlc.arg(data_min_adjustment_magnitude), sqlc.arg(data_min_adjustment_step), sqlc.arg(data_policy_arn), sqlc.arg(data_policy_name), sqlc.arg(data_policy_type), sqlc.arg(data_scaling_adjustment), sqlc.arg(has_data_step_adjustments), sqlc.arg(has_data_target_tracking_configuration), sqlc.arg(has_data_target_tracking_configuration_customized_metric_specification), sqlc.arg(has_data_target_tracking_configuration_customized_metric_specification_dimensions), sqlc.arg(data_target_tracking_configuration_customized_metric_specification_metric_name), sqlc.arg(has_data_target_tracking_configuration_customized_metric_specification_metrics), sqlc.arg(data_target_tracking_configuration_customized_metric_specification_namespace), sqlc.arg(data_target_tracking_configuration_customized_metric_specification_period), sqlc.arg(data_target_tracking_configuration_customized_metric_specification_statistic), sqlc.arg(data_target_tracking_configuration_customized_metric_specification_unit), sqlc.arg(data_target_tracking_configuration_disable_scale_in), sqlc.arg(has_data_target_tracking_configuration_predefined_metric_specification), sqlc.arg(data_target_tracking_configuration_predefined_metric_specification_predefined_metric_type), sqlc.arg(data_target_tracking_configuration_predefined_metric_specification_resource_label), sqlc.arg(data_target_tracking_configuration_target_value)
)
ON CONFLICT(partition, account_id, region, group_name, name) DO UPDATE SET
 group_id = excluded.group_id,
 last_scale_at = excluded.last_scale_at,
 data_adjustment_type = excluded.data_adjustment_type,
 has_data_alarms = excluded.has_data_alarms,
 data_auto_scaling_group_name = excluded.data_auto_scaling_group_name,
 data_cooldown = excluded.data_cooldown,
 data_enabled = excluded.data_enabled,
 data_estimated_instance_warmup = excluded.data_estimated_instance_warmup,
 data_metric_aggregation_type = excluded.data_metric_aggregation_type,
 data_min_adjustment_magnitude = excluded.data_min_adjustment_magnitude,
 data_min_adjustment_step = excluded.data_min_adjustment_step,
 data_policy_arn = excluded.data_policy_arn,
 data_policy_name = excluded.data_policy_name,
 data_policy_type = excluded.data_policy_type,
 data_scaling_adjustment = excluded.data_scaling_adjustment,
 has_data_step_adjustments = excluded.has_data_step_adjustments,
 has_data_target_tracking_configuration = excluded.has_data_target_tracking_configuration,
 has_data_target_tracking_configuration_customized_metric_specification = excluded.has_data_target_tracking_configuration_customized_metric_specification,
 has_data_target_tracking_configuration_customized_metric_specification_dimensions = excluded.has_data_target_tracking_configuration_customized_metric_specification_dimensions,
 data_target_tracking_configuration_customized_metric_specification_metric_name = excluded.data_target_tracking_configuration_customized_metric_specification_metric_name,
 has_data_target_tracking_configuration_customized_metric_specification_metrics = excluded.has_data_target_tracking_configuration_customized_metric_specification_metrics,
 data_target_tracking_configuration_customized_metric_specification_namespace = excluded.data_target_tracking_configuration_customized_metric_specification_namespace,
 data_target_tracking_configuration_customized_metric_specification_period = excluded.data_target_tracking_configuration_customized_metric_specification_period,
 data_target_tracking_configuration_customized_metric_specification_statistic = excluded.data_target_tracking_configuration_customized_metric_specification_statistic,
 data_target_tracking_configuration_customized_metric_specification_unit = excluded.data_target_tracking_configuration_customized_metric_specification_unit,
 data_target_tracking_configuration_disable_scale_in = excluded.data_target_tracking_configuration_disable_scale_in,
 has_data_target_tracking_configuration_predefined_metric_specification = excluded.has_data_target_tracking_configuration_predefined_metric_specification,
 data_target_tracking_configuration_predefined_metric_specification_predefined_metric_type = excluded.data_target_tracking_configuration_predefined_metric_specification_predefined_metric_type,
 data_target_tracking_configuration_predefined_metric_specification_resource_label = excluded.data_target_tracking_configuration_predefined_metric_specification_resource_label,
 data_target_tracking_configuration_target_value = excluded.data_target_tracking_configuration_target_value
RETURNING policy_pk;

-- name: GetPolicy :one
SELECT * FROM asg_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) AND name = sqlc.arg(name);

-- name: DeletePolicy :exec
DELETE FROM asg_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) AND name = sqlc.arg(name);

-- name: InsertPoliciesAlarms :exec
INSERT INTO asg_policies_alarms (
 policy_pk, position, item_alarm_arn, item_alarm_name
) VALUES (
 sqlc.arg(policy_pk), sqlc.arg(position), sqlc.arg(item_alarm_arn), sqlc.arg(item_alarm_name)
);

-- name: ListPoliciesAlarms :many
SELECT * FROM asg_policies_alarms WHERE policy_pk = sqlc.arg(policy_pk) ORDER BY position;

-- name: DeletePoliciesAlarms :exec
DELETE FROM asg_policies_alarms WHERE policy_pk = sqlc.arg(policy_pk);

-- name: InsertPoliciesStepAdjustments :exec
INSERT INTO asg_policies_step_adjustments (
 policy_pk, position, item_metric_interval_lower_bound, item_metric_interval_upper_bound, item_scaling_adjustment
) VALUES (
 sqlc.arg(policy_pk), sqlc.arg(position), sqlc.arg(item_metric_interval_lower_bound), sqlc.arg(item_metric_interval_upper_bound), sqlc.arg(item_scaling_adjustment)
);

-- name: ListPoliciesStepAdjustments :many
SELECT * FROM asg_policies_step_adjustments WHERE policy_pk = sqlc.arg(policy_pk) ORDER BY position;

-- name: DeletePoliciesStepAdjustments :exec
DELETE FROM asg_policies_step_adjustments WHERE policy_pk = sqlc.arg(policy_pk);

-- name: InsertPoliciesDimensions :exec
INSERT INTO asg_policies_dimensions (
 policy_pk, position, item_name, item_value
) VALUES (
 sqlc.arg(policy_pk), sqlc.arg(position), sqlc.arg(item_name), sqlc.arg(item_value)
);

-- name: ListPoliciesDimensions :many
SELECT * FROM asg_policies_dimensions WHERE policy_pk = sqlc.arg(policy_pk) ORDER BY position;

-- name: DeletePoliciesDimensions :exec
DELETE FROM asg_policies_dimensions WHERE policy_pk = sqlc.arg(policy_pk);

-- name: InsertPoliciesMetrics :one
INSERT INTO asg_policies_metrics (
 policy_pk, position, item_expression, item_id, item_label, has_item_metric_stat, has_item_metric_stat_metric, has_item_metric_stat_metric_dimensions, item_metric_stat_metric_metric_name, item_metric_stat_metric_namespace, item_metric_stat_period, item_metric_stat_stat, item_metric_stat_unit, item_period, item_return_data
) VALUES (
 sqlc.arg(policy_pk), sqlc.arg(position), sqlc.arg(item_expression), sqlc.arg(item_id), sqlc.arg(item_label), sqlc.arg(has_item_metric_stat), sqlc.arg(has_item_metric_stat_metric), sqlc.arg(has_item_metric_stat_metric_dimensions), sqlc.arg(item_metric_stat_metric_metric_name), sqlc.arg(item_metric_stat_metric_namespace), sqlc.arg(item_metric_stat_period), sqlc.arg(item_metric_stat_stat), sqlc.arg(item_metric_stat_unit), sqlc.arg(item_period), sqlc.arg(item_return_data)
) RETURNING item_pk;

-- name: ListPoliciesMetrics :many
SELECT * FROM asg_policies_metrics WHERE policy_pk = sqlc.arg(policy_pk) ORDER BY position;

-- name: DeletePoliciesMetrics :exec
DELETE FROM asg_policies_metrics WHERE policy_pk = sqlc.arg(policy_pk);

-- name: InsertPoliciesMetricsDimensions :exec
INSERT INTO asg_policies_metrics_dimensions (
 item_pk, position, item_name, item_value
) VALUES (
 sqlc.arg(item_pk), sqlc.arg(position), sqlc.arg(item_name), sqlc.arg(item_value)
);

-- name: ListPoliciesMetricsDimensions :many
SELECT * FROM asg_policies_metrics_dimensions WHERE item_pk = sqlc.arg(item_pk) ORDER BY position;

-- name: DeletePoliciesMetricsDimensions :exec
DELETE FROM asg_policies_metrics_dimensions WHERE item_pk = sqlc.arg(item_pk);

-- name: PutSchedule :exec
INSERT INTO asg_schedules (
 partition, account_id, region, group_name, name, group_id, next_due, origin_event_id, data_auto_scaling_group_name, data_desired_capacity, data_end_time, data_max_size, data_min_size, data_recurrence, data_scheduled_action_arn, data_scheduled_action_name, data_start_time, data_time, data_time_zone
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(group_name), sqlc.arg(name), sqlc.arg(group_id), sqlc.arg(next_due), sqlc.arg(origin_event_id), sqlc.arg(data_auto_scaling_group_name), sqlc.arg(data_desired_capacity), sqlc.arg(data_end_time), sqlc.arg(data_max_size), sqlc.arg(data_min_size), sqlc.arg(data_recurrence), sqlc.arg(data_scheduled_action_arn), sqlc.arg(data_scheduled_action_name), sqlc.arg(data_start_time), sqlc.arg(data_time), sqlc.arg(data_time_zone)
)
ON CONFLICT(partition, account_id, region, group_name, name) DO UPDATE SET
 group_id = excluded.group_id,
 next_due = excluded.next_due,
 origin_event_id = excluded.origin_event_id,
 data_auto_scaling_group_name = excluded.data_auto_scaling_group_name,
 data_desired_capacity = excluded.data_desired_capacity,
 data_end_time = excluded.data_end_time,
 data_max_size = excluded.data_max_size,
 data_min_size = excluded.data_min_size,
 data_recurrence = excluded.data_recurrence,
 data_scheduled_action_arn = excluded.data_scheduled_action_arn,
 data_scheduled_action_name = excluded.data_scheduled_action_name,
 data_start_time = excluded.data_start_time,
 data_time = excluded.data_time,
 data_time_zone = excluded.data_time_zone;

-- name: GetSchedule :one
SELECT * FROM asg_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) AND name = sqlc.arg(name);

-- name: DeleteSchedule :exec
DELETE FROM asg_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) AND name = sqlc.arg(name);

-- name: PutHook :exec
INSERT INTO asg_hooks (
 partition, account_id, region, group_name, name, group_id, data_auto_scaling_group_name, data_default_result, data_global_timeout, data_heartbeat_timeout, data_lifecycle_hook_name, data_lifecycle_transition, data_notification_metadata, data_notification_target_arn, data_role_arn
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(group_name), sqlc.arg(name), sqlc.arg(group_id), sqlc.arg(data_auto_scaling_group_name), sqlc.arg(data_default_result), sqlc.arg(data_global_timeout), sqlc.arg(data_heartbeat_timeout), sqlc.arg(data_lifecycle_hook_name), sqlc.arg(data_lifecycle_transition), sqlc.arg(data_notification_metadata), sqlc.arg(data_notification_target_arn), sqlc.arg(data_role_arn)
)
ON CONFLICT(partition, account_id, region, group_name, name) DO UPDATE SET
 group_id = excluded.group_id,
 data_auto_scaling_group_name = excluded.data_auto_scaling_group_name,
 data_default_result = excluded.data_default_result,
 data_global_timeout = excluded.data_global_timeout,
 data_heartbeat_timeout = excluded.data_heartbeat_timeout,
 data_lifecycle_hook_name = excluded.data_lifecycle_hook_name,
 data_lifecycle_transition = excluded.data_lifecycle_transition,
 data_notification_metadata = excluded.data_notification_metadata,
 data_notification_target_arn = excluded.data_notification_target_arn,
 data_role_arn = excluded.data_role_arn;

-- name: GetHook :one
SELECT * FROM asg_hooks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) AND name = sqlc.arg(name);

-- name: DeleteHook :exec
DELETE FROM asg_hooks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) AND name = sqlc.arg(name);

-- name: PutLifecycleAction :exec
INSERT INTO asg_lifecycle_actions (
 partition, account_id, region, group_name, token, group_id, hook_name, instance_id, transition, default_result, heartbeat_timeout, deadline, global_deadline, origin_event_id
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(group_name), sqlc.arg(token), sqlc.arg(group_id), sqlc.arg(hook_name), sqlc.arg(instance_id), sqlc.arg(transition), sqlc.arg(default_result), sqlc.arg(heartbeat_timeout), sqlc.arg(deadline), sqlc.arg(global_deadline), sqlc.arg(origin_event_id)
)
ON CONFLICT(partition, account_id, region, group_name, token) DO UPDATE SET
 group_id = excluded.group_id,
 hook_name = excluded.hook_name,
 instance_id = excluded.instance_id,
 transition = excluded.transition,
 default_result = excluded.default_result,
 heartbeat_timeout = excluded.heartbeat_timeout,
 deadline = excluded.deadline,
 global_deadline = excluded.global_deadline,
 origin_event_id = excluded.origin_event_id;

-- name: DeleteLifecycleAction :exec
DELETE FROM asg_lifecycle_actions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) AND token = sqlc.arg(token);

-- name: ListInstances :many
SELECT * FROM asg_instances WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) ORDER BY instance_id;

-- name: DeleteGroupInstances :exec
DELETE FROM asg_instances WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name);

-- name: ListPolicies :many
SELECT * FROM asg_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) ORDER BY name;

-- name: DeleteGroupPolicies :exec
DELETE FROM asg_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name);

-- name: ListSchedules :many
SELECT * FROM asg_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) ORDER BY name;

-- name: DeleteGroupSchedules :exec
DELETE FROM asg_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name);

-- name: ListHooks :many
SELECT * FROM asg_hooks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) ORDER BY name;

-- name: DeleteGroupHooks :exec
DELETE FROM asg_hooks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name);

-- name: ListLifecycleActions :many
SELECT * FROM asg_lifecycle_actions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name) ORDER BY token;

-- name: DeleteGroupLifecycleActions :exec
DELETE FROM asg_lifecycle_actions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND group_name = sqlc.arg(group_name);

-- name: ListGroups :many
SELECT * FROM asg_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name > sqlc.arg(after_name) AND (sqlc.arg(has_names) = 0 OR name IN (SELECT value FROM json_each(sqlc.arg(names)))) ORDER BY name LIMIT sqlc.arg(row_limit);

-- name: ListGroupKeys :many
SELECT partition, account_id, region, name FROM asg_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) ORDER BY region, name;

-- name: PendingGroups :many
SELECT partition, account_id, region, name, native_id, version, reconcile_at, metric_at, deleting FROM asg_groups WHERE reconcile_at IS NOT NULL OR metric_at IS NOT NULL ORDER BY reconcile_at, partition, account_id, region, name;

-- name: PendingSchedules :many
SELECT * FROM asg_schedules WHERE next_due IS NOT NULL ORDER BY next_due, partition, account_id, region, group_name, name;

-- name: PendingLifecycleActions :many
SELECT * FROM asg_lifecycle_actions ORDER BY CASE WHEN deadline IS NULL THEN global_deadline WHEN global_deadline IS NULL THEN deadline ELSE min(deadline, global_deadline) END, partition, account_id, region, group_name, token;

-- name: ListActivities :many
SELECT a.* FROM asg_activities a WHERE a.partition = sqlc.arg(partition) AND a.account_id = sqlc.arg(account_id) AND a.region = sqlc.arg(region) AND (CAST(sqlc.arg(group_name) AS TEXT) = '' OR a.group_name = sqlc.arg(group_name)) AND (sqlc.arg(include_deleted) != 0 OR EXISTS (SELECT 1 FROM asg_groups g WHERE g.partition = a.group_partition AND g.account_id = a.group_account_id AND g.region = a.group_region AND g.name = a.group_name AND g.native_id = a.group_id)) ORDER BY a.data_start_time DESC, a.activity_id;

-- name: DeleteActivitiesBefore :exec
DELETE FROM asg_activities WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND data_end_time < sqlc.arg(before_time);

-- name: ListRefreshes :many
SELECT * FROM asg_refreshes WHERE partition=? AND account_id=? AND region=? AND group_name=? ORDER BY requested_at DESC,refresh_id DESC;

-- name: PutRefresh :one
INSERT INTO asg_refreshes (partition,account_id,region,group_name,group_id,refresh_id,origin_event_id,requested_at,blocked_since,pause_until,active_deadline,checkpoint,wait_for_transitioning,status,status_reason,strategy,start_time,end_time,percentage_complete,instances_to_update,has_desired,has_progress,has_warm_progress,has_rollback,has_rollback_progress,has_rollback_warm_progress,original_id,original_name,original_version,target_id,target_name,target_version,desired_id,desired_name,desired_version,min_healthy,max_healthy,instance_warmup,checkpoint_delay,bake_time,skip_matching,auto_rollback,protected_instances,standby_instances,live_percentage,live_remaining,warm_percentage,warm_remaining,rollback_live_percentage,rollback_live_remaining,rollback_warm_percentage,rollback_warm_remaining,rollback_reason,rollback_start,rollback_percentage,rollback_remaining) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,refresh_id) DO UPDATE SET group_name=excluded.group_name,group_id=excluded.group_id,origin_event_id=excluded.origin_event_id,requested_at=excluded.requested_at,blocked_since=excluded.blocked_since,pause_until=excluded.pause_until,active_deadline=excluded.active_deadline,checkpoint=excluded.checkpoint,wait_for_transitioning=excluded.wait_for_transitioning,status=excluded.status,status_reason=excluded.status_reason,strategy=excluded.strategy,start_time=excluded.start_time,end_time=excluded.end_time,percentage_complete=excluded.percentage_complete,instances_to_update=excluded.instances_to_update,has_desired=excluded.has_desired,has_progress=excluded.has_progress,has_warm_progress=excluded.has_warm_progress,has_rollback=excluded.has_rollback,has_rollback_progress=excluded.has_rollback_progress,has_rollback_warm_progress=excluded.has_rollback_warm_progress,original_id=excluded.original_id,original_name=excluded.original_name,original_version=excluded.original_version,target_id=excluded.target_id,target_name=excluded.target_name,target_version=excluded.target_version,desired_id=excluded.desired_id,desired_name=excluded.desired_name,desired_version=excluded.desired_version,min_healthy=excluded.min_healthy,max_healthy=excluded.max_healthy,instance_warmup=excluded.instance_warmup,checkpoint_delay=excluded.checkpoint_delay,bake_time=excluded.bake_time,skip_matching=excluded.skip_matching,auto_rollback=excluded.auto_rollback,protected_instances=excluded.protected_instances,standby_instances=excluded.standby_instances,live_percentage=excluded.live_percentage,live_remaining=excluded.live_remaining,warm_percentage=excluded.warm_percentage,warm_remaining=excluded.warm_remaining,rollback_live_percentage=excluded.rollback_live_percentage,rollback_live_remaining=excluded.rollback_live_remaining,rollback_warm_percentage=excluded.rollback_warm_percentage,rollback_warm_remaining=excluded.rollback_warm_remaining,rollback_reason=excluded.rollback_reason,rollback_start=excluded.rollback_start,rollback_percentage=excluded.rollback_percentage,rollback_remaining=excluded.rollback_remaining
RETURNING refresh_pk;

-- name: ListRefreshMembers :many
SELECT * FROM asg_refresh_members WHERE refresh_pk=? ORDER BY position;
-- name: DeleteRefreshMembers :exec
DELETE FROM asg_refresh_members WHERE refresh_pk=?;
-- name: PutRefreshMember :exec
INSERT INTO asg_refresh_members (refresh_pk,position,instance_id,warm) VALUES (?,?,?,?);

-- name: ListRefreshCheckpoints :many
SELECT * FROM asg_refresh_checkpoints WHERE refresh_pk=? ORDER BY position;
-- name: DeleteRefreshCheckpoints :exec
DELETE FROM asg_refresh_checkpoints WHERE refresh_pk=?;
-- name: PutRefreshCheckpoint :exec
INSERT INTO asg_refresh_checkpoints (refresh_pk,position,percentage) VALUES (?,?,?);

-- name: ListRefreshAlarms :many
SELECT * FROM asg_refresh_alarms WHERE refresh_pk=? ORDER BY position;
-- name: DeleteRefreshAlarms :exec
DELETE FROM asg_refresh_alarms WHERE refresh_pk=?;
-- name: PutRefreshAlarm :exec
INSERT INTO asg_refresh_alarms (refresh_pk,position,name) VALUES (?,?,?);

