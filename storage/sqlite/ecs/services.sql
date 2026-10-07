-- name: GetService :one
SELECT * FROM ecs_services WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ?;

-- name: ListServices :many
SELECT * FROM ecs_services
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND cluster_name = sqlc.arg(cluster_name)
 AND service_name > CAST(sqlc.arg(after_name) AS TEXT)
 AND (CAST(sqlc.arg(include_inactive) AS INTEGER) <> 0 OR service_status = 'ACTIVE')
 AND (CAST(sqlc.arg(launch_type) AS TEXT) = '' OR service_effective_launch_type = CAST(sqlc.arg(launch_type) AS TEXT))
 AND (CAST(sqlc.arg(scheduling_strategy) AS TEXT) = '' OR service_scheduling_strategy = CAST(sqlc.arg(scheduling_strategy) AS TEXT))
ORDER BY service_name LIMIT sqlc.arg(row_limit);

-- name: ListActiveServiceKeys :many
SELECT partition, account_id, region, cluster_name, service_name FROM ecs_services
WHERE service_status IN ('ACTIVE', 'DRAINING')
ORDER BY partition, account_id, region, cluster_name, service_name;

-- name: PutService :exec
INSERT INTO ecs_services (
 ownership,
 partition,
 account_id,
 region,
 cluster_name,
 service_name,
 service_availability_zone_rebalancing,
 service_capacity_provider_strategy,
 service_cluster_arn,
 service_created_at,
 service_created_by,
 service_current_service_deployment,
 service_current_service_revisions,
 service_deployment_configuration,
 service_deployment_controller,
 service_desired_count,
 service_enable_ecs_managed_tags,
 service_enable_execute_command,
 service_events,
 service_health_check_grace_period_seconds,
 service_launch_type,
 service_load_balancers,
 service_network_configuration,
 service_pending_count,
 service_placement_constraints,
 service_placement_strategy,
 service_platform_family,
 service_platform_version,
 service_propagate_tags,
 service_resource_management_type,
 service_role_arn,
 service_running_count,
 service_scheduling_strategy,
 service_service_arn,
 service_service_name,
 service_service_registries,
 service_status,
 service_task_definition,
 service_task_sets,
 create_availability_zone_rebalancing,
 create_capacity_provider_strategy,
 create_client_token,
 create_cluster,
 create_deployment_configuration,
 create_deployment_controller,
 create_desired_count,
 create_enable_ecs_managed_tags,
 create_enable_execute_command,
 create_health_check_grace_period_seconds,
 create_launch_type,
 create_load_balancers,
 create_monitoring,
 create_network_configuration,
 create_placement_constraints,
 create_placement_strategy,
 create_platform_version,
 create_propagate_tags,
 create_role,
 create_scheduling_strategy,
 create_service_connect_configuration,
 create_service_name,
 create_service_registries,
 create_tags,
 create_task_definition,
 create_volume_configurations,
 create_vpc_lattice_configurations,
 accepted_event_id,
 drain_after,
 deployments_present,
 service_effective_launch_type,
 next_metric_collection
) VALUES (
 ?,
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
 , ?, ?
)
ON CONFLICT(partition, account_id, region, cluster_name, service_name) DO UPDATE SET
 ownership = excluded.ownership,
 service_availability_zone_rebalancing = excluded.service_availability_zone_rebalancing,
 service_capacity_provider_strategy = excluded.service_capacity_provider_strategy,
 service_cluster_arn = excluded.service_cluster_arn,
 service_created_at = excluded.service_created_at,
 service_created_by = excluded.service_created_by,
 service_current_service_deployment = excluded.service_current_service_deployment,
 service_current_service_revisions = excluded.service_current_service_revisions,
 service_deployment_configuration = excluded.service_deployment_configuration,
 service_deployment_controller = excluded.service_deployment_controller,
 service_desired_count = excluded.service_desired_count,
 service_enable_ecs_managed_tags = excluded.service_enable_ecs_managed_tags,
 service_enable_execute_command = excluded.service_enable_execute_command,
 service_events = excluded.service_events,
 service_health_check_grace_period_seconds = excluded.service_health_check_grace_period_seconds,
 service_launch_type = excluded.service_launch_type,
 service_effective_launch_type = excluded.service_effective_launch_type,
 service_load_balancers = excluded.service_load_balancers,
 service_network_configuration = excluded.service_network_configuration,
 service_pending_count = excluded.service_pending_count,
 service_placement_constraints = excluded.service_placement_constraints,
 service_placement_strategy = excluded.service_placement_strategy,
 service_platform_family = excluded.service_platform_family,
 service_platform_version = excluded.service_platform_version,
 service_propagate_tags = excluded.service_propagate_tags,
 service_resource_management_type = excluded.service_resource_management_type,
 service_role_arn = excluded.service_role_arn,
 service_running_count = excluded.service_running_count,
 service_scheduling_strategy = excluded.service_scheduling_strategy,
 service_service_arn = excluded.service_service_arn,
 service_service_name = excluded.service_service_name,
 service_service_registries = excluded.service_service_registries,
 service_status = excluded.service_status,
 service_task_definition = excluded.service_task_definition,
 service_task_sets = excluded.service_task_sets,
 create_availability_zone_rebalancing = excluded.create_availability_zone_rebalancing,
 create_capacity_provider_strategy = excluded.create_capacity_provider_strategy,
 create_client_token = excluded.create_client_token,
 create_cluster = excluded.create_cluster,
 create_deployment_configuration = excluded.create_deployment_configuration,
 create_deployment_controller = excluded.create_deployment_controller,
 create_desired_count = excluded.create_desired_count,
 create_enable_ecs_managed_tags = excluded.create_enable_ecs_managed_tags,
 create_enable_execute_command = excluded.create_enable_execute_command,
 create_health_check_grace_period_seconds = excluded.create_health_check_grace_period_seconds,
 create_launch_type = excluded.create_launch_type,
 create_load_balancers = excluded.create_load_balancers,
 create_monitoring = excluded.create_monitoring,
 create_network_configuration = excluded.create_network_configuration,
 create_placement_constraints = excluded.create_placement_constraints,
 create_placement_strategy = excluded.create_placement_strategy,
 create_platform_version = excluded.create_platform_version,
 create_propagate_tags = excluded.create_propagate_tags,
 create_role = excluded.create_role,
 create_scheduling_strategy = excluded.create_scheduling_strategy,
 create_service_connect_configuration = excluded.create_service_connect_configuration,
 create_service_name = excluded.create_service_name,
 create_service_registries = excluded.create_service_registries,
 create_tags = excluded.create_tags,
 create_task_definition = excluded.create_task_definition,
 create_volume_configurations = excluded.create_volume_configurations,
 create_vpc_lattice_configurations = excluded.create_vpc_lattice_configurations,
 accepted_event_id = excluded.accepted_event_id,
 drain_after = excluded.drain_after,
 next_metric_collection = excluded.next_metric_collection,
 deployments_present = excluded.deployments_present;

-- name: ListServiceDeployments :many
SELECT * FROM ecs_service_deployments WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? ORDER BY position;

-- name: DeleteServiceDeployments :exec
DELETE FROM ecs_service_deployments WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ?;

-- name: PutServiceDeployment :exec
INSERT INTO ecs_service_deployments (
 partition,
 account_id,
 region,
 cluster_name,
 service_name,
 position,
 deployment_capacity_provider_strategy,
 deployment_created_at,
 deployment_desired_count,
 deployment_failed_tasks,
 deployment_fargate_ephemeral_storage,
 deployment_id,
 deployment_launch_type,
 deployment_network_configuration,
 deployment_pending_count,
 deployment_platform_family,
 deployment_platform_version,
 deployment_rollout_state,
 deployment_rollout_state_reason,
 deployment_running_count,
 deployment_service_connect_configuration,
 deployment_service_connect_resources,
 deployment_status,
 deployment_task_definition,
 deployment_updated_at,
 deployment_volume_configurations,
 deployment_vpc_lattice_configurations,
 definition_compatibilities,
 definition_container_definitions,
 definition_cpu,
 definition_delete_requested_at,
 definition_deregistered_at,
 definition_enable_fault_injection,
 definition_ephemeral_storage,
 definition_execution_role_arn,
 definition_family,
 definition_inference_accelerators,
 definition_ipc_mode,
 definition_memory,
 definition_network_mode,
 definition_pid_mode,
 definition_placement_constraints,
 definition_previous_status,
 definition_proxy_configuration,
 definition_registered_at,
 definition_registered_by,
 definition_requires_attributes,
 definition_requires_compatibilities,
 definition_revision,
 definition_runtime_platform,
 definition_status,
 definition_task_definition_arn,
 definition_task_role_arn,
 definition_volumes,
 input_capacity_provider_strategy,
 input_client_token,
 input_cluster,
 input_count,
 input_enable_ecs_managed_tags,
 input_enable_execute_command,
 input_group,
 input_launch_type,
 input_network_configuration,
 input_overrides,
 input_placement_constraints,
 input_placement_strategy,
 input_platform_version,
 input_propagate_tags,
 input_reference_id,
 input_started_by,
 input_tags,
 input_task_definition,
 input_volume_configurations,
 accepted_event_id,
 failures,
 retry_after,
 deadline,
 completed,
 observed_tasks_present,
 resolved_images_present,
 monitoring,
 load_balancers
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
 , ?, ?, ?
);

-- name: ListServiceObservedTasks :many
SELECT task_id, status FROM ecs_service_observed_tasks WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? AND position = ? ORDER BY task_id;

-- name: PutServiceObservedTask :exec
INSERT INTO ecs_service_observed_tasks (
 partition,
 account_id,
 region,
 cluster_name,
 service_name,
 position,
 task_id,
 status
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?
);

-- name: ListServiceResolvedImages :many
SELECT container_name, image_reference FROM ecs_service_resolved_images WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? AND position = ? ORDER BY container_name;

-- name: PutServiceResolvedImage :exec
INSERT INTO ecs_service_resolved_images (
 partition, account_id, region, cluster_name, service_name, position, container_name, image_reference
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
