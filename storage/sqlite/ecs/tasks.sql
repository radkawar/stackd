-- name: GetTask :one
SELECT * FROM ecs_tasks WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND task_id = ?;

-- name: ListTasks :many
SELECT * FROM ecs_tasks
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND cluster_name = sqlc.arg(cluster_name)
 AND task_id > CAST(sqlc.arg(after_id) AS TEXT)
 AND (CAST(sqlc.arg(desired_status) AS TEXT) = '' OR task_desired_status = CAST(sqlc.arg(desired_status) AS TEXT))
 AND (CAST(sqlc.arg(family) AS TEXT) = '' OR definition_family = CAST(sqlc.arg(family) AS TEXT))
 AND (CAST(sqlc.arg(started_by) AS TEXT) = '' OR task_started_by = CAST(sqlc.arg(started_by) AS TEXT))
 AND (CAST(sqlc.arg(launch_type) AS TEXT) = '' OR task_launch_type = CAST(sqlc.arg(launch_type) AS TEXT))
 AND (CAST(sqlc.arg(service_name) AS TEXT) = '' OR service_name = CAST(sqlc.arg(service_name) AS TEXT))
 AND (CAST(sqlc.arg(active_only) AS INTEGER) = 0 OR task_last_status IS NULL OR task_last_status <> 'STOPPED')
ORDER BY task_id LIMIT sqlc.arg(row_limit);

-- name: ListActiveTaskKeys :many
SELECT partition, account_id, region, cluster_name, task_id FROM ecs_tasks
WHERE task_last_status IS NULL OR task_last_status <> 'STOPPED'
ORDER BY partition, account_id, region, cluster_name, task_id;

-- name: PutTask :exec
INSERT INTO ecs_tasks (
 service_name, service_deployment_id,
 partition, account_id, region, cluster_name, task_id, task_attachments, task_attributes, task_availability_zone, task_capacity_provider_name, task_cluster_arn, task_connectivity, task_connectivity_at, task_container_instance_arn, task_containers, task_cpu, task_created_at, task_desired_status, task_enable_execute_command, task_ephemeral_storage, task_execution_stopped_at, task_fargate_ephemeral_storage, task_group, task_health_status, task_inference_accelerators, task_last_status, task_launch_type, task_memory, task_overrides, task_platform_family, task_platform_version, task_pull_started_at, task_pull_stopped_at, task_started_at, task_started_by, task_stop_code, task_stopped_at, task_stopped_reason, task_stopping_at, task_task_arn, task_task_definition_arn, task_version, definition_compatibilities, definition_container_definitions, definition_cpu, definition_delete_requested_at, definition_deregistered_at, definition_enable_fault_injection, definition_ephemeral_storage, definition_execution_role_arn, definition_family, definition_inference_accelerators, definition_ipc_mode, definition_memory, definition_network_mode, definition_pid_mode, definition_placement_constraints, definition_previous_status, definition_proxy_configuration, definition_registered_at, definition_registered_by, definition_requires_attributes, definition_requires_compatibilities, definition_revision, definition_runtime_platform, definition_status, definition_task_definition_arn, definition_task_role_arn, definition_volumes, network_configuration, accepted_event_id, credential_token, metadata_tokens, log_cursors, dependency_wait_started
) VALUES (
 ?, ?,
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT(partition, account_id, region, cluster_name, task_id) DO UPDATE SET
 service_name = excluded.service_name,
 service_deployment_id = excluded.service_deployment_id,
 task_attachments = excluded.task_attachments,
 task_attributes = excluded.task_attributes,
 task_availability_zone = excluded.task_availability_zone,
 task_capacity_provider_name = excluded.task_capacity_provider_name,
 task_cluster_arn = excluded.task_cluster_arn,
 task_connectivity = excluded.task_connectivity,
 task_connectivity_at = excluded.task_connectivity_at,
 task_container_instance_arn = excluded.task_container_instance_arn,
 task_containers = excluded.task_containers,
 task_cpu = excluded.task_cpu,
 task_created_at = excluded.task_created_at,
 task_desired_status = excluded.task_desired_status,
 task_enable_execute_command = excluded.task_enable_execute_command,
 task_ephemeral_storage = excluded.task_ephemeral_storage,
 task_execution_stopped_at = excluded.task_execution_stopped_at,
 task_fargate_ephemeral_storage = excluded.task_fargate_ephemeral_storage,
 task_group = excluded.task_group,
 task_health_status = excluded.task_health_status,
 task_inference_accelerators = excluded.task_inference_accelerators,
 task_last_status = excluded.task_last_status,
 task_launch_type = excluded.task_launch_type,
 task_memory = excluded.task_memory,
 task_overrides = excluded.task_overrides,
 task_platform_family = excluded.task_platform_family,
 task_platform_version = excluded.task_platform_version,
 task_pull_started_at = excluded.task_pull_started_at,
 task_pull_stopped_at = excluded.task_pull_stopped_at,
 task_started_at = excluded.task_started_at,
 task_started_by = excluded.task_started_by,
 task_stop_code = excluded.task_stop_code,
 task_stopped_at = excluded.task_stopped_at,
 task_stopped_reason = excluded.task_stopped_reason,
 task_stopping_at = excluded.task_stopping_at,
 task_task_arn = excluded.task_task_arn,
 task_task_definition_arn = excluded.task_task_definition_arn,
 task_version = excluded.task_version,
 definition_compatibilities = excluded.definition_compatibilities,
 definition_container_definitions = excluded.definition_container_definitions,
 definition_cpu = excluded.definition_cpu,
 definition_delete_requested_at = excluded.definition_delete_requested_at,
 definition_deregistered_at = excluded.definition_deregistered_at,
 definition_enable_fault_injection = excluded.definition_enable_fault_injection,
 definition_ephemeral_storage = excluded.definition_ephemeral_storage,
 definition_execution_role_arn = excluded.definition_execution_role_arn,
 definition_family = excluded.definition_family,
 definition_inference_accelerators = excluded.definition_inference_accelerators,
 definition_ipc_mode = excluded.definition_ipc_mode,
 definition_memory = excluded.definition_memory,
 definition_network_mode = excluded.definition_network_mode,
 definition_pid_mode = excluded.definition_pid_mode,
 definition_placement_constraints = excluded.definition_placement_constraints,
 definition_previous_status = excluded.definition_previous_status,
 definition_proxy_configuration = excluded.definition_proxy_configuration,
 definition_registered_at = excluded.definition_registered_at,
 definition_registered_by = excluded.definition_registered_by,
 definition_requires_attributes = excluded.definition_requires_attributes,
 definition_requires_compatibilities = excluded.definition_requires_compatibilities,
 definition_revision = excluded.definition_revision,
 definition_runtime_platform = excluded.definition_runtime_platform,
 definition_status = excluded.definition_status,
 definition_task_definition_arn = excluded.definition_task_definition_arn,
 definition_task_role_arn = excluded.definition_task_role_arn,
 definition_volumes = excluded.definition_volumes,
 network_configuration = excluded.network_configuration,
 accepted_event_id = excluded.accepted_event_id,
 credential_token = excluded.credential_token,
 metadata_tokens = excluded.metadata_tokens,
 log_cursors = excluded.log_cursors,
 dependency_wait_started = excluded.dependency_wait_started;

-- name: GetTaskRun :one
SELECT * FROM ecs_task_runs WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND client_token = ?;

-- name: PutTaskRun :exec
INSERT INTO ecs_task_runs (
 partition, account_id, region, cluster_name, client_token, input_capacity_provider_strategy, input_client_token, input_cluster, input_count, input_enable_ecs_managed_tags, input_enable_execute_command, input_group, input_launch_type, input_network_configuration, input_overrides, input_placement_constraints, input_placement_strategy, input_platform_version, input_propagate_tags, input_reference_id, input_started_by, input_tags, input_task_definition, input_volume_configurations, task_ids, created
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, cluster_name, client_token) DO UPDATE SET
 input_capacity_provider_strategy = excluded.input_capacity_provider_strategy,
 input_client_token = excluded.input_client_token,
 input_cluster = excluded.input_cluster,
 input_count = excluded.input_count,
 input_enable_ecs_managed_tags = excluded.input_enable_ecs_managed_tags,
 input_enable_execute_command = excluded.input_enable_execute_command,
 input_group = excluded.input_group,
 input_launch_type = excluded.input_launch_type,
 input_network_configuration = excluded.input_network_configuration,
 input_overrides = excluded.input_overrides,
 input_placement_constraints = excluded.input_placement_constraints,
 input_placement_strategy = excluded.input_placement_strategy,
 input_platform_version = excluded.input_platform_version,
 input_propagate_tags = excluded.input_propagate_tags,
 input_reference_id = excluded.input_reference_id,
 input_started_by = excluded.input_started_by,
 input_tags = excluded.input_tags,
 input_task_definition = excluded.input_task_definition,
 input_volume_configurations = excluded.input_volume_configurations,
 task_ids = excluded.task_ids,
 created = excluded.created;
