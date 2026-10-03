-- name: GetServiceRevision :one
SELECT * FROM ecs_service_revisions
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? AND revision_id = ?;

-- name: PutServiceRevision :exec
INSERT INTO ecs_service_revisions (
 partition, account_id, region, cluster_name, service_name, revision_id,
 created_at, task_definition, launch_type, platform_family, platform_version, guard_duty_enabled,
 capacity_provider_strategy, container_images, ecs_managed_resources, fargate_ephemeral_storage,
 load_balancers, monitoring, network_configuration, overrides, resolved_configuration,
 service_connect_configuration, service_registries, volume_configurations, vpc_lattice_configurations
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, cluster_name, service_name, revision_id) DO NOTHING;

-- name: DeleteServiceRevisions :exec
DELETE FROM ecs_service_revisions
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ?;
