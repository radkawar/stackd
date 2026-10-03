-- name: GetCluster :one
SELECT * FROM ecs_clusters WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListClusters :many
SELECT * FROM ecs_clusters
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND name > CAST(sqlc.arg(after_name) AS TEXT)
 AND (CAST(sqlc.arg(include_inactive) AS INTEGER) <> 0 OR status = 'ACTIVE')
ORDER BY name LIMIT sqlc.arg(row_limit);

-- name: ListActiveClusterKeys :many
SELECT region, name FROM ecs_clusters
WHERE partition = ? AND account_id = ? AND status = 'ACTIVE'
ORDER BY region, name;

-- name: PutCluster :exec
INSERT INTO ecs_clusters (
 partition, account_id, region, name, cluster_arn, cluster_name, status,
 active_services_count, pending_tasks_count, registered_container_instances_count, running_tasks_count,
 attachments_status, attachments, configuration, default_capacity_provider_strategy,
 service_connect_defaults, settings, statistics, capacity_providers_present, created, updated
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
 cluster_arn = excluded.cluster_arn, cluster_name = excluded.cluster_name, status = excluded.status,
 active_services_count = excluded.active_services_count, pending_tasks_count = excluded.pending_tasks_count,
 registered_container_instances_count = excluded.registered_container_instances_count,
 running_tasks_count = excluded.running_tasks_count, attachments_status = excluded.attachments_status,
 attachments = excluded.attachments, configuration = excluded.configuration,
 default_capacity_provider_strategy = excluded.default_capacity_provider_strategy,
 service_connect_defaults = excluded.service_connect_defaults, settings = excluded.settings,
 statistics = excluded.statistics, capacity_providers_present = excluded.capacity_providers_present,
 created = excluded.created, updated = excluded.updated;

-- name: GetClusterCreateInput :one
SELECT * FROM ecs_cluster_create_inputs WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutClusterCreateInput :exec
INSERT INTO ecs_cluster_create_inputs (
 partition, account_id, region, name, cluster_name, configuration, default_capacity_provider_strategy,
 service_connect_defaults, settings, capacity_providers_present, tags_present
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
 cluster_name = excluded.cluster_name, configuration = excluded.configuration,
 default_capacity_provider_strategy = excluded.default_capacity_provider_strategy,
 service_connect_defaults = excluded.service_connect_defaults, settings = excluded.settings,
 capacity_providers_present = excluded.capacity_providers_present, tags_present = excluded.tags_present;

-- name: ListClusterCapacityProviders :many
SELECT provider FROM ecs_cluster_capacity_providers
WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND original = ? ORDER BY position;

-- name: DeleteClusterCapacityProviders :exec
DELETE FROM ecs_cluster_capacity_providers WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutClusterCapacityProvider :exec
INSERT INTO ecs_cluster_capacity_providers (partition, account_id, region, name, original, position, provider)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListClusterCreateTags :many
SELECT key, value FROM ecs_cluster_create_tags
WHERE partition = ? AND account_id = ? AND region = ? AND name = ? ORDER BY position;

-- name: DeleteClusterCreateTags :exec
DELETE FROM ecs_cluster_create_tags WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutClusterCreateTag :exec
INSERT INTO ecs_cluster_create_tags (partition, account_id, region, name, position, key, value) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetTaskDefinition :one
SELECT * FROM ecs_task_definitions WHERE partition = ? AND account_id = ? AND region = ? AND family = ? AND revision = ?;

-- name: DeleteTaskDefinition :exec
DELETE FROM ecs_task_definitions WHERE partition = ? AND account_id = ? AND region = ? AND family = ? AND revision = ?;

-- Bind direction before ORDER BY; SQLC leaves argument macros in sort expressions.
-- name: ListTaskDefinitions :many
WITH ordering AS (SELECT CAST(sqlc.arg(descending) AS INTEGER) AS reverse)
SELECT ecs_task_definitions.* FROM ecs_task_definitions CROSS JOIN ordering
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND (CAST(sqlc.arg(exact_family) AS TEXT) = '' OR family = CAST(sqlc.arg(exact_family) AS TEXT))
 AND substr(family, 1, length(CAST(sqlc.arg(family_prefix) AS TEXT))) = CAST(sqlc.arg(family_prefix) AS TEXT)
 AND (CAST(sqlc.arg(task_status) AS TEXT) = '' OR status = CAST(sqlc.arg(task_status) AS TEXT))
 AND (CAST(sqlc.arg(after_family) AS TEXT) = ''
  OR (CAST(sqlc.arg(descending) AS INTEGER) = 0 AND (family > CAST(sqlc.arg(after_family) AS TEXT)
   OR (family = CAST(sqlc.arg(after_family) AS TEXT) AND revision > CAST(sqlc.arg(after_revision) AS INTEGER))))
  OR (CAST(sqlc.arg(descending) AS INTEGER) <> 0 AND (family < CAST(sqlc.arg(after_family) AS TEXT)
   OR (family = CAST(sqlc.arg(after_family) AS TEXT) AND revision < CAST(sqlc.arg(after_revision) AS INTEGER)))))
ORDER BY
 CASE WHEN ordering.reverse = 0 THEN family END ASC,
 CASE WHEN ordering.reverse = 0 THEN revision END ASC,
 CASE WHEN ordering.reverse <> 0 THEN family END DESC,
 CASE WHEN ordering.reverse <> 0 THEN revision END DESC
LIMIT sqlc.arg(row_limit);

-- name: PutTaskDefinition :exec
INSERT INTO ecs_task_definitions (
 partition, account_id, region, family, revision, task_definition_arn, task_family, task_revision, status,
 cpu, memory, network_mode, ipc_mode, pid_mode, execution_role_arn, task_role_arn, registered_by,
 registered_at, deregistered_at, delete_requested_at, enable_fault_injection,
 container_definitions, ephemeral_storage, inference_accelerators, placement_constraints,
 proxy_configuration, requires_attributes, runtime_platform, volumes,
 compatibilities_present, requires_compatibilities_present
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, family, revision) DO UPDATE SET
 task_definition_arn = excluded.task_definition_arn, task_family = excluded.task_family,
 task_revision = excluded.task_revision, status = excluded.status, cpu = excluded.cpu, memory = excluded.memory,
 network_mode = excluded.network_mode, ipc_mode = excluded.ipc_mode, pid_mode = excluded.pid_mode,
 execution_role_arn = excluded.execution_role_arn, task_role_arn = excluded.task_role_arn,
 registered_by = excluded.registered_by, registered_at = excluded.registered_at,
 deregistered_at = excluded.deregistered_at, delete_requested_at = excluded.delete_requested_at,
 enable_fault_injection = excluded.enable_fault_injection, container_definitions = excluded.container_definitions,
 ephemeral_storage = excluded.ephemeral_storage, inference_accelerators = excluded.inference_accelerators,
 placement_constraints = excluded.placement_constraints, proxy_configuration = excluded.proxy_configuration,
 requires_attributes = excluded.requires_attributes, runtime_platform = excluded.runtime_platform,
 volumes = excluded.volumes, compatibilities_present = excluded.compatibilities_present,
 requires_compatibilities_present = excluded.requires_compatibilities_present;

-- name: NextTaskDefinitionRevision :one
INSERT INTO ecs_task_definition_revisions (partition, account_id, region, family, revision)
VALUES (?, ?, ?, ?, 1)
ON CONFLICT(partition, account_id, region, family) DO UPDATE SET revision = revision + 1
WHERE revision < 2147483647
RETURNING revision;

-- name: ListTaskDefinitionCompatibilities :many
SELECT compatibility FROM ecs_task_definition_compatibilities
WHERE partition = ? AND account_id = ? AND region = ? AND family = ? AND revision = ? AND required = ? ORDER BY position;

-- name: DeleteTaskDefinitionCompatibilities :exec
DELETE FROM ecs_task_definition_compatibilities WHERE partition = ? AND account_id = ? AND region = ? AND family = ? AND revision = ?;

-- name: PutTaskDefinitionCompatibility :exec
INSERT INTO ecs_task_definition_compatibilities (partition, account_id, region, family, revision, required, position, compatibility)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetTagSet :one
SELECT tags_present FROM ecs_tag_sets WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ?;

-- name: DeleteTagSet :exec
DELETE FROM ecs_tag_sets WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ?;

-- name: PutTagSet :exec
INSERT INTO ecs_tag_sets (partition, account_id, region, resource_arn, tags_present) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, resource_arn) DO UPDATE SET tags_present = excluded.tags_present;

-- name: ListTags :many
SELECT key, value FROM ecs_tags WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ? ORDER BY position;

-- name: DeleteTags :exec
DELETE FROM ecs_tags WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ?;

-- name: PutTag :exec
INSERT INTO ecs_tags (partition, account_id, region, resource_arn, position, key, value) VALUES (?, ?, ?, ?, ?, ?, ?);
