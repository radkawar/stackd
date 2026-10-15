-- name: GetServiceDeploymentHistoryPresence :one
SELECT deployment_history_present FROM ecs_services
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ?;

-- name: SetServiceDeploymentHistoryPresence :exec
UPDATE ecs_services SET deployment_history_present = ?
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ?;

-- name: ListServiceDeploymentFinishTimes :many
SELECT position, finished_at FROM ecs_service_deployments
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? ORDER BY position;

-- name: SetServiceDeploymentFinishedAt :exec
UPDATE ecs_service_deployments SET finished_at = ?
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? AND position = ?;

-- name: ListServiceDeploymentHistory :many
SELECT * FROM ecs_service_deployment_history
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? ORDER BY position;

-- name: DeleteServiceDeploymentHistory :exec
DELETE FROM ecs_service_deployment_history
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ?;

-- name: PutServiceDeploymentHistory :exec
INSERT INTO ecs_service_deployment_history (
 partition, account_id, region, cluster_name, service_name, position,
 service_deployment_arn, service_arn, cluster_arn, created_at, started_at, updated_at,
 finished_at, stopped_at, status, status_reason, target_service_revision
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
