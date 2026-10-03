-- name: NextMetricPublication :one
SELECT partition, account_id, region, cluster_name, service_name, due
FROM ecs_service_metric_samples
ORDER BY due, partition, account_id, region, cluster_name, service_name LIMIT 1;

-- name: MetricSamples :many
SELECT metric_name, task_id, resolution_seconds, minimum, maximum, observation_sum, observation_count
FROM ecs_service_metric_samples
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? AND due = ?
ORDER BY metric_name, task_id, resolution_seconds;

-- name: AddMetricSample :exec
INSERT INTO ecs_service_metric_samples (
 partition, account_id, region, cluster_name, service_name, due,
 metric_name, task_id, resolution_seconds, minimum, maximum, observation_sum, observation_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, cluster_name, service_name, due, metric_name, task_id, resolution_seconds)
DO UPDATE SET
 minimum = MIN(ecs_service_metric_samples.minimum, excluded.minimum),
 maximum = MAX(ecs_service_metric_samples.maximum, excluded.maximum),
 observation_sum = ecs_service_metric_samples.observation_sum + excluded.observation_sum,
 observation_count = ecs_service_metric_samples.observation_count + excluded.observation_count;

-- name: DeleteMetricPublication :exec
DELETE FROM ecs_service_metric_samples
WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND service_name = ? AND due = ?;
