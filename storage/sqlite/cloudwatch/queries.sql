-- name: GetMetric :one
SELECT * FROM cloudwatch_metrics
WHERE partition = ? AND account_id = ? AND region = ? AND namespace = ? AND name = ? AND dimensions = ?;

-- name: ListMetrics :many
SELECT * FROM cloudwatch_metrics
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND (sqlc.arg(namespace) = '' OR namespace = sqlc.arg(namespace))
 AND (sqlc.arg(name) = '' OR name = sqlc.arg(name))
 AND (CAST(sqlc.arg(has_published_after) AS INTEGER) = 0 OR published_at > sqlc.arg(published_after))
 AND (CAST(sqlc.arg(has_after) AS INTEGER) = 0 OR
      (namespace, name, dimensions) > (sqlc.arg(after_namespace), sqlc.arg(after_name), sqlc.arg(after_dimensions)))
ORDER BY namespace, name, dimensions LIMIT sqlc.arg(page_limit);

-- name: PutMetric :exec
INSERT INTO cloudwatch_metrics (partition, account_id, region, namespace, name, dimensions, id, created, published_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, namespace, name, dimensions) DO UPDATE SET published_at=excluded.published_at;

-- name: ListDimensions :many
SELECT name, value FROM cloudwatch_dimensions WHERE metric_id = ? ORDER BY name;

-- name: DeleteDimensions :exec
DELETE FROM cloudwatch_dimensions WHERE metric_id = ?;

-- name: PutDimension :exec
INSERT INTO cloudwatch_dimensions (metric_id, name, value) VALUES (?, ?, ?);

-- name: ListPoints :many
SELECT * FROM cloudwatch_points
WHERE metric_id = sqlc.arg(metric_id)
 AND timestamp >= sqlc.arg(start_time) AND timestamp < sqlc.arg(end_time)
 AND sequence > sqlc.arg(after_sequence)
ORDER BY sequence LIMIT sqlc.arg(page_limit);

-- name: AppendPoint :exec
INSERT INTO cloudwatch_points (metric_id, timestamp, unit, resolution, sample_count, sum, minimum, maximum, raw)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
