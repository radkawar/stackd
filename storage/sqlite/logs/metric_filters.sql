-- name: GetMetricFilter :one
SELECT f.*, g.name AS group_name FROM logs_metric_filters f
JOIN logs_groups g ON g.id = f.group_id
WHERE f.group_id = ? AND f.name = ?;

-- name: ListMetricFilters :many
SELECT f.*, g.name AS group_name FROM logs_metric_filters f
JOIN logs_groups g ON g.id = f.group_id
WHERE g.partition = sqlc.arg(partition) AND g.account_id = sqlc.arg(account_id) AND g.region = sqlc.arg(region)
 AND (sqlc.arg(group_id) = '' OR f.group_id = sqlc.arg(group_id))
 AND substr(f.name, 1, length(sqlc.arg(prefix))) = sqlc.arg(prefix)
 AND (sqlc.arg(metric_name) = '' OR f.metric_name = sqlc.arg(metric_name))
 AND (sqlc.arg(metric_namespace) = '' OR f.metric_namespace = sqlc.arg(metric_namespace))
 AND (f.name, g.name) > (sqlc.arg(after_name), sqlc.arg(after_group_name))
ORDER BY f.name, g.name LIMIT sqlc.arg(page_limit);

-- name: PutMetricFilter :exec
INSERT INTO logs_metric_filters (group_id, name, pattern, metric_namespace, metric_name, metric_value, unit, default_value, apply_on_transformed_logs, field_selection, created, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(group_id, name) DO UPDATE SET pattern=excluded.pattern,
 metric_namespace=excluded.metric_namespace, metric_name=excluded.metric_name, metric_value=excluded.metric_value,
 unit=excluded.unit, default_value=excluded.default_value,
 apply_on_transformed_logs=excluded.apply_on_transformed_logs, field_selection=excluded.field_selection, created=excluded.created, cfn_owner=excluded.cfn_owner;

-- name: DeleteMetricFilter :exec
DELETE FROM logs_metric_filters WHERE group_id = ? AND name = ?;

-- name: MetricFilterDimensions :many
SELECT name, value FROM logs_metric_filter_dimensions WHERE group_id = ? AND filter_name = ? ORDER BY name;

-- name: DeleteMetricFilterDimensions :exec
DELETE FROM logs_metric_filter_dimensions WHERE group_id = ? AND filter_name = ?;

-- name: PutMetricFilterDimension :exec
INSERT INTO logs_metric_filter_dimensions (group_id, filter_name, name, value) VALUES (?, ?, ?, ?);

-- name: MetricFilterSystemFields :many
SELECT field FROM logs_metric_filter_system_fields WHERE group_id = ? AND filter_name = ? ORDER BY ordinal;

-- name: DeleteMetricFilterSystemFields :exec
DELETE FROM logs_metric_filter_system_fields WHERE group_id = ? AND filter_name = ?;

-- name: PutMetricFilterSystemField :exec
INSERT INTO logs_metric_filter_system_fields (group_id, filter_name, ordinal, field) VALUES (?, ?, ?, ?);
