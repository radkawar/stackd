-- name: ListMethodSettings :many
SELECT method_key, metrics_enabled, logging_level, data_trace_enabled FROM apigateway_method_settings
WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND stage = ?
ORDER BY method_key;

-- name: PutMethodSettings :exec
INSERT INTO apigateway_method_settings (partition, account_id, region, api_id, stage, method_key, metrics_enabled, logging_level, data_trace_enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteMethodSettings :exec
DELETE FROM apigateway_method_settings
WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND stage = ?;
