-- name: NextMetricPublication :one
SELECT partition, account_id, region, api_id, minute, protocol_type, api_name, stage, method, resource, route
FROM apigateway_metric_samples
ORDER BY minute, partition, account_id, region, api_id, protocol_type, api_name, stage, method, resource, route
LIMIT 1;

-- name: ListMetricSamples :many
SELECT metric_name, value, sample_count FROM apigateway_metric_samples
WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND minute = ?
    AND protocol_type = ? AND api_name = ? AND stage = ? AND method = ? AND resource = ? AND route = ?
ORDER BY metric_name, value;

-- name: PutMetricSample :exec
INSERT INTO apigateway_metric_samples
    (partition, account_id, region, api_id, minute, protocol_type, api_name, stage, method, resource, route, metric_name, value, sample_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, minute, protocol_type, api_name, stage, method, resource, route, metric_name, value)
DO UPDATE SET sample_count = sample_count + excluded.sample_count;

-- name: DeleteMetricPublication :exec
DELETE FROM apigateway_metric_samples
WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND minute = ?
    AND protocol_type = ? AND api_name = ? AND stage = ? AND method = ? AND resource = ? AND route = ?;
