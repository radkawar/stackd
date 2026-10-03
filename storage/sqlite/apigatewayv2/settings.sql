-- name: ListRouteSettings :many
SELECT route_key, detailed_metrics, logging_level, data_trace FROM apigatewayv2_route_settings
WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND stage = ?
ORDER BY route_key;

-- name: PutRouteSettings :exec
INSERT INTO apigatewayv2_route_settings (partition, account_id, region, gateway_id, stage, route_key, detailed_metrics, logging_level, data_trace)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteRouteSettings :exec
DELETE FROM apigatewayv2_route_settings
WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND stage = ?;
