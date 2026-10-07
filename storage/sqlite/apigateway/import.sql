-- name: ListBinaryMediaTypes :many
SELECT * FROM apigateway_binary_media_types WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY ordinal;

-- name: DeleteBinaryMediaTypes :exec
DELETE FROM apigateway_binary_media_types WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ?;

-- name: PutBinaryMediaTypes :exec
INSERT INTO apigateway_binary_media_types (partition, account_id, region, api_id, ordinal, media_type) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListGatewayResponses :many
SELECT * FROM apigateway_gateway_responses WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY response_type;

-- name: DeleteGatewayResponses :exec
DELETE FROM apigateway_gateway_responses WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ?;

-- name: PutGatewayResponses :exec
INSERT INTO apigateway_gateway_responses (partition, account_id, region, api_id, response_type, status_code) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListGatewayHeaders :many
SELECT * FROM apigateway_gateway_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND response_type = ? ORDER BY name;

-- name: DeleteGatewayHeaders :exec
DELETE FROM apigateway_gateway_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND response_type = ?;

-- name: PutGatewayHeaders :exec
INSERT INTO apigateway_gateway_headers (partition, account_id, region, api_id, response_type, name, value) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListGatewayTemplates :many
SELECT * FROM apigateway_gateway_templates WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND response_type = ? ORDER BY media_type;

-- name: DeleteGatewayTemplates :exec
DELETE FROM apigateway_gateway_templates WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND response_type = ?;

-- name: PutGatewayTemplates :exec
INSERT INTO apigateway_gateway_templates (partition, account_id, region, api_id, response_type, media_type, template) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListMockIntegrations :many
SELECT * FROM apigateway_mock_integrations WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ? ORDER BY partition, account_id, region, api_id, resource_id, http_method;

-- name: DeleteMockIntegrations :exec
DELETE FROM apigateway_mock_integrations WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutMockIntegrations :exec
INSERT INTO apigateway_mock_integrations (partition, account_id, region, api_id, resource_id, http_method, status_code, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListMockIntegrationHeaders :many
SELECT * FROM apigateway_mock_integration_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ? ORDER BY name;

-- name: DeleteMockIntegrationHeaders :exec
DELETE FROM apigateway_mock_integration_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutMockIntegrationHeaders :exec
INSERT INTO apigateway_mock_integration_headers (partition, account_id, region, api_id, resource_id, http_method, name, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListMockRoutes :many
SELECT * FROM apigateway_mock_routes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ? ORDER BY partition, account_id, region, api_id, deployment_id, resource_id, http_method;

-- name: DeleteMockRoutes :exec
DELETE FROM apigateway_mock_routes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutMockRoutes :exec
INSERT INTO apigateway_mock_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method, status_code, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListMockRouteHeaders :many
SELECT * FROM apigateway_mock_route_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ? ORDER BY name;

-- name: DeleteMockRouteHeaders :exec
DELETE FROM apigateway_mock_route_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutMockRouteHeaders :exec
INSERT INTO apigateway_mock_route_headers (partition, account_id, region, api_id, deployment_id, resource_id, http_method, name, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListMethodResponses :many
SELECT * FROM apigateway_method_responses WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ? ORDER BY status_code;

-- name: DeleteMethodResponses :exec
DELETE FROM apigateway_method_responses WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutMethodResponses :exec
INSERT INTO apigateway_method_responses (partition, account_id, region, api_id, resource_id, http_method, status_code) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListMethodResponseHeaders :many
SELECT * FROM apigateway_method_response_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ? AND status_code = ? ORDER BY name;

-- name: DeleteMethodResponseHeaders :exec
DELETE FROM apigateway_method_response_headers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ? AND status_code = ?;

-- name: PutMethodResponseHeaders :exec
INSERT INTO apigateway_method_response_headers (partition, account_id, region, api_id, resource_id, http_method, status_code, name, required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
