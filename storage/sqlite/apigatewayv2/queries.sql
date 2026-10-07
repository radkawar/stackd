-- name: GetAPI :one
SELECT * FROM apigatewayv2_api WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;

-- name: ListAPIs :many
SELECT * FROM apigatewayv2_api WHERE partition = ? AND account_id = ? AND region = ? ORDER BY id;

-- name: PutAPI :exec
INSERT INTO apigatewayv2_api (partition, account_id, region, id, name, description, version, disabled, created_at, tags, protocol_type, route_selection_expression, owner_stack_id, owner_logical_id, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, id) DO UPDATE SET name = excluded.name, description = excluded.description, version = excluded.version, disabled = excluded.disabled, created_at = excluded.created_at, tags = excluded.tags, protocol_type = excluded.protocol_type, route_selection_expression = excluded.route_selection_expression, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;

-- name: DeleteAPI :exec
DELETE FROM apigatewayv2_api WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;

-- name: GetIntegration :one
SELECT * FROM apigatewayv2_integration WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: ListIntegrations :many
SELECT * FROM apigatewayv2_integration WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? ORDER BY id;

-- name: PutIntegration :exec
INSERT INTO apigatewayv2_integration (partition, account_id, region, gateway_id, id, description, uri, payload_version, timeout_millis, passthrough_behavior, credentials_arn, owner_stack_id, owner_logical_id, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, gateway_id, id) DO UPDATE SET description = excluded.description, uri = excluded.uri, payload_version = excluded.payload_version, timeout_millis = excluded.timeout_millis, passthrough_behavior = excluded.passthrough_behavior, credentials_arn = excluded.credentials_arn, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;

-- name: DeleteIntegration :exec
DELETE FROM apigatewayv2_integration WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: GetAuthorizer :one
SELECT * FROM apigatewayv2_authorizer WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: ListAuthorizers :many
SELECT * FROM apigatewayv2_authorizer WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? ORDER BY id;

-- name: PutAuthorizer :exec
INSERT INTO apigatewayv2_authorizer (partition, account_id, region, gateway_id, id, name, issuer, audiences, authorizer_type, uri, function_arn, payload_version, identity_sources, ttl_seconds, simple_responses, credentials_arn, validation_expression, owner_stack_id, owner_logical_id, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, gateway_id, id) DO UPDATE SET name = excluded.name, issuer = excluded.issuer, audiences = excluded.audiences, authorizer_type = excluded.authorizer_type, uri = excluded.uri, function_arn = excluded.function_arn, payload_version = excluded.payload_version, identity_sources = excluded.identity_sources, ttl_seconds = excluded.ttl_seconds, simple_responses = excluded.simple_responses, credentials_arn = excluded.credentials_arn, validation_expression = excluded.validation_expression, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;

-- name: DeleteAuthorizer :exec
DELETE FROM apigatewayv2_authorizer WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: GetRoute :one
SELECT * FROM apigatewayv2_route WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: ListRoutes :many
SELECT * FROM apigatewayv2_route WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? ORDER BY id;

-- name: PutRoute :exec
INSERT INTO apigatewayv2_route (partition, account_id, region, gateway_id, id, route_key, target, authorization_type, authorizer_id, operation_name, scopes, route_response_selection_expression, owner_stack_id, owner_logical_id, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, gateway_id, id) DO UPDATE SET route_key = excluded.route_key, target = excluded.target, authorization_type = excluded.authorization_type, authorizer_id = excluded.authorizer_id, operation_name = excluded.operation_name, scopes = excluded.scopes, route_response_selection_expression = excluded.route_response_selection_expression, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;

-- name: DeleteRoute :exec
DELETE FROM apigatewayv2_route WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: GetStage :one
SELECT * FROM apigatewayv2_stage WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: ListStages :many
SELECT * FROM apigatewayv2_stage WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? ORDER BY id;

-- name: PutStage :exec
INSERT INTO apigatewayv2_stage (partition, account_id, region, gateway_id, id, description, deployment_id, last_deployment_status_message, auto_deploy, created_at, updated_at, variables, tags, detailed_metrics, logging_level, data_trace, access_log_destination_arn, access_log_format, owner_stack_id, owner_logical_id, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, gateway_id, id) DO UPDATE SET description = excluded.description, deployment_id = excluded.deployment_id, last_deployment_status_message = excluded.last_deployment_status_message, auto_deploy = excluded.auto_deploy, created_at = excluded.created_at, updated_at = excluded.updated_at, variables = excluded.variables, tags = excluded.tags, detailed_metrics = excluded.detailed_metrics, logging_level = excluded.logging_level, data_trace = excluded.data_trace, access_log_destination_arn = excluded.access_log_destination_arn, access_log_format = excluded.access_log_format, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;

-- name: DeleteStage :exec
DELETE FROM apigatewayv2_stage WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: GetDeployment :one
SELECT * FROM apigatewayv2_deployment WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: ListDeployments :many
SELECT * FROM apigatewayv2_deployment WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? ORDER BY id;

-- name: PutDeployment :exec
INSERT INTO apigatewayv2_deployment (partition, account_id, region, gateway_id, id, description, auto_deployed, created_at, route_selection_expression, owner_stack_id, owner_logical_id, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, gateway_id, id) DO UPDATE SET description = excluded.description, auto_deployed = excluded.auto_deployed, created_at = excluded.created_at, route_selection_expression = excluded.route_selection_expression, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;

-- name: DeleteDeployment :exec
DELETE FROM apigatewayv2_deployment WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: ListDeployedRoutes :many
SELECT * FROM apigatewayv2_deployed_route WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND deployment_id = ? ORDER BY route_id;

-- name: PutDeployedRoute :exec
INSERT INTO apigatewayv2_deployed_route (partition, account_id, region, gateway_id, deployment_id, route_id, route_key, function_arn, payload_version, authorization_type, issuer, audiences, scopes, authorizer_id, authorizer_type, authorizer_function_arn, authorizer_payload_version, authorizer_identity_sources, authorizer_ttl_seconds, authorizer_simple_responses, authorizer_credentials_arn, websocket_response_enabled, timeout_millis, credentials_arn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAPIByID :one
SELECT * FROM apigatewayv2_api WHERE id = ?;

-- name: GetAuthorizerCache :one
SELECT * FROM apigatewayv2_authorizer_cache WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND stage_id = ? AND authorizer_id = ? AND identity_key = ?;

-- name: PutAuthorizerCache :exec
INSERT INTO apigatewayv2_authorizer_cache (partition, account_id, region, gateway_id, stage_id, authorizer_id, identity_key, principal_id, policy_document, context, is_authorized, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, gateway_id, stage_id, authorizer_id, identity_key) DO UPDATE SET principal_id = excluded.principal_id, policy_document = excluded.policy_document, context = excluded.context, is_authorized = excluded.is_authorized, expires_at = excluded.expires_at;

-- name: DeleteStageAuthorizerCache :exec
DELETE FROM apigatewayv2_authorizer_cache WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND stage_id = ?;

-- name: PruneAuthorizerCache :exec
DELETE FROM apigatewayv2_authorizer_cache WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND expires_at <= ?;

-- name: GetRouteResponse :one
SELECT * FROM apigatewayv2_route_response WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;

-- name: ListRouteResponses :many
SELECT * FROM apigatewayv2_route_response WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND route_id = ? ORDER BY id;

-- name: PutRouteResponse :exec
INSERT INTO apigatewayv2_route_response (partition, account_id, region, gateway_id, id, route_id, response_key, owner_stack_id, owner_logical_id, owner_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, gateway_id, id) DO UPDATE SET route_id = excluded.route_id, response_key = excluded.response_key, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;

-- name: DeleteRouteResponse :exec
DELETE FROM apigatewayv2_route_response WHERE partition = ? AND account_id = ? AND region = ? AND gateway_id = ? AND id = ?;
