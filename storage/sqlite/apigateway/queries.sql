-- name: GetAPI :one
SELECT * FROM apigateway_apis WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ?;

-- name: ListAPIs :many
SELECT * FROM apigateway_apis WHERE partition = ? AND account_id = ? AND region = ? ORDER BY api_id;

-- name: PutAPI :exec
INSERT INTO apigateway_apis (partition, account_id, region, api_id, name, description, version, root_resource_id, created, disabled, effective_disabled, api_key_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id) DO UPDATE SET name = excluded.name, description = excluded.description, version = excluded.version, root_resource_id = excluded.root_resource_id, created = excluded.created, disabled = excluded.disabled, effective_disabled = excluded.effective_disabled, api_key_source = excluded.api_key_source;

-- name: DeleteAPI :exec
DELETE FROM apigateway_apis WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ?;

-- name: GetResource :one
SELECT * FROM apigateway_resources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ?;

-- name: ListResources :many
SELECT * FROM apigateway_resources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY resource_id;

-- name: PutResource :exec
INSERT INTO apigateway_resources (partition, account_id, region, api_id, resource_id, parent_id, path_part, path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, resource_id) DO UPDATE SET parent_id = excluded.parent_id, path_part = excluded.path_part, path = excluded.path;

-- name: DeleteResource :exec
DELETE FROM apigateway_resources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ?;

-- name: GetMethod :one
SELECT * FROM apigateway_methods WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: ListMethods :many
SELECT * FROM apigateway_methods WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY resource_id, http_method;

-- name: PutMethod :exec
INSERT INTO apigateway_methods (partition, account_id, region, api_id, resource_id, http_method, authorization_type, authorizer_id, operation_name, api_key_required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, resource_id, http_method) DO UPDATE SET authorization_type = excluded.authorization_type, authorizer_id = excluded.authorizer_id, operation_name = excluded.operation_name, api_key_required = excluded.api_key_required;

-- name: DeleteMethod :exec
DELETE FROM apigateway_methods WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: GetIntegration :one
SELECT * FROM apigateway_integrations WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutIntegration :exec
INSERT INTO apigateway_integrations (partition, account_id, region, api_id, resource_id, http_method, uri, timeout_millis, credentials_arn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, resource_id, http_method) DO UPDATE SET uri = excluded.uri, timeout_millis = excluded.timeout_millis, credentials_arn = excluded.credentials_arn;

-- name: DeleteIntegration :exec
DELETE FROM apigateway_integrations WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: GetAuthorizer :one
SELECT * FROM apigateway_authorizers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND authorizer_id = ?;

-- name: ListAuthorizers :many
SELECT * FROM apigateway_authorizers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY authorizer_id;

-- name: PutAuthorizer :exec
INSERT INTO apigateway_authorizers (partition, account_id, region, api_id, authorizer_id, name, auth_type, authorizer_type, authorizer_uri, function_arn, validation_expression, ttl_seconds, credentials_arn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, authorizer_id) DO UPDATE SET name = excluded.name, auth_type = excluded.auth_type, authorizer_type = excluded.authorizer_type, authorizer_uri = excluded.authorizer_uri, function_arn = excluded.function_arn, validation_expression = excluded.validation_expression, ttl_seconds = excluded.ttl_seconds, credentials_arn = excluded.credentials_arn;

-- name: DeleteAuthorizer :exec
DELETE FROM apigateway_authorizers WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND authorizer_id = ?;

-- name: GetDeployment :one
SELECT * FROM apigateway_deployments WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ?;

-- name: ListDeployments :many
SELECT * FROM apigateway_deployments WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY deployment_id;

-- name: PutDeployment :exec
INSERT INTO apigateway_deployments (partition, account_id, region, api_id, deployment_id, description, created, api_key_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, deployment_id) DO UPDATE SET description = excluded.description, created = excluded.created, api_key_source = excluded.api_key_source;

-- name: DeleteDeployment :exec
DELETE FROM apigateway_deployments WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ?;

-- name: GetStage :one
SELECT * FROM apigateway_stages WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND name = ?;

-- name: ListStages :many
SELECT * FROM apigateway_stages WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY name;

-- name: PutStage :exec
INSERT INTO apigateway_stages (partition, account_id, region, api_id, name, deployment_id, description, created, updated, access_log_destination_arn, access_log_format) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, name) DO UPDATE SET deployment_id = excluded.deployment_id, description = excluded.description, created = excluded.created, updated = excluded.updated, access_log_destination_arn = excluded.access_log_destination_arn, access_log_format = excluded.access_log_format;

-- name: DeleteStage :exec
DELETE FROM apigateway_stages WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND name = ?;

-- name: GetOwner :one
SELECT * FROM apigateway_apis WHERE api_id = ?;

-- name: ListAPITags :many
SELECT * FROM apigateway_api_tags WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? ORDER BY key;

-- name: DeleteAPITags :exec
DELETE FROM apigateway_api_tags WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ?;

-- name: PutAPITags :exec
INSERT INTO apigateway_api_tags (partition, account_id, region, api_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListMethodScopes :many
SELECT * FROM apigateway_method_scopes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ? ORDER BY ordinal;

-- name: DeleteMethodScopes :exec
DELETE FROM apigateway_method_scopes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutMethodScopes :exec
INSERT INTO apigateway_method_scopes (partition, account_id, region, api_id, resource_id, http_method, ordinal, scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAuthorizerPools :many
SELECT * FROM apigateway_authorizer_pools WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND authorizer_id = ? ORDER BY ordinal;

-- name: DeleteAuthorizerPools :exec
DELETE FROM apigateway_authorizer_pools WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND authorizer_id = ?;

-- name: PutAuthorizerPools :exec
INSERT INTO apigateway_authorizer_pools (partition, account_id, region, api_id, authorizer_id, ordinal, arn) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListStageTags :many
SELECT * FROM apigateway_stage_tags WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND name = ? ORDER BY key;

-- name: DeleteStageTags :exec
DELETE FROM apigateway_stage_tags WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND name = ?;

-- name: PutStageTags :exec
INSERT INTO apigateway_stage_tags (partition, account_id, region, api_id, name, key, value) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListStageVariables :many
SELECT * FROM apigateway_stage_variables WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND name = ? ORDER BY key;

-- name: DeleteStageVariables :exec
DELETE FROM apigateway_stage_variables WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND name = ?;

-- name: PutStageVariables :exec
INSERT INTO apigateway_stage_variables (partition, account_id, region, api_id, name, key, value) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListDeploymentRoutes :many
SELECT * FROM apigateway_deployment_routes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? ORDER BY resource_id, http_method;

-- name: DeleteDeploymentRoutes :exec
DELETE FROM apigateway_deployment_routes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ?;

-- name: PutDeploymentRoutes :exec
INSERT INTO apigateway_deployment_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method, path, authorization_type, function_arn, timeout_millis, authorizer_id, authorizer_type, authorizer_function_arn, authorizer_validation_expression, authorizer_ttl_seconds, authorizer_credentials_arn, credentials_arn, api_key_required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListRouteScopes :many
SELECT * FROM apigateway_route_scopes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ? ORDER BY ordinal;

-- name: DeleteRouteScopes :exec
DELETE FROM apigateway_route_scopes WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutRouteScopes :exec
INSERT INTO apigateway_route_scopes (partition, account_id, region, api_id, deployment_id, resource_id, http_method, ordinal, scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListRoutePools :many
SELECT * FROM apigateway_route_pools WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ? ORDER BY ordinal;

-- name: DeleteRoutePools :exec
DELETE FROM apigateway_route_pools WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ?;

-- name: PutRoutePools :exec
INSERT INTO apigateway_route_pools (partition, account_id, region, api_id, deployment_id, resource_id, http_method, ordinal, arn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListDeploymentResources :many
SELECT * FROM apigateway_deployment_resources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? ORDER BY resource_id;

-- name: DeleteDeploymentResources :exec
DELETE FROM apigateway_deployment_resources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ?;

-- name: PutDeploymentResources :exec
INSERT INTO apigateway_deployment_resources (partition, account_id, region, api_id, deployment_id, resource_id, path) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListAuthorizerIdentitySources :many
SELECT * FROM apigateway_authorizer_identity_sources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND authorizer_id = ? ORDER BY ordinal;

-- name: DeleteAuthorizerIdentitySources :exec
DELETE FROM apigateway_authorizer_identity_sources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND authorizer_id = ?;

-- name: PutAuthorizerIdentitySources :exec
INSERT INTO apigateway_authorizer_identity_sources (partition, account_id, region, api_id, authorizer_id, ordinal, source) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListRouteIdentitySources :many
SELECT * FROM apigateway_route_identity_sources WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND deployment_id = ? AND resource_id = ? AND http_method = ? ORDER BY ordinal;

-- name: PutRouteIdentitySources :exec
INSERT INTO apigateway_route_identity_sources (partition, account_id, region, api_id, deployment_id, resource_id, http_method, ordinal, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAuthorizerCache :one
SELECT * FROM apigateway_authorizer_cache WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND stage_name = ? AND authorizer_id = ? AND identity_key = ?;

-- name: PutAuthorizerCache :exec
INSERT INTO apigateway_authorizer_cache (partition, account_id, region, api_id, stage_name, authorizer_id, identity_key, principal_id, policy_document, context, is_authorized, expires_at, usage_identifier_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, api_id, stage_name, authorizer_id, identity_key) DO UPDATE SET principal_id = excluded.principal_id, policy_document = excluded.policy_document, context = excluded.context, is_authorized = excluded.is_authorized, expires_at = excluded.expires_at, usage_identifier_key = excluded.usage_identifier_key;

-- name: DeleteStageAuthorizerCache :exec
DELETE FROM apigateway_authorizer_cache WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND stage_name = ?;

-- name: PruneAuthorizerCache :exec
DELETE FROM apigateway_authorizer_cache WHERE partition = ? AND account_id = ? AND region = ? AND api_id = ? AND stage_name = ? AND expires_at <= ?;
