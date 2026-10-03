-- name: GetAPI :one
SELECT * FROM appsync_apis WHERE api_id = ?;

-- name: ListAPI :many
SELECT * FROM appsync_apis ORDER BY api_id;

-- name: PutAPI :exec
INSERT INTO appsync_apis (partition, account_id, region, api_id, name, auth_type, api_type, visibility, introspection, owner, owner_contact, query_depth_limit, resolver_count_limit, xray_enabled, graphql_uri, realtime_uri, schema_definition, schema_status, schema_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (api_id) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, auth_type=excluded.auth_type, api_type=excluded.api_type, visibility=excluded.visibility, introspection=excluded.introspection, owner=excluded.owner, owner_contact=excluded.owner_contact, query_depth_limit=excluded.query_depth_limit, resolver_count_limit=excluded.resolver_count_limit, xray_enabled=excluded.xray_enabled, graphql_uri=excluded.graphql_uri, realtime_uri=excluded.realtime_uri, schema_definition=excluded.schema_definition, schema_status=excluded.schema_status, schema_details=excluded.schema_details;

-- name: DeleteAPI :execrows
DELETE FROM appsync_apis WHERE api_id = ?;

-- name: ListAuth :many
SELECT * FROM appsync_auth WHERE api_id = ? ORDER BY api_id, ordinal;

-- name: PutAuth :exec
INSERT INTO appsync_auth (api_id, ordinal, auth_type, pool_region, pool_id, client_regex, default_action, issuer, oidc_client, auth_ttl, iat_ttl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (api_id, ordinal) DO UPDATE SET auth_type=excluded.auth_type, pool_region=excluded.pool_region, pool_id=excluded.pool_id, client_regex=excluded.client_regex, default_action=excluded.default_action, issuer=excluded.issuer, oidc_client=excluded.oidc_client, auth_ttl=excluded.auth_ttl, iat_ttl=excluded.iat_ttl;

-- name: ClearAuth :exec
DELETE FROM appsync_auth WHERE api_id = ?;

-- name: ListTag :many
SELECT * FROM appsync_tags WHERE api_id = ? ORDER BY api_id, tag_key;

-- name: PutTag :exec
INSERT INTO appsync_tags (api_id, tag_key, tag_value) VALUES (?, ?, ?) ON CONFLICT (api_id, tag_key) DO UPDATE SET tag_value=excluded.tag_value;

-- name: ClearTag :exec
DELETE FROM appsync_tags WHERE api_id = ?;

-- name: ListDataSource :many
SELECT * FROM appsync_data_sources WHERE api_id = ? ORDER BY api_id, name;

-- name: PutDataSource :exec
INSERT INTO appsync_data_sources (api_id, name, arn, description, kind, role_arn, metrics, lambda_arn, ddb_region, ddb_table, ddb_caller, ddb_versioned, http_endpoint, rds_type, rds_region, rds_secret, rds_database, rds_cluster, rds_schema) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (api_id, name) DO UPDATE SET arn=excluded.arn, description=excluded.description, kind=excluded.kind, role_arn=excluded.role_arn, metrics=excluded.metrics, lambda_arn=excluded.lambda_arn, ddb_region=excluded.ddb_region, ddb_table=excluded.ddb_table, ddb_caller=excluded.ddb_caller, ddb_versioned=excluded.ddb_versioned, http_endpoint=excluded.http_endpoint, rds_type=excluded.rds_type, rds_region=excluded.rds_region, rds_secret=excluded.rds_secret, rds_database=excluded.rds_database, rds_cluster=excluded.rds_cluster, rds_schema=excluded.rds_schema;

-- name: DeleteDataSource :execrows
DELETE FROM appsync_data_sources WHERE api_id = ? AND name = ?;

-- name: ListFunction :many
SELECT * FROM appsync_functions WHERE api_id = ? ORDER BY api_id, function_id;

-- name: PutFunction :exec
INSERT INTO appsync_functions (api_id, function_id, name, arn, description, source_name, runtime_name, runtime_version, code, function_version, request_template, response_template, max_batch_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (api_id, function_id) DO UPDATE SET name=excluded.name, arn=excluded.arn, description=excluded.description, source_name=excluded.source_name, runtime_name=excluded.runtime_name, runtime_version=excluded.runtime_version, code=excluded.code, function_version=excluded.function_version, request_template=excluded.request_template, response_template=excluded.response_template, max_batch_size=excluded.max_batch_size;

-- name: DeleteFunction :execrows
DELETE FROM appsync_functions WHERE api_id = ? AND function_id = ?;

-- name: ListResolver :many
SELECT * FROM appsync_resolvers WHERE api_id = ? ORDER BY api_id, type_name, field_name;

-- name: PutResolver :exec
INSERT INTO appsync_resolvers (api_id, type_name, field_name, arn, kind, source_name, runtime_name, runtime_version, code, request_template, response_template, max_batch_size, metrics) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (api_id, type_name, field_name) DO UPDATE SET arn=excluded.arn, kind=excluded.kind, source_name=excluded.source_name, runtime_name=excluded.runtime_name, runtime_version=excluded.runtime_version, code=excluded.code, request_template=excluded.request_template, response_template=excluded.response_template, max_batch_size=excluded.max_batch_size, metrics=excluded.metrics;

-- name: DeleteResolver :execrows
DELETE FROM appsync_resolvers WHERE api_id = ? AND type_name = ? AND field_name = ?;

-- name: ListPipeline :many
SELECT * FROM appsync_pipeline WHERE api_id = ? ORDER BY api_id, type_name, field_name, ordinal;

-- name: PutPipeline :exec
INSERT INTO appsync_pipeline (api_id, type_name, field_name, ordinal, function_id) VALUES (?, ?, ?, ?, ?) ON CONFLICT (api_id, type_name, field_name, ordinal) DO UPDATE SET function_id=excluded.function_id;

-- name: ListAPIKey :many
SELECT * FROM appsync_keys WHERE api_id = ? ORDER BY api_id, key_id;

-- name: PutAPIKey :exec
INSERT INTO appsync_keys (api_id, key_id, description, expires, deletes) VALUES (?, ?, ?, ?, ?) ON CONFLICT (api_id, key_id) DO UPDATE SET description=excluded.description, expires=excluded.expires, deletes=excluded.deletes;

-- name: DeleteAPIKey :execrows
DELETE FROM appsync_keys WHERE api_id = ? AND key_id = ?;

-- name: ClearPipeline :exec
DELETE FROM appsync_pipeline WHERE api_id = ? AND type_name = ? AND field_name = ?;
