-- Lambda authorizer configuration is relational; deployments own immutable copies.
ALTER TABLE apigateway_authorizers ADD COLUMN authorizer_type TEXT NOT NULL DEFAULT 'COGNITO_USER_POOLS';
ALTER TABLE apigateway_authorizers ADD COLUMN authorizer_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_authorizers ADD COLUMN function_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_authorizers ADD COLUMN validation_expression TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_authorizers ADD COLUMN ttl_seconds INTEGER NOT NULL DEFAULT 0;

CREATE TABLE apigateway_authorizer_identity_sources (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 authorizer_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 source TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, authorizer_id, ordinal),
 FOREIGN KEY (partition, account_id, region, api_id, authorizer_id) REFERENCES apigateway_authorizers (partition, account_id, region, api_id, authorizer_id) ON DELETE CASCADE
);

ALTER TABLE apigateway_deployment_routes ADD COLUMN authorizer_id TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_deployment_routes ADD COLUMN authorizer_type TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_deployment_routes ADD COLUMN authorizer_function_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_deployment_routes ADD COLUMN authorizer_validation_expression TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_deployment_routes ADD COLUMN authorizer_ttl_seconds INTEGER NOT NULL DEFAULT 0;

CREATE TABLE apigateway_route_identity_sources (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 source TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method, ordinal),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method) REFERENCES apigateway_deployment_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method) ON DELETE CASCADE
);

-- Policy and context JSON are successful authorizer protocol domain data, not
-- generic resource blobs. Cache lifetime and ownership remain typed and scoped.
CREATE TABLE apigateway_authorizer_cache (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 stage_name TEXT NOT NULL,
 authorizer_id TEXT NOT NULL,
 identity_key TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 policy_document BLOB,
 context BLOB NOT NULL,
 is_authorized BOOLEAN,
 expires_at TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, stage_name, authorizer_id, identity_key),
 FOREIGN KEY (partition, account_id, region, api_id, stage_name) REFERENCES apigateway_stages (partition, account_id, region, api_id, name) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, api_id, authorizer_id) REFERENCES apigateway_authorizers (partition, account_id, region, api_id, authorizer_id) ON DELETE CASCADE
);
