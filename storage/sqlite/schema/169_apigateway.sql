-- Retained REST control plane. Deployment rows own route/authentication snapshots.
CREATE TABLE apigateway_apis (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 version TEXT NOT NULL,
 root_resource_id TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 disabled BOOLEAN NOT NULL,
 effective_disabled BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id),
 UNIQUE (api_id)
);

CREATE TABLE apigateway_resources (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 path_part TEXT NOT NULL,
 path TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id),
 FOREIGN KEY (partition, account_id, region, api_id) REFERENCES apigateway_apis (partition, account_id, region, api_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_methods (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 authorization_type TEXT NOT NULL,
 authorizer_id TEXT NOT NULL,
 operation_name TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id) REFERENCES apigateway_resources (partition, account_id, region, api_id, resource_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_integrations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 uri TEXT NOT NULL,
 timeout_millis INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_methods (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_authorizers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 authorizer_id TEXT NOT NULL,
 name TEXT NOT NULL,
 auth_type TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, authorizer_id),
 FOREIGN KEY (partition, account_id, region, api_id) REFERENCES apigateway_apis (partition, account_id, region, api_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_deployments (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 description TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id),
 FOREIGN KEY (partition, account_id, region, api_id) REFERENCES apigateway_apis (partition, account_id, region, api_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_stages (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 name TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 description TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, name),
 FOREIGN KEY (partition, account_id, region, api_id) REFERENCES apigateway_apis (partition, account_id, region, api_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id) REFERENCES apigateway_deployments (partition, account_id, region, api_id, deployment_id)
);

CREATE TABLE apigateway_api_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, key),
 FOREIGN KEY (partition, account_id, region, api_id) REFERENCES apigateway_apis (partition, account_id, region, api_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_method_scopes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 scope TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method, ordinal),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_methods (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_authorizer_pools (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 authorizer_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 arn TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, authorizer_id, ordinal),
 FOREIGN KEY (partition, account_id, region, api_id, authorizer_id) REFERENCES apigateway_authorizers (partition, account_id, region, api_id, authorizer_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_stage_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, name, key),
 FOREIGN KEY (partition, account_id, region, api_id, name) REFERENCES apigateway_stages (partition, account_id, region, api_id, name) ON DELETE CASCADE
);

CREATE TABLE apigateway_stage_variables (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, name, key),
 FOREIGN KEY (partition, account_id, region, api_id, name) REFERENCES apigateway_stages (partition, account_id, region, api_id, name) ON DELETE CASCADE
);

CREATE TABLE apigateway_deployment_routes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 path TEXT NOT NULL,
 authorization_type TEXT NOT NULL,
 function_arn TEXT NOT NULL,
 timeout_millis INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id) REFERENCES apigateway_deployments (partition, account_id, region, api_id, deployment_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_route_scopes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 scope TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method, ordinal),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method) REFERENCES apigateway_deployment_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_route_pools (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 arn TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method, ordinal),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method) REFERENCES apigateway_deployment_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_deployment_resources (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 path TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id) REFERENCES apigateway_deployments (partition, account_id, region, api_id, deployment_id) ON DELETE CASCADE
);
