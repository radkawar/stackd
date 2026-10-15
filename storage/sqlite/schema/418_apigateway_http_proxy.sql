-- Bounded public HTTP proxy configuration and immutable deployment snapshots.
CREATE TABLE apigateway_method_request_parameters (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 name TEXT NOT NULL,
 required BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method, name),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_methods (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_http_proxy_integrations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 uri TEXT NOT NULL,
 integration_method TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_integrations (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_http_proxy_integration_paths (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 target TEXT NOT NULL,
 source TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method, target),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_http_proxy_integrations (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_http_proxy_routes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 uri TEXT NOT NULL,
 integration_method TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method) REFERENCES apigateway_deployment_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_http_proxy_route_paths (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 target TEXT NOT NULL,
 source TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method, target),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method) REFERENCES apigateway_http_proxy_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method) ON DELETE CASCADE
);
