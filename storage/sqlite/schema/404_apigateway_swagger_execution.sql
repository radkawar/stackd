-- Typed live REST settings and immutable static MOCK deployment snapshots.

CREATE TABLE apigateway_binary_media_types (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 media_type TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, ordinal),
 FOREIGN KEY (partition, account_id, region, api_id) REFERENCES apigateway_apis (partition, account_id, region, api_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_gateway_responses (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 response_type TEXT NOT NULL,
 status_code INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, response_type),
 FOREIGN KEY (partition, account_id, region, api_id) REFERENCES apigateway_apis (partition, account_id, region, api_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_gateway_headers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 response_type TEXT NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, response_type, name),
 FOREIGN KEY (partition, account_id, region, api_id, response_type) REFERENCES apigateway_gateway_responses (partition, account_id, region, api_id, response_type) ON DELETE CASCADE
);

CREATE TABLE apigateway_gateway_templates (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 response_type TEXT NOT NULL,
 media_type TEXT NOT NULL,
 template TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, response_type, media_type),
 FOREIGN KEY (partition, account_id, region, api_id, response_type) REFERENCES apigateway_gateway_responses (partition, account_id, region, api_id, response_type) ON DELETE CASCADE
);

CREATE TABLE apigateway_mock_integrations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 status_code INTEGER NOT NULL,
 body TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_integrations (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_mock_integration_headers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method, name),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_mock_integrations (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_mock_routes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 status_code INTEGER NOT NULL,
 body TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method) REFERENCES apigateway_deployment_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_mock_route_headers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method, name),
 FOREIGN KEY (partition, account_id, region, api_id, deployment_id, resource_id, http_method) REFERENCES apigateway_mock_routes (partition, account_id, region, api_id, deployment_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_method_responses (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 status_code TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method, status_code),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method) REFERENCES apigateway_methods (partition, account_id, region, api_id, resource_id, http_method) ON DELETE CASCADE
);

CREATE TABLE apigateway_method_response_headers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 api_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 http_method TEXT NOT NULL,
 status_code TEXT NOT NULL,
 name TEXT NOT NULL,
 required BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, api_id, resource_id, http_method, status_code, name),
 FOREIGN KEY (partition, account_id, region, api_id, resource_id, http_method, status_code) REFERENCES apigateway_method_responses (partition, account_id, region, api_id, resource_id, http_method, status_code) ON DELETE CASCADE
);

ALTER TABLE apigateway_method_settings ADD COLUMN throttling_burst_limit INTEGER;

ALTER TABLE apigateway_method_settings ADD COLUMN throttling_rate_limit REAL;
