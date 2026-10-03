ALTER TABLE apigateway_apis ADD COLUMN api_key_source TEXT NOT NULL DEFAULT 'HEADER';
ALTER TABLE apigateway_methods ADD COLUMN api_key_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE apigateway_deployments ADD COLUMN api_key_source TEXT NOT NULL DEFAULT 'HEADER';
ALTER TABLE apigateway_deployment_routes ADD COLUMN api_key_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE apigateway_authorizer_cache ADD COLUMN usage_identifier_key TEXT NOT NULL DEFAULT '';
