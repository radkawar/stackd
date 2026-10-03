ALTER TABLE apigateway_integrations ADD COLUMN credentials_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_deployment_routes ADD COLUMN credentials_arn TEXT NOT NULL DEFAULT '';
