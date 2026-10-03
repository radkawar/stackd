ALTER TABLE apigateway_authorizers ADD COLUMN credentials_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_deployment_routes ADD COLUMN authorizer_credentials_arn TEXT NOT NULL DEFAULT '';
