ALTER TABLE apigatewayv2_authorizer ADD COLUMN credentials_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_credentials_arn TEXT NOT NULL DEFAULT '';
