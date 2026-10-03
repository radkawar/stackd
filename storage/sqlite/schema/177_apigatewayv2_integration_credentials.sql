ALTER TABLE apigatewayv2_integration ADD COLUMN credentials_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN credentials_arn TEXT NOT NULL DEFAULT '';
