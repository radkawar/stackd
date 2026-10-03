ALTER TABLE apigatewayv2_authorizer ADD COLUMN authorizer_type TEXT NOT NULL DEFAULT 'JWT';
ALTER TABLE apigatewayv2_authorizer ADD COLUMN uri TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_authorizer ADD COLUMN function_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_authorizer ADD COLUMN payload_version TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_authorizer ADD COLUMN identity_sources BLOB NOT NULL DEFAULT '[]';
ALTER TABLE apigatewayv2_authorizer ADD COLUMN ttl_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE apigatewayv2_authorizer ADD COLUMN simple_responses INTEGER NOT NULL DEFAULT 0;

ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_id TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_type TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_function_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_payload_version TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_identity_sources BLOB NOT NULL DEFAULT '[]';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_ttl_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN authorizer_simple_responses INTEGER NOT NULL DEFAULT 0;

CREATE TABLE apigatewayv2_authorizer_cache (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  stage_id TEXT NOT NULL,
  authorizer_id TEXT NOT NULL,
  identity_key TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  policy_document BLOB,
  context BLOB NOT NULL,
  is_authorized INTEGER,
  expires_at TIMESTAMP NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, stage_id, authorizer_id, identity_key),
  FOREIGN KEY (partition, account_id, region, gateway_id, stage_id) REFERENCES apigatewayv2_stage(partition, account_id, region, gateway_id, id) ON DELETE CASCADE,
  FOREIGN KEY (partition, account_id, region, gateway_id, authorizer_id) REFERENCES apigatewayv2_authorizer(partition, account_id, region, gateway_id, id) ON DELETE CASCADE
);

CREATE INDEX apigatewayv2_authorizer_cache_expiry ON apigatewayv2_authorizer_cache(partition, account_id, region, gateway_id, expires_at);
