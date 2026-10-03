CREATE TABLE apigatewayv2_api (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  version TEXT NOT NULL,
  disabled INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL,
  tags BLOB NOT NULL,
  PRIMARY KEY (partition, account_id, region, id),
  UNIQUE (id)
);

CREATE TABLE apigatewayv2_integration (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  id TEXT NOT NULL,
  description TEXT NOT NULL,
  uri TEXT NOT NULL,
  payload_version TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, id),
  FOREIGN KEY (partition, account_id, region, gateway_id) REFERENCES apigatewayv2_api(partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE apigatewayv2_authorizer (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  audiences BLOB NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, id),
  FOREIGN KEY (partition, account_id, region, gateway_id) REFERENCES apigatewayv2_api(partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE apigatewayv2_route (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  id TEXT NOT NULL,
  route_key TEXT NOT NULL,
  target TEXT NOT NULL,
  authorization_type TEXT NOT NULL,
  authorizer_id TEXT NOT NULL,
  operation_name TEXT NOT NULL,
  scopes BLOB NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, id),
  FOREIGN KEY (partition, account_id, region, gateway_id) REFERENCES apigatewayv2_api(partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE apigatewayv2_stage (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  id TEXT NOT NULL,
  description TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  last_deployment_status_message TEXT NOT NULL,
  auto_deploy INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  variables BLOB NOT NULL,
  tags BLOB NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, id),
  FOREIGN KEY (partition, account_id, region, gateway_id) REFERENCES apigatewayv2_api(partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE apigatewayv2_deployment (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  id TEXT NOT NULL,
  description TEXT NOT NULL,
  auto_deployed INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, id),
  FOREIGN KEY (partition, account_id, region, gateway_id) REFERENCES apigatewayv2_api(partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE apigatewayv2_deployed_route (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  route_id TEXT NOT NULL,
  route_key TEXT NOT NULL,
  function_arn TEXT NOT NULL,
  payload_version TEXT NOT NULL,
  authorization_type TEXT NOT NULL,
  issuer TEXT NOT NULL,
  audiences BLOB NOT NULL,
  scopes BLOB NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, deployment_id, route_id),
  FOREIGN KEY (partition, account_id, region, gateway_id, deployment_id) REFERENCES apigatewayv2_deployment(partition, account_id, region, gateway_id, id) ON DELETE CASCADE
);

