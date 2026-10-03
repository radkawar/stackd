ALTER TABLE apigatewayv2_api ADD COLUMN protocol_type TEXT NOT NULL DEFAULT 'HTTP';
ALTER TABLE apigatewayv2_api ADD COLUMN route_selection_expression TEXT NOT NULL DEFAULT '$request.method $request.path';
ALTER TABLE apigatewayv2_integration ADD COLUMN timeout_millis INTEGER NOT NULL DEFAULT 30000;
ALTER TABLE apigatewayv2_integration ADD COLUMN passthrough_behavior TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_route ADD COLUMN route_response_selection_expression TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_deployment ADD COLUMN route_selection_expression TEXT NOT NULL DEFAULT '$request.method $request.path';
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN websocket_response_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE apigatewayv2_deployed_route ADD COLUMN timeout_millis INTEGER NOT NULL DEFAULT 30000;

CREATE TABLE apigatewayv2_route_response (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  id TEXT NOT NULL,
  route_id TEXT NOT NULL,
  response_key TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, gateway_id, id),
  UNIQUE (partition, account_id, region, gateway_id, route_id, response_key),
  FOREIGN KEY (partition, account_id, region, gateway_id, route_id) REFERENCES apigatewayv2_route(partition, account_id, region, gateway_id, id) ON DELETE CASCADE
);
