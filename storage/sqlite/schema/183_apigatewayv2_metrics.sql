ALTER TABLE apigatewayv2_stage ADD COLUMN detailed_metrics BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE apigatewayv2_route_metrics (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    gateway_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    route_key TEXT NOT NULL,
    enabled BOOLEAN,
    PRIMARY KEY (partition, account_id, region, gateway_id, stage, route_key),
    FOREIGN KEY (partition, account_id, region, gateway_id, stage)
        REFERENCES apigatewayv2_stage(partition, account_id, region, gateway_id, id) ON DELETE CASCADE
);
