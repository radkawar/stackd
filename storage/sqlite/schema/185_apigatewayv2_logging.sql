ALTER TABLE apigatewayv2_stage ADD COLUMN logging_level TEXT NOT NULL DEFAULT 'OFF';
ALTER TABLE apigatewayv2_stage ADD COLUMN data_trace BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE apigatewayv2_stage ADD COLUMN access_log_destination_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigatewayv2_stage ADD COLUMN access_log_format TEXT NOT NULL DEFAULT '';

CREATE TABLE apigatewayv2_route_settings (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    gateway_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    route_key TEXT NOT NULL,
    detailed_metrics BOOLEAN,
    logging_level TEXT NOT NULL DEFAULT '',
    data_trace BOOLEAN,
    PRIMARY KEY (partition, account_id, region, gateway_id, stage, route_key),
    FOREIGN KEY (partition, account_id, region, gateway_id, stage)
        REFERENCES apigatewayv2_stage(partition, account_id, region, gateway_id, id) ON DELETE CASCADE
);

INSERT INTO apigatewayv2_route_settings (partition, account_id, region, gateway_id, stage, route_key, detailed_metrics)
SELECT partition, account_id, region, gateway_id, stage, route_key, enabled FROM apigatewayv2_route_metrics;
DROP TABLE apigatewayv2_route_metrics;
