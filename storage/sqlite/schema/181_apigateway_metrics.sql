-- API Gateway owns publication for REST, HTTP and WebSocket execution. These
-- dimensions outlive API/stage deletion and deliberately have no resource FK.
CREATE TABLE apigateway_metric_samples (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    api_id TEXT NOT NULL,
    minute DATETIME NOT NULL,
    protocol_type TEXT NOT NULL,
    api_name TEXT NOT NULL,
    stage TEXT NOT NULL,
    method TEXT NOT NULL,
    resource TEXT NOT NULL,
    route TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    sample_count INTEGER NOT NULL,
    PRIMARY KEY (partition, account_id, region, api_id, minute, protocol_type, api_name, stage, method, resource, route, metric_name, value)
);
CREATE INDEX apigateway_metric_due ON apigateway_metric_samples
    (minute, partition, account_id, region, api_id, protocol_type, api_name, stage, method, resource, route);
