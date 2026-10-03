CREATE TABLE apigateway_method_metrics (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    api_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    method_key TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, api_id, stage, method_key),
    FOREIGN KEY (partition, account_id, region, api_id, stage)
        REFERENCES apigateway_stages(partition, account_id, region, api_id, name) ON DELETE CASCADE
);
