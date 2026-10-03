CREATE TABLE apigateway_accounts (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    cloudwatch_role_arn TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region)
);

ALTER TABLE apigateway_stages ADD COLUMN access_log_destination_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_stages ADD COLUMN access_log_format TEXT NOT NULL DEFAULT '';

-- Retain each existing metrics override in the same method-settings row.
ALTER TABLE apigateway_method_metrics RENAME TO apigateway_method_settings;
ALTER TABLE apigateway_method_settings RENAME COLUMN enabled TO metrics_enabled;
ALTER TABLE apigateway_method_settings ADD COLUMN logging_level TEXT NOT NULL DEFAULT '';
ALTER TABLE apigateway_method_settings ADD COLUMN data_trace_enabled BOOLEAN NOT NULL DEFAULT FALSE;
