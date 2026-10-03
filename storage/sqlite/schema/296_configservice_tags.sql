CREATE TABLE config_tags (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 arn TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn, key)
);
