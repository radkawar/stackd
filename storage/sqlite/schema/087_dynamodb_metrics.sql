-- Recurring sampling is owned by the table, including unsampled active tables.
ALTER TABLE dynamodb_tables ADD COLUMN metrics_next_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
CREATE INDEX dynamodb_table_metric_deadlines ON dynamodb_tables(metrics_next_at,partition,account_id,region,name)
WHERE table_status IN ('ACTIVE','UPDATING');

-- Resource identity is a CloudWatch dimension, not a cascading foreign key.
CREATE TABLE dynamodb_metric_samples (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, table_name TEXT NOT NULL,
 minute TIMESTAMP NOT NULL, index_name TEXT NOT NULL, metric_name TEXT NOT NULL,
 value REAL NOT NULL, sample_count INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,table_name,minute,index_name,metric_name,value)
);
CREATE INDEX dynamodb_metric_samples_due ON dynamodb_metric_samples(minute,partition,account_id,region,table_name);
