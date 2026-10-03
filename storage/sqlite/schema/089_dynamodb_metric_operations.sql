-- Retain pending samples while adding independent operation dimensions.
ALTER TABLE dynamodb_metric_samples RENAME TO dynamodb_metric_samples_without_operations;
DROP INDEX dynamodb_metric_samples_due;

CREATE TABLE dynamodb_metric_samples (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, table_name TEXT NOT NULL,
 minute TIMESTAMP NOT NULL, index_name TEXT NOT NULL, operation TEXT NOT NULL DEFAULT '',
 operation_type TEXT NOT NULL DEFAULT '', verb TEXT NOT NULL DEFAULT '', metric_name TEXT NOT NULL,
 value REAL NOT NULL, sample_count INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,table_name,minute,index_name,operation,operation_type,verb,metric_name,value)
);
INSERT INTO dynamodb_metric_samples(partition,account_id,region,table_name,minute,index_name,metric_name,value,sample_count)
 SELECT partition,account_id,region,table_name,minute,index_name,metric_name,value,sample_count
 FROM dynamodb_metric_samples_without_operations;
DROP TABLE dynamodb_metric_samples_without_operations;
CREATE INDEX dynamodb_metric_samples_due ON dynamodb_metric_samples(minute,partition,account_id,region,table_name);
