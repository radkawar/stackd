-- Preserve existing count samples while allowing measured fractional milliseconds.
ALTER TABLE lambda_metric_samples RENAME TO lambda_metric_samples_integer;
DROP INDEX lambda_metric_samples_due;

CREATE TABLE lambda_metric_samples (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 resource TEXT NOT NULL DEFAULT '', executed_version TEXT NOT NULL DEFAULT '',
 minute TIMESTAMP NOT NULL, metric_name TEXT NOT NULL, value REAL NOT NULL, sample_count INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,resource,executed_version,minute,metric_name,value)
);
INSERT INTO lambda_metric_samples(partition,account,region,function_name,resource,executed_version,minute,metric_name,value,sample_count)
 SELECT partition,account,region,function_name,resource,executed_version,minute,metric_name,CAST(value AS REAL),sample_count
 FROM lambda_metric_samples_integer;
DROP TABLE lambda_metric_samples_integer;
CREATE INDEX lambda_metric_samples_due ON lambda_metric_samples(minute,partition,account,region,function_name,resource,executed_version);
