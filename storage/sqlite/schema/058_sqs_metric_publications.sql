-- Queue identity is a metric dimension, not a cascading foreign key.
CREATE TABLE sqs_metric_samples (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, queue_name TEXT NOT NULL,
 minute TIMESTAMP NOT NULL, metric_name TEXT NOT NULL, value INTEGER NOT NULL, sample_count INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,queue_name,minute,metric_name,value)
);
CREATE INDEX sqs_metric_samples_due ON sqs_metric_samples(minute,partition,account,region,queue_name);
