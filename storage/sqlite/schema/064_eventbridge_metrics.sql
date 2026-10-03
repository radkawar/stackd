-- Bus and rule names are metric dimensions, not cascading foreign keys.
CREATE TABLE eventbridge_metric_samples (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 minute TIMESTAMP NOT NULL, metric_name TEXT NOT NULL,
 event_bus_name TEXT NOT NULL, rule_name TEXT NOT NULL, source TEXT NOT NULL,
 value REAL NOT NULL, sample_count INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,minute,metric_name,event_bus_name,rule_name,source,value)
);
CREATE INDEX eventbridge_metric_samples_due ON eventbridge_metric_samples(minute,partition,account,region);
