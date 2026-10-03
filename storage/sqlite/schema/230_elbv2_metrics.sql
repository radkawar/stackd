ALTER TABLE elbv2_load_balancers ADD COLUMN next_metric_at INTEGER NOT NULL DEFAULT -9223372036854775808;

CREATE TABLE elbv2_metric_samples (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    load_balancer_arn TEXT NOT NULL,
    due INTEGER NOT NULL,
    name TEXT NOT NULL,
    target_group_arn TEXT NOT NULL,
    availability_zone TEXT NOT NULL,
    minimum REAL NOT NULL,
    maximum REAL NOT NULL,
    sum REAL NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (partition, account_id, region, load_balancer_arn, due, name, target_group_arn, availability_zone)
);
CREATE INDEX elbv2_metric_samples_due ON elbv2_metric_samples (due, load_balancer_arn);
