CREATE TABLE s3_notification_states (
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    desired_event_bridge BOOLEAN NOT NULL,
    applied_event_bridge BOOLEAN NOT NULL,
    apply_at TIMESTAMP,
    version BLOB NOT NULL CHECK (typeof(version) = 'blob' AND length(version) = 8),
    PRIMARY KEY (partition, bucket_name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE INDEX s3_notification_change_due ON s3_notification_states(apply_at, (partition || ':' || bucket_name)) WHERE apply_at IS NOT NULL;

CREATE TABLE s3_notification_rules (
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    applied BOOLEAN NOT NULL,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    destination_arn TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, applied, position),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_notification_states(partition, bucket_name) ON DELETE CASCADE
);
CREATE TABLE s3_notification_events (
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    applied BOOLEAN NOT NULL,
    rule_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, applied, rule_position, position),
    FOREIGN KEY (partition, bucket_name, applied, rule_position) REFERENCES s3_notification_rules(partition, bucket_name, applied, position) ON DELETE CASCADE
);
CREATE TABLE s3_notification_filters (
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    applied BOOLEAN NOT NULL,
    rule_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, applied, rule_position, position),
    FOREIGN KEY (partition, bucket_name, applied, rule_position) REFERENCES s3_notification_rules(partition, bucket_name, applied, position) ON DELETE CASCADE
);

-- Accepted notifications retain their source identity and payload after bucket deletion.
-- Only due, attempts and version change while delivery is pending.
CREATE TABLE s3_notification_deliveries (
    id TEXT PRIMARY KEY,
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    protocol TEXT NOT NULL,
    destination_arn TEXT NOT NULL,
    payload TEXT NOT NULL,
    request_id TEXT NOT NULL,
    parent_event_id TEXT NOT NULL,
    due TIMESTAMP NOT NULL,
    attempts INTEGER NOT NULL,
    version BLOB NOT NULL CHECK (typeof(version) = 'blob' AND length(version) = 8)
);
CREATE INDEX s3_notification_delivery_due ON s3_notification_deliveries(due, id);
