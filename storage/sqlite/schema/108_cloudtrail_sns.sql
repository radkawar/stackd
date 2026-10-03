ALTER TABLE cloudtrail_trails ADD COLUMN sns_topic_name TEXT NOT NULL DEFAULT '';

-- Preserve retained batches and their journal references while allowing the
-- successful S3 work item to advance to its notification stage.
ALTER TABLE cloudtrail_delivery_events RENAME TO cloudtrail_delivery_events_previous;
ALTER TABLE cloudtrail_deliveries RENAME TO cloudtrail_deliveries_previous;
CREATE TABLE cloudtrail_deliveries (
    id TEXT PRIMARY KEY,
    trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL, region TEXT NOT NULL, bucket TEXT NOT NULL, object_key TEXT NOT NULL,
    created TIMESTAMP NOT NULL, due TIMESTAMP NOT NULL, expires TIMESTAMP NOT NULL,
    sealed BOOLEAN NOT NULL, event_count INTEGER NOT NULL, attempts INTEGER NOT NULL, version BLOB NOT NULL,
    destination TEXT NOT NULL DEFAULT 's3' CHECK (destination IN ('s3', 'logs', 'sns')),
    logs_group_arn TEXT NOT NULL DEFAULT '', logs_role_arn TEXT NOT NULL DEFAULT ''
);
INSERT INTO cloudtrail_deliveries(id, trail_id, account_id, region, bucket, object_key, created, due, expires, sealed, event_count, attempts, version, destination, logs_group_arn, logs_role_arn)
SELECT id, trail_id, account_id, region, bucket, object_key, created, due, expires, sealed, event_count, attempts, version, destination, logs_group_arn, logs_role_arn
FROM cloudtrail_deliveries_previous;
CREATE TABLE cloudtrail_delivery_events (
    delivery_id TEXT NOT NULL REFERENCES cloudtrail_deliveries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    event_id TEXT NOT NULL REFERENCES api_call_events(event_id),
    PRIMARY KEY (delivery_id, position)
);
INSERT INTO cloudtrail_delivery_events(delivery_id, position, event_id)
SELECT delivery_id, position, event_id FROM cloudtrail_delivery_events_previous;
DROP TABLE cloudtrail_delivery_events_previous;
DROP TABLE cloudtrail_deliveries_previous;
CREATE INDEX cloudtrail_deliveries_due ON cloudtrail_deliveries(due, id);
CREATE INDEX cloudtrail_deliveries_open ON cloudtrail_deliveries(trail_id, region, destination, sealed, due, id);

ALTER TABLE cloudtrail_delivery_status RENAME TO cloudtrail_delivery_status_previous;
CREATE TABLE cloudtrail_delivery_status (
    trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    destination TEXT NOT NULL CHECK (destination IN ('s3', 'logs', 'sns')),
    last_attempt TIMESTAMP, last_success TIMESTAMP, last_error TEXT NOT NULL,
    PRIMARY KEY (trail_id, destination)
);
INSERT INTO cloudtrail_delivery_status(trail_id, destination, last_attempt, last_success, last_error)
SELECT trail_id, destination, last_attempt, last_success, last_error FROM cloudtrail_delivery_status_previous;
DROP TABLE cloudtrail_delivery_status_previous;
