ALTER TABLE cloudtrail_trails ADD COLUMN logs_group_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudtrail_trails ADD COLUMN logs_role_arn TEXT NOT NULL DEFAULT '';

-- Existing retained batches keep their IDs, event references and S3 attempts.
ALTER TABLE cloudtrail_deliveries ADD COLUMN destination TEXT NOT NULL DEFAULT 's3' CHECK (destination IN ('s3', 'logs'));
ALTER TABLE cloudtrail_deliveries ADD COLUMN logs_group_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudtrail_deliveries ADD COLUMN logs_role_arn TEXT NOT NULL DEFAULT '';
DROP INDEX cloudtrail_deliveries_open;
CREATE INDEX cloudtrail_deliveries_open ON cloudtrail_deliveries(trail_id, region, destination, sealed, due, id);

-- Re-key status without discarding the previous S3 result.
ALTER TABLE cloudtrail_delivery_status RENAME TO cloudtrail_delivery_status_s3;
CREATE TABLE cloudtrail_delivery_status (
    trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
    destination TEXT NOT NULL CHECK (destination IN ('s3', 'logs')),
    last_attempt TIMESTAMP, last_success TIMESTAMP, last_error TEXT NOT NULL,
    PRIMARY KEY (trail_id, destination)
);
INSERT INTO cloudtrail_delivery_status(trail_id, destination, last_attempt, last_success, last_error)
SELECT trail_id, 's3', last_attempt, last_success, last_error FROM cloudtrail_delivery_status_s3;
DROP TABLE cloudtrail_delivery_status_s3;
