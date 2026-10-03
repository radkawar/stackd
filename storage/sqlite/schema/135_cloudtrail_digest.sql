ALTER TABLE cloudtrail_trails ADD COLUMN log_file_validation BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE cloudtrail_digest_keys (
 partition TEXT NOT NULL, region TEXT NOT NULL, fingerprint TEXT NOT NULL,
 start TIMESTAMP NOT NULL, end TIMESTAMP NOT NULL, private_der BLOB NOT NULL, public_der BLOB NOT NULL,
 PRIMARY KEY (partition, region, fingerprint)
);
-- Chains outlive deleted trails until their final object has been delivered.
CREATE TABLE cloudtrail_digest_streams (
 id TEXT PRIMARY KEY, trail_id TEXT NOT NULL,
 partition TEXT NOT NULL, trail_account TEXT NOT NULL, home_region TEXT NOT NULL, trail_name TEXT NOT NULL,
 account_id TEXT NOT NULL, region TEXT NOT NULL, organization_id TEXT NOT NULL,
 bucket TEXT NOT NULL, prefix TEXT NOT NULL, kms_key_id TEXT NOT NULL,
 start TIMESTAMP NOT NULL, end TIMESTAMP NOT NULL, due TIMESTAMP NOT NULL,
 closed BOOLEAN NOT NULL, closed_at TIMESTAMP NOT NULL, version INTEGER NOT NULL,
 previous_bucket TEXT NOT NULL, previous_object TEXT NOT NULL, previous_hash TEXT NOT NULL, previous_signature TEXT NOT NULL,
 pending BLOB NOT NULL, pending_object TEXT NOT NULL, pending_hash TEXT NOT NULL, pending_signature TEXT NOT NULL
);
CREATE INDEX cloudtrail_digest_streams_due ON cloudtrail_digest_streams(due,id);
CREATE INDEX cloudtrail_digest_streams_trail ON cloudtrail_digest_streams(trail_id,id);
CREATE TABLE cloudtrail_digest_logs (
 stream_id TEXT NOT NULL REFERENCES cloudtrail_digest_streams(id) ON DELETE CASCADE,
 delivery_id TEXT NOT NULL, bucket TEXT NOT NULL, object TEXT NOT NULL, hash TEXT NOT NULL,
 delivered TIMESTAMP NOT NULL, oldest TIMESTAMP NOT NULL, newest TIMESTAMP NOT NULL,
 PRIMARY KEY (stream_id, delivery_id)
);
CREATE INDEX cloudtrail_digest_logs_time ON cloudtrail_digest_logs(stream_id,delivered,delivery_id);
CREATE TABLE cloudtrail_digest_status (
 trail_id TEXT NOT NULL REFERENCES cloudtrail_trails(id) ON DELETE CASCADE,
 account_id TEXT NOT NULL, region TEXT NOT NULL,
 last_attempt TIMESTAMP, last_success TIMESTAMP, last_error TEXT NOT NULL,
 PRIMARY KEY (trail_id, account_id, region)
);
