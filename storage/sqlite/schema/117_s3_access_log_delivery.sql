-- Accepted access logs retain source identity and destination after bucket deletion.
-- Only due changes while delivery is pending.
CREATE TABLE s3_access_log_deliveries (
    id TEXT NOT NULL PRIMARY KEY,
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    target_bucket TEXT NOT NULL,
    target_prefix TEXT NOT NULL,
    key_format TEXT NOT NULL,
    has_grants BOOLEAN NOT NULL,
    record TEXT NOT NULL,
    at TIMESTAMP NOT NULL,
    due TIMESTAMP NOT NULL
);
CREATE INDEX s3_access_log_delivery_due ON s3_access_log_deliveries(due, id);

CREATE TABLE s3_access_log_delivery_grants (
    delivery_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    grantee_type TEXT NOT NULL,
    grantee_id TEXT NOT NULL,
    grantee_uri TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (delivery_id, position),
    FOREIGN KEY (delivery_id) REFERENCES s3_access_log_deliveries(id) ON DELETE CASCADE
);
