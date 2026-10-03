CREATE TABLE s3_bucket_lifecycle (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    minimum_object_size TEXT NOT NULL,
    next_scan TIMESTAMP, parent_event_id TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE INDEX s3_bucket_lifecycle_due ON s3_bucket_lifecycle(next_scan, partition, bucket_name)
    WHERE next_scan IS NOT NULL;

CREATE TABLE s3_bucket_lifecycle_rules (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, position INTEGER NOT NULL,
    id TEXT NOT NULL, enabled BOOLEAN NOT NULL,
    filter_kind TEXT NOT NULL, filter_prefix TEXT,
    object_size_greater_than INTEGER, object_size_less_than INTEGER,
    expiration_date TIMESTAMP, expiration_days INTEGER, expired_object_delete_marker BOOLEAN,
    noncurrent_expiration_days INTEGER, noncurrent_expiration_newer_versions INTEGER,
    abort_incomplete_days INTEGER,
    PRIMARY KEY (partition, bucket_name, position),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_bucket_lifecycle(partition, bucket_name) ON DELETE CASCADE
);

CREATE TABLE s3_bucket_lifecycle_tags (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, rule_position INTEGER NOT NULL, position INTEGER NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, rule_position, position),
    FOREIGN KEY (partition, bucket_name, rule_position) REFERENCES s3_bucket_lifecycle_rules(partition, bucket_name, position) ON DELETE CASCADE
);

CREATE TABLE s3_bucket_lifecycle_transitions (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, rule_position INTEGER NOT NULL,
    noncurrent BOOLEAN NOT NULL, position INTEGER NOT NULL,
    date TIMESTAMP, days INTEGER, storage_class TEXT NOT NULL, newer_noncurrent_versions INTEGER,
    PRIMARY KEY (partition, bucket_name, rule_position, noncurrent, position),
    FOREIGN KEY (partition, bucket_name, rule_position) REFERENCES s3_bucket_lifecycle_rules(partition, bucket_name, position) ON DELETE CASCADE
);
