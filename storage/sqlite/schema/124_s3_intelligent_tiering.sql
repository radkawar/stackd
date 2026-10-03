ALTER TABLE s3_object_versions ADD COLUMN tiering_accessed TIMESTAMP;
ALTER TABLE s3_object_versions ADD COLUMN archive_tier TEXT NOT NULL DEFAULT '';

-- Existing eligible payloads start a known access window at migration time.
-- LastModified is not evidence of when an object was last accessed.
UPDATE s3_object_versions
SET tiering_accessed = COALESCE((SELECT instant FROM clock_state WHERE id = 1), CURRENT_TIMESTAMP)
WHERE storage_class = 'INTELLIGENT_TIERING' AND size >= 131072 AND delete_marker = false;

CREATE TABLE s3_bucket_tiering_configurations (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL, has_filter BOOLEAN NOT NULL,
    filter_kind TEXT NOT NULL, filter_prefix TEXT,
    parent_event_id TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, id),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);

CREATE TABLE s3_bucket_tiering_tags (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, configuration_id TEXT NOT NULL,
    position INTEGER NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, configuration_id, position),
    FOREIGN KEY (partition, bucket_name, configuration_id) REFERENCES s3_bucket_tiering_configurations(partition, bucket_name, id) ON DELETE CASCADE
);

CREATE TABLE s3_bucket_tiering_rules (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, configuration_id TEXT NOT NULL,
    position INTEGER NOT NULL, access_tier TEXT NOT NULL, days INTEGER NOT NULL,
    PRIMARY KEY (partition, bucket_name, configuration_id, position),
    FOREIGN KEY (partition, bucket_name, configuration_id) REFERENCES s3_bucket_tiering_configurations(partition, bucket_name, id) ON DELETE CASCADE
);

CREATE TABLE s3_bucket_tiering_scans (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, due TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, bucket_name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE INDEX s3_bucket_tiering_scans_due ON s3_bucket_tiering_scans(due, partition, bucket_name);
