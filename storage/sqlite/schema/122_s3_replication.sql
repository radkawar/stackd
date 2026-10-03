-- Replicas retain the source notification sequence. It is not a globally
-- unique object identity; only the immutable bucket/key/version tuple is.
-- Rebuild dependents before dropping the old parent so foreign keys remain
-- enabled throughout the upgrade and no retained payload is cascaded away.
CREATE TABLE s3_object_versions_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    name TEXT NOT NULL COLLATE BINARY,
    version_id TEXT NOT NULL CHECK (version_id <> ''),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    delete_marker BOOLEAN NOT NULL,
    modified TIMESTAMP NOT NULL, size INTEGER NOT NULL,
    etag TEXT NOT NULL, checksum_algorithm TEXT NOT NULL, checksum TEXT NOT NULL,
    content_type TEXT NOT NULL, content_encoding TEXT NOT NULL, content_language TEXT NOT NULL,
    content_disposition TEXT NOT NULL, cache_control TEXT NOT NULL, expires TIMESTAMP,
    encryption_algorithm TEXT NOT NULL DEFAULT '', kms_key_arn TEXT NOT NULL DEFAULT '',
    website_redirect_location TEXT NOT NULL DEFAULT '',
    created_order INTEGER NOT NULL DEFAULT 0, upload_id TEXT NOT NULL DEFAULT '', checksum_type TEXT NOT NULL DEFAULT '',
    owner_account_id TEXT NOT NULL DEFAULT '', owner_id TEXT NOT NULL DEFAULT '', acl_legacy BOOLEAN NOT NULL DEFAULT true,
    retention_mode TEXT NOT NULL DEFAULT '', retain_until TIMESTAMP, retention_modified TIMESTAMP,
    event_hold TEXT NOT NULL DEFAULT '', event_hold_days INTEGER NOT NULL DEFAULT 0, event_hold_years INTEGER NOT NULL DEFAULT 0,
    legal_hold TEXT NOT NULL DEFAULT '', legal_hold_modified TIMESTAMP,
    storage_class TEXT NOT NULL DEFAULT '', replica BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (partition, bucket_name, name, version_id),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
INSERT INTO s3_object_versions_replacement (
    partition, bucket_name, name, version_id, sequence, delete_marker, modified, size, etag, checksum_algorithm, checksum,
    content_type, content_encoding, content_language, content_disposition, cache_control, expires,
    encryption_algorithm, kms_key_arn, website_redirect_location, created_order, upload_id, checksum_type,
    owner_account_id, owner_id, acl_legacy, retention_mode, retain_until, retention_modified,
    event_hold, event_hold_days, event_hold_years, legal_hold, legal_hold_modified, storage_class)
SELECT partition, bucket_name, name, version_id, sequence, delete_marker, modified, size, etag, checksum_algorithm, checksum,
    content_type, content_encoding, content_language, content_disposition, cache_control, expires,
    encryption_algorithm, kms_key_arn, website_redirect_location, created_order, upload_id, checksum_type,
    owner_account_id, owner_id, acl_legacy, retention_mode, retain_until, retention_modified,
    event_hold, event_hold_days, event_hold_years, legal_hold, legal_hold_modified, storage_class
FROM s3_object_versions;

CREATE TABLE s3_object_version_metadata_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions_replacement(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
INSERT INTO s3_object_version_metadata_replacement SELECT * FROM s3_object_version_metadata;

CREATE TABLE s3_object_version_data_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    encryption_key BLOB NOT NULL, ciphertext BLOB NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions_replacement(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
INSERT INTO s3_object_version_data_replacement SELECT * FROM s3_object_version_data;

CREATE TABLE s3_object_version_encryption_context_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions_replacement(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
INSERT INTO s3_object_version_encryption_context_replacement SELECT * FROM s3_object_version_encryption_context;

CREATE TABLE s3_object_version_tags_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    object_name TEXT NOT NULL COLLATE BINARY, version_id TEXT NOT NULL,
    key TEXT NOT NULL COLLATE BINARY, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions_replacement(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
INSERT INTO s3_object_version_tags_replacement SELECT * FROM s3_object_version_tags;

CREATE TABLE s3_encrypted_parts_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL,
    upload_id TEXT, version_id TEXT,
    number INTEGER NOT NULL CHECK (number BETWEEN 1 AND 10000),
    modified TIMESTAMP NOT NULL, size INTEGER NOT NULL,
    etag TEXT NOT NULL, checksum TEXT NOT NULL, ciphertext BLOB NOT NULL,
    CHECK ((upload_id IS NOT NULL AND version_id IS NULL) OR (upload_id IS NULL AND version_id IS NOT NULL)),
    UNIQUE (partition, bucket_name, object_name, upload_id, number),
    UNIQUE (partition, bucket_name, object_name, version_id, number),
    FOREIGN KEY (partition, bucket_name, object_name, upload_id) REFERENCES s3_multipart_uploads(partition, bucket_name, object_name, upload_id) ON DELETE CASCADE,
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions_replacement(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
INSERT INTO s3_encrypted_parts_replacement SELECT * FROM s3_encrypted_parts;

CREATE TABLE s3_object_version_acl_grants_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    grantee_type TEXT NOT NULL, grantee_id TEXT NOT NULL, grantee_uri TEXT NOT NULL, permission TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, position),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions_replacement(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
INSERT INTO s3_object_version_acl_grants_replacement SELECT * FROM s3_object_version_acl_grants;

CREATE TABLE s3_object_restores_replacement (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    due TIMESTAMP NOT NULL, ongoing BOOLEAN NOT NULL, days INTEGER NOT NULL,
    tier TEXT NOT NULL, parent_event_id TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions_replacement(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
INSERT INTO s3_object_restores_replacement SELECT * FROM s3_object_restores;

DROP TABLE s3_object_version_metadata;
DROP TABLE s3_object_version_data;
DROP TABLE s3_object_version_encryption_context;
DROP TABLE s3_object_version_tags;
DROP TABLE s3_encrypted_parts;
DROP TABLE s3_object_version_acl_grants;
DROP TABLE s3_object_restores;
DROP TABLE s3_object_versions;

ALTER TABLE s3_object_versions_replacement RENAME TO s3_object_versions;
ALTER TABLE s3_object_version_metadata_replacement RENAME TO s3_object_version_metadata;
ALTER TABLE s3_object_version_data_replacement RENAME TO s3_object_version_data;
ALTER TABLE s3_object_version_encryption_context_replacement RENAME TO s3_object_version_encryption_context;
ALTER TABLE s3_object_version_tags_replacement RENAME TO s3_object_version_tags;
ALTER TABLE s3_encrypted_parts_replacement RENAME TO s3_encrypted_parts;
ALTER TABLE s3_object_version_acl_grants_replacement RENAME TO s3_object_version_acl_grants;
ALTER TABLE s3_object_restores_replacement RENAME TO s3_object_restores;
CREATE INDEX s3_object_versions_history ON s3_object_versions(partition, bucket_name, name COLLATE BINARY, created_order DESC);
CREATE UNIQUE INDEX s3_object_versions_upload ON s3_object_versions(partition, bucket_name, name, upload_id) WHERE upload_id <> '';
CREATE INDEX s3_object_restores_due ON s3_object_restores(due, partition, bucket_name, object_name, version_id);

CREATE TABLE s3_bucket_replication (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);

CREATE TABLE s3_replication_rules (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, position INTEGER NOT NULL,
    id TEXT NOT NULL, priority INTEGER, enabled BOOLEAN NOT NULL,
    filter_kind TEXT NOT NULL, filter_prefix TEXT,
    delete_marker_replication TEXT NOT NULL, sse_kms_objects TEXT NOT NULL,
    replica_modifications TEXT NOT NULL,
    destination_partition TEXT NOT NULL, destination_bucket TEXT NOT NULL,
    destination_region TEXT NOT NULL,
    account_id TEXT NOT NULL, owner_override BOOLEAN NOT NULL,
    storage_class TEXT NOT NULL, kms_key_id TEXT NOT NULL,
    metrics_status TEXT NOT NULL, metrics_minutes INTEGER,
    metrics_ready_at TIMESTAMP NOT NULL,
    time_status TEXT NOT NULL, time_minutes INTEGER,
    PRIMARY KEY (partition, bucket_name, position),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_bucket_replication(partition, bucket_name) ON DELETE CASCADE
);

CREATE TABLE s3_replication_filter_tags (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    rule_position INTEGER NOT NULL, position INTEGER NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, rule_position, position),
    FOREIGN KEY (partition, bucket_name, rule_position) REFERENCES s3_replication_rules(partition, bucket_name, position) ON DELETE CASCADE
);

CREATE TABLE s3_replication_states (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    object_name TEXT NOT NULL COLLATE BINARY, version_id TEXT NOT NULL,
    destination_partition TEXT NOT NULL, destination_bucket TEXT NOT NULL,
    operation TEXT NOT NULL, sequence INTEGER NOT NULL, status TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, destination_partition, destination_bucket, operation),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);

CREATE TABLE s3_replication_jobs (
    sequence INTEGER NOT NULL PRIMARY KEY,
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    object_name TEXT NOT NULL COLLATE BINARY, version_id TEXT NOT NULL,
    destination_partition TEXT NOT NULL, destination_bucket TEXT NOT NULL,
    destination_region TEXT NOT NULL,
    account_id TEXT NOT NULL, owner_override BOOLEAN NOT NULL,
    storage_class TEXT NOT NULL, kms_key_id TEXT NOT NULL,
    metrics_status TEXT NOT NULL, metrics_minutes INTEGER,
    metrics_ready_at TIMESTAMP NOT NULL,
    time_status TEXT NOT NULL, time_minutes INTEGER,
    operation TEXT NOT NULL, role_arn TEXT NOT NULL, rule_id TEXT NOT NULL,
    parent_event_id TEXT NOT NULL,
    created TIMESTAMP NOT NULL, due TIMESTAMP NOT NULL, attempts INTEGER NOT NULL,
    threshold_reported BOOLEAN NOT NULL DEFAULT false,
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
CREATE INDEX s3_replication_jobs_due ON s3_replication_jobs(due, sequence);
CREATE INDEX s3_replication_jobs_threshold ON s3_replication_jobs(created, sequence)
    WHERE time_status = 'Enabled' AND threshold_reported = false;
CREATE INDEX s3_replication_jobs_source ON s3_replication_jobs(partition, bucket_name, object_name, version_id, sequence);
CREATE INDEX s3_replication_jobs_metrics ON s3_replication_jobs(partition, bucket_name, destination_partition, destination_bucket, rule_id, created, sequence);

-- Sampled gauges and accepted counters outlive source buckets and replication rules.
CREATE TABLE s3_replication_metric_publications (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    destination_partition TEXT NOT NULL, destination_bucket TEXT NOT NULL,
    account_id TEXT NOT NULL, source_region TEXT NOT NULL, destination_region TEXT NOT NULL,
    rule_id TEXT NOT NULL, at TIMESTAMP NOT NULL, ready_at TIMESTAMP NOT NULL,
    operations INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
    recurring BOOLEAN NOT NULL DEFAULT false,
    sampled BOOLEAN NOT NULL DEFAULT false,
    pending_operations INTEGER NOT NULL DEFAULT 0, pending_bytes INTEGER NOT NULL DEFAULT 0,
    pending_oldest TIMESTAMP,
    PRIMARY KEY (partition, bucket_name, destination_partition, destination_bucket,
        account_id, source_region, destination_region, rule_id, at)
);
CREATE INDEX s3_replication_metric_publications_due ON s3_replication_metric_publications(
    (CASE WHEN recurring = false AND ready_at > at THEN ready_at ELSE at END),
    at, partition, bucket_name, destination_partition, destination_bucket,
    account_id, source_region, destination_region, rule_id);
