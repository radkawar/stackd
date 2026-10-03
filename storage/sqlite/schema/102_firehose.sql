CREATE TABLE firehose_streams (
    id TEXT PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    version INTEGER NOT NULL,
    created DATETIME NOT NULL,
    updated DATETIME,
    lifecycle_due DATETIME NOT NULL,
    buffer_id TEXT NOT NULL,
    tags_present BOOLEAN NOT NULL,
    UNIQUE (partition, account_id, region, name)
);
CREATE INDEX firehose_lifecycle_due ON firehose_streams(lifecycle_due, id) WHERE status IN ('CREATING', 'DELETING');
CREATE TABLE firehose_sources (
    stream_id TEXT PRIMARY KEY REFERENCES firehose_streams(id) ON DELETE CASCADE,
    arn TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    created DATETIME NOT NULL,
    delivery_start DATETIME NOT NULL,
    due DATETIME NOT NULL,
    retention_hours INTEGER NOT NULL
);
CREATE INDEX firehose_source_due ON firehose_sources(due, stream_id);
CREATE TABLE firehose_tags (
    stream_id TEXT NOT NULL REFERENCES firehose_streams(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (stream_id, key)
);
CREATE TABLE firehose_buffers (
    id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL REFERENCES firehose_streams(id) ON DELETE CASCADE,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    created DATETIME NOT NULL,
    due DATETIME NOT NULL,
    count INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    parent_event_id TEXT NOT NULL,
    object_key TEXT NOT NULL,
    stream_version INTEGER NOT NULL
);
CREATE INDEX firehose_buffer_due ON firehose_buffers(due, id);
CREATE INDEX firehose_buffer_stream ON firehose_buffers(stream_id);
-- A stream owns its current configuration; a sealed buffer owns an independent
-- copy. Optional scalar columns and explicit container presence retain the API
-- distinction between omitted and present-empty fields without JSON blobs.
CREATE TABLE firehose_configurations (
    id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL REFERENCES firehose_streams(id) ON DELETE CASCADE,
    buffer_id TEXT REFERENCES firehose_buffers(id) ON DELETE CASCADE,
    bucket_arn TEXT,
    role_arn TEXT,
    prefix TEXT,
    error_output_prefix TEXT,
    compression_format TEXT,
    custom_time_zone TEXT,
    file_extension TEXT,
    backup_mode TEXT,
    buffering_present BOOLEAN NOT NULL,
    interval_seconds INTEGER,
    size_mbs INTEGER,
    logging_present BOOLEAN NOT NULL,
    logging_enabled BOOLEAN,
    log_group TEXT,
    log_stream TEXT,
    encryption_present BOOLEAN NOT NULL,
    no_encryption TEXT,
    processing_present BOOLEAN NOT NULL,
    processing_enabled BOOLEAN,
    processors_present BOOLEAN NOT NULL
);
CREATE INDEX firehose_configuration_stream ON firehose_configurations(stream_id);
CREATE INDEX firehose_configuration_buffer ON firehose_configurations(buffer_id);
CREATE TABLE firehose_processors (
    configuration_id TEXT NOT NULL REFERENCES firehose_configurations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    type TEXT,
    parameters_present BOOLEAN NOT NULL,
    PRIMARY KEY (configuration_id, position)
);
-- Disabled processors are retained exactly, including their parameter text.
CREATE TABLE firehose_processor_parameters (
    configuration_id TEXT NOT NULL,
    processor_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT,
    value TEXT,
    PRIMARY KEY (configuration_id, processor_position, position),
    FOREIGN KEY (configuration_id, processor_position) REFERENCES firehose_processors(configuration_id, position) ON DELETE CASCADE
);
CREATE TABLE firehose_records (
    buffer_id TEXT NOT NULL REFERENCES firehose_buffers(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    data BLOB,
    arrived DATETIME NOT NULL,
    PRIMARY KEY (buffer_id, position)
);
CREATE TABLE firehose_checkpoints (
    stream_id TEXT NOT NULL REFERENCES firehose_streams(id) ON DELETE CASCADE,
    shard_id TEXT NOT NULL,
    sequence TEXT NOT NULL,
    closed BOOLEAN NOT NULL,
    PRIMARY KEY (stream_id, shard_id)
);
-- Metrics belong to a publication name and minute, not a live incarnation.
CREATE TABLE firehose_metric_samples (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    minute DATETIME NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    sample_count INTEGER NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, minute, metric_name, value)
);
CREATE INDEX firehose_metric_due ON firehose_metric_samples(minute, partition, account_id, region, name);
