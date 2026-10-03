CREATE TABLE kinesis_streams (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    engine_id TEXT NOT NULL,
    next_partition INTEGER NOT NULL,
    retention_next_at TIMESTAMP NOT NULL,
    metrics_next_at TIMESTAMP NOT NULL,
    channel_count INTEGER,
    consumer_count INTEGER,
    encryption_type TEXT,
    key_id TEXT,
    max_record_size_kib INTEGER,
    open_shard_count INTEGER,
    retention_hours INTEGER,
    stream_arn TEXT,
    created_at TIMESTAMP,
    stream_id TEXT,
    mode_present BOOLEAN NOT NULL,
    mode TEXT,
    stream_name TEXT,
    status TEXT,
    warm_present BOOLEAN NOT NULL,
    warm_current INTEGER,
    warm_target INTEGER,
    monitoring_present BOOLEAN NOT NULL,
    shard_updates_present BOOLEAN NOT NULL,
    encryption_updates_present BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE kinesis_pending_updates (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    accepted_at TIMESTAMP NOT NULL,
    retention_hours INTEGER NOT NULL,
    mode TEXT NOT NULL,
    max_record_size_kib INTEGER NOT NULL,
    encryption_type TEXT NOT NULL,
    key_id TEXT NOT NULL,
    monitoring_present BOOLEAN NOT NULL,
    warm_mibps INTEGER,
    peak_shard_count INTEGER NOT NULL,
    PRIMARY KEY (partition, account_id, region, name),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_monitoring_groups (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    position INTEGER NOT NULL,
    metrics_present BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, position),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_monitoring_metrics (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    group_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    metric TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, group_position, position),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_pending_metrics (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    position INTEGER NOT NULL,
    metric TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, position),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_shard_updates (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    position INTEGER NOT NULL,
    at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, position),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_encryption_updates (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    position INTEGER NOT NULL,
    at TIMESTAMP NOT NULL,
    enabled BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, position),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_shards (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    native_partition INTEGER NOT NULL,
    state TEXT NOT NULL,
    opened_at TIMESTAMP NOT NULL,
    closed_at TIMESTAMP NOT NULL,
    shard_id TEXT,
    parent_id TEXT,
    adjacent_parent_id TEXT,
    hash_present BOOLEAN NOT NULL,
    hash_start TEXT,
    hash_end TEXT,
    sequence_present BOOLEAN NOT NULL,
    sequence_start TEXT,
    sequence_end TEXT,
    PRIMARY KEY (partition, account_id, region, name, native_partition),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_consumers (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    consumer_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    consumer_arn TEXT,
    creation_timestamp TIMESTAMP,
    data_name TEXT,
    status TEXT,
    stream_arn TEXT,
    delete_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, consumer_name, created_at),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_streams (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_tag_sets (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    arn TEXT NOT NULL,
    tags_present BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, arn)
);

CREATE TABLE kinesis_tags (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    arn TEXT NOT NULL,
    position INTEGER NOT NULL,
    key TEXT,
    value TEXT,
    PRIMARY KEY (partition, account_id, region, arn, position),
    FOREIGN KEY (partition, account_id, region, arn) REFERENCES kinesis_tag_sets (partition, account_id, region, arn) ON DELETE CASCADE
);

CREATE TABLE kinesis_policies (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    arn TEXT NOT NULL,
    document TEXT NOT NULL,
    trust_policy BOOLEAN NOT NULL,
    principals_present BOOLEAN NOT NULL,
    effective_document TEXT NOT NULL,
    effective_trust_policy BOOLEAN NOT NULL,
    effective_principals_present BOOLEAN NOT NULL,
    publish_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account_id, region, arn)
);

CREATE TABLE kinesis_policy_principals (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    arn TEXT NOT NULL,
    effective BOOLEAN NOT NULL,
    principal TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region, arn, effective, principal),
    FOREIGN KEY (partition, account_id, region, arn) REFERENCES kinesis_policies (partition, account_id, region, arn) ON DELETE CASCADE
);

CREATE TABLE kinesis_accounts (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    earliest_allowed_end_at TIMESTAMP,
    ended_at TIMESTAMP,
    started_at TIMESTAMP,
    status TEXT,
    PRIMARY KEY (partition, account_id, region)
);

CREATE TABLE kinesis_mode_switch_sets (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    times_present BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE kinesis_mode_switches (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    position INTEGER NOT NULL,
    at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, position),
    FOREIGN KEY (partition, account_id, region, name) REFERENCES kinesis_mode_switch_sets (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE kinesis_metric_samples (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    minute TIMESTAMP NOT NULL,
    shard_id TEXT NOT NULL,
    consumer_name TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    sample_count INTEGER NOT NULL,
    PRIMARY KEY (partition, account_id, region, name, minute, consumer_name, shard_id, metric_name, value)
);

CREATE INDEX kinesis_streams_metrics_due ON kinesis_streams (metrics_next_at, partition, account_id, region, name);

CREATE INDEX kinesis_metrics_due ON kinesis_metric_samples (minute, partition, account_id, region, name);
