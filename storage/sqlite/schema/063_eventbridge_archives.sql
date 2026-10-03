ALTER TABLE eventbridge_rules ADD COLUMN archive_id TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_deliveries ADD COLUMN archive_id TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_events ADD COLUMN replay_name TEXT NOT NULL DEFAULT '';

-- Rules deliberately do not reference archives: a denied KMS creation may leave
-- its managed rule behind, and retained deliveries fence an old incarnation.
CREATE TABLE eventbridge_archives (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
    id TEXT NOT NULL UNIQUE,
    source_partition TEXT NOT NULL, source_account TEXT NOT NULL, source_region TEXT NOT NULL, source_bus_name TEXT NOT NULL,
    description TEXT NOT NULL, kms_key_identifier TEXT NOT NULL, key_arn TEXT NOT NULL,
    pattern_content BLOB NOT NULL, pattern_data_key BLOB NOT NULL,
    retention_days INTEGER NOT NULL, created TIMESTAMP NOT NULL,
    state TEXT NOT NULL, state_reason TEXT NOT NULL,
    version BLOB NOT NULL CHECK(length(version)=8), event_count INTEGER NOT NULL, size_bytes INTEGER NOT NULL,
    PRIMARY KEY (partition, account, region, name)
);
CREATE TABLE eventbridge_archive_entries (
    archive_id TEXT NOT NULL REFERENCES eventbridge_archives(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    event_seconds INTEGER NOT NULL, event_nanos INTEGER NOT NULL,
    ingested_seconds INTEGER NOT NULL, ingested_nanos INTEGER NOT NULL,
    expires_seconds INTEGER, expires_nanos INTEGER NOT NULL,
    content BLOB NOT NULL, data_key BLOB NOT NULL, size_bytes INTEGER NOT NULL,
    PRIMARY KEY (archive_id, id)
);
CREATE INDEX eventbridge_archive_event_time ON eventbridge_archive_entries(archive_id, event_seconds, event_nanos, id);
CREATE INDEX eventbridge_archive_expiration ON eventbridge_archive_entries(expires_seconds, expires_nanos, archive_id, id) WHERE expires_seconds IS NOT NULL;

-- Replay history survives source archive and bus deletion.
CREATE TABLE eventbridge_replays (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
    archive_partition TEXT NOT NULL, archive_account TEXT NOT NULL, archive_region TEXT NOT NULL, archive_name TEXT NOT NULL, archive_id TEXT NOT NULL,
    destination_partition TEXT NOT NULL, destination_account TEXT NOT NULL, destination_region TEXT NOT NULL, destination_bus_name TEXT NOT NULL,
    description TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL, end_time TIMESTAMP NOT NULL, started TIMESTAMP NOT NULL,
    finished_seconds INTEGER, finished_nanos INTEGER NOT NULL,
    due_seconds INTEGER NOT NULL, due_nanos INTEGER NOT NULL,
    cursor_seconds INTEGER NOT NULL, cursor_nanos INTEGER NOT NULL, cursor_id TEXT NOT NULL,
    state TEXT NOT NULL, state_reason TEXT NOT NULL, version BLOB NOT NULL CHECK(length(version)=8),
    request_id TEXT NOT NULL, actor_arn TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, name)
);
CREATE TABLE eventbridge_replay_filters (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, replay_name TEXT NOT NULL,
    position INTEGER NOT NULL, arn TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, replay_name, position),
    FOREIGN KEY (partition, account, region, replay_name) REFERENCES eventbridge_replays(partition, account, region, name) ON DELETE CASCADE
);
CREATE INDEX eventbridge_replay_due ON eventbridge_replays(due_seconds, due_nanos, partition, account, region, name) WHERE state IN ('STARTING', 'RUNNING', 'CANCELLING');
CREATE INDEX eventbridge_replay_expiration ON eventbridge_replays(finished_seconds, finished_nanos, partition, account, region, name) WHERE finished_seconds IS NOT NULL AND state IN ('COMPLETED', 'CANCELLED', 'FAILED');
