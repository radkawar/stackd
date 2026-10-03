CREATE TABLE logs_batch_accepted_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    batch_id TEXT NOT NULL,
    log_group_arn TEXT NOT NULL,
    log_stream_name TEXT NOT NULL,
    event_count INTEGER NOT NULL
);
