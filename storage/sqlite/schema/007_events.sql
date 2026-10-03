-- Shared envelope ordering is owned by the journal. Payload columns are typed
-- for the emitting service; no credentials or serialized resource blobs belong here.
CREATE TABLE kernel_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at timestamp NOT NULL,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    request_id TEXT NOT NULL,
    actor_arn TEXT NOT NULL,
    event_type TEXT NOT NULL
);

CREATE TABLE iam_session_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    principal_arn TEXT NOT NULL,
    issuer_arn TEXT NOT NULL,
    session_type TEXT NOT NULL,
    expiration timestamp NOT NULL
);
