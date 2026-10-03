ALTER TABLE api_call_events ADD COLUMN additional_event_data TEXT NOT NULL DEFAULT 'null';
CREATE TABLE api_call_native_resources (
    sequence INTEGER NOT NULL REFERENCES api_call_events(sequence),
    position INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    arn TEXT NOT NULL,
    arn_prefix TEXT NOT NULL,
    PRIMARY KEY (sequence, position)
);
