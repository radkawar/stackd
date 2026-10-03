-- Completed API observations share kernel ordering with service transitions.
-- Parameter and response documents are sanitized event fields, never stored resources.
ALTER TABLE kernel_events ADD COLUMN parent_event_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kernel_events ADD COLUMN actor_service TEXT NOT NULL DEFAULT '';
CREATE TABLE api_call_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    event_id TEXT NOT NULL UNIQUE,
    event_source TEXT NOT NULL,
    event_name TEXT NOT NULL,
    event_category TEXT NOT NULL,
    read_only INTEGER NOT NULL,
    identity_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    identity_account_id TEXT NOT NULL,
    access_key_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    issuer_arn TEXT NOT NULL,
    issuer_user_name TEXT NOT NULL,
    session_created_at timestamp,
    mfa_authenticated INTEGER NOT NULL,
    source_identity TEXT NOT NULL,
    source_ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    request_parameters TEXT NOT NULL,
    response_elements TEXT NOT NULL
);
CREATE INDEX api_call_events_name ON api_call_events(event_name, sequence);
CREATE INDEX kernel_events_history_scope ON kernel_events(partition, account_id, region, occurred_at, sequence);
CREATE TABLE api_call_event_resources (
    sequence INTEGER NOT NULL REFERENCES api_call_events(sequence),
    position INTEGER NOT NULL,
    resource_type TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    PRIMARY KEY (sequence, position)
);
CREATE INDEX api_call_resources_name ON api_call_event_resources(resource_name, sequence);
CREATE INDEX api_call_resources_type ON api_call_event_resources(resource_type, sequence);
CREATE TABLE eventbridge_accepted_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    event_id TEXT NOT NULL,
    event_bus_arn TEXT NOT NULL
);
CREATE TABLE sqs_message_accepted_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    message_id TEXT NOT NULL,
    queue_arn TEXT NOT NULL
);
