-- Cloud Control stores execution intent and progress only. Live resources remain
-- in the existing service-owned tables. Documents below are admitted request
-- inputs, before-images and historical progress, never a resource lookup store.
CREATE TABLE cloudcontrol_requests (
    token TEXT PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    client_token TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    type_name TEXT NOT NULL,
    identifier TEXT NOT NULL,
    operation TEXT NOT NULL,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    desired TEXT NOT NULL,
    before_model TEXT NOT NULL,
    patch TEXT NOT NULL,
    model TEXT NOT NULL,
    error_code TEXT NOT NULL,
    message TEXT NOT NULL,
    caller_json TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    event_time TIMESTAMP NOT NULL,
    due TIMESTAMP NOT NULL,
    revision INTEGER NOT NULL
);
CREATE INDEX cloudcontrol_requests_scope ON cloudcontrol_requests(partition, account_id, region, token);
CREATE INDEX cloudcontrol_requests_due ON cloudcontrol_requests(status, due, token);
