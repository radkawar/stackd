CREATE TABLE org_account_creation_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    organization_id TEXT NOT NULL,
    creation_request_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    state TEXT NOT NULL,
    failure_reason TEXT NOT NULL
);
