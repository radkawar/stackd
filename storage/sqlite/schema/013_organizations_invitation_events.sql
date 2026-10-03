CREATE TABLE org_invitation_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    organization_id TEXT NOT NULL,
    handshake_id TEXT NOT NULL,
    target_account_id TEXT NOT NULL,
    state TEXT NOT NULL
);
