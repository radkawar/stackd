-- Public key identifiers correlate committed IAM mutations; signing secrets
-- and session tokens stay in the credential store.
CREATE TABLE iam_access_key_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    change_kind TEXT NOT NULL,
    access_key_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    key_status TEXT NOT NULL
);
