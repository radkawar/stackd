CREATE TABLE org_effective_policy_events (
    sequence INTEGER PRIMARY KEY,
    organization_id TEXT NOT NULL,
    target_account_id TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    state TEXT NOT NULL,
    FOREIGN KEY (sequence) REFERENCES kernel_events(sequence) ON DELETE CASCADE
);
