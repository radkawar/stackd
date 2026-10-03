CREATE TABLE org_effective_policy_generations (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, org_id, account_id, policy_type),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);
