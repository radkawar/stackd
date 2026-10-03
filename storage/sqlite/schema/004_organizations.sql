-- Organizations owns its account registry, policy graph and provisioning intents.
CREATE TABLE org_partitions (
    partition TEXT NOT NULL,
    revision BLOB NOT NULL,
    account_sequence BLOB NOT NULL,
    PRIMARY KEY (partition)
);

CREATE TABLE org_registry (
    partition TEXT NOT NULL,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    arn TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL,
    state TEXT NOT NULL,
    joined_method TEXT NOT NULL,
    joined_timestamp REAL NOT NULL,
    PRIMARY KEY (partition, position),
    FOREIGN KEY (partition) REFERENCES org_partitions(partition) ON DELETE CASCADE
);

CREATE TABLE org_organizations (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    arn TEXT NOT NULL,
    feature_set TEXT NOT NULL,
    master_account_id TEXT NOT NULL,
    master_account_arn TEXT NOT NULL,
    master_account_email TEXT NOT NULL,
    root_id TEXT NOT NULL,
    root_arn TEXT NOT NULL,
    root_name TEXT NOT NULL,
    credentials_management BOOLEAN NOT NULL,
    root_sessions BOOLEAN NOT NULL,
    PRIMARY KEY (partition, org_id),
    FOREIGN KEY (partition) REFERENCES org_partitions(partition) ON DELETE CASCADE
);

CREATE TABLE org_available_policy_types (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_root_policy_types (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_members (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    arn TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL,
    state TEXT NOT NULL,
    joined_method TEXT NOT NULL,
    joined_timestamp REAL NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_units (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    arn TEXT NOT NULL,
    name TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_parents (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    child_id TEXT NOT NULL,
    parent_id TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_creations (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    account_name TEXT NOT NULL,
    email TEXT NOT NULL,
    role_name TEXT NOT NULL,
    state TEXT NOT NULL,
    failure_reason TEXT NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    due TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_policies (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    arn TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    aws_managed BOOLEAN NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_attachments (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    target_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_tags (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    resource_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_services (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    principal TEXT NOT NULL,
    enabled REAL NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_delegations (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    enabled REAL NOT NULL,
    PRIMARY KEY (partition, org_id, position),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);

CREATE TABLE org_creation_tags (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    creation_position INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, org_id, creation_position, key),
    FOREIGN KEY (partition, org_id, creation_position) REFERENCES org_creations(partition, org_id, position) ON DELETE CASCADE
);
