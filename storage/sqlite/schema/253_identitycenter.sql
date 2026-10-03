-- IAM Identity Center owns relationships between its domain records. Cascades
-- apply only to normalized fields, not assignments, IAM roles or login state.
CREATE TABLE identitycenter_instances (
    arn TEXT PRIMARY KEY NOT NULL,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    store_id TEXT NOT NULL,
    name TEXT NOT NULL,
    client_token TEXT NOT NULL,
    created DATETIME NOT NULL
);
CREATE INDEX identitycenter_instances_scope ON identitycenter_instances(partition, account_id, region, arn);
CREATE TABLE identitycenter_instance_tags (
    instance_arn TEXT NOT NULL REFERENCES identitycenter_instances(arn) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(instance_arn, key)
);
CREATE TABLE identitycenter_permission_sets (
    arn TEXT PRIMARY KEY NOT NULL,
    instance_arn TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    relay_state TEXT NOT NULL,
    inline_policy TEXT NOT NULL,
    duration_ns INTEGER NOT NULL,
    created DATETIME NOT NULL,
    boundary_arn TEXT NOT NULL,
    boundary_name TEXT NOT NULL,
    boundary_path TEXT NOT NULL
);
CREATE INDEX identitycenter_permission_sets_instance ON identitycenter_permission_sets(instance_arn, arn);
CREATE TABLE identitycenter_permission_set_tags (
    permission_set_arn TEXT NOT NULL REFERENCES identitycenter_permission_sets(arn) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(permission_set_arn, key)
);
CREATE TABLE identitycenter_managed_policies (
    permission_set_arn TEXT NOT NULL REFERENCES identitycenter_permission_sets(arn) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    arn TEXT NOT NULL,
    PRIMARY KEY(permission_set_arn, position)
);
CREATE TABLE identitycenter_customer_managed_policies (
    permission_set_arn TEXT NOT NULL REFERENCES identitycenter_permission_sets(arn) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY(permission_set_arn, position)
);
CREATE TABLE identitycenter_assignments (
    instance_arn TEXT NOT NULL,
    permission_set_arn TEXT NOT NULL,
    account_id TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    PRIMARY KEY(instance_arn, permission_set_arn, account_id, principal_type, principal_id)
);
CREATE TABLE identitycenter_provisionings (
    instance_arn TEXT NOT NULL,
    permission_set_arn TEXT NOT NULL,
    account_id TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    role_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    PRIMARY KEY(permission_set_arn, account_id)
);
CREATE INDEX identitycenter_provisionings_instance ON identitycenter_provisionings(instance_arn, permission_set_arn, account_id);
-- Operation rows represent completed commands; IAM/STS owns the actual role
-- and credential effects. There is no separate speculative operation status.
CREATE TABLE identitycenter_operations (
    id TEXT PRIMARY KEY NOT NULL,
    instance_arn TEXT NOT NULL,
    kind TEXT NOT NULL,
    permission_set_arn TEXT NOT NULL,
    account_id TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created DATETIME NOT NULL
);
CREATE INDEX identitycenter_operations_instance ON identitycenter_operations(instance_arn, id);
CREATE TABLE identitycenter_clients (
    id TEXT PRIMARY KEY NOT NULL,
    secret_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    region TEXT NOT NULL,
    partition TEXT NOT NULL,
    created DATETIME NOT NULL,
    expires DATETIME NOT NULL
);
CREATE TABLE identitycenter_client_scopes (
    client_id TEXT NOT NULL REFERENCES identitycenter_clients(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY(client_id, position)
);
CREATE TABLE identitycenter_devices (
    code_hash TEXT PRIMARY KEY NOT NULL,
    user_code TEXT NOT NULL,
    client_id TEXT NOT NULL,
    instance_arn TEXT NOT NULL,
    user_id TEXT NOT NULL,
    csrf TEXT NOT NULL,
    state TEXT NOT NULL,
    created DATETIME NOT NULL,
    expires DATETIME NOT NULL,
    last_poll DATETIME NOT NULL,
    interval INTEGER NOT NULL
);
CREATE INDEX identitycenter_devices_user_code ON identitycenter_devices(user_code, code_hash);
CREATE TABLE identitycenter_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    family_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    instance_arn TEXT NOT NULL,
    user_id TEXT NOT NULL,
    access_hash TEXT NOT NULL,
    refresh_hash TEXT NOT NULL,
    created DATETIME NOT NULL,
    access_expires DATETIME NOT NULL,
    refresh_expires DATETIME NOT NULL,
    revoked BOOLEAN NOT NULL
);
CREATE INDEX identitycenter_sessions_access ON identitycenter_sessions(access_hash, id);
CREATE INDEX identitycenter_sessions_refresh ON identitycenter_sessions(refresh_hash, id);
CREATE INDEX identitycenter_sessions_family ON identitycenter_sessions(family_id, id);
CREATE TABLE identitycenter_client_grant_types (
    client_id TEXT NOT NULL REFERENCES identitycenter_clients(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    grant_type TEXT NOT NULL,
    PRIMARY KEY(client_id, position)
);
