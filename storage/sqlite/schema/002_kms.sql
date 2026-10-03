-- Shared material belongs to a partition/account key set. Regional policy,
-- lifecycle, grants and imports belong to independent regional key records.
CREATE TABLE kms_key_sets (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    key_id TEXT NOT NULL,
    spec TEXT NOT NULL,
    usage TEXT NOT NULL,
    origin TEXT NOT NULL,
    current_material_id TEXT NOT NULL,
    pending_material_id TEXT NOT NULL,
    rotation_enabled BOOLEAN NOT NULL,
    rotation_period_days INTEGER NOT NULL,
    rotation_next TIMESTAMP NOT NULL,
    rotation_started TIMESTAMP NOT NULL,
    multi_region BOOLEAN NOT NULL,
    primary_region TEXT NOT NULL,
    PRIMARY KEY (partition, account, key_id)
);
CREATE TABLE kms_materials (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    key_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    material_id TEXT NOT NULL,
    material BLOB,
    rotation_date TIMESTAMP NOT NULL,
    rotation_type TEXT NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (partition, account, key_id, position),
    FOREIGN KEY (partition, account, key_id) REFERENCES kms_key_sets(partition, account, key_id) ON DELETE CASCADE
);
CREATE TABLE kms_replica_regions (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    key_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    region TEXT NOT NULL,
    PRIMARY KEY (partition, account, key_id, position),
    FOREIGN KEY (partition, account, key_id) REFERENCES kms_key_sets(partition, account, key_id) ON DELETE CASCADE
);
CREATE TABLE kms_keys (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    arn TEXT NOT NULL,
    description TEXT NOT NULL,
    manager TEXT NOT NULL,
    state TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    deletion TIMESTAMP,
    available_at TIMESTAMP NOT NULL,
    pending_deletion_days INTEGER NOT NULL,
    policy TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, key_id),
    FOREIGN KEY (partition, account, key_id) REFERENCES kms_key_sets(partition, account, key_id)
);
CREATE TABLE kms_principals (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    reference TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, key_id, reference),
    FOREIGN KEY (partition, account, region, key_id) REFERENCES kms_keys(partition, account, region, key_id) ON DELETE CASCADE
);
CREATE TABLE kms_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, key_id, tag_key),
    FOREIGN KEY (partition, account, region, key_id) REFERENCES kms_keys(partition, account, region, key_id) ON DELETE CASCADE
);
CREATE TABLE kms_imports (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    material_id TEXT NOT NULL,
    valid_to TIMESTAMP,
    PRIMARY KEY (partition, account, region, key_id, material_id),
    FOREIGN KEY (partition, account, region, key_id) REFERENCES kms_keys(partition, account, region, key_id) ON DELETE CASCADE
);
CREATE TABLE kms_import_parameters (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    token BLOB NOT NULL,
    private_key BLOB NOT NULL,
    algorithm TEXT NOT NULL,
    valid_to TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, region, key_id, position),
    FOREIGN KEY (partition, account, region, key_id) REFERENCES kms_keys(partition, account, region, key_id) ON DELETE CASCADE
);
CREATE TABLE kms_grants (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    grantee TEXT NOT NULL,
    grantee_id TEXT NOT NULL,
    retiring TEXT NOT NULL,
    retiring_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, region, key_id, grant_id),
    FOREIGN KEY (partition, account, region, key_id) REFERENCES kms_keys(partition, account, region, key_id) ON DELETE CASCADE
);
CREATE TABLE kms_grant_lists (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, key_id, grant_id, kind, position),
    FOREIGN KEY (partition, account, region, key_id, grant_id) REFERENCES kms_grants(partition, account, region, key_id, grant_id) ON DELETE CASCADE
);
CREATE TABLE kms_grant_constraints (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    key_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, key_id, grant_id, kind, tag_key),
    FOREIGN KEY (partition, account, region, key_id, grant_id) REFERENCES kms_grants(partition, account, region, key_id, grant_id) ON DELETE CASCADE
);
CREATE TABLE kms_aliases (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    updated TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, region, name),
    FOREIGN KEY (partition, account, region, key_id) REFERENCES kms_keys(partition, account, region, key_id) ON DELETE CASCADE
);
