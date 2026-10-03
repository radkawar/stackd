CREATE TABLE appregistry_applications (
    arn TEXT PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    client_token TEXT NOT NULL,
    create_fingerprint TEXT NOT NULL,
    group_arn TEXT NOT NULL,
    tag_group_arn TEXT NOT NULL,
    created INTEGER,
    modified INTEGER,
    UNIQUE (partition, account_id, region, id),
    UNIQUE (partition, account_id, region, name)
);

CREATE TABLE appregistry_application_tags (
    application_arn TEXT NOT NULL REFERENCES appregistry_applications(arn) ON DELETE CASCADE,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (application_arn, tag_key)
);

CREATE TABLE appregistry_attribute_groups (
    arn TEXT PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    attributes TEXT NOT NULL,
    client_token TEXT NOT NULL,
    create_fingerprint TEXT NOT NULL,
    created INTEGER,
    modified INTEGER,
    UNIQUE (partition, account_id, region, id),
    UNIQUE (partition, account_id, region, name)
);

CREATE TABLE appregistry_attribute_group_tags (
    attribute_group_arn TEXT NOT NULL REFERENCES appregistry_attribute_groups(arn) ON DELETE CASCADE,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (attribute_group_arn, tag_key)
);

CREATE TABLE appregistry_attribute_links (
    application_arn TEXT NOT NULL REFERENCES appregistry_applications(arn) ON DELETE CASCADE,
    attribute_group_arn TEXT NOT NULL REFERENCES appregistry_attribute_groups(arn) ON DELETE CASCADE,
    PRIMARY KEY (application_arn, attribute_group_arn)
);
CREATE INDEX appregistry_attribute_links_group ON appregistry_attribute_links(attribute_group_arn);

CREATE TABLE appregistry_resource_associations (
    application_arn TEXT NOT NULL REFERENCES appregistry_applications(arn) ON DELETE CASCADE,
    resource_arn TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    incarnation TEXT NOT NULL,
    apply_tag INTEGER NOT NULL CHECK (apply_tag IN (0, 1)),
    created INTEGER,
    PRIMARY KEY (application_arn, resource_arn)
);

CREATE TABLE appregistry_configurations (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    tag_key TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region)
);
