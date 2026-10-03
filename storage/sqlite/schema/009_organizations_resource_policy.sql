-- Organizations delegation policies share the organization transaction and tags.
CREATE TABLE org_resource_policies (
    partition TEXT NOT NULL,
    org_id TEXT NOT NULL,
    id TEXT NOT NULL,
    arn TEXT NOT NULL,
    content TEXT NOT NULL,
    PRIMARY KEY (partition, org_id),
    FOREIGN KEY (partition, org_id) REFERENCES org_organizations(partition, org_id) ON DELETE CASCADE
);
