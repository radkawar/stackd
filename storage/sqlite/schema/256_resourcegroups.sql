CREATE TABLE resourcegroups_groups (
    arn TEXT PRIMARY KEY NOT NULL,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    query_present INTEGER NOT NULL CHECK (query_present IN (0, 1)),
    query_type TEXT,
    query_string TEXT,
    created INTEGER,
    UNIQUE (partition, account_id, region, name)
);

CREATE TABLE resourcegroups_group_tags (
    group_arn TEXT NOT NULL REFERENCES resourcegroups_groups(arn) ON DELETE CASCADE,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (group_arn, tag_key)
);
