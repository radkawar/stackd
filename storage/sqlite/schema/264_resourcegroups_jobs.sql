ALTER TABLE resourcegroups_groups ADD COLUMN incarnation TEXT NOT NULL DEFAULT '';
UPDATE resourcegroups_groups SET incarnation = lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2) || '-8' || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6)));
ALTER TABLE resourcegroups_groupings ADD COLUMN task_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groupings ADD COLUMN status TEXT NOT NULL DEFAULT 'SUCCESS';
ALTER TABLE resourcegroups_groups ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groups ADD COLUMN owner TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groups ADD COLUMN criticality INTEGER;
ALTER TABLE resourcegroups_groupings ADD COLUMN error_code TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groupings ADD COLUMN error_message TEXT NOT NULL DEFAULT '';

CREATE TABLE resourcegroups_tag_sync_tasks (
 arn TEXT PRIMARY KEY,
 group_arn TEXT NOT NULL REFERENCES resourcegroups_groups(arn) ON DELETE CASCADE,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 query_type TEXT NOT NULL,
 query_string TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 uses_tag INTEGER NOT NULL,
 status TEXT NOT NULL,
 error_message TEXT NOT NULL,
 created INTEGER NOT NULL,
 next_check INTEGER,
 version INTEGER NOT NULL
);
CREATE TABLE resourcegroups_applied_memberships (
 task_arn TEXT NOT NULL REFERENCES resourcegroups_tag_sync_tasks(arn) ON DELETE CASCADE,
 resource_arn TEXT NOT NULL,
 resource_type TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 applied_at INTEGER NOT NULL,
 PRIMARY KEY (task_arn, resource_arn)
);
CREATE TABLE resourcegroups_lifecycle_accounts (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 desired TEXT NOT NULL,
 status TEXT NOT NULL,
 message TEXT NOT NULL,
 initialized INTEGER NOT NULL,
 next_check INTEGER,
 version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region)
);
-- Snapshots deliberately do not reference the live group: a deletion remains
-- observable until its event and snapshot removal commit together.
CREATE TABLE resourcegroups_lifecycle_snapshots (
 group_arn TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 query_type TEXT,
 query_string TEXT,
 created INTEGER,
 managed_type TEXT NOT NULL,
 application_arn TEXT NOT NULL,
 source_arn TEXT NOT NULL,
 source_name TEXT NOT NULL,
 parent_arn TEXT NOT NULL,
 sequence INTEGER NOT NULL
);
CREATE TABLE resourcegroups_lifecycle_members (
 group_arn TEXT NOT NULL REFERENCES resourcegroups_lifecycle_snapshots(group_arn) ON DELETE CASCADE,
 resource_arn TEXT NOT NULL,
 resource_type TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 PRIMARY KEY (group_arn, resource_arn)
);
