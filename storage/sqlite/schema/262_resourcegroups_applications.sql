ALTER TABLE resourcegroups_groups ADD COLUMN managed_type TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groups ADD COLUMN application_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groups ADD COLUMN source_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groups ADD COLUMN source_name TEXT NOT NULL DEFAULT '';
ALTER TABLE resourcegroups_groups ADD COLUMN parent_arn TEXT NOT NULL DEFAULT '';

CREATE TABLE resourcegroups_groupings (
 group_arn TEXT NOT NULL REFERENCES resourcegroups_groups(arn) ON DELETE CASCADE,
 resource_arn TEXT NOT NULL,
 resource_type TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 action TEXT NOT NULL,
 updated INTEGER NOT NULL,
 PRIMARY KEY (group_arn, resource_arn)
);
