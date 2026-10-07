-- Private CloudFormation incarnation claims; public tags never establish ownership.
ALTER TABLE org_units ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE org_policies ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE org_resource_policies ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
