-- Private CloudFormation incarnation claims; public tags never establish ownership.
ALTER TABLE identitycenter_instances ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE identitycenter_permission_sets ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
