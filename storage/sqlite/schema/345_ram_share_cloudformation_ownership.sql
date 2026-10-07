-- Private CloudFormation provenance for shares and their live edges. Public
-- share tags never carry ownership; empty is the unowned direct-API scope.
ALTER TABLE ram_shares ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE ram_resources ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE ram_principals ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE ram_share_permissions ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
