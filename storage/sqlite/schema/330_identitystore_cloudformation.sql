ALTER TABLE identitystore_groups ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE identitystore_memberships ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
