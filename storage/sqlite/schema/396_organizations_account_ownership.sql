-- Private account claims are admitted with provisioning receipts, never tags.
ALTER TABLE org_creations ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE org_members ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE org_members ADD COLUMN cloudformation_region TEXT NOT NULL DEFAULT '';
ALTER TABLE org_registry ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE org_registry ADD COLUMN cloudformation_region TEXT NOT NULL DEFAULT '';
