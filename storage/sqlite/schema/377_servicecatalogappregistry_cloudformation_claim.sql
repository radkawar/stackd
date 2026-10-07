ALTER TABLE appregistry_attribute_links ADD COLUMN cloudformation_claim TEXT NOT NULL DEFAULT '';
ALTER TABLE appregistry_resource_associations ADD COLUMN cloudformation_claim TEXT NOT NULL DEFAULT '';
ALTER TABLE appregistry_applications ADD COLUMN cloudformation_claim TEXT NOT NULL DEFAULT '';
ALTER TABLE appregistry_attribute_groups ADD COLUMN cloudformation_claim TEXT NOT NULL DEFAULT '';
