ALTER TABLE cloudformation_resources ADD COLUMN dynamic_references TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(dynamic_references));
ALTER TABLE cloudformation_steps ADD COLUMN before_dynamic_references TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(before_dynamic_references));
ALTER TABLE cloudformation_steps ADD COLUMN after_dynamic_references TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(after_dynamic_references));
