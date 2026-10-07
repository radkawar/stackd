ALTER TABLE logs_groups ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_destinations ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
