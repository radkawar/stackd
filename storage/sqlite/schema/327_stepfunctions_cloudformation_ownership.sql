ALTER TABLE stepfunctions_versions ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE stepfunctions_aliases ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
