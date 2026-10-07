ALTER TABLE stepfunctions_machines ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE stepfunctions_activities ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
