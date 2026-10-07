ALTER TABLE cloudwatch_alarms ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE cloudwatch_dashboards ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
