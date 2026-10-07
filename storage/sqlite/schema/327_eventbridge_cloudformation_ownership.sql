ALTER TABLE eventbridge_archives ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_connections ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE eventbridge_api_destinations ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
