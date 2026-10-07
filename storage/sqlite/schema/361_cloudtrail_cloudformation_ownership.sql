ALTER TABLE cloudtrail_trails ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
CREATE INDEX cloudtrail_trails_cfn_owner ON cloudtrail_trails(partition, region, name, cfn_owner) WHERE cfn_owner <> '';
