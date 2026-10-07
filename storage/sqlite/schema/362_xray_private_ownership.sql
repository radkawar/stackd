ALTER TABLE xray_groups ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE xray_sampling_rules ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
