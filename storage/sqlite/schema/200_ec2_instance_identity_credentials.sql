ALTER TABLE ec2_instances ADD COLUMN identity_credential_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_instances ADD COLUMN identity_info_last_updated DATETIME;
UPDATE ec2_instances SET identity_info_last_updated = launch_time;
