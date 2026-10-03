ALTER TABLE ec2_instances ADD COLUMN hibernation_configured BOOLEAN;
ALTER TABLE ec2_instances ADD COLUMN hibernation_ready BOOLEAN NOT NULL DEFAULT FALSE;
