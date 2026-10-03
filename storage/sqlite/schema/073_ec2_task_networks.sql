ALTER TABLE ec2_network_interfaces ADD COLUMN task_owner_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_network_interfaces ADD COLUMN task_public_networking BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_present BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_id TEXT;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_time DATETIME;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_delete_on_termination BOOLEAN;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_device_index INTEGER;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_network_card_index INTEGER;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_status TEXT;
