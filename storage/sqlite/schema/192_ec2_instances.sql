ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_instance_id TEXT;
ALTER TABLE ec2_network_interfaces ADD COLUMN attachment_instance_owner_id TEXT;

CREATE TABLE ec2_instances (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 reservation_id TEXT NOT NULL,
 user_data BLOB,
 metadata_token_key BLOB,
 public_key TEXT NOT NULL,
 shutdown_behavior TEXT NOT NULL,
 disable_api_stop BOOLEAN NOT NULL,
 disable_api_termination BOOLEAN NOT NULL,
 intent TEXT NOT NULL,
 generation BLOB NOT NULL CHECK(length(generation) = 8),
 runtime_prepared BOOLEAN NOT NULL,
 effect_started BOOLEAN NOT NULL,
 force BOOLEAN NOT NULL,
 next_action_at DATETIME,
 shutdown_deadline DATETIME,
 command_id TEXT NOT NULL,
 causation_id TEXT NOT NULL,
 console BLOB,
 console_offset INTEGER NOT NULL,
 console_at DATETIME,
 system_status BLOB NOT NULL,
 guest_status BLOB NOT NULL,
 credit_mode TEXT NOT NULL,
 credit_earned INTEGER NOT NULL,
 credit_launch INTEGER NOT NULL,
 credit_surplus INTEGER NOT NULL,
 credit_excess INTEGER NOT NULL,
 credit_usage INTEGER NOT NULL,
 credit_metric_usage INTEGER NOT NULL,
 credit_metric_charged INTEGER NOT NULL,
 credit_metric_period_end DATETIME,
 credit_updated_at DATETIME,
 credit_stopped_at DATETIME,
 credit_hour_end DATETIME,
 credit_native_pid INTEGER NOT NULL,
 credit_native_start_time_ticks BLOB NOT NULL CHECK(length(credit_native_start_time_ticks) = 8),
 ami_launch_index INTEGER,
 architecture TEXT,
 boot_mode TEXT,
 client_token TEXT,
 cpu_options BLOB NOT NULL,
 current_instance_boot_mode TEXT,
 ebs_optimized BOOLEAN,
 ena_support BOOLEAN,
 iam_instance_profile BLOB NOT NULL,
 image_id TEXT,
 instance_id TEXT,
 instance_type TEXT,
 key_name TEXT,
 launch_time DATETIME,
 metadata_options BLOB NOT NULL,
 monitoring BLOB NOT NULL,
 placement BLOB NOT NULL,
 private_dns_name TEXT,
 private_ip_address TEXT,
 root_device_name TEXT,
 root_device_type TEXT,
 source_dest_check BOOLEAN,
 state BLOB NOT NULL,
 state_reason BLOB NOT NULL,
 state_transition_reason TEXT,
 subnet_id TEXT,
 virtualization_type TEXT,
 vpc_id TEXT,
 mappings_present BOOLEAN NOT NULL,
 networks_present BOOLEAN NOT NULL,
 groups_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);
CREATE INDEX ec2_instances_deadline ON ec2_instances (next_action_at, partition, account_id, region, resource_id) WHERE next_action_at IS NOT NULL;

-- These rows, not the EBS catalog, own instance attachment and delete policy.
CREATE TABLE ec2_instance_mappings (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 device_name TEXT,
 ebs_present BOOLEAN NOT NULL,
 associated_resource TEXT,
 attach_time DATETIME,
 delete_on_termination BOOLEAN,
 ebs_card_index INTEGER,
 operator BLOB NOT NULL,
 status TEXT,
 volume_id TEXT,
 volume_owner_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_instances (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE INDEX ec2_instance_volume_attachment ON ec2_instance_mappings (partition, account_id, region, volume_id, resource_id, position) WHERE volume_id IS NOT NULL AND volume_id != '';

-- Mutable ENI configuration and attachment properties belong to ec2_network_interfaces.
CREATE TABLE ec2_instance_networks (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 network_interface_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_instances (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_instance_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 group_id TEXT,
 group_name TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_instances (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_instance_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_instances (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_reservations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 client_token TEXT NOT NULL,
 token_zone TEXT NOT NULL,
 requester_id TEXT NOT NULL,
 launch_principal_arn TEXT NOT NULL,
 launch_principal_id TEXT NOT NULL,
 image_id TEXT,
 instance_type TEXT,
 min_count INTEGER,
 max_count INTEGER,
 key_name TEXT,
 subnet_id TEXT,
 private_ip_address TEXT,
 user_data BLOB,
 disable_api_stop BOOLEAN,
 disable_api_termination BOOLEAN,
 ebs_optimized BOOLEAN,
 shutdown_behavior TEXT,
 cpu_options BLOB NOT NULL,
 credit_specification BLOB NOT NULL,
 iam_instance_profile BLOB NOT NULL,
 metadata_options BLOB NOT NULL,
 monitoring BLOB NOT NULL,
 placement BLOB NOT NULL,
 instances_present BOOLEAN NOT NULL,
 mappings_present BOOLEAN NOT NULL,
 networks_present BOOLEAN NOT NULL,
 groups_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 elastic_gpu_specification_present BOOLEAN NOT NULL,
 elastic_inference_accelerators_present BOOLEAN NOT NULL,
 ipv6_addresses_present BOOLEAN NOT NULL,
 license_specifications_present BOOLEAN NOT NULL,
 secondary_interfaces_present BOOLEAN NOT NULL,
 security_groups_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);
CREATE UNIQUE INDEX ec2_reservations_token_zone ON ec2_reservations (partition, account_id, region, client_token, token_zone) WHERE client_token != '';
CREATE TABLE ec2_reservation_instances (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 instance_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_reservations (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_reservation_mappings (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 device_name TEXT,
 no_device TEXT,
 virtual_name TEXT,
 ebs BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_reservations (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_reservation_networks (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 associate_carrier_ip_address BOOLEAN,
 associate_public_ip_address BOOLEAN,
 delete_on_termination BOOLEAN,
 description TEXT,
 device_index INTEGER,
 interface_type TEXT,
 network_card_index INTEGER,
 network_interface_id TEXT,
 private_ip_address TEXT,
 subnet_id TEXT,
 groups_present BOOLEAN NOT NULL,
 ipv4_prefixes_present BOOLEAN NOT NULL,
 ipv6_addresses_present BOOLEAN NOT NULL,
 ipv6_prefixes_present BOOLEAN NOT NULL,
 private_ip_addresses_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_reservations (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_reservation_network_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 network_position INTEGER NOT NULL,
 position INTEGER NOT NULL,
 group_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, network_position, position),
 FOREIGN KEY (partition, account_id, region, resource_id, network_position) REFERENCES ec2_reservation_networks (partition, account_id, region, resource_id, position) ON DELETE CASCADE
);
CREATE TABLE ec2_reservation_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 group_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_reservations (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_reservation_tag_specifications (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 resource_type TEXT,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_reservations (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_reservation_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 specification_position INTEGER NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, specification_position, position),
 FOREIGN KEY (partition, account_id, region, resource_id, specification_position) REFERENCES ec2_reservation_tag_specifications (partition, account_id, region, resource_id, position) ON DELETE CASCADE
);

CREATE TABLE ec2_instance_credit_defaults (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 family TEXT NOT NULL,
 mode TEXT NOT NULL,
 changes_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, family)
);
CREATE TABLE ec2_instance_credit_default_changes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 family TEXT NOT NULL,
 position INTEGER NOT NULL,
 changed_at DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, family, position),
 FOREIGN KEY (partition, account_id, region, family) REFERENCES ec2_instance_credit_defaults (partition, account_id, region, family) ON DELETE CASCADE
);
CREATE TABLE ec2_instance_credit_launches (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 starts_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region)
);
CREATE TABLE ec2_instance_credit_launch_starts (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 position INTEGER NOT NULL,
 started_at DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, position),
 FOREIGN KEY (partition, account_id, region) REFERENCES ec2_instance_credit_launches (partition, account_id, region) ON DELETE CASCADE
);
CREATE TABLE ec2_instance_credit_modifications (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 specifications_present BOOLEAN NOT NULL,
 successful_present BOOLEAN NOT NULL,
 unsuccessful_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, token)
);
CREATE TABLE ec2_instance_credit_modification_specs (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 position INTEGER NOT NULL,
 instance_id TEXT NOT NULL,
 mode TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, token, position),
 FOREIGN KEY (partition, account_id, region, token) REFERENCES ec2_instance_credit_modifications (partition, account_id, region, token) ON DELETE CASCADE
);
CREATE TABLE ec2_instance_credit_modification_successes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 position INTEGER NOT NULL,
 instance_id TEXT,
 PRIMARY KEY (partition, account_id, region, token, position),
 FOREIGN KEY (partition, account_id, region, token) REFERENCES ec2_instance_credit_modifications (partition, account_id, region, token) ON DELETE CASCADE
);
CREATE TABLE ec2_instance_credit_modification_failures (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 position INTEGER NOT NULL,
 instance_id TEXT,
 error_present BOOLEAN NOT NULL,
 error_code TEXT,
 error_message TEXT,
 PRIMARY KEY (partition, account_id, region, token, position),
 FOREIGN KEY (partition, account_id, region, token) REFERENCES ec2_instance_credit_modifications (partition, account_id, region, token) ON DELETE CASCADE
);
