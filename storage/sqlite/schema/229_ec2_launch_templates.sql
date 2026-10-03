-- Launch-template metadata, immutable typed versions, ordered children and scoped idempotency.
CREATE TABLE ec2_launch_template (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, resource_id TEXT NOT NULL,
 name TEXT NOT NULL, created_at TIMESTAMP NOT NULL, created_by TEXT NOT NULL,
 default_version INTEGER NOT NULL, latest_version INTEGER NOT NULL, last_version INTEGER NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY(partition,account_id,region,resource_id), UNIQUE(partition,account_id,region,name)
);
CREATE TABLE ec2_launch_template_tag (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, resource_id TEXT NOT NULL,
 position INTEGER NOT NULL, key TEXT, value TEXT,
 PRIMARY KEY(partition,account_id,region,resource_id,position),
 FOREIGN KEY(partition,account_id,region,resource_id) REFERENCES ec2_launch_template(partition,account_id,region,resource_id) ON DELETE CASCADE
);
CREATE TABLE ec2_launch_template_token (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 action TEXT NOT NULL, token TEXT NOT NULL, fingerprint TEXT NOT NULL, resource_id TEXT NOT NULL, version INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,action,token)
);
ALTER TABLE ec2_reservations ADD COLUMN launch_template BLOB NOT NULL DEFAULT 'null';

CREATE TABLE ec2_lt_version_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 created_at TIMESTAMP NOT NULL,
 created_by TEXT NOT NULL,
 description TEXT,
 block_device_mappings_present BOOLEAN NOT NULL,
 capacity_reservation_specification BLOB NOT NULL,
 cpu_options BLOB NOT NULL,
 credit_specification BLOB NOT NULL,
 disable_api_stop BOOLEAN,
 disable_api_termination BOOLEAN,
 ebs_optimized BOOLEAN,
 elastic_gpu_specifications_present BOOLEAN NOT NULL,
 elastic_inference_accelerators_present BOOLEAN NOT NULL,
 enclave_options BLOB NOT NULL,
 hibernation_options BLOB NOT NULL,
 iam_instance_profile BLOB NOT NULL,
 image_id TEXT,
 instance_initiated_shutdown_behavior TEXT,
 instance_market_options BLOB NOT NULL,
 instance_requirements BLOB NOT NULL,
 instance_type TEXT,
 kernel_id TEXT,
 key_name TEXT,
 license_specifications_present BOOLEAN NOT NULL,
 maintenance_options BLOB NOT NULL,
 metadata_options BLOB NOT NULL,
 monitoring BLOB NOT NULL,
 network_interfaces_present BOOLEAN NOT NULL,
 network_performance_options BLOB NOT NULL,
 operator BLOB NOT NULL,
 placement BLOB NOT NULL,
 private_dns_name_options BLOB NOT NULL,
 ram_disk_id TEXT,
 secondary_interfaces_present BOOLEAN NOT NULL,
 security_group_ids_present BOOLEAN NOT NULL,
 security_groups_present BOOLEAN NOT NULL,
 tag_specifications_present BOOLEAN NOT NULL,
 user_data TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version),
 FOREIGN KEY (partition,account_id,region,resource_id) REFERENCES ec2_launch_template(partition,account_id,region,resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_block_device_mappings_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 device_name TEXT,
 ebs BLOB NOT NULL,
 no_device TEXT,
 virtual_name TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_elastic_gpu_specifications_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 type TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_elastic_inference_accelerators_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 count INTEGER,
 type TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_license_specifications_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 license_configuration_arn TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_network_interfaces_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 associate_carrier_ip_address BOOLEAN,
 associate_public_ip_address BOOLEAN,
 connection_tracking_specification BLOB NOT NULL,
 delete_on_termination BOOLEAN,
 description TEXT,
 device_index INTEGER,
 ena_queue_count INTEGER,
 ena_srd_specification BLOB NOT NULL,
 groups_present BOOLEAN NOT NULL,
 interface_type TEXT,
 ipv4_prefix_count INTEGER,
 ipv4_prefixes_present BOOLEAN NOT NULL,
 ipv6_address_count INTEGER,
 ipv6_addresses_present BOOLEAN NOT NULL,
 ipv6_prefix_count INTEGER,
 ipv6_prefixes_present BOOLEAN NOT NULL,
 network_card_index INTEGER,
 network_interface_id TEXT,
 primary_ipv6 BOOLEAN,
 private_ip_address TEXT,
 private_ip_addresses_present BOOLEAN NOT NULL,
 secondary_private_ip_address_count INTEGER,
 subnet_id TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_network_interfaces_groups_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 version_network_interfaces_position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version,version_position) REFERENCES ec2_lt_version_network_interfaces_record(partition,account_id,region,resource_id,version,version_position) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_network_interfaces_ipv4_prefixes_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 version_network_interfaces_position INTEGER NOT NULL,
 ipv4_prefix TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version,version_position) REFERENCES ec2_lt_version_network_interfaces_record(partition,account_id,region,resource_id,version,version_position) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_network_interfaces_ipv6_addresses_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 version_network_interfaces_position INTEGER NOT NULL,
 ipv6_address TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version,version_position) REFERENCES ec2_lt_version_network_interfaces_record(partition,account_id,region,resource_id,version,version_position) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_network_interfaces_ipv6_prefixes_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 version_network_interfaces_position INTEGER NOT NULL,
 ipv6_prefix TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version,version_position) REFERENCES ec2_lt_version_network_interfaces_record(partition,account_id,region,resource_id,version,version_position) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_network_interfaces_private_ip_addresses_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 version_network_interfaces_position INTEGER NOT NULL,
 "primary" BOOLEAN,
 private_ip_address TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version,version_position) REFERENCES ec2_lt_version_network_interfaces_record(partition,account_id,region,resource_id,version,version_position) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_secondary_interfaces_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 delete_on_termination BOOLEAN,
 device_index INTEGER,
 interface_type TEXT,
 network_card_index INTEGER,
 private_ip_address_count INTEGER,
 private_ip_addresses_present BOOLEAN NOT NULL,
 secondary_subnet_id TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_secondary_interfaces_private_ip_addresses_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 version_secondary_interfaces_position INTEGER NOT NULL,
 private_ip_address TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position,version_secondary_interfaces_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version,version_position) REFERENCES ec2_lt_version_secondary_interfaces_record(partition,account_id,region,resource_id,version,version_position) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_security_group_ids_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_security_groups_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_tag_specifications_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 resource_type TEXT,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version) REFERENCES ec2_lt_version_record(partition,account_id,region,resource_id,version) ON DELETE CASCADE
);

CREATE TABLE ec2_lt_version_tag_specifications_tags_record (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 version_position INTEGER NOT NULL,
 version_tag_specifications_position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition,account_id,region,resource_id,version,version_position,version_tag_specifications_position),
 FOREIGN KEY (partition,account_id,region,resource_id,version,version_position) REFERENCES ec2_lt_version_tag_specifications_record(partition,account_id,region,resource_id,version,version_position) ON DELETE CASCADE
);
