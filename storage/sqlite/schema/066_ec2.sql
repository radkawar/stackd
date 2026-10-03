-- EC2 networking records preserve pointer presence and ordered protocol sets.

-- Service transactions own resource dependencies and SG rule/permission synchronization.

-- Child foreign keys protect ownership only; no cross-resource cascade changes service semantics.

CREATE TABLE ec2_vpcs (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 block_public_access_states BLOB NOT NULL,
 cidr_block TEXT,
 dhcp_options_id TEXT,
 encryption_control BLOB NOT NULL,
 instance_tenancy TEXT,
 is_default BOOLEAN,
 owner_id TEXT,
 state TEXT,
 vpc_id TEXT,
 dns_hostnames BOOLEAN NOT NULL,
 dns_support BOOLEAN NOT NULL,
 network_address_usage_metrics BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 cidr_block_association_set_present BOOLEAN NOT NULL,
 ipv6_cidr_block_association_set_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_subnets (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 assign_ipv6_address_on_creation BOOLEAN,
 availability_zone TEXT,
 availability_zone_id TEXT,
 available_ip_address_count INTEGER,
 block_public_access_states BLOB NOT NULL,
 cidr_block TEXT,
 customer_owned_ipv4_pool TEXT,
 default_for_az BOOLEAN,
 enable_dns64 BOOLEAN,
 enable_lni_at_device_index INTEGER,
 ipv6_native BOOLEAN,
 map_customer_owned_ip_on_launch BOOLEAN,
 map_public_ip_on_launch BOOLEAN,
 outpost_arn TEXT,
 owner_id TEXT,
 private_dns_name_options_on_launch BLOB NOT NULL,
 state TEXT,
 subnet_arn TEXT,
 subnet_id TEXT,
 type TEXT,
 vpc_id TEXT,
 tags_present BOOLEAN NOT NULL,
 ipv6_cidr_block_association_set_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_security_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 description TEXT,
 group_id TEXT,
 group_name TEXT,
 owner_id TEXT,
 security_group_arn TEXT,
 vpc_id TEXT,
 tags_present BOOLEAN NOT NULL,
 ip_permissions_present BOOLEAN NOT NULL,
 ip_permissions_egress_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_security_group_rules (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 cidr_ipv4 TEXT,
 cidr_ipv6 TEXT,
 description TEXT,
 from_port INTEGER,
 group_id TEXT,
 group_owner_id TEXT,
 ip_protocol TEXT,
 is_egress BOOLEAN,
 prefix_list_id TEXT,
 referenced_group_info BLOB NOT NULL,
 security_group_rule_arn TEXT,
 security_group_rule_id TEXT,
 to_port INTEGER,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_route_tables (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 owner_id TEXT,
 route_table_id TEXT,
 vpc_id TEXT,
 tags_present BOOLEAN NOT NULL,
 associations_present BOOLEAN NOT NULL,
 propagating_vgws_present BOOLEAN NOT NULL,
 routes_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_network_acls (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 is_default BOOLEAN,
 network_acl_id TEXT,
 owner_id TEXT,
 vpc_id TEXT,
 tags_present BOOLEAN NOT NULL,
 associations_present BOOLEAN NOT NULL,
 entries_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_vpc_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpcs (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_subnet_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_subnets (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_security_group_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_security_groups (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_security_group_rule_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_security_group_rules (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_route_table_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_route_tables (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_network_acl_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_network_acls (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_cidr_associations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 association_id TEXT,
 cidr_block TEXT,
 cidr_block_state BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpcs (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_ipv6_associations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 association_id TEXT,
 ip_source TEXT,
 ipv6_address_attribute TEXT,
 ipv6_cidr_block TEXT,
 ipv6_cidr_block_state BLOB NOT NULL,
 ipv6_pool TEXT,
 network_border_group TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpcs (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_subnet_ipv6_associations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 association_id TEXT,
 ip_source TEXT,
 ipv6_address_attribute TEXT,
 ipv6_cidr_block TEXT,
 ipv6_cidr_block_state BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_subnets (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_security_group_permissions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 egress BOOLEAN NOT NULL,
 position INTEGER NOT NULL,
 from_port INTEGER,
 ip_protocol TEXT,
 ip_ranges BLOB NOT NULL,
 ipv6_ranges BLOB NOT NULL,
 prefix_list_ids BLOB NOT NULL,
 to_port INTEGER,
 user_id_group_pairs BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, egress, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_security_groups (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_route_table_associations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 association_state BLOB NOT NULL,
 gateway_id TEXT,
 main BOOLEAN,
 public_ipv4_pool TEXT,
 route_table_association_id TEXT,
 route_table_id TEXT,
 subnet_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_route_tables (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_route_table_propagations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 gateway_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_route_tables (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_route_table_routes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 carrier_gateway_id TEXT,
 core_network_arn TEXT,
 destination_cidr_block TEXT,
 destination_ipv6_cidr_block TEXT,
 destination_prefix_list_id TEXT,
 egress_only_internet_gateway_id TEXT,
 gateway_id TEXT,
 instance_id TEXT,
 instance_owner_id TEXT,
 ip_address TEXT,
 local_gateway_id TEXT,
 nat_gateway_id TEXT,
 network_interface_id TEXT,
 odb_network_arn TEXT,
 origin TEXT,
 state TEXT,
 transit_gateway_id TEXT,
 vpc_peering_connection_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_route_tables (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_network_acl_associations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 network_acl_association_id TEXT,
 network_acl_id TEXT,
 subnet_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_network_acls (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_network_acl_entries (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 cidr_block TEXT,
 egress BOOLEAN,
 icmp_type_code BLOB NOT NULL,
 ipv6_cidr_block TEXT,
 port_range BLOB NOT NULL,
 protocol TEXT,
 rule_action TEXT,
 rule_number INTEGER,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_network_acls (partition, account_id, region, resource_id) ON DELETE CASCADE
);

-- Independent counters survive every resource deletion and preserve all uint64 values.
CREATE TABLE ec2_sequences (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, prefix TEXT NOT NULL,
 sequence BLOB NOT NULL CHECK(length(sequence) = 8),
 PRIMARY KEY (partition, account_id, region, prefix)
);
