CREATE TABLE ec2_nat_gateways (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 nat_gateway_id TEXT,
 vpc_id TEXT,
 subnet_id TEXT,
 connectivity_type TEXT,
 availability_mode TEXT,
 state TEXT,
 create_time TEXT,
 delete_time TEXT,
 failure_code TEXT,
 failure_message TEXT,
 tags_present BOOLEAN NOT NULL,
 nat_gateway_addresses_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_nat_gateway_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_nat_gateways (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_nat_gateway_addresses (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 allocation_id TEXT,
 association_id TEXT,
 network_interface_id TEXT,
 private_ip TEXT,
 public_ip TEXT,
 is_primary BOOLEAN,
 status TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_nat_gateways (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_endpoints (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 vpc_endpoint_id TEXT,
 vpc_id TEXT,
 vpc_endpoint_type TEXT,
 service_name TEXT,
 service_region TEXT,
 owner_id TEXT,
 requester_managed BOOLEAN,
 state TEXT,
 creation_timestamp TEXT,
 policy_document TEXT,
 private_dns_enabled BOOLEAN,
 ip_address_type TEXT,
 tags_present BOOLEAN NOT NULL,
 groups_present BOOLEAN NOT NULL,
 route_table_ids_present BOOLEAN NOT NULL,
 subnet_ids_present BOOLEAN NOT NULL,
 network_interface_ids_present BOOLEAN NOT NULL,
 dns_entries_present BOOLEAN NOT NULL,
 dns_options_present BOOLEAN NOT NULL,
 dns_record_ip_type TEXT,
 private_dns_only_for_inbound_resolver_endpoint BOOLEAN,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_vpc_endpoint_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpc_endpoints (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_endpoint_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 group_id TEXT,
 group_name TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpc_endpoints (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_endpoint_route_tables (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpc_endpoints (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_endpoint_subnets (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpc_endpoints (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_endpoint_interfaces (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpc_endpoints (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_vpc_endpoint_dns_entries (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 dns_name TEXT,
 hosted_zone_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_vpc_endpoints (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_network_owner_creations (partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,action TEXT NOT NULL,token TEXT NOT NULL,resource_id TEXT NOT NULL,fingerprint TEXT NOT NULL,PRIMARY KEY(partition,account_id,region,action,token));
ALTER TABLE ec2_network_interfaces ADD COLUMN lambda_function_owner_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_network_interfaces ADD COLUMN lambda_function_owner_incarnation TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_network_interfaces ADD COLUMN network_control_owner_id TEXT NOT NULL DEFAULT '';
