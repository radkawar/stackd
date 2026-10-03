CREATE TABLE ec2_network_interfaces (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 network_interface_id TEXT,
 owner_id TEXT,
 requester_id TEXT,
 requester_managed BOOLEAN,
 availability_zone TEXT,
 availability_zone_id TEXT,
 subnet_id TEXT,
 vpc_id TEXT,
 mac_address TEXT,
 description TEXT,
 interface_type TEXT,
 source_dest_check BOOLEAN,
 status TEXT,
 private_ip_address TEXT,
 private_dns_name TEXT,
 groups_present BOOLEAN NOT NULL,
 private_ip_addresses_present BOOLEAN NOT NULL,
 ipv6_addresses_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 operator_present BOOLEAN NOT NULL,
 operator_managed BOOLEAN,
 operator_hidden_by_default BOOLEAN,
 operator_principal TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_network_interface_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 group_id TEXT,
 group_name TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_network_interfaces (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_network_interface_private_ips (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 private_ip_address TEXT,
 is_primary BOOLEAN,
 private_dns_name TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_network_interfaces (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_network_interface_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_network_interfaces (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_network_interface_creations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 subnet_id TEXT,
 description TEXT,
 interface_type TEXT,
 private_ip_address TEXT,
 secondary_private_ip_address_count INTEGER,
 groups_present BOOLEAN NOT NULL,
 private_ip_addresses_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, token)
);

CREATE TABLE ec2_network_interface_creation_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 position INTEGER NOT NULL,
 group_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, token, position),
 FOREIGN KEY (partition, account_id, region, token) REFERENCES ec2_network_interface_creations (partition, account_id, region, token) ON DELETE CASCADE
);

CREATE TABLE ec2_network_interface_creation_private_ips (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 position INTEGER NOT NULL,
 private_ip_address TEXT,
 is_primary BOOLEAN,
 PRIMARY KEY (partition, account_id, region, token, position),
 FOREIGN KEY (partition, account_id, region, token) REFERENCES ec2_network_interface_creations (partition, account_id, region, token) ON DELETE CASCADE
);
