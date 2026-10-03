-- Retain regional default initialization even after its resource is deleted.
CREATE TABLE ec2_dhcp_defaults (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 options_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region)
);

CREATE TABLE ec2_dhcp_options (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 dhcp_options_id TEXT,
 owner_id TEXT,
 tags_present BOOLEAN NOT NULL,
 configurations_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_dhcp_options_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_dhcp_options (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_dhcp_configurations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 values_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_dhcp_options (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_dhcp_configuration_values (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 configuration_position INTEGER NOT NULL,
 position INTEGER NOT NULL,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, configuration_position, position),
 FOREIGN KEY (partition, account_id, region, resource_id, configuration_position) REFERENCES ec2_dhcp_configurations (partition, account_id, region, resource_id, position) ON DELETE CASCADE
);
