CREATE TABLE ec2_internet_gateways (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 internet_gateway_id TEXT,
 owner_id TEXT,
 attachments_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_internet_gateway_attachments (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 state TEXT,
 vpc_id TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_internet_gateways (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_internet_gateway_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_internet_gateways (partition, account_id, region, resource_id) ON DELETE CASCADE
);
