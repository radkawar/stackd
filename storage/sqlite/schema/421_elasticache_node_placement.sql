-- Retained cache reservation identity; live packet and DHCP policy is never stored.
ALTER TABLE elasticache_cluster ADD COLUMN subnet_group TEXT NOT NULL DEFAULT '';
ALTER TABLE elasticache_cluster ADD COLUMN client_port INTEGER NOT NULL DEFAULT 0;
CREATE TABLE elasticache_client_subnet (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
 subnet_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, ordinal),
 UNIQUE (partition, account_id, region, kind, name, subnet_id)
);
CREATE TABLE elasticache_security_group (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
 security_group_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, ordinal),
 UNIQUE (partition, account_id, region, kind, name, security_group_id)
);
CREATE TABLE elasticache_node_placement (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
 node_index INTEGER NOT NULL CHECK (node_index > 0),
 interface_id TEXT NOT NULL,
 subnet_id TEXT NOT NULL,
 availability_zone TEXT NOT NULL,
 network_id TEXT NOT NULL,
 address TEXT NOT NULL,
 gateway TEXT NOT NULL,
 pool TEXT NOT NULL,
 mac TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, node_index),
 UNIQUE (partition, account_id, region, kind, name, ordinal),
 UNIQUE (partition, account_id, region, kind, name, interface_id)
);
