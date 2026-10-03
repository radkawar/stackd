CREATE TABLE memorydb_clusters (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 status TEXT NOT NULL,
 operation TEXT NOT NULL,
 description TEXT NOT NULL,
 node_type TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 acl_name TEXT NOT NULL,
 parameter_group TEXT NOT NULL,
 restore_snapshot TEXT NOT NULL,
 shards INTEGER NOT NULL,
 replicas INTEGER NOT NULL,
 tls_enabled INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition, account_id, region, name)
);
CREATE TABLE memorydb_users (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 access_string TEXT NOT NULL,
 authentication TEXT NOT NULL,
 status TEXT NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition, account_id, region, name)
);
CREATE TABLE memorydb_acls (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 status TEXT NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition, account_id, region, name)
);
CREATE TABLE memorydb_parameter_groups (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 family TEXT NOT NULL,
 description TEXT NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition, account_id, region, name)
);
CREATE TABLE memorydb_subnet_groups (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition, account_id, region, name)
);
CREATE TABLE memorydb_snapshots (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 source_runtime_id TEXT NOT NULL,
 source TEXT NOT NULL,
 copy_source TEXT NOT NULL,
 status TEXT NOT NULL,
 operation TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 node_type TEXT NOT NULL,
 parameter_group TEXT NOT NULL,
 acl_name TEXT NOT NULL,
 shards INTEGER NOT NULL,
 replicas INTEGER NOT NULL,
 tls_enabled INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition, account_id, region, name)
);
CREATE TABLE memorydb_tags (
 owner_arn TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (owner_arn,tag_key)
);
CREATE TABLE memorydb_nodes (
 owner_arn TEXT NOT NULL,
 node_id TEXT NOT NULL,
 shard INTEGER NOT NULL,
 replica INTEGER NOT NULL,
 address TEXT NOT NULL,
 port INTEGER NOT NULL,
 PRIMARY KEY (owner_arn,node_id)
);
CREATE TABLE memorydb_password_hashes (
 owner_arn TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 PRIMARY KEY (owner_arn,password_hash)
);
CREATE TABLE memorydb_acl_users (
 owner_arn TEXT NOT NULL,
 user_name TEXT NOT NULL,
 PRIMARY KEY (owner_arn,user_name)
);
CREATE TABLE memorydb_parameters (
 owner_arn TEXT NOT NULL,
 parameter_name TEXT NOT NULL,
 parameter_value TEXT NOT NULL,
 PRIMARY KEY (owner_arn,parameter_name)
);
CREATE TABLE memorydb_subnets (
 owner_arn TEXT NOT NULL,
 subnet_id TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 availability_zone TEXT NOT NULL,
 PRIMARY KEY (owner_arn,subnet_id)
);
