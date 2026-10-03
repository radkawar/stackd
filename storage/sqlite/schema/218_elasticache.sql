-- Scoped ElastiCache intent. Credentials are SHA-256 hashes; native bytes stay outside SQLite.
CREATE TABLE elasticache_cluster (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 node_type TEXT NOT NULL,
 description TEXT NOT NULL,
 parameter_group TEXT NOT NULL,
 user_group TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 status TEXT NOT NULL,
 operation TEXT NOT NULL,
 restore_snapshot TEXT NOT NULL,
 shards INTEGER NOT NULL,
 replicas INTEGER NOT NULL,
 cluster_mode INTEGER NOT NULL,
 tls_enabled INTEGER NOT NULL,
 memory_bytes INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE elasticache_snapshot (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 source_kind TEXT NOT NULL,
 source TEXT NOT NULL,
 source_runtime_id TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 copy_source TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 node_type TEXT NOT NULL,
 status TEXT NOT NULL,
 operation TEXT NOT NULL,
 shards INTEGER NOT NULL,
 replicas INTEGER NOT NULL,
 cluster_mode INTEGER NOT NULL,
 tls_enabled INTEGER NOT NULL,
 memory_bytes INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE elasticache_user (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 user_name TEXT NOT NULL,
 engine TEXT NOT NULL,
 access_string TEXT NOT NULL,
 status TEXT NOT NULL,
 no_password INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE elasticache_user_group (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 engine TEXT NOT NULL,
 status TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE elasticache_parameter_group (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 family TEXT NOT NULL,
 description TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE elasticache_subnet_group (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE elasticache_tag (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, tag_key)
);
CREATE TABLE elasticache_parameter (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 parameter_name TEXT NOT NULL,
 parameter_value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, parameter_name)
);
CREATE TABLE elasticache_node (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 node_id TEXT NOT NULL,
 address TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 shard INTEGER NOT NULL,
 replica INTEGER NOT NULL,
 port INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, ordinal)
);
CREATE TABLE elasticache_password_hash (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 hex_hash TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, ordinal)
);
CREATE TABLE elasticache_member (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 user_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, user_id)
);
CREATE TABLE elasticache_subnet (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 subnet_id TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 availability_zone TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, subnet_id)
);
