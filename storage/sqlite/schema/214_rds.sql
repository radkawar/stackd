-- RDS native database intent; engine bytes remain outside SQLite.
CREATE TABLE rds_database (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 database_name TEXT NOT NULL,
 username TEXT NOT NULL,
 class TEXT NOT NULL,
 parameter_group TEXT NOT NULL,
 cluster TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 status TEXT NOT NULL,
 desired TEXT NOT NULL,
 operation TEXT NOT NULL,
 restore_snapshot TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 pending_ciphertext BLOB NOT NULL,
 address TEXT NOT NULL,
 port INTEGER NOT NULL,
 requested_port INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 deletion_protection INTEGER NOT NULL,
 http_enabled INTEGER NOT NULL,
 copy_tags INTEGER NOT NULL,
 pending_parameters INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE rds_snapshot (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 source TEXT NOT NULL,
 source_runtime_id TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 database_name TEXT NOT NULL,
 username TEXT NOT NULL,
 class TEXT NOT NULL,
 status TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE rds_parameter_group (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 family TEXT NOT NULL,
 description TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE rds_subnet_group (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name)
);
CREATE TABLE rds_tag (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, tag_key)
);
CREATE TABLE rds_parameter (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 parameter_name TEXT NOT NULL,
 parameter_value TEXT NOT NULL,
 apply_method TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, kind, name, parameter_name)
);
CREATE TABLE rds_subnet (
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
