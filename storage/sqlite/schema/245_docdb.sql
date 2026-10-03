-- DocumentDB control intent only; native engine volumes own document data.
CREATE TABLE docdb_cluster (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 username TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 status TEXT NOT NULL,
 operation TEXT NOT NULL,
 restore_snapshot TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 pending_ciphertext BLOB NOT NULL,
 address TEXT NOT NULL,
 port INTEGER NOT NULL,
 replica_set TEXT NOT NULL,
 ca BLOB NOT NULL,
 requested_port INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 deletion_protection INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,name)
);
CREATE TABLE docdb_instance (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 cluster TEXT NOT NULL,
 class TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 status TEXT NOT NULL,
 created INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,name)
);
CREATE TABLE docdb_snapshot (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 source TEXT NOT NULL,
 source_runtime_id TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 username TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 status TEXT NOT NULL,
 operation TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,name)
);
CREATE TABLE docdb_tag (partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,tag_key TEXT NOT NULL,tag_value TEXT NOT NULL, PRIMARY KEY(partition,account_id,region,kind,name,tag_key));
