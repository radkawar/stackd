-- Global identifiers and ARNs have no Region. The empty metadata lifecycle has
-- no member/source/endpoint columns: replication must be implemented before a
-- regional database can join. Encryption is retained configuration, not a volume.
CREATE TABLE rds_global_cluster (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 name TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 database_name TEXT NOT NULL,
 engine_lifecycle_support TEXT NOT NULL,
 deletion_protection INTEGER NOT NULL,
 storage_encrypted INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, name)
);
