CREATE TABLE msk_clusters (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 kafka_version TEXT NOT NULL,
 security_mode TEXT NOT NULL,
 state TEXT NOT NULL,
 failure TEXT NOT NULL,
 operation TEXT NOT NULL,
 operation_arn TEXT NOT NULL,
 configuration_arn TEXT NOT NULL,
 pending_configuration_arn TEXT NOT NULL,
 configuration_revision INTEGER NOT NULL,
 pending_configuration_revision INTEGER NOT NULL,
 server_properties TEXT NOT NULL,
 pending_server_properties TEXT NOT NULL,
 brokers INTEGER NOT NULL,
 reboot_broker_id INTEGER NOT NULL,
 version INTEGER NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 capem BLOB NOT NULL,
 policy_document TEXT NOT NULL,
 policy_version INTEGER NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition,account_id,region,name)
);
CREATE TABLE msk_configurations (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 created INTEGER NOT NULL,
 latest_revision INTEGER NOT NULL,
 PRIMARY KEY (arn),
 UNIQUE (partition,account_id,region,name)
);
CREATE TABLE msk_revisions (
 arn TEXT NOT NULL,
 revision INTEGER NOT NULL,
 description TEXT NOT NULL,
 server_properties TEXT NOT NULL,
 created INTEGER NOT NULL,
 PRIMARY KEY (arn,revision)
);
CREATE TABLE msk_operations (
 arn TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 cluster_arn TEXT NOT NULL,
 type TEXT NOT NULL,
 state TEXT NOT NULL,
 failure TEXT NOT NULL,
 source_configuration_arn TEXT NOT NULL,
 target_configuration_arn TEXT NOT NULL,
 source_revision INTEGER NOT NULL,
 target_revision INTEGER NOT NULL,
 created INTEGER NOT NULL,
 ended INTEGER NOT NULL,
 PRIMARY KEY (arn)
);
CREATE TABLE msk_cluster_tags (
 arn TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (arn,tag_key),
 FOREIGN KEY (arn) REFERENCES msk_clusters(arn) ON DELETE CASCADE
);
CREATE TABLE msk_cluster_secrets (
 arn TEXT NOT NULL,
 secret_arn TEXT NOT NULL,
 PRIMARY KEY (arn,secret_arn),
 FOREIGN KEY (arn) REFERENCES msk_clusters(arn) ON DELETE CASCADE
);
CREATE TABLE msk_cluster_brokers (
 arn TEXT NOT NULL,
 broker_id INTEGER NOT NULL,
 address TEXT NOT NULL,
 PRIMARY KEY (arn,broker_id),
 FOREIGN KEY (arn) REFERENCES msk_clusters(arn) ON DELETE CASCADE
);
CREATE TABLE msk_policy_principals (
 arn TEXT NOT NULL,
 principal_arn TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 PRIMARY KEY (arn,principal_arn),
 FOREIGN KEY (arn) REFERENCES msk_clusters(arn) ON DELETE CASCADE
);
CREATE TABLE msk_configuration_versions (
 arn TEXT NOT NULL,
 kafka_version TEXT NOT NULL,
 PRIMARY KEY (arn,kafka_version),
 FOREIGN KEY (arn) REFERENCES msk_configurations(arn) ON DELETE CASCADE
);
CREATE INDEX msk_operation_cluster ON msk_operations(cluster_arn);
