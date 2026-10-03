ALTER TABLE lambda_kafka_mappings ADD COLUMN root_ca_secret_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_kafka_mappings ADD COLUMN network_role_arn TEXT NOT NULL DEFAULT '';

CREATE TABLE lambda_kafka_bootstrap_servers (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 position INTEGER NOT NULL,
 endpoint TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,position),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_kafka_mappings(partition,account,region,uuid) ON DELETE CASCADE
);

CREATE TABLE lambda_kafka_network_components (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 uuid TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('subnet','security_group')),
 resource_id TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,uuid,kind,resource_id),
 FOREIGN KEY(partition,account,region,uuid) REFERENCES lambda_kafka_mappings(partition,account,region,uuid) ON DELETE CASCADE
);
