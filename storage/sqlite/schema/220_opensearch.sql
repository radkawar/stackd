-- OpenSearch control intent; native indices and documents remain in owned volumes.
CREATE TABLE opensearch_domain (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 status TEXT NOT NULL,
 native_endpoint TEXT NOT NULL,
 last_error TEXT NOT NULL,
 access_policy TEXT NOT NULL,
 instance_type TEXT NOT NULL,
 instance_count INTEGER NOT NULL,
 created INTEGER NOT NULL,
 updated INTEGER NOT NULL,
 due INTEGER NOT NULL,
 version INTEGER NOT NULL,
 config_version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE opensearch_advanced_option (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 option_key TEXT NOT NULL,
 option_value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, option_key),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES opensearch_domain(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE opensearch_policy_principal (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 principal_arn TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, principal_arn),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES opensearch_domain(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE opensearch_tag (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, tag_key),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES opensearch_domain(partition, account_id, region, name) ON DELETE CASCADE
);
