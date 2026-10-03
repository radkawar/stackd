CREATE TABLE glue_registries (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 registry_name TEXT NOT NULL,
 description TEXT,
 status TEXT NOT NULL,
 created_at DATETIME NOT NULL,
 updated_at DATETIME NOT NULL,
 due_at DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, registry_name)
);
CREATE INDEX glue_registry_deletions ON glue_registries (due_at) WHERE status = 'DELETING';
CREATE TABLE glue_registry_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 registry_name TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, registry_name, tag_key),
 FOREIGN KEY (partition, account_id, region, registry_name) REFERENCES glue_registries ON DELETE CASCADE
);
CREATE TABLE glue_schemas (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 registry_name TEXT NOT NULL,
 schema_name TEXT NOT NULL,
 description TEXT,
 data_format TEXT NOT NULL,
 compatibility TEXT NOT NULL,
 status TEXT NOT NULL,
 checkpoint INTEGER NOT NULL,
 latest_version INTEGER NOT NULL,
 next_version INTEGER NOT NULL,
 created_at DATETIME NOT NULL,
 updated_at DATETIME NOT NULL,
 due_at DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, registry_name, schema_name),
 FOREIGN KEY (partition, account_id, region, registry_name) REFERENCES glue_registries ON DELETE CASCADE
);
CREATE INDEX glue_schema_deletions ON glue_schemas (due_at) WHERE status = 'DELETING';
CREATE TABLE glue_schema_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 registry_name TEXT NOT NULL,
 schema_name TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, registry_name, schema_name, tag_key),
 FOREIGN KEY (partition, account_id, region, registry_name, schema_name) REFERENCES glue_schemas ON DELETE CASCADE
);
CREATE TABLE glue_schema_versions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 registry_name TEXT NOT NULL,
 schema_name TEXT NOT NULL,
 version_number INTEGER NOT NULL,
 version_id TEXT NOT NULL UNIQUE,
 definition TEXT NOT NULL,
 canonical TEXT NOT NULL,
 status TEXT NOT NULL,
 created_at DATETIME NOT NULL,
 due_at DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, registry_name, schema_name, version_number),
 FOREIGN KEY (partition, account_id, region, registry_name, schema_name) REFERENCES glue_schemas ON DELETE CASCADE
);
CREATE INDEX glue_schema_version_deletions ON glue_schema_versions (due_at) WHERE status = 'DELETING';
CREATE TABLE glue_schema_metadata (
 version_id TEXT NOT NULL,
 metadata_key TEXT NOT NULL,
 metadata_value TEXT NOT NULL,
 created_at DATETIME NOT NULL,
 ordinal INTEGER NOT NULL,
 PRIMARY KEY (version_id, metadata_key, metadata_value),
 FOREIGN KEY (version_id) REFERENCES glue_schema_versions (version_id) ON DELETE CASCADE
);
