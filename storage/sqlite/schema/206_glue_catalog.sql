-- Glue Data Catalog metadata. Nested AWS structures are typed configuration
-- columns; identities, scopes, versions and relationships remain relational.
CREATE TABLE glue_catalogs (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  parameters_json TEXT NOT NULL,
  database_permissions_json TEXT NOT NULL,
  table_permissions_json TEXT NOT NULL,
  full_table_access TEXT,
  tags_json TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id)
);

CREATE TABLE glue_databases (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  description TEXT,
  location_uri TEXT,
  created_at TIMESTAMP NOT NULL,
  parameters_json TEXT NOT NULL,
  default_permissions_json TEXT NOT NULL,
  target_database_json TEXT NOT NULL,
  tags_json TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name)
);

CREATE TABLE glue_tables (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  version INTEGER NOT NULL,
  description TEXT,
  owner TEXT,
  created_by TEXT,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  last_access_at TIMESTAMP,
  last_analyzed_at TIMESTAMP,
  retention INTEGER,
  storage_descriptor_json TEXT NOT NULL,
  partition_keys_json TEXT NOT NULL,
  parameters_json TEXT NOT NULL,
  table_type TEXT,
  target_table_json TEXT NOT NULL,
  view_original_text TEXT,
  view_expanded_text TEXT,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name, table_name)
);

CREATE TABLE glue_table_versions (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  version INTEGER NOT NULL,
  description TEXT,
  owner TEXT,
  created_by TEXT,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  last_access_at TIMESTAMP,
  last_analyzed_at TIMESTAMP,
  retention INTEGER,
  storage_descriptor_json TEXT NOT NULL,
  partition_keys_json TEXT NOT NULL,
  parameters_json TEXT NOT NULL,
  table_type TEXT,
  target_table_json TEXT NOT NULL,
  view_original_text TEXT,
  view_expanded_text TEXT,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name, table_name, version)
);

CREATE TABLE glue_partitions (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  values_json TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  last_access_at TIMESTAMP,
  last_analyzed_at TIMESTAMP,
  parameters_json TEXT NOT NULL,
  storage_descriptor_json TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name, table_name, values_json)
);

CREATE TABLE glue_functions (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  function_name TEXT NOT NULL,
  class_name TEXT,
  function_type TEXT,
  owner_name TEXT,
  owner_type TEXT,
  created_at TIMESTAMP NOT NULL,
  resource_uris_json TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name, function_name)
);

CREATE TABLE glue_partition_indexes (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  index_name TEXT NOT NULL,
  status TEXT NOT NULL,
  keys_json TEXT NOT NULL,
  backfill_errors_json TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name, table_name, index_name)
);

CREATE TABLE glue_column_statistics (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  column_name TEXT NOT NULL,
  column_type TEXT NOT NULL,
  analyzed_at TIMESTAMP NOT NULL,
  statistics_data_json TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name, table_name, column_name)
);

CREATE TABLE glue_partition_column_statistics (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  database_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  values_json TEXT NOT NULL,
  column_name TEXT NOT NULL,
  column_type TEXT NOT NULL,
  analyzed_at TIMESTAMP NOT NULL,
  statistics_data_json TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id, database_name, table_name, values_json, column_name)
);

CREATE TABLE glue_resource_policies (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  document TEXT NOT NULL,
  principal_ids_json TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  PRIMARY KEY (partition, account_id, region)
);

CREATE TABLE glue_catalog_imports (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  catalog_id TEXT NOT NULL,
  completed INTEGER NOT NULL,
  imported_at TIMESTAMP NOT NULL,
  imported_by TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, catalog_id)
);

