-- AppSync authoritative GraphQL definitions and typed child configuration.
CREATE TABLE appsync_apis (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  api_id TEXT NOT NULL,
  name TEXT NOT NULL,
  auth_type TEXT NOT NULL,
  api_type TEXT NOT NULL,
  visibility TEXT NOT NULL,
  introspection TEXT NOT NULL,
  owner TEXT NOT NULL,
  owner_contact TEXT,
  query_depth_limit INTEGER,
  resolver_count_limit INTEGER,
  xray_enabled INTEGER,
  graphql_uri TEXT NOT NULL,
  realtime_uri TEXT NOT NULL,
  schema_definition TEXT NOT NULL,
  schema_status TEXT NOT NULL,
  schema_details BLOB NOT NULL,
  PRIMARY KEY (api_id)
);

CREATE TABLE appsync_auth (
  api_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  auth_type TEXT NOT NULL,
  pool_region TEXT,
  pool_id TEXT,
  client_regex TEXT,
  default_action TEXT,
  issuer TEXT,
  oidc_client TEXT,
  auth_ttl INTEGER,
  iat_ttl INTEGER,
  PRIMARY KEY (api_id, ordinal),
  FOREIGN KEY (api_id) REFERENCES appsync_apis(api_id) ON DELETE CASCADE
);

CREATE TABLE appsync_tags (
  api_id TEXT NOT NULL,
  tag_key TEXT NOT NULL,
  tag_value TEXT NOT NULL,
  PRIMARY KEY (api_id, tag_key),
  FOREIGN KEY (api_id) REFERENCES appsync_apis(api_id) ON DELETE CASCADE
);

CREATE TABLE appsync_data_sources (
  api_id TEXT NOT NULL,
  name TEXT NOT NULL,
  arn TEXT NOT NULL,
  description TEXT,
  kind TEXT NOT NULL,
  role_arn TEXT,
  metrics TEXT,
  lambda_arn TEXT,
  ddb_region TEXT,
  ddb_table TEXT,
  ddb_caller INTEGER,
  ddb_versioned INTEGER,
  http_endpoint TEXT,
  rds_type TEXT,
  rds_region TEXT,
  rds_secret TEXT,
  rds_database TEXT,
  rds_cluster TEXT,
  rds_schema TEXT,
  PRIMARY KEY (api_id, name),
  FOREIGN KEY (api_id) REFERENCES appsync_apis(api_id) ON DELETE CASCADE
);

CREATE TABLE appsync_functions (
  api_id TEXT NOT NULL,
  function_id TEXT NOT NULL,
  name TEXT NOT NULL,
  arn TEXT NOT NULL,
  description TEXT,
  source_name TEXT NOT NULL,
  runtime_name TEXT,
  runtime_version TEXT,
  code TEXT,
  function_version TEXT,
  request_template TEXT,
  response_template TEXT,
  max_batch_size INTEGER,
  PRIMARY KEY (api_id, function_id),
  FOREIGN KEY (api_id) REFERENCES appsync_apis(api_id) ON DELETE CASCADE,
  FOREIGN KEY (api_id,source_name) REFERENCES appsync_data_sources(api_id,name)
);

CREATE TABLE appsync_resolvers (
  api_id TEXT NOT NULL,
  type_name TEXT NOT NULL,
  field_name TEXT NOT NULL,
  arn TEXT NOT NULL,
  kind TEXT NOT NULL,
  source_name TEXT,
  runtime_name TEXT,
  runtime_version TEXT,
  code TEXT,
  request_template TEXT,
  response_template TEXT,
  max_batch_size INTEGER,
  metrics TEXT,
  PRIMARY KEY (api_id, type_name, field_name),
  FOREIGN KEY (api_id) REFERENCES appsync_apis(api_id) ON DELETE CASCADE,
  FOREIGN KEY (api_id,source_name) REFERENCES appsync_data_sources(api_id,name)
);

CREATE TABLE appsync_pipeline (
  api_id TEXT NOT NULL,
  type_name TEXT NOT NULL,
  field_name TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  function_id TEXT NOT NULL,
  PRIMARY KEY (api_id, type_name, field_name, ordinal),
  FOREIGN KEY (api_id) REFERENCES appsync_apis(api_id) ON DELETE CASCADE,
  FOREIGN KEY (api_id,type_name,field_name) REFERENCES appsync_resolvers(api_id,type_name,field_name) ON DELETE CASCADE,
  FOREIGN KEY (api_id,function_id) REFERENCES appsync_functions(api_id,function_id)
);

CREATE TABLE appsync_keys (
  api_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  description TEXT,
  expires INTEGER NOT NULL,
  deletes INTEGER NOT NULL,
  PRIMARY KEY (api_id, key_id),
  FOREIGN KEY (api_id) REFERENCES appsync_apis(api_id) ON DELETE CASCADE
);

