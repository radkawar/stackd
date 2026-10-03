-- AppConfig owns independent resource lifetimes; only nested value rows cascade.
CREATE TABLE appconfig_applications (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 UNIQUE (partition, account_id, region, id)
);

CREATE TABLE appconfig_environments (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 application_id TEXT NOT NULL,
 id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 state TEXT NOT NULL,
 last_poll TIMESTAMP NOT NULL,
 created_at TIMESTAMP NOT NULL,
 UNIQUE (partition, account_id, region, application_id, id)
);

CREATE TABLE appconfig_profiles (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 application_id TEXT NOT NULL,
 id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 location_uri TEXT NOT NULL,
 retrieval_role_arn TEXT NOT NULL,
 type TEXT NOT NULL,
 kms_key_identifier TEXT NOT NULL,
 kms_key_arn TEXT NOT NULL,
 last_poll TIMESTAMP NOT NULL,
 next_version INTEGER NOT NULL,
 created_at TIMESTAMP NOT NULL,
 UNIQUE (partition, account_id, region, application_id, id)
);

CREATE TABLE appconfig_hosted_versions (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 application_id TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 number INTEGER NOT NULL,
 description TEXT NOT NULL,
 content_type TEXT NOT NULL,
 version_label TEXT NOT NULL,
 kms_key_arn TEXT NOT NULL,
 content BLOB NOT NULL,
 UNIQUE (partition, account_id, region, application_id, profile_id, number)
);

CREATE TABLE appconfig_strategies (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 growth_type TEXT NOT NULL,
 replicate_to TEXT NOT NULL,
 duration_minutes INTEGER NOT NULL,
 final_bake_minutes INTEGER NOT NULL,
 growth_factor REAL NOT NULL,
 UNIQUE (partition, account_id, region, id)
);

CREATE TABLE appconfig_deployments (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 application_id TEXT NOT NULL,
 environment_id TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 strategy_id TEXT NOT NULL,
 number INTEGER NOT NULL,
 previous_deployment INTEGER NOT NULL,
 configuration_name TEXT NOT NULL,
 configuration_version TEXT NOT NULL,
 version_label TEXT NOT NULL,
 location_uri TEXT NOT NULL,
 description TEXT NOT NULL,
 content_type TEXT NOT NULL,
 state TEXT NOT NULL,
 type TEXT NOT NULL,
 experiment_flags TEXT NOT NULL,
 growth_type TEXT NOT NULL,
 kms_key_identifier TEXT NOT NULL,
 kms_key_arn TEXT NOT NULL,
 content BLOB NOT NULL,
 duration_minutes INTEGER NOT NULL,
 final_bake_minutes INTEGER NOT NULL,
 growth_factor REAL NOT NULL,
 percentage REAL NOT NULL,
 started_at TIMESTAMP NOT NULL,
 completed_at TIMESTAMP NOT NULL,
 due TIMESTAMP NOT NULL,
 generation INTEGER NOT NULL,
 UNIQUE (partition, account_id, region, application_id, environment_id, number)
);

CREATE TABLE appconfig_sessions (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 client_id TEXT NOT NULL,
 application_id TEXT NOT NULL,
 environment_id TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 last_deployment INTEGER NOT NULL,
 poll_seconds INTEGER NOT NULL,
 created_at TIMESTAMP NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 next_poll TIMESTAMP NOT NULL,
 UNIQUE (partition, account_id, region, token)
);

CREATE TABLE appconfig_extensions (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 arn TEXT NOT NULL,
 version INTEGER NOT NULL,
 UNIQUE (partition, account_id, region, id, version)
);

CREATE TABLE appconfig_associations (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 arn TEXT NOT NULL,
 extension_id TEXT NOT NULL,
 extension_arn TEXT NOT NULL,
 resource_arn TEXT NOT NULL,
 extension_version INTEGER NOT NULL,
 UNIQUE (partition, account_id, region, id)
);

CREATE INDEX appconfig_deployments_due ON appconfig_deployments(due, partition, account_id, region, application_id, environment_id, number);

CREATE TABLE appconfig_environment_monitors (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_environments(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 alarm_arn TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 UNIQUE (parent_id, ordinal)
);

CREATE TABLE appconfig_profile_validators (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_profiles(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 type TEXT NOT NULL,
 content TEXT NOT NULL,
 UNIQUE (parent_id, ordinal)
);

CREATE TABLE appconfig_extension_actions (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_extensions(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 point TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 uri TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 UNIQUE (parent_id, ordinal)
);

CREATE TABLE appconfig_extension_parameters (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_extensions(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 required BOOLEAN NOT NULL,
 dynamic BOOLEAN NOT NULL,
 UNIQUE (parent_id, ordinal)
);

CREATE TABLE appconfig_deployment_events (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_deployments(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 type TEXT NOT NULL,
 description TEXT NOT NULL,
 triggered_by TEXT NOT NULL,
 at TIMESTAMP NOT NULL,
 UNIQUE (parent_id, ordinal)
);

CREATE TABLE appconfig_deployment_invocations (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_deployment_events(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 id TEXT NOT NULL,
 extension_id TEXT NOT NULL,
 action_name TEXT NOT NULL,
 uri TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 error_code TEXT NOT NULL,
 error_message TEXT NOT NULL,
 UNIQUE (parent_id, ordinal)
);

CREATE TABLE appconfig_deployment_extensions (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_deployments(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 association_id TEXT NOT NULL,
 extension_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 UNIQUE (parent_id, ordinal)
);

CREATE TABLE appconfig_association_parameters (
 parent_id INTEGER NOT NULL REFERENCES appconfig_associations(row_id) ON DELETE CASCADE,
 name TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY (parent_id, name)
);

CREATE TABLE appconfig_deployment_extension_parameters (
 parent_id INTEGER NOT NULL REFERENCES appconfig_deployment_extensions(row_id) ON DELETE CASCADE,
 name TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY (parent_id, name)
);

CREATE TABLE appconfig_deployment_extension_actions (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_deployment_extensions(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 point TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL,
 uri TEXT NOT NULL, role_arn TEXT NOT NULL,
 UNIQUE (parent_id,ordinal)
);

CREATE TABLE appconfig_deployment_dynamic_parameters (
 row_id INTEGER PRIMARY KEY,
 parent_id INTEGER NOT NULL REFERENCES appconfig_deployments(row_id) ON DELETE CASCADE,
 name TEXT NOT NULL, UNIQUE (parent_id,name)
);
CREATE TABLE appconfig_deployment_dynamic_values (
 parent_id INTEGER NOT NULL REFERENCES appconfig_deployment_dynamic_parameters(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY (parent_id,ordinal)
);
CREATE TABLE appconfig_tags (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 arn TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY (partition,account_id,region,arn,key)
);
CREATE TABLE appconfig_settings (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 deletion_protection_enabled BOOLEAN NOT NULL, protection_minutes INTEGER NOT NULL,
 vended_metrics_enabled BOOLEAN NOT NULL,
 vended_metrics_set BOOLEAN NOT NULL,
 PRIMARY KEY (partition,account_id,region)
);
