CREATE TABLE lambda_code_signing_configs (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 description TEXT NOT NULL,
 policy TEXT NOT NULL CHECK(policy IN ('Warn','Enforce')),
 modified TIMESTAMP NOT NULL,
 PRIMARY KEY(partition,account,region,id)
);

CREATE TABLE lambda_code_signing_publishers (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 config_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 profile_version_arn TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,config_id,position),
 FOREIGN KEY(partition,account,region,config_id) REFERENCES lambda_code_signing_configs(partition,account,region,id) ON DELETE CASCADE
);

CREATE TABLE lambda_code_signing_tags (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 config_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,config_id,key),
 FOREIGN KEY(partition,account,region,config_id) REFERENCES lambda_code_signing_configs(partition,account,region,id) ON DELETE CASCADE
);

CREATE TABLE lambda_function_code_signing_configs (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 function_name TEXT NOT NULL,
 config_id TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name),
 FOREIGN KEY(partition,account,region,config_id) REFERENCES lambda_code_signing_configs(partition,account,region,id)
);

ALTER TABLE lambda_functions ADD COLUMN signing_profile_version_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_functions ADD COLUMN signing_job_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_layer_versions ADD COLUMN signing_profile_version_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_layer_versions ADD COLUMN signing_job_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_layers ADD COLUMN signing_profile_version_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_layers ADD COLUMN signing_job_arn TEXT NOT NULL DEFAULT '';
