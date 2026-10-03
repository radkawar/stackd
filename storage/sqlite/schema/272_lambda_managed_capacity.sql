CREATE TABLE lambda_capacity_providers (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 generation TEXT NOT NULL, state TEXT NOT NULL, state_reason TEXT NOT NULL,
 operator_role_arn TEXT NOT NULL, kms_key_arn TEXT NOT NULL, architecture TEXT NOT NULL,
 scaling_mode TEXT NOT NULL, max_vcpus INTEGER NOT NULL, target_cpu REAL NOT NULL,
 log_group TEXT NOT NULL, system_log_level TEXT NOT NULL, propagate_explicit BOOLEAN NOT NULL, modified TIMESTAMP NOT NULL,
 PRIMARY KEY(partition,account,region,name)
);
CREATE TABLE lambda_capacity_provider_members (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, provider_name TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('subnet','security-group','allowed-instance-type','excluded-instance-type')),
 position INTEGER NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,provider_name,kind,position),
 FOREIGN KEY(partition,account,region,provider_name) REFERENCES lambda_capacity_providers(partition,account,region,name) ON DELETE CASCADE
);
CREATE TABLE lambda_capacity_provider_tags (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, provider_name TEXT NOT NULL,
 propagated BOOLEAN NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,provider_name,propagated,key),
 FOREIGN KEY(partition,account,region,provider_name) REFERENCES lambda_capacity_providers(partition,account,region,name) ON DELETE CASCADE
);
CREATE TABLE lambda_function_capacity (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL, version INTEGER NOT NULL,
 provider_arn TEXT NOT NULL, memory_gib_per_vcpu REAL NOT NULL, max_concurrency INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,pending,version),
 FOREIGN KEY(partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
CREATE TABLE lambda_capacity_scaling (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL, qualifier TEXT NOT NULL,
 generation TEXT NOT NULL, min_environments INTEGER NOT NULL, max_environments INTEGER NOT NULL,
 applied_min INTEGER NOT NULL, applied_max INTEGER NOT NULL, modified TIMESTAMP NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,qualifier)
);
CREATE TABLE lambda_capacity_guests (
 id TEXT NOT NULL PRIMARY KEY,
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, provider_name TEXT NOT NULL,
 generation TEXT NOT NULL, instance_id TEXT NOT NULL, subnet_id TEXT NOT NULL, instance_type TEXT NOT NULL,
 endpoint TEXT NOT NULL, agent_token TEXT NOT NULL, agent_certificate BLOB NOT NULL, agent_private_key BLOB NOT NULL,
 command_id TEXT NOT NULL, state TEXT NOT NULL, error TEXT NOT NULL, vcpus INTEGER NOT NULL, memory_mb INTEGER NOT NULL, modified TIMESTAMP NOT NULL
);
CREATE INDEX lambda_capacity_guests_provider ON lambda_capacity_guests(partition,account,region,provider_name);
CREATE TABLE lambda_capacity_environments (
 id TEXT NOT NULL PRIMARY KEY,
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL, version INTEGER NOT NULL,
 generation TEXT NOT NULL, guest_id TEXT NOT NULL, state TEXT NOT NULL, error TEXT NOT NULL,
 credentials_expire TIMESTAMP NOT NULL, modified TIMESTAMP NOT NULL
);
CREATE INDEX lambda_capacity_environments_function ON lambda_capacity_environments(partition,account,region,function_name,version);
