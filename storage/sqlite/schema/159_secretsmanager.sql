CREATE TABLE secretsmanager_secrets (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 arn TEXT NOT NULL,
 type TEXT NOT NULL,
 description TEXT,
 kms_key_id TEXT NOT NULL,
 owning_service TEXT NOT NULL,
 created DATETIME NOT NULL,
 changed DATETIME NOT NULL,
 last_accessed DATETIME,
 deleted DATETIME,
 delete_after DATETIME,
 tags_present BOOLEAN NOT NULL,
 policy_document TEXT NOT NULL,
 policy_principals_present BOOLEAN NOT NULL,
 policy_trust BOOLEAN NOT NULL,
 rotation_enabled BOOLEAN,
 rotation_lambda_arn TEXT NOT NULL,
 last_rotated DATETIME,
 next_rotation DATETIME,
 rotation_due DATETIME,
 primary_region TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);
CREATE INDEX secretsmanager_deletions ON secretsmanager_secrets(delete_after, arn) WHERE delete_after IS NOT NULL;
CREATE INDEX secretsmanager_schedules ON secretsmanager_secrets(rotation_due, arn) WHERE rotation_due IS NOT NULL AND deleted IS NULL;

CREATE TABLE secretsmanager_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, secret_name, key),
 FOREIGN KEY (partition, account_id, region, secret_name)
 REFERENCES secretsmanager_secrets(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE secretsmanager_policy_principals (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 arn TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, secret_name, arn),
 FOREIGN KEY (partition, account_id, region, secret_name)
 REFERENCES secretsmanager_secrets(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE secretsmanager_rotation_rules (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 automatically_after_days INTEGER,
 duration TEXT,
 schedule_expression TEXT,
 PRIMARY KEY (partition, account_id, region, secret_name),
 FOREIGN KEY (partition, account_id, region, secret_name)
 REFERENCES secretsmanager_secrets(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE secretsmanager_versions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 id TEXT NOT NULL,
 binary BOOLEAN NOT NULL,
 stages_present BOOLEAN NOT NULL,
 created DATETIME NOT NULL,
 last_accessed DATETIME,
 PRIMARY KEY (partition, account_id, region, secret_name, id),
 FOREIGN KEY (partition, account_id, region, secret_name)
 REFERENCES secretsmanager_secrets(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE INDEX secretsmanager_version_order ON secretsmanager_versions(partition, account_id, region, secret_name, created, id);

CREATE TABLE secretsmanager_version_stages (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 version_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 stage TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, secret_name, version_id, position),
 FOREIGN KEY (partition, account_id, region, secret_name, version_id)
 REFERENCES secretsmanager_versions(partition, account_id, region, secret_name, id) ON DELETE CASCADE
);

-- A separate header distinguishes an absent value (an unfinished AWSPENDING
-- version) from a stored empty slice without touching version metadata.
CREATE TABLE secretsmanager_encrypted_versions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 version_id TEXT NOT NULL,
 values_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, secret_name, version_id),
 FOREIGN KEY (partition, account_id, region, secret_name, version_id)
 REFERENCES secretsmanager_versions(partition, account_id, region, secret_name, id) ON DELETE CASCADE
);

CREATE TABLE secretsmanager_sealed_values (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 version_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key_id TEXT NOT NULL,
 wrapped_key BLOB,
 payload BLOB,
 PRIMARY KEY (partition, account_id, region, secret_name, version_id, position),
 FOREIGN KEY (partition, account_id, region, secret_name, version_id)
 REFERENCES secretsmanager_encrypted_versions(partition, account_id, region, secret_name, version_id) ON DELETE CASCADE
);

CREATE TABLE secretsmanager_replicas (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 replica_region TEXT NOT NULL,
 primary_arn TEXT NOT NULL,
 kms_key_id TEXT NOT NULL,
 status TEXT NOT NULL,
 status_message TEXT NOT NULL,
 due DATETIME,
 PRIMARY KEY (partition, account_id, region, secret_name, replica_region),
 FOREIGN KEY (partition, account_id, region, secret_name)
 REFERENCES secretsmanager_secrets(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE INDEX secretsmanager_replica_work ON secretsmanager_replicas(due, primary_arn || replica_region) WHERE due IS NOT NULL;

CREATE TABLE secretsmanager_rotations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 secret_name TEXT NOT NULL,
 arn TEXT NOT NULL,
 token TEXT NOT NULL,
 invocation_token TEXT NOT NULL,
 step INTEGER NOT NULL,
 attempt INTEGER NOT NULL,
 test_only BOOLEAN NOT NULL,
 due DATETIME NOT NULL,
 deadline DATETIME NOT NULL,
 last_error TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, secret_name),
 FOREIGN KEY (partition, account_id, region, secret_name)
 REFERENCES secretsmanager_secrets(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE INDEX secretsmanager_rotation_work ON secretsmanager_rotations(due, arn);
