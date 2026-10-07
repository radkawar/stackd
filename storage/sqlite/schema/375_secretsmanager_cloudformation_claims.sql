-- Private claims belong to the native secret incarnation and its independent edges.
ALTER TABLE secretsmanager_secrets ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN policy_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN policy_token TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN rotation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN rotation_token TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN attachment_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN attachment_token TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN attachment_engine TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN attachment_host TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN attachment_port REAL NOT NULL DEFAULT 0;
ALTER TABLE secretsmanager_secrets ADD COLUMN attachment_db_instance TEXT NOT NULL DEFAULT '';
ALTER TABLE secretsmanager_secrets ADD COLUMN attachment_db_cluster TEXT NOT NULL DEFAULT '';
