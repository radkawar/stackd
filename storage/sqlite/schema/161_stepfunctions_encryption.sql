ALTER TABLE stepfunctions_revisions ADD COLUMN encrypted_data_key BLOB;
ALTER TABLE stepfunctions_revisions ADD COLUMN encrypted_content BLOB;
ALTER TABLE stepfunctions_revisions ADD COLUMN definition_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE stepfunctions_revisions ADD COLUMN needs_nested_sync BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE stepfunctions_activities ADD COLUMN encryption_type TEXT NOT NULL DEFAULT 'AWS_OWNED_KEY';
ALTER TABLE stepfunctions_activities ADD COLUMN kms_key_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE stepfunctions_activities ADD COLUMN data_key_reuse_seconds INTEGER NOT NULL DEFAULT 0;

ALTER TABLE stepfunctions_executions ADD COLUMN encrypted_data_key BLOB;
ALTER TABLE stepfunctions_executions ADD COLUMN encrypted_content BLOB;

ALTER TABLE stepfunctions_frames ADD COLUMN encrypted_data_key BLOB;
ALTER TABLE stepfunctions_frames ADD COLUMN encrypted_content BLOB;

ALTER TABLE stepfunctions_tasks ADD COLUMN encrypted_data_key BLOB;
ALTER TABLE stepfunctions_tasks ADD COLUMN encrypted_content BLOB;
ALTER TABLE stepfunctions_tasks ADD COLUMN input_data_key BLOB;
ALTER TABLE stepfunctions_tasks ADD COLUMN input_content BLOB;

ALTER TABLE stepfunctions_history ADD COLUMN encrypted_data_key BLOB;
ALTER TABLE stepfunctions_history ADD COLUMN encrypted_content BLOB;
