ALTER TABLE sns_topics ADD COLUMN kms_master_key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_messages ADD COLUMN kms_key_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_messages ADD COLUMN wrapped_data_key BLOB;
ALTER TABLE sns_messages ADD COLUMN encrypted_body BLOB;
