-- IAM remains the credential authority. EC2 retains one reference per delivery
-- protocol; HttpTokens changes do not revoke already-issued credentials.
-- Legacy references have no delivery context. Issuers replace those references
-- on retrieval instead of relabeling existing credentials.
ALTER TABLE ec2_instances RENAME COLUMN identity_credential_id TO identity_credential_id_v2;
ALTER TABLE ec2_instances ADD COLUMN identity_credential_id_v1 TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_instance_profile_associations RENAME COLUMN credential_id TO credential_id_v2;
ALTER TABLE ec2_instance_profile_associations ADD COLUMN credential_id_v1 TEXT NOT NULL DEFAULT '';
