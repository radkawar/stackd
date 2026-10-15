-- Retain caller-authorized SCRAM grant identities, not credentials. Existing
-- policy-only associations remain untrusted until explicit reassociation.
ALTER TABLE msk_cluster_secrets ADD COLUMN kms_key_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE msk_cluster_secrets ADD COLUMN grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE msk_cluster_secrets ADD COLUMN incarnation TEXT NOT NULL DEFAULT '';
