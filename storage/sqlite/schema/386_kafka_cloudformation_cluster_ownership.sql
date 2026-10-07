-- Private CloudFormation incarnation claim for MSK clusters, matching the
-- configuration claim from 333. Public cluster tags never carry ownership.
ALTER TABLE msk_clusters ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE msk_clusters ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE msk_clusters ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
