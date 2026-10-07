-- Private CloudFormation provenance for identity pools, written once with the
-- row and removed with it. Empty is the unowned direct-API scope. Public pool
-- tags never carry ownership.
ALTER TABLE cognitoidentity_pools ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidentity_pools ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidentity_pools ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX cognitoidentity_pools_owner_incarnation ON cognitoidentity_pools(partition, account_id, region, owner_stack_id, owner_logical_id, owner_token) WHERE owner_token <> '';
