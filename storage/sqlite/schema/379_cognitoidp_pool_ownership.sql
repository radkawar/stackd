-- Private CloudFormation provenance for user pools. A pool claim names the
-- pool itself, cascades with it, and is found by exact incarnation to recover
-- a generated pool ID. Public pool tags never carry ownership.
CREATE UNIQUE INDEX cognitoidp_resource_owners_pool_incarnation ON cognitoidp_resource_owners(partition, account_id, region, stack_id, logical_id, token) WHERE kind = 'pool';
