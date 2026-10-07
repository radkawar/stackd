CREATE TABLE cognitoidp_resource_owners (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 physical_id TEXT NOT NULL,
 member_user TEXT NOT NULL,
 member_group TEXT NOT NULL,
 stack_id TEXT NOT NULL,
 logical_id TEXT NOT NULL,
 token TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id, kind, name),
 FOREIGN KEY (partition, account_id, region, pool_id) REFERENCES cognitoidp_pools(partition, account_id, region, pool_id) ON DELETE CASCADE
);

CREATE INDEX cognitoidp_resource_owners_physical ON cognitoidp_resource_owners(partition, account_id, region, pool_id, kind, physical_id);
CREATE INDEX cognitoidp_resource_owners_member_user ON cognitoidp_resource_owners(partition, account_id, region, pool_id, member_user);
CREATE INDEX cognitoidp_resource_owners_member_group ON cognitoidp_resource_owners(partition, account_id, region, pool_id, member_group);

CREATE TABLE cognitoidp_identity_providers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 provider_name TEXT NOT NULL,
 provider_type TEXT NOT NULL,
 provider_details BLOB NOT NULL,
 attribute_mapping BLOB NOT NULL,
 idp_identifiers BLOB NOT NULL,
 creation_date TIMESTAMP,
 last_modified_date TIMESTAMP,
 PRIMARY KEY (partition, account_id, region, pool_id, provider_name),
 FOREIGN KEY (partition, account_id, region, pool_id) REFERENCES cognitoidp_pools(partition, account_id, region, pool_id) ON DELETE CASCADE
);

-- Prefix domains are unique within a Region across accounts.
CREATE UNIQUE INDEX cognitoidp_pools_domain ON cognitoidp_pools(partition, region, domain) WHERE domain IS NOT NULL;

-- Unsigned public calls to a regionless endpoint resolve a client ID partition-wide.
CREATE INDEX cognitoidp_clients_partition_id ON cognitoidp_clients(partition, client_id);
