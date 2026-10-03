CREATE TABLE cognitoidentity_pools (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, pool_id TEXT NOT NULL,
 name TEXT NOT NULL, allow_unauthenticated INTEGER NOT NULL, allow_classic INTEGER NOT NULL,
 providers BLOB NOT NULL, tags BLOB NOT NULL, roles BLOB NOT NULL, mappings BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id), UNIQUE (partition,region,pool_id)
);
CREATE TABLE cognitoidentity_identities (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, pool_id TEXT NOT NULL,
 identity_id TEXT NOT NULL, created TIMESTAMP NOT NULL, modified TIMESTAMP NOT NULL,
 PRIMARY KEY (partition,region,identity_id),
 FOREIGN KEY (partition,account_id,region,pool_id) REFERENCES cognitoidentity_pools(partition,account_id,region,pool_id) ON DELETE CASCADE
);
CREATE INDEX cognitoidentity_pool_identities ON cognitoidentity_identities(partition,account_id,region,pool_id,identity_id);
CREATE TABLE cognitoidentity_logins (
 partition TEXT NOT NULL, region TEXT NOT NULL, pool_id TEXT NOT NULL, identity_id TEXT NOT NULL,
 provider TEXT NOT NULL, subject TEXT NOT NULL,
 PRIMARY KEY (partition,region,pool_id,provider,subject),
 FOREIGN KEY (partition,region,identity_id) REFERENCES cognitoidentity_identities(partition,region,identity_id) ON DELETE CASCADE
);
CREATE INDEX cognitoidentity_identity_logins ON cognitoidentity_logins(partition,region,identity_id);
