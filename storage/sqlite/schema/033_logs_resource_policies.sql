CREATE TABLE logs_resource_policies (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 policy_scope TEXT NOT NULL CHECK (policy_scope IN ('ACCOUNT', 'RESOURCE')),
 name TEXT NOT NULL,
 group_id TEXT REFERENCES logs_groups(id) ON DELETE CASCADE,
 document TEXT NOT NULL,
 updated INTEGER NOT NULL,
 revision INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, policy_scope, name),
 UNIQUE (group_id),
 CHECK ((policy_scope = 'ACCOUNT' AND group_id IS NULL AND revision = 0)
     OR (policy_scope = 'RESOURCE' AND group_id IS NOT NULL AND revision > 0))
);
