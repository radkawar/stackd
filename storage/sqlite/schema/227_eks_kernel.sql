-- EKS control intent only; native Kubernetes state and admin credentials stay outside SQLite.
-- Collection columns encode only typed string lists or string-to-string tag maps.
CREATE TABLE eks_cluster (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 kubernetes_version TEXT NOT NULL,
 status TEXT NOT NULL,
 operation TEXT NOT NULL,
 error TEXT NOT NULL,
 endpoint TEXT NOT NULL,
 certificate_authority TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 subnets TEXT NOT NULL,
 security_groups TEXT NOT NULL,
 tags TEXT NOT NULL,
 created INTEGER NOT NULL,
 due INTEGER NOT NULL,
 generation INTEGER NOT NULL,
 client_token TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 creator_arn TEXT NOT NULL,
 creator_id TEXT NOT NULL,
 authentication_mode TEXT NOT NULL,
 bootstrap_admin INTEGER NOT NULL,
 deletion_protection INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE eks_access_entry (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 principal_arn TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 username TEXT NOT NULL,
 type TEXT NOT NULL,
 id TEXT NOT NULL,
 client_token TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 groups TEXT NOT NULL,
 tags TEXT NOT NULL,
 created INTEGER NOT NULL,
 modified INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, principal_arn)
);

CREATE TABLE eks_access_policy (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 principal_arn TEXT NOT NULL,
 policy_arn TEXT NOT NULL,
 scope_type TEXT NOT NULL,
 namespaces TEXT NOT NULL,
 associated INTEGER NOT NULL,
 modified INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, principal_arn, policy_arn)
);

CREATE TABLE eks_update (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL,
 type TEXT NOT NULL,
 status TEXT NOT NULL,
 error_code TEXT NOT NULL,
 error_message TEXT NOT NULL,
 client_token TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 created INTEGER NOT NULL,
 deletion_protection INTEGER,
 authentication_mode TEXT NOT NULL,
 kubernetes_version TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, id)
);

-- Retained command tokens fence replay after later access revocations.
CREATE TABLE eks_access_mutation (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 principal_arn TEXT NOT NULL,
 token TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, principal_arn, token)
);
