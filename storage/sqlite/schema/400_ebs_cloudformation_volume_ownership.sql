CREATE TABLE ebs_cloudformation_claims (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_type TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 owner TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
) WITHOUT ROWID;

CREATE TABLE ebs_cloudformation_creations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_type TEXT NOT NULL,
 owner TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_type, owner)
) WITHOUT ROWID;
