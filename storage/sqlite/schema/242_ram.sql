ALTER TABLE ec2_network_interfaces ADD COLUMN subnet_owner_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ec2_security_groups ADD COLUMN vpc_owner_account_id TEXT NOT NULL DEFAULT '';

CREATE TABLE ram_shares (
 arn TEXT PRIMARY KEY, partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 name TEXT NOT NULL, status TEXT NOT NULL, feature_set TEXT NOT NULL, policy_id TEXT NOT NULL,
 allow_external BOOLEAN NOT NULL, retain_on_leave BOOLEAN NOT NULL,
 created TIMESTAMP NOT NULL, updated TIMESTAMP NOT NULL
);
CREATE INDEX ram_shares_scope ON ram_shares(partition,account_id,region);
CREATE TABLE ram_share_tags (
 share_arn TEXT NOT NULL REFERENCES ram_shares(arn) ON DELETE CASCADE,
 key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(share_arn,key)
);
CREATE TABLE ram_resources (
 share_arn TEXT NOT NULL REFERENCES ram_shares(arn) ON DELETE CASCADE,position INTEGER NOT NULL,
 arn TEXT NOT NULL,resource_type TEXT NOT NULL,partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,
 organization_only BOOLEAN NOT NULL,supports_iam_principals BOOLEAN NOT NULL,
 status TEXT NOT NULL,status_message TEXT NOT NULL,created TIMESTAMP NOT NULL,updated TIMESTAMP NOT NULL,
 PRIMARY KEY(share_arn,position),UNIQUE(share_arn,arn)
);
CREATE INDEX ram_resource_grants ON ram_resources(arn,status);
CREATE TABLE ram_principals (
 share_arn TEXT NOT NULL REFERENCES ram_shares(arn) ON DELETE CASCADE,position INTEGER NOT NULL,
 principal TEXT NOT NULL,principal_id TEXT NOT NULL,status TEXT NOT NULL,invitation_arn TEXT NOT NULL,
 organization BOOLEAN NOT NULL,created TIMESTAMP NOT NULL,updated TIMESTAMP NOT NULL,
 PRIMARY KEY(share_arn,position),UNIQUE(share_arn,principal)
);
CREATE TABLE ram_share_permissions (
 share_arn TEXT NOT NULL REFERENCES ram_shares(arn) ON DELETE CASCADE,position INTEGER NOT NULL,
 arn TEXT NOT NULL,resource_type TEXT NOT NULL,version INTEGER NOT NULL,
 PRIMARY KEY(share_arn,position),UNIQUE(share_arn,resource_type)
);
CREATE TABLE ram_invitations (
 arn TEXT PRIMARY KEY,partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,
 share_arn TEXT NOT NULL,share_name TEXT NOT NULL,sender TEXT NOT NULL,receiver TEXT NOT NULL,status TEXT NOT NULL,
 created TIMESTAMP NOT NULL,updated TIMESTAMP NOT NULL
);
CREATE INDEX ram_invitations_receiver ON ram_invitations(partition,region,receiver);
CREATE TABLE ram_permissions (
 arn TEXT PRIMARY KEY,partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,
 name TEXT NOT NULL,resource_type TEXT NOT NULL,type TEXT NOT NULL,feature_set TEXT NOT NULL,status TEXT NOT NULL,
 resource_type_default BOOLEAN NOT NULL,default_version INTEGER NOT NULL,created TIMESTAMP NOT NULL,updated TIMESTAMP NOT NULL
);
CREATE TABLE ram_permission_tags (
 permission_arn TEXT NOT NULL REFERENCES ram_permissions(arn) ON DELETE CASCADE,
 key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(permission_arn,key)
);
CREATE TABLE ram_permission_versions (
 permission_arn TEXT NOT NULL REFERENCES ram_permissions(arn) ON DELETE CASCADE,version INTEGER NOT NULL,
 document TEXT NOT NULL,created TIMESTAMP NOT NULL,updated TIMESTAMP NOT NULL,deleted BOOLEAN NOT NULL,
 PRIMARY KEY(permission_arn,version)
);
CREATE TABLE ram_permission_actions (
 permission_arn TEXT NOT NULL,version INTEGER NOT NULL,position INTEGER NOT NULL,action TEXT NOT NULL,
 PRIMARY KEY(permission_arn,version,position),
 FOREIGN KEY(permission_arn,version) REFERENCES ram_permission_versions(permission_arn,version) ON DELETE CASCADE
);
CREATE TABLE ram_receipts (
 partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,operation TEXT NOT NULL,token TEXT NOT NULL,
 hash TEXT NOT NULL,arn TEXT NOT NULL,version INTEGER NOT NULL,PRIMARY KEY(partition,account_id,region,operation,token)
);
CREATE TABLE ram_replacements (
 id TEXT PRIMARY KEY,partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,
 from_arn TEXT NOT NULL,to_arn TEXT NOT NULL,status TEXT NOT NULL,from_version INTEGER NOT NULL,to_version INTEGER NOT NULL,
 created TIMESTAMP NOT NULL,updated TIMESTAMP NOT NULL
);
