CREATE TABLE sesv2_identity_policies (
 arn TEXT NOT NULL REFERENCES sesv2_identities(arn) ON DELETE CASCADE,
 name TEXT NOT NULL,
 document TEXT NOT NULL,
 PRIMARY KEY(arn,name)
);
CREATE TABLE sesv2_identity_policy_principals (
 arn TEXT NOT NULL,
 policy_name TEXT NOT NULL,
 principal_arn TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 PRIMARY KEY(arn,policy_name,principal_arn),
 FOREIGN KEY(arn,policy_name) REFERENCES sesv2_identity_policies(arn,name) ON DELETE CASCADE
);
ALTER TABLE sesv2_messages ADD COLUMN source_identity_arn TEXT NOT NULL DEFAULT '';
