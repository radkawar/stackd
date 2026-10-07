ALTER TABLE iam_user ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_user_inline ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_group ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_group_inline ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_group_members ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_role ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_role_inline ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_credential ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_user_attached ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_group_attached ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_role_attached ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
CREATE TABLE iam_group_membership_claims (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 resource_key TEXT NOT NULL,
 owner TEXT NOT NULL,
 PRIMARY KEY (partition, account, resource_key, owner),
 FOREIGN KEY (partition, account, resource_key) REFERENCES iam_group(partition, account, resource_key) ON DELETE CASCADE
);
