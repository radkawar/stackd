ALTER TABLE iam_role ADD COLUMN identity_center_instance_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_role ADD COLUMN identity_center_permission_set_arn TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX iam_role_identity_center_owner
ON iam_role (partition, account, identity_center_instance_arn, identity_center_permission_set_arn)
WHERE identity_center_instance_arn <> '';
