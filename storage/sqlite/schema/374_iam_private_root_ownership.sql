ALTER TABLE iam_managed_policy ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_instance_profile ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_oidc_provider ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_saml_provider ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_mfa_device ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_server_certificate ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
