terraform {
  required_version = "= 1.15.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}

variable "endpoint" {
  type = string
  validation {
    condition     = can(regex("^http://127\\.0\\.0\\.1:[0-9]+$", var.endpoint))
    error_message = "Only an explicit IPv4 loopback HTTP endpoint is permitted."
  }
}
variable "name" { type = string }
variable "account_id" { type = string }
variable "identity_store_id" { type = string }
variable "revision" { type = string }
variable "contacts" { type = bool }

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = false
  ignore_tags {
    keys = ["ConsumerRevision"]
  }
  endpoints {
    account        = var.endpoint
    iam            = var.endpoint
    identitystore  = var.endpoint
    kms            = var.endpoint
    secretsmanager = var.endpoint
    sts            = var.endpoint
  }
}

locals {
  root_arn = "arn:aws:iam::${var.account_id}:root"
  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "AccountAuthority${var.revision}", Effect = "Allow"
      Principal = { AWS = local.root_arn }, Action = "kms:*", Resource = "*"
    }]
  })
  consumer_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Secret${var.revision}", Effect = "Allow", Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], Resource = aws_secretsmanager_secret.payload.arn },
      { Sid = "Key${var.revision}", Effect = "Allow", Action = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"], Resource = aws_kms_key.payload.arn }
    ]
  })
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Sid = "Read${var.revision}", Effect = "Allow", Action = "secretsmanager:ListSecrets", Resource = "*" }]
  })
}

resource "aws_iam_user" "reader" {
  name = "${var.name}-reader"
  path = "/${var.name}/"
  tags = { Revision = var.revision }
}
resource "aws_iam_user" "denied" {
  name = "${var.name}-denied"
  path = "/${var.name}/"
  tags = { Revision = var.revision }
}
resource "aws_iam_group" "readers" {
  name = "${var.name}-readers"
  path = var.revision == "v1" ? "/${var.name}/" : "/${var.name}/updated/"
}
resource "aws_iam_group" "secondary" {
  name = "${var.name}-secondary"
}
resource "aws_iam_role" "consumer" {
  name                 = "${var.name}-consumer"
  path                 = "/${var.name}/"
  description          = "Consumer ${var.revision}"
  max_session_duration = var.revision == "v1" ? 3600 : 7200
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Sid = "Trust${var.revision}", Effect = "Allow", Principal = { AWS = aws_iam_user.reader.arn }, Action = "sts:AssumeRole" }]
  })
  tags = { Revision = var.revision }
}
resource "aws_iam_instance_profile" "consumer" {
  name = "${var.name}-consumer"
  role = aws_iam_role.consumer.name
  tags = { Revision = var.revision }
}
resource "aws_iam_policy" "consumer" {
  name        = "${var.name}-consumer"
  path        = "/${var.name}/"
  description = "Local secret and symmetric key consumer"
  policy      = local.consumer_policy
  tags        = { Revision = var.revision }
}
resource "aws_iam_user_policy_attachment" "consumer" {
  user       = aws_iam_user.reader.name
  policy_arn = aws_iam_policy.consumer.arn
}
resource "aws_iam_group_policy_attachment" "consumer" {
  group      = aws_iam_group.readers.name
  policy_arn = aws_iam_policy.consumer.arn
}
resource "aws_iam_role_policy_attachment" "consumer" {
  role       = aws_iam_role.consumer.name
  policy_arn = aws_iam_policy.consumer.arn
}
resource "aws_iam_user_policy" "reader" {
  name   = "${var.name}-inline"
  user   = aws_iam_user.reader.name
  policy = local.inline_policy
}
resource "aws_iam_group_policy" "readers" {
  name   = "${var.name}-inline"
  group  = aws_iam_group.readers.name
  policy = local.inline_policy
}
resource "aws_iam_role_policy" "consumer" {
  name   = "${var.name}-inline"
  role   = aws_iam_role.consumer.name
  policy = local.inline_policy
}
resource "aws_iam_group_membership" "readers" {
  name  = "${var.name}-readers"
  group = aws_iam_group.readers.name
  users = var.revision == "v1" ? [aws_iam_user.reader.name] : []
}
resource "aws_iam_user_group_membership" "secondary" {
  user   = aws_iam_user.reader.name
  groups = var.revision == "v1" ? [aws_iam_group.secondary.name] : []
}
resource "aws_iam_access_key" "reader" {
  user = aws_iam_user.reader.name
}
resource "aws_iam_access_key" "denied" {
  user = aws_iam_user.denied.name
}

# Exclusive resources share only the explicitly listed attachments/inline
# policies. Each has an edge to its ordinary resource writer.
resource "aws_iam_user_policies_exclusive" "reader" {
  user_name    = aws_iam_user.reader.name
  policy_names = [aws_iam_user_policy.reader.name]
}
resource "aws_iam_group_policies_exclusive" "readers" {
  group_name   = aws_iam_group.readers.name
  policy_names = [aws_iam_group_policy.readers.name]
}
resource "aws_iam_role_policies_exclusive" "consumer" {
  role_name    = aws_iam_role.consumer.name
  policy_names = [aws_iam_role_policy.consumer.name]
}
resource "aws_iam_user_policy_attachments_exclusive" "reader" {
  user_name   = aws_iam_user.reader.name
  policy_arns = [aws_iam_user_policy_attachment.consumer.policy_arn]
}
resource "aws_iam_group_policy_attachments_exclusive" "readers" {
  group_name  = aws_iam_group.readers.name
  policy_arns = [aws_iam_group_policy_attachment.consumer.policy_arn]
}
resource "aws_iam_role_policy_attachments_exclusive" "consumer" {
  role_name   = aws_iam_role.consumer.name
  policy_arns = [aws_iam_role_policy_attachment.consumer.policy_arn]
}

resource "aws_kms_key" "payload" {
  description             = "Identity payload ${var.revision}"
  enable_key_rotation     = true
  rotation_period_in_days = var.revision == "v1" ? 365 : 180
  deletion_window_in_days = 7
  tags                    = { Revision = var.revision }
}
resource "aws_kms_key" "alias_target" {
  description             = "Alias replacement ${var.revision}"
  deletion_window_in_days = 7
  tags                    = { Revision = var.revision }
}
resource "aws_kms_key_policy" "payload" {
  key_id = aws_kms_key.payload.id
  policy = local.key_policy
}
resource "aws_kms_alias" "payload" {
  name          = "alias/${var.name}"
  target_key_id = var.revision == "v1" ? aws_kms_key.payload.id : aws_kms_key.alias_target.id
}
resource "aws_kms_grant" "consumer" {
  name              = "${var.name}-${var.revision}"
  key_id            = aws_kms_key.payload.id
  grantee_principal = aws_iam_user.denied.arn
  operations        = ["Decrypt"]
  constraints {
    encryption_context_equals = { Fixture = var.name, Revision = var.revision }
  }
  depends_on = [aws_kms_key_policy.payload]
}
resource "aws_kms_ciphertext" "payload" {
  key_id    = aws_kms_key.payload.id
  plaintext = "stackd symmetric plaintext ${var.revision}"
  context   = { Fixture = var.name, Revision = var.revision }
  depends_on = [aws_kms_key_policy.payload]
}

resource "aws_secretsmanager_secret" "payload" {
  name                    = "${var.name}/payload"
  description             = "Identity secret ${var.revision}"
  kms_key_id              = aws_kms_key.payload.arn
  recovery_window_in_days = 0
  tags                    = { Revision = var.revision }
  depends_on              = [aws_kms_key_policy.payload]
}
resource "aws_secretsmanager_secret_version" "payload" {
  secret_id     = aws_secretsmanager_secret.payload.id
  secret_string = jsonencode({ revision = var.revision, payload = "local-only-identity-${var.revision}" })
  version_stages = ["AWSCURRENT", "fixture-${var.revision}"]
}
resource "aws_secretsmanager_secret_policy" "payload" {
  secret_arn          = aws_secretsmanager_secret.payload.arn
  block_public_policy = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "Consumer${var.revision}", Effect = "Allow"
      Principal = { AWS = [aws_iam_user.reader.arn, aws_iam_role.consumer.arn] }
      Action = "secretsmanager:GetSecretValue", Resource = aws_secretsmanager_secret.payload.arn
    }]
  })
}
resource "aws_secretsmanager_tag" "extra" {
  secret_id = aws_secretsmanager_secret.payload.id
  key       = "ConsumerRevision"
  value     = var.revision
}

resource "aws_identitystore_user" "consumer" {
  identity_store_id = var.identity_store_id
  user_name        = "${var.name}-directory-user"
  display_name     = "Directory ${var.revision}"
  name {
    given_name  = "Local"
    family_name = var.revision == "v1" ? "Consumer" : "Updated"
  }
  emails {
    value   = "${var.revision}@example.invalid"
    type    = "work"
    primary = true
  }
  dynamic "addresses" {
    for_each = var.contacts ? [1] : []
    content {
      street_address = var.revision == "v1" ? "1 Local Street" : "2 Local Street"
      locality       = "Seattle"
      region         = "WA"
      postal_code    = "98101"
      country        = "US"
      type           = "work"
      primary        = true
    }
  }
  dynamic "phone_numbers" {
    for_each = var.contacts ? [1] : []
    content {
      value   = var.revision == "v1" ? "+12065550101" : "+12065550102"
      type    = "work"
      primary = true
    }
  }
}
resource "aws_identitystore_group" "consumers" {
  identity_store_id = var.identity_store_id
  display_name     = "${var.name}-directory-group"
  description      = "Directory group ${var.revision}"
}
resource "aws_identitystore_group_membership" "consumer" {
  identity_store_id = var.identity_store_id
  group_id         = aws_identitystore_group.consumers.group_id
  member_id        = aws_identitystore_user.consumer.user_id
}

# These settings are safe only because run.py starts a private, fresh local
# controller. The runner seeds and restores the primary-contact before-image.
resource "aws_account_primary_contact" "local" {
  address_line_1 = "1 Local Street"
  city          = "Seattle"
  country_code  = "US"
  full_name     = "Local Fixture ${var.revision}"
  phone_number  = "+12065550100"
  postal_code   = "98101"
  state_or_region = "WA"
}
resource "aws_account_alternate_contact" "local" {
  alternate_contact_type = "SECURITY"
  email_address          = "${var.revision}@example.invalid"
  name                   = "Local Security ${var.revision}"
  phone_number           = "+12065550100"
  title                  = "Local fixture contact"
}

output "identity" {
  sensitive = true
  value = {
    name              = var.name
    user              = aws_iam_user.reader.name
    denied_user       = aws_iam_user.denied.name
    user_arn          = aws_iam_user.reader.arn
    denied_user_arn    = aws_iam_user.denied.arn
    role              = aws_iam_role.consumer.name
    role_arn          = aws_iam_role.consumer.arn
    group             = aws_iam_group.readers.name
    secondary_group   = aws_iam_group.secondary.name
    profile           = aws_iam_instance_profile.consumer.name
    policy_arn        = aws_iam_policy.consumer.arn
    inline_name       = aws_iam_user_policy.reader.name
    reader_key        = aws_iam_access_key.reader.id
    reader_secret     = aws_iam_access_key.reader.secret
    denied_key        = aws_iam_access_key.denied.id
    denied_secret     = aws_iam_access_key.denied.secret
    key_id            = aws_kms_key.payload.id
    key_arn           = aws_kms_key.payload.arn
    alias_target_key  = aws_kms_key.alias_target.id
    alias_resolved_key = var.revision == "v1" ? aws_kms_key.payload.id : aws_kms_key.alias_target.id
    alias             = aws_kms_alias.payload.name
    ciphertext        = aws_kms_ciphertext.payload.ciphertext_blob
    grant_id          = aws_kms_grant.consumer.grant_id
    secret_arn        = aws_secretsmanager_secret.payload.arn
    secret_version    = aws_secretsmanager_secret_version.payload.version_id
    identity_store_id = var.identity_store_id
    directory_user    = aws_identitystore_user.consumer.user_id
    directory_group   = aws_identitystore_group.consumers.group_id
    membership        = aws_identitystore_group_membership.consumer.membership_id
  }
}
