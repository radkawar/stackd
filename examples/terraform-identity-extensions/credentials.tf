variable "credential_material" {
  type = object({
    server_certificate = string
    server_private_key = string
    signing_certificate = string
    ssh_public_key = string
  })
  sensitive = true
}

resource "aws_iam_account_alias" "credentials" {
  account_alias = "${var.name}-${var.revision}"
}

resource "aws_iam_account_password_policy" "credentials" {
  minimum_password_length        = var.revision == "v1" ? 16 : 24
  require_lowercase_characters    = true
  require_uppercase_characters    = true
  require_numbers                 = true
  require_symbols                 = true
  allow_users_to_change_password   = true
  password_reuse_prevention        = var.revision == "v1" ? 3 : 5
  max_password_age                 = var.revision == "v1" ? 90 : 60
  hard_expiry                      = var.revision == "v2"
}

# The provider has no importer and deletion is a no-op. The runner restores the
# account's captured preference after destroy instead of claiming reversibility.
resource "aws_iam_security_token_service_preferences" "credentials" {
  global_endpoint_token_version = var.revision == "v1" ? "v1Token" : "v2Token"
}

resource "aws_iam_user" "credentials" {
  name = "${var.name}-credentials"
  path = "/credentials/"
  tags = { Revision = var.revision }
}

resource "aws_iam_user" "credentials_denied" {
  name = "${var.name}-credentials-denied"
}

resource "aws_iam_access_key" "credentials" {
  user = aws_iam_user.credentials.name
}

resource "aws_iam_access_key" "credentials_denied" {
  user = aws_iam_user.credentials_denied.name
}

resource "aws_iam_group" "credentials" {
  name = "${var.name}-credentials"
}

resource "aws_iam_group_membership" "credentials" {
  name  = "${var.name}-credentials-membership"
  group = aws_iam_group.credentials.name
  users = [aws_iam_user.credentials.name]
}

resource "aws_iam_role" "credentials" {
  name = "${var.name}-credential-consumer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = aws_iam_user.credentials.arn } }]
  })
}

resource "aws_ssm_parameter" "credentials" {
  name  = "/${var.name}/credential-policy"
  type  = "String"
  value = var.revision
}

resource "aws_ssm_parameter" "credentials_mfa" {
  name  = "/${var.name}/credential-mfa"
  type  = "String"
  value = var.revision
}

resource "aws_iam_policy" "credentials" {
  name = "${var.name}-credential-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "ssm:GetParameter", Resource = aws_ssm_parameter.credentials.arn }]
  })
}

# This policy and these principals are deliberately separate from federation
# and other attachment owners: policy_attachment exclusively owns its bindings.
resource "aws_iam_policy_attachment" "credentials" {
  name       = "${var.name}-credential-bindings"
  policy_arn = aws_iam_policy.credentials.arn
  groups     = var.revision == "v1" ? [aws_iam_group.credentials.name] : []
  users      = var.revision == "v2" ? [aws_iam_user.credentials.name] : []
  roles      = [aws_iam_role.credentials.name]
}

resource "aws_iam_user_policy" "credentials" {
  name = "${var.name}-credential-session"
  user = aws_iam_user.credentials.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "iam:ChangePassword", Resource = aws_iam_user.credentials.arn },
      { Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.credentials.arn },
      { Effect = "Allow", Action = "ssm:GetParameter", Resource = aws_ssm_parameter.credentials_mfa.arn,
        Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } } }
    ]
  })
}

resource "aws_iam_user_login_profile" "credentials" {
  user                    = aws_iam_user.credentials.name
  password_length         = 32
  depends_on              = [aws_iam_account_password_policy.credentials]
  lifecycle {
    # Create-only material cannot be recovered by the native importer.
    ignore_changes = [password_length, pgp_key]
  }
}

resource "aws_iam_server_certificate" "credentials" {
  name             = "${var.name}-server-${var.revision}"
  path             = "/credentials/${var.revision}/"
  certificate_body = var.credential_material.server_certificate
  private_key      = var.credential_material.server_private_key
  tags             = { Revision = var.certificate_tag_revision }
  lifecycle {
    # IAM GetServerCertificate intentionally never discloses a private key.
    ignore_changes = [private_key]
  }
}

resource "aws_iam_signing_certificate" "credentials" {
  user_name        = aws_iam_user.credentials.name
  certificate_body = var.credential_material.signing_certificate
  status           = var.revision == "v1" ? "Active" : "Inactive"
}

resource "aws_iam_service_specific_credential" "credentials" {
  user_name    = aws_iam_user.credentials.name
  service_name = "codecommit.amazonaws.com"
  status       = var.revision == "v1" ? "Active" : "Inactive"
}

resource "aws_iam_user_ssh_key" "credentials" {
  username   = aws_iam_user.credentials.name
  encoding   = "SSH"
  public_key = var.credential_material.ssh_public_key
  status     = var.revision == "v1" ? "Active" : "Inactive"
}

resource "aws_iam_virtual_mfa_device" "credentials" {
  # Native enrollment binds this device to the user; delete it before that user.
  depends_on = [aws_iam_user.credentials]
  virtual_mfa_device_name = "${var.name}-totp"
  path                   = "/credentials/"
  tags                   = { Revision = var.revision }
}

output "credentials" {
  sensitive = true
  value = {
    alias           = aws_iam_account_alias.credentials.account_alias
    user            = aws_iam_user.credentials.name
    user_arn        = aws_iam_user.credentials.arn
    denied_user     = aws_iam_user.credentials_denied.name
    key             = aws_iam_access_key.credentials.id
    secret          = aws_iam_access_key.credentials.secret
    denied_key      = aws_iam_access_key.credentials_denied.id
    denied_secret   = aws_iam_access_key.credentials_denied.secret
    password        = aws_iam_user_login_profile.credentials.password
    group           = aws_iam_group.credentials.name
    role            = aws_iam_role.credentials.name
    role_arn        = aws_iam_role.credentials.arn
    policy_arn      = aws_iam_policy.credentials.arn
    parameter       = aws_ssm_parameter.credentials.name
    mfa_parameter   = aws_ssm_parameter.credentials_mfa.name
    server_name     = aws_iam_server_certificate.credentials.name
    server_arn      = aws_iam_server_certificate.credentials.arn
    server_id       = aws_iam_server_certificate.credentials.id
    signing_id      = aws_iam_signing_certificate.credentials.certificate_id
    service_id      = aws_iam_service_specific_credential.credentials.service_specific_credential_id
    service_login   = aws_iam_service_specific_credential.credentials.service_user_name
    service_secret  = aws_iam_service_specific_credential.credentials.service_password
    ssh_id          = aws_iam_user_ssh_key.credentials.ssh_public_key_id
    mfa_serial      = aws_iam_virtual_mfa_device.credentials.arn
    mfa_seed        = aws_iam_virtual_mfa_device.credentials.base_32_string_seed
  }
}
