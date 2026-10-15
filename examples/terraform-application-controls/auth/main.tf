# This fixture covers only the resources below, not complete Cognito or SES parity.
terraform {
  required_version = ">= 1.15.9, < 2.0.0"
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
    error_message = "Only an explicit IPv4 loopback endpoint is allowed."
  }
}
variable "name" { type = string }
variable "password" {
  type      = string
  sensitive = true
}
variable "revision" {
  type    = string
  default = "initial"
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  endpoints {
    cognitoidentity = var.endpoint
    cognitoidp      = var.endpoint
    iam             = var.endpoint
    ses             = var.endpoint
    sesv2           = var.endpoint
    sts             = var.endpoint
  }
}

resource "aws_cognito_user_pool" "users" {
  name                     = var.name
  user_pool_tier           = "LITE"
  mfa_configuration        = "OFF"
  auto_verified_attributes = ["email"]
  software_token_mfa_configuration {
    enabled = false
  }
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
  tags = { Revision = var.revision }
}
resource "aws_cognito_user_pool_client" "app" {
  user_pool_id                  = aws_cognito_user_pool.users.id
  name                          = "${var.name}-${var.revision}"
  explicit_auth_flows           = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors = "ENABLED"
  access_token_validity         = 1
  id_token_validity             = 1
  refresh_token_validity        = 30
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
  read_attributes  = ["email", "email_verified", "name"]
  write_attributes = ["email", "name"]
}
resource "aws_cognito_user" "alice" {
  user_pool_id   = aws_cognito_user_pool.users.id
  username       = "alice"
  message_action = "SUPPRESS"
  password       = var.password
  attributes = {
    email          = "${var.name}@example.com"
    email_verified = "true"
    name           = var.revision
  }
}
resource "aws_cognito_user_group" "readers" {
  user_pool_id = aws_cognito_user_pool.users.id
  name         = "readers"
  description  = var.revision
  precedence   = 1
}
resource "aws_cognito_user_in_group" "alice" {
  user_pool_id = aws_cognito_user_pool.users.id
  username     = aws_cognito_user.alice.username
  group_name   = aws_cognito_user_group.readers.name
}
resource "aws_cognito_identity_pool" "identities" {
  identity_pool_name               = "${var.name}-${var.revision}"
  allow_unauthenticated_identities = false
  allow_classic_flow               = false
  cognito_identity_providers {
    client_id               = aws_cognito_user_pool_client.app.id
    provider_name           = "cognito-idp.us-east-1.amazonaws.com/${aws_cognito_user_pool.users.id}"
    server_side_token_check = true
  }
  tags = { Revision = var.revision }
}
resource "aws_iam_role" "authenticated" {
  name = var.name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "cognito-identity.amazonaws.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals             = { "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.identities.id }
        "ForAnyValue:StringLike" = { "cognito-identity.amazonaws.com:amr" = "authenticated" }
      }
    }]
  })
}
resource "aws_iam_role_policy" "mail" {
  name = "mail"
  role = aws_iam_role.authenticated.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ses:SendEmail", "ses:SendTemplatedEmail"], Resource = "*" }]
  })
}
resource "aws_cognito_identity_pool_roles_attachment" "authenticated" {
  identity_pool_id = aws_cognito_identity_pool.identities.id
  roles            = { authenticated = aws_iam_role.authenticated.arn }
}
resource "aws_sesv2_configuration_set" "mail" {
  configuration_set_name = var.name
  sending_options {
    sending_enabled = true
  }
  tags = { Revision = var.revision }
}
resource "aws_ses_configuration_set" "classic" {
  name            = "${var.name}-classic"
  sending_enabled = true
}
resource "aws_sesv2_email_identity" "sender" {
  email_identity         = "${var.name}@example.com"
  configuration_set_name = aws_sesv2_configuration_set.mail.configuration_set_name
  tags                   = { Revision = var.revision }
}
resource "aws_ses_template" "message" {
  name    = var.name
  subject = "Lifecycle ${var.revision} {{name}}"
  text    = "Captured ${var.revision} email for {{name}}."
  html    = "<p>Captured ${var.revision} email for {{name}}.</p>"
}

data "aws_cognito_user_pool" "users" { user_pool_id = aws_cognito_user_pool.users.id }
data "aws_cognito_user_pool_client" "app" {
  user_pool_id = aws_cognito_user_pool.users.id
  client_id    = aws_cognito_user_pool_client.app.id
}
data "aws_cognito_user_group" "readers" {
  user_pool_id = aws_cognito_user_pool.users.id
  name         = aws_cognito_user_group.readers.name
}
data "aws_cognito_identity_pool" "identities" {
  identity_pool_name = aws_cognito_identity_pool.identities.identity_pool_name
}
data "aws_sesv2_email_identity" "sender" { email_identity = aws_sesv2_email_identity.sender.email_identity }
data "aws_ses_email_identity" "sender" { email = aws_sesv2_email_identity.sender.email_identity }
data "aws_sesv2_configuration_set" "mail" { configuration_set_name = aws_sesv2_configuration_set.mail.configuration_set_name }

output "application" {
  value = {
    pool_id         = aws_cognito_user_pool.users.id
    client_id       = aws_cognito_user_pool_client.app.id
    user_sub        = aws_cognito_user.alice.sub
    identity_pool   = aws_cognito_identity_pool.identities.id
    role_name       = aws_iam_role.authenticated.name
    sender          = aws_sesv2_email_identity.sender.email_identity
    configuration   = aws_sesv2_configuration_set.mail.configuration_set_name
    classic_config  = aws_ses_configuration_set.classic.name
    template        = aws_ses_template.message.name
    data_pool_id    = data.aws_cognito_user_pool.users.id
    data_client_id  = data.aws_cognito_user_pool_client.app.id
    data_group      = data.aws_cognito_user_group.readers.name
    data_identity   = data.aws_cognito_identity_pool.identities.id
    data_sender_arn = data.aws_ses_email_identity.sender.arn
  }
}
