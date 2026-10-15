terraform {
  required_version = ">= 1.5.0, < 2.0.0"
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
variable "revision" { type = string }
variable "bootstrap" {
  type    = bool
  default = false
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  http_proxy                  = var.endpoint
  https_proxy                 = ""
  no_proxy                    = "127.0.0.1,localhost"
  endpoints {
    account       = var.endpoint
    organizations = var.endpoint
    iam           = var.endpoint
    s3            = var.endpoint
    s3control     = var.endpoint
    sts           = var.endpoint
  }
}

resource "aws_organizations_organization" "proof" {
  feature_set = "ALL"
  # AWS enables SCP at creation. Provider 6.68.0 calls EnablePolicyType for
  # every create-time entry, so first create with no explicit policy types.
  enabled_policy_types          = var.bootstrap ? null : ["SERVICE_CONTROL_POLICY", "TAG_POLICY"]
  aws_service_access_principals = ["account.amazonaws.com", "ram.amazonaws.com", "sso.amazonaws.com"]
}
resource "aws_organizations_organizational_unit" "parent" {
  name      = "${var.name}-${var.revision}"
  parent_id = aws_organizations_organization.proof.roots[0].id
  tags      = { Fixture = var.name, Revision = var.revision }
}
resource "aws_organizations_organizational_unit" "child" {
  name      = "${var.name}-child"
  parent_id = aws_organizations_organizational_unit.parent.id
  tags      = { Fixture = var.name }
}
resource "aws_organizations_account" "member" {
  count             = 2
  name              = "${var.name}-${count.index}-${var.revision}"
  email             = "${var.name}-${count.index}@example.invalid"
  parent_id         = var.revision == "one" ? aws_organizations_organizational_unit.parent.id : aws_organizations_organizational_unit.child.id
  close_on_deletion = false
  tags              = { Fixture = var.name, Revision = var.revision }
}
resource "aws_organizations_policy" "deny" {
  depends_on  = [aws_organizations_organization.proof]
  name        = "${var.name}-deny"
  description = "Current member data-plane restriction ${var.revision}"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = var.revision == "one" ? "s3:PutObject" : "s3:DeleteObject"
      Resource = "arn:aws:s3:::${var.name}-member/*"
    }]
  })
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_organizations_policy_attachment" "deny" {
  policy_id = aws_organizations_policy.deny.id
  target_id = aws_organizations_account.member[0].id
}
resource "aws_organizations_policy" "required" {
  depends_on = [aws_organizations_organization.proof]
  name = "${var.name}-required"
  type = "TAG_POLICY"
  content = jsonencode({
    tags = { fixture = {
      tag_key = { "@@assign" = "Fixture" }
      report_required_tag_for = { "@@assign" = ["s3:bucket", "sqs:queue"] }
    } }
  })
}
resource "aws_organizations_policy_attachment" "required" {
  policy_id = aws_organizations_policy.required.id
  target_id = aws_organizations_organization.proof.roots[0].id
}
resource "aws_organizations_aws_service_access" "sso" {
  service_principal = "sso.amazonaws.com"
  depends_on        = [aws_organizations_organization.proof]
}
resource "aws_organizations_delegated_administrator" "sso" {
  account_id        = aws_organizations_account.member[1].id
  service_principal = aws_organizations_aws_service_access.sso.service_principal
}
resource "aws_organizations_resource_policy" "read" {
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${aws_organizations_account.member[1].id}:root" }
      Action    = ["organizations:DescribeOrganization", "organizations:ListRoots", "organizations:ListAccounts"]
      Resource  = "*"
    }]
  })
  tags = { Fixture = var.name }
}
# A standalone tag owns a different key from the OU resource's tags.
resource "aws_organizations_tag" "root" {
  resource_id = aws_organizations_organization.proof.roots[0].id
  key         = "Revision"
  value       = var.revision
}

data "aws_organizations_organization" "proof" {
  depends_on = [aws_organizations_account.member, aws_organizations_delegated_administrator.sso]
}
data "aws_organizations_account" "member" {
  account_id = aws_organizations_account.member[0].id
}
data "aws_organizations_organizational_unit" "parent" {
  parent_id = aws_organizations_organizational_unit.parent.parent_id
  name      = aws_organizations_organizational_unit.parent.name
}
data "aws_organizations_organizational_unit_child_accounts" "child" {
  parent_id  = aws_organizations_organizational_unit.child.id
  depends_on = [aws_organizations_account.member]
}
data "aws_organizations_organizational_unit_descendant_accounts" "parent" {
  parent_id  = aws_organizations_organizational_unit.parent.id
  depends_on = [aws_organizations_account.member]
}
data "aws_organizations_organizational_units" "parent" {
  parent_id = aws_organizations_organizational_unit.parent.id
}
data "aws_organizations_organizational_unit_descendant_organizational_units" "root" {
  parent_id = aws_organizations_organization.proof.roots[0].id
  depends_on = [aws_organizations_organizational_unit.child]
}
data "aws_organizations_entity_path" "member" {
  entity_id = aws_organizations_account.member[0].id
}
data "aws_organizations_policies" "scp" {
  filter     = "SERVICE_CONTROL_POLICY"
  depends_on = [aws_organizations_policy.deny]
}
data "aws_organizations_policies_for_target" "member" {
  target_id  = aws_organizations_account.member[0].id
  filter     = "SERVICE_CONTROL_POLICY"
  depends_on = [aws_organizations_policy_attachment.deny]
}
data "aws_organizations_policy" "deny" {
  policy_id = aws_organizations_policy.deny.id
}
data "aws_organizations_resource_tags" "root" {
  resource_id = aws_organizations_tag.root.resource_id
  depends_on  = [aws_organizations_tag.root]
}
data "aws_organizations_delegated_administrators" "sso" {
  service_principal = aws_organizations_delegated_administrator.sso.service_principal
  depends_on        = [aws_organizations_delegated_administrator.sso]
}
data "aws_organizations_delegated_services" "member" {
  account_id = aws_organizations_account.member[1].id
  depends_on = [aws_organizations_delegated_administrator.sso]
}

output "governance" {
  value = {
    organization = aws_organizations_organization.proof.id
    root         = aws_organizations_organization.proof.roots[0].id
    parent       = aws_organizations_organizational_unit.parent.id
    child        = aws_organizations_organizational_unit.child.id
    members      = aws_organizations_account.member[*].id
    policy       = aws_organizations_policy.deny.id
    member_names = aws_organizations_account.member[*].name
    entity_path  = data.aws_organizations_entity_path.member.entity_path
    child_accounts = [for account in data.aws_organizations_organizational_unit_child_accounts.child.accounts : account.id]
    descendant_accounts = [for account in data.aws_organizations_organizational_unit_descendant_accounts.parent.accounts : account.id]
    policy_targets = data.aws_organizations_policies_for_target.member.ids
  }
}
