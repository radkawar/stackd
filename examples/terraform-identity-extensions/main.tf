terraform {
  required_version = "= 1.16.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}

variable "endpoint" {
  type = string
  validation {
    condition = can(regex("^http://127\\.0\\.0\\.1:[0-9]+$", var.endpoint))
    error_message = "Use the private controller's explicit IPv4 loopback endpoint."
  }
}
variable "name" { type = string }
variable "account_id" { type = string }
variable "member_account_id" { type = string }
variable "artifact_directory" { type = string }
variable "revision" {
  type = string
  validation {
    condition = contains(["v1", "v2"], var.revision)
    error_message = "Use v1 or v2."
  }
}
variable "certificate_tag_revision" {
  type = string
  default = "v1"
  validation {
    condition = contains(["v1", "v2"], var.certificate_tag_revision)
    error_message = "Use v1 or v2."
  }
}
variable "architecture" { type = string }

provider "aws" {
  region = "us-east-1"
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  skip_requesting_account_id = false
  endpoints {
    account = var.endpoint
    iam = var.endpoint
    kms = var.endpoint
    secretsmanager = var.endpoint
    sts = var.endpoint
    ssm = var.endpoint
    lambda = var.endpoint
    cloudwatchlogs = var.endpoint
    organizations = var.endpoint
    ec2 = var.endpoint
    elbv2 = var.endpoint
  }
}
provider "aws" {
  alias = "west"
  region = "us-west-2"
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  skip_requesting_account_id = false
  endpoints {
    iam = var.endpoint
    kms = var.endpoint
    sts = var.endpoint
    ssm = var.endpoint
  }
}

# Both settings are account-global. Only the runner's new private account is
# changed. The runner restores the Region before-image: provider Delete is noop.
resource "aws_account_region" "opt_in" {
  region_name = "ap-southeast-3"
  enabled = var.revision == "v1"
  timeouts {
    create = "5m"
    update = "5m"
  }
}
resource "aws_iam_organizations_features" "root_access" {
  enabled_features = var.revision == "v1" ? ["RootCredentialsManagement"] : ["RootCredentialsManagement", "RootSessions"]
}
resource "aws_iam_user" "root_operator" { name = "${var.name}-root-operator" }
resource "aws_iam_access_key" "root_operator" { user = aws_iam_user.root_operator.name }
resource "aws_iam_user_policy" "root_operator" {
  name = "member-root-audit"
  user = aws_iam_user.root_operator.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRoot", Resource = "arn:aws:iam::${var.member_account_id}:root" }]
  })
}
resource "aws_iam_service_linked_role" "elb" {
  aws_service_name = "elasticloadbalancing.amazonaws.com"
  description = "Identity extension linked-role lifecycle ${var.revision}"
  tags = { Fixture = var.name, Revision = var.revision }
}
output "controls" {
  sensitive = true
  value = {
    region = aws_account_region.opt_in.region_name
    account_id = var.account_id
    region_enabled = aws_account_region.opt_in.enabled
    organization_id = aws_iam_organizations_features.root_access.id
    member_account_id = var.member_account_id
    operator = aws_iam_user.root_operator.name
    operator_key = aws_iam_access_key.root_operator.id
    operator_secret = aws_iam_access_key.root_operator.secret
    operator_policy = aws_iam_user_policy.root_operator.name
    service_linked_role = aws_iam_service_linked_role.elb.name
    service_linked_role_arn = aws_iam_service_linked_role.elb.arn
    revision = var.revision
  }
}
