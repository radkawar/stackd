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
variable "owner_account" { type = string }
variable "member_account" { type = string }
variable "external_account" { type = string }
variable "instance_arn" { type = string }
variable "group_id" { type = string }
variable "seed_parameter" { type = string }
variable "external_credentials" {
  type = object({ access_key = string, secret_key = string, token = string })
  sensitive = true
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
    cloudformation             = var.endpoint
    cloudcontrol               = var.endpoint
    iam                        = var.endpoint
    organizations              = var.endpoint
    ram                        = var.endpoint
    resourcegroups             = var.endpoint
    resourcegroupstaggingapi    = var.endpoint
    servicecatalogappregistry  = var.endpoint
    s3                         = var.endpoint
    s3control                  = var.endpoint
    ssoadmin                   = var.endpoint
    sts                        = var.endpoint
  }
}
provider "aws" {
  alias                       = "external"
  region                      = "us-east-1"
  access_key                  = var.external_credentials.access_key
  secret_key                  = var.external_credentials.secret_key
  token                       = var.external_credentials.token
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  http_proxy                  = var.endpoint
  https_proxy                 = ""
  no_proxy                    = "127.0.0.1,localhost"
  endpoints {
    ram = var.endpoint
    iam = var.endpoint
    sts = var.endpoint
    s3        = var.endpoint
    s3control = var.endpoint
  }
}

resource "aws_cloudformation_stack" "native" {
  name = "${var.name}-native"
  tags = { Fixture = var.name, Revision = var.revision }
  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Resources = {
      Bucket = { Type = "AWS::S3::Bucket", Properties = {
        BucketName = "${var.name}-native"
        Tags = [{ Key = "Fixture", Value = var.name }]
      } }
      Queue = { Type = "AWS::SQS::Queue", Properties = {
        QueueName = "${var.name}-native"
        VisibilityTimeout = var.revision == "one" ? 30 : 45
        Tags = [{ Key = "Fixture", Value = var.name }]
      } }
      Parameter = { Type = "AWS::SSM::Parameter", Properties = {
        Name = "/${var.name}/native"
        Type = "String"
        Tier = "Advanced"
        Value = "{{resolve:ssm:${var.seed_parameter}:${var.revision == "one" ? 1 : 2}}}"
        Tags = { Fixture = var.name }
      } }
    }
    Outputs = {
      Bucket = { Value = { Ref = "Bucket" } }
      QueueURL = { Value = { Ref = "Queue" } }
      QueueARN = { Value = { "Fn::GetAtt" = ["Queue", "Arn"] } }
      ParameterName = { Value = { Ref = "Parameter" }, Export = { Name = "${var.name}-parameter" } }
    }
  })
}
resource "aws_cloudformation_stack" "reference" {
  name = "${var.name}-reference"
  template_body = jsonencode({
    Resources = { Reference = { Type = "AWS::SSM::Parameter", Properties = {
      Name = "/${var.name}/reference"
      Type = "String"
      Value = { "Fn::ImportValue" = "${var.name}-parameter" }
      Description = "Safe live export reference ${var.revision}"
    } } }
  })
  depends_on = [aws_cloudformation_stack.native]
}
data "aws_cloudformation_stack" "native" { name = aws_cloudformation_stack.native.name }
data "aws_cloudformation_export" "parameter" {
  name       = "${var.name}-parameter"
  depends_on = [aws_cloudformation_stack.native]
}
resource "aws_cloudcontrolapi_resource" "parameter" {
  type_name = "AWS::SSM::Parameter"
  desired_state = jsonencode({
    Name = "/${var.name}/cloudcontrol"
    Type = "String"
    Tier = "Advanced"
    Value = var.revision
    Tags = { Fixture = var.name }
  })
}
data "aws_cloudcontrolapi_resource" "parameter" {
  type_name  = aws_cloudcontrolapi_resource.parameter.type_name
  identifier = aws_cloudcontrolapi_resource.parameter.id
}
data "aws_cloudformation_type" "parameter" {
  type      = "RESOURCE"
  type_name = "AWS::SSM::Parameter"
}
data "aws_resourcegroupstaggingapi_required_tags" "proof" {}

resource "aws_ram_sharing_with_organization" "proof" {}
resource "aws_ram_permission" "read" {
  name          = "${var.name}-read"
  resource_type = "ssm:Parameter"
  policy_template = jsonencode({
    Effect = "Allow"
    Action = var.revision == "one" ? ["ssm:GetParameter", "ssm:GetParameters", "ssm:DescribeParameters"] : ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory", "ssm:DescribeParameters"]
  })
  tags = { Fixture = var.name }
}
resource "aws_ram_resource_share" "member" {
  name                      = "${var.name}-member-${var.revision}"
  allow_external_principals = false
  permission_arns          = [aws_ram_permission.read.arn]
  tags                     = { Fixture = var.name, Revision = var.revision }
  depends_on               = [aws_ram_sharing_with_organization.proof]
}
resource "aws_ram_principal_association" "member" {
  principal          = var.member_account
  resource_share_arn = aws_ram_resource_share.member.arn
}
resource "aws_ram_resource_association" "member" {
  resource_arn       = "arn:aws:ssm:us-east-1:${var.owner_account}:parameter/${var.name}/native"
  resource_share_arn = aws_ram_resource_share.member.arn
  depends_on        = [aws_cloudformation_stack.native]
}
resource "aws_ram_resource_share" "external" {
  name                      = "${var.name}-external"
  allow_external_principals = true
  tags                     = { Fixture = var.name }
}
resource "aws_ram_resource_share_associations_exclusive" "external" {
  resource_share_arn = aws_ram_resource_share.external.arn
  principals         = [var.external_account]
  resource_arns      = ["arn:aws:ssm:us-east-1:${var.owner_account}:parameter/${var.name}/cloudcontrol"]
  depends_on         = [aws_cloudcontrolapi_resource.parameter]
}
resource "aws_ram_resource_share_accepter" "external" {
  provider   = aws.external
  share_arn  = aws_ram_resource_share.external.arn
  depends_on = [aws_ram_resource_share_associations_exclusive.external]
}
data "aws_ram_resource_share" "member" {
  name           = aws_ram_resource_share.member.name
  resource_owner = "SELF"
}

resource "aws_ssoadmin_permission_set" "proof" {
  instance_arn     = var.instance_arn
  name             = "${var.name}-Access"
  description      = "Real IAM consumer ${var.revision}"
  session_duration = var.revision == "one" ? "PT1H" : "PT2H"
  relay_state      = "https://example.invalid/${var.revision}"
  tags             = { Fixture = var.name, Revision = var.revision }
}
resource "aws_ssoadmin_permission_set_inline_policy" "proof" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.proof.arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "s3:PutObject"
      Resource = "arn:aws:s3:::${var.name}-native/sso/${var.revision}/*"
    }]
  })
}
resource "aws_ssoadmin_managed_policy_attachment" "proof" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.proof.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
resource "aws_ssoadmin_customer_managed_policy_attachment" "proof" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.proof.arn
  customer_managed_policy_reference { name = "${var.name}-customer" }
}
resource "aws_ssoadmin_permissions_boundary_attachment" "proof" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.proof.arn
  permissions_boundary { managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" }
}
resource "aws_ssoadmin_account_assignment" "proof" {
  for_each           = toset([var.owner_account, var.member_account])
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.proof.arn
  principal_id       = var.group_id
  principal_type     = "GROUP"
  target_id          = each.value
  target_type        = "AWS_ACCOUNT"
  depends_on = [aws_ssoadmin_permission_set_inline_policy.proof,
    aws_ssoadmin_managed_policy_attachment.proof,
    aws_ssoadmin_customer_managed_policy_attachment.proof,
    aws_ssoadmin_permissions_boundary_attachment.proof]
}
resource "aws_ssoadmin_permission_set" "exclusive" {
  instance_arn = var.instance_arn
  name         = "${var.name}-Read"
  description  = "Independent exclusive attachments"
}
resource "aws_ssoadmin_managed_policy_attachments_exclusive" "proof" {
  instance_arn        = var.instance_arn
  permission_set_arn  = aws_ssoadmin_permission_set.exclusive.arn
  managed_policy_arns = var.revision == "one" ? ["arn:aws:iam::aws:policy/ReadOnlyAccess"] : ["arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
}
resource "aws_ssoadmin_customer_managed_policy_attachments_exclusive" "proof" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.exclusive.arn
  customer_managed_policy_reference { name = "${var.name}-customer" }
}
resource "aws_ssoadmin_account_assignment" "exclusive" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.exclusive.arn
  principal_id       = var.group_id
  principal_type     = "GROUP"
  target_id          = var.owner_account
  target_type        = "AWS_ACCOUNT"
  depends_on = [aws_ssoadmin_managed_policy_attachments_exclusive.proof,
    aws_ssoadmin_customer_managed_policy_attachments_exclusive.proof]
}
data "aws_ssoadmin_instances" "proof" {}
data "aws_ssoadmin_permission_set" "proof" {
  instance_arn = var.instance_arn
  arn          = aws_ssoadmin_permission_set.proof.arn
}
data "aws_ssoadmin_permission_sets" "proof" {
  instance_arn = var.instance_arn
  depends_on   = [aws_ssoadmin_permission_set.proof, aws_ssoadmin_permission_set.exclusive]
}

resource "aws_resourcegroups_group" "tags" {
  name        = "${var.name}-tags"
  description = "Owner-backed tag discovery ${var.revision}"
  resource_query {
    type = "TAG_FILTERS_1_0"
    query = jsonencode({ ResourceTypeFilters = ["AWS::S3::Bucket", "AWS::SQS::Queue", "AWS::SSM::Parameter"], TagFilters = [{ Key = "Fixture", Values = [var.name] }] })
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
data "aws_resourcegroupstaggingapi_resources" "proof" {
  resource_type_filters = ["s3", "sqs", "ssm"]
  tag_filter {
    key    = "Fixture"
    values = [var.name]
  }
  depends_on = [aws_cloudformation_stack.native, aws_cloudcontrolapi_resource.parameter]
}
resource "aws_servicecatalogappregistry_application" "proof" {
  name        = var.name
  description = "Application owner ${var.revision}"
  tags        = { Fixture = var.name, Revision = var.revision }
}
resource "aws_servicecatalogappregistry_attribute_group" "proof" {
  name        = "${var.name}-attributes"
  description = "Application attributes ${var.revision}"
  attributes  = jsonencode({ revision = var.revision, owner = "local-fixture" })
  tags        = { Fixture = var.name }
}
resource "aws_servicecatalogappregistry_attribute_group_association" "proof" {
  application_id     = aws_servicecatalogappregistry_application.proof.id
  attribute_group_id = aws_servicecatalogappregistry_attribute_group.proof.id
}
resource "aws_resourcegroups_resource" "application" {
  group_arn    = aws_servicecatalogappregistry_application.proof.application_tag["awsApplication"]
  resource_arn = aws_cloudformation_stack.native.outputs["QueueARN"]
}
data "aws_servicecatalogappregistry_application" "proof" {
  id = aws_servicecatalogappregistry_application.proof.id
}
data "aws_servicecatalogappregistry_attribute_group" "proof" {
  id = aws_servicecatalogappregistry_attribute_group.proof.id
}
data "aws_servicecatalogappregistry_attribute_group_associations" "proof" {
  id = aws_servicecatalogappregistry_application.proof.id
  depends_on     = [aws_servicecatalogappregistry_attribute_group_association.proof]
}
output "governance" {
  value = {
    bucket            = aws_cloudformation_stack.native.outputs["Bucket"]
    queue_url         = aws_cloudformation_stack.native.outputs["QueueURL"]
    queue_arn         = aws_cloudformation_stack.native.outputs["QueueARN"]
    parameter_name    = aws_cloudformation_stack.native.outputs["ParameterName"]
    stack             = aws_cloudformation_stack.native.id
    reference_stack   = aws_cloudformation_stack.reference.id
    exported_parameter = data.aws_cloudformation_export.parameter.value
    cloudcontrol_parameter = aws_cloudcontrolapi_resource.parameter.id
    registry_type_arn = data.aws_cloudformation_type.parameter.arn
    registry_schema   = data.aws_cloudformation_type.parameter.schema
    permission_set    = aws_ssoadmin_permission_set.proof.arn
    permission_name   = aws_ssoadmin_permission_set.proof.name
    exclusive_permission_set = aws_ssoadmin_permission_set.exclusive.arn
    application       = aws_servicecatalogappregistry_application.proof.id
    attribute_group   = aws_servicecatalogappregistry_attribute_group.proof.id
    application_group = aws_servicecatalogappregistry_application.proof.application_tag["awsApplication"]
    tag_group         = aws_resourcegroups_group.tags.arn
    member_share      = aws_ram_resource_share.member.arn
    external_share    = aws_ram_resource_share.external.arn
    ram_permission    = aws_ram_permission.read.arn
    tagged_resources  = data.aws_resourcegroupstaggingapi_resources.proof.resource_tag_mapping_list
    required_tags = data.aws_resourcegroupstaggingapi_required_tags.proof.required_tags
  }
}
