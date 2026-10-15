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
    error_message = "Use an explicit IPv4 loopback HTTP endpoint."
  }
}
variable "name" { type = string }
variable "cidr" { type = string }
variable "source_cidr" { type = string }
variable "destination_cidr" { type = string }
variable "eni_id" {
  type    = string
  default = ""
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
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    ec2            = var.endpoint
    iam            = var.endpoint
    cloudwatchlogs = var.endpoint
    s3             = var.endpoint
    sts            = var.endpoint
  }
}

locals {
  fields = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${flow-direction}"
  tags   = { Name = var.name, Fixture = "vpc-flow-logs", Revision = var.revision }
}
resource "aws_vpc" "owned" {
  cidr_block = var.cidr
  tags       = local.tags
}
resource "aws_subnet" "source" {
  vpc_id            = aws_vpc.owned.id
  cidr_block        = var.source_cidr
  availability_zone = "us-east-1a"
  tags              = local.tags
}
resource "aws_subnet" "destination" {
  vpc_id            = aws_vpc.owned.id
  cidr_block        = var.destination_cidr
  availability_zone = "us-east-1a"
  tags              = local.tags
}
resource "aws_security_group" "source" {
  name   = "${var.name}-source"
  vpc_id = aws_vpc.owned.id
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [var.cidr]
  }
  tags = local.tags
}
resource "aws_security_group" "destination" {
  name   = "${var.name}-destination"
  vpc_id = aws_vpc.owned.id
  # Port 33001 has a live listener, but no security group ingress permission.
  ingress {
    protocol    = "udp"
    from_port   = 33000
    to_port     = 33000
    cidr_blocks = [var.source_cidr]
  }
  ingress {
    protocol    = "udp"
    from_port   = 33002
    to_port     = 33002
    cidr_blocks = [var.source_cidr]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [var.cidr]
  }
  tags = local.tags
}
resource "aws_network_acl" "destination" {
  vpc_id     = aws_vpc.owned.id
  subnet_ids = [aws_subnet.destination.id]
  # Distinct subnets make this a real ingress NACL path.
  ingress {
    protocol   = "udp"
    rule_no    = 50
    action     = "deny"
    cidr_block = var.source_cidr
    from_port  = 33002
    to_port    = 33002
  }
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  tags = local.tags
}
resource "aws_s3_bucket" "delivery" {
  bucket        = var.name
  force_destroy = true
  tags          = local.tags
}
# No aws_s3_bucket_policy: CreateFlowLogs must attach the delivery policy.
resource "aws_cloudwatch_log_group" "all" {
  name = "/${var.name}/all"
  tags = local.tags
}
resource "aws_cloudwatch_log_group" "reject" {
  name = "/${var.name}/reject"
  tags = local.tags
}
resource "aws_iam_role" "delivery" {
  name = var.name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy" "delivery" {
  name = "delivery"
  role = aws_iam_role.delivery.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"], Resource = [aws_cloudwatch_log_group.all.arn, "${aws_cloudwatch_log_group.all.arn}:*", aws_cloudwatch_log_group.reject.arn, "${aws_cloudwatch_log_group.reject.arn}:*"] }]
  })
}
resource "aws_flow_log" "all" {
  vpc_id                   = aws_vpc.owned.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.all.arn
  iam_role_arn             = aws_iam_role.delivery.arn
  max_aggregation_interval = 60
  log_format               = local.fields
  tags                     = local.tags
  depends_on               = [aws_iam_role_policy.delivery]
}
resource "aws_flow_log" "accept" {
  subnet_id                = aws_subnet.destination.id
  traffic_type             = "ACCEPT"
  log_destination_type     = "s3"
  log_destination          = "${aws_s3_bucket.delivery.arn}/records"
  max_aggregation_interval = 60
  log_format               = local.fields
  destination_options {
    file_format                = "plain-text"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }
  tags = local.tags
}
resource "aws_flow_log" "reject" {
  count                    = var.eni_id == "" ? 0 : 1
  eni_id                   = var.eni_id
  traffic_type             = "REJECT"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.reject.arn
  iam_role_arn             = aws_iam_role.delivery.arn
  max_aggregation_interval = 60
  log_format               = local.fields
  tags                     = local.tags
  depends_on               = [aws_iam_role_policy.delivery]
}
output "fixture" {
  value = {
    vpc_id             = aws_vpc.owned.id
    source_subnet      = aws_subnet.source.id
    destination_subnet = aws_subnet.destination.id
    source_group       = aws_security_group.source.id
    destination_group  = aws_security_group.destination.id
    bucket             = aws_s3_bucket.delivery.id
    all_group          = aws_cloudwatch_log_group.all.name
    reject_group       = aws_cloudwatch_log_group.reject.name
    role               = aws_iam_role.delivery.name
    flow_logs          = concat([aws_flow_log.all.id, aws_flow_log.accept.id], aws_flow_log.reject[*].id)
    log_format         = local.fields
  }
}
