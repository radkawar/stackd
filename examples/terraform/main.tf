terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
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

variable "name" {
  type = string
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

  # Every service used by this configuration, including identity discovery.
  endpoints {
    iam = var.endpoint
    s3  = var.endpoint
    sqs = var.endpoint
    ssm = var.endpoint
    sts = var.endpoint
  }
}

resource "aws_s3_bucket" "payloads" {
  bucket = "${var.name}-payloads"
}

resource "aws_sqs_queue" "jobs" {
  name                       = "${var.name}-jobs"
  visibility_timeout_seconds = 30
}

resource "aws_ssm_parameter" "revision" {
  name  = "/${var.name}/revision"
  type  = "String"
  value = "v1"
}

output "application" {
  value = {
    bucket         = aws_s3_bucket.payloads.id
    queue_url      = aws_sqs_queue.jobs.url
    parameter_name = aws_ssm_parameter.revision.name
  }
}
