terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.68.0"
    }
  }
}

variable "endpoint" {
  type = string
  validation {
    condition     = can(regex("^http://127\\.0\\.0\\.1:[0-9]+$", var.endpoint))
    error_message = "The fixture requires the owned loopback controller endpoint."
  }
}
variable "account_id" { type = string }
variable "name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,27}$", var.name))
    error_message = "Search domain names must contain 3–28 lowercase letters, digits or hyphens."
  }
}
variable "revision" {
  type    = string
  default = "v1"
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  endpoints {
    opensearch    = var.endpoint
    elasticsearch = var.endpoint
    iam           = var.endpoint
    sts           = var.endpoint
  }
}

# One real OpenSearch 2.19.4 node. No EC2 instance class, EBS, managed TLS,
# VPC, fine-grained security or legacy Elasticsearch version is simulated.
resource "aws_opensearch_domain" "application" {
  domain_name    = var.name
  engine_version = "OpenSearch_2.19"
  advanced_options = {
    "indices.query.bool.max_clause_count"      = var.revision == "v1" ? "8" : "16"
    "rest.action.multi.allow_explicit_index" = var.revision == "v1" ? "true" : "false"
  }
  ebs_options {
    ebs_enabled = false
  }
  encrypt_at_rest {
    enabled = false
  }
  node_to_node_encryption {
    enabled = false
  }
  advanced_security_options {
    enabled = false
  }
  domain_endpoint_options {
    enforce_https = false
  }
  software_update_options {
    auto_software_update_enabled = false
  }
  tags = {
    Fixture  = var.name
    Revision = var.revision
  }
}

resource "aws_opensearch_domain_policy" "application" {
  domain_name = aws_opensearch_domain.application.domain_name
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = var.revision == "v1" ? "FixtureInitial" : "FixtureUpdated"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = var.revision == "v1" ? ["es:ESHttp*"] : ["es:ESHttpGet", "es:ESHttpHead", "es:ESHttpPost", "es:ESHttpPut", "es:ESHttpDelete"]
      Resource  = "${aws_opensearch_domain.application.arn}/*"
    }]
  })
}

data "aws_opensearch_domain" "application" {
  domain_name = aws_opensearch_domain.application.domain_name
  depends_on  = [aws_opensearch_domain_policy.application]
}

# The historical API can describe the modern domain; its version output stays
# OpenSearch_2.19, never a substituted Elasticsearch 7.x version.
data "aws_elasticsearch_domain" "application" {
  domain_name = aws_opensearch_domain.application.domain_name
  depends_on  = [aws_opensearch_domain_policy.application]
}

output "imports" {
  value = {
    "aws_opensearch_domain.application"        = aws_opensearch_domain.application.domain_name
    "aws_opensearch_domain_policy.application" = aws_opensearch_domain_policy.application.id
  }
}

output "application" {
  value = {
    domain_name    = aws_opensearch_domain.application.domain_name
    domain_id      = aws_opensearch_domain.application.domain_id
    arn            = aws_opensearch_domain.application.arn
    policy_id      = aws_opensearch_domain_policy.application.id
    endpoint       = aws_opensearch_domain.application.endpoint
    engine_version = aws_opensearch_domain.application.engine_version
    modern_data_id = data.aws_opensearch_domain.application.id
    legacy_data_id = data.aws_elasticsearch_domain.application.id
    legacy_version = data.aws_elasticsearch_domain.application.elasticsearch_version
    revision       = var.revision
  }
}
