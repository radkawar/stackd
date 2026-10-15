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
    error_message = "Use the owned IPv4 loopback endpoint."
  }
}
variable "name" { type = string }
variable "revision" { type = string }
variable "network_octet" { type = number }
variable "password" {
  type      = string
  sensitive = true
}
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  endpoints {
    ec2            = var.endpoint
    iam            = var.endpoint
    kafka          = var.endpoint
    kms            = var.endpoint
    secretsmanager = var.endpoint
    sts            = var.endpoint
  }
}
resource "aws_vpc" "native" {
  cidr_block           = cidrsubnet("10.0.0.0/8", 8, var.network_octet)
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "native" {
  count             = 2
  vpc_id            = aws_vpc.native.id
  cidr_block        = cidrsubnet(aws_vpc.native.cidr_block, 8, count.index)
  availability_zone = count.index == 0 ? "us-east-1a" : "us-east-1b"
}
resource "aws_security_group" "native" {
  name   = var.name
  vpc_id = aws_vpc.native.id
  ingress {
    protocol    = "tcp"
    from_port   = 9092
    to_port     = 9092
    cidr_blocks = [aws_vpc.native.cidr_block]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [aws_vpc.native.cidr_block]
  }
}
resource "aws_kms_key" "scram" {
  description             = "Owned Terraform MSK SCRAM secret encryption"
  deletion_window_in_days  = 7
  enable_key_rotation     = false
}
resource "aws_secretsmanager_secret" "scram" {
  name                    = "AmazonMSK_${var.name}"
  kms_key_id              = aws_kms_key.scram.arn
  recovery_window_in_days = 0
}
resource "aws_secretsmanager_secret_version" "scram" {
  secret_id     = aws_secretsmanager_secret.scram.id
  secret_string = jsonencode({ username = "consumer", password = var.password })
}
resource "aws_msk_configuration" "native" {
  name              = var.name
  kafka_versions    = ["3.7.1"]
  server_properties = "auto.create.topics.enable=true\nlog.retention.ms=${var.revision == "v1" ? "86400000" : "172800000"}\n"
}
resource "aws_msk_cluster" "native" {
  cluster_name           = var.name
  kafka_version          = "3.7.1"
  number_of_broker_nodes = 2
  enhanced_monitoring    = "DEFAULT"
  broker_node_group_info {
    instance_type   = "kafka.local"
    client_subnets  = aws_subnet.native[*].id
    security_groups = [aws_security_group.native.id]
    az_distribution = "DEFAULT"
  }
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
  client_authentication {
    sasl {
      scram = true
      iam   = false
    }
    unauthenticated = false
  }
  configuration_info {
    arn      = aws_msk_configuration.native.arn
    revision = aws_msk_configuration.native.latest_revision
  }
  tags = { Revision = var.revision }
}
resource "aws_msk_scram_secret_association" "native" {
  cluster_arn     = aws_msk_cluster.native.arn
  secret_arn_list = [aws_secretsmanager_secret.scram.arn]
  depends_on      = [aws_secretsmanager_secret_version.scram]
}
data "aws_msk_configuration" "native" { name = aws_msk_configuration.native.name }
data "aws_msk_cluster" "native" {
  cluster_name = aws_msk_cluster.native.cluster_name
  depends_on   = [aws_msk_scram_secret_association.native]
}
data "aws_msk_bootstrap_brokers" "native" {
  cluster_arn = aws_msk_cluster.native.arn
  depends_on  = [aws_msk_scram_secret_association.native]
}
data "aws_msk_broker_nodes" "native" {
  cluster_arn = aws_msk_cluster.native.arn
  depends_on  = [aws_msk_scram_secret_association.native]
}
data "aws_msk_kafka_version" "native" { version = "3.7.1" }
output "application" {
  value = {
    name       = aws_msk_cluster.native.cluster_name
    arn        = aws_msk_cluster.native.arn
    brokers    = data.aws_msk_bootstrap_brokers.native.bootstrap_brokers_sasl_scram
    group      = aws_security_group.native.id
    vpc        = aws_vpc.native.id
    cidr       = aws_vpc.native.cidr_block
    revision   = var.revision
    subnets    = aws_subnet.native[*].id
    topic      = "${var.name}-native"
    key_id     = aws_kms_key.scram.key_id
  }
}
output "imports" {
  value = {
    "aws_msk_configuration.native" = aws_msk_configuration.native.arn
    "aws_msk_cluster.native"       = aws_msk_cluster.native.arn
    "aws_msk_scram_secret_association.native" = aws_msk_cluster.native.arn
  }
}
