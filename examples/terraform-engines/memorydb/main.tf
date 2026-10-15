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
    memorydb = var.endpoint
    iam      = var.endpoint
    sts      = var.endpoint
  }
}
resource "aws_memorydb_parameter_group" "native" {
  name   = var.name
  family = "memorydb_valkey7"
  parameter {
    name  = "maxmemory-policy"
    value = var.revision == "v1" ? "noeviction" : "allkeys-lru"
  }
}
resource "aws_memorydb_user" "consumer" {
  user_name     = "${var.name}-consumer"
  access_string = "on ~fixture:* -@all +ping +get +set +del +info"
  authentication_mode {
    type      = "password"
    passwords = [var.password]
  }
}
resource "aws_memorydb_acl" "native" {
  name       = var.name
  user_names = [aws_memorydb_user.consumer.user_name]
}
resource "aws_memorydb_cluster" "native" {
  name                       = var.name
  description                = "Native Terraform ${var.revision}"
  acl_name                   = aws_memorydb_acl.native.name
  node_type                  = "db.t4g.small"
  engine                     = "valkey"
  engine_version             = "8.1.6"
  num_shards                 = 1
  num_replicas_per_shard      = 0
  auto_minor_version_upgrade = false
  snapshot_retention_limit   = 0
  tls_enabled                = true
  parameter_group_name       = aws_memorydb_parameter_group.native.name
  tags = {
    Revision = var.revision
  }
}
# Capture bytes written by the v1 independent consumer, then restore an
# independent real cluster. Terraform owns both physical snapshot and restore.
resource "aws_memorydb_snapshot" "native" {
  count        = var.revision == "v2" ? 1 : 0
  name         = "${var.name}-snapshot"
  cluster_name = aws_memorydb_cluster.native.name
}
resource "aws_memorydb_cluster" "restored" {
  count                      = var.revision == "v2" ? 1 : 0
  name                       = "${var.name}-restored"
  acl_name                   = aws_memorydb_acl.native.name
  node_type                  = "db.t4g.small"
  engine                     = "valkey"
  engine_version             = "8.1.6"
  num_shards                 = 1
  num_replicas_per_shard      = 0
  auto_minor_version_upgrade = false
  snapshot_retention_limit   = 0
  tls_enabled                = true
  parameter_group_name       = aws_memorydb_parameter_group.native.name
  snapshot_name              = aws_memorydb_snapshot.native[0].name
}
data "aws_memorydb_cluster" "native" { name = aws_memorydb_cluster.native.name }
data "aws_memorydb_acl" "native" { name = aws_memorydb_acl.native.name }
data "aws_memorydb_user" "native" { user_name = aws_memorydb_user.consumer.user_name }
data "aws_memorydb_parameter_group" "native" { name = aws_memorydb_parameter_group.native.name }
data "aws_memorydb_snapshot" "native" {
  count = var.revision == "v2" ? 1 : 0
  name  = aws_memorydb_snapshot.native[0].name
}
output "application" {
  value = {
    name     = aws_memorydb_cluster.native.name
    address  = data.aws_memorydb_cluster.native.cluster_endpoint[0].address
    port     = data.aws_memorydb_cluster.native.cluster_endpoint[0].port
    username = aws_memorydb_user.consumer.user_name
    revision = var.revision
    restored = length(aws_memorydb_cluster.restored) == 0 ? null : {
      name    = aws_memorydb_cluster.restored[0].name
      address = aws_memorydb_cluster.restored[0].cluster_endpoint[0].address
      port    = aws_memorydb_cluster.restored[0].cluster_endpoint[0].port
    }
  }
}
output "imports" {
  value = merge({
    "aws_memorydb_parameter_group.native" = aws_memorydb_parameter_group.native.name
    "aws_memorydb_user.consumer"          = aws_memorydb_user.consumer.user_name
    "aws_memorydb_acl.native"             = aws_memorydb_acl.native.name
    "aws_memorydb_cluster.native"         = aws_memorydb_cluster.native.name
    }, length(aws_memorydb_snapshot.native) == 0 ? {} : {
    "aws_memorydb_snapshot.native[0]"  = aws_memorydb_snapshot.native[0].name
    "aws_memorydb_cluster.restored[0]" = aws_memorydb_cluster.restored[0].name
  })
}
