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
    ec2         = var.endpoint
    elasticache = var.endpoint
    iam         = var.endpoint
    sts         = var.endpoint
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
    from_port   = 6379
    to_port     = 6379
    cidr_blocks = [aws_vpc.native.cidr_block]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [aws_vpc.native.cidr_block]
  }
}
resource "aws_elasticache_subnet_group" "native" {
  name       = var.name
  subnet_ids = aws_subnet.native[*].id
}

resource "aws_elasticache_parameter_group" "native" {
  name   = var.name
  family = "valkey8"
  parameter {
    name  = "maxmemory-policy"
    value = var.revision == "v1" ? "noeviction" : "allkeys-lru"
  }
}

# A distinct disabled default user prevents the image's default open-access login.
resource "aws_elasticache_user" "default" {
  user_id              = "${var.name}-default"
  user_name            = "default"
  engine               = "VALKEY"
  access_string        = "off ~* -@all"
  no_password_required = true
}
resource "aws_elasticache_user" "consumer" {
  user_id       = "${var.name}-consumer"
  user_name     = "consumer"
  engine        = "VALKEY"
  access_string = "on ~fixture:* -@all +ping +get +set +del +info"
  authentication_mode {
    type      = "password"
    passwords = [var.password]
  }
}
resource "aws_elasticache_user_group" "native" {
  user_group_id = var.name
  engine        = "VALKEY"
  user_ids      = [aws_elasticache_user.default.user_id, aws_elasticache_user.consumer.user_id]
}
resource "aws_elasticache_replication_group" "native" {
  replication_group_id       = var.name
  description                = "Native Terraform ${var.revision}"
  engine                     = "valkey"
  engine_version             = "8.1"
  node_type                  = "cache.t4g.micro"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.native.name
  security_group_ids         = [aws_security_group.native.id]
  num_cache_clusters         = 2
  automatic_failover_enabled = false
  multi_az_enabled           = false
  at_rest_encryption_enabled = "false"
  auto_minor_version_upgrade = "false"
  transit_encryption_enabled = true
  transit_encryption_mode    = "required"
  parameter_group_name       = aws_elasticache_parameter_group.native.name
  user_group_ids             = [aws_elasticache_user_group.native.user_group_id]
  apply_immediately          = true
  tags = {
    Revision = var.revision
  }
}

data "aws_elasticache_replication_group" "native" {
  replication_group_id = aws_elasticache_replication_group.native.replication_group_id
}
data "aws_elasticache_cluster" "native" {
  cluster_id = sort(tolist(aws_elasticache_replication_group.native.member_clusters))[0]
}
data "aws_elasticache_cluster" "reader" {
  cluster_id = sort(tolist(aws_elasticache_replication_group.native.member_clusters))[1]
}
data "aws_elasticache_user" "native" {
  user_id = aws_elasticache_user.consumer.user_id
}

output "application" {
  value = {
    name                = aws_elasticache_replication_group.native.replication_group_id
    address             = data.aws_elasticache_replication_group.native.primary_endpoint_address
    arn                 = aws_elasticache_replication_group.native.arn
    vpc                 = aws_vpc.native.id
    cidr                = aws_vpc.native.cidr_block
    group               = aws_security_group.native.id
    subnets             = aws_subnet.native[*].id
    primary_zone        = data.aws_elasticache_cluster.native.availability_zone
    reader_zone         = data.aws_elasticache_cluster.reader.availability_zone
    node_address        = data.aws_elasticache_cluster.native.cache_nodes[0].address
    reader_node_address = data.aws_elasticache_cluster.reader.cache_nodes[0].address
    # Top-level datasource.port is configuration-endpoint-only (Memcached);
    # Valkey consumers use the actual DescribeCacheClusters node endpoint.
    port           = data.aws_elasticache_cluster.native.cache_nodes[0].port
    username       = "consumer"
    reader_address = data.aws_elasticache_replication_group.native.reader_endpoint_address
    reader_port    = data.aws_elasticache_cluster.reader.cache_nodes[0].port
    revision       = var.revision
  }
}
output "imports" {
  value = merge({
    "aws_elasticache_parameter_group.native"   = aws_elasticache_parameter_group.native.name
    "aws_vpc.native"                           = aws_vpc.native.id
    "aws_security_group.native"                = aws_security_group.native.id
    "aws_elasticache_subnet_group.native"      = aws_elasticache_subnet_group.native.name
    "aws_elasticache_user.default"             = aws_elasticache_user.default.user_id
    "aws_elasticache_user.consumer"            = aws_elasticache_user.consumer.user_id
    "aws_elasticache_user_group.native"        = aws_elasticache_user_group.native.user_group_id
    "aws_elasticache_replication_group.native" = aws_elasticache_replication_group.native.replication_group_id
    }, {
    for index, subnet in aws_subnet.native : "aws_subnet.native[${index}]" => subnet.id
  })
}
