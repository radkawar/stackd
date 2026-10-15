terraform {
  required_version = "= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}
variable "endpoint" { type = string }
variable "name" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "revision" { type = string }
variable "pitr_enabled" { type = bool }
variable "replicas_enabled" { type = bool }
variable "restores_enabled" { type = bool }
variable "backup_arn" { type = string }
variable "restore_time" { type = string }
variable "separate_replica_enabled" { type = bool }
variable "separate_source_name" { type = string }
variable "separate_source_arn" { type = string }
variable "deletion_protection_enabled" { type = bool }
provider "aws" {
  region = var.region
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  ignore_tags { keys = ["SeparateOwner"] }
  endpoints {
    dynamodb = var.endpoint
    iam = var.endpoint
    sts = var.endpoint
    kms = var.endpoint
    kinesis = var.endpoint
  }
}
provider "aws" {
  alias = "replica"
  region = "us-west-2"
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  endpoints {
    dynamodb = var.endpoint
    iam = var.endpoint
    sts = var.endpoint
    kms = var.endpoint
    kinesis = var.endpoint
  }
}
resource "aws_dynamodb_table" "source" {
  name = "${var.name}-ddb-source"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "pk"
  deletion_protection_enabled = var.deletion_protection_enabled
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "group"
    type = "S"
  }
  global_secondary_index {
    name = "by-group"
    key_schema {
      attribute_name = "group"
      key_type = "HASH"
    }
    projection_type = "ALL"
  }
  stream_enabled = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  ttl {
    attribute_name = "expires"
    enabled = true
  }
  point_in_time_recovery {
    enabled = var.pitr_enabled
    recovery_period_in_days = var.revision == "initial" ? 3 : 4
  }
  dynamic "replica" {
    for_each = var.replicas_enabled ? ["us-west-2"] : []
    content {
      region_name = replica.value
      point_in_time_recovery = true
      propagate_tags = true
      consistency_mode = "EVENTUAL"
    }
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_dynamodb_table" "capacity" {
  name = "${var.name}-ddb-capacity"
  billing_mode = "PROVISIONED"
  hash_key = "pk"
  read_capacity = var.revision == "initial" ? 1 : 2
  write_capacity = var.revision == "initial" ? 1 : 2
  attribute {
    name = "pk"
    type = "S"
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_dynamodb_table" "limited" {
  name = "${var.name}-ddb-limited"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "pk"
  attribute {
    name = "pk"
    type = "S"
  }
  on_demand_throughput {
    max_read_request_units = var.revision == "initial" ? 1 : 2
    max_write_request_units = var.revision == "initial" ? 1 : 2
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_dynamodb_global_secondary_index" "group" {
  table_name = aws_dynamodb_table.capacity.name
  index_name = "by-group"
  key_schema {
    attribute_name = "group"
    attribute_type = "S"
    key_type = "HASH"
  }
  projection { projection_type = "ALL" }
  provisioned_throughput {
    read_capacity_units = var.revision == "initial" ? 2 : 3
    write_capacity_units = var.revision == "initial" ? 2 : 3
  }
}
resource "aws_dynamodb_table_item" "item" {
  table_name = aws_dynamodb_table.capacity.name
  hash_key = "pk"
  item = jsonencode({ pk = { S = "terraform" }, group = { S = "fixture" }, revision = { S = var.revision } })
  depends_on = [aws_dynamodb_global_secondary_index.group]
}
resource "aws_dynamodb_table" "backup" {
  count = var.restores_enabled ? 1 : 0
  name = "${var.name}-ddb-backup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "pk"
  restore_backup_arn = var.backup_arn
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "group"
    type = "S"
  }
  global_secondary_index {
    name = "by-group"
    key_schema {
      attribute_name = "group"
      key_type = "HASH"
    }
    projection_type = "ALL"
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_dynamodb_table" "pitr" {
  count = var.restores_enabled ? 1 : 0
  name = "${var.name}-ddb-pitr"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "pk"
  restore_source_table_arn = aws_dynamodb_table.source.arn
  restore_date_time = var.restore_time
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "group"
    type = "S"
  }
  global_secondary_index {
    name = "by-group"
    key_schema {
      attribute_name = "group"
      key_type = "HASH"
    }
    projection_type = "ALL"
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
# This resource needs a real pre-existing regional AWS-managed DynamoDB KMS
# alias even without explicit SSE. The Python module never manufactures one.
resource "aws_dynamodb_table_replica" "separate" {
  count = var.separate_replica_enabled ? 1 : 0
  provider = aws.replica
  global_table_arn = var.separate_source_arn
  point_in_time_recovery = true
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_iam_user" "reader" { name = "${var.name}-ddb-reader" }
resource "aws_dynamodb_resource_policy" "reader" {
  resource_arn = aws_dynamodb_table.source.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Sid = "Read${var.revision}", Effect = "Allow", Principal = { AWS = aws_iam_user.reader.arn }, Action = "dynamodb:GetItem", Resource = aws_dynamodb_table.source.arn }]
  })
}
resource "aws_dynamodb_tag" "separate" {
  resource_arn = aws_dynamodb_table.source.arn
  key = "SeparateOwner"
  value = var.revision
}
resource "aws_kinesis_stream" "changes" {
  name = "${var.name}-ddb-changes"
  shard_count = 1
  retention_period = 24
  encryption_type = "NONE"
  tags = { Fixture = var.name }
}
resource "aws_dynamodb_kinesis_streaming_destination" "changes" {
  table_name = aws_dynamodb_table.source.name
  stream_arn = aws_kinesis_stream.changes.arn
  approximate_creation_date_time_precision = "MICROSECOND"
}
data "aws_dynamodb_table" "source" { name = aws_dynamodb_table.source.name }
data "aws_dynamodb_table_item" "item" {
  table_name = aws_dynamodb_table.capacity.name
  key = jsonencode({ pk = { S = "terraform" } })
  depends_on = [aws_dynamodb_table_item.item]
}
data "aws_dynamodb_tables" "owned" { depends_on = [aws_dynamodb_table.source, aws_dynamodb_table.capacity] }
data "aws_dynamodb_backups" "source" {
  table_name = aws_dynamodb_table.source.name
  backup_type = "USER"
}
output "dynamodb" {
  value = {
    source = aws_dynamodb_table.source.name
    source_arn = aws_dynamodb_table.source.arn
    source_lookup_arn = data.aws_dynamodb_table.source.arn
    capacity = aws_dynamodb_table.capacity.name
    limited = aws_dynamodb_table.limited.name
    item = jsondecode(data.aws_dynamodb_table_item.item.item)
    table_names = data.aws_dynamodb_tables.owned.names
    backups = data.aws_dynamodb_backups.source.backup_summaries
    backup = try(aws_dynamodb_table.backup[0].name, null)
    pitr = try(aws_dynamodb_table.pitr[0].name, null)
    stream_arn = aws_dynamodb_table.source.stream_arn
    kinesis_name = aws_kinesis_stream.changes.name
    kinesis_arn = aws_kinesis_stream.changes.arn
    reader = aws_iam_user.reader.name
    separate = var.separate_replica_enabled ? var.separate_source_name : null
  }
}
