# Permanent expansion of .stackd/rds-provider-proof/main.tf and report.json.
# AllocatedStorage is requested GiB control intent, not a Docker volume quota.
# Empty control-plane clusters have no SQL endpoint. Their primary writers must
# complete authenticated native startup before Data API or SQL is ready.
terraform {
  required_version = "= 1.15.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}

variable "endpoint" { type = string }
variable "name" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "capacity" { type = number }
variable "revision" { type = string }
variable "snapshots" { type = bool }
variable "password" {
  type      = string
  sensitive = true
}

provider "aws" {
  region                      = var.region
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  endpoints {
    rds            = var.endpoint
    secretsmanager = var.endpoint
    iam            = var.endpoint
    sts            = var.endpoint
  }
}

locals {
  engines = {
    postgres = { version = "17.11", aurora = "aurora-postgresql", family = "postgres17", parameter = "statement_timeout", initial = "7000", updated = "9000" }
    mysql    = { version = "8.4.11", aurora = "aurora-mysql", family = "mysql8.4", parameter = "wait_timeout", initial = "7000", updated = "9000" }
  }
  tags = { Fixture = var.name, Revision = var.revision }
}

resource "aws_db_parameter_group" "native" {
  for_each    = local.engines
  name        = "${var.name}-${each.key}"
  family      = each.value.family
  description = "Native SQL setting and retained data proof"
  parameter {
    name         = each.value.parameter
    value        = var.revision == "initial" ? each.value.initial : each.value.updated
    apply_method = "immediate"
  }
  dynamic "parameter" {
    for_each = each.key == "postgres" ? [1] : []
    content {
      name         = "rds.force_ssl"
      value        = var.revision == "initial" ? "1" : "0"
      apply_method = "immediate"
    }
  }
  tags = local.tags
}

resource "aws_db_instance" "native" {
  for_each                   = local.engines
  identifier                 = "${var.name}-${each.key}"
  engine                     = each.key
  engine_version             = each.value.version
  instance_class             = "db.t3.micro"
  allocated_storage          = var.capacity
  username                   = "lindm_admin"
  password                   = var.password
  db_name                    = "proof"
  parameter_group_name       = aws_db_parameter_group.native[each.key].name
  apply_immediately          = true
  auto_minor_version_upgrade = false
  backup_retention_period    = 0
  storage_encrypted          = false
  publicly_accessible        = false
  skip_final_snapshot        = true
  tags                       = local.tags
}

resource "aws_db_snapshot" "native" {
  for_each               = var.snapshots ? local.engines : {}
  db_instance_identifier = aws_db_instance.native[each.key].identifier
  db_snapshot_identifier = "${var.name}-${each.key}-manual"
  tags                   = local.tags
}

resource "aws_db_instance" "restored" {
  for_each                   = var.snapshots ? local.engines : {}
  identifier                 = "${var.name}-${each.key}-restored"
  snapshot_identifier        = aws_db_snapshot.native[each.key].id
  engine                     = each.key
  instance_class             = "db.t3.micro"
  allocated_storage          = var.capacity
  parameter_group_name       = aws_db_parameter_group.native[each.key].name
  apply_immediately          = true
  auto_minor_version_upgrade = false
  backup_retention_period    = 0
  storage_encrypted          = false
  publicly_accessible        = false
  skip_final_snapshot        = true
  tags                       = local.tags
}

resource "aws_rds_cluster_parameter_group" "data" {
  name        = "${var.name}-aurora-postgres"
  family      = "aurora-postgresql17"
  description = "Verified TLS and native force_ssl policy"
  parameter {
    name         = "rds.force_ssl"
    value        = var.revision == "initial" ? "1" : "0"
    apply_method = "immediate"
  }
  tags = local.tags
}

resource "aws_rds_cluster" "data" {
  for_each                   = local.engines
  cluster_identifier         = "${var.name}-aurora-${each.key}"
  engine                     = each.value.aurora
  engine_version             = each.value.version
  db_cluster_parameter_group_name = each.key == "postgres" ? aws_rds_cluster_parameter_group.data.name : null
  database_name              = "proof"
  master_username            = "lindm_admin"
  master_password            = var.password
  engine_mode                = "provisioned"
  enable_http_endpoint       = true
  apply_immediately          = true
  auto_minor_version_upgrade = false
  backup_retention_period    = 0
  storage_encrypted          = false
  skip_final_snapshot        = true
  tags                       = local.tags
}

resource "aws_rds_cluster_instance" "writer" {
  for_each                   = local.engines
  identifier                 = "${var.name}-aurora-${each.key}-writer"
  cluster_identifier         = aws_rds_cluster.data[each.key].id
  engine                     = aws_rds_cluster.data[each.key].engine
  engine_version             = each.value.version
  instance_class             = "db.t3.micro"
  auto_minor_version_upgrade = false
  apply_immediately          = true
  tags                       = local.tags
}

resource "aws_secretsmanager_secret" "data" {
  for_each                = local.engines
  name                    = "${var.name}-${each.key}-data"
  recovery_window_in_days = 0
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "data" {
  for_each      = local.engines
  secret_id     = aws_secretsmanager_secret.data[each.key].id
  secret_string = jsonencode({ username = "lindm_admin", password = var.password })
}

data "aws_db_instance" "current" {
  for_each = local.engines
  db_instance_identifier = aws_db_instance.native[each.key].identifier
}

data "aws_db_snapshot" "current" {
  for_each = var.snapshots ? local.engines : {}
  db_snapshot_identifier = aws_db_snapshot.native[each.key].id
}

data "aws_rds_cluster" "current" {
  for_each = local.engines
  cluster_identifier = aws_rds_cluster.data[each.key].id
  depends_on = [aws_rds_cluster_instance.writer]
}

output "rds" {
  value = {
    native = { for key, db in aws_db_instance.native : key => {
      identifier = db.identifier, arn = db.arn, host = db.address, port = db.port, capacity = db.allocated_storage
    } }
    restored = { for key, db in aws_db_instance.restored : key => {
      identifier = db.identifier, arn = db.arn, host = db.address, port = db.port, capacity = db.allocated_storage
    } }
    snapshots = { for key, snapshot in aws_db_snapshot.native : key => {
      identifier = snapshot.id, arn = snapshot.db_snapshot_arn, capacity = snapshot.allocated_storage
    } }
    data = { for key, cluster in aws_rds_cluster.data : key => {
      identifier = cluster.id, arn = cluster.arn, host = aws_rds_cluster_instance.writer[key].endpoint,
      port = aws_rds_cluster_instance.writer[key].port, writer = aws_rds_cluster_instance.writer[key].id,
      writer_arn = aws_rds_cluster_instance.writer[key].arn, secret = aws_secretsmanager_secret.data[key].arn
    } }
    lookups = {
      native = { for key, db in data.aws_db_instance.current : key => {
        arn = db.db_instance_arn, host = db.address, port = db.port, capacity = db.allocated_storage
      } }
      snapshots = { for key, snapshot in data.aws_db_snapshot.current : key => {
        arn = snapshot.db_snapshot_arn, capacity = snapshot.allocated_storage
      } }
      data = { for key, cluster in data.aws_rds_cluster.current : key => {
        arn = cluster.arn, host = cluster.endpoint, port = cluster.port
      } }
    }
  }
}
