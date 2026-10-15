terraform {
  required_version = "= 1.15.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}
provider "aws" {
  region                      = var.region
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  endpoints {
    docdb = var.endpoint
    rds   = var.endpoint
    iam   = var.endpoint
    sts   = var.endpoint
  }
}
variable "endpoint" { type = string }
variable "region" { type = string }
variable "name" { type = string }
variable "password" {
  type      = string
  sensitive = true
}
variable "native_port" { type = number }
variable "restore_port" { type = number }
variable "retention" {
  type    = number
  default = 1
}
variable "backup_window" {
  type    = string
  default = "09:00-09:30"
}
variable "revision" {
  type    = string
  default = "one"
}
variable "restore_snapshot" {
  type    = string
  default = ""
}
resource "aws_docdb_cluster" "source" {
  cluster_identifier      = "${var.name}-docdb"
  engine                  = "docdb"
  engine_version          = "5.0"
  master_username         = "storageowner"
  master_password         = var.password
  backup_retention_period = var.retention
  preferred_backup_window = var.backup_window
  port                    = var.native_port
  apply_immediately       = true
  deletion_protection     = false
  storage_encrypted       = false
  skip_final_snapshot     = true
  tags                    = { Revision = var.revision }
}
resource "aws_docdb_cluster_instance" "source" {
  identifier                 = "${var.name}-docdb-writer"
  cluster_identifier         = aws_docdb_cluster.source.id
  instance_class             = "db.r5.large"
  engine                     = "docdb"
  auto_minor_version_upgrade = false
  promotion_tier             = 0
  apply_immediately          = true
  tags                       = { Revision = var.revision }
}
resource "aws_docdb_cluster" "restore" {
  count                   = var.restore_snapshot == "" ? 0 : 1
  cluster_identifier      = "${var.name}-docdb-restore"
  engine                  = "docdb"
  engine_version          = "5.0"
  snapshot_identifier     = var.restore_snapshot
  backup_retention_period = 1
  port                    = var.restore_port
  apply_immediately       = true
  deletion_protection     = false
  storage_encrypted       = false
  skip_final_snapshot     = true
  tags                    = { Revision = var.revision }
}
resource "aws_docdb_cluster_instance" "restore" {
  count                      = var.restore_snapshot == "" ? 0 : 1
  identifier                 = "${var.name}-docdb-restored-writer"
  cluster_identifier         = aws_docdb_cluster.restore[0].id
  instance_class             = "db.r5.large"
  engine                     = "docdb"
  auto_minor_version_upgrade = false
  promotion_tier             = 0
  apply_immediately          = true
  tags                       = { Revision = var.revision }
}
output "clusters" {
  value = {
    source = {
      id = aws_docdb_cluster.source.id
      writer_id = aws_docdb_cluster_instance.source.id
      arn = aws_docdb_cluster.source.arn
      resource_id = aws_docdb_cluster.source.cluster_resource_id
      address = aws_docdb_cluster.source.endpoint
      port = aws_docdb_cluster.source.port
    }
    restore = var.restore_snapshot == "" ? null : {
      id = aws_docdb_cluster.restore[0].id
      writer_id = aws_docdb_cluster_instance.restore[0].id
      arn = aws_docdb_cluster.restore[0].arn
      resource_id = aws_docdb_cluster.restore[0].cluster_resource_id
      address = aws_docdb_cluster.restore[0].endpoint
      port = aws_docdb_cluster.restore[0].port
    }
  }
}
