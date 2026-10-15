# AWS provider 6.68.0 uses RSAES_OAEP_SHA_256/RSA_2048 to import these real bytes.
# KMS never exports imported master material: native Terraform import cannot
# reconstruct key_material_base64. Keep that create-only secret out of post-import
# diffs; valid_to is updated before the runner performs native imports.
variable "keys_valid_to_v1" {
  type = string
}

variable "keys_valid_to_v2" {
  type = string
}

locals {
  keys_valid_to = var.revision == "v1" ? var.keys_valid_to_v1 : var.keys_valid_to_v2
  keys_tags = {
    Fixture          = var.name
    ConsumerRevision = var.revision
    MaterialOwner    = "keys"
  }
  keys_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "Consumer${var.revision}"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.keys_consumer.arn }
        Action    = ["kms:Encrypt", "kms:Decrypt"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:Fixture"  = var.name
            "kms:EncryptionContext:Revision" = var.revision
          }
        }
      }
    ]
  })
}

resource "aws_iam_user" "keys_consumer" {
  name = "${var.name}-key-consumer"
  tags = local.keys_tags
}

resource "aws_iam_access_key" "keys_consumer" {
  user = aws_iam_user.keys_consumer.name
}

resource "aws_iam_user" "keys_denied" {
  name = "${var.name}-key-denied"
  tags = local.keys_tags
}

resource "aws_iam_access_key" "keys_denied" {
  user = aws_iam_user.keys_denied.name
}

resource "aws_kms_external_key" "keys_single" {
  description             = "${var.name} imported single ${var.revision}"
  key_material_base64     = filebase64("${var.artifact_directory}/keys/single.bin")
  key_usage               = "ENCRYPT_DECRYPT"
  multi_region            = false
  enabled                 = true
  valid_to                = local.keys_valid_to
  policy                  = local.keys_policy
  deletion_window_in_days = 7
  tags                    = local.keys_tags

  lifecycle {
    ignore_changes = [key_material_base64]
  }
}

resource "aws_kms_external_key" "keys_external_primary" {
  description             = "${var.name} imported primary ${var.revision}"
  key_material_base64     = filebase64("${var.artifact_directory}/keys/multi.bin")
  key_usage               = "ENCRYPT_DECRYPT"
  multi_region            = true
  enabled                 = true
  policy                  = local.keys_policy
  deletion_window_in_days = 7
  tags                    = local.keys_tags

  lifecycle {
    ignore_changes = [key_material_base64]
  }
}

resource "aws_kms_replica_external_key" "keys_external_replica" {
  provider                = aws.west
  primary_key_arn         = aws_kms_external_key.keys_external_primary.arn
  description             = "${var.name} imported replica ${var.revision}"
  key_material_base64     = filebase64("${var.artifact_directory}/keys/multi.bin")
  enabled                 = var.revision == "v1"
  valid_to                = local.keys_valid_to
  policy                  = local.keys_policy
  deletion_window_in_days = 7
  tags                    = local.keys_tags

  lifecycle {
    ignore_changes = [key_material_base64]
  }
}

resource "aws_kms_key" "keys_primary" {
  description             = "${var.name} generated primary ${var.revision}"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage               = "ENCRYPT_DECRYPT"
  multi_region            = true
  is_enabled              = true
  enable_key_rotation     = true
  rotation_period_in_days = var.revision == "v1" ? 365 : 180
  policy                  = local.keys_policy
  deletion_window_in_days = 7
  tags                    = local.keys_tags
}

resource "aws_kms_replica_key" "keys_replica" {
  provider                = aws.west
  primary_key_arn         = aws_kms_key.keys_primary.arn
  description             = "${var.name} generated replica ${var.revision}"
  enabled                 = var.revision == "v1"
  policy                  = local.keys_policy
  deletion_window_in_days = 7
  tags                    = local.keys_tags
}

resource "aws_kms_alias" "keys_single" {
  name          = "alias/${var.name}-imported-single"
  target_key_id = aws_kms_external_key.keys_single.id
}

resource "aws_kms_alias" "keys_external_primary" {
  name          = "alias/${var.name}-imported-primary"
  target_key_id = aws_kms_external_key.keys_external_primary.id
}

resource "aws_kms_alias" "keys_external_replica" {
  provider      = aws.west
  name          = "alias/${var.name}-imported-replica"
  target_key_id = aws_kms_replica_external_key.keys_external_replica.key_id
}

resource "aws_kms_alias" "keys_primary" {
  name          = "alias/${var.name}-generated-primary"
  target_key_id = aws_kms_key.keys_primary.id
}

resource "aws_kms_alias" "keys_replica" {
  provider      = aws.west
  name          = "alias/${var.name}-generated-replica"
  target_key_id = aws_kms_replica_key.keys_replica.key_id
}

output "keys" {
  sensitive = true
  value = {
    name            = var.name
    account_id      = var.account_id
    revision        = var.revision
    policy          = local.keys_policy
    consumer_user   = aws_iam_user.keys_consumer.name
    consumer_key    = aws_iam_access_key.keys_consumer.id
    consumer_secret = aws_iam_access_key.keys_consumer.secret
    denied_key      = aws_iam_access_key.keys_denied.id
    denied_secret   = aws_iam_access_key.keys_denied.secret
    resources = {
      single = {
        id          = aws_kms_external_key.keys_single.id
        arn         = aws_kms_external_key.keys_single.arn
        region      = "us-east-1"
        description = aws_kms_external_key.keys_single.description
        enabled     = aws_kms_external_key.keys_single.enabled
        alias       = aws_kms_alias.keys_single.name
        valid_to    = local.keys_valid_to
        origin      = "EXTERNAL"
        multi_region = false
      }
      external_primary = {
        id          = aws_kms_external_key.keys_external_primary.id
        arn         = aws_kms_external_key.keys_external_primary.arn
        region      = "us-east-1"
        description = aws_kms_external_key.keys_external_primary.description
        enabled     = aws_kms_external_key.keys_external_primary.enabled
        alias       = aws_kms_alias.keys_external_primary.name
        valid_to    = ""
        origin      = "EXTERNAL"
        multi_region = true
      }
      external_replica = {
        id          = aws_kms_replica_external_key.keys_external_replica.key_id
        arn         = aws_kms_replica_external_key.keys_external_replica.arn
        region      = "us-west-2"
        description = aws_kms_replica_external_key.keys_external_replica.description
        enabled     = aws_kms_replica_external_key.keys_external_replica.enabled
        alias       = aws_kms_alias.keys_external_replica.name
        valid_to    = local.keys_valid_to
        origin      = "EXTERNAL"
        multi_region = true
      }
      primary = {
        id          = aws_kms_key.keys_primary.id
        arn         = aws_kms_key.keys_primary.arn
        region      = "us-east-1"
        description = aws_kms_key.keys_primary.description
        enabled     = aws_kms_key.keys_primary.is_enabled
        alias       = aws_kms_alias.keys_primary.name
        valid_to    = ""
        origin      = "AWS_KMS"
        multi_region = true
      }
      replica = {
        id          = aws_kms_replica_key.keys_replica.key_id
        arn         = aws_kms_replica_key.keys_replica.arn
        region      = "us-west-2"
        description = aws_kms_replica_key.keys_replica.description
        enabled     = aws_kms_replica_key.keys_replica.enabled
        alias       = aws_kms_alias.keys_replica.name
        valid_to    = ""
        origin      = "AWS_KMS"
        multi_region = true
      }
    }
  }
}
