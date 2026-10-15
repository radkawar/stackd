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
provider "aws" {
  region = var.region
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  s3_use_path_style = true
  http_proxy = var.endpoint
  https_proxy = ""
  no_proxy = "127.0.0.1,localhost"
  endpoints {
    s3 = var.endpoint
    s3control = var.endpoint
    sts = var.endpoint
    iam = var.endpoint
    kms = var.endpoint
    sqs = var.endpoint
    sns = var.endpoint
    cloudwatch = var.endpoint
  }
}
locals {
  buckets = toset(["data", "site", "reports", "replica", "lifecycle", "tiering", "payment"])
}
resource "aws_s3_bucket" "owned" {
  for_each = local.buckets
  bucket = "${var.name}-s3-${each.key}"
  force_destroy = true
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_s3_bucket" "locked" {
  bucket = "${var.name}-s3-lock"
  object_lock_enabled = true
  force_destroy = true
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_s3_bucket_versioning" "owned" {
  for_each = toset(["data", "replica", "lifecycle"])
  bucket = aws_s3_bucket.owned[each.key].id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_versioning" "locked" {
  bucket = aws_s3_bucket.locked.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  rule { object_ownership = "BucketOwnerPreferred" }
}
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  acl = "private"
  depends_on = [aws_s3_bucket_ownership_controls.data]
}
resource "aws_s3_account_public_access_block" "owned" {
  account_id = var.account_id
  block_public_acls = false
  ignore_public_acls = false
  block_public_policy = false
  restrict_public_buckets = false
}
resource "aws_s3_bucket_public_access_block" "owned" {
  for_each = local.buckets
  bucket = aws_s3_bucket.owned[each.key].id
  block_public_acls = each.key != "site"
  ignore_public_acls = each.key != "site"
  block_public_policy = each.key != "site"
  restrict_public_buckets = each.key != "site"
}
resource "aws_s3_bucket_abac" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  abac_status { status = "Enabled" }
}
resource "aws_s3_bucket_accelerate_configuration" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  status = var.revision == "initial" ? "Enabled" : "Suspended"
}
resource "aws_s3_bucket_request_payment_configuration" "payment" {
  bucket = aws_s3_bucket.owned["payment"].id
  payer = "Requester"
}
resource "aws_kms_key" "objects" {
  description = "Owned S3 bytes ${var.revision}"
  deletion_window_in_days = 7
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid = "AccountAuthority", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" },
    Action = "kms:*", Resource = "*"
  }] })
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.objects.arn
    }
    bucket_key_enabled = false
  }
}
resource "aws_s3_bucket_cors_configuration" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  cors_rule {
    allowed_methods = ["GET", "HEAD"]
    allowed_origins = ["https://${var.revision}.example.invalid"]
    allowed_headers = ["*"]
    expose_headers = ["ETag"]
    max_age_seconds = 60
  }
}
resource "aws_s3_object" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  key = "terraform.txt"
  content = "kms-storage-${var.revision}"
  server_side_encryption = "aws:kms"
  kms_key_id = aws_kms_key.objects.arn
  depends_on = [aws_s3_bucket_versioning.owned, aws_s3_bucket_server_side_encryption_configuration.data]
}
resource "aws_s3_object_copy" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  key = "copied.txt"
  source = "${aws_s3_bucket.owned["data"].id}/${aws_s3_object.data.key}?versionId=${aws_s3_object.data.version_id}"
  server_side_encryption = "aws:kms"
  kms_key_id = aws_kms_key.objects.arn
}
resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.owned["reports"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "Logs", Effect = "Allow", Principal = { Service = "logging.s3.amazonaws.com" }, Action = "s3:PutObject",
      Resource = "${aws_s3_bucket.owned["reports"].arn}/logs/*", Condition = { ArnEquals = { "aws:SourceArn" = aws_s3_bucket.owned["data"].arn } } },
    { Sid = "Inventory", Effect = "Allow", Principal = { Service = "s3.amazonaws.com" }, Action = "s3:PutObject",
      Resource = "${aws_s3_bucket.owned["reports"].arn}/inventory/*", Condition = { ArnEquals = { "aws:SourceArn" = aws_s3_bucket.owned["data"].arn } } }
  ] })
}
resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  target_bucket = aws_s3_bucket.owned["reports"].id
  target_prefix = "logs/${var.revision}/"
  depends_on = [aws_s3_bucket_policy.reports]
}
resource "aws_s3_bucket_inventory" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  name = "daily"
  included_object_versions = "All"
  optional_fields = ["Size", "EncryptionStatus"]
  schedule { frequency = "Daily" }
  destination {
    bucket {
      bucket_arn = aws_s3_bucket.owned["reports"].arn
      account_id = var.account_id
      format = "CSV"
      prefix = "inventory/${var.revision}"
      encryption {
        sse_s3 {}
      }
    }
  }
  depends_on = [aws_s3_bucket_policy.reports]
}
resource "aws_s3_bucket_analytics_configuration" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  name = "selection"
  filter { prefix = "analytics/${var.revision}/" }
}
resource "aws_s3_bucket_metric" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  name = "requests"
  filter { prefix = "events/" }
}
resource "aws_sqs_queue" "events" {
  name = "${var.name}-s3-events"
  message_retention_seconds = 1209600
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.url
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "s3.amazonaws.com" }, Action = "sqs:SendMessage",
    Resource = aws_sqs_queue.events.arn,
    Condition = { ArnEquals = { "aws:SourceArn" = aws_s3_bucket.owned["data"].arn } }
  }] })
}
resource "aws_s3_bucket_notification" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  queue {
    id = "objects-${var.revision}"
    queue_arn = aws_sqs_queue.events.arn
    events = ["s3:ObjectCreated:*"]
    filter_prefix = "events/"
  }
  depends_on = [aws_sqs_queue_policy.events]
}
resource "aws_s3_bucket_website_configuration" "site" {
  bucket = aws_s3_bucket.owned["site"].id
  index_document { suffix = "index.html" }
  error_document { key = "error.html" }
}
resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.owned["site"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid = "Website${var.revision}", Effect = "Allow", Principal = "*", Action = "s3:GetObject",
    Resource = "${aws_s3_bucket.owned["site"].arn}/*"
  }] })
  depends_on = [aws_s3_bucket_public_access_block.owned, aws_s3_account_public_access_block.owned]
}
resource "aws_s3_object" "site" {
  for_each = toset(["index.html", "error.html"])
  bucket = aws_s3_bucket.owned["site"].id
  key = each.key
  content = "${each.key}-${var.revision}"
  content_type = "text/html"
}
resource "aws_s3_bucket_lifecycle_configuration" "owned" {
  bucket = aws_s3_bucket.owned["lifecycle"].id
  transition_default_minimum_object_size = "all_storage_classes_128K"
  rule {
    id = "expire-${var.revision}"
    status = "Enabled"
    filter { prefix = "expire/" }
    expiration { days = 1 }
    noncurrent_version_expiration { noncurrent_days = 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  rule {
    id = "transition-${var.revision}"
    status = "Enabled"
    filter { prefix = "transition/" }
    transition {
      days = 1
      storage_class = "GLACIER"
    }
  }
  depends_on = [aws_s3_bucket_versioning.owned]
}
resource "aws_s3_bucket_intelligent_tiering_configuration" "owned" {
  bucket = aws_s3_bucket.owned["tiering"].id
  name = "archive"
  filter { prefix = "archive/" }
  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days = var.revision == "initial" ? 90 : 91
  }
}
resource "aws_s3_bucket_object_lock_configuration" "owned" {
  bucket = aws_s3_bucket.locked.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.revision == "initial" ? 1 : 2
    }
  }
  depends_on = [aws_s3_bucket_versioning.locked]
}
resource "aws_iam_role" "replication" {
  name = "${var.name}-s3-replication"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "s3.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role_policy" "replication" {
  name = "transfer"
  role = aws_iam_role.replication.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:GetReplicationConfiguration", "s3:ListBucket"], Resource = aws_s3_bucket.owned["data"].arn },
    { Effect = "Allow", Action = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"], Resource = "${aws_s3_bucket.owned["data"].arn}/*" },
    { Effect = "Allow", Action = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"], Resource = "${aws_s3_bucket.owned["replica"].arn}/*" },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.objects.arn }
  ] })
}
resource "aws_s3_bucket_replication_configuration" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  role = aws_iam_role.replication.arn
  rule {
    id = "transfer-${var.revision}"
    priority = 1
    status = "Enabled"
    filter { prefix = "replicate/" }
    delete_marker_replication { status = "Enabled" }
    source_selection_criteria {
      sse_kms_encrypted_objects { status = "Enabled" }
    }
    destination {
      bucket = aws_s3_bucket.owned["replica"].arn
      storage_class = "STANDARD"
      encryption_configuration { replica_kms_key_id = aws_kms_key.objects.arn }
    }
  }
  depends_on = [aws_s3_bucket_versioning.owned, aws_iam_role_policy.replication]
}
resource "aws_s3_access_point" "data" {
  bucket = aws_s3_bucket.owned["data"].id
  name = "${var.name}-s3-ap"
  account_id = var.account_id
  public_access_block_configuration {
    block_public_acls = true
    ignore_public_acls = true
    block_public_policy = true
    restrict_public_buckets = true
  }
}
resource "aws_s3control_access_point_policy" "data" {
  access_point_arn = aws_s3_access_point.data.arn
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid = "Read${var.revision}", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" },
    Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${aws_s3_access_point.data.arn}/object/*"
  }] })
}
resource "aws_iam_user" "consumer" { name = "${var.name}-s3-consumer" }
resource "aws_iam_user_policy" "consumer" {
  name = "current-authority"
  user = aws_iam_user.consumer.name
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${aws_s3_bucket.owned["data"].arn}/*" },
    { Effect = "Allow", Action = "s3:ListBucket", Resource = aws_s3_bucket.owned["data"].arn,
      Condition = { StringEquals = { "aws:ResourceTag/Revision" = var.revision } } }
  ] })
}
data "aws_canonical_user_id" "current" {}
data "aws_s3_bucket" "current" { bucket = aws_s3_bucket.owned["data"].id }
data "aws_s3_object" "current" {
  bucket = aws_s3_bucket.owned["data"].id
  key = aws_s3_object.data.key
  download_body = true
}
data "aws_s3_objects" "current" {
  bucket = aws_s3_bucket.owned["data"].id
  depends_on = [aws_s3_object.data, aws_s3_object_copy.data]
}
data "aws_s3_bucket_policy" "current" {
  bucket = aws_s3_bucket.owned["site"].id
  depends_on = [aws_s3_bucket_policy.site]
}
data "aws_s3_bucket_notification" "current" {
  bucket = aws_s3_bucket.owned["data"].id
  depends_on = [aws_s3_bucket_notification.data]
}
data "aws_s3_bucket_object_lock_configuration" "current" {
  bucket = aws_s3_bucket.locked.id
  depends_on = [aws_s3_bucket_object_lock_configuration.owned]
}
data "aws_s3_bucket_replication_configuration" "current" {
  bucket = aws_s3_bucket.owned["data"].id
  depends_on = [aws_s3_bucket_replication_configuration.data]
}
data "aws_s3_buckets" "current" { depends_on = [aws_s3_bucket.owned, aws_s3_bucket.locked] }
data "aws_s3_access_point" "current" {
  account_id = var.account_id
  name = aws_s3_access_point.data.name
}
data "aws_s3_account_public_access_block" "current" {
  account_id = var.account_id
  depends_on = [aws_s3_account_public_access_block.owned]
}
data "aws_s3control_access_points" "current" {
  account_id = var.account_id
  bucket = aws_s3_bucket.owned["data"].id
  depends_on = [aws_s3_access_point.data]
}
output "s3" {
  value = {
    buckets = { for k, v in aws_s3_bucket.owned : k => v.id }
    locked = aws_s3_bucket.locked.id
    key_id = aws_kms_key.objects.key_id
    key_arn = aws_kms_key.objects.arn
    queue = aws_sqs_queue.events.url
    queue_arn = aws_sqs_queue.events.arn
    role = aws_iam_role.replication.name
    user = aws_iam_user.consumer.name
    access_point = aws_s3_access_point.data.name
    access_point_arn = aws_s3_access_point.data.arn
    lookup_arn = data.aws_s3_bucket.current.arn
    lookup_body_base64 = data.aws_s3_object.current.body_base64
    lookup_keys = data.aws_s3_objects.current.keys
    lookup_policy = data.aws_s3_bucket_policy.current.policy
    canonical_id = data.aws_canonical_user_id.current.id
    lookup_buckets = data.aws_s3_buckets.current.buckets
    lookup_access_point_arn = data.aws_s3_access_point.current.arn
    lookup_notifications = data.aws_s3_bucket_notification.current.queue
    lookup_lock = data.aws_s3_bucket_object_lock_configuration.current.rule
    lookup_replication = data.aws_s3_bucket_replication_configuration.current.rule
    lookup_access_points = data.aws_s3control_access_points.current.access_points
    lookup_account_block = {
      block_public_acls = data.aws_s3_account_public_access_block.current.block_public_acls
      ignore_public_acls = data.aws_s3_account_public_access_block.current.ignore_public_acls
      block_public_policy = data.aws_s3_account_public_access_block.current.block_public_policy
      restrict_public_buckets = data.aws_s3_account_public_access_block.current.restrict_public_buckets
    }
  }
}
