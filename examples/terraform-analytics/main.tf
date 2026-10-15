terraform {
  required_version = ">= 1.5.0, < 2.0.0"
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
    error_message = "Only an explicit IPv4 loopback HTTP endpoint is permitted."
  }
}
variable "name" { type = string }
variable "account_id" { type = string }
variable "revision" {
  type    = number
  default = 1
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true
  # S3 Control adds the account to the hostname. Route that signed authority
  # to the owned HTTP listener without changing DNS or the signed Host.
  http_proxy  = var.endpoint
  https_proxy = ""
  no_proxy    = "127.0.0.1,localhost"
  endpoints {
    athena   = var.endpoint
    firehose = var.endpoint
    glue     = var.endpoint
    iam      = var.endpoint
    kinesis  = var.endpoint
    s3       = var.endpoint
    s3control = var.endpoint
    sts      = var.endpoint
  }
}

locals {
  database = replace("${var.name}_catalog", "-", "_")
  tags     = { Example = "terraform-analytics", Revision = tostring(var.revision) }
  columns  = [{ name = "label", type = "string" }, { name = "amount", type = "bigint" }]
}

resource "aws_s3_bucket" "lake" {
  bucket        = "${var.name}-lake"
  force_destroy = true
  tags          = local.tags
}

resource "aws_iam_role" "delivery" {
  name = "${var.name}-delivery"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "firehose.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy" "delivery" {
  name = "delivery"
  role = aws_iam_role.delivery.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"], Resource = aws_s3_bucket.lake.arn },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload"], Resource = "${aws_s3_bucket.lake.arn}/*" },
      { Effect = "Allow", Action = ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:ListShards", "kinesis:GetShardIterator", "kinesis:GetRecords"], Resource = aws_kinesis_stream.records.arn }
    ]
  })
}

resource "aws_glue_catalog_database" "lake" {
  name        = local.database
  catalog_id  = var.account_id
  description = "Partitioned Terraform lake revision ${var.revision}"
  location_uri = "s3://${aws_s3_bucket.lake.bucket}/input/"
  parameters  = { revision = tostring(var.revision) }
  tags        = local.tags
}
resource "aws_glue_catalog_table" "numbers" {
  name          = "numbers"
  catalog_id    = var.account_id
  database_name = aws_glue_catalog_database.lake.name
  description   = "Actual JSON rows revision ${var.revision}"
  table_type    = "EXTERNAL_TABLE"
  parameters    = { classification = "json", EXTERNAL = "TRUE", revision = tostring(var.revision) }
  partition_keys {
    name = "region"
    type = "string"
  }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/input/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
    ser_de_info {
      name                  = "json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }
  }
}
resource "aws_glue_partition" "regions" {
  for_each         = toset(["east", "west"])
  catalog_id       = var.account_id
  database_name    = aws_glue_catalog_database.lake.name
  table_name       = aws_glue_catalog_table.numbers.name
  partition_values = [each.key]
  parameters       = { revision = tostring(var.revision) }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/input/region=${each.key}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
    ser_de_info {
      name                  = "json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }
  }
}

resource "aws_athena_data_catalog" "lake" {
  name        = "${var.name}-catalog"
  type        = "GLUE"
  description = "Glue execution catalog revision ${var.revision}"
  parameters  = { "catalog-id" = var.account_id }
  tags        = local.tags
}
resource "aws_athena_workgroup" "lake" {
  name          = "${var.name}-queries"
  description   = "Trino execution revision ${var.revision}"
  force_destroy = true
  tags          = local.tags
  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    engine_version { selected_engine_version = "Athena engine version 3" }
    result_configuration {
      output_location       = "s3://${aws_s3_bucket.lake.bucket}/results/"
      expected_bucket_owner = var.account_id
      encryption_configuration { encryption_option = "SSE_S3" }
    }
  }
}
resource "aws_athena_database" "written" {
  name          = replace("${var.name}_written", "-", "_")
  bucket        = aws_s3_bucket.lake.bucket
  comment       = "Actual Terraform Hive DDL"
  force_destroy = true
  workgroup     = aws_athena_workgroup.lake.name
}
resource "aws_athena_named_query" "totals" {
  name        = "${var.name}-totals"
  database    = aws_glue_catalog_database.lake.name
  workgroup   = aws_athena_workgroup.lake.name
  description = "Saved query revision ${var.revision}"
  query       = "SELECT label, sum(amount) + ${var.revision - 1} AS total, region FROM numbers GROUP BY label, region ORDER BY label, region"
}
resource "aws_athena_prepared_statement" "total" {
  name            = "region_total"
  workgroup       = aws_athena_workgroup.lake.name
  description     = "Prepared query revision ${var.revision}"
  query_statement = "SELECT sum(amount) + ${var.revision - 1} AS total FROM numbers WHERE region = ?"
}

data "aws_athena_named_query" "totals" {
  name      = aws_athena_named_query.totals.name
  workgroup = aws_athena_workgroup.lake.name
  depends_on = [aws_athena_named_query.totals]
}
data "aws_glue_catalog_table" "numbers" {
  name          = aws_glue_catalog_table.numbers.name
  database_name = aws_glue_catalog_database.lake.name
  catalog_id    = var.account_id
}

resource "aws_kinesis_stream" "records" {
  name                   = "${var.name}-records"
  shard_count            = var.revision
  retention_period       = var.revision == 1 ? 24 : 48
  max_record_size_in_kib  = var.revision == 1 ? 1024 : 2048
  shard_level_metrics    = var.revision == 1 ? ["IncomingBytes"] : ["OutgoingRecords"]
  enforce_consumer_deletion = true
  stream_mode_details { stream_mode = "PROVISIONED" }
  tags = local.tags
}
resource "aws_kinesis_stream_consumer" "reader" {
  name       = "${var.name}-reader"
  stream_arn = aws_kinesis_stream.records.arn
  tags       = local.tags
}
resource "aws_kinesis_resource_policy" "records" {
  resource_arn = aws_kinesis_stream.records.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Sid = "OwnedReaderRevision${var.revision}", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }, Action = ["kinesis:DescribeStream", "kinesis:GetRecords"], Resource = aws_kinesis_stream.records.arn }]
  })
}
data "aws_kinesis_stream" "records" { name = aws_kinesis_stream.records.name }
data "aws_kinesis_stream_consumer" "reader" {
  name       = aws_kinesis_stream_consumer.reader.name
  stream_arn = aws_kinesis_stream.records.arn
}

resource "aws_kinesis_firehose_delivery_stream" "direct" {
  name        = "${var.name}-direct"
  destination = "extended_s3"
  tags        = local.tags
  extended_s3_configuration {
    role_arn           = aws_iam_role.delivery.arn
    bucket_arn         = aws_s3_bucket.lake.arn
    prefix             = "direct/revision-${var.revision}/"
    buffering_interval = 1
    buffering_size     = 1
    compression_format = var.revision == 1 ? "UNCOMPRESSED" : "GZIP"
  }
  depends_on = [aws_iam_role_policy.delivery]
}
resource "aws_kinesis_firehose_delivery_stream" "source" {
  name        = "${var.name}-source"
  destination = "extended_s3"
  tags        = local.tags
  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.records.arn
    role_arn           = aws_iam_role.delivery.arn
  }
  extended_s3_configuration {
    role_arn           = aws_iam_role.delivery.arn
    bucket_arn         = aws_s3_bucket.lake.arn
    prefix             = "source/revision-${var.revision}/"
    buffering_interval = 1
    buffering_size     = 1
    compression_format = var.revision == 1 ? "UNCOMPRESSED" : "GZIP"
  }
  depends_on = [aws_iam_role_policy.delivery]
}
data "aws_kinesis_firehose_delivery_stream" "direct" { name = aws_kinesis_firehose_delivery_stream.direct.name }

output "analytics" {
  value = {
    bucket            = aws_s3_bucket.lake.bucket
    database          = aws_glue_catalog_database.lake.name
    written_database  = aws_athena_database.written.name
    catalog           = aws_athena_data_catalog.lake.name
    workgroup         = aws_athena_workgroup.lake.name
    named_query_id    = aws_athena_named_query.totals.id
    named_query_sql   = data.aws_athena_named_query.totals.querystring
    prepared_name     = aws_athena_prepared_statement.total.name
    table_arn         = data.aws_glue_catalog_table.numbers.arn
    stream_name       = aws_kinesis_stream.records.name
    stream_arn        = data.aws_kinesis_stream.records.arn
    consumer_arn      = data.aws_kinesis_stream_consumer.reader.arn
    direct_name       = aws_kinesis_firehose_delivery_stream.direct.name
    direct_arn        = data.aws_kinesis_firehose_delivery_stream.direct.arn
    source_name       = aws_kinesis_firehose_delivery_stream.source.name
    source_arn        = aws_kinesis_firehose_delivery_stream.source.arn
    revision          = var.revision
  }
}
