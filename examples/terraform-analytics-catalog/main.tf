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
variable "account_id" { type = string }
variable "plain_catalog_id" { type = string }
variable "postgres_port" { type = number }
variable "postgres_password" {
  type      = string
  sensitive = true
}
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
  skip_requesting_account_id  = false
  s3_use_path_style           = true
  http_proxy                  = var.endpoint
  https_proxy                 = ""
  no_proxy                    = "127.0.0.1,localhost"
  endpoints {
    athena         = var.endpoint
    cloudwatch     = var.endpoint
    glue           = var.endpoint
    iam            = var.endpoint
    kinesis        = var.endpoint
    kms            = var.endpoint
    logs           = var.endpoint
    s3             = var.endpoint
    s3control      = var.endpoint
    secretsmanager = var.endpoint
    sts            = var.endpoint
  }
}

locals {
  database = replace(var.name, "-", "_")
  delimiter = var.revision == 1 ? "|" : ";"
  tags = { Fixture = "terraform-analytics-catalog", Revision = tostring(var.revision) }
}

resource "aws_s3_bucket" "lake" {
  bucket        = var.name
  force_destroy = true
  tags          = local.tags
}
resource "aws_kms_key" "lake" {
  description             = "Analytics catalog revision ${var.revision}"
  deletion_window_in_days  = 7
  enable_key_rotation     = true
  tags                    = local.tags
}
resource "aws_iam_role" "glue" {
  name = "${var.name}-glue"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "glue.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags = local.tags
}
resource "aws_iam_role_policy" "glue" {
  name = "native-catalog-consumer"
  role = aws_iam_role.glue.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts"], Resource = [aws_s3_bucket.lake.arn, "${aws_s3_bucket.lake.arn}/*"] },
    { Effect = "Allow", Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], Resource = aws_kms_key.lake.arn },
    { Effect = "Allow", Action = ["glue:GetDatabase", "glue:GetTable", "glue:GetTables", "glue:GetPartition", "glue:GetPartitions", "glue:CreateTable", "glue:UpdateTable", "glue:DeleteTable", "glue:UpdatePartition", "glue:BatchCreatePartition", "glue:BatchUpdatePartition", "glue:BatchDeletePartition", "glue:GetConnection", "glue:GetUserDefinedFunction", "glue:GetWorkflowRunProperties", "glue:GetSecurityConfiguration"], Resource = "*" },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.postgres.arn },
    { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams", "cloudwatch:PutMetricData"], Resource = "*" }
  ] })
}
resource "aws_secretsmanager_secret" "postgres" {
  name                    = "${var.name}-postgres"
  recovery_window_in_days = 0
  tags                    = local.tags
}
resource "aws_secretsmanager_secret_version" "postgres" {
  secret_id     = aws_secretsmanager_secret.postgres.id
  secret_string = jsonencode({ username = "catalog", password = var.postgres_password })
}
resource "aws_glue_data_catalog_encryption_settings" "passwords" {
  catalog_id = var.account_id
  data_catalog_encryption_settings {
    connection_password_encryption {
      aws_kms_key_id                      = aws_kms_key.lake.arn
      return_connection_password_encrypted = var.revision == 1
    }
    encryption_at_rest {
      catalog_encryption_mode = "DISABLED"
    }
  }
}
resource "aws_glue_connection" "postgres" {
  catalog_id      = var.account_id
  name            = "${var.name}-postgres"
  connection_type = "JDBC"
  description     = "Real PostgreSQL consumer revision ${var.revision}"
  connection_properties = {
    JDBC_CONNECTION_URL = "jdbc:postgresql://127.0.0.1:${var.postgres_port}/catalog"
    SECRET_ID           = aws_secretsmanager_secret.postgres.arn
    JDBC_ENFORCE_SSL     = "false"
  }
  tags       = local.tags
  depends_on = [aws_secretsmanager_secret_version.postgres, aws_glue_data_catalog_encryption_settings.passwords]
}
resource "aws_glue_catalog_database" "lake" {
  catalog_id  = var.account_id
  name        = local.database
  description = "Native catalog revision ${var.revision}"
  location_uri = "s3://${aws_s3_bucket.lake.bucket}/"
  parameters  = { revision = tostring(var.revision) }
  tags        = local.tags
}
resource "aws_glue_classifier" "csv" {
  name = "${var.name}-csv"
  csv_classifier {
    contains_header       = "PRESENT"
    delimiter             = local.delimiter
    quote_symbol          = "\""
    header                = ["label", "amount"]
    allow_single_column   = false
    disable_value_trimming = true
    serde                 = "LazySimpleSerDe"
  }
}
resource "aws_glue_crawler" "s3" {
  name          = "${var.name}-s3"
  role          = aws_iam_role.glue.arn
  database_name = aws_glue_catalog_database.lake.name
  description   = "Native CSV discovery revision ${var.revision}"
  classifiers   = [aws_glue_classifier.csv.name]
  table_prefix  = "csv_"
  s3_target { path = "s3://${aws_s3_bucket.lake.bucket}/input/" }
  schema_change_policy {
    update_behavior = "UPDATE_IN_DATABASE"
    delete_behavior = "DELETE_FROM_DATABASE"
  }
  recrawl_policy { recrawl_behavior = "CRAWL_EVERYTHING" }
  tags       = local.tags
  depends_on = [aws_iam_role_policy.glue]
}
resource "aws_glue_crawler" "postgres" {
  name          = "${var.name}-jdbc"
  role          = aws_iam_role.glue.arn
  database_name = aws_glue_catalog_database.lake.name
  description   = "Native PostgreSQL discovery revision ${var.revision}"
  table_prefix  = "jdbc_"
  jdbc_target {
    connection_name = aws_glue_connection.postgres.name
    path            = "catalog/source/%"
    exclusions      = ["source/excluded"]
  }
  tags       = local.tags
  depends_on = [aws_iam_role_policy.glue]
}
resource "aws_glue_catalog_table" "indexed" {
  catalog_id    = var.account_id
  database_name = aws_glue_catalog_database.lake.name
  name          = "indexed"
  table_type    = "EXTERNAL_TABLE"
  description   = "Independent partition consumer revision ${var.revision}"
  parameters    = { classification = "csv", "skip.header.line.count" = "1" }
  partition_keys {
    name = "region"
    type = "string"
  }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/input/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    columns {
      name = "label"
      type = "string"
    }
    columns {
      name = "amount"
      type = "int"
    }
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
      parameters = { "field.delim" = local.delimiter, "serialization.format" = local.delimiter }
    }
  }
}
resource "aws_glue_partition" "regions" {
  for_each         = toset(["east", "west"])
  catalog_id       = var.account_id
  database_name    = aws_glue_catalog_database.lake.name
  table_name       = aws_glue_catalog_table.indexed.name
  partition_values = [each.key]
  parameters       = { revision = tostring(var.revision) }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/input/region=${each.key}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    columns {
      name = "label"
      type = "string"
    }
    columns {
      name = "amount"
      type = "int"
    }
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
      parameters = { "field.delim" = local.delimiter, "serialization.format" = local.delimiter }
    }
  }
}
resource "aws_glue_partition_index" "region" {
  catalog_id    = var.account_id
  database_name = aws_glue_catalog_database.lake.name
  table_name    = aws_glue_catalog_table.indexed.name
  partition_index {
    index_name = "region-${var.revision}"
    keys       = ["region"]
  }
  depends_on = [aws_glue_partition.regions]
}
resource "aws_glue_registry" "records" {
  registry_name = "${var.name}-records"
  description   = "Actual Avro records revision ${var.revision}"
  tags          = local.tags
}
resource "aws_glue_schema" "records" {
  registry_arn = aws_glue_registry.records.arn
  schema_name  = "records"
  description  = "Actual serializer revision ${var.revision}"
  compatibility = "BACKWARD"
  data_format   = "AVRO"
  schema_definition = jsonencode({ type = "record", name = "Record", fields = [
    { name = "label", type = "string" },
    { name = "amount", type = var.revision == 1 ? "int" : "long" }
  ] })
  tags = local.tags
}
resource "aws_iam_user" "reader" {
  name          = "${var.name}-reader"
  force_destroy = true
  tags          = local.tags
}
resource "aws_iam_user_policy" "reader" {
  name = "read-catalog"
  user = aws_iam_user.reader.name
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["glue:GetDatabase", "glue:GetTable"], Resource = "*" }] })
}
resource "aws_iam_access_key" "reader" { user = aws_iam_user.reader.name }
resource "aws_glue_resource_policy" "reader" {
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid = "Revision${var.revision}", Effect = "Deny", Principal = { AWS = aws_iam_user.reader.arn },
    Action = var.revision == 1 ? "glue:GetDatabase" : "glue:GetTable",
    Resource = var.revision == 1 ? "arn:aws:glue:us-east-1:${var.account_id}:database/${local.database}" : "arn:aws:glue:us-east-1:${var.account_id}:table/${local.database}/indexed"
  }] })
}
resource "aws_glue_security_configuration" "writer" {
  name = "${var.name}-writer-${var.revision}"
  encryption_configuration {
    s3_encryption {
      s3_encryption_mode = var.revision == 1 ? "SSE-KMS" : "SSE-S3"
      kms_key_arn        = var.revision == 1 ? aws_kms_key.lake.arn : null
    }
    cloudwatch_encryption { cloudwatch_encryption_mode = "DISABLED" }
    job_bookmarks_encryption { job_bookmarks_encryption_mode = "DISABLED" }
  }
}
resource "aws_glue_user_defined_function" "case" {
  catalog_id    = var.account_id
  database_name = aws_glue_catalog_database.lake.name
  name          = "catalog_case"
  class_name    = var.revision == 1 ? "org.apache.hadoop.hive.ql.udf.generic.GenericUDFUpper" : "org.apache.hadoop.hive.ql.udf.generic.GenericUDFLower"
  owner_name    = aws_iam_role.glue.name
  owner_type    = "ROLE"
}
resource "aws_s3_object" "script" {
  bucket       = aws_s3_bucket.lake.id
  key          = "scripts/producer.py"
  source       = "${path.module}/producer.py"
  source_hash  = filemd5("${path.module}/producer.py")
  content_type = "text/x-python"
}
resource "aws_glue_job" "producer" {
  name                   = "${var.name}-producer"
  role_arn               = aws_iam_role.glue.arn
  description            = "Native Spark and catalog UDF revision ${var.revision}"
  glue_version           = "5.0"
  execution_class        = "STANDARD"
  worker_type            = "G.1X"
  number_of_workers      = 2
  max_retries            = 0
  timeout                = 10
  security_configuration = aws_glue_security_configuration.writer.name
  execution_property { max_concurrent_runs = 1 }
  command {
    name            = "glueetl"
    python_version  = "3"
    script_location = "s3://${aws_s3_object.script.bucket}/${aws_s3_object.script.key}"
  }
  default_arguments = {
    "--bucket"        = aws_s3_bucket.lake.bucket
    "--database"      = aws_glue_catalog_database.lake.name
    "--catalog-id"    = var.account_id
    "--udf-name"      = aws_glue_user_defined_function.case.name
    "--revision"      = tostring(var.revision)
    "--delimiter"     = local.delimiter
    "--job-bookmark-option" = "job-bookmark-disable"
    "--enable-metrics" = "true"
  }
  tags       = local.tags
  depends_on = [aws_iam_role_policy.glue]
}
resource "aws_glue_workflow" "catalog" {
  name                   = "${var.name}-workflow"
  description            = "Actual producer and two native crawlers revision ${var.revision}"
  max_concurrent_runs     = 1
  default_run_properties = { revision = tostring(var.revision), consumer = "native-spark-csv" }
  tags                   = local.tags
}
resource "aws_glue_trigger" "start" {
  name          = "${var.name}-start"
  type          = "ON_DEMAND"
  enabled       = false
  workflow_name = aws_glue_workflow.catalog.name
  description   = "Explicit workflow admission revision ${var.revision}"
  actions { job_name = aws_glue_job.producer.name }
  tags = local.tags
}
resource "aws_glue_trigger" "discover" {
  name              = "${var.name}-discover"
  type              = "CONDITIONAL"
  enabled           = true
  start_on_creation = true
  workflow_name     = aws_glue_workflow.catalog.name
  description       = "Discover only actual successful producer output revision ${var.revision}"
  actions { crawler_name = aws_glue_crawler.s3.name }
  actions { crawler_name = aws_glue_crawler.postgres.name }
  predicate {
    logical = "AND"
    conditions {
      job_name = aws_glue_job.producer.name
      state    = "SUCCEEDED"
    }
  }
  tags = local.tags
}
resource "aws_athena_workgroup" "catalog" {
  name          = "${var.name}-catalog"
  force_destroy = true
  description   = "Native crawler output consumer revision ${var.revision}"
  configuration {
    enforce_workgroup_configuration = true
    engine_version { selected_engine_version = "Athena engine version 3" }
    result_configuration { output_location = "s3://${aws_s3_bucket.lake.bucket}/query-results/" }
  }
  tags = local.tags
}
resource "aws_kinesis_account_settings" "capacity" {
  minimum_throughput_billing_commitment { status = var.revision == 1 ? "ENABLED" : "DISABLED" }
}
resource "aws_kinesis_stream" "avro" {
  name                   = "${var.name}-avro"
  warm_throughput_mib_ps  = var.revision + 3
  retention_period       = 24
  stream_mode_details { stream_mode = "ON_DEMAND" }
  tags       = local.tags
  depends_on = [aws_kinesis_account_settings.capacity]
}

data "aws_glue_catalog" "plain" { name = var.plain_catalog_id }
data "aws_glue_registry" "records" { name = aws_glue_registry.records.registry_name }
data "aws_glue_connection" "postgres" { id = aws_glue_connection.postgres.id }
data "aws_glue_data_catalog_encryption_settings" "passwords" {
  catalog_id = var.account_id
  depends_on = [aws_glue_data_catalog_encryption_settings.passwords]
}
data "aws_glue_catalog_table" "indexed" {
  catalog_id    = var.account_id
  database_name = aws_glue_catalog_database.lake.name
  name          = aws_glue_catalog_table.indexed.name
}

output "catalog" {
  value = {
    bucket = aws_s3_bucket.lake.bucket, key_arn = aws_kms_key.lake.arn,
    database = aws_glue_catalog_database.lake.name, workgroup = aws_athena_workgroup.catalog.name,
    workflow = aws_glue_workflow.catalog.name, job = aws_glue_job.producer.name,
    s3_crawler = aws_glue_crawler.s3.name, jdbc_crawler = aws_glue_crawler.postgres.name,
    classifier = aws_glue_classifier.csv.name, connection = aws_glue_connection.postgres.name,
    security = aws_glue_security_configuration.writer.name, udf = aws_glue_user_defined_function.case.name,
    registry_arn = aws_glue_registry.records.arn, schema_arn = aws_glue_schema.records.arn,
    stream_name = aws_kinesis_stream.avro.name, stream_arn = aws_kinesis_stream.avro.arn,
    plain_catalog_id = data.aws_glue_catalog.plain.catalog_id
  }
}
output "reader" {
  sensitive = true
  value = { key = aws_iam_access_key.reader.id, secret = aws_iam_access_key.reader.secret }
}
