terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}

variable "endpoint" { type = string }
variable "name" { type = string }
variable "revision" { type = string }
variable "protected" { type = bool }
variable "certificate" { type = string }
variable "private_key" {
  type      = string
  sensitive = true
}
variable "source_zip" { type = string }
variable "target_url" { type = string }

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  http_proxy                  = var.endpoint
  https_proxy                 = ""
  no_proxy                    = "127.0.0.1,localhost"
  s3_use_path_style           = true
  endpoints {
    acm            = var.endpoint
    apigateway     = var.endpoint
    cloudtrail     = var.endpoint
    cloudwatch     = var.endpoint
    cloudwatchlogs = var.endpoint
    configservice  = var.endpoint
    guardduty      = var.endpoint
    iam            = var.endpoint
    kinesis        = var.endpoint
    kms            = var.endpoint
    route53        = var.endpoint
    s3             = var.endpoint
    s3control      = var.endpoint
    signer         = var.endpoint
    ssm            = var.endpoint
    sts            = var.endpoint
    wafv2          = var.endpoint
    xray           = var.endpoint
  }
}

locals {
  tags = { Fixture = var.name, Revision = var.revision }
}

resource "aws_cloudwatch_log_group" "application" {
  name                        = "/${var.name}/application"
  retention_in_days           = var.revision == "initial" ? 1 : 3
  deletion_protection_enabled = var.protected
  tags                        = local.tags
}
resource "aws_cloudwatch_log_stream" "application" {
  name           = "consumer"
  log_group_name = aws_cloudwatch_log_group.application.name
}
resource "aws_cloudwatch_log_metric_filter" "events" {
  name           = "events"
  log_group_name = aws_cloudwatch_log_group.application.name
  pattern        = "{ $.revision = \"*\" }"
  metric_transformation {
    name      = "Events"
    namespace = var.name
    value     = "1"
    unit      = "Count"
  }
}
resource "aws_cloudwatch_log_resource_policy" "delivery" {
  policy_name = var.name
  policy_document = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect   = "Allow", Principal = { Service = "delivery.logs.amazonaws.com" },
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = "${aws_cloudwatch_log_group.application.arn}:*"
    }]
  })
}
data "aws_cloudwatch_log_group" "application" { name = aws_cloudwatch_log_group.application.name }
data "aws_cloudwatch_log_groups" "application" { log_group_name_prefix = "/${var.name}/" }
resource "aws_cloudwatch_metric_alarm" "events" {
  alarm_name          = "${var.name}-events"
  alarm_description   = var.revision
  namespace           = var.name
  metric_name         = "Events"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  tags                = local.tags
}
resource "aws_cloudwatch_composite_alarm" "events" {
  alarm_name        = "${var.name}-composite"
  alarm_description = var.revision
  alarm_rule        = "ALARM(\"${aws_cloudwatch_metric_alarm.events.alarm_name}\")"
  tags              = local.tags
}
resource "aws_cloudwatch_dashboard" "application" {
  dashboard_name = var.name
  dashboard_body = jsonencode({ widgets = [{
    type       = "metric", x = 0, y = 0, width = 12, height = 6,
    properties = { title = var.revision, region = "us-east-1", metrics = [[var.name, "Events"]], period = 60, stat = "Sum" }
  }] })
}

resource "aws_s3_bucket" "evidence" {
  bucket        = "${var.name}-evidence"
  force_destroy = true
  tags          = local.tags
}
resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Principal = { Service = ["cloudtrail.amazonaws.com", "config.amazonaws.com"] }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.evidence.arn },
    { Effect = "Allow", Principal = { Service = ["cloudtrail.amazonaws.com", "config.amazonaws.com"] }, Action = "s3:PutObject", Resource = "${aws_s3_bucket.evidence.arn}/*", Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } } }
  ] })
}
resource "aws_cloudtrail" "application" {
  name                          = var.name
  s3_bucket_name                = aws_s3_bucket.evidence.id
  s3_key_prefix                 = "trail"
  include_global_service_events = true
  enable_logging                = true
  tags                          = local.tags
  depends_on                    = [aws_s3_bucket_policy.evidence]
}
data "aws_cloudtrail_service_account" "local" {}

resource "aws_iam_role" "config" {
  name = "${var.name}-config"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "config.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role_policy" "config" {
  role = aws_iam_role.config.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["s3:*", "sqs:*"], Resource = "*"
  }] })
}
resource "aws_config_configuration_recorder" "application" {
  name     = var.name
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::S3::Bucket"]
    recording_strategy { use_only = "INCLUSION_BY_RESOURCE_TYPES" }
  }
  depends_on = [aws_iam_role_policy.config]
}
resource "aws_config_delivery_channel" "application" {
  name           = var.name
  s3_bucket_name = aws_s3_bucket.evidence.id
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.application, aws_s3_bucket_policy.evidence]
}
resource "aws_config_configuration_recorder_status" "application" {
  name       = aws_config_configuration_recorder.application.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.application]
}
resource "aws_config_config_rule" "tags" {
  name             = "${var.name}-tags"
  description      = var.revision
  input_parameters = jsonencode({ tag1Key = "Fixture", tag1Value = var.name })
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  scope { compliance_resource_types = ["AWS::S3::Bucket"] }
  tags       = local.tags
  depends_on = [aws_config_configuration_recorder_status.application]
}
resource "aws_config_aggregate_authorization" "local" {
  account_id = "738492615083"
  region     = "us-east-1"
  tags       = local.tags
}
resource "aws_config_configuration_aggregator" "local" {
  name = var.name
  account_aggregation_source {
    account_ids = ["738492615083"]
    regions     = ["us-east-1"]
  }
  tags = local.tags
}

resource "aws_guardduty_detector" "application" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = local.tags
}
resource "aws_guardduty_detector_feature" "s3" {
  detector_id = aws_guardduty_detector.application.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}
resource "aws_guardduty_filter" "application" {
  name        = var.name
  detector_id = aws_guardduty_detector.application.id
  action      = "NOOP"
  rank        = 1
  description = var.revision
  finding_criteria {
    criterion {
      field                 = "severity"
      greater_than_or_equal = "4"
    }
  }
  tags = local.tags
}
data "aws_guardduty_detector" "application" { depends_on = [aws_guardduty_detector.application] }
data "aws_guardduty_finding_ids" "application" { detector_id = aws_guardduty_detector.application.id }
resource "aws_s3_object" "trusted" {
  bucket  = aws_s3_bucket.evidence.id
  key     = "lists/trusted-${var.revision}.txt"
  content = var.revision == "initial" ? "192.0.2.0/24\n" : "198.51.100.0/24\n"
}
resource "aws_s3_object" "threats" {
  bucket  = aws_s3_bucket.evidence.id
  key     = "lists/threats.txt"
  content = "127.0.0.0/8\n"
}
resource "aws_guardduty_ipset" "application" {
  name        = var.name
  detector_id = aws_guardduty_detector.application.id
  format      = "TXT"
  location    = "https://s3.amazonaws.com/${aws_s3_object.trusted.bucket}/${aws_s3_object.trusted.key}"
  activate    = true
  tags        = local.tags
}
resource "aws_guardduty_threatintelset" "application" {
  name        = var.name
  detector_id = aws_guardduty_detector.application.id
  format      = "TXT"
  location    = "https://s3.amazonaws.com/${aws_s3_object.threats.bucket}/${aws_s3_object.threats.key}"
  activate    = true
  tags        = local.tags
}
resource "aws_kms_key" "guardduty" {
  description = var.revision
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Principal = { AWS = "arn:aws:iam::738492615083:root" }, Action = "kms:*", Resource = "*" },
    { Effect = "Allow", Principal = { Service = "guardduty.amazonaws.com" }, Action = ["kms:GenerateDataKey"], Resource = "*" }
  ] })
}
resource "aws_s3_bucket_policy" "guardduty" {
  bucket = aws_s3_bucket.signing.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Principal = { Service = "guardduty.amazonaws.com" }, Action = ["s3:GetBucketLocation", "s3:GetBucketAcl"], Resource = aws_s3_bucket.signing.arn },
    { Effect = "Allow", Principal = { Service = "guardduty.amazonaws.com" }, Action = "s3:PutObject", Resource = "${aws_s3_bucket.signing.arn}/*" }
  ] })
}
resource "aws_guardduty_publishing_destination" "application" {
  detector_id     = aws_guardduty_detector.application.id
  destination_arn = aws_s3_bucket.signing.arn
  kms_key_arn     = aws_kms_key.guardduty.arn
  depends_on      = [aws_s3_bucket_policy.guardduty]
}

resource "aws_wafv2_ip_set" "application" {
  name               = var.name
  description        = var.revision
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["192.0.2.0/24"]
  tags               = local.tags
}
resource "aws_wafv2_web_acl" "application" {
  name        = var.name
  description = var.revision
  scope       = "REGIONAL"
  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-acl"
    sampled_requests_enabled   = true
  }
  rule {
    name     = "blocked-header"
    priority = 1
    action {
      block {}
    }
    statement {
      byte_match_statement {
        positional_constraint = "EXACTLY"
        search_string         = "block"
        field_to_match {
          single_header { name = "x-fixture" }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-blocked"
      sampled_requests_enabled   = true
    }
  }
  rule {
    name     = "blocked-ip"
    priority = 2
    action {
      block {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.application.arn
        ip_set_forwarded_ip_config {
          header_name       = "x-client-ip"
          position          = "FIRST"
          fallback_behavior = "NO_MATCH"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-ip"
      sampled_requests_enabled   = true
    }
  }
}
data "aws_wafv2_ip_set" "application" {
  name  = aws_wafv2_ip_set.application.name
  scope = "REGIONAL"
}
data "aws_wafv2_web_acl" "application" {
  name  = aws_wafv2_web_acl.application.name
  scope = "REGIONAL"
}
resource "aws_api_gateway_rest_api" "consumer" { name = "${var.name}-consumer" }
resource "aws_api_gateway_method" "consumer" {
  rest_api_id   = aws_api_gateway_rest_api.consumer.id
  resource_id   = aws_api_gateway_rest_api.consumer.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}
resource "aws_api_gateway_integration" "consumer" {
  rest_api_id             = aws_api_gateway_rest_api.consumer.id
  resource_id             = aws_api_gateway_rest_api.consumer.root_resource_id
  http_method             = aws_api_gateway_method.consumer.http_method
  integration_http_method = "GET"
  type                    = "HTTP_PROXY"
  uri                     = var.target_url
}
resource "aws_api_gateway_deployment" "consumer" {
  rest_api_id = aws_api_gateway_rest_api.consumer.id
  depends_on  = [aws_api_gateway_integration.consumer]
}
resource "aws_api_gateway_stage" "consumer" {
  rest_api_id   = aws_api_gateway_rest_api.consumer.id
  deployment_id = aws_api_gateway_deployment.consumer.id
  stage_name    = "live"
}
resource "aws_wafv2_web_acl_association" "consumer" {
  resource_arn = aws_api_gateway_stage.consumer.arn
  web_acl_arn  = aws_wafv2_web_acl.application.arn
}

resource "aws_xray_group" "application" {
  group_name        = var.name
  filter_expression = "service(\"${var.name}\")"
  tags              = local.tags
}
resource "aws_xray_sampling_rule" "application" {
  rule_name      = var.name
  priority       = 1
  version        = 1
  reservoir_size = 1
  fixed_rate     = var.revision == "initial" ? 0.5 : 1.0
  resource_arn   = "*"
  service_name   = var.name
  service_type   = "*"
  host           = "*"
  http_method    = "*"
  url_path       = "*"
  tags           = local.tags
}
resource "aws_xray_resource_policy" "application" {
  policy_name = var.name
  policy_document = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "events.amazonaws.com" },
    Action = "xray:PutTraceSegments", Resource = "*"
  }] })
}

resource "aws_ssm_parameter" "application" {
  for_each    = toset(["String", "StringList", "SecureString"])
  name        = "/${var.name}/${each.key}"
  type        = each.key
  value       = each.key == "StringList" ? "${var.revision},bytes" : var.revision
  description = var.revision
  tier        = "Standard"
  tags        = local.tags
}
data "aws_ssm_parameter" "application" { name = aws_ssm_parameter.application["String"].name }
data "aws_ssm_parameters_by_path" "application" { path = "/${var.name}/" }
resource "aws_ssm_service_setting" "application" {
  setting_id    = "arn:aws:ssm:us-east-1:738492615083:servicesetting/ssm/parameter-store/default-parameter-tier"
  setting_value = var.revision == "initial" ? "Standard" : "Advanced"
}
resource "aws_ssm_document" "application" {
  name            = var.name
  document_type   = "Command"
  document_format = "JSON"
  content = jsonencode({ schemaVersion = "2.2", description = var.revision, mainSteps = [{
    action = "aws:runShellScript", name = "consumer", inputs = { runCommand = ["printf '${var.revision}\\n'"] }
  }] })
  tags = local.tags
}
data "aws_ssm_document" "application" { name = aws_ssm_document.application.name }
data "aws_ssm_instances" "application" {}

resource "aws_acm_certificate" "application" {
  certificate_body = var.certificate
  private_key      = var.private_key
  tags             = local.tags
}
data "aws_acm_certificate" "application" {
  domain      = "${var.name}.example.test"
  statuses    = ["ISSUED"]
  types       = ["IMPORTED"]
  most_recent = true
  depends_on  = [aws_acm_certificate.application]
}
resource "aws_route53_zone" "application" { name = "${var.name}.example.test" }
resource "aws_acm_certificate" "requested" {
  domain_name       = "tls.${var.name}.example.test"
  validation_method = "DNS"
  options {
    export                                      = "ENABLED"
    certificate_transparency_logging_preference = var.revision == "initial" ? "ENABLED" : "DISABLED"
  }
  tags = local.tags
}
resource "aws_route53_record" "validation" {
  for_each = {
    for validation in aws_acm_certificate.requested.domain_validation_options :
    validation.domain_name => validation
  }
  zone_id = aws_route53_zone.application.zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 60
}
resource "aws_acm_certificate_validation" "requested" {
  certificate_arn         = aws_acm_certificate.requested.arn
  validation_record_fqdns = [for record in aws_route53_record.validation : record.fqdn]
}
resource "aws_s3_bucket" "signing" {
  bucket        = "${var.name}-signing"
  force_destroy = true
}
resource "aws_s3_bucket_versioning" "signing" {
  bucket = aws_s3_bucket.signing.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_object" "signing" {
  bucket     = aws_s3_bucket.signing.id
  key        = "source.zip"
  source     = var.source_zip
  depends_on = [aws_s3_bucket_versioning.signing]
}
resource "aws_signer_signing_profile" "application" {
  name        = replace(var.name, "-", "_")
  platform_id = "AWSLambda-SHA384-ECDSA"
  tags        = local.tags
}
data "aws_signer_signing_profile" "application" { name = aws_signer_signing_profile.application.name }
resource "aws_signer_signing_job" "application" {
  profile_name = aws_signer_signing_profile.application.name
  source {
    s3 {
      bucket  = aws_s3_bucket.signing.id
      key     = aws_s3_object.signing.key
      version = aws_s3_object.signing.version_id
    }
  }
  destination {
    s3 {
      bucket = aws_s3_bucket.signing.id
      prefix = "signed/"
    }
  }
}
data "aws_signer_signing_job" "application" { job_id = aws_signer_signing_job.application.job_id }

output "application" {
  value = {
    name                   = var.name, revision = var.revision,
    log_group              = aws_cloudwatch_log_group.application.name, log_group_arn = aws_cloudwatch_log_group.application.arn,
    log_stream             = aws_cloudwatch_log_stream.application.name, metric_alarm = aws_cloudwatch_metric_alarm.events.alarm_name,
    composite_alarm        = aws_cloudwatch_composite_alarm.events.alarm_name, dashboard = aws_cloudwatch_dashboard.application.id,
    bucket                 = aws_s3_bucket.evidence.id, trail = aws_cloudtrail.application.id,
    recorder               = aws_config_configuration_recorder.application.name, channel = aws_config_delivery_channel.application.name,
    config_rule            = aws_config_config_rule.tags.name, aggregator = aws_config_configuration_aggregator.local.name,
    detector               = aws_guardduty_detector.application.id,
    trusted_list           = aws_guardduty_ipset.application.id, threat_list = aws_guardduty_threatintelset.application.id,
    publishing_destination = aws_guardduty_publishing_destination.application.id,
    acl_id                 = aws_wafv2_web_acl.application.id, acl_arn = aws_wafv2_web_acl.application.arn,
    ip_set_id              = aws_wafv2_ip_set.application.id, api_id = aws_api_gateway_rest_api.consumer.id,
    xray_group             = aws_xray_group.application.arn, sampling_rule = aws_xray_sampling_rule.application.rule_name,
    parameters             = { for kind, parameter in aws_ssm_parameter.application : kind => parameter.name },
    document               = aws_ssm_document.application.name, certificate = aws_acm_certificate.application.arn,
    requested_certificate  = aws_acm_certificate_validation.requested.certificate_arn,
    profile                = aws_signer_signing_profile.application.name, signing_job = aws_signer_signing_job.application.job_id,
    signing_bucket         = aws_s3_bucket.signing.id,
    signed_object          = aws_signer_signing_job.application.signed_object
  }
}
