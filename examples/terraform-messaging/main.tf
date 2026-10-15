terraform {
  required_version = ">= 1.15.9, < 2.0.0"
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
    error_message = "Use an explicit IPv4 loopback HTTP endpoint."
  }
}
variable "name" { type = string }
variable "revision" {
  type    = string
  default = "v1"
}
variable "schedule_times" { type = map(string) }
variable "receiver_endpoint" { type = string }
variable "receiver_token" {
  type      = string
  sensitive = true
}

provider "aws" {
  region     = "us-east-1"
  access_key = "test"
  secret_key = "test"
  endpoints {
    appconfig   = var.endpoint
    eventbridge = var.endpoint
    iam         = var.endpoint
    pipes       = var.endpoint
    scheduler   = var.endpoint
    sns         = var.endpoint
    sqs         = var.endpoint
    sts         = var.endpoint
  }
}

data "aws_caller_identity" "current" {}
locals {
  tags = { Fixture = var.name, Revision = var.revision }
}

resource "aws_sqs_queue" "messages" {
  for_each                   = toset(["sns", "events", "source", "pipe", "scheduler", "dlq", "extensions"])
  name                       = "${var.name}-${each.key}"
  visibility_timeout_seconds = 30
  receive_wait_time_seconds  = 0
  message_retention_seconds  = 3600
  tags                       = local.tags
}
resource "aws_sqs_queue_redrive_policy" "source" {
  queue_url = aws_sqs_queue.messages["source"].url
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.messages["dlq"].arn
    maxReceiveCount    = 3
  })
}
resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  queue_url = aws_sqs_queue.messages["dlq"].url
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.messages["source"].arn]
  })
}

resource "aws_sns_topic" "notifications" {
  name         = "${var.name}-notifications"
  display_name = "Messaging ${var.revision}"
  tags         = local.tags
}
resource "aws_sns_topic_policy" "notifications" {
  arn = aws_sns_topic.notifications.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountPublisher"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = ["sns:Publish", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:Subscribe", "sns:DeleteTopic"]
      Resource  = aws_sns_topic.notifications.arn
    }]
  })
}
resource "aws_sqs_queue_policy" "sns" {
  queue_url = aws_sqs_queue.messages["sns"].url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TopicDelivery"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.messages["sns"].arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.notifications.arn } }
    }]
  })
}
resource "aws_sns_topic_subscription" "queue" {
  topic_arn            = aws_sns_topic.notifications.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.messages["sns"].arn
  raw_message_delivery = true
  filter_policy        = jsonencode({ revision = [var.revision] })
  filter_policy_scope  = "MessageAttributes"
  depends_on           = [aws_sqs_queue_policy.sns, aws_sns_topic_policy.notifications]
}

resource "aws_cloudwatch_event_bus" "messages" {
  name        = "${var.name}-bus"
  description = "Messaging ${var.revision}"
  tags        = local.tags
}
resource "aws_cloudwatch_event_bus_policy" "messages" {
  event_bus_name = aws_cloudwatch_event_bus.messages.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountEvents"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "events:PutEvents"
      Resource  = aws_cloudwatch_event_bus.messages.arn
    }]
  })
}
# Separate permission ownership uses a separate bus. It must not compete with
# the full-policy resource for the same native policy document.
resource "aws_cloudwatch_event_bus" "permissions" {
  name = "${var.name}-permissions"
  tags = local.tags
}
resource "aws_cloudwatch_event_permission" "account" {
  event_bus_name = aws_cloudwatch_event_bus.permissions.name
  statement_id   = "AccountEvents"
  principal      = data.aws_caller_identity.current.account_id
  action         = "events:PutEvents"
}
resource "aws_cloudwatch_event_rule" "messages" {
  name           = "${var.name}-rule"
  event_bus_name = aws_cloudwatch_event_bus.messages.name
  description   = "Messaging ${var.revision}"
  event_pattern = jsonencode({
    source = ["stackd.terraform.messaging"]
    detail = { revision = [var.revision] }
  })
  tags = local.tags
}
resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.messages["events"].url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "RuleDelivery"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.messages["events"].arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.messages.arn } }
    }]
  })
}
resource "aws_cloudwatch_event_target" "queue" {
  rule           = aws_cloudwatch_event_rule.messages.name
  event_bus_name = aws_cloudwatch_event_bus.messages.name
  target_id      = "queue"
  arn            = aws_sqs_queue.messages["events"].arn
  input_path     = "$.detail"
  depends_on     = [aws_sqs_queue_policy.events]
}
resource "aws_cloudwatch_event_archive" "messages" {
  name             = "${var.name}-archive"
  event_source_arn = aws_cloudwatch_event_bus.messages.arn
  description     = "Messaging ${var.revision}"
  retention_days  = 1
  event_pattern   = aws_cloudwatch_event_rule.messages.event_pattern
}

resource "aws_iam_service_linked_role" "events" {
  aws_service_name = "apidestinations.events.amazonaws.com"
  description      = "Messaging ${var.revision}"
}
resource "aws_cloudwatch_event_connection" "messages" {
  name               = "${var.name}-connection"
  description        = "Messaging ${var.revision}"
  authorization_type = "API_KEY"
  auth_parameters {
    api_key {
      key   = "X-Fixture-Token"
      value = var.receiver_token
    }
  }
  depends_on = [aws_iam_service_linked_role.events]
}
resource "aws_cloudwatch_event_api_destination" "messages" {
  name                             = "${var.name}-destination"
  description                      = "Messaging ${var.revision}"
  connection_arn                   = aws_cloudwatch_event_connection.messages.arn
  invocation_endpoint              = "${var.receiver_endpoint}/delivery"
  http_method                      = "POST"
  invocation_rate_limit_per_second = 10
}
resource "aws_iam_role" "events" {
  name = "${var.name}-events"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.messages.arn } }
    }]
  })
}
resource "aws_iam_role_policy" "events" {
  role = aws_iam_role.events.id
  name = "delivery"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Action = "events:InvokeApiDestination"
      Resource = aws_cloudwatch_event_api_destination.messages.arn
    }]
  })
}
resource "aws_cloudwatch_event_target" "https" {
  rule           = aws_cloudwatch_event_rule.messages.name
  event_bus_name = aws_cloudwatch_event_bus.messages.name
  target_id      = "https"
  arn            = aws_cloudwatch_event_api_destination.messages.arn
  role_arn       = aws_iam_role.events.arn
  input_path     = "$.detail"
  http_target { header_parameters = { X-Revision = var.revision } }
  depends_on = [aws_iam_role_policy.events]
}

resource "aws_iam_role" "pipes" {
  name = "${var.name}-pipes"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pipes.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}
resource "aws_iam_role_policy" "pipes" {
  role = aws_iam_role.pipes.id
  name = "delivery"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.messages["source"].arn },
      { Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.messages["pipe"].arn }
    ]
  })
}
resource "aws_pipes_pipe" "messages" {
  name        = "${var.name}-pipe"
  description = "Messaging ${var.revision}"
  role_arn    = aws_iam_role.pipes.arn
  source      = aws_sqs_queue.messages["source"].arn
  target      = aws_sqs_queue.messages["pipe"].arn
  source_parameters {
    sqs_queue_parameters { batch_size = 1 }
  }
  target_parameters {
    input_template = "{\"kind\":\"pipe\",\"revision\":<$.body.revision>,\"marker\":<$.body.marker>}"
  }
  tags       = local.tags
  depends_on = [aws_iam_role_policy.pipes, aws_sqs_queue_redrive_policy.source]
}

resource "aws_scheduler_schedule_group" "messages" {
  name = "${var.name}-group"
  tags = local.tags
}
resource "aws_iam_role" "scheduler" {
  name = "${var.name}-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { ArnEquals = { "aws:SourceArn" = aws_scheduler_schedule_group.messages.arn } }
    }]
  })
}
resource "aws_iam_role_policy" "scheduler" {
  role = aws_iam_role.scheduler.id
  name = "delivery"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sqs:SendMessage"
      Resource = [aws_sqs_queue.messages["scheduler"].arn, aws_sqs_queue.messages["dlq"].arn]
    }]
  })
}
resource "aws_scheduler_schedule" "messages" {
  for_each                    = var.schedule_times
  name                        = "${var.name}-${each.key}"
  group_name                  = aws_scheduler_schedule_group.messages.name
  description                 = "Messaging ${var.revision}"
  schedule_expression         = "at(${each.value})"
  schedule_expression_timezone = "UTC"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_sqs_queue.messages["scheduler"].arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ kind = "scheduler", stage = each.key, revision = var.revision })
    retry_policy {
      maximum_retry_attempts       = 0
      maximum_event_age_in_seconds = 60
    }
    dead_letter_config { arn = aws_sqs_queue.messages["dlq"].arn }
  }
  depends_on = [aws_iam_role_policy.scheduler]
}

resource "aws_appconfig_application" "messages" {
  name        = "${var.name}-application"
  description = "Messaging ${var.revision}"
  tags        = local.tags
}
resource "aws_appconfig_environment" "messages" {
  application_id = aws_appconfig_application.messages.id
  name           = "local"
  description    = "Messaging ${var.revision}"
  tags           = local.tags
}
resource "aws_appconfig_configuration_profile" "messages" {
  application_id = aws_appconfig_application.messages.id
  name           = "messages"
  description    = "Messaging ${var.revision}"
  location_uri   = "hosted"
  type           = "AWS.Freeform"
  validator {
    type = "JSON_SCHEMA"
    content = jsonencode({
      type = "object", required = ["revision", "message", "enabled"]
      properties = { revision = { type = "string" }, message = { type = "string" }, enabled = { type = "boolean" } }
      additionalProperties = false
    })
  }
  tags = local.tags
}
resource "aws_appconfig_deployment_strategy" "messages" {
  name                           = "${var.name}-strategy"
  description                    = "Messaging ${var.revision}"
  deployment_duration_in_minutes = 0
  final_bake_time_in_minutes      = 0
  growth_factor                  = 100
  growth_type                    = "LINEAR"
  replicate_to                   = "NONE"
  tags                           = local.tags
}
resource "aws_iam_role" "appconfig" {
  name = "${var.name}-appconfig"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "appconfig.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "appconfig" {
  role = aws_iam_role.appconfig.id
  name = "delivery"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.messages["extensions"].arn }]
  })
}
resource "aws_appconfig_extension" "messages" {
  name        = "${var.name}-extension"
  description = "Publish actual deployment completion"
  action_point {
    point = "ON_DEPLOYMENT_COMPLETE"
    action {
      name     = "QueueNotification"
      uri      = aws_sqs_queue.messages["extensions"].arn
      role_arn = aws_iam_role.appconfig.arn
    }
  }
  tags       = { Fixture = var.name }
  depends_on = [aws_iam_role_policy.appconfig]
}
resource "aws_appconfig_extension_association" "messages" {
  resource_arn  = aws_appconfig_environment.messages.arn
  extension_arn = aws_appconfig_extension.messages.arn
}
resource "aws_appconfig_hosted_configuration_version" "messages" {
  application_id           = aws_appconfig_application.messages.id
  configuration_profile_id = aws_appconfig_configuration_profile.messages.configuration_profile_id
  description              = "Messaging ${var.revision}"
  content_type             = "application/json"
  content                  = jsonencode({ revision = var.revision, message = "Real AppConfig value", enabled = true })
}
resource "aws_appconfig_deployment" "messages" {
  application_id           = aws_appconfig_application.messages.id
  environment_id           = aws_appconfig_environment.messages.environment_id
  configuration_profile_id = aws_appconfig_configuration_profile.messages.configuration_profile_id
  configuration_version    = aws_appconfig_hosted_configuration_version.messages.version_number
  deployment_strategy_id   = aws_appconfig_deployment_strategy.messages.id
  description              = "Messaging ${var.revision}"
  tags                     = local.tags
  depends_on               = [aws_appconfig_extension_association.messages]
}

data "aws_sns_topic" "messages" { name = aws_sns_topic.notifications.name }
data "aws_sqs_queue" "messages" { name = aws_sqs_queue.messages["sns"].name }
data "aws_sqs_queues" "messages" {
  queue_name_prefix = var.name
  depends_on        = [aws_sqs_queue.messages]
}
data "aws_cloudwatch_event_bus" "messages" { name = aws_cloudwatch_event_bus.messages.name }
data "aws_cloudwatch_event_connection" "messages" { name = aws_cloudwatch_event_connection.messages.name }
data "aws_cloudwatch_event_buses" "messages" {
  name_prefix = var.name
  depends_on  = [aws_cloudwatch_event_bus.messages, aws_cloudwatch_event_bus.permissions]
}
data "aws_appconfig_application" "messages" { name = aws_appconfig_application.messages.name }
data "aws_appconfig_environment" "messages" {
  application_id = aws_appconfig_application.messages.id
  environment_id = aws_appconfig_environment.messages.environment_id
}
data "aws_appconfig_environments" "messages" {
  application_id = aws_appconfig_application.messages.id
  depends_on     = [aws_appconfig_environment.messages]
}
data "aws_appconfig_configuration_profile" "messages" {
  application_id           = aws_appconfig_application.messages.id
  configuration_profile_id = aws_appconfig_configuration_profile.messages.configuration_profile_id
}
data "aws_appconfig_configuration_profiles" "messages" {
  application_id = aws_appconfig_application.messages.id
  depends_on     = [aws_appconfig_configuration_profile.messages]
}

output "application" {
  value = {
    name                  = var.name
    revision              = var.revision
    queues                = { for key, queue in aws_sqs_queue.messages : key => { url = queue.url, arn = queue.arn } }
    topic_arn             = aws_sns_topic.notifications.arn
    subscription_arn      = aws_sns_topic_subscription.queue.arn
    bus_name              = aws_cloudwatch_event_bus.messages.name
    permission_bus_name   = aws_cloudwatch_event_bus.permissions.name
    rule_name             = aws_cloudwatch_event_rule.messages.name
    archive_name          = aws_cloudwatch_event_archive.messages.name
    connection_name       = aws_cloudwatch_event_connection.messages.name
    destination_name      = aws_cloudwatch_event_api_destination.messages.name
    connection_secret_arn = data.aws_cloudwatch_event_connection.messages.secret_arn
    linked_role_name      = aws_iam_service_linked_role.events.name
    pipe_name             = aws_pipes_pipe.messages.name
    scheduler_group       = aws_scheduler_schedule_group.messages.name
    scheduler_role        = aws_iam_role.scheduler.name
    schedules             = { for key, schedule in aws_scheduler_schedule.messages : key => schedule.name }
    application_id        = aws_appconfig_application.messages.id
    environment_id        = aws_appconfig_environment.messages.environment_id
    profile_id            = aws_appconfig_configuration_profile.messages.configuration_profile_id
    strategy_id           = aws_appconfig_deployment_strategy.messages.id
    extension_id          = aws_appconfig_extension.messages.id
    association_id        = aws_appconfig_extension_association.messages.id
    deployment_number     = aws_appconfig_deployment.messages.deployment_number
    version_number        = aws_appconfig_hosted_configuration_version.messages.version_number
    discovered_topic      = data.aws_sns_topic.messages.arn
    discovered_queue      = data.aws_sqs_queue.messages.url
    discovered_queues     = data.aws_sqs_queues.messages.queue_urls
    discovered_bus        = data.aws_cloudwatch_event_bus.messages.arn
    discovered_buses      = data.aws_cloudwatch_event_buses.messages.event_buses
    discovered_app        = data.aws_appconfig_application.messages.id
    discovered_env        = data.aws_appconfig_environment.messages.environment_id
    discovered_envs       = data.aws_appconfig_environments.messages.environment_ids
    discovered_profile    = data.aws_appconfig_configuration_profile.messages.configuration_profile_id
    discovered_profiles   = data.aws_appconfig_configuration_profiles.messages.configuration_profile_ids
  }
}
