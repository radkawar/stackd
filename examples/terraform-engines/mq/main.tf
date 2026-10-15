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

variable "name" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.name))
    error_message = "Use at most 20 lowercase letters, digits or hyphens so owned names stay within 28 characters."
  }
}

variable "revision" {
  type    = string
  default = "v1"
  validation {
    condition     = contains(["v1", "v2"], var.revision)
    error_message = "The native lifecycle has revisions v1 and v2."
  }
}

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
    iam = var.endpoint
    mq  = var.endpoint
    sts = var.endpoint
  }
}

locals {
  queue = "${var.name}-payload"
}

data "aws_mq_broker_engine_types" "installed" {
  engine_type = "ACTIVEMQ"
}

data "aws_mq_broker_instance_type_offerings" "installed" {
  engine_type        = "ACTIVEMQ"
  host_instance_type = "mq.t3.micro"
}

# Provider6.68.0's RabbitMQ initial read invokes the ActiveMQ-only DescribeUser
# API. This fixture uses the real ActiveMQ owner instead of inventing RabbitMQ
# user APIs or hiding the resulting drift with ignore_changes.
resource "aws_mq_configuration" "native" {
  name                    = "${var.name}-config"
  engine_type             = "ACTIVEMQ"
  engine_version          = "5.18"
  authentication_strategy = "SIMPLE"
  description             = "Native Terraform lifecycle ${var.revision}"
  data = <<-XML
    <broker xmlns="http://activemq.apache.org/schema/core" advisorySupport="false" populateJMSXUserID="${var.revision == "v2" ? "true" : "false"}">
      <destinations>
        <queue physicalName="${local.queue}"/>
      </destinations>
    </broker>
  XML
  tags = {
    Fixture  = var.name
    Revision = var.revision
  }
}

resource "aws_mq_broker" "native" {
  broker_name                = var.name
  engine_type                = "ActiveMQ"
  engine_version             = "5.18"
  host_instance_type         = "mq.t3.micro"
  deployment_mode            = "SINGLE_INSTANCE"
  authentication_strategy    = "SIMPLE"
  publicly_accessible        = true
  auto_minor_version_upgrade = false
  apply_immediately          = true

  configuration {
    id       = aws_mq_configuration.native.id
    revision = aws_mq_configuration.native.latest_revision
  }

  user {
    username         = "writer"
    password         = var.password
    groups           = ["clients"]
    console_access   = false
    replication_user = false
  }

  logs {
    general = false
    audit   = "false"
  }

  tags = {
    Fixture  = var.name
    Revision = var.revision
  }
}

data "aws_mq_broker" "by_id" {
  broker_id  = aws_mq_broker.native.id
  depends_on = [aws_mq_broker.native]
}

data "aws_mq_broker" "by_name" {
  broker_name = aws_mq_broker.native.broker_name
  depends_on  = [aws_mq_broker.native]
}

output "application" {
  value = {
    broker_id              = aws_mq_broker.native.id
    broker_arn             = aws_mq_broker.native.arn
    broker_name            = aws_mq_broker.native.broker_name
    discovered_by_id        = data.aws_mq_broker.by_id.id
    discovered_by_name      = data.aws_mq_broker.by_name.id
    native_endpoint        = data.aws_mq_broker.by_id.instances[0].endpoints[0]
    console_url            = data.aws_mq_broker.by_id.instances[0].console_url
    configuration_id       = aws_mq_configuration.native.id
    configuration_revision = aws_mq_configuration.native.latest_revision
    queue                  = local.queue
    revision               = var.revision
    engine_type            = data.aws_mq_broker.by_id.engine_type
    engine_version         = data.aws_mq_broker.by_id.engine_version
    catalogue_engine_types = data.aws_mq_broker_engine_types.installed.broker_engine_types
    catalogue_instances    = data.aws_mq_broker_instance_type_offerings.installed.broker_instance_options
  }
}

output "imports" {
  value = {
    "aws_mq_broker.native"        = aws_mq_broker.native.id
    "aws_mq_configuration.native" = aws_mq_configuration.native.id
  }
}
