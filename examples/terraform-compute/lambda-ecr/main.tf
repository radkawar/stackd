terraform {
  required_version = ">= 1.15.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}

variable "endpoint" { type = string }
variable "name" { type = string }
variable "architecture" {
  type    = string
  default = "x86_64"
}
variable "revision" {
  type    = string
  default = "first"
}
variable "include_image" {
  type    = bool
  default = false
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
  endpoints {
    lambda         = var.endpoint
    ecr            = var.endpoint
    iam            = var.endpoint
    sts            = var.endpoint
    cloudwatchlogs = var.endpoint
  }
}

# The role and log group are owned prerequisites. Data-source readback remains
# part of the current-provider lifecycle; no role is imported from another run.
resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_cloudwatch_log_group" "application" {
  name = "/aws/lambda/${var.name}"
}
resource "aws_iam_role_policy" "execution" {
  name = "runtime-logs"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.application.arn}:*" }]
  })
}
data "aws_iam_role" "execution" { name = aws_iam_role.execution.name }

resource "aws_lambda_layer_version" "library" {
  layer_name               = "${var.name}-library"
  filename                 = "${path.module}/layer.zip"
  source_code_hash         = filebase64sha256("${path.module}/layer.zip")
  compatible_runtimes      = ["python3.12"]
  compatible_architectures = [var.architecture]
  description              = "Real Python import from /opt/python"
  license_info             = "MIT"
}

resource "aws_lambda_layer_version_permission" "library" {
  layer_name     = aws_lambda_layer_version.library.layer_name
  version_number = aws_lambda_layer_version.library.version
  statement_id   = "FixtureLayerRead"
  action         = "lambda:GetLayerVersion"
  principal      = "738492615083"
}

resource "aws_lambda_function" "application" {
  depends_on                     = [aws_iam_role_policy.execution]
  function_name                  = var.name
  filename                       = "${path.module}/function.zip"
  source_code_hash               = filebase64sha256("${path.module}/function.zip")
  role                           = data.aws_iam_role.execution.arn
  runtime                        = "python3.12"
  handler                        = "handler.invoke"
  architectures                  = [var.architecture]
  publish                        = true
  timeout                        = 20
  memory_size                    = var.revision == "first" ? 256 : 384
  description                    = "Native Lambda ZIP ${var.revision}"
  layers                         = [aws_lambda_layer_version.library.arn]
  reserved_concurrent_executions = 10
  environment {
    variables = { FIXTURE_REVISION = var.revision }
  }
  ephemeral_storage { size = 512 }
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.application.name
  }
  tracing_config { mode = "PassThrough" }
  tags = { Fixture = var.name, Revision = var.revision }
}

resource "aws_lambda_alias" "live" {
  name             = "live"
  function_name    = aws_lambda_function.application.function_name
  function_version = aws_lambda_function.application.version
  description      = "Consumer selection ${var.revision}"
}

resource "aws_lambda_function_recursion_config" "application" {
  function_name  = aws_lambda_function.application.function_name
  recursive_loop = var.revision == "first" ? "Terminate" : "Allow"
}

resource "aws_lambda_runtime_management_config" "application" {
  function_name     = aws_lambda_function.application.function_name
  update_runtime_on = var.revision == "first" ? "Auto" : "FunctionUpdate"
}

resource "aws_lambda_function_event_invoke_config" "application" {
  function_name                = aws_lambda_function.application.function_name
  qualifier                    = aws_lambda_alias.live.name
  maximum_event_age_in_seconds = var.revision == "first" ? 60 : 120
  maximum_retry_attempts       = var.revision == "first" ? 0 : 1
}

resource "aws_lambda_function_url" "application" {
  function_name      = aws_lambda_function.application.function_name
  qualifier          = aws_lambda_alias.live.name
  authorization_type = "NONE"
  invoke_mode        = "BUFFERED"
  cors {
    allow_origins = ["https://fixture.example.invalid"]
    allow_methods = ["POST"]
    allow_headers = ["content-type"]
    max_age       = 60
  }
}

resource "aws_lambda_permission" "url" {
  statement_id           = "FixtureURL"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.application.function_name
  qualifier              = aws_lambda_alias.live.name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "url_invoke" {
  statement_id             = "FixtureURLInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.application.function_name
  qualifier                = aws_lambda_alias.live.name
  principal                = "*"
  invoked_via_function_url = true
}

resource "aws_lambda_invocation" "application" {
  function_name = aws_lambda_function.application.function_name
  qualifier     = aws_lambda_alias.live.name
  input         = jsonencode({ message = "terraform-resource", revision = var.revision })
  triggers      = { revision = var.revision, version = aws_lambda_function.application.version }
}

data "aws_lambda_function" "application" {
  function_name = aws_lambda_function.application.function_name
  depends_on    = [aws_lambda_function.application]
}
data "aws_lambda_alias" "live" {
  function_name = aws_lambda_function.application.function_name
  name          = aws_lambda_alias.live.name
  depends_on    = [aws_lambda_alias.live]
}
data "aws_lambda_functions" "all" { depends_on = [aws_lambda_function.application] }
data "aws_lambda_function_url" "application" {
  function_name = aws_lambda_function.application.function_name
  qualifier     = aws_lambda_alias.live.name
  depends_on    = [aws_lambda_function_url.application]
}
data "aws_lambda_layer_version" "library" {
  layer_version_arn = aws_lambda_layer_version.library.arn
}
data "aws_lambda_invocation" "application" {
  function_name = aws_lambda_function.application.function_name
  qualifier     = aws_lambda_alias.live.name
  input         = jsonencode({ message = "terraform-data", revision = var.revision })
  depends_on    = [aws_lambda_alias.live]
}

resource "aws_ecr_repository" "application" {
  name                 = "${var.name}/application"
  force_delete         = true
  image_tag_mutability = var.revision == "first" ? "IMMUTABLE_WITH_EXCLUSION" : "MUTABLE"
  dynamic "image_tag_mutability_exclusion_filter" {
    for_each = var.revision == "first" ? ["dev-*"] : []
    content {
      filter_type = "WILDCARD"
      filter      = image_tag_mutability_exclusion_filter.value
    }
  }
  image_scanning_configuration { scan_on_push = false }
  encryption_configuration { encryption_type = "AES256" }
  tags = { Fixture = var.name, Revision = var.revision }
}

resource "aws_ecr_repository_policy" "application" {
  repository = aws_ecr_repository.application.name
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid    = "FixtureRead", Effect = "Allow", Principal = { AWS = "arn:aws:iam::738492615083:root" },
    Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
  }] })
}

data "aws_ecr_lifecycle_policy_document" "application" {
  rule {
    priority    = 1
    description = "Retain real fixture images ${var.revision}"
    selection {
      tag_status   = "any"
      count_type   = "imageCountMoreThan"
      count_number = var.revision == "first" ? 100 : 101
    }
    action { type = "expire" }
  }
}
resource "aws_ecr_lifecycle_policy" "application" {
  repository = aws_ecr_repository.application.name
  policy     = data.aws_ecr_lifecycle_policy_document.application.json
}
data "aws_ecr_repository" "application" { name = aws_ecr_repository.application.name }
data "aws_ecr_repositories" "all" { depends_on = [aws_ecr_repository.application] }
data "aws_ecr_image" "application" {
  count           = var.include_image ? 1 : 0
  repository_name = aws_ecr_repository.application.name
  image_tag       = "dev-current"
}
data "aws_ecr_images" "application" {
  count           = var.include_image ? 1 : 0
  repository_name = aws_ecr_repository.application.name
}

output "application" {
  value = {
    function_name     = aws_lambda_function.application.function_name
    function_arn      = aws_lambda_function.application.arn
    version           = aws_lambda_function.application.version
    alias             = aws_lambda_alias.live.name
    function_url      = aws_lambda_function_url.application.function_url
    layer_arn         = aws_lambda_layer_version.library.arn
    layer_name        = aws_lambda_layer_version.library.layer_name
    layer_version     = tonumber(aws_lambda_layer_version.library.version)
    repository        = aws_ecr_repository.application.name
    repository_url    = aws_ecr_repository.application.repository_url
    image_digest      = var.include_image ? data.aws_ecr_image.application[0].image_digest : ""
    invocation_result = jsondecode(aws_lambda_invocation.application.result)
    data_result       = jsondecode(data.aws_lambda_invocation.application.result)
    revision          = var.revision
  }
}
