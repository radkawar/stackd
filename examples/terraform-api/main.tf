terraform {
  required_version = "= 1.15.9"
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
    condition     = can(regex("^https?://127\\.0\\.0\\.1:[0-9]+$", var.endpoint))
    error_message = "Use the owned IPv4 loopback endpoint."
  }
}
variable "name" { type = string }
variable "revision" { type = string }
variable "function_arn" { type = string }
variable "ca_file" { type = string }
variable "certificate_arn" { type = string }

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  custom_ca_bundle            = var.ca_file
  endpoints {
    apigateway   = var.endpoint
    apigatewayv2 = var.endpoint
    appsync      = var.endpoint
    route53      = var.endpoint
    iam          = var.endpoint
    lambda       = var.endpoint
    sts          = var.endpoint
  }
}

resource "aws_api_gateway_rest_api" "proof" {
  name        = var.name
  description = var.revision
  endpoint_configuration { types = ["REGIONAL"] }
  tags = { Revision = var.revision }
}
resource "aws_api_gateway_resource" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  parent_id   = aws_api_gateway_rest_api.proof.root_resource_id
  path_part   = "proof"
}
resource "aws_api_gateway_method" "proof" {
  rest_api_id   = aws_api_gateway_rest_api.proof.id
  resource_id   = aws_api_gateway_resource.proof.id
  http_method   = "GET"
  authorization = "NONE"
  api_key_required = true
  operation_name = var.revision
}
resource "aws_api_gateway_integration" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  resource_id = aws_api_gateway_resource.proof.id
  http_method = aws_api_gateway_method.proof.http_method
  type        = "MOCK"
  request_templates = { "application/json" = jsonencode({ statusCode = 200 }) }
}
resource "aws_api_gateway_method_response" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  resource_id = aws_api_gateway_resource.proof.id
  http_method = aws_api_gateway_method.proof.http_method
  status_code = "200"
  response_parameters = { "method.response.header.X-Revision" = true }
}
resource "aws_api_gateway_integration_response" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  resource_id = aws_api_gateway_resource.proof.id
  http_method = aws_api_gateway_method.proof.http_method
  status_code = aws_api_gateway_method_response.proof.status_code
  response_parameters = { "method.response.header.X-Revision" = "'${var.revision}'" }
  response_templates  = { "application/json" = jsonencode({ revision = var.revision }) }
  depends_on = [aws_api_gateway_integration.proof]
}
resource "aws_api_gateway_gateway_response" "proof" {
  rest_api_id   = aws_api_gateway_rest_api.proof.id
  response_type = "MISSING_AUTHENTICATION_TOKEN"
  status_code   = "404"
  response_templates = { "application/json" = jsonencode({ missing = var.revision }) }
}
resource "aws_api_gateway_gateway_response" "fallback" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  response_type = "DEFAULT_4XX"
  status_code = "418"
  response_templates = { "application/json" = jsonencode({ denied = var.revision }) }
}
resource "aws_api_gateway_deployment" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  triggers = { revision = var.revision }
  lifecycle { create_before_destroy = true }
  depends_on = [aws_api_gateway_integration_response.proof]
}
resource "aws_api_gateway_stage" "proof" {
  rest_api_id   = aws_api_gateway_rest_api.proof.id
  deployment_id = aws_api_gateway_deployment.proof.id
  stage_name    = "live"
  description   = var.revision
  variables     = { revision = var.revision }
  tags          = { Revision = var.revision }
}
resource "aws_api_gateway_api_key" "proof" {
  name    = var.name
  enabled = true
  tags    = { Revision = var.revision }
}
resource "aws_api_gateway_usage_plan" "proof" {
  name = var.name
  api_stages {
    api_id = aws_api_gateway_rest_api.proof.id
    stage  = aws_api_gateway_stage.proof.stage_name
  }
  quota_settings {
    limit = 1000
    period = "DAY"
  }
  tags = { Revision = var.revision }
}
resource "aws_api_gateway_usage_plan_key" "proof" {
  key_id = aws_api_gateway_api_key.proof.id
  key_type = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.proof.id
}

resource "aws_apigatewayv2_api" "proof" {
  name = var.name
  protocol_type = "HTTP"
  description = var.revision
  tags = { Revision = var.revision }
}
resource "aws_apigatewayv2_integration" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  integration_type = "AWS_PROXY"
  integration_uri = var.function_arn
  integration_method = "POST"
  payload_format_version = "2.0"
  description = var.revision
}
resource "aws_apigatewayv2_route" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  route_key = "POST /proof"
  target = "integrations/${aws_apigatewayv2_integration.proof.id}"
}
resource "aws_apigatewayv2_deployment" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  description = var.revision
  triggers = { revision = var.revision }
  lifecycle { create_before_destroy = true }
  depends_on = [aws_apigatewayv2_route.proof, aws_apigatewayv2_integration.proof]
}
resource "aws_apigatewayv2_stage" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  name = "live"
  deployment_id = aws_apigatewayv2_deployment.proof.id
  description = var.revision
  stage_variables = { revision = var.revision }
  tags = { Revision = var.revision }
}
resource "aws_apigatewayv2_domain_name" "proof" {
  domain_name = "${var.name}.test"
  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type = "REGIONAL"
    security_policy = "TLS_1_2"
  }
  tags = { Revision = var.revision }
}
resource "aws_apigatewayv2_api_mapping" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  domain_name = aws_apigatewayv2_domain_name.proof.id
  stage = aws_apigatewayv2_stage.proof.name
  api_mapping_key = var.revision
}

resource "aws_appsync_graphql_api" "proof" {
  name = var.name
  authentication_type = "API_KEY"
  schema = "type Query { proof(input: String!): String! }\nschema { query: Query }"
  tags = { Revision = var.revision }
}
resource "aws_appsync_api_key" "proof" {
  api_id = aws_appsync_graphql_api.proof.id
  description = var.revision
}
resource "aws_appsync_datasource" "proof" {
  api_id = aws_appsync_graphql_api.proof.id
  name = "proof"
  type = "NONE"
  description = var.revision
}
resource "aws_appsync_function" "proof" {
  api_id = aws_appsync_graphql_api.proof.id
  name = "proof"
  data_source = aws_appsync_datasource.proof.name
  runtime {
    name = "APPSYNC_JS"
    runtime_version = "1.0.0"
  }
  code = "export function request(ctx) { return {payload: ctx.args.input}; }\nexport function response(ctx) { return '${var.revision}:' + ctx.result; }"
}
resource "aws_appsync_resolver" "proof" {
  api_id = aws_appsync_graphql_api.proof.id
  type = "Query"
  field = "proof"
  kind = "PIPELINE"
  runtime {
    name = "APPSYNC_JS"
    runtime_version = "1.0.0"
  }
  code = "export function request(ctx) { return {}; }\nexport function response(ctx) { return ctx.prev.result; }"
  pipeline_config { functions = [aws_appsync_function.proof.function_id] }
}

resource "aws_route53_zone" "proof" {
  name = "${var.name}.test"
  comment = var.revision
  tags = { Revision = var.revision }
}
resource "aws_route53_record" "proof" {
  zone_id = aws_route53_zone.proof.zone_id
  name = "proof.${aws_route53_zone.proof.name}"
  type = "TXT"
  ttl = 30
  # The provider adds the outer DNS quotes for this resource type.
  records = [var.revision]
}
resource "aws_route53_record" "address" {
  zone_id = aws_route53_zone.proof.zone_id
  name = "address.${aws_route53_zone.proof.name}"
  type = "A"
  ttl = 30
  records = ["192.0.2.${var.revision == "first" ? 1 : 2}"]
}
resource "aws_route53_record" "alias" {
  zone_id = aws_route53_zone.proof.zone_id
  name = "alias.${aws_route53_zone.proof.name}"
  type = "A"
  alias {
    name = aws_route53_record.address.fqdn
    zone_id = aws_route53_zone.proof.zone_id
    evaluate_target_health = false
  }
}
resource "aws_route53_record" "domain" {
  zone_id = aws_route53_zone.proof.zone_id
  name = aws_route53_zone.proof.name
  type = "A"
  ttl = 30
  records = ["127.0.0.1"]
}

output "proof" {
  value = {
    rest_id = aws_api_gateway_rest_api.proof.id
    rest_key_id = aws_api_gateway_api_key.proof.id
    rest_resource_id = aws_api_gateway_resource.proof.id
    rest_stage = aws_api_gateway_stage.proof.stage_name
    rest_deployment_id = aws_api_gateway_deployment.proof.id
    http_id = aws_apigatewayv2_api.proof.id
    http_stage = aws_apigatewayv2_stage.proof.name
    http_deployment_id = aws_apigatewayv2_deployment.proof.id
    domain = aws_apigatewayv2_domain_name.proof.id
    mapping_key = aws_apigatewayv2_api_mapping.proof.api_mapping_key
    graphql_id = aws_appsync_graphql_api.proof.id
    graphql_url = aws_appsync_graphql_api.proof.uris["GRAPHQL"]
    zone_id = aws_route53_zone.proof.zone_id
    zone_name = aws_route53_zone.proof.name
    dns_name = aws_route53_record.proof.fqdn
    address_name = aws_route53_record.address.fqdn
    alias_name = aws_route53_record.alias.fqdn
  }
}
