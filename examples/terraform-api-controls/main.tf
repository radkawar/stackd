terraform {
  required_version = "= 1.16.6"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}
variable "endpoint" {
  type = string
  validation {
    condition = can(regex("^http://127\\.0\\.0\\.1:[0-9]+$", var.endpoint))
    error_message = "Use the owned loopback controller."
  }
}
variable "name" { type = string }
variable "revision" { type = string }
variable "function_arn" { type = string }
variable "appsync_role_arn" { type = string }
variable "log_role_arns" { type = list(string) }
variable "log_group_arn" { type = string }
variable "http_origin" { type = string }
locals {
  lambda_uri = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/${var.function_arn}/invocations"
}
provider "aws" {
  region = "us-east-1"
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  endpoints {
    apigateway = var.endpoint
    apigatewayv2 = var.endpoint
    appsync = var.endpoint
    route53 = var.endpoint
    iam = var.endpoint
    sts = var.endpoint
    lambda = var.endpoint
    cloudwatchlogs = var.endpoint
  }
}
resource "aws_api_gateway_account" "proof" {
  cloudwatch_role_arn = var.log_role_arns[var.revision == "first" ? 0 : 1]
}
resource "aws_api_gateway_rest_api" "proof" {
  name = "${var.name}-auth"
  endpoint_configuration { types = ["REGIONAL"] }
}
resource "aws_api_gateway_authorizer" "proof" {
  name = "${var.name}-${var.revision}"
  rest_api_id = aws_api_gateway_rest_api.proof.id
  type = "TOKEN"
  authorizer_uri = local.lambda_uri
  identity_source = "method.request.header.Authorization"
  identity_validation_expression = "^(allow|deny)-${var.revision}$"
  authorizer_result_ttl_in_seconds = 60
}
resource "aws_api_gateway_resource" "proof" {
  for_each = toset(["protected", "iam", "request"])
  rest_api_id = aws_api_gateway_rest_api.proof.id
  parent_id = aws_api_gateway_rest_api.proof.root_resource_id
  path_part = each.value
}
resource "aws_api_gateway_method" "proof" {
  for_each = aws_api_gateway_resource.proof
  rest_api_id = aws_api_gateway_rest_api.proof.id
  resource_id = each.value.id
  http_method = "POST"
  authorization = each.key == "iam" ? "AWS_IAM" : "CUSTOM"
  authorizer_id = each.key == "iam" ? null : each.key == "protected" ? aws_api_gateway_authorizer.proof.id : aws_api_gateway_authorizer.request.id
  operation_name = var.revision
}
resource "aws_api_gateway_integration" "proof" {
  for_each = aws_api_gateway_method.proof
  rest_api_id = aws_api_gateway_rest_api.proof.id
  resource_id = aws_api_gateway_resource.proof[each.key].id
  http_method = each.value.http_method
  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = local.lambda_uri
}
resource "aws_api_gateway_deployment" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  triggers = { revision = var.revision }
  lifecycle { create_before_destroy = true }
  depends_on = [aws_api_gateway_integration.proof, aws_api_gateway_authorizer.proof, aws_api_gateway_integration.cognito]
}
resource "aws_api_gateway_stage" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  deployment_id = aws_api_gateway_deployment.proof.id
  stage_name = "live"
  variables = { revision = var.revision }
  access_log_settings {
    destination_arn = var.log_group_arn
    format = "{\"requestId\":\"$context.requestId\",\"status\":\"$context.status\",\"path\":\"$context.resourcePath\"}"
  }
  depends_on = [aws_api_gateway_account.proof]
}
resource "aws_api_gateway_method_settings" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  stage_name = aws_api_gateway_stage.proof.stage_name
  method_path = "*/*"
  settings {
    logging_level = "INFO"
    metrics_enabled = true
    data_trace_enabled = true
    throttling_burst_limit = var.revision == "first" ? 100 : 200
    throttling_rate_limit = var.revision == "first" ? 100 : 200
  }
}
resource "aws_api_gateway_api_key" "proof" {
  name = var.name
  enabled = true
}

resource "aws_api_gateway_rest_api" "imported" {
  name = "${var.name}-swagger"
  endpoint_configuration { types = ["REGIONAL"] }
}
resource "aws_api_gateway_rest_api_put" "proof" {
  rest_api_id = aws_api_gateway_rest_api.imported.id
  fail_on_warnings = true
  triggers = { revision = var.revision }
  body = jsonencode({
    swagger = "2.0"
    info = { title = "${var.name}-swagger", version = var.revision }
    paths = { "/imported" = { get = {
      responses = { "200" = { description = "literal response" } }
      "x-amazon-apigateway-integration" = {
        type = "mock"
        requestTemplates = { "application/json" = jsonencode({ statusCode = 200 }) }
        responses = { default = {
          statusCode = "200"
          responseTemplates = { "application/json" = jsonencode({ revision = var.revision }) }
        } }
      }
    } } }
  })
}
resource "aws_api_gateway_deployment" "imported" {
  rest_api_id = aws_api_gateway_rest_api.imported.id
  triggers = { revision = var.revision }
  lifecycle { create_before_destroy = true }
  depends_on = [aws_api_gateway_rest_api_put.proof]
}
resource "aws_api_gateway_stage" "imported" {
  rest_api_id = aws_api_gateway_rest_api.imported.id
  deployment_id = aws_api_gateway_deployment.imported.id
  stage_name = "live"
}

resource "aws_apigatewayv2_api" "proof" {
  name = "${var.name}-http"
  protocol_type = "HTTP"
}
resource "aws_apigatewayv2_authorizer" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  name = "${var.name}-${var.revision}"
  authorizer_type = "REQUEST"
  authorizer_uri = local.lambda_uri
  authorizer_payload_format_version = "2.0"
  enable_simple_responses = true
  identity_sources = ["$request.header.Authorization"]
  authorizer_result_ttl_in_seconds = 60
}
resource "aws_apigatewayv2_integration" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  integration_type = "AWS_PROXY"
  integration_uri = var.function_arn
  payload_format_version = "2.0"
}
resource "aws_apigatewayv2_route" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  route_key = "POST /protected"
  authorization_type = "CUSTOM"
  authorizer_id = aws_apigatewayv2_authorizer.proof.id
  target = "integrations/${aws_apigatewayv2_integration.proof.id}"
}
resource "aws_apigatewayv2_stage" "proof" {
  api_id = aws_apigatewayv2_api.proof.id
  name = "live"
  auto_deploy = true
  stage_variables = { revision = var.revision }
}
resource "aws_appsync_graphql_api" "proof" {
  name = "${var.name}-${var.revision}-graphql"
  authentication_type = "AWS_IAM"
  additional_authentication_provider {
    authentication_type = "API_KEY"
  }
  additional_authentication_provider {
    authentication_type = "AMAZON_COGNITO_USER_POOLS"
    user_pool_config {
      aws_region = "us-east-1"
      user_pool_id = var.pool_id
    }
  }
  additional_authentication_provider {
    authentication_type = "OPENID_CONNECT"
    openid_connect_config {
      issuer = var.oidc_issuer
      client_id = "^owned-graph-client$"
      auth_ttl = 3600000
      iat_ttl = 3600000
    }
  }
  schema = local.graphql_schema
}
resource "aws_appsync_datasource" "http" {
  api_id = aws_appsync_graphql_api.proof.id
  name = "http"
  type = "HTTP"
  description = var.revision
  http_config { endpoint = var.http_origin }
}
resource "aws_appsync_resolver" "http" {
  api_id = aws_appsync_graphql_api.proof.id
  type = "Query"
  field = "http"
  data_source = aws_appsync_datasource.http.name
  runtime {
    name = "APPSYNC_JS"
    runtime_version = "1.0.0"
  }
  code = "export function request(ctx) { return {method:'POST',resourcePath:'/echo',params:{headers:{'content-type':'application/json'},body:{input:ctx.args.input,revision:'${var.revision}'}}}; }\nexport function response(ctx) { return JSON.parse(ctx.result.body).value; }"
}
resource "aws_appsync_datasource" "direct" {
  api_id = aws_appsync_graphql_api.proof.id
  name = "direct"
  type = "AWS_LAMBDA"
  description = var.revision
  service_role_arn = var.appsync_role_arn
  lambda_config { function_arn = var.function_arn }
}
resource "aws_appsync_resolver" "direct" {
  api_id = aws_appsync_graphql_api.proof.id
  type = "Query"
  field = "direct"
  data_source = aws_appsync_datasource.direct.name
}
resource "aws_route53_zone" "proof" {
  name = "${var.name}.test"
  force_destroy = true
}
resource "aws_route53_records_exclusive" "proof" {
  zone_id = aws_route53_zone.proof.zone_id
  resource_record_set {
    name = "address.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "A"
    ttl = 30
    resource_records { value = var.revision == "first" ? "192.0.2.10" : "192.0.2.20" }
  }
  resource_record_set {
    name = "text.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "TXT"
    ttl = 30
    resource_records { value = "\"${var.revision}\"" }
  }
  resource_record_set {
    name = "alias.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "CNAME"
    ttl = 30
    resource_records { value = "address.${trimsuffix(aws_route53_zone.proof.name, ".")}." }
  }
  resource_record_set {
    name = "weighted.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "A"
    ttl = 30
    set_identifier = "positive"
    weight = 1
    resource_records { value = "192.0.2.30" }
  }
  resource_record_set {
    name = "weighted.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "A"
    ttl = 30
    set_identifier = "zero"
    weight = 0
    resource_records { value = "192.0.2.40" }
  }
  resource_record_set {
    name = "ipv6.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "AAAA"
    ttl = 30
    resource_records { value = "2001:db8::1" }
  }
  resource_record_set {
    name = "ptr.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "PTR"
    ttl = 30
    resource_records { value = "address.${trimsuffix(aws_route53_zone.proof.name, ".")}." }
  }
  resource_record_set {
    name = "mail.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "MX"
    ttl = 30
    resource_records { value = "10 address.${trimsuffix(aws_route53_zone.proof.name, ".")}." }
  }
  resource_record_set {
    name = "_service._tcp.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "SRV"
    ttl = 30
    resource_records { value = "10 20 443 address.${trimsuffix(aws_route53_zone.proof.name, ".")}." }
  }
  resource_record_set {
    name = "certificate.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "CAA"
    ttl = 30
    resource_records { value = "0 issue \"ca.example.test\"" }
  }
  dynamic "resource_record_set" {
    for_each = toset(["192.0.2.50", "192.0.2.51"])
    content {
      name = "multi.${trimsuffix(aws_route53_zone.proof.name, ".")}."
      type = "A"
      ttl = 30
      set_identifier = resource_record_set.value
      multi_value_answer = true
      resource_records { value = resource_record_set.value }
    }
  }
  resource_record_set {
    name = "delegate.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "NS"
    ttl = 30
    resource_records { value = "nameserver.delegate.${trimsuffix(aws_route53_zone.proof.name, ".")}." }
  }
  resource_record_set {
    name = "nameserver.delegate.${trimsuffix(aws_route53_zone.proof.name, ".")}."
    type = "A"
    ttl = 30
    resource_records { value = "127.0.0.1" }
  }
}

data "aws_api_gateway_rest_api" "proof" {
  name = aws_api_gateway_rest_api.proof.name
}
data "aws_api_gateway_resource" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  path = "/protected"
  depends_on = [aws_api_gateway_resource.proof]
}
data "aws_api_gateway_authorizer" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  authorizer_id = aws_api_gateway_authorizer.proof.id
}
data "aws_api_gateway_authorizers" "proof" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  depends_on = [aws_api_gateway_authorizer.proof]
}
data "aws_api_gateway_api_key" "proof" { id = aws_api_gateway_api_key.proof.id }
data "aws_api_gateway_api_keys" "proof" {
  include_values = true
  depends_on = [aws_api_gateway_api_key.proof]
}
data "aws_apigatewayv2_api" "proof" { api_id = aws_apigatewayv2_api.proof.id }
data "aws_apigatewayv2_apis" "proof" {
  name = aws_apigatewayv2_api.proof.name
  protocol_type = "HTTP"
}
data "aws_route53_zone" "proof" { zone_id = aws_route53_zone.proof.zone_id }
data "aws_route53_zones" "proof" {
  depends_on = [aws_route53_zone.proof]
}
data "aws_route53_records" "proof" {
  zone_id = aws_route53_zone.proof.zone_id
  depends_on = [aws_route53_records_exclusive.proof]
}
output "proof" {
  value = {
    account_id = aws_api_gateway_account.proof.id
    rest_deployment_id = aws_api_gateway_deployment.proof.id
    imported_deployment_id = aws_api_gateway_deployment.imported.id
    ws_id = aws_apigatewayv2_api.socket.id
    ws_authorizer_id = aws_apigatewayv2_authorizer.socket.id
    ws_deployment_id = aws_apigatewayv2_deployment.socket.id
    ws_route_id = aws_apigatewayv2_route.socket["echo"].id
    ws_response_id = aws_apigatewayv2_route_response.socket.id
    rest_id = aws_api_gateway_rest_api.proof.id
    rest_authorizer_id = aws_api_gateway_authorizer.proof.id
    rest_cognito_authorizer_id = aws_api_gateway_authorizer.cognito.id
    rest_resource_id = aws_api_gateway_resource.proof["protected"].id
    imported_id = aws_api_gateway_rest_api.imported.id
    http_id = aws_apigatewayv2_api.proof.id
    http_authorizer_id = aws_apigatewayv2_authorizer.proof.id
    graphql_id = aws_appsync_graphql_api.proof.id
    graphql_url = aws_appsync_graphql_api.proof.uris["GRAPHQL"]
    zone_id = aws_route53_zone.proof.zone_id
    zone_name = aws_route53_zone.proof.name
    read_rest_id = data.aws_api_gateway_rest_api.proof.id
    read_resource_id = data.aws_api_gateway_resource.proof.id
    read_authorizer_id = data.aws_api_gateway_authorizer.proof.id
    read_authorizer_ids = data.aws_api_gateway_authorizers.proof.ids
    read_key_id = data.aws_api_gateway_api_key.proof.id
    key_id = aws_api_gateway_api_key.proof.id
    read_key_count = length(data.aws_api_gateway_api_keys.proof.items)
    read_http_id = data.aws_apigatewayv2_api.proof.id
    read_http_ids = data.aws_apigatewayv2_apis.proof.ids
    read_zone_id = data.aws_route53_zone.proof.zone_id
    read_zone_ids = data.aws_route53_zones.proof.ids
    read_record_count = length(data.aws_route53_records.proof.resource_record_sets)
  }
}
