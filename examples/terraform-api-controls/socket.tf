resource "aws_apigatewayv2_api" "socket" {
  name = "${var.name}-socket"
  protocol_type = "WEBSOCKET"
  route_selection_expression = "$request.body.action"
}
resource "aws_apigatewayv2_authorizer" "socket" {
  api_id = aws_apigatewayv2_api.socket.id
  name = "${var.name}-${var.revision}"
  authorizer_type = "REQUEST"
  authorizer_uri = local.lambda_uri
  identity_sources = ["route.request.querystring.token"]
}
resource "aws_apigatewayv2_integration" "socket" {
  api_id = aws_apigatewayv2_api.socket.id
  integration_type = "AWS_PROXY"
  integration_uri = local.lambda_uri
  payload_format_version = "1.0"
  description = var.revision
}
resource "aws_apigatewayv2_route" "socket" {
  for_each = toset(["$connect", "$disconnect", "echo"])
  api_id = aws_apigatewayv2_api.socket.id
  route_key = each.value
  authorization_type = each.value == "$connect" ? "CUSTOM" : "NONE"
  authorizer_id = each.value == "$connect" ? aws_apigatewayv2_authorizer.socket.id : null
  route_response_selection_expression = each.value == "echo" ? "$default" : null
  target = "integrations/${aws_apigatewayv2_integration.socket.id}"
}
resource "aws_apigatewayv2_route_response" "socket" {
  api_id = aws_apigatewayv2_api.socket.id
  route_id = aws_apigatewayv2_route.socket["echo"].id
  route_response_key = "$default"
}
resource "aws_apigatewayv2_deployment" "socket" {
  api_id = aws_apigatewayv2_api.socket.id
  triggers = { revision = var.revision }
  lifecycle { create_before_destroy = true }
  depends_on = [aws_apigatewayv2_route.socket, aws_apigatewayv2_route_response.socket]
}
resource "aws_apigatewayv2_stage" "socket" {
  api_id = aws_apigatewayv2_api.socket.id
  name = "live"
  deployment_id = aws_apigatewayv2_deployment.socket.id
  stage_variables = { revision = var.revision }
}
resource "aws_api_gateway_authorizer" "cognito" {
  name = "${var.name}-cognito-${var.revision}"
  rest_api_id = aws_api_gateway_rest_api.proof.id
  type = "COGNITO_USER_POOLS"
  identity_source = "method.request.header.Authorization"
  provider_arns = [var.pool_arn]
  # Native Create omits this field. The provider reads omission as0; PATCH300
  # is retained on update. Cognito verification remains current, without cache.
  authorizer_result_ttl_in_seconds = var.revision == "first" ? 0 : 300
}
resource "aws_api_gateway_resource" "cognito" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  parent_id = aws_api_gateway_rest_api.proof.root_resource_id
  path_part = "cognito"
}
resource "aws_api_gateway_method" "cognito" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  resource_id = aws_api_gateway_resource.cognito.id
  http_method = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}
resource "aws_api_gateway_integration" "cognito" {
  rest_api_id = aws_api_gateway_rest_api.proof.id
  resource_id = aws_api_gateway_resource.cognito.id
  http_method = aws_api_gateway_method.cognito.http_method
  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = local.lambda_uri
}
variable "pool_arn" { type = string }
