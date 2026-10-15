resource "aws_api_gateway_authorizer" "request" {
  name = "${var.name}-request-${var.revision}"
  rest_api_id = aws_api_gateway_rest_api.proof.id
  type = "REQUEST"
  authorizer_uri = local.lambda_uri
  identity_source = "method.request.header.Authorization"
  authorizer_result_ttl_in_seconds = 60
}
resource "aws_apigatewayv2_authorizer" "request1" {
  api_id = aws_apigatewayv2_api.proof.id
  name = "${var.name}-request1-${var.revision}"
  authorizer_type = "REQUEST"
  authorizer_uri = local.lambda_uri
  authorizer_payload_format_version = "1.0"
  identity_sources = ["$request.header.Authorization"]
  authorizer_result_ttl_in_seconds = 60
}
resource "aws_apigatewayv2_route" "request1" {
  api_id = aws_apigatewayv2_api.proof.id
  route_key = "POST /request1"
  authorization_type = "CUSTOM"
  authorizer_id = aws_apigatewayv2_authorizer.request1.id
  target = "integrations/${aws_apigatewayv2_integration.proof.id}"
}
variable "oidc_issuer" { type = string }
