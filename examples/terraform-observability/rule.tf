# A native-created ACL is an explicit external prerequisite. This separates
# individual rule ownership from aws_wafv2_web_acl's exclusive inline rules.
variable "native_acl_arn" { type = string }
resource "aws_wafv2_web_acl_rule" "application" {
  web_acl_arn = var.native_acl_arn
  name        = "standalone"
  priority    = 1
  action {
    block {}
  }
  statement {
    byte_match_statement {
      positional_constraint = "EXACTLY"
      search_string         = var.revision
      field_to_match {
        single_header { name = "x-managed" }
      }
      text_transformation {
        priority = 0
        type     = "NONE"
      }
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-standalone"
    sampled_requests_enabled   = true
  }
}
resource "aws_api_gateway_stage" "standalone" {
  rest_api_id   = aws_api_gateway_rest_api.consumer.id
  deployment_id = aws_api_gateway_deployment.consumer.id
  stage_name    = "standalone"
}
resource "aws_wafv2_web_acl_association" "standalone" {
  resource_arn = aws_api_gateway_stage.standalone.arn
  web_acl_arn  = var.native_acl_arn
  depends_on   = [aws_wafv2_web_acl_rule.application]
}
