variable "stream_runtime" {
  type    = bool
  default = false
}

resource "aws_kinesis_stream" "logs" {
  count       = var.stream_runtime ? 1 : 0
  name        = "${var.name}-logs"
  shard_count = 1
  tags        = local.tags
}
resource "aws_iam_role" "logs" {
  count = var.stream_runtime ? 1 : 0
  name  = "${var.name}-logs"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "logs.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role_policy" "logs" {
  count = var.stream_runtime ? 1 : 0
  role  = aws_iam_role.logs[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["kinesis:PutRecord", "kinesis:PutRecords"], Resource = aws_kinesis_stream.logs[0].arn
  }] })
}
resource "aws_cloudwatch_log_destination" "logs" {
  count      = var.stream_runtime ? 1 : 0
  name       = var.name
  role_arn   = aws_iam_role.logs[0].arn
  target_arn = aws_kinesis_stream.logs[0].arn
  tags       = local.tags
  depends_on = [aws_iam_role_policy.logs]
}
resource "aws_cloudwatch_log_destination_policy" "logs" {
  count            = var.stream_runtime ? 1 : 0
  destination_name = aws_cloudwatch_log_destination.logs[0].name
  access_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { AWS = "738492615083" },
    Action = "logs:PutSubscriptionFilter", Resource = aws_cloudwatch_log_destination.logs[0].arn
  }] })
}
resource "aws_cloudwatch_log_subscription_filter" "logs" {
  count           = var.stream_runtime ? 1 : 0
  name            = var.name
  log_group_name  = aws_cloudwatch_log_group.application.name
  filter_pattern  = "{ $.revision = \"*\" }"
  destination_arn = aws_cloudwatch_log_destination.logs[0].arn
  distribution    = "ByLogStream"
  depends_on      = [aws_cloudwatch_log_destination_policy.logs]
}
output "stream" {
  value = var.stream_runtime ? {
    name         = aws_kinesis_stream.logs[0].name,
    destination  = aws_cloudwatch_log_destination.logs[0].name,
    subscription = aws_cloudwatch_log_subscription_filter.logs[0].name
  } : null
}
