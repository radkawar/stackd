variable "rotation_app_user" { type = string }
variable "rotation_app_password" {
  type = string
  sensitive = true
}
variable "rotation_app_endpoint" { type = string }

resource "aws_kms_key" "rotation" {
  description = "Actual rotation payload encryption ${var.revision}"
  deletion_window_in_days = 7
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_secretsmanager_secret" "rotation" {
  name = "${var.name}-rotation"
  description = "Four real Lambda callback stages ${var.revision}"
  kms_key_id = aws_kms_key.rotation.arn
  recovery_window_in_days = 0
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_secretsmanager_secret_version" "seed" {
  secret_id = aws_secretsmanager_secret.rotation.id
  secret_string = jsonencode({ revision = "seed", username = var.rotation_app_user, password = var.rotation_app_password })
  # AWSCURRENT is owned by finishSecret, not by this seed resource after creation.
}
resource "aws_iam_role" "rotation" {
  name = "${var.name}-rotation"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_cloudwatch_log_group" "rotation" { name = "/aws/lambda/${var.name}-rotation" }
resource "aws_iam_role_policy" "rotation" {
  name = "rotation-callback"
  role = aws_iam_role.rotation.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:ListSecretVersionIds", "secretsmanager:UpdateSecretVersionStage"], Resource = aws_secretsmanager_secret.rotation.arn },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"], Resource = aws_kms_key.rotation.arn },
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.rotation.arn}:*" }
    ]
  })
}
resource "aws_lambda_function" "rotation" {
  depends_on = [aws_iam_role_policy.rotation]
  function_name = "${var.name}-rotation"
  role = aws_iam_role.rotation.arn
  filename = "${var.artifact_directory}/rotation.zip"
  source_code_hash = filebase64sha256("${var.artifact_directory}/rotation.zip")
  runtime = "python3.12"
  handler = "rotation_handler.invoke"
  architectures = [var.architecture]
  timeout = 30
  memory_size = 256
  environment {
    variables = {
      FIXTURE_REVISION = var.revision
      FIXTURE_SECRET = aws_secretsmanager_secret.rotation.arn
      FIXTURE_ROLE = aws_iam_role.rotation.name
      FIXTURE_APPLICATION = var.rotation_app_endpoint
    }
  }
  logging_config {
    log_format = "Text"
    log_group = aws_cloudwatch_log_group.rotation.name
  }
}
resource "aws_lambda_permission" "rotation" {
  statement_id = "OwnedSecretRotation"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal = "secretsmanager.amazonaws.com"
  source_arn = aws_secretsmanager_secret.rotation.arn
  source_account = var.account_id
}
resource "aws_secretsmanager_secret_rotation" "rotation" {
  depends_on = [aws_lambda_permission.rotation, aws_secretsmanager_secret_version.seed]
  secret_id = aws_secretsmanager_secret.rotation.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  rotate_immediately = true
  rotation_rules {
    automatically_after_days = var.revision == "v1" ? 30 : 31
    duration = "1h"
  }
}
output "rotation" {
  sensitive = true
  value = {
    secret = aws_secretsmanager_secret.rotation.arn
    seed_version = aws_secretsmanager_secret_version.seed.version_id
    function = aws_lambda_function.rotation.function_name
    function_arn = aws_lambda_function.rotation.arn
    role = aws_iam_role.rotation.name
    role_policy = aws_iam_role_policy.rotation.name
    permission = aws_lambda_permission.rotation.statement_id
    log_group = aws_cloudwatch_log_group.rotation.name
    key = aws_kms_key.rotation.id
    key_arn = aws_kms_key.rotation.arn
    revision = var.revision
  }
}
