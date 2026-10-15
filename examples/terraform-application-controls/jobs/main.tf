# Run with run.py: all API endpoints and credentials are owned loopback fixtures.
# Docker is optional; without it, the pipeline consumes actual S3 ZIP bytes,
# and CodeBuild projects are lifecycle controls only, never simulated jobs.
terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}

variable "endpoint" { type = string }
variable "name" { type = string }
variable "revision" { type = string }
variable "source_zip" { type = string }
variable "docker" { type = bool }
variable "build_image" { type = string }

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true
  # S3 Control prefixes its signed Host with the account ID. Route that
  # absolute-form HTTP request through the same owned listener, never DNS.
  http_proxy  = var.endpoint
  https_proxy = ""
  no_proxy    = "127.0.0.1,localhost"
  endpoints {
    codebuild    = var.endpoint
    codepipeline = var.endpoint
    iam          = var.endpoint
    s3           = var.endpoint
    s3control    = var.endpoint
    sfn          = var.endpoint
    sts          = var.endpoint
  }
}

locals {
  principals = {
    build    = "codebuild.amazonaws.com"
    pipeline = "codepipeline.amazonaws.com"
    workflow = "states.amazonaws.com"
  }
  standalone_spec = yamlencode({
    version = "0.2"
    phases = { build = { commands = [
      "python3 -c 'from pathlib import Path; import os; Path(\"result.bin\").write_bytes(b\"stackd actual build\\x00\\xff:\" + os.environ[\"REVISION\"].encode())'"
    ] } }
    artifacts = { files = ["result.bin"] }
  })
  pipeline_spec = yamlencode({
    version = "0.2"
    phases = { build = { commands = [
      "python3 -c 'from pathlib import Path; import os; Path(\"result.bin\").write_bytes(Path(\"payload.bin\").read_bytes() + b\"|built:\" + os.environ[\"REVISION\"].encode())'"
    ] } }
    artifacts = { files = ["result.bin"] }
  })
}

resource "aws_iam_role" "job" {
  for_each = local.principals
  name     = "${var.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = each.value }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_s3_bucket" "bytes" {
  for_each      = toset(["source", "artifacts", "destination", "build"])
  bucket        = "${var.name}-${each.key}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = aws_s3_bucket.bytes["source"].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_iam_role_policy" "effects" {
  for_each = toset(["build", "pipeline"])
  role     = aws_iam_role.job[each.key].id
  name     = "fixture-effects"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:*"], Resource = flatten([for bucket in aws_s3_bucket.bytes : [bucket.arn, "${bucket.arn}/*"]]) },
      { Effect = "Allow", Action = ["codebuild:StartBuild", "codebuild:BatchGetBuilds"], Resource = "arn:aws:codebuild:us-east-1:738492615083:project/${var.name}-pipeline" },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"], Resource = "*" }
    ]
  })
}

resource "aws_s3_object" "source" {
  bucket         = aws_s3_bucket.bytes["source"].id
  key            = "source.zip"
  content_base64 = var.source_zip
  depends_on     = [aws_s3_bucket_versioning.source]
}

resource "aws_codebuild_project" "standalone" {
  name                   = "${var.name}-standalone"
  description            = "Actual build consumer ${var.revision}"
  service_role           = aws_iam_role.job["build"].arn
  build_timeout          = 5
  concurrent_build_limit = var.revision == "v1" ? 2 : null
  artifacts {
    type     = "S3"
    location = aws_s3_bucket.bytes["build"].id
    path     = "standalone"
    # Keep every real build artifact available for the reopen/history assertions.
    namespace_type      = "BUILD_ID"
    name                = "result.zip"
    packaging           = "ZIP"
    encryption_disabled = true
  }
  source {
    type      = "NO_SOURCE"
    buildspec = local.standalone_spec
  }
  environment {
    type                        = "LINUX_CONTAINER"
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = var.build_image
    image_pull_credentials_type = "CODEBUILD"
    environment_variable {
      name  = "REVISION"
      value = var.revision
      type  = "PLAINTEXT"
    }
  }
  logs_config {
    cloudwatch_logs { status = "DISABLED" }
    s3_logs { status = "DISABLED" }
  }
  tags       = { Revision = var.revision }
  depends_on = [aws_iam_role_policy.effects]
}

resource "aws_codebuild_project" "pipeline" {
  name         = "${var.name}-pipeline"
  description  = "Pipeline byte transformer ${var.revision}"
  service_role = aws_iam_role.job["build"].arn
  artifacts { type = "CODEPIPELINE" }
  source {
    type      = "CODEPIPELINE"
    buildspec = local.pipeline_spec
  }
  environment {
    type                        = "LINUX_CONTAINER"
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = var.build_image
    image_pull_credentials_type = "CODEBUILD"
    environment_variable {
      name  = "REVISION"
      value = var.revision
      type  = "PLAINTEXT"
    }
  }
  logs_config {
    cloudwatch_logs { status = "DISABLED" }
    s3_logs { status = "DISABLED" }
  }
  tags       = { Revision = var.revision }
  depends_on = [aws_iam_role_policy.effects]
}

resource "aws_codepipeline" "jobs" {
  name           = var.name
  role_arn       = aws_iam_role.job["pipeline"].arn
  pipeline_type  = "V2"
  execution_mode = "QUEUED"
  artifact_store {
    type     = "S3"
    location = aws_s3_bucket.bytes["artifacts"].id
  }
  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["SourceBytes"]
      configuration = {
        S3Bucket             = aws_s3_bucket.bytes["source"].id
        S3ObjectKey          = aws_s3_object.source.key
        PollForSourceChanges = "false"
      }
    }
  }
  dynamic "stage" {
    for_each = var.docker ? [1] : []
    content {
      name = "Build"
      action {
        name             = "Build"
        category         = "Build"
        owner            = "AWS"
        provider         = "CodeBuild"
        version          = "1"
        input_artifacts  = ["SourceBytes"]
        output_artifacts = ["BuiltBytes"]
        configuration    = { ProjectName = aws_codebuild_project.pipeline.name }
      }
    }
  }
  stage {
    name = "Deploy"
    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "S3"
      version         = "1"
      input_artifacts = [var.docker ? "BuiltBytes" : "SourceBytes"]
      configuration = {
        BucketName = aws_s3_bucket.bytes["destination"].id
        Extract    = "true"
        ObjectKey  = var.revision
      }
    }
  }
  tags       = { Revision = var.revision }
  depends_on = [aws_iam_role_policy.effects, aws_codebuild_project.pipeline]
}

resource "aws_sfn_activity" "worker" {
  name = "${var.name}-worker"
  tags = { Revision = var.revision }
}

resource "aws_sfn_state_machine" "jobs" {
  name     = var.name
  role_arn = aws_iam_role.job["workflow"].arn
  type     = "STANDARD"
  publish  = true
  definition = jsonencode({
    StartAt = "Prepare"
    States = {
      Prepare = {
        Type       = "Pass"
        Parameters = { revision = var.revision, "payload.$" = "$.payload" }
        Next       = "Worker"
      }
      Worker = {
        Type           = "Task", Resource = aws_sfn_activity.worker.id
        TimeoutSeconds = 60, HeartbeatSeconds = 30, End = true
      }
    }
  })
  tags = { Revision = var.revision }
}

resource "aws_sfn_alias" "live" {
  name        = "live"
  description = "Live worker ${var.revision}"
  routing_configuration {
    state_machine_version_arn = aws_sfn_state_machine.jobs.state_machine_version_arn
    weight                    = 100
  }
}

data "aws_sfn_activity" "worker" {
  name       = aws_sfn_activity.worker.name
  depends_on = [aws_sfn_activity.worker]
}
data "aws_sfn_state_machine" "jobs" {
  name       = aws_sfn_state_machine.jobs.name
  depends_on = [aws_sfn_state_machine.jobs]
}
data "aws_sfn_alias" "live" {
  name             = aws_sfn_alias.live.name
  statemachine_arn = aws_sfn_state_machine.jobs.id
  depends_on       = [aws_sfn_alias.live]
}
data "aws_sfn_state_machine_versions" "jobs" {
  statemachine_arn = aws_sfn_state_machine.jobs.id
  depends_on       = [aws_sfn_state_machine.jobs]
}

output "jobs" {
  value = {
    pipeline             = aws_codepipeline.jobs.name
    project              = aws_codebuild_project.standalone.name
    project_arn          = aws_codebuild_project.standalone.arn
    pipeline_project     = aws_codebuild_project.pipeline.name
    pipeline_project_arn = aws_codebuild_project.pipeline.arn
    machine              = aws_sfn_state_machine.jobs.id
    version              = aws_sfn_state_machine.jobs.state_machine_version_arn
    alias                = aws_sfn_alias.live.id
    activity             = aws_sfn_activity.worker.id
    buckets              = { for key, bucket in aws_s3_bucket.bytes : key => bucket.id }
    lookups = {
      machine  = data.aws_sfn_state_machine.jobs.arn
      activity = data.aws_sfn_activity.worker.arn
      alias    = data.aws_sfn_alias.live.arn
      versions = data.aws_sfn_state_machine_versions.jobs.statemachine_versions
    }
  }
}
