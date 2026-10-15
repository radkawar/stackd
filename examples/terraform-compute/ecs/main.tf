terraform {
  required_version = ">= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}

variable "endpoint" { type = string }
variable "name" { type = string }
variable "image" { type = string }
variable "revision" { type = string }
variable "desired_count" { type = number }
variable "vpc_cidr" { type = string }
variable "subnet_cidr" { type = string }

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  endpoints {
    ec2                    = var.endpoint
    ecs                    = var.endpoint
    iam                    = var.endpoint
    sts                    = var.endpoint
    applicationautoscaling = var.endpoint
    cloudwatch             = var.endpoint
  }
}

# Official service trust, owned by this Terraform run. The task application only
# serves HTTP; it needs no AWS identity policy. The execution policy follows the
# ordinary ECR/log boundary and does not replace native packet enforcement.
resource "aws_iam_role" "task" {
  name = "${var.name}-task"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "execution" {
  name = "execution"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "*" }]
  })
}
data "aws_iam_role" "task" { name = aws_iam_role.task.name }
data "aws_iam_role" "execution" { name = aws_iam_role.execution.name }

resource "aws_vpc" "compute" {
  cidr_block = var.vpc_cidr
  tags       = { Name = var.name }
}
resource "aws_subnet" "compute" {
  vpc_id            = aws_vpc.compute.id
  cidr_block        = var.subnet_cidr
  availability_zone = "us-east-1a"
  tags              = { Name = var.name }
}
resource "aws_security_group" "compute" {
  name   = var.name
  vpc_id = aws_vpc.compute.id
  ingress {
    protocol    = "tcp"
    from_port   = 8080
    to_port     = 8080
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_ecs_cluster" "compute" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
  tags = { revision = var.revision }
}
resource "aws_ecs_cluster_capacity_providers" "compute" {
  cluster_name       = aws_ecs_cluster.compute.name
  capacity_providers = ["FARGATE"]
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 0
  }
}
resource "aws_ecs_task_definition" "compute" {
  depends_on               = [aws_iam_role_policy.execution]
  family                   = var.name
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  task_role_arn            = data.aws_iam_role.task.arn
  execution_role_arn       = data.aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name         = "app"
    image        = var.image
    essential    = true
    entryPoint   = ["/bin/sh", "-c"]
    command      = ["mkdir -p /www; printf '%s\\n' \"$STACKD_REVISION\" > /www/index.html; printf 'COMPUTE:%s\\n' \"$STACKD_REVISION\"; exec httpd -f -p 8080 -h /www"]
    environment  = [{ name = "STACKD_REVISION", value = var.revision }]
    portMappings = [{ containerPort = 8080, hostPort = 8080, protocol = "tcp" }]
    healthCheck = {
      command     = ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:8080/"]
      interval    = 5
      timeout     = 2
      retries     = 3
      startPeriod = 0
    }
  }])
  tags = { revision = var.revision }
}
resource "aws_ecs_service" "compute" {
  name                               = var.name
  cluster                            = aws_ecs_cluster.compute.arn
  task_definition                    = aws_ecs_task_definition.compute.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  wait_for_steady_state              = true
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 200
  availability_zone_rebalancing      = "DISABLED"
  network_configuration {
    subnets          = [aws_subnet.compute.id]
    security_groups  = [aws_security_group.compute.id]
    assign_public_ip = false
  }
  tags = { revision = var.revision }
}
resource "aws_appautoscaling_target" "compute" {
  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"
  resource_id        = "service/${aws_ecs_cluster.compute.name}/${aws_ecs_service.compute.name}"
  min_capacity       = 1
  max_capacity       = 3
  suspended_state {
    dynamic_scaling_in_suspended  = true
    dynamic_scaling_out_suspended = true
    scheduled_scaling_suspended   = true
  }
}
resource "aws_appautoscaling_policy" "compute" {
  name               = var.name
  service_namespace  = aws_appautoscaling_target.compute.service_namespace
  scalable_dimension = aws_appautoscaling_target.compute.scalable_dimension
  resource_id        = aws_appautoscaling_target.compute.resource_id
  policy_type        = "TargetTrackingScaling"
  target_tracking_scaling_policy_configuration {
    target_value = 75
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}
resource "aws_appautoscaling_scheduled_action" "compute" {
  name               = var.name
  service_namespace  = aws_appautoscaling_target.compute.service_namespace
  scalable_dimension = aws_appautoscaling_target.compute.scalable_dimension
  resource_id        = aws_appautoscaling_target.compute.resource_id
  schedule           = "cron(0 0 1 1 ? 2099)"
  scalable_target_action {
    min_capacity = 1
    max_capacity = 3
  }
}

data "aws_ecs_cluster" "compute" {
  cluster_name = aws_ecs_cluster.compute.name
  depends_on   = [aws_ecs_service.compute]
}
data "aws_ecs_clusters" "compute" { depends_on = [aws_ecs_cluster.compute] }
data "aws_ecs_service" "compute" {
  cluster_arn  = aws_ecs_cluster.compute.arn
  service_name = aws_ecs_service.compute.name
}
data "aws_ecs_task_definition" "compute" { task_definition = aws_ecs_task_definition.compute.arn }
data "aws_ecs_container_definition" "compute" {
  task_definition = aws_ecs_task_definition.compute.arn
  container_name  = "app"
}
output "compute" {
  value = {
    cluster          = aws_ecs_cluster.compute.arn
    cluster_name     = aws_ecs_cluster.compute.name
    service          = aws_ecs_service.compute.name
    definition       = aws_ecs_task_definition.compute.arn
    subnet           = aws_subnet.compute.id
    security_group   = aws_security_group.compute.id
    vpc              = aws_vpc.compute.id
    scaling_target   = aws_appautoscaling_target.compute.resource_id
    scaling_policy   = aws_appautoscaling_policy.compute.arn
    scaling_schedule = aws_appautoscaling_scheduled_action.compute.name
    read_cluster     = data.aws_ecs_cluster.compute.arn
    read_service     = data.aws_ecs_service.compute.arn
    read_definition  = data.aws_ecs_task_definition.compute.arn
    read_image       = data.aws_ecs_container_definition.compute.image
    listed_clusters  = data.aws_ecs_clusters.compute.cluster_arns
  }
}
