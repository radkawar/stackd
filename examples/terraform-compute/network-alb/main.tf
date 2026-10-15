# Current-provider control lifecycle and independent native compute consumer.
# All evidence stays unverified until the parent executes the complete stages.
# enable_alb=false exercises network controls or bootstraps an actual ECS target.
terraform {
  required_version = ">= 1.15.9"
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
    condition     = can(regex("^http://127\\.0\\.0\\.1:[0-9]+$", var.endpoint))
    error_message = "Use the explicitly owned loopback controller."
  }
}
variable "name" { type = string }
variable "revision" { default = "one" }
variable "enable_alb" { default = true }
variable "enable_target" { default = false }
variable "target_image" { default = "busybox:1.36.1" }
variable "vpc_cidr" { default = "10.179.0.0/16" }
variable "subnet_cidrs" { default = ["10.179.1.0/24", "10.179.2.0/24"] }
variable "availability_zones" { default = ["us-east-1a", "us-east-1b"] }
variable "listener_port" { default = 8080 }
# External private targets remain optional. By default the runner first creates
# its own real ECS HTTP container and uses the task's authoritative private IP.
variable "targets" {
  type    = map(object({ ip = string, port = number, availability_zone = string }))
  default = {}
}
variable "expected_target_body" { default = "" }
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  endpoints {
    ec2   = var.endpoint
    elbv2 = var.endpoint
    ecs   = var.endpoint
    iam   = var.endpoint
    sts   = var.endpoint
  }
}
resource "aws_vpc" "network" {
  cidr_block = var.vpc_cidr
  tags       = { Name = var.name, Revision = var.revision }
}
resource "aws_subnet" "zone" {
  count             = 2
  vpc_id            = aws_vpc.network.id
  cidr_block        = var.subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]
  tags              = { Name = "${var.name}-${count.index}", Revision = var.revision }
}
resource "aws_security_group" "network" {
  name        = var.name
  description = "Terraform network and native ALB fixture"
  vpc_id      = aws_vpc.network.id
  ingress {
    protocol    = "tcp"
    from_port   = var.listener_port
    to_port     = var.listener_port
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Revision = var.revision }
}
resource "aws_network_interface" "network" {
  subnet_id       = aws_subnet.zone[0].id
  security_groups = [aws_security_group.network.id]
  description     = "Terraform revision ${var.revision}"
  tags            = { Revision = var.revision }
}
resource "aws_iam_role" "target_task" {
  count = var.enable_target ? 1 : 0
  name  = "${var.name}-target-task"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role" "target_execution" {
  count = var.enable_target ? 1 : 0
  name  = "${var.name}-target-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "target_execution" {
  count = var.enable_target ? 1 : 0
  name  = "execution"
  role  = aws_iam_role.target_execution[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "*" }]
  })
}
data "aws_iam_role" "target_task" {
  count = var.enable_target ? 1 : 0
  name  = aws_iam_role.target_task[0].name
}
data "aws_iam_role" "target_execution" {
  count = var.enable_target ? 1 : 0
  name  = aws_iam_role.target_execution[0].name
}
resource "aws_ecs_cluster" "target" {
  count = var.enable_target ? 1 : 0
  name  = "${var.name}-target"
}
resource "aws_ecs_task_definition" "target" {
  count                    = var.enable_target ? 1 : 0
  depends_on               = [aws_iam_role_policy.target_execution]
  family                   = "${var.name}-target"
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  task_role_arn            = data.aws_iam_role.target_task[0].arn
  execution_role_arn       = data.aws_iam_role.target_execution[0].arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name         = "target"
    image        = var.target_image
    essential    = true
    command      = ["/bin/sh", "-c", "mkdir -p /www; printf 'target-${var.revision}\\n' >/www/index.html; cp /www/index.html /www/forward; printf 'ALB_TARGET:${var.revision}\\n'; exec httpd -f -p ${var.listener_port} -h /www"]
    portMappings = [{ containerPort = var.listener_port, hostPort = var.listener_port, protocol = "tcp" }]
    healthCheck  = { command = ["CMD-SHELL", "wget -qO- http://127.0.0.1:${var.listener_port}/ >/dev/null || exit 1"], interval = 5, timeout = 2, retries = 3, startPeriod = 0 }
  }])
  tags = { Revision = var.revision }
}
resource "aws_ecs_service" "target" {
  count                              = var.enable_target ? 1 : 0
  name                               = "${var.name}-target"
  cluster                            = aws_ecs_cluster.target[0].id
  task_definition                    = aws_ecs_task_definition.target[0].arn
  desired_count                      = 1
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  wait_for_steady_state              = true
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 200
  availability_zone_rebalancing      = "DISABLED"
  network_configuration {
    subnets          = [aws_subnet.zone[0].id]
    security_groups  = [aws_security_group.network.id]
    assign_public_ip = false
  }
}
resource "aws_lb" "network" {
  count              = var.enable_alb ? 1 : 0
  name               = var.name
  internal           = true
  load_balancer_type = "application"
  ip_address_type    = "ipv4"
  subnets            = aws_subnet.zone[*].id
  security_groups    = [aws_security_group.network.id]
  # Native HTTP1 preserves Host. Defensive desync requires the real configured
  # guardian pre-parser; these fields do not suppress any provider defaults.
  enable_http2         = false
  preserve_host_header = true
  idle_timeout         = 60
  tags                 = { Revision = var.revision }
}
resource "aws_lb_target_group" "network" {
  count                = var.enable_alb && length(var.targets) > 0 ? 1 : 0
  name                 = "${var.name}-tg"
  protocol             = "HTTP"
  port                 = 80
  target_type          = "ip"
  vpc_id               = aws_vpc.network.id
  deregistration_delay = 0
  health_check {
    path                = "/"
    interval            = 5
    timeout             = 2
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = { Revision = var.revision }
}
resource "aws_lb_target_group_attachment" "network" {
  for_each          = var.enable_alb ? var.targets : {}
  target_group_arn  = aws_lb_target_group.network[0].arn
  target_id         = each.value.ip
  port              = each.value.port
  availability_zone = each.value.availability_zone
}
resource "aws_lb_listener" "network" {
  count             = var.enable_alb ? 1 : 0
  load_balancer_arn = aws_lb.network[0].arn
  port              = var.listener_port
  protocol          = "HTTP"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
      message_body = "fixed-${var.revision}"
    }
  }
  tags = { Revision = var.revision }
}
resource "aws_lb_listener_rule" "forward" {
  count        = var.enable_alb && length(var.targets) > 0 ? 1 : 0
  listener_arn = aws_lb_listener.network[0].arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.network[0].arn
  }
  condition {
    path_pattern { values = ["/forward"] }
  }
  tags = { Revision = var.revision }
}
output "consumer" {
  value = {
    vpc_id               = aws_vpc.network.id
    subnet_ids           = aws_subnet.zone[*].id
    group_id             = aws_security_group.network.id
    interface_id         = aws_network_interface.network.id
    load_balancer_arn    = try(aws_lb.network[0].arn, null)
    dns_name             = try(aws_lb.network[0].dns_name, null)
    listener_arn         = try(aws_lb_listener.network[0].arn, null)
    rule_arn             = try(aws_lb_listener_rule.forward[0].arn, null)
    target_group_arn     = try(aws_lb_target_group.network[0].arn, null)
    listener_port        = var.listener_port
    revision             = var.revision
    expected_target_body = var.expected_target_body
    targets              = var.targets
    target_cluster       = try(aws_ecs_cluster.target[0].arn, null)
    target_service       = try(aws_ecs_service.target[0].name, null)
    target_definition    = try(aws_ecs_task_definition.target[0].arn, null)
  }
}
