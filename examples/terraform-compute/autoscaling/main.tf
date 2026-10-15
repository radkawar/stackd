terraform {
  required_version = ">= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}
variable "endpoint" { type = string }
variable "name" { type = string }
variable "image_id" { type = string }
variable "revision" { type = string }
variable "desired_capacity" { type = number }
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
    ec2         = var.endpoint
    autoscaling = var.endpoint
    sts         = var.endpoint
  }
}
resource "aws_vpc" "compute" { cidr_block = var.vpc_cidr }
resource "aws_subnet" "compute" {
  vpc_id            = aws_vpc.compute.id
  cidr_block        = var.subnet_cidr
  availability_zone = "us-east-1a"
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
# image_id must be an actually imported bootable Linux HVM cloud-init image.
# This code uses installed Python, not a boot-time package or image download.
resource "aws_launch_template" "compute" {
  name                   = var.name
  image_id               = var.image_id
  instance_type          = "t3.small"
  vpc_security_group_ids = [aws_security_group.compute.id]
  user_data = base64encode(<<-SCRIPT
    #!/bin/sh
    set -eu
    mkdir -p /opt/stackd-compute
    printf '%s\n' '${var.revision}' >/opt/stackd-compute/index.html
    printf 'ASG:%s\n' '${var.revision}' >/dev/console
    cat >/etc/systemd/system/stackd-compute.service <<'UNIT'
    [Unit]
    After=network.target
    [Service]
    ExecStart=/usr/bin/python3 -m http.server 8080 --bind 0.0.0.0 --directory /opt/stackd-compute
    Restart=on-failure
    [Install]
    WantedBy=multi-user.target
    UNIT
    systemctl daemon-reload
    systemctl enable --now stackd-compute.service
  SCRIPT
  )
  tags = { revision = var.revision }
}
resource "aws_autoscaling_group" "compute" {
  name                      = var.name
  min_size                  = 1
  max_size                  = 2
  desired_capacity          = var.desired_capacity
  default_cooldown          = 0
  health_check_grace_period = 0
  health_check_type         = "EC2"
  vpc_zone_identifier       = [aws_subnet.compute.id]
  wait_for_capacity_timeout = "10m"
  launch_template {
    id      = aws_launch_template.compute.id
    version = tostring(aws_launch_template.compute.latest_version)
  }
  tag {
    key                 = "revision"
    value               = var.revision
    propagate_at_launch = true
  }
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 0
      instance_warmup        = 0
    }
  }
}
resource "aws_autoscaling_policy" "compute" {
  name                   = var.name
  autoscaling_group_name = aws_autoscaling_group.compute.name
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = 1
  cooldown               = 0
}
resource "aws_autoscaling_schedule" "compute" {
  scheduled_action_name  = var.name
  autoscaling_group_name = aws_autoscaling_group.compute.name
  recurrence             = "0 0 1 1 *"
  start_time             = "2099-01-01T00:00:00Z"
  min_size               = 1
  max_size               = 2
  desired_capacity       = 1
}
resource "aws_autoscaling_lifecycle_hook" "compute" {
  name                   = var.name
  autoscaling_group_name = aws_autoscaling_group.compute.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result         = "CONTINUE"
  heartbeat_timeout      = 30
}
data "aws_autoscaling_group" "compute" { name = aws_autoscaling_group.compute.name }
data "aws_autoscaling_groups" "compute" { names = [aws_autoscaling_group.compute.name] }
output "compute" {
  value = {
    name            = aws_autoscaling_group.compute.name
    group_arn       = aws_autoscaling_group.compute.arn
    launch_template = aws_launch_template.compute.id
    subnet          = aws_subnet.compute.id
    security_group  = aws_security_group.compute.id
    vpc             = aws_vpc.compute.id
    policy          = aws_autoscaling_policy.compute.name
    read_name       = data.aws_autoscaling_group.compute.name
    listed_names    = data.aws_autoscaling_groups.compute.names
  }
}
