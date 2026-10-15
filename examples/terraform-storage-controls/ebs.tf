terraform {
  required_version = "= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}

variable "endpoint" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "name" { type = string }
variable "image_id" { type = string }
variable "user_data" {
  type = string
  sensitive = true
}
variable "vpc_cidr" { type = string }
variable "instance_type" { type = string }
variable "source_size" { type = number }
variable "source_attached" { type = bool }
variable "snapshot_enabled" { type = bool }
variable "restore_enabled" { type = bool }
variable "permission_enabled" { type = bool }
variable "share_account" { type = string }
variable "reader_allowed" { type = bool }
variable "revision" { type = string }

provider "aws" {
  region = var.region
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  endpoints {
    ec2 = var.endpoint
    sts = var.endpoint
    iam = var.endpoint
    kms = var.endpoint
  }
}

# Network, AMI and instance are execution prerequisites, not broad EC2 coverage.
resource "aws_vpc" "guest" {
  cidr_block = var.vpc_cidr
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = { Fixture = var.name }
}
resource "aws_subnet" "guest" {
  vpc_id = aws_vpc.guest.id
  cidr_block = var.vpc_cidr
  availability_zone = "${var.region}a"
  tags = { Fixture = var.name }
}
resource "aws_security_group" "guest" {
  name = "${var.name}-ebs-guest"
  description = "Owned native EBS consumer; no Internet route"
  vpc_id = aws_vpc.guest.id
  ingress {
    protocol = "tcp"
    from_port = 8765
    to_port = 8765
    cidr_blocks = ["${cidrhost(var.vpc_cidr, 1)}/32"]
  }
  egress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = [var.vpc_cidr]
  }
  tags = { Fixture = var.name }
}
resource "aws_instance" "guest" {
  ami = var.image_id
  instance_type = var.instance_type
  subnet_id = aws_subnet.guest.id
  vpc_security_group_ids = [aws_security_group.guest.id]
  associate_public_ip_address = false
  user_data = var.user_data
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
  }
  root_block_device {
    delete_on_termination = true
    volume_type = "gp3"
  }
  tags = { Fixture = var.name }
}
resource "aws_ebs_volume" "source" {
  availability_zone = "${var.region}a"
  size = var.source_size
  type = "gp3"
  iops = 3000
  throughput = 125
  encrypted = false
  final_snapshot = false
  tags = { Fixture = var.name, Role = "source", Revision = var.revision }
}
resource "aws_volume_attachment" "source" {
  count = var.source_attached ? 1 : 0
  device_name = "/dev/sdf"
  volume_id = aws_ebs_volume.source.id
  instance_id = aws_instance.guest.id
  force_detach = false
  skip_destroy = false
  stop_instance_before_detaching = false
}
# Python admits this resource only after a completed real native detach.
resource "aws_ebs_snapshot" "cold" {
  count = var.snapshot_enabled ? 1 : 0
  volume_id = aws_ebs_volume.source.id
  description = "${var.name} detached native binary marker"
  storage_tier = "standard"
  tags = { Fixture = var.name, Role = "cold", Revision = var.revision }
}
resource "aws_snapshot_create_volume_permission" "cold" {
  count = var.snapshot_enabled && var.permission_enabled ? 1 : 0
  snapshot_id = aws_ebs_snapshot.cold[0].id
  account_id = var.share_account
}
resource "aws_ebs_volume" "restored" {
  count = var.restore_enabled ? 1 : 0
  availability_zone = "${var.region}a"
  snapshot_id = aws_ebs_snapshot.cold[0].id
  size = 2
  type = "gp3"
  iops = 3000
  throughput = 125
  encrypted = false
  final_snapshot = false
  tags = { Fixture = var.name, Role = "restored", Revision = var.revision }
}
resource "aws_volume_attachment" "restored" {
  count = var.restore_enabled ? 1 : 0
  device_name = "/dev/sdg"
  volume_id = aws_ebs_volume.restored[0].id
  instance_id = aws_instance.guest.id
  force_detach = false
  skip_destroy = false
  stop_instance_before_detaching = false
}

data "aws_ebs_volume" "source" {
  filter {
    name = "volume-id"
    values = [aws_ebs_volume.source.id]
  }
  depends_on = [aws_volume_attachment.source]
}
data "aws_ebs_volumes" "owned" {
  tags = { Fixture = var.name }
  depends_on = [aws_ebs_volume.source, aws_ebs_volume.restored]
}
data "aws_ebs_snapshot" "cold" {
  count = var.snapshot_enabled ? 1 : 0
  snapshot_ids = [aws_ebs_snapshot.cold[0].id]
  owners = [var.account_id]
}
data "aws_ebs_snapshot_ids" "cold" {
  count = var.snapshot_enabled ? 1 : 0
  owners = [var.account_id]
  filter {
    name = "snapshot-id"
    values = [aws_ebs_snapshot.cold[0].id]
  }
}

# This principal proves current EBS authority, including revocation of an old
# block token. It is not used by the guest or by Terraform's admin provider.
resource "aws_iam_user" "reader" {
  name = "${var.name}-ebs-reader"
  force_destroy = true
}
resource "aws_iam_access_key" "reader" { user = aws_iam_user.reader.name }
resource "aws_iam_user_policy" "reader" {
  name = "current-ebs-reader"
  user = aws_iam_user.reader.name
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = var.reader_allowed ? "Allow" : "Deny", Action = ["ec2:DescribeVolumes"], Resource = "*" },
    { Effect = var.reader_allowed ? "Allow" : "Deny", Action = ["ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock"],
      Resource = var.snapshot_enabled ? aws_ebs_snapshot.cold[0].arn : "arn:aws:ec2:${var.region}::snapshot/*" }
  ] })
}

output "ebs" {
  sensitive = true
  value = {
    source_id = aws_ebs_volume.source.id
    source_arn = aws_ebs_volume.source.arn
    source_size = aws_ebs_volume.source.size
    source_data_id = data.aws_ebs_volume.source.id
    source_data_size = data.aws_ebs_volume.source.size
    owned_volume_ids = data.aws_ebs_volumes.owned.ids
    snapshot_id = try(aws_ebs_snapshot.cold[0].id, null)
    snapshot_arn = try(aws_ebs_snapshot.cold[0].arn, null)
    snapshot_source_id = try(data.aws_ebs_snapshot.cold[0].volume_id, null)
    snapshot_size = try(data.aws_ebs_snapshot.cold[0].volume_size, null)
    snapshot_data_ids = try(data.aws_ebs_snapshot_ids.cold[0].ids, [])
    restored_id = try(aws_ebs_volume.restored[0].id, null)
    restored_source_snapshot = try(aws_ebs_volume.restored[0].snapshot_id, null)
    instance_id = aws_instance.guest.id
    root_volume_id = aws_instance.guest.root_block_device[0].volume_id
    guest_ip = aws_instance.guest.private_ip
    vpc_id = aws_vpc.guest.id
    subnet_id = aws_subnet.guest.id
    security_group_id = aws_security_group.guest.id
    reader_key = aws_iam_access_key.reader.id
    reader_secret = aws_iam_access_key.reader.secret
  }
}
