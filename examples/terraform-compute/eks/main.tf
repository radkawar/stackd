terraform {
  required_version = ">= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}
variable "endpoint" { type = string }
variable "name" { type = string }
variable "revision" { type = string }
variable "vpc_cidr" { type = string }
variable "subnet_a_cidr" { type = string }
variable "subnet_b_cidr" { type = string }

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  endpoints {
    ec2 = var.endpoint
    eks = var.endpoint
    iam = var.endpoint
    sts = var.endpoint
  }
}
resource "aws_iam_role" "cluster" {
  name = "${var.name}-cluster"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "eks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
# The native cluster admission reads authoritative subnet and SG dependencies.
# Broader AmazonEKSClusterPolicy actions are not needed by this local baseline.
resource "aws_iam_role_policy" "cluster" {
  name = "cluster-network-read"
  role = aws_iam_role.cluster.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"], Resource = "*" }]
  })
}
resource "aws_iam_role" "access" {
  name = "${var.name}-access"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::738492615083:root" }, Action = "sts:AssumeRole" }]
  })
}
data "aws_iam_role" "cluster" { name = aws_iam_role.cluster.name }
data "aws_iam_role" "access" { name = aws_iam_role.access.name }
resource "aws_vpc" "compute" { cidr_block = var.vpc_cidr }
resource "aws_subnet" "a" {
  vpc_id            = aws_vpc.compute.id
  cidr_block        = var.subnet_a_cidr
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "b" {
  vpc_id            = aws_vpc.compute.id
  cidr_block        = var.subnet_b_cidr
  availability_zone = "us-east-1b"
}
# These are real EC2 dependency records. The current k3s adapter does not put
# its pods into this VPC or enforce these SGs on Kubernetes traffic.
resource "aws_security_group" "compute" {
  name   = var.name
  vpc_id = aws_vpc.compute.id
}
resource "aws_eks_cluster" "compute" {
  depends_on                    = [aws_iam_role_policy.cluster]
  name                          = var.name
  role_arn                      = data.aws_iam_role.cluster.arn
  version                       = "1.33"
  bootstrap_self_managed_addons = true
  deletion_protection           = false
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }
  vpc_config {
    subnet_ids              = [aws_subnet.a.id, aws_subnet.b.id]
    security_group_ids      = [aws_security_group.compute.id]
    endpoint_public_access  = true
    endpoint_private_access = false
  }
  tags = { revision = var.revision }
}
resource "aws_eks_access_entry" "compute" {
  cluster_name  = aws_eks_cluster.compute.name
  principal_arn = data.aws_iam_role.access.arn
  type          = "STANDARD"
  tags          = { revision = var.revision }
}
resource "aws_eks_access_policy_association" "compute" {
  cluster_name  = aws_eks_cluster.compute.name
  principal_arn = aws_eks_access_entry.compute.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
  access_scope { type = "cluster" }
}
data "aws_eks_addon_version" "compute" {
  addon_name         = "coredns"
  kubernetes_version = aws_eks_cluster.compute.version
  most_recent        = true
}
resource "aws_eks_addon" "compute" {
  cluster_name                = aws_eks_cluster.compute.name
  addon_name                  = "coredns"
  addon_version               = data.aws_eks_addon_version.compute.version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  configuration_values        = jsonencode({ replicaCount = 1 })
  tags                        = { revision = var.revision }
}
data "aws_eks_cluster" "compute" { name = aws_eks_cluster.compute.name }
data "aws_eks_clusters" "compute" { depends_on = [aws_eks_cluster.compute] }
data "aws_eks_access_entry" "compute" {
  cluster_name  = aws_eks_cluster.compute.name
  principal_arn = aws_eks_access_entry.compute.principal_arn
}
data "aws_eks_access_policies" "compute" {}
data "aws_eks_addon" "compute" {
  cluster_name = aws_eks_cluster.compute.name
  addon_name   = aws_eks_addon.compute.addon_name
}
output "compute" {
  sensitive = true
  value = {
    name             = aws_eks_cluster.compute.name
    endpoint         = data.aws_eks_cluster.compute.endpoint
    ca               = data.aws_eks_cluster.compute.certificate_authority[0].data
    listed_clusters  = data.aws_eks_clusters.compute.names
    access_principal = data.aws_eks_access_entry.compute.principal_arn
    addon_version    = data.aws_eks_addon.compute.addon_version
  }
}
