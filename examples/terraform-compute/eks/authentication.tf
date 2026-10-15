terraform {
  required_version = ">= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}
variable "name" { type = string }
# This provider only signs a token. It sends no AWS HTTP request and owns no
# resource. The lifecycle provider discovers its account through local STS.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
data "aws_eks_cluster_auth" "compute" { name = var.name }
output "token" {
  value     = data.aws_eks_cluster_auth.compute.token
  sensitive = true
}
