terraform {
  required_version = ">= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}
variable "endpoint" { type = string }
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  endpoints {
    ecr = var.endpoint
    sts = var.endpoint
  }
}
data "aws_ecr_authorization_token" "application" {}
output "authorization" {
  value     = data.aws_ecr_authorization_token.application
  sensitive = true
}
