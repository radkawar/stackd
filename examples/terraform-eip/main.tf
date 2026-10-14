terraform {
  required_version = ">= 1.5.0, < 2.0.0"
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
    error_message = "Only an explicit IPv4 loopback HTTP endpoint is permitted."
  }
}

variable "name" {
  type = string
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true

  endpoints {
    ec2 = var.endpoint
    iam = var.endpoint
    sts = var.endpoint
  }
}

resource "aws_eip" "proof" {
  count  = 2
  domain = "vpc"
  tags = {
    Name = "${var.name}-${count.index}"
  }
}

output "addresses" {
  value = [for address in aws_eip.proof : {
    allocation_id = address.allocation_id
    public_ip     = address.public_ip
    ptr_record    = address.ptr_record
  }]
}
