data "aws_cloudwatch_log_data_protection_policy_document" "application" {
  name = var.name
  statement {
    data_identifiers = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
    operation {
      audit {
        findings_destination {
          cloudwatch_logs {
            log_group = aws_cloudwatch_log_group.application.name
          }
        }
      }
    }
  }
  statement {
    data_identifiers = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
    operation {
      deidentify {
        mask_config {}
      }
    }
  }
}
output "provider_policy_document" {
  value = data.aws_cloudwatch_log_data_protection_policy_document.application.json
}
