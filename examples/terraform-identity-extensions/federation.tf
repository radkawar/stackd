variable "federation_issuer_url" {
  type = string
}

variable "federation_thumbprint" {
  type = string
}

resource "aws_iam_openid_connect_provider" "federation" {
  url             = var.federation_issuer_url
  client_id_list  = ["${var.name}-${var.revision}"]
  thumbprint_list = var.revision == "v1" ? [var.federation_thumbprint] : [var.federation_thumbprint, "0000000000000000000000000000000000000000"]
  tags            = { Name = "${var.name}-oidc", Revision = var.revision }
}

resource "aws_iam_saml_provider" "federation" {
  name                   = "${var.name}-saml"
  saml_metadata_document = file("${var.artifact_directory}/federation/saml-${var.revision}.xml")
  tags                   = { Revision = var.revision }
}

resource "aws_iam_outbound_web_identity_federation" "federation" {}

resource "aws_ssm_parameter" "federation" {
  name  = "/${var.name}/federation"
  type  = "String"
  value = "signed-federation-consumer-${var.revision}"
}

resource "aws_iam_role" "federation_oidc" {
  name        = "${var.name}-oidc"
  description = "OIDC signed consumer ${var.revision}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Action = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = aws_iam_openid_connect_provider.federation.arn }
      Condition = { StringEquals = {
        "${trimprefix(var.federation_issuer_url, "https://")}:aud" = "${var.name}-${var.revision}"
        "${trimprefix(var.federation_issuer_url, "https://")}:sub" = "local-signed-subject"
      } }
    }]
  })
}

resource "aws_iam_role" "federation_saml" {
  name        = "${var.name}-saml"
  description = "SAML signed consumer ${var.revision}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Action = "sts:AssumeRoleWithSAML"
      Principal = { Federated = aws_iam_saml_provider.federation.arn }
      Condition = { StringEquals = { "SAML:aud" = "https://signin.aws.amazon.com/saml" } }
    }]
  })
}

resource "aws_iam_role_policy" "federation_oidc" {
  name = "${var.name}-federation-consumer"
  role = aws_iam_role.federation_oidc.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "ssm:GetParameter", Resource = aws_ssm_parameter.federation.arn },
      { Effect = "Allow", Action = ["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken"], Resource = "arn:aws:sts::${var.account_id}:self" }
    ]
  })
}

resource "aws_iam_role_policy" "federation_saml" {
  name   = aws_iam_role_policy.federation_oidc.name
  role   = aws_iam_role.federation_saml.id
  policy = aws_iam_role_policy.federation_oidc.policy
}

output "federation" {
  value = {
    account_id    = var.account_id
    audience      = "${var.name}-${var.revision}"
    issuer_url    = var.federation_issuer_url
    oidc_arn      = aws_iam_openid_connect_provider.federation.arn
    saml_arn      = aws_iam_saml_provider.federation.arn
    outbound_url  = aws_iam_outbound_web_identity_federation.federation.issuer_identifier
    parameter     = aws_ssm_parameter.federation.name
    oidc_role     = aws_iam_role.federation_oidc.name
    oidc_role_arn = aws_iam_role.federation_oidc.arn
    saml_role     = aws_iam_role.federation_saml.name
    saml_role_arn = aws_iam_role.federation_saml.arn
    policy_name   = aws_iam_role_policy.federation_oidc.name
  }
}
