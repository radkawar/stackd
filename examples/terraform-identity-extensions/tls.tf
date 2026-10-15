variable "tls_vpc_cidr" { type = string }
variable "tls_subnet_cidrs" { type = list(string) }
variable "tls_ready" {
  type = bool
  default = false
}
variable "tls_certificate_body" {
  type = string
  default = null
}

resource "aws_vpc" "identity_tls" {
  cidr_block = var.tls_vpc_cidr
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_subnet" "identity_tls" {
  count = 2
  vpc_id = aws_vpc.identity_tls.id
  cidr_block = var.tls_subnet_cidrs[count.index]
  availability_zone = count.index == 0 ? "us-east-1a" : "us-east-1b"
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_security_group" "identity_tls" {
  name = "${var.name}-tls"
  description = "Actual verified IAM certificate TLS consumer"
  vpc_id = aws_vpc.identity_tls.id
  ingress {
    protocol = "tcp"
    from_port = 8443
    to_port = 8443
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
resource "aws_lb" "identity_tls" {
  depends_on = [aws_iam_service_linked_role.elb]
  name = "id-tls-${substr(var.name, length(var.name) - 10, 10)}"
  internal = true
  load_balancer_type = "application"
  ip_address_type = "ipv4"
  subnets = aws_subnet.identity_tls[*].id
  security_groups = [aws_security_group.identity_tls.id]
  enable_http2 = false
  preserve_host_header = true
  idle_timeout = 60
  tags = { Fixture = var.name, Revision = var.revision }
}
# A real DNS name must exist before issuing a matching certificate. The runner
# creates the network/LB first, then supplies genuine material and enables these.
resource "aws_iam_server_certificate" "identity_tls" {
  count = var.tls_ready ? 1 : 0
  name = "${var.name}-tls-${var.revision}"
  path = "/identity-tls/${var.revision}/"
  certificate_body = var.tls_certificate_body
  private_key = var.credential_material.server_private_key
  tags = { Fixture = var.name, Revision = var.certificate_tag_revision }
  lifecycle { ignore_changes = [private_key] }
}
resource "aws_lb_listener" "identity_tls" {
  count = var.tls_ready ? 1 : 0
  load_balancer_arn = aws_lb.identity_tls.arn
  port = 8443
  protocol = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn = aws_iam_server_certificate.identity_tls[0].arn
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code = "200"
      message_body = "real-iam-tls-${var.revision}"
    }
  }
  tags = { Fixture = var.name, Revision = var.revision }
}
output "tls" {
  value = {
    vpc = aws_vpc.identity_tls.id
    subnets = aws_subnet.identity_tls[*].id
    group = aws_security_group.identity_tls.id
    load_balancer = aws_lb.identity_tls.arn
    dns_name = aws_lb.identity_tls.dns_name
    listener = try(aws_lb_listener.identity_tls[0].arn, null)
    certificate_name = try(aws_iam_server_certificate.identity_tls[0].name, null)
    certificate_id = try(aws_iam_server_certificate.identity_tls[0].id, null)
    certificate_arn = try(aws_iam_server_certificate.identity_tls[0].arn, null)
    revision = var.revision
  }
}
