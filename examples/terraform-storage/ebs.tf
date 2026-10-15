variable "source_snapshot_id" {
  type = string
  default = ""
}
resource "aws_ebs_snapshot_copy" "data" {
  source_snapshot_id = var.source_snapshot_id
  source_region = var.region
  description = var.name
  tags = { Revision = var.revision }
}
resource "aws_ebs_snapshot_block_public_access" "data" {
  state = var.revision == "initial" ? "block-new-sharing" : "block-all-sharing"
}
output "ebs" {
  value = { public_access_state = aws_ebs_snapshot_block_public_access.data.state, snapshot_id = aws_ebs_snapshot_copy.data.id }
}
