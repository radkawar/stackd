resource "aws_s3_bucket" "data" {
  bucket = var.name
  force_destroy = true
  tags = { Revision = var.revision }
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls = true
  ignore_public_acls = true
  block_public_policy = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_cors_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  cors_rule {
    allowed_methods = ["GET", "HEAD"]
    allowed_origins = ["https://${var.revision}.example.invalid"]
    allowed_headers = ["*"]
    expose_headers = ["ETag"]
    max_age_seconds = 60
  }
}
resource "aws_s3_object" "data" {
  bucket = aws_s3_bucket.data.id
  key = "terraform.txt"
  content = "storage-${var.revision}"
  server_side_encryption = "AES256"
  depends_on = [aws_s3_bucket_versioning.data, aws_s3_bucket_ownership_controls.data, aws_s3_bucket_server_side_encryption_configuration.data]
}
resource "aws_s3_object_copy" "data" {
  bucket = aws_s3_bucket.data.id
  key = "copied.txt"
  source = "${aws_s3_bucket.data.id}/${aws_s3_object.data.key}?versionId=${aws_s3_object.data.version_id}"
  server_side_encryption = "AES256"
}
resource "aws_s3_account_public_access_block" "data" {
  account_id = var.account_id
  block_public_acls = true
  ignore_public_acls = true
  block_public_policy = true
  restrict_public_buckets = true
}
resource "aws_s3_access_point" "data" {
  bucket = aws_s3_bucket.data.id
  name = "${var.name}-ap"
  account_id = var.account_id
  public_access_block_configuration {
    block_public_acls = true
    ignore_public_acls = true
    block_public_policy = true
    restrict_public_buckets = true
  }
}
resource "aws_s3control_access_point_policy" "data" {
  access_point_arn = aws_s3_access_point.data.arn
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid = "Read${var.revision}", Effect = "Allow",
    Principal = { AWS = "arn:aws:iam::${var.account_id}:root" },
    Action = ["s3:GetObject"], Resource = "${aws_s3_access_point.data.arn}/object/*"
  }] })
}
data "aws_s3_bucket" "current" {
  bucket = aws_s3_bucket.data.id
}
data "aws_s3_object" "current" {
  bucket = aws_s3_bucket.data.id
  key = aws_s3_object.data.key
  download_body = true
}
output "s3" {
  value = {
    bucket = aws_s3_bucket.data.id, access_point = aws_s3_access_point.data.name, access_point_arn = aws_s3_access_point.data.arn
    lookup_arn = data.aws_s3_bucket.current.arn, lookup_body_base64 = data.aws_s3_object.current.body_base64
  }
}
