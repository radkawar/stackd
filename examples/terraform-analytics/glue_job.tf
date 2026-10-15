# run.py copies this file into the owned workspace only with --glue-job.
# That flag requires the installed Glue Spark and Python images and operator
# acceptance of compute/glue/AWS-GLUE-LICENSE.txt. No job runtime is synthesized.
resource "aws_iam_role" "glue" {
  name = "${var.name}-glue"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "glue.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy" "glue" {
  name = "analytics"
  role = aws_iam_role.glue.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"], Resource = [aws_s3_bucket.lake.arn, "${aws_s3_bucket.lake.arn}/*"] }]
  })
}
resource "aws_s3_object" "job" {
  bucket  = aws_s3_bucket.lake.bucket
  key     = "scripts/producer.py"
  content = <<-PYTHON
    import argparse
    import json
    import boto3
    parser = argparse.ArgumentParser()
    parser.add_argument('--bucket', required=True)
    parser.add_argument('--revision', required=True, type=int)
    args, _ = parser.parse_known_args()
    body = json.dumps({'producer': 'real-glue-python-shell', 'revision': args.revision}).encode() + b'\n'
    boto3.client('s3').put_object(Bucket=args.bucket, Key='glue/revision-' + str(args.revision) + '.json', Body=body)
    print('real-glue-producer-complete', flush=True)
  PYTHON
}
resource "aws_glue_job" "producer" {
  name         = "${var.name}-producer"
  role_arn     = aws_iam_role.glue.arn
  description  = "Real Python shell revision ${var.revision}"
  execution_class = "STANDARD"
  max_capacity = 0.0625
  max_retries  = 0
  timeout      = 2
  command {
    name            = "pythonshell"
    python_version  = "3.9"
    script_location = "s3://${aws_s3_bucket.lake.bucket}/${aws_s3_object.job.key}"
  }
  default_arguments = { "--bucket" = aws_s3_bucket.lake.bucket, "--revision" = tostring(var.revision), "--library-set" = "none" }
  tags = local.tags
  depends_on = [aws_iam_role_policy.glue]
}
output "glue_job" { value = aws_glue_job.producer.name }
