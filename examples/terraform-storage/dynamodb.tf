resource "aws_dynamodb_table" "data" {
  name = "${var.name}-ddb"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "pk"
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "group"
    type = "S"
  }
  global_secondary_index {
    name = "by-group"
    hash_key = "group"
    projection_type = "ALL"
  }
  stream_enabled = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  tags = { Revision = var.revision }
}
resource "aws_dynamodb_table_item" "data" {
  table_name = aws_dynamodb_table.data.name
  hash_key = aws_dynamodb_table.data.hash_key
  item = jsonencode({ pk = { S = "terraform" }, group = { S = "fixture" }, revision = { S = var.revision } })
}
data "aws_dynamodb_table" "current" {
  name = aws_dynamodb_table.data.name
}
data "aws_dynamodb_table_item" "current" {
  table_name = aws_dynamodb_table.data.name
  key = jsonencode({ pk = { S = "terraform" } })
  depends_on = [aws_dynamodb_table_item.data]
}
output "dynamodb" {
  value = {
    table = aws_dynamodb_table.data.name, stream_arn = aws_dynamodb_table.data.stream_arn
    lookup_arn = data.aws_dynamodb_table.current.arn, lookup_item = jsondecode(data.aws_dynamodb_table_item.current.item)
  }
}
