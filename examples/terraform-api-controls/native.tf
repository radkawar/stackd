variable "table_name" { type = string }
variable "cluster_arn" { type = string }
variable "secret_arn" { type = string }
variable "pool_id" { type = string }
variable "pool_client_id" { type = string }
variable "jwt_issuer" { type = string }
locals {
  graphql_schema = <<-GRAPHQL
    type Query {
      http(input: String!): String! @aws_iam @aws_cognito_user_pools @aws_oidc
      direct(input: String!): String! @aws_iam @aws_cognito_user_pools
    }
    type Mutation {
      put(input: String!): String! @aws_iam @aws_api_key
      sql(input: String!): String! @aws_iam
    }
    type Subscription {
      changed: String! @aws_subscribe(mutations: ["put"]) @aws_api_key
    }
    schema { query: Query, mutation: Mutation, subscription: Subscription }
  GRAPHQL
}
resource "aws_appsync_api_key" "proof" { api_id = aws_appsync_graphql_api.proof.id }
resource "aws_appsync_datasource" "ddb" {
  api_id = aws_appsync_graphql_api.proof.id
  name = "ddb"
  type = "AMAZON_DYNAMODB"
  description = var.revision
  service_role_arn = var.appsync_role_arn
  dynamodb_config {
    table_name = var.table_name
    region = "us-east-1"
  }
}
resource "aws_appsync_resolver" "ddb" {
  api_id = aws_appsync_graphql_api.proof.id
  type = "Mutation"
  field = "put"
  data_source = aws_appsync_datasource.ddb.name
  runtime {
    name = "APPSYNC_JS"
    runtime_version = "1.0.0"
  }
  code = "import {util} from '@aws-appsync/utils'; export function request(ctx) {return {operation:'PutItem',key:util.dynamodb.toMapValues({id:ctx.args.input}),attributeValues:util.dynamodb.toMapValues({value:'${var.revision}:'+ctx.args.input})};} export function response(ctx) {if(ctx.error){util.error(ctx.error.message,ctx.error.type);}return ctx.result.value;}"
}
resource "aws_appsync_datasource" "sql" {
  api_id = aws_appsync_graphql_api.proof.id
  name = "sql"
  type = "RELATIONAL_DATABASE"
  description = var.revision
  service_role_arn = var.appsync_role_arn
  relational_database_config {
    source_type = "RDS_HTTP_ENDPOINT"
    http_endpoint_config {
      region = "us-east-1"
      db_cluster_identifier = var.cluster_arn
      database_name = "appdb"
      aws_secret_store_arn = var.secret_arn
    }
  }
}
resource "aws_appsync_resolver" "sql" {
  api_id = aws_appsync_graphql_api.proof.id
  type = "Mutation"
  field = "sql"
  data_source = aws_appsync_datasource.sql.name
  runtime {
    name = "APPSYNC_JS"
    runtime_version = "1.0.0"
  }
  code = "import {util} from '@aws-appsync/utils';export function request(ctx){return {statements:['INSERT INTO records (id,value) VALUES (:id,:value) RETURNING value'],variableMap:{':id':ctx.args.input,':value':'${var.revision}:'+ctx.args.input}};}export function response(ctx){if(ctx.error){util.error(ctx.error.message,ctx.error.type);}return JSON.parse(ctx.result).sqlStatementResults[0].records[0][0].stringValue;}"
}
resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id = aws_apigatewayv2_api.proof.id
  name = "${var.name}-jwt-${var.revision}"
  authorizer_type = "JWT"
  identity_sources = ["$request.header.Authorization"]
  jwt_configuration {
    issuer = var.jwt_issuer
    audience = [var.pool_client_id]
  }
}
resource "aws_apigatewayv2_route" "jwt" {
  api_id = aws_apigatewayv2_api.proof.id
  route_key = "POST /jwt"
  authorization_type = "JWT"
  authorizer_id = aws_apigatewayv2_authorizer.jwt.id
  target = "integrations/${aws_apigatewayv2_integration.proof.id}"
}
