#!/usr/bin/env python3
"""Exercise AppSync through the actual executable and real service data planes."""
import argparse
import base64
import datetime
import io
import json
import os
from pathlib import Path
import socket
import threading
import time
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
import requests
import websocket
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

from stackd_process import StackdProcess

RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
SCHEMA = '''
type Record @aws_api_key @aws_iam @aws_cognito_user_pools {id:ID!,title:String!}
input RecordInput {id:ID!,title:String!}
type Query { get(id:ID!):Record @aws_api_key @aws_iam @aws_cognito_user_pools, whoami:String @aws_cognito_user_pools }
type Mutation {put(input:RecordInput!):Record, invoke(input:RecordInput!):Record, remote(input:RecordInput!):Record, sql(input:RecordInput!):Record}
type Subscription {changed(id:ID):Record @aws_subscribe(mutations:["put"])}
schema {query:Query,mutation:Mutation,subscription:Subscription}
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Application:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state / "state.sqlite"
        require(not self.database.exists(), "Use a new isolated state directory")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.name = "appsync-proof-" + uuid.uuid4().hex[:10]
        self.controller = StackdProcess(self.state)
        self.report = {"name": self.name, "observations": {}, "controllers": self.controller.runs, "cleanup": {}}
        self.clients = {service: self.client(service) for service in ("appsync", "iam", "dynamodb", "lambda", "rds", "rds-data", "secretsmanager", "cognito-idp")}
        self.roles, self.apis, self.users = [], [], []
        self.table = self.function = self.cluster = self.writer = self.secret = self.pool = None
        self.http = None
        self.socket = None

    def client(self, service, key="test", secret="test", region="us-east-1"):
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region, aws_access_key_id=key, aws_secret_access_key=secret,
                            config=Config(retries={"max_attempts": 0}, connect_timeout=3, read_timeout=90))

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"0.0.0.0:{self.port}", "-public-endpoint", self.endpoint,
                   "-database", str(self.database), "-docker-host", self.args.docker_host, "-lambda-runtime", "-dynamodb-runtime", "-rds-runtime",
                   "-compute-endpoint", f"http://host.docker.internal:{self.port}"]
        if self.args.telemetry_directory:
            command += ["-lambda-telemetry-directory", self.args.telemetry_directory]
        environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        self.controller.start(command, self.endpoint, environment=environment, timeout=90)

    @staticmethod
    def wait(action, label, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = action()
            if value:
                return value
            time.sleep(0.2)
        raise TimeoutError(label)

    def wait_database(self):
        rds = self.clients["rds"]
        self.wait(lambda: rds.describe_db_instances(DBInstanceIdentifier=self.writer)["DBInstances"][0]["DBInstanceStatus"] == "available", "PostgreSQL writer ready")
        return self.wait(lambda: next((c for c in rds.describe_db_clusters(DBClusterIdentifier=self.cluster)["DBClusters"] if c["Status"] == "available"), None), "cluster ready")

    def role(self, suffix, service, actions):
        iam = self.clients["iam"]
        name = self.name + "-" + suffix
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        self.roles.append(name)
        iam.put_role_policy(RoleName=name, PolicyName="allow", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}))
        return arn

    def graphql(self, document, variables=None, auth=None, expect_errors=False):
        payload = {"query": document, "variables": variables or {}}
        headers = {"x-api-key": self.key} if auth is None else dict(auth)
        headers["content-type"] = "application/json"
        response = requests.post(self.graphql_url, json=payload, headers=headers, timeout=60)
        body = response.json()
        if expect_errors:
            require(bool(body.get("errors")), f"Expected GraphQL rejection: {body}")
        else:
            require(response.status_code == 200 and not body.get("errors"), f"GraphQL failed: {response.status_code} {body}")
        return body

    def receive(self, kind, identifier=None):
        while True:
            message = json.loads(self.socket.recv())
            if message["type"] == kind and (identifier is None or message.get("id") == identifier):
                return message
            if message["type"] in ("error", "connection_error"):
                raise AssertionError(str(message))

    def workflows(self):
        app, ddb, functions, rds, data, sm, cognito = [self.clients[n] for n in ("appsync", "dynamodb", "lambda", "rds", "rds-data", "secretsmanager", "cognito-idp")]
        source_role = self.role("sources", "appsync.amazonaws.com", ["dynamodb:*", "lambda:InvokeFunction", "rds-data:*", "secretsmanager:GetSecretValue", "kms:Decrypt"])
        function_role = self.role("lambda", "lambda.amazonaws.com", ["dynamodb:PutItem", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"])
        self.table = self.name
        ddb.create_table(TableName=self.table, AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}], KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST")
        self.wait(lambda: ddb.describe_table(TableName=self.table)["Table"]["TableStatus"] == "ACTIVE", "DynamoDB active")
        self.pool = cognito.create_user_pool(PoolName=self.name)["UserPool"]["Id"]
        client_id = cognito.create_user_pool_client(UserPoolId=self.pool, ClientName=self.name, ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])["UserPoolClient"]["ClientId"]
        password = "Owned!" + uuid.uuid4().hex
        cognito.admin_create_user(UserPoolId=self.pool, Username="reader", MessageAction="SUPPRESS")
        cognito.admin_set_user_password(UserPoolId=self.pool, Username="reader", Password=password, Permanent=True)
        token = cognito.initiate_auth(ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH", AuthParameters={"USERNAME": "reader", "PASSWORD": password})["AuthenticationResult"]["IdToken"]
        created = app.create_graphql_api(name=self.name, authenticationType="API_KEY", additionalAuthenticationProviders=[{"authenticationType": "AWS_IAM"}, {"authenticationType": "AMAZON_COGNITO_USER_POOLS", "userPoolConfig": {"userPoolId": self.pool, "awsRegion": "us-east-1"}}])["graphqlApi"]
        self.api_id = created["apiId"]
        self.apis.append(self.api_id)
        self.graphql_url = created["uris"]["GRAPHQL"]
        require(self.graphql_url.startswith(self.endpoint + "/"), "API URI did not use advertised endpoint")
        app.start_schema_creation(apiId=self.api_id, definition=SCHEMA.encode())
        require(app.get_schema_creation_status(apiId=self.api_id)["status"] == "SUCCESS", "schema activation failed")
        self.key = app.create_api_key(apiId=self.api_id)["apiKey"]["id"]
        app.create_data_source(apiId=self.api_id, name="ddb", type="AMAZON_DYNAMODB", serviceRoleArn=source_role, dynamodbConfig={"tableName": self.table, "awsRegion": "us-east-1"})
        app.create_data_source(apiId=self.api_id, name="none", type="NONE")
        self.resolver("Query", "get", "ddb", "import {util} from '@aws-appsync/utils';export function request(ctx){return {operation:'GetItem',key:util.dynamodb.toMapValues({id:ctx.args.id}),consistentRead:true};}export function response(ctx){if(ctx.error){util.error(ctx.error.message,ctx.error.type);}return ctx.result;}")
        self.resolver("Query", "whoami", "none", "export function request(ctx){return {payload:ctx.identity.username+':'+ctx.request.headers['x-appsync-proof']+':'+(ctx.request.headers.cookie===undefined)};}export function response(ctx){return ctx.result;}")
        fn = app.create_function(apiId=self.api_id, name="write", dataSourceName="ddb", runtime=RUNTIME, code="import {util} from '@aws-appsync/utils';export function request(ctx){return {operation:'PutItem',key:util.dynamodb.toMapValues({id:ctx.prev.result.id}),attributeValues:util.dynamodb.toMapValues({title:ctx.stash.title})};}export function response(ctx){if(ctx.error){util.error(ctx.error.message,ctx.error.type);}return ctx.result;}")["functionConfiguration"]["functionId"]
        app.create_resolver(apiId=self.api_id, typeName="Mutation", fieldName="put", kind="PIPELINE", runtime=RUNTIME, code="export function request(ctx){ctx.stash.title=ctx.args.input.title+'!';return ctx.args.input;}export function response(ctx){return ctx.prev.result;}", pipelineConfig={"functions": [fn]})
        auth = {"host": requests.utils.urlparse(self.graphql_url).netloc, "x-api-key": self.key}
        realtime = created["uris"]["REALTIME"].replace("http://", "ws://").replace("https://", "wss://")
        self.socket = websocket.create_connection(realtime + "?header=" + base64.b64encode(json.dumps(auth).encode()).decode() + "&payload=e30=", subprotocols=["graphql-ws"], timeout=20)
        self.socket.send(json.dumps({"type": "connection_init"}))
        self.receive("connection_ack")
        self.socket.send(json.dumps({"id": "owned", "type": "start", "payload": {"data": json.dumps({"query": 'subscription {changed(id:"one"){id title}}'}), "extensions": {"authorization": auth}}}))
        self.receive("start_ack", "owned")
        put = self.graphql('mutation {put(input:{id:"one",title:"stored"}){id title}}')["data"]["put"]
        event = self.receive("data", "owned")["payload"]["data"]["changed"]
        require(put == event == {"id": "one", "title": "stored!"}, "mutation/subscription mismatch")
        actual = ddb.get_item(TableName=self.table, Key={"id": {"S": "one"}}, ConsistentRead=True)["Item"]
        require(actual["title"]["S"] == "stored!", "GraphQL mutation did not write the native DynamoDB item")
        self.report["observations"]["dynamodbPipelineSubscription"] = {"mutation": put, "event": event, "nativeTitle": actual["title"]["S"]}
        with Client(transport=RequestsHTTPTransport(url=self.graphql_url, headers={"x-api-key": self.key}, timeout=30), fetch_schema_from_transport=True) as graph:
            selected = graph.execute(gql("query Read($id:ID!){get(id:$id){id title}}"), variable_values={"id": "one"})
        require(selected["get"] == put, "unmodified gql client query differs from native mutation")
        self.report["observations"]["graphqlClient"] = {"library": "gql", "version": "3.5.3", "schemaIntrospection": True, "variables": True, "query": selected}
        self.socket.send(json.dumps({"id": "owned", "type": "stop"})); self.receive("complete", "owned");self.socket.close();self.socket = None
        require(self.graphql("{whoami}", auth={"Authorization": token, "x-appsync-proof": "visible", "Cookie": "excluded=value"})["data"]["whoami"] == "reader:visible:true", "Cognito identity or native request header context missing")
        self.report["observations"]["resolverRequestHeaders"] = {"customHeader": True, "cookieExcluded": True}
        self.graphql('{get(id:"one"){id}}', auth={"x-api-key": "wrong"}, expect_errors=True)
        self.graphql('{get(id:"one"){id}}', auth={"Authorization": token[:-3] + "bad"}, expect_errors=True)
        self.report["observations"]["cognito"] = {"signedIDToken": True, "tamperedTokenDenied": True, "wrongAPIKeyDenied": True}
        self.iam_workflow(created["arn"])
        self.clients["iam"].put_role_policy(RoleName=self.name + "-sources", PolicyName="deny", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "dynamodb:PutItem", "Resource": "*"}]}))
        self.graphql('mutation {put(input:{id:"denied",title:"must not exist"}){id}}', expect_errors=True)
        require("Item" not in ddb.get_item(TableName=self.table, Key={"id": {"S": "denied"}}), "Denied data-source write leaked")
        self.clients["iam"].delete_role_policy(RoleName=self.name + "-sources", PolicyName="deny")
        self.report["observations"]["currentRoleAuthority"] = {"deniedPut": True, "noNativeWrite": True}
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("handler.py", "import os,boto3\ndef handler(event,context):\n    boto3.client('dynamodb').put_item(TableName=os.environ['TABLE'],Item={'id':{'S':event['id']},'title':{'S':event['title']+'-lambda'}})\n    return {'id':event['id'],'title':event['title']+'-lambda'}\n")
        self.function = self.name
        function_arn = functions.create_function(FunctionName=self.function, Role=function_role, Runtime="python3.13", Handler="handler.handler", Timeout=20, Code={"ZipFile": archive.getvalue()}, Environment={"Variables": {"TABLE": self.table, "AWS_ENDPOINT_URL": f"http://host.docker.internal:{self.port}"}})["FunctionArn"]
        self.wait(lambda: functions.get_function_configuration(FunctionName=self.function).get("State") == "Active", "Lambda active")
        app.create_data_source(apiId=self.api_id, name="lambda", type="AWS_LAMBDA", serviceRoleArn=source_role, lambdaConfig={"lambdaFunctionArn": function_arn})
        self.resolver("Mutation", "invoke", "lambda", "import {util} from '@aws-appsync/utils';export function request(ctx){return {operation:'Invoke',payload:ctx.args.input};}export function response(ctx){if(ctx.error){util.error(ctx.error.message,ctx.error.type);}return ctx.result;}")
        output = self.graphql('mutation {invoke(input:{id:"runtime",title:"real"}){id title}}')["data"]["invoke"]
        require(output["title"] == "real-lambda" and ddb.get_item(TableName=self.table, Key={"id": {"S": "runtime"}})["Item"]["title"]["S"] == "real-lambda", "real Lambda side effect absent")
        self.report["observations"]["lambdaRuntime"] = output
        self.http_workflow(source_role)
        self.cluster = self.name
        rds.create_db_cluster(DBClusterIdentifier=self.cluster, Engine="aurora-postgresql", DatabaseName="appdb", MasterUsername="owner", MasterUserPassword=password, EnableHttpEndpoint=True)
        self.writer = self.name + "-writer"
        rds.create_db_instance(DBInstanceIdentifier=self.writer, DBClusterIdentifier=self.cluster, Engine="aurora-postgresql", DBInstanceClass="db.t3.small")
        cluster = self.wait_database()
        self.secret = sm.create_secret(Name=self.name, SecretString=json.dumps({"username": "owner", "password": password}))["ARN"]
        arn = cluster["DBClusterArn"]
        data.execute_statement(resourceArn=arn, secretArn=self.secret, database="appdb", sql="CREATE TABLE records (id TEXT PRIMARY KEY, title TEXT NOT NULL)")
        app.create_data_source(apiId=self.api_id, name="sql", type="RELATIONAL_DATABASE", serviceRoleArn=source_role, relationalDatabaseConfig={"relationalDatabaseSourceType": "RDS_HTTP_ENDPOINT", "rdsHttpEndpointConfig": {"awsRegion": "us-east-1", "dbClusterIdentifier": arn, "databaseName": "appdb", "awsSecretStoreArn": self.secret}})
        self.resolver("Mutation", "sql", "sql", "import {util} from '@aws-appsync/utils';export function request(ctx){return {statements:['INSERT INTO records (id,title) VALUES (:id,:title) RETURNING id,title'],variableMap:{':id':ctx.args.input.id,':title':ctx.args.input.title}};}export function response(ctx){if(ctx.error){util.error(ctx.error.message,ctx.error.type);}const row=JSON.parse(ctx.result).sqlStatementResults[0].records[0];return {id:row[0].stringValue,title:row[1].stringValue};}")
        output = self.graphql('mutation {sql(input:{id:"engine",title:"postgres"}){id title}}')["data"]["sql"]
        rows = data.execute_statement(resourceArn=arn, secretArn=self.secret, database="appdb", sql="SELECT title FROM records WHERE id='engine'")["records"]
        require(output["title"] == rows[0][0]["stringValue"] == "postgres", "RDS data-source write missing")
        self.report["observations"]["postgresEngine"] = output
        self.controller.stop(timeout=60);self.start()
        self.wait_database()
        require(app.get_graphql_api(apiId=self.api_id)["graphqlApi"]["apiId"] == self.api_id, "API control state lost")
        require(self.graphql('{get(id:"one"){id title}}')["data"]["get"] == put, "resolver/key/DynamoDB state lost across restart")
        require(data.execute_statement(resourceArn=arn, secretArn=self.secret, database="appdb", sql="SELECT title FROM records WHERE id='engine'")["records"] == rows, "RDS engine rows lost")
        self.report["observations"]["restart"] = {"api": True, "schema": True, "resolvers": True, "functions": True, "apiKey": True, "dynamodb": True, "postgres": True}
        for isolated in (self.client("appsync", region="us-west-2"), self.client("appsync", key="111111111111")):
            try:
                isolated.get_graphql_api(apiId=self.api_id)
            except ClientError as error:
                require(error.response["Error"]["Code"] == "NotFoundException", str(error))
            else:
                raise AssertionError("control API scope leaked")
        self.report["observations"]["scopeIsolation"] = True

    def resolver(self, parent, field, source, code):
        self.clients["appsync"].create_resolver(apiId=self.api_id, typeName=parent, fieldName=field, dataSourceName=source, runtime=RUNTIME, code=code)

    def iam_workflow(self, arn):
        iam = self.clients["iam"]
        user = self.name
        iam.create_user(UserName=user)
        self.users.append(user)
        key = iam.create_access_key(UserName=user)["AccessKey"]
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "appsync:GraphQL", "Resource": arn + "/types/Query/fields/get"}]}
        iam.put_user_policy(UserName=user, PolicyName="query", PolicyDocument=json.dumps(policy))
        raw = json.dumps({"query": '{get(id:"one"){id title}}'})
        def signed():
            request = AWSRequest(method="POST", url=self.graphql_url, data=raw, headers={"content-type": "application/json"})
            SigV4Auth(Credentials(key["AccessKeyId"], key["SecretAccessKey"]), "appsync", "us-east-1").add_auth(request)
            return requests.post(self.graphql_url, data=raw, headers=dict(request.headers), timeout=30).json()
        require(signed()["data"]["get"]["title"] == "stored!", "root-field IAM grant failed nested selection")
        iam.delete_user_policy(UserName=user, PolicyName="query")
        require(bool(signed().get("errors")), "current IAM policy revocation ignored")
        iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
        self.report["observations"]["signedIAM"] = {"rootFieldGrant": True, "nestedSelection": True, "livePolicyRevocation": True}

    def http_workflow(self, source_role):
        effects = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["content-length"])))
                effects.append(payload)
                payload["title"] += "-http"
                encoded = json.dumps(payload).encode()
                self.send_response(200);self.send_header("content-type", "application/json");self.send_header("content-length", str(len(encoded)));self.end_headers();self.wfile.write(encoded)
            def log_message(self, *args):
                pass
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.clients["appsync"].create_data_source(apiId=self.api_id, name="http", type="HTTP", httpConfig={"endpoint": f"http://127.0.0.1:{self.http.server_port}"})
        self.resolver("Mutation", "remote", "http", "export function request(ctx){return {method:'POST',resourcePath:'/write',params:{headers:{'content-type':'application/json'},body:JSON.stringify(ctx.args.input)}};}export function response(ctx){return JSON.parse(ctx.result.body);}")
        result = self.graphql('mutation {remote(input:{id:"http",title:"actual"}){id title}}')["data"]["remote"]
        require(len(effects) == 1 and result == {"id": "http", "title": "actual-http"}, "HTTP resolver did not perform its request")
        self.report["observations"]["http"] = result

    def cleanup(self):
        if self.socket:
            self.socket.close()
        if self.controller.process and self.controller.process.poll() is None:
            for api in self.apis:
                self.clients["appsync"].delete_graphql_api(apiId=api)
            if self.function:
                self.clients["lambda"].delete_function(FunctionName=self.function)
                logs = self.client("logs")
                group = "/aws/lambda/" + self.function
                if any(item["logGroupName"] == group for item in logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])):
                    logs.delete_log_group(logGroupName=group)
            if self.writer:
                self.clients["rds"].delete_db_instance(DBInstanceIdentifier=self.writer, SkipFinalSnapshot=True)
                self.wait(lambda: not self.clients["rds"].describe_db_instances()["DBInstances"], "writer deletion")
            if self.cluster:
                self.clients["rds"].delete_db_cluster(DBClusterIdentifier=self.cluster, SkipFinalSnapshot=True)
                self.wait(lambda: not self.clients["rds"].describe_db_clusters()["DBClusters"], "cluster deletion")
            if self.secret:
                self.clients["secretsmanager"].delete_secret(SecretId=self.secret, ForceDeleteWithoutRecovery=True)
            if self.pool:
                self.clients["cognito-idp"].delete_user_pool(UserPoolId=self.pool)
            if self.table:
                self.clients["dynamodb"].delete_table(TableName=self.table)
            for user in self.users:
                iam = self.clients["iam"]
                for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
                    iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
                for policy in iam.list_user_policies(UserName=user)["PolicyNames"]:
                    iam.delete_user_policy(UserName=user, PolicyName=policy)
                iam.delete_user(UserName=user)
            for role in self.roles:
                for policy in self.clients["iam"].list_role_policies(RoleName=role)["PolicyNames"]:
                    self.clients["iam"].delete_role_policy(RoleName=role, PolicyName=policy)
                self.clients["iam"].delete_role(RoleName=role)
            self.report["cleanup"]["resourcesDeleted"] = True
        if self.http:
            self.http.shutdown();self.http.server_close()
        self.controller.stop(timeout=60)
        self.report["cleanup"]["controllersStopped"] = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--telemetry-directory")
    args = parser.parse_args()
    app = Application(args)
    try:
        app.start();app.workflows()
    except Exception as error:
        app.report["failure"] = str(error)
        raise
    finally:
        try:
            app.cleanup()
        finally:
            (app.state / "report.json").write_text(json.dumps(app.report, indent=2) + "\n")
            print(json.dumps({"report": str(app.state / "report.json"), "observations": app.report["observations"], "cleanup": app.report["cleanup"]}))


if __name__ == "__main__":
    main()
