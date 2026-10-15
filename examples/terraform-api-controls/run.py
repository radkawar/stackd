"""Run current-provider API controls with real authorization, sockets and database effects."""

import base64
import contextlib
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, urlencode
import uuid
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
import websocket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (REGION, arguments, client, controller, environment,
                   expect_missing, require, workspace)

STORAGE = "ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"
RUNTIME = "public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3"
DYNAMODB = "amazon/dynamodb-local@sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab"
POSTGRES = "postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652"
MYSQL = "mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d"
ROOT = Credentials("test", "test")
HANDLER = '''import json
import uuid

def invoke(event, context):
    if event.get('type') in ('TOKEN', 'REQUEST'):
        headers = {key.lower(): value for key, value in (event.get('headers') or {}).items()}
        token = event.get('authorizationToken') or headers.get('authorization') or (event.get('queryStringParameters') or {}).get('token', '')
        allowed = token.startswith('allow')
        stamp = str(uuid.uuid4())
        if event.get('version') == '2.0':
            return {'isAuthorized': allowed, 'context': {'stamp': stamp}}
        return {'principalId': 'reader', 'context': {'stamp': stamp}, 'policyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow' if allowed else 'Deny', 'Action': 'execute-api:Invoke', 'Resource': event['methodArn']}]}}
    if 'info' in event and 'arguments' in event:
        return 'lambda:' + event['arguments']['input']
    data = json.loads(event.get('body') or '{}')
    authorizer = (event.get('requestContext') or {}).get('authorizer') or {}
    authorizer = authorizer.get('lambda', authorizer)
    result = {'nonce': data.get('nonce'), 'revision': (event.get('stageVariables') or {}).get('revision'), 'stamp': authorizer.get('stamp'), 'connection_id': (event.get('requestContext') or {}).get('connectionId')}
    print(json.dumps({'consumer_nonce': data.get('nonce'), 'result': result}))
    return {'statusCode': 200, 'headers': {'content-type': 'application/json'}, 'body': json.dumps(result)}
'''


def wait_value(action, label, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        value = action()
        if value:
            return value
        require(time.monotonic() < deadline, label + " timed out")
        time.sleep(0.2)


def main():
    parser = arguments(__doc__, 14803)
    parser.add_argument("--dns-port", type=int, default=15803)
    parser.add_argument("--http-port", type=int, default=16803)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    args = parser.parse_args()
    for binary in ("terraform", "docker", "dig", "psql", "openssl"):
        require(shutil.which(binary), f"Install {binary} first")
    require(args.docker_host.startswith("unix:///"), "Use an explicit local Docker Unix socket")
    require(len({args.port, args.dns_port, args.http_port}) == 3, "Use distinct owned ports")
    for port in (args.dns_port, args.http_port):
        require(1024 <= port <= 65535, "Use unprivileged ports")
        for protocol in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(type=protocol) as probe:
                probe.bind(("127.0.0.1", port))
    for image in (STORAGE, RUNTIME, DYNAMODB, POSTGRES, MYSQL):
        subprocess.run(["docker", "--host", args.docker_host, "image", "inspect", image],
                       check=True, stdout=subprocess.DEVNULL)
    helper = args.stackd.resolve().parent / "lambda-telemetry-amd64"
    require(helper.is_file(), f"Prepare the Linux telemetry helper: {helper}")
    root = workspace(args, "terraform-api-controls")
    root.chmod(0o700)
    account = str(100000000000 + uuid.uuid4().int % 900000000000)
    evidence = {"account": account, "terraform": "1.16.6", "provider": "6.68.0",
                "binary": str(args.stackd.resolve()),
                "binary_sha256": hashlib.sha256(args.stackd.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "helper_sha256": hashlib.sha256((Path(__file__).resolve().parents[1] / "local.py").read_bytes()).hexdigest(),
                "fixture_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in Path(__file__).resolve().parent.glob("*.tf")},
                "commands": [], "completed": [], "success": False}

    def record(stage):
        evidence["completed"].append(stage)
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    source = Path(__file__).resolve().parent
    for path in source.glob("*.tf"):
        shutil.copyfile(path, root / path.name)
    env = environment()
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror does not exist")
        configuration += ("provider_installation {\n filesystem_mirror {\n path = "
                          + json.dumps(str(args.provider_mirror.resolve()))
                          + '\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\n')
    (root / "terraform.rc").write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        result = subprocess.run(["terraform", *command], cwd=root, env=env, check=False,
                                text=True, capture_output=True)
        number = len(evidence["commands"])
        output_path = root / f"terraform-{number:03d}.log"
        output_path.write_text(result.stdout + result.stderr)
        evidence["commands"].append({"argv": ["terraform", *command], "returncode": result.returncode,
                                     "log": output_path.name})
        if not capture:
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", file=sys.stderr, flush=True)
        if check:
            result.check_returncode()
        return result

    require(json.loads(terraform("version", "-json", capture=True).stdout)["terraform_version"] == "1.16.6",
            "Use official Terraform1.16.6, not a downgraded binary")
    name = "stackd-api-controls-" + uuid.uuid4().hex[:12]
    effects = []
    issuer = f"https://127.0.0.1:{args.http_port}/oidc"
    oidc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = oidc_key.public_key().public_numbers()

    def encoded_integer(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    jwks = {"keys": [{"kty": "RSA", "kid": "owned", "use": "sig", "alg": "RS256",
                     "n": encoded_integer(public.n), "e": encoded_integer(public.e)}]}

    def oidc_token():
        instant = int(time.time())
        header = {"alg": "RS256", "kid": "owned"}
        claims = {"iss": issuer, "sub": "owned-reader", "aud": "owned-graph-client",
                  "iat": instant, "auth_time": instant, "exp": instant + 3600}
        segments = [base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
                    for value in (header, claims)]
        unsigned = ".".join(segments).encode()
        signature = oidc_key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
        return unsigned.decode() + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")

    # The actual HTTP data source and OIDC issuer share an owned TLS listener.
    # Go's ordinary verifier trusts this exact CA through its documented root
    # store environment, not an insecure transport or a metadata-only issuer.
    ca, certificate, key = root / "source-ca.pem", root / "source.pem", root / "source.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=stackd-api-controls", "-keyout", str(root / "source-ca.key"), "-out", str(ca),
                    "-addext", "basicConstraints=critical,CA:TRUE"], check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
                    "-keyout", str(key), "-out", str(root / "source.csr")], check=True, capture_output=True)
    (root / "source.ext").write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
                                   "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    subprocess.run(["openssl", "x509", "-req", "-in", str(root / "source.csr"), "-CA", str(ca),
                    "-CAkey", str(root / "source-ca.key"), "-CAcreateserial", "-days", "2",
                    "-extfile", str(root / "source.ext"), "-out", str(certificate)], check=True, capture_output=True)
    empty_ca = root / "empty-ca-directory"
    empty_ca.mkdir()
    previous_ssl = {name: os.environ.get(name) for name in ("SSL_CERT_FILE", "SSL_CERT_DIR")}
    os.environ.update(SSL_CERT_FILE=str(ca), SSL_CERT_DIR=str(empty_ca))
    env.update(SSL_CERT_FILE=str(ca), SSL_CERT_DIR=str(empty_ca))

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/oidc/.well-known/openid-configuration":
                value = {"issuer": issuer, "jwks_uri": issuer + "/keys",
                         "id_token_signing_alg_values_supported": ["RS256"]}
            elif self.path == "/oidc/keys":
                value = jwks
            else:
                self.send_error(404)
                return
            data = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            require(self.path == "/echo", "Unexpected HTTP data-source path")
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size < 65536, "Unexpected HTTP data-source request length")
            value = json.loads(self.rfile.read(size))
            effects.append(value)
            data = json.dumps({"value": value["revision"] + ":" + value["input"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *unused):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", args.http_port), Origin)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, key)
    origin.socket = tls.wrap_socket(origin.socket, server_side=True)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    extra = ["-dns-listen", f"127.0.0.1:{args.dns_port}", "-docker-host", args.docker_host,
             "-oidc-discovery", "-lambda-runtime", "-lambda-telemetry-directory", str(helper.parent), "-dynamodb-runtime",
             "-rds-runtime", "-rds-postgres-image", POSTGRES, "-rds-mysql-image", MYSQL,
             "-compute-endpoint", f"http://host.docker.internal:{args.port}"]
    try:
        with contextlib.ExitStack() as controllers:
            endpoint = controllers.enter_context(controller(args, root, extra, containers=True, account=account))
            sdk = {service: client(service, endpoint) for service in
                   ("iam", "lambda", "apigateway", "apigatewayv2", "appsync", "route53", "logs",
                    "dynamodb", "rds", "rds-data", "secretsmanager", "cognito-idp")}
            roles, groups = [], []
            function = table = cluster = writer = secret = pool = user_key = user = None
            outputs = None
            socket_connection = graph_connection = None
            variables = None
            password = "Owned!" + uuid.uuid4().hex

            def request(path, data=None, headers=None, credentials=None, service="execute-api", method=None):
                require(path.startswith("/") and not path.startswith("//"), "Use an owned request path")
                method = method or ("POST" if data is not None else "GET")
                headers = {"Content-Type": "application/json", **(headers or {})}
                if credentials is not None:
                    signed = AWSRequest(method=method, url=endpoint + path, data=data, headers=headers)
                    SigV4Auth(credentials, service, REGION).add_auth(signed)
                    headers = dict(signed.headers)
                parsed = urlsplit(endpoint)
                connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=60)
                try:
                    connection.request(method, path, body=data, headers=headers)
                    response = connection.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                finally:
                    connection.close()

            def dns(label, kind, expected, tcp=False):
                result = subprocess.check_output(["dig", "@127.0.0.1", "-p", str(args.dns_port), label, kind,
                                                  "+time=2", "+tries=1", "+short", *(["+tcp"] if tcp else [])], text=True)
                require(sorted(result.strip().splitlines()) == sorted(expected), f"Actual DNS answer for {label}: {result!r}")

            def role(suffix, principal, actions=None):
                role_name = name + "-" + suffix
                roles.append(role_name)
                arn = sdk["iam"].create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({
                    "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                                                            "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
                if actions:
                    sdk["iam"].put_role_policy(RoleName=role_name, PolicyName="allow", PolicyDocument=json.dumps({
                        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}))
                return arn

            def graphql(document, nonce, auth=None, expect_errors=False):
                require(outputs["graphql_url"].startswith(endpoint + "/"), "GraphQL URI escaped the owned endpoint")
                data = json.dumps({"query": document, "variables": {"input": nonce}})
                status, _, body = request(urlsplit(outputs["graphql_url"]).path, data,
                                           headers=auth, credentials=ROOT if auth is None else None, service="appsync")
                result = json.loads(body)
                if expect_errors:
                    require(status in (200, 401, 403) and bool(result.get("errors")), f"Expected GraphQL denial: {status} {result}")
                else:
                    require(status == 200 and not result.get("errors"), f"Actual GraphQL failure: {status} {result}")
                return result

            def sql_row(nonce):
                writer_state = sdk["rds"].describe_db_instances(DBInstanceIdentifier=writer)["DBInstances"][0]
                address = writer_state["Endpoint"]
                require(address["Address"] == "127.0.0.1", "Native SQL endpoint is not owned loopback")
                pg_env = env.copy()
                pg_env.update(PGPASSWORD=password, PGSSLMODE="disable", PGSERVICEFILE=os.devnull,
                              PGPASSFILE=os.devnull, PGOPTIONS="")
                actual = subprocess.check_output(["psql", "-h", address["Address"], "-p", str(address["Port"]),
                                                  "-U", "owner", "-d", "appdb", "-v", "ON_ERROR_STOP=1", "-A", "-t",
                                                  "-c", "SELECT value FROM records WHERE id='" + nonce + "'"],
                                                 env=pg_env, text=True)
                return actual.strip()

            def log_messages(group):
                result = []
                token = None
                for unused in range(20):
                    parameters = {"logGroupName": group, "limit": 1000}
                    if token:
                        parameters["nextToken"] = token
                    output = sdk["logs"].filter_log_events(**parameters)
                    result.extend(row["message"] for row in output.get("events", []))
                    token = output.get("nextToken")
                    if not token:
                        return result
                raise RuntimeError("Owned log read exceeded20pages")

            def socket_echo(revision):
                nonce = uuid.uuid4().hex
                socket_connection.send(json.dumps({"action": "echo", "nonce": nonce}))
                value = json.loads(socket_connection.recv())
                require(value["nonce"] == nonce and value["revision"] == revision and value["connection_id"],
                        f"Actual WebSocket Lambda reply differs: {value}")
                return value["connection_id"]

            def receive_graph(kind, identifier=None):
                for unused in range(10):
                    value = json.loads(graph_connection.recv())
                    require(value["type"] not in ("error", "connection_error"), f"Subscription failed: {value}")
                    if value["type"] == kind and (identifier is None or value.get("id") == identifier):
                        return value
                raise RuntimeError("GraphQL subscription exceeded10frames")

            def consume(revision):
                nonce = uuid.uuid4().hex
                data = json.dumps({"nonce": nonce})
                rest_path = f"/_stackd/execute-api/{outputs['rest_id']}/live/protected"
                http_path = f"/_stackd/execute-api/{outputs['http_id']}/live/protected"
                for path in (rest_path, http_path, f"/_stackd/execute-api/{outputs['rest_id']}/live/request",
                             f"/_stackd/execute-api/{outputs['http_id']}/live/request1"):
                    status, _, body = request(path, data)
                    require(status == 401, f"Missing authorizer identity was not401: {status} {body!r}")
                    status, _, body = request(path, data, {"Authorization": "deny-" + revision})
                    require(status == 403, f"Real Lambda policy denial was not403: {status} {body!r}")
                    stamp = None
                    for unused in range(2):
                        status, _, body = request(path, data, {"Authorization": "allow-" + revision})
                        value = json.loads(body)
                        require(status == 200 and value["nonce"] == nonce and value["revision"] == revision and value["stamp"],
                                f"Authorized real Lambda output: {status} {body!r}")
                        require(stamp is None or stamp == value["stamp"], "A repeated identity did not use the60-second authorizer cache")
                        stamp = value["stamp"]
                    if path == rest_path:
                        sdk["apigateway"].flush_stage_authorizers_cache(restApiId=outputs["rest_id"], stageName="live")
                        status, _, body = request(path, data, {"Authorization": "allow-" + revision})
                        require(status == 200 and json.loads(body)["stamp"] != stamp, "Stage authorizer flush did not invoke real Lambda again")
                for path in (f"/_stackd/execute-api/{outputs['rest_id']}/live/cognito",
                             f"/_stackd/execute-api/{outputs['http_id']}/live/jwt"):
                    status, _, body = request(path, data, {"Authorization": id_token})
                    require(status == 200 and json.loads(body)["nonce"] == nonce, f"Current Cognito/JWT request failed: {status} {body!r}")
                    status, _, body = request(path, data, {"Authorization": id_token[:-4] + "bad!"})
                    require(status == 401, f"Tampered Cognito/JWT token was accepted: {status} {body!r}")
                status, _, body = request(f"/_stackd/execute-api/{outputs['imported_id']}/live/imported")
                require(status == 200 and json.loads(body) == {"revision": revision}, f"Swagger deployment output: {status} {body!r}")
                graph = graphql("query Read($input:String!){http(input:$input) direct(input:$input)}", nonce)
                require(graph["data"] == {"http": revision + ":" + nonce, "direct": "lambda:" + nonce}, f"External GraphQL sources: {graph}")
                require({"input": nonce, "revision": revision} in effects, "GraphQL did not reach the actual HTTP source")
                graph = graphql("query Read($input:String!){http(input:$input)}", nonce, {"Authorization": id_token})
                require(graph["data"] == {"http": revision + ":" + nonce}, "GraphQL Cognito authentication did not consume the HTTP source")
                graph = graphql("query Read($input:String!){http(input:$input)}", nonce, {"Authorization": oidc_token()})
                require(graph["data"] == {"http": revision + ":" + nonce}, "Verified OIDC token did not consume the TLS HTTP source")
                token = oidc_token()
                graphql("query Read($input:String!){http(input:$input)}", nonce, {"Authorization": token[:-4] + "bad!"}, expect_errors=True)
                graph = graphql("mutation Put($input:String!){put(input:$input)}", nonce)
                expected = revision + ":" + nonce
                require(graph["data"] == {"put": expected}, f"DynamoDB resolver mutation: {graph}")
                require(sdk["dynamodb"].get_item(TableName=table, Key={"id": {"S": nonce}}, ConsistentRead=True)["Item"]["value"]["S"] == expected,
                        "Actual native DynamoDB item does not match the GraphQL mutation")
                delivered = receive_graph("data", "owned")["payload"]
                require(delivered == {"data": {"changed": expected}}, f"Actual GraphQL subscription differs: {delivered}")
                graph = graphql("mutation SQL($input:String!){sql(input:$input)}", nonce)
                require(graph["data"] == {"sql": expected} and sql_row(nonce) == expected,
                        "GraphQL SQL mutation did not write the independently consumed PostgreSQL row")
                socket_echo(revision)
                for tcp in (False, True):
                    dns("address." + outputs["zone_name"], "A", ["192.0.2.10" if revision == "first" else "192.0.2.20"], tcp)
                    dns("text." + outputs["zone_name"], "TXT", [json.dumps(revision)], tcp)
                    dns("weighted." + outputs["zone_name"], "A", ["192.0.2.30"], tcp)
                    zone = outputs["zone_name"].rstrip(".") + "."
                    dns("ipv6." + zone, "AAAA", ["2001:db8::1"], tcp)
                    dns("ptr." + zone, "PTR", ["address." + zone], tcp)
                    dns("mail." + zone, "MX", ["10 address." + zone], tcp)
                    dns("_service._tcp." + zone, "SRV", ["10 20 443 address." + zone], tcp)
                    dns("certificate." + zone, "CAA", ['0 issue "ca.example.test"'], tcp)
                    dns("multi." + zone, "A", ["192.0.2.50", "192.0.2.51"], tcp)
                    referral = subprocess.check_output(["dig", "@127.0.0.1", "-p", str(args.dns_port), "leaf.delegate." + zone,
                        "A", "+time=2", "+tries=1", "+norecurse", "+noall", "+authority", "+additional", *(["+tcp"] if tcp else [])], text=True)
                    require("NS" in referral and "nameserver.delegate." + zone in referral and "127.0.0.1" in referral,
                            f"Actual NS referral/glue is missing: {referral!r}")
                    native_records = sdk["route53"].list_resource_record_sets(HostedZoneId=outputs["zone_id"])["ResourceRecordSets"]
                    soa = next(row["ResourceRecords"][0]["Value"] for row in native_records if row["Type"] == "SOA")
                    dns(zone, "SOA", [soa], tcp)
                    dns("alias." + outputs["zone_name"], "CNAME", ["address." + outputs["zone_name"].rstrip(".") + "."], tcp)
                for left, right in (("read_rest_id", "rest_id"), ("read_resource_id", "rest_resource_id"),
                                    ("read_authorizer_id", "rest_authorizer_id"), ("read_key_id", "key_id"),
                                    ("read_http_id", "http_id"), ("read_zone_id", "zone_id")):
                    require(outputs[left] == outputs[right], f"Current-provider data source identity mismatch: {left}")
                require(outputs["rest_authorizer_id"] in outputs["read_authorizer_ids"] and len(outputs["read_authorizer_ids"]) == 3,
                        "Authorizer collection does not retain TOKEN/REQUEST/Cognito owners")
                require(outputs["http_id"] in outputs["read_http_ids"] and outputs["zone_id"] in outputs["read_zone_ids"]
                        and outputs["read_key_count"] == 1 and outputs["read_record_count"] == 16,
                        "Current-provider grouped API/key/zone/record reads differ")
                print(f"Consumed {revision}: TOKEN/REQUEST/JWT/Cognito and OIDC authority,60-second caches, Swagger, real sockets, TLS HTTP/Lambda/DynamoDB/PostgreSQL GraphQL, subscription and UDP/TCP DNS types/routing", flush=True)
                record("consume-" + revision)

            try:
                lambda_role = role("lambda", "lambda.amazonaws.com", ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"])
                source_role = role("sources", "appsync.amazonaws.com", ["dynamodb:PutItem", "lambda:InvokeFunction", "rds-data:ExecuteStatement", "secretsmanager:GetSecretValue", "kms:Decrypt"])
                log_roles = [role("logs" + str(index), "apigateway.amazonaws.com", ["logs:CreateLogGroup", "logs:CreateLogStream",
                             "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:PutLogEvents", "logs:GetLogEvents", "logs:FilterLogEvents"]) for index in range(2)]
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
                    package.writestr("handler.py", HANDLER)
                function = name
                function_arn = sdk["lambda"].create_function(FunctionName=function, Role=lambda_role, Runtime="python3.12",
                    Handler="handler.invoke", Code={"ZipFile": archive.getvalue()}, Timeout=15, MemorySize=256)["FunctionArn"]
                sdk["lambda"].add_permission(FunctionName=function, StatementId="apigateway", Action="lambda:InvokeFunction",
                    Principal="apigateway.amazonaws.com", SourceArn=f"arn:aws:execute-api:{REGION}:{account}:*")
                wait_value(lambda: sdk["lambda"].get_function_configuration(FunctionName=function).get("State") == "Active", "Real Lambda active")
                group = name + "-access"
                sdk["logs"].create_log_group(logGroupName=group)
                groups.append(group)
                group_arn = next(row["arn"] for row in sdk["logs"].describe_log_groups(logGroupNamePrefix=group)["logGroups"] if row["logGroupName"] == group)
                table = name
                sdk["dynamodb"].create_table(TableName=table, AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                    KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST")
                wait_value(lambda: sdk["dynamodb"].describe_table(TableName=table)["Table"]["TableStatus"] == "ACTIVE", "Native DynamoDB active")
                cluster = name
                sdk["rds"].create_db_cluster(DBClusterIdentifier=cluster, Engine="aurora-postgresql", EngineVersion="17.11",
                    DatabaseName="appdb", MasterUsername="owner", MasterUserPassword=password, EnableHttpEndpoint=True)
                writer = name + "-writer"
                sdk["rds"].create_db_instance(DBInstanceIdentifier=writer, DBClusterIdentifier=cluster, Engine="aurora-postgresql", DBInstanceClass="db.t3.medium")
                wait_value(lambda: sdk["rds"].describe_db_instances(DBInstanceIdentifier=writer)["DBInstances"][0]["DBInstanceStatus"] == "available", "Native PostgreSQL writer")
                cluster_state = wait_value(lambda: next((row for row in sdk["rds"].describe_db_clusters(DBClusterIdentifier=cluster)["DBClusters"] if row["Status"] == "available"), None), "Native PostgreSQL cluster")
                secret = sdk["secretsmanager"].create_secret(Name=name, SecretString=json.dumps({"username": "owner", "password": password}))["ARN"]
                sdk["rds-data"].execute_statement(resourceArn=cluster_state["DBClusterArn"], secretArn=secret, database="appdb",
                                                sql="CREATE TABLE records (id TEXT PRIMARY KEY, value TEXT NOT NULL)")
                pool_state = sdk["cognito-idp"].create_user_pool(PoolName=name)["UserPool"]
                pool = pool_state["Id"]
                pool_client = sdk["cognito-idp"].create_user_pool_client(UserPoolId=pool, ClientName=name,
                    ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])["UserPoolClient"]["ClientId"]
                sdk["cognito-idp"].admin_create_user(UserPoolId=pool, Username="reader", MessageAction="SUPPRESS")
                sdk["cognito-idp"].admin_set_user_password(UserPoolId=pool, Username="reader", Password=password, Permanent=True)
                id_token = sdk["cognito-idp"].initiate_auth(ClientId=pool_client, AuthFlow="USER_PASSWORD_AUTH",
                    AuthParameters={"USERNAME": "reader", "PASSWORD": password})["AuthenticationResult"]["IdToken"]
                claims = json.loads(base64.urlsafe_b64decode(id_token.split(".")[1] + "=="))
                require(claims["iss"] == endpoint + "/" + pool, "JWT issuer escaped the configured local Cognito owner")
                variables = {"endpoint": endpoint, "name": name, "revision": "first", "function_arn": function_arn,
                             "appsync_role_arn": source_role, "log_role_arns": log_roles, "log_group_arn": group_arn,
                             "http_origin": f"https://127.0.0.1:{args.http_port}", "table_name": table,
                             "cluster_arn": cluster_state["DBClusterArn"], "secret_arn": secret, "pool_id": pool,
                             "pool_arn": pool_state["Arn"], "pool_client_id": pool_client, "jwt_issuer": claims["iss"],
                             "oidc_issuer": issuer}
                variable_file = root / "terraform.tfvars.json"
                variable_file.write_text(json.dumps(variables))
                terraform("init", "-input=false")
                terraform("apply", "-input=false", "-auto-approve")
                outputs = json.loads(terraform("output", "-json", "proof", capture=True).stdout)
                execution_group = "API-Gateway-Execution-Logs_" + outputs["rest_id"] + "/live"
                groups.extend([execution_group, "/aws/lambda/" + function])
                def connect_consumers():
                    nonlocal socket_connection, graph_connection
                    socket_url = endpoint.replace("http://", "ws://", 1) + f"/_stackd/execute-api/{outputs['ws_id']}/live"
                    for query, expected in (("", 401), ("?token=deny", 403)):
                        try:
                            unexpected = websocket.create_connection(socket_url + query, timeout=60, http_proxy_host=None)
                        except websocket.WebSocketBadStatusException as error:
                            require(error.status_code == expected, f"WebSocket authorization denial: {error.status_code}")
                        else:
                            unexpected.close()
                            raise AssertionError("Unauthorized WebSocket upgrade succeeded")
                    socket_connection = websocket.create_connection(socket_url + "?token=allow", timeout=60, http_proxy_host=None)
                    api_key = sdk["appsync"].list_api_keys(apiId=outputs["graphql_id"])["apiKeys"][0]["id"]
                    auth = {"host": urlsplit(endpoint).netloc, "x-api-key": api_key}
                    encoded_auth = base64.b64encode(json.dumps(auth).encode()).decode()
                    graph_url = outputs["graphql_url"].replace("http://", "ws://", 1) + "/realtime?" + urlencode({"header": encoded_auth, "payload": "e30="})
                    graph_connection = websocket.create_connection(graph_url, timeout=60, subprotocols=["graphql-ws"], http_proxy_host=None)
                    graph_connection.send(json.dumps({"type": "connection_init"}))
                    receive_graph("connection_ack")
                    graph_connection.send(json.dumps({"id": "owned", "type": "start", "payload": {
                        "data": json.dumps({"query": "subscription{changed}"}), "extensions": {"authorization": auth}}}))
                    receive_graph("start_ack", "owned")

                connect_consumers()
                consume("first")
                print("Completed current-provider create and real consumer stages", flush=True)
                record("create")

                # Method settings act on the live stage without deployment.
                throttle_patch = [{"op": "replace", "path": "/*/POST/throttling/burstLimit", "value": "0"},
                                  {"op": "replace", "path": "/*/POST/throttling/rateLimit", "value": "0"}]
                sdk["apigateway"].update_stage(restApiId=outputs["rest_id"], stageName="live", patchOperations=throttle_patch)
                status, _, body = request(f"/_stackd/execute-api/{outputs['rest_id']}/live/protected", json.dumps({"nonce": "throttled"}), {"Authorization": "allow-first"})
                require(status == 429, f"Zero live-stage throttle did not reject invocation: {status} {body!r}")
                # Remove the extra per-POST setting. Terraform repairs the owned
                # wildcard setting separately; no ignored changes or fake credit.
                sdk["apigateway"].update_stage(restApiId=outputs["rest_id"], stageName="live", patchOperations=[{"op": "remove", "path": "/*/POST"}])

                iam_path = f"/_stackd/execute-api/{outputs['rest_id']}/live/iam"
                user = name + "-reader"
                sdk["iam"].create_user(UserName=user)
                user_key = sdk["iam"].create_access_key(UserName=user)["AccessKey"]
                credentials = Credentials(user_key["AccessKeyId"], user_key["SecretAccessKey"])
                iam_data = json.dumps({"nonce": "iam-current"})
                require(request(iam_path, iam_data)[0] == 403 and request(iam_path, iam_data, credentials=credentials)[0] == 403,
                        "Unsigned/ungranted IAM invocation was not denied")
                sdk["iam"].put_user_policy(UserName=user, PolicyName="invoke", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Action": "execute-api:Invoke", "Resource": f"arn:aws:execute-api:{REGION}:{account}:{outputs['rest_id']}/live/POST/iam"}]}))
                require(request(iam_path, iam_data, credentials=credentials)[0] == 200, "Current IAM grant did not allow the real Lambda invocation")
                sdk["iam"].delete_user_policy(UserName=user, PolicyName="invoke")
                require(request(iam_path, iam_data, credentials=credentials)[0] == 403, "Deleted current IAM grant remained effective")

                log_nonce = uuid.uuid4().hex
                status, headers, _ = request(f"/_stackd/execute-api/{outputs['rest_id']}/live/protected", json.dumps({"nonce": log_nonce}), {"Authorization": "allow-first"})
                require(status == 200, "Logged invocation failed")
                request_id = next(value for key, value in headers.items() if key.lower() == "x-amzn-requestid")
                wait_value(lambda: any(request_id in row and '"status":"200"' in row for row in log_messages(group)), "Actual request-correlated access row")
                wait_value(lambda: any(log_nonce in row for row in log_messages(execution_group)), "Actual execution trace body")
                sdk["iam"].put_role_policy(RoleName=name + "-logs0", PolicyName="deny", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                    "Effect": "Deny", "Action": "logs:PutLogEvents", "Resource": "*"}]}))
                denied_nonce = uuid.uuid4().hex
                require(request(f"/_stackd/execute-api/{outputs['rest_id']}/live/protected", json.dumps({"nonce": denied_nonce}), {"Authorization": "allow-first"})[0] == 200,
                        "Best-effort Logs denial changed the client response")
                require(not any(denied_nonce in row for row in log_messages(execution_group)), "Current Logs role denial still ingested the execution body")
                sdk["iam"].delete_role_policy(RoleName=name + "-logs0", PolicyName="deny")
                print("Consumed current IAM revocation, live method throttle and real Logs/current role authority", flush=True)
                record("current-iam-throttle-logs")

                denied_nonce = uuid.uuid4().hex
                sdk["iam"].put_role_policy(RoleName=name + "-sources", PolicyName="deny", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                    "Effect": "Deny", "Action": "dynamodb:PutItem", "Resource": "*"}]}))
                graphql("mutation Put($input:String!){put(input:$input)}", denied_nonce, expect_errors=True)
                require("Item" not in sdk["dynamodb"].get_item(TableName=table, Key={"id": {"S": denied_nonce}}, ConsistentRead=True),
                        "Denied AppSync source-role write reached native DynamoDB")
                sdk["iam"].delete_role_policy(RoleName=name + "-sources", PolicyName="deny")
                record("current-appsync-role-denial")

                rogue = "rogue." + outputs["zone_name"]
                sdk["route53"].change_resource_record_sets(HostedZoneId=outputs["zone_id"], ChangeBatch={"Changes": [{"Action": "CREATE", "ResourceRecordSet": {
                    "Name": rogue, "Type": "A", "TTL": 30, "ResourceRecords": [{"Value": "192.0.2.99"}]}}]})
                dns(rogue, "A", ["192.0.2.99"])
                terraform("apply", "-input=false", "-auto-approve")
                dns(rogue, "A", [])
                print("Consumed records_exclusive reconciliation through actual DNS deletion", flush=True)
                record("records-exclusive-reconciliation")

                # Route responses are deployment snapshots, not immediate socket
                # flags. Preserve an open connection across both publications.
                sdk["apigatewayv2"].delete_route_response(ApiId=outputs["ws_id"], RouteId=outputs["ws_route_id"], RouteResponseId=outputs["ws_response_id"])
                socket_echo("first")
                without_response = sdk["apigatewayv2"].create_deployment(ApiId=outputs["ws_id"])["DeploymentId"]
                sdk["apigatewayv2"].update_stage(ApiId=outputs["ws_id"], StageName="live", DeploymentId=without_response)
                socket_connection.settimeout(1)
                socket_connection.send(json.dumps({"action": "echo", "nonce": "no-route-response"}))
                try:
                    socket_connection.recv()
                except websocket.WebSocketTimeoutException:
                    pass
                else:
                    raise AssertionError("New deployment without route response still delivered a Lambda reply")
                socket_connection.settimeout(60)
                wait_value(lambda: any('"consumer_nonce": "no-route-response"' in row for row in log_messages("/aws/lambda/" + function)),
                           "Actual backend invocation without a deployed route response")
                terraform("apply", "-input=false", "-auto-approve")
                outputs = json.loads(terraform("output", "-json", "proof", capture=True).stdout)
                connection_id = socket_echo("first")
                management = f"/_stackd/execute-api/{outputs['ws_id']}/live/@connections/{connection_id}"
                require(request(management, credentials=ROOT)[0] == 200, "Management get did not see the actual socket")
                require(request(management, "must-not-deliver", credentials=credentials)[0] == 403, "Ungrantable management callback was accepted")
                callback = json.dumps({"callback": uuid.uuid4().hex})
                require(request(management, callback, credentials=ROOT)[0] == 200, "Signed management POST failed")
                require(socket_connection.recv() == callback, "Management POST did not deliver the exact socket frame")
                print("Consumed WebSocket authorizer, response deployment boundary and signed management frame delivery", flush=True)
                record("websocket-deployed-response-and-management")

                imports = (("aws_api_gateway_account.proof", outputs["account_id"]),
                           ("aws_api_gateway_authorizer.proof", outputs["rest_id"] + "/" + outputs["rest_authorizer_id"]),
                           ("aws_api_gateway_authorizer.cognito", outputs["rest_id"] + "/" + outputs["rest_cognito_authorizer_id"]),
                           ("aws_api_gateway_method_settings.proof", outputs["rest_id"] + "/live/*/*"),
                           ("aws_apigatewayv2_authorizer.proof", outputs["http_id"] + "/" + outputs["http_authorizer_id"]),
                           ("aws_apigatewayv2_route_response.socket", outputs["ws_id"] + "/" + outputs["ws_route_id"] + "/" + outputs["ws_response_id"]),
                           ("aws_appsync_datasource.http", outputs["graphql_id"] + "-http"),
                           ("aws_route53_records_exclusive.proof", outputs["zone_id"]))
                for address, identifier in imports:
                    backup = root / "before-import.tfstate"
                    backup.write_text(terraform("state", "pull", capture=True).stdout)
                    terraform("state", "rm", address)
                    try:
                        terraform("import", "-input=false", address, identifier)
                    except BaseException:
                        terraform("state", "push", "-force", str(backup))
                        raise
                record("eight-imports")
                require(terraform("plan", "-input=false", "-detailed-exitcode", check=False).returncode == 0,
                        "Imported existing control resources do not produce a strict no-op")
                outputs = json.loads(terraform("output", "-json", "proof", capture=True).stdout)
                consume("first")
                print("Completed eight imports, refresh and strict no-op with real consumers", flush=True)
                before = outputs.copy()
                variables["revision"] = "second"
                variable_file.write_text(json.dumps(variables))
                terraform("apply", "-input=false", "-auto-approve")
                outputs = json.loads(terraform("output", "-json", "proof", capture=True).stdout)
                for field in ("rest_id", "imported_id", "http_id", "ws_id", "graphql_id", "zone_id"):
                    require(outputs[field] == before[field], f"Update replaced stable owner: {field}")
                for field in ("rest_deployment_id", "imported_deployment_id", "ws_deployment_id"):
                    require(outputs[field] != before[field], f"Update did not publish the new snapshot: {field}")
                require(sdk["apigateway"].get_account()["cloudwatchRoleArn"] == log_roles[1], "Account logging role update did not retain the new authority")
                consume("second")
                require(request(f"/_stackd/execute-api/{outputs['rest_id']}/live/protected",
                                json.dumps({"nonce": uuid.uuid4().hex}), {"Authorization": "allow-first"})[0] == 401,
                        "Redeployed TOKEN authorizer retained the old identity-validation expression or stale cached result")
                # Clear the modeled setting while the stage is still alive.
                # Ingestion must stop without turning best-effort logging into
                # a client invocation failure. Terraform then restores the role.
                sdk["apigateway"].update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn"}])
                require(not sdk["apigateway"].get_account().get("cloudwatchRoleArn"), "Nil account replace did not clear the optional role")
                cleared_nonce = uuid.uuid4().hex
                path = f"/_stackd/execute-api/{outputs['rest_id']}/live/protected"
                require(request(path, json.dumps({"nonce": cleared_nonce}), {"Authorization": "allow-second"})[0] == 200,
                        "Cleared logging account changed the actual client result")
                require(not any(cleared_nonce in row for row in log_messages(execution_group)),
                        "Cleared account still authorized execution ingestion")
                terraform("apply", "-input=false", "-auto-approve")
                restored_nonce = uuid.uuid4().hex
                require(request(path, json.dumps({"nonce": restored_nonce}), {"Authorization": "allow-second"})[0] == 200,
                        "Restored logging role failed its real client invocation")
                wait_value(lambda: any(restored_nonce in row for row in log_messages(execution_group)), "Restored current role ingestion")
                print("Consumed nil account reset and current restored Logs ingestion without response rewriting", flush=True)
                require(terraform("plan", "-input=false", "-detailed-exitcode", check=False).returncode == 0, "Repeated updated control plan has drift")
                record("update-strict-plan")
                graph_connection.send(json.dumps({"id": "owned", "type": "stop"}))
                receive_graph("complete", "owned")
                graph_connection.close()
                graph_connection = None
                socket_connection.close()
                socket_connection = None
                print("Completed current-provider update with retained sockets and changed real effects", flush=True)
                controllers.close()
                shutil.move(root / "stackd.log", root / "stackd-initial.log")
                endpoint = controllers.enter_context(controller(args, root, extra, containers=True, account=account))
                sdk = {service: client(service, endpoint) for service in sdk}
                outputs = json.loads(terraform("output", "-json", "proof", capture=True).stdout)
                connect_consumers()
                consume("second")
                require(request(iam_path, iam_data, credentials=credentials)[0] == 403,
                        "Reopen revived the deleted IAM grant")
                require(terraform("plan", "-input=false", "-detailed-exitcode", check=False).returncode == 0,
                        "Reopened controls plan has drift")
                record("reopen-consumers-current-iam-strict-plan")
                # Run the refresh-only gate last so all declared consumers and
                # reopen checks execute even if Terraform Core reports exit2
                # for a no-diff plan. Exit2 is always a failure, never applied.
                refresh = terraform("plan", "-refresh-only", "-input=false", "-detailed-exitcode",
                                    "-out=refresh.tfplan", check=False)
                terraform("show", "-json", "refresh.tfplan", capture=True)
                require(refresh.returncode == 0, "Strict refresh-only plan must exit0; see retained refresh.tfplan and command logs")
                record("strict-refresh-only")
            finally:
                for connection in (graph_connection, socket_connection):
                    if connection is not None:
                        connection.close()
                try:
                    if (root / ".terraform").exists():
                        terraform("destroy", "-input=false", "-auto-approve")
                        if outputs is not None:
                            require(not sdk["apigateway"].get_account().get("cloudwatchRoleArn"), "Account resource destroy did not reset the modeled optional role")
                            for key in ("rest_id", "imported_id"):
                                expect_missing(sdk["apigateway"].get_rest_api, {"NotFoundException"}, restApiId=outputs[key])
                            for key in ("http_id", "ws_id"):
                                expect_missing(sdk["apigatewayv2"].get_api, {"NotFoundException"}, ApiId=outputs[key])
                            expect_missing(sdk["appsync"].get_graphql_api, {"NotFoundException"}, apiId=outputs["graphql_id"])
                            expect_missing(sdk["route53"].get_hosted_zone, {"NoSuchHostedZone"}, Id=outputs["zone_id"])
                            response = subprocess.check_output(["dig", "@127.0.0.1", "-p", str(args.dns_port), "address." + outputs["zone_name"], "A", "+time=2", "+tries=1"], text=True)
                            require("status: REFUSED" in response and not terraform("state", "list", capture=True).stdout.strip(),
                                    "Destroy left authoritative DNS publication or Terraform resources")
                            print("Completed Terraform destroy, API/account absence and real DNS refusal", flush=True)
                            record("destroy-api-account-dns-absence")
                finally:
                    def delete(action, **parameters):
                        try:
                            action(**parameters)
                        except ClientError as error:
                            require(error.response["Error"]["Code"] in {"ResourceNotFoundException", "NotFoundException", "NoSuchEntity", "DBInstanceNotFound", "DBClusterNotFound"},
                                    f"Owned prerequisite cleanup failed: {error}")
                    if function:
                        delete(sdk["lambda"].delete_function, FunctionName=function)
                    if writer:
                        delete(sdk["rds"].delete_db_instance, DBInstanceIdentifier=writer, SkipFinalSnapshot=True)
                        wait_value(lambda: not sdk["rds"].describe_db_instances()["DBInstances"], "Owned writer deletion")
                    if cluster:
                        delete(sdk["rds"].delete_db_cluster, DBClusterIdentifier=cluster, SkipFinalSnapshot=True)
                        wait_value(lambda: not sdk["rds"].describe_db_clusters()["DBClusters"], "Owned cluster deletion")
                    if secret:
                        delete(sdk["secretsmanager"].delete_secret, SecretId=secret, ForceDeleteWithoutRecovery=True)
                    if pool:
                        delete(sdk["cognito-idp"].delete_user_pool, UserPoolId=pool)
                    if table:
                        delete(sdk["dynamodb"].delete_table, TableName=table)
                    if user_key:
                        delete(sdk["iam"].delete_access_key, UserName=user, AccessKeyId=user_key["AccessKeyId"])
                    if user:
                        for policy in sdk["iam"].list_user_policies(UserName=user)["PolicyNames"]:
                            sdk["iam"].delete_user_policy(UserName=user, PolicyName=policy)
                        delete(sdk["iam"].delete_user, UserName=user)
                    for role_name in roles:
                        for policy in sdk["iam"].list_role_policies(RoleName=role_name)["PolicyNames"]:
                            sdk["iam"].delete_role_policy(RoleName=role_name, PolicyName=policy)
                        sdk["iam"].delete_role(RoleName=role_name)
                    for group in dict.fromkeys(groups):
                        delete(sdk["logs"].delete_log_group, logGroupName=group)
                    print("Completed exact-owned SDK prerequisite cleanup", flush=True)
                    record("sdk-prerequisite-cleanup")
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        for key, previous in previous_ssl.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        evidence["error"] = str(sys.exc_info()[1]) if sys.exc_info()[1] is not None else None
        error = sys.exc_info()[1]
        evidence["error_chain"] = []
        while error is not None:
            evidence["error_chain"].append(str(error))
            error = error.__cause__ or error.__context__
        evidence["success"] = evidence["error"] is None
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Current-provider API control lifecycle complete. Private owned artifacts: {root}")


if __name__ == "__main__":
    main()
