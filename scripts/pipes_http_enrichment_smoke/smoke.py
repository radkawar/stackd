#!/usr/bin/env python3
"""Signed Go SDK -> SQS -> Pipes -> real trusted HTTPS -> SQS, with retained SQLite.

Use --baseline with the old binary before rebuilding. The default scenario retains
the enrichment/authentication workflow; --scenario response-encoding exercises
real compressed HTTPS responses, source retention, restart, and wire-size bounds.
Reports and controller logs remain in the explicitly owned fresh state
directory; resources are removed by exact identifiers. No native AWS credentials are loaded.
"""
import argparse
import base64
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from urllib.parse import parse_qs, urlsplit
import uuid
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "aws"))
from stackd_process import StackdProcess


def require(value, message):
    if not value:
        raise AssertionError(message)


def policy(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


class Receiver:
    def __init__(self, state):
        self.state = state
        self.lock = threading.Lock()
        self.requests = []
        self.mode = "success"
        self.response_shape = "array"
        self.encoding = "identity"
        self.defect = None
        self.decoded_size = None
        self.cert, key = state / "receiver.pem", state / "receiver.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(self.cert)], check=True, capture_output=True)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    value = json.loads(raw)
                    rows = value if isinstance(value, list) else [value]
                    transformed = [{"marker": row["marker"], "doubled": row["value"] * 2,
                        "template": row["template"], "enrichedBy": "real-https"} for row in rows]
                except (ValueError, KeyError, TypeError):
                    self.send_error(400)
                    return
                with owner.lock:
                    mode = owner.mode
                    status = 503 if mode == "fail" else 204 if mode == "no-content" else 200
                    response = transformed[0] if owner.response_shape == "object" else transformed
                    if owner.response_shape == "multi":
                        response = [transformed[0], dict(transformed[0], doubled=transformed[0]["doubled"] + 1)]
                    if mode == "empty-array":
                        response = []
                    elif mode == "empty-object":
                        response = {}
                    if owner.decoded_size is not None:
                        require(0 <= owner.decoded_size <= 6 * 1024 * 1024 + 1,
                            "receiver output must stay within the bounded limit probe")
                        transformed[0]["padding"] = ""
                        padding = owner.decoded_size - len(json.dumps(response).encode())
                        require(padding >= 0, "decoded response size cannot hold the result")
                        transformed[0]["padding"] = "x" * padding
                    decoded = b"" if mode == "no-content" else json.dumps(response).encode()
                    body = decoded
                    encoding = owner.encoding
                    if mode == "no-content":
                        body = b""
                    elif encoding == "gzip":
                        body = gzip.compress(decoded, mtime=0)
                    elif encoding == "deflate":
                        body = zlib.compress(decoded)
                    elif encoding == "raw-deflate":
                        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
                        body = compressor.compress(decoded) + compressor.flush()
                    if owner.defect == "malformed":
                        body = b"not a compressed response"
                    elif owner.defect == "truncated":
                        body = body[:-4]
                    elif owner.defect == "bad-checksum":
                        body = body[:-1] + bytes([body[-1] ^ 0xff])
                    content_encoding = "deflate" if encoding == "raw-deflate" else encoding
                    wire_file = None
                    if len(body) >= 65536:
                        wire_file = owner.state / f"response-{len(owner.requests) + 1}.bin"
                        wire_file.write_bytes(body)
                    owner.requests.append({"body": value, "path": self.path,
                        "headers": dict(self.headers), "status": status,
                        "response": decoded.decode() if len(decoded) < 65536 else None,
                        "content_encoding": content_encoding, "encoding": encoding, "defect": owner.defect,
                        "decoded_bytes": len(decoded), "wire_bytes": len(body),
                        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                        "wire_sha256": hashlib.sha256(body).hexdigest(),
                        "wire_response_base64": base64.b64encode(body).decode() if wire_file is None else None,
                        "wire_response_file": str(wire_file) if wire_file else None})
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if status != 204:
                    self.send_header("Content-Length", str(len(body)))
                if encoding != "identity":
                    self.send_header("Content-Encoding", content_encoding)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"https://127.0.0.1:{self.server.server_port}"

    def captured(self, marker):
        with self.lock:
            return [row for row in self.requests if any(item.get("marker") == marker for item in
                (row["body"] if isinstance(row["body"], list) else [row["body"]]))]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class Application:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        require(not (self.state / "state.sqlite").exists(), "requires a fresh owned state directory")
        self.prefix = "pipes-http-" + uuid.uuid4().hex[:10]
        self.controller = StackdProcess(self.state)
        self.receiver = Receiver(self.state)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.owned = []
        self.report = {"prefix": self.prefix, "endpoint": self.endpoint,
            "binary_sha256": hashlib.file_digest(open(args.binary, "rb"), "sha256").hexdigest(),
            "sdk": "AWS SDK for Go v2, signed local credentials only", "baseline": args.baseline,
            "scenario": args.scenario,
            "controllers": self.controller.runs, "operations": [], "cases": {}, "cleanup": []}

    def sdk(self, operation, expected_error=None, raw=False, **parameters):
        process = subprocess.run([self.args.helper, "-endpoint", self.endpoint],
            input=json.dumps({"Operation": operation, "Parameters": parameters}), text=True,
            capture_output=True, timeout=70, check=True)
        result = json.loads(process.stdout)
        self.report["operations"].append(result)
        if raw:
            return result
        if expected_error:
            require(result.get("Error", {}).get("Code") == expected_error,
                f"{operation}: expected {expected_error}: {result}")
            return result["Error"]
        require("Error" not in result, f"{operation}: {result.get('Error')}")
        return result["Output"]

    def absent(self, operation, code, **parameters):
        def check():
            result = self.sdk(operation, raw=True, **parameters)
            if "Error" not in result:
                return False
            require(result["Error"]["Code"] == code, f"unexpected absence error: {result}")
            return result["Error"]
        return self.wait(check, "owned resource absence " + operation)

    def start(self):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        environment["SSL_CERT_FILE"] = str(self.receiver.cert)
        self.controller.start([self.args.binary, "-listen", f"127.0.0.1:{self.port}",
            "-public-endpoint", self.endpoint, "-database", str(self.state / "state.sqlite"),
            "-account-id", "111111111111", "-clock-start", "2031-01-02T03:04:05Z"],
            self.endpoint, environment=environment)
        require(self.sdk("sts.GetCallerIdentity")["Account"] == "111111111111", "local identity mismatch")

    def advance(self, seconds=1):
        for path, payload in (("/_stackd/clock", {"advance": f"{seconds}s"}),
                              ("/_stackd/jobs/drain?limit=1024", None)):
            request = urllib.request.Request(self.endpoint + path,
                data=json.dumps(payload).encode() if payload is not None else b"",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=60) as response:
                json.load(response)

    def wait(self, fn, label, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = fn()
            if result:
                return result
            self.advance()
            time.sleep(.1)
        raise TimeoutError(label)

    def queue(self, suffix):
        name = self.prefix + "-" + suffix
        url = self.sdk("sqs.CreateQueue", QueueName=name, Attributes={"VisibilityTimeout": "5"})["QueueUrl"]
        self.owned.append(("queue", url, name))
        arn = self.sdk("sqs.GetQueueAttributes", QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        return {"url": url, "arn": arn}

    def work(self):
        with sqlite3.connect(f"file:{self.state / 'state.sqlite'}?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("select id, record_id, attempts, phase, last_error, due_ns from pipes_work")]

    def send(self, source, marker, value=7):
        return self.sdk("sqs.SendMessage", QueueUrl=source["url"], MessageBody=json.dumps({
            "marker": marker, "value": value, "route": "original-route", "query": "original-query"}))

    def receive(self, target, marker, value=7, template="v1"):
        result = self.wait(lambda: self.sdk("sqs.ReceiveMessage", QueueUrl=target["url"],
            MaxNumberOfMessages=10).get("Messages"), "target delivery " + marker)
        require(len(result) == 1, f"unexpected target messages: {result}")
        body = json.loads(result[0]["Body"])
        require(body == {"marker": marker, "doubled": value * 2, "template": template,
            "enrichedBy": "real-https"}, f"HTTP output not delivered exactly: {body}")
        self.sdk("sqs.DeleteMessage", QueueUrl=target["url"], ReceiptHandle=result[0]["ReceiptHandle"])
        return body

    def no_target(self, target):
        require(not self.sdk("sqs.ReceiveMessage", QueueUrl=target["url"]).get("Messages"), "failed work reached target")

    def parameters(self, version):
        result = {"InputTemplate": '{"marker":<$.body.marker>,"value":<$.body.value>,"template":"' + version + '"}',
            "HttpParameters": {"PathParameterValues": ["part " + version],
                "HeaderParameters": {"X-Shared": "pipe", "X-Pipe": version},
                "QueryStringParameters": {"shared": "pipe", "pipe": version}}}
        if version == "v2":
            result["HttpParameters"]["PathParameterValues"] = ["$.body.route"]
            result["HttpParameters"]["QueryStringParameters"]["dynamic"] = "$.body.query"
            result["HttpParameters"]["HeaderParameters"]["X-Dynamic"] = "$.body.route"
        return result

    def assert_http(self, marker, version, password="owned-password"):
        rows = self.receiver.captured(marker)
        require(rows, "real receiver did not observe " + marker)
        row = rows[-1]
        require(isinstance(row["body"], dict), "native API destination request must be a scalar event, not an array")
        headers = {k.lower(): v for k, v in row["headers"].items()}
        require(headers.get("authorization") == "Basic " + base64.b64encode(("owned-user:" + password).encode()).decode(), "current connection credentials differ")
        require(headers.get("x-shared") == "connection" and headers.get("x-pipe") == version, "header precedence differs")
        address = urlsplit(row["path"])
        expected_path = "/enrich/part%20v1" if version == "v1" else "/enrich/original-route"
        expected_query = {"base": ["endpoint"], "shared": ["connection"], "pipe": [version]}
        if version == "v2":
            expected_query["dynamic"] = ["original-query"]
            require(headers.get("x-dynamic") == "original-route", "dynamic header did not use pre-template source")
        require(address.path == expected_path and parse_qs(address.query) == expected_query, "path/query composition differs")
        return row

    def cleanup(self):
        failures = []
        for kind, identifier, name in reversed(self.owned):
            try:
                if kind == "pipe":
                    self.sdk("pipes.StopPipe", Name=name)
                    self.wait(lambda: self.sdk("pipes.DescribePipe", Name=name)["CurrentState"] == "STOPPED", "stop owned pipe")
                    self.sdk("pipes.DeletePipe", Name=name)
                    self.absent("pipes.DescribePipe", "NotFoundException", Name=name)
                elif kind == "destination":
                    self.sdk("events.DeleteApiDestination", Name=name)
                    self.absent("events.DescribeApiDestination", "ResourceNotFoundException", Name=name)
                elif kind == "connection":
                    self.sdk("events.DeleteConnection", Name=name)
                    self.absent("events.DescribeConnection", "ResourceNotFoundException", Name=name)
                elif kind == "role":
                    for policy_name in ("owned", "deny"):
                        output = self.sdk("iam.GetRole", RoleName=name)
                        require(output["Role"]["Arn"] == identifier, "role ownership changed")
                        result = self.sdk("iam.DeleteRolePolicy", raw=True, RoleName=name, PolicyName=policy_name)
                        require("Error" not in result or result["Error"]["Code"] == "NoSuchEntity",
                            f"owned role policy deletion failed: {result}")
                    self.sdk("iam.DeleteRole", RoleName=name)
                    self.sdk("iam.GetRole", expected_error="NoSuchEntity", RoleName=name)
                elif kind == "queue":
                    self.sdk("sqs.DeleteQueue", QueueUrl=identifier)
                    self.sdk("sqs.GetQueueUrl", expected_error="AWS.SimpleQueueService.NonExistentQueue", QueueName=name)
                self.report["cleanup"].append({"kind": kind, "identifier": identifier, "absent": True})
            except Exception as error:
                failures.append(f"{kind} {identifier}: {error}")
        self.report["cleanup_failures"] = failures
        require(not failures, "owned cleanup failed: " + "; ".join(failures))


def provision(app):
    source, target = app.queue("source"), app.queue("target")
    role = app.sdk("iam.CreateRole", RoleName=app.prefix, AssumeRolePolicyDocument=policy([{
        "Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}]))["Role"]["Arn"]
    app.owned.append(("role", role, app.prefix))
    app.sdk("iam.PutRolePolicy", RoleName=app.prefix, PolicyName="owned", PolicyDocument=policy([
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": source["arn"]},
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target["arn"]},
        {"Effect": "Allow", "Action": "events:InvokeApiDestination", "Resource": "*"}]))
    auth = {"BasicAuthParameters": {"Username": "owned-user", "Password": "owned-password"},
        "InvocationHttpParameters": {"HeaderParameters": [{"Key": "X-Shared", "Value": "connection", "IsValueSecret": False}],
            "QueryStringParameters": [{"Key": "shared", "Value": "connection", "IsValueSecret": False}]}}
    connection = app.sdk("events.CreateConnection", Name=app.prefix, AuthorizationType="BASIC", AuthParameters=auth)["ConnectionArn"]
    app.owned.append(("connection", connection, app.prefix))
    destination = app.sdk("events.CreateApiDestination", Name=app.prefix, ConnectionArn=connection,
        InvocationEndpoint=app.receiver.endpoint + "/enrich/*?base=endpoint", HttpMethod="POST",
        InvocationRateLimitPerSecond=100)["ApiDestinationArn"]
    app.owned.append(("destination", destination, app.prefix))
    parameters = app.parameters("v1")
    create = {"Name": app.prefix, "RoleArn": role, "Source": source["arn"], "Target": target["arn"],
        "Enrichment": destination, "EnrichmentParameters": parameters,
        "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}}, "DesiredState": "RUNNING"}
    return source, target, role, parameters, create, auth


def run(app):
    source, target, role, parameters, create, auth = provision(app)
    if app.args.baseline:
        app.report["cases"]["unsupported-http-parameters"] = app.sdk("pipes.CreatePipe", expected_error="NotImplementedException", **create)
        create.pop("EnrichmentParameters")
        app.report["cases"]["unsupported-api-destination"] = app.sdk("pipes.CreatePipe", expected_error="NotImplementedException", **create)
        require(not app.receiver.requests, "unsupported-before unexpectedly invoked HTTPS")
        return
    invalid_batch = dict(create, Name=app.prefix + "-invalid", SourceParameters={"SqsQueueParameters": {"BatchSize": 2}})
    app.report["cases"]["nonbatchable-enrichment"] = app.sdk("pipes.CreatePipe", expected_error="ValidationException", **invalid_batch)
    output = app.sdk("pipes.CreatePipe", **create)
    app.owned.append(("pipe", output["Arn"], app.prefix))
    app.wait(lambda: app.sdk("pipes.DescribePipe", Name=app.prefix)["CurrentState"] == "RUNNING", "running pipe")
    require(app.sdk("pipes.DescribePipe", Name=app.prefix)["EnrichmentParameters"] == parameters, "create readback lost HTTP/template")
    app.send(source, "first")
    app.report["cases"]["https-transformation"] = {"target": app.receive(target, "first"), "http": app.assert_http("first", "v1")}

    parameters = app.parameters("v2")
    app.sdk("pipes.UpdatePipe", Name=app.prefix, RoleArn=role, EnrichmentParameters=parameters)
    app.wait(lambda: app.sdk("pipes.DescribePipe", Name=app.prefix)["CurrentState"] == "RUNNING", "updated pipe")
    require(app.sdk("pipes.DescribePipe", Name=app.prefix)["EnrichmentParameters"] == parameters, "update readback lost HTTP/template")
    app.receiver.response_shape = "object"
    app.send(source, "updated", 11)
    app.report["cases"]["http-template-update"] = {"target": app.receive(target, "updated", 11, "v2"), "http": app.assert_http("updated", "v2")}

    app.sdk("iam.PutRolePolicy", RoleName=app.prefix, PolicyName="deny", PolicyDocument=policy([{
        "Effect": "Deny", "Action": "events:InvokeApiDestination", "Resource": create["Enrichment"]}]))
    app.send(source, "role-denied")
    denied = app.wait(lambda: [row for row in app.work() if row["attempts"] > 0], "retained IAM-denied work")
    app.no_target(target)
    require(not app.receiver.captured("role-denied"), "current role denial reached HTTPS")
    app.sdk("iam.DeleteRolePolicy", RoleName=app.prefix, PolicyName="deny")
    app.report["cases"]["current-role-deny-recovery"] = {"retained": denied, "target": app.receive(target, "role-denied", template="v2")}

    app.sdk("events.DeauthorizeConnection", Name=app.prefix)
    app.send(source, "connection-denied")
    denied = app.wait(lambda: [row for row in app.work() if row["attempts"] > 0], "retained deauthorized-connection work")
    app.no_target(target)
    require(not app.receiver.captured("connection-denied"), "deauthorized connection reached HTTPS")
    auth["BasicAuthParameters"]["Password"] = "rotated-password"
    app.sdk("events.UpdateConnection", Name=app.prefix, AuthorizationType="BASIC", AuthParameters=auth)
    app.report["cases"]["current-connection-recovery"] = {"retained": denied,
        "target": app.receive(target, "connection-denied", template="v2"),
        "http": app.assert_http("connection-denied", "v2", "rotated-password")}

    app.receiver.mode = "fail"
    app.send(source, "restart-failure", 13)
    failed = app.wait(lambda: [row for row in app.work() if row["attempts"] > 0], "retained HTTP-503 work")
    require(app.receiver.captured("restart-failure")[-1]["status"] == 503, "failure was not observed real HTTP 503")
    app.no_target(target)
    app.controller.stop(kill_on_timeout=True)
    retained = app.work()
    require(retained == failed, "stopped SQLite did not retain failed work")
    app.receiver.mode = "success"
    app.start()
    require(app.sdk("pipes.DescribePipe", Name=app.prefix)["EnrichmentParameters"] == parameters, "restart lost parameters")
    delivered = app.receive(target, "restart-failure", 13, "v2")
    app.wait(lambda: not app.work(), "successful retry removes retained work")
    app.report["cases"]["sqlite-controller-restart"] = {"failed": failed, "retained_stopped": retained,
        "target": delivered, "http": app.assert_http("restart-failure", "v2", "rotated-password")}

    for mode in ("empty-array", "empty-object"):
        app.receiver.mode = mode
        app.send(source, mode)
        app.wait(lambda: app.receiver.captured(mode), "real " + mode + " HTTP response")
        app.wait(lambda: not app.work(), mode + " acknowledges source")
        for _ in range(4):
            app.advance(5)
            app.no_target(target)
        attributes = app.sdk("sqs.GetQueueAttributes", QueueUrl=source["url"], AttributeNames=["All"])["Attributes"]
        require(attributes["ApproximateNumberOfMessages"] == "0" and attributes["ApproximateNumberOfMessagesNotVisible"] == "0", mode + " retained source")
        app.report["cases"][mode] = {"target_messages": 0, "source_attributes": attributes,
            "http": app.receiver.captured(mode)}

    app.sdk("pipes.UpdatePipe", Name=app.prefix, RoleArn=role,
        EnrichmentParameters={"InputTemplate": parameters["InputTemplate"], "HttpParameters": {}})
    app.wait(lambda: app.sdk("pipes.DescribePipe", Name=app.prefix)["CurrentState"] == "RUNNING", "cleared HTTP parameters")
    cleared = app.sdk("pipes.DescribePipe", Name=app.prefix)["EnrichmentParameters"]
    require(cleared["HttpParameters"] is not None and not any(cleared["HttpParameters"].values()),
        "explicit empty HttpParameters did not clear all fields while retaining presence")
    app.sdk("pipes.UpdatePipe", Name=app.prefix, RoleArn=role,
        EnrichmentParameters={"InputTemplate": parameters["InputTemplate"]})
    app.wait(lambda: app.sdk("pipes.DescribePipe", Name=app.prefix)["CurrentState"] == "RUNNING", "omitted HTTP parameters")
    omitted = app.sdk("pipes.DescribePipe", Name=app.prefix)["EnrichmentParameters"]
    require(omitted == cleared, "omitted HttpParameters changed explicit empty readback")
    app.report["cases"]["http-parameters-clear-and-omit"] = {"cleared": cleared, "omitted": omitted}
    app.report["limitations"] = ["Local retained same-message retry is exercised; native same-message retry remains unmeasured."]


def response_no_content(app, source, target):
    marker = "gzip-no-content"
    with app.receiver.lock:
        app.receiver.mode = "no-content"
        app.receiver.encoding = "gzip"
        app.receiver.defect = None
        app.receiver.decoded_size = None
        app.receiver.response_shape = "array"
    message_id = app.send(source, marker)["MessageId"]
    app.wait(lambda: app.receiver.captured(marker), "actual gzip-labeled 204 response")
    http = app.assert_http(marker, "v1")
    require(http["status"] == 204 and http["content_encoding"] == "gzip" and
        http["wire_bytes"] == 0 and http["wire_response_base64"] == "", "receiver emitted a nonempty 204")
    result = {"source_message_id": message_id, "http": http, "target_messages": 0}
    if app.args.baseline:
        result["retained"] = app.wait(lambda: [row for row in app.work()
            if row["record_id"] == message_id and row["attempts"] > 0], "retained empty-204 failure")
        attributes = app.sdk("sqs.GetQueueAttributes", QueueUrl=source["url"], AttributeNames=["All"])["Attributes"]
        require(int(attributes["ApproximateNumberOfMessages"]) +
            int(attributes["ApproximateNumberOfMessagesNotVisible"]) == 1, "baseline empty-204 source not retained")
        result["source_retained"] = True
        marker += "-failed-before"
    else:
        app.wait(lambda: not app.work(), "empty 204 acknowledges source")
        for _ in range(2):
            app.advance(5)
            app.no_target(target)
        attributes = app.sdk("sqs.GetQueueAttributes", QueueUrl=source["url"], AttributeNames=["All"])["Attributes"]
        require(attributes["ApproximateNumberOfMessages"] == "0" and
            attributes["ApproximateNumberOfMessagesNotVisible"] == "0", "empty 204 retained source")
        result["source_acknowledged"] = True
    app.no_target(target)
    result["source_attributes"] = attributes
    app.report["cases"][marker] = result


def run_response_encoding(app):
    app.report["response_case"] = app.args.response_case
    source, target, _, _, create, _ = provision(app)
    create["TargetParameters"] = {"InputTemplate":
        '{"marker":<$.marker>,"doubled":<$.doubled>,"template":<$.template>,"enrichedBy":<$.enrichedBy>}'}
    output = app.sdk("pipes.CreatePipe", **create)
    app.owned.append(("pipe", output["Arn"], app.prefix))
    app.wait(lambda: app.sdk("pipes.DescribePipe", Name=app.prefix)["CurrentState"] == "RUNNING", "running pipe")
    if app.args.response_case == "no-content":
        response_no_content(app, source, target)
        return
    app.receiver.encoding = "gzip"
    message_id = app.send(source, "gzip")["MessageId"]
    if app.args.baseline:
        failed = app.wait(lambda: [row for row in app.work()
            if row["record_id"] == message_id and row["attempts"] > 0], "retained gzip failure")
        app.no_target(target)
        attributes = app.sdk("sqs.GetQueueAttributes", QueueUrl=source["url"], AttributeNames=["All"])["Attributes"]
        require(int(attributes["ApproximateNumberOfMessages"]) +
            int(attributes["ApproximateNumberOfMessagesNotVisible"]) == 1, "gzip failure acknowledged source")
        http = app.assert_http("gzip", "v1")
        require(http["content_encoding"] == "gzip" and
            gzip.decompress(base64.b64decode(http["wire_response_base64"])) == http["response"].encode(),
            "receiver did not send the actual gzip bytes")
        app.report["cases"]["gzip-failed-before"] = {"retained": failed, "source_attributes": attributes,
            "source_retained": True, "target_messages": 0, "http": http}
        app.report["limitations"] = ["Local failed-before only; no native compression-parity claim."]
        return
    def configure(encoding="gzip", defect=None, size=None, shape="array"):
        with app.receiver.lock:
            app.receiver.encoding = encoding
            app.receiver.defect = defect
            app.receiver.decoded_size = size
            app.receiver.response_shape = shape

    def delivered(marker):
        body = app.receive(target, marker)
        app.wait(lambda: not app.work(), "successful response acknowledges source " + marker)
        attributes = app.sdk("sqs.GetQueueAttributes", QueueUrl=source["url"], AttributeNames=["All"])["Attributes"]
        require(attributes["ApproximateNumberOfMessages"] == "0" and
            attributes["ApproximateNumberOfMessagesNotVisible"] == "0", "successful response retained source")
        return {"target": body, "http": app.assert_http(marker, "v1"), "source_attributes": attributes}

    def rejected(marker, restart=False):
        message_id = app.send(source, marker)["MessageId"]
        failed = app.wait(lambda: [row for row in app.work()
            if row["record_id"] == message_id and row["attempts"] > 0], "retained response failure " + marker)
        app.no_target(target)
        attributes = app.sdk("sqs.GetQueueAttributes", QueueUrl=source["url"], AttributeNames=["All"])["Attributes"]
        require(int(attributes["ApproximateNumberOfMessages"]) +
            int(attributes["ApproximateNumberOfMessagesNotVisible"]) == 1, "response failure acknowledged source")
        result = {"source_message_id": message_id, "retained": failed, "source_attributes": attributes,
            "source_retained": True, "target_messages": 0, "http": app.assert_http(marker, "v1")}
        app.report["cases"][marker] = result
        if restart:
            app.controller.stop(kill_on_timeout=True)
            result["retained_stopped"] = app.work()
            require(result["retained_stopped"] == failed, "stopped SQLite did not retain response failure")
        configure()
        if restart:
            app.start()
        result["recovery"] = delivered(marker)
        return result

    app.report["cases"]["gzip"] = delivered("gzip")
    for encoding, shape in (("deflate", "object"), ("raw-deflate", "array")):
        configure(encoding, shape=shape)
        app.send(source, encoding)
        app.report["cases"][encoding] = delivered(encoding)

    configure(shape="multi")
    marker = "gzip-multi-result"
    message_id = app.send(source, marker)["MessageId"]
    targets = []

    def collect_multi():
        messages = app.sdk("sqs.ReceiveMessage", QueueUrl=target["url"], MaxNumberOfMessages=10).get("Messages") or []
        for message in messages:
            targets.append(json.loads(message["Body"]))
            app.sdk("sqs.DeleteMessage", QueueUrl=target["url"], ReceiptHandle=message["ReceiptHandle"])
        return len(targets) >= 2

    app.wait(collect_multi, "two distinct results for one source message")
    require(sorted(targets, key=lambda row: row["doubled"]) == [
        {"marker": marker, "doubled": value, "template": "v1", "enrichedBy": "real-https"}
        for value in (14, 15)], "multi-result response lost or duplicated a distinct target effect")
    app.wait(lambda: not app.work(), "multi-result response acknowledges its one source")
    attributes = app.sdk("sqs.GetQueueAttributes", QueueUrl=source["url"], AttributeNames=["All"])["Attributes"]
    require(attributes["ApproximateNumberOfMessages"] == "0" and
        attributes["ApproximateNumberOfMessagesNotVisible"] == "0", "multi-result response retained source")
    app.no_target(target)
    app.report["cases"][marker] = {"source_message_id": message_id, "targets": targets,
        "source_attributes": attributes, "http": app.assert_http(marker, "v1")}

    for encoding, defect in (
        ("gzip", "malformed"), ("deflate", "malformed"),
        ("gzip", "truncated"), ("deflate", "truncated"), ("raw-deflate", "truncated"),
        ("gzip", "bad-checksum"), ("deflate", "bad-checksum"),
    ):
        configure(encoding, defect)
        rejected(encoding + "-" + defect, restart=encoding == "gzip" and defect == "truncated")

    wire_limit = 6 * 1024 * 1024
    for size in (wire_limit, wire_limit + 1):
        marker = f"gzip-decoded-{size}"
        configure(size=size)
        app.send(source, marker)
        app.report["cases"][marker] = delivered(marker)
        require(app.report["cases"][marker]["http"]["decoded_bytes"] == size,
            "large decoded response length differs")
    configure(encoding="identity", size=wire_limit)
    app.send(source, "wire-at-limit")
    app.report["cases"]["wire-at-limit"] = delivered("wire-at-limit")
    require(app.report["cases"]["wire-at-limit"]["http"]["wire_bytes"] == wire_limit,
        "wire boundary response length differs")
    configure(encoding="identity", size=wire_limit + 1)
    oversized = rejected("wire-over-limit")
    require(oversized["http"]["wire_bytes"] == wire_limit + 1, "oversized wire response length differs")
    response_no_content(app, source, target)
    app.report["response_limits"] = {
        "wire_bytes": wire_limit, "wire_boundary_native_measured": False,
        "decoded_safety_bytes": 64 * 1024 * 1024, "decoded_safety_rejection_exercised": False,
        "max_generated_decoded_bytes": wire_limit + 1,
        "target_input_template_strips_padding": create["TargetParameters"]["InputTemplate"],
    }
    app.report["native_calibration"] = [
        "testdata/aws/pipes/http_response.json",
        "testdata/aws/pipes/http_response_admission.json",
    ]
    app.report["limitations"] = [
        "The local 64MiB decoded safety guard is not exercised by this executable, which generates at most 6MiB+1.",
        "Native gzip 6MiB+1 delivery is matched; neither the wire ceiling nor decoded safety ceiling is claimed as native parity.",
        "Local retained same-message recovery and SQLite restart are exercised; native retry/restart equivalence is not claimed.",
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument("--helper", required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--scenario", choices=("enrichment", "response-encoding"), default="enrichment")
    parser.add_argument("--response-case", choices=("all", "no-content"), default="all")
    args = parser.parse_args()
    app = Application(args)
    try:
        app.start()
        (run_response_encoding if args.scenario == "response-encoding" else run)(app)
        app.report["scenario_complete"] = True
    except BaseException as error:
        app.report["failure"] = str(error)
        raise
    finally:
        try:
            if app.owned:
                if app.controller.process is None:
                    app.start()
                app.cleanup()
            app.report["complete"] = app.report.get("scenario_complete", False)
        finally:
            try:
                app.controller.stop(kill_on_timeout=True)
            finally:
                app.receiver.close()
                app.report["http_requests"] = app.receiver.requests
                (app.state / "report.json").write_text(json.dumps(app.report, indent=2) + "\n")
                print(json.dumps({"report": str(app.state / "report.json"), "complete": app.report.get("complete", False),
                    "cases": list(app.report["cases"])}), flush=True)


if __name__ == "__main__":
    main()
