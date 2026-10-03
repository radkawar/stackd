#!/usr/bin/env python3
"""Local-only signed SDK -> rule/Pipes -> real HTTPS proof with SQLite reopen.

No AWS credentials are read or forwarded. The executable and HTTPS receiver bind
only loopback; the temporary receiver certificate is trusted only by the child.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess


def require(value, message):
    if not value:
        raise AssertionError(message)


def policy(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


class Receiver:
    def __init__(self, state):
        self.lock = threading.Lock()
        self.requests = []
        self.counts = {}
        cert, key = state / "receiver.pem", state / "receiver.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    value = json.loads(body)
                except ValueError:
                    self.send_error(400)
                    return
                marker = value.get("marker", "")
                with owner.lock:
                    count = owner.counts.get(marker, 0) + 1
                    owner.counts[marker] = count
                    owner.requests.append({"marker": marker, "path": self.path,
                        "headers": dict(self.headers), "body": value})
                status = 503 if marker in ("retry-reopen", "pipe-retry") and count == 1 else 204
                self.send_response(status)
                if status == 503:
                    self.send_header("Retry-After", "15")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"https://127.0.0.1:{self.server.server_port}"
        self.certificate = cert

    def captured(self, marker):
        with self.lock:
            return [row for row in self.requests if row["marker"] == marker]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class Application:
    def __init__(self, binary, state, receiver):
        self.binary, self.state, self.receiver = binary, state, receiver
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.controller = StackdProcess(self.state)
        self.account = "111111111111"
        self.clients = {name: boto3.client(name, endpoint_url=self.endpoint, region_name="us-east-1",
            aws_access_key_id=self.account, aws_secret_access_key="test",
            config=Config(retries={"max_attempts": 0}, connect_timeout=2, read_timeout=30))
            for name in ("events", "iam", "sqs", "pipes", "sts")}

    def start(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        environment["SSL_CERT_FILE"] = str(self.receiver.certificate)
        command = [self.binary, "-listen", f"127.0.0.1:{self.port}",
            "-database", str(self.state / "state.sqlite"), "-account-id", self.account,
            "-clock-start", "2031-01-02T03:04:05Z"]
        self.controller.start(command, self.endpoint, environment=environment)
        require(self.clients["sts"].get_caller_identity()["Account"] == self.account,
            "local account identity mismatch")

    def control(self, path, payload=None):
        request = urllib.request.Request(self.endpoint + path,
            data=json.dumps(payload).encode() if payload is not None else b"",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def advance(self, seconds=0):
        self.control("/_stackd/clock", {"advance": f"{seconds}s"})
        self.control("/_stackd/jobs/drain?limit=1024")

    def wait(self, fn, label, seconds=30, advance=0):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.advance(advance)
            result = fn()
            if result:
                return result
            time.sleep(.05)
        raise TimeoutError(label)

    def delivery(self, marker):
        with sqlite3.connect(f"file:{self.state / 'state.sqlite'}?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute("select * from eventbridge_deliveries where input like ? order by due", ("%" + marker + "%",)).fetchall()
            return [dict(row) for row in rows]


def run(app):
    events, iam, sqs, pipes = [app.clients[name] for name in ("events", "iam", "sqs", "pipes")]
    prefix = "api-destination-local-owned"
    connection = events.create_connection(Name=prefix, AuthorizationType="BASIC", AuthParameters={
        "BasicAuthParameters": {"Username": "owned-user", "Password": "owned-password"},
        "InvocationHttpParameters": {
            "HeaderParameters": [{"Key": "X-Shared", "Value": "connection", "IsValueSecret": False}],
            "QueryStringParameters": [{"Key": "shared", "Value": "connection", "IsValueSecret": False}],
            "BodyParameters": [{"Key": "shared", "Value": "connection", "IsValueSecret": False}]}})
    destination = events.create_api_destination(Name=prefix, ConnectionArn=connection["ConnectionArn"],
        InvocationEndpoint=app.receiver.endpoint + "/deliver/*?base=endpoint", HttpMethod="POST",
        InvocationRateLimitPerSecond=1)
    destination_arn = destination["ApiDestinationArn"]
    role = iam.create_role(RoleName=prefix, AssumeRolePolicyDocument=policy([{
        "Effect": "Allow", "Principal": {"Service": ["events.amazonaws.com", "pipes.amazonaws.com"]},
        "Action": "sts:AssumeRole"}]))["Role"]
    invoke = {"Effect": "Allow", "Action": "events:InvokeApiDestination", "Resource": destination_arn}
    iam.put_role_policy(RoleName=prefix, PolicyName="invoke", PolicyDocument=policy([invoke]))
    events.create_event_bus(Name=prefix)
    rule = events.put_rule(Name=prefix, EventBusName=prefix, EventPattern='{"source":["owned"]}')
    queue = sqs.create_queue(QueueName=prefix + "-dlq")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": policy([{
        "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
        "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule["RuleArn"]}}}])})

    def publish(marker):
        result = events.put_targets(EventBusName=prefix, Rule=prefix, Targets=[{
            "Id": "http", "Arn": destination_arn, "RoleArn": role["Arn"],
            "Input": json.dumps({"marker": marker, "shared": "target"}),
            "HttpParameters": {"HeaderParameters": {"X-Shared": "target", "X-Target": "retained"},
                "PathParameterValues": ["part one"], "QueryStringParameters": {"shared": "target", "target": "yes"}},
            "RetryPolicy": {"MaximumRetryAttempts": 3, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": queue_arn}}])
        require(result["FailedEntryCount"] == 0, "target admission failed")
        result = events.put_events(Entries=[{"EventBusName": prefix, "Source": "owned",
            "DetailType": "proof", "Detail": "{}"}])
        require(result["FailedEntryCount"] == 0, "event admission failed")
        app.advance()

    publish("basic")
    row = app.wait(lambda: app.receiver.captured("basic"), "Basic HTTPS effect")[0]
    headers = {key.lower(): value for key, value in row["headers"].items()}
    require(headers.get("authorization") == "Basic " + base64.b64encode(b"owned-user:owned-password").decode(), "Basic credentials differ")
    require(headers.get("x-shared") == "connection" and headers.get("x-target") == "retained", "header composition differs")
    require(headers.get("user-agent") == "Amazon/EventBridge/ApiDestinations" and headers.get("range") == "bytes=0-1048575", "service headers differ")
    require(row["body"] == {"marker": "basic", "shared": "connection"}, "body precedence differs")
    from urllib.parse import urlsplit, parse_qs
    address = urlsplit(row["path"])
    require(address.path == "/deliver/part%20one" and parse_qs(address.query) == {
        "base": ["endpoint"], "shared": ["connection"], "target": ["yes"]}, "path/query composition differs")
    print(json.dumps({"case": "signed-rule-https", "authentication": "Basic", "composition": "exact"}), flush=True)

    app.advance(1)
    publish("retry-reopen")
    app.wait(lambda: app.delivery("retry-reopen") and app.delivery("retry-reopen")[0]["attempts"] == 1, "retained retry")
    require(len(app.receiver.captured("retry-reopen")) == 1, "unexpected retry before deadline")
    app.controller.stop(kill_on_timeout=True)
    app.start()
    app.advance(14)
    require(len(app.receiver.captured("retry-reopen")) == 1, "Retry-After ignored across reopen")
    app.advance(1)
    app.wait(lambda: len(app.receiver.captured("retry-reopen")) == 2, "retry after reopen")
    require(app.delivery("retry-reopen")[0]["state"] == "delivered", "successful retry not committed")
    print(json.dumps({"case": "sqlite-reopen-retry-after", "attempts": 2, "delay_seconds": 15}), flush=True)

    iam.put_role_policy(RoleName=prefix, PolicyName="deny", PolicyDocument=policy([{
        "Effect": "Deny", "Action": "events:InvokeApiDestination", "Resource": destination_arn}]))
    publish("denied")
    messages = app.wait(lambda: sqs.receive_message(QueueUrl=queue, MessageAttributeNames=["All"]).get("Messages"), "denied invocation DLQ")
    require(not app.receiver.captured("denied"), "current role denial reached HTTPS")
    require(messages[0]["MessageAttributes"]["ERROR_CODE"]["StringValue"] == "NO_PERMISSIONS", "DLQ classification differs")
    sqs.delete_message(QueueUrl=queue, ReceiptHandle=messages[0]["ReceiptHandle"])
    iam.delete_role_policy(RoleName=prefix, PolicyName="deny")
    app.advance(1)
    publish("restored")
    app.wait(lambda: app.receiver.captured("restored"), "current role restoration")
    print(json.dumps({"case": "current-iam-deny-restoration", "denial": "NO_PERMISSIONS", "dlq": True}), flush=True)

    source = sqs.create_queue(QueueName=prefix + "-source", Attributes={"VisibilityTimeout": "30"})["QueueUrl"]
    source_arn = sqs.get_queue_attributes(QueueUrl=source, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    iam.put_role_policy(RoleName=prefix, PolicyName="source", PolicyDocument=policy([{
        "Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": source_arn}]))
    pipes.create_pipe(Name=prefix, RoleArn=role["Arn"], Source=source_arn, Target=destination_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}}, TargetParameters={
            "InputTemplate": '{"marker":<$.body.marker>,"shared":"pipe"}',
            "HttpParameters": {"PathParameterValues": ["$.body.path"],
                "QueryStringParameters": {"dynamic": "$.body.query"},
                "HeaderParameters": {"X-Pipe": "literal"}}})
    sqs.send_message(QueueUrl=source, MessageBody='{"marker":"pipe-retry","path":"pipe-part","query":"source"}')
    app.advance(1)
    app.wait(lambda: app.receiver.captured("pipe-retry"), "Pipes first HTTP effect", advance=1)
    require(len(app.receiver.captured("pipe-retry")) == 1, "Pipes failed effect was not retained")
    app.advance(16)
    app.wait(lambda: len(app.receiver.captured("pipe-retry")) == 2, "Pipes retry", advance=1)
    pipe_request = app.receiver.captured("pipe-retry")[-1]
    pipe_headers = {key.lower(): value for key, value in pipe_request["headers"].items()}
    require(pipe_headers.get("authorization") == headers["authorization"] and pipe_headers.get("x-pipe") == "literal",
        "Pipes did not use the shared Connection credentials and target header")
    require(pipe_request["body"] == {"marker": "pipe-retry", "shared": "connection"}, "Pipes body merge differs")
    require(urlsplit(pipe_request["path"]).path == "/deliver/pipe-part", "Pipes dynamic path differs")
    require(parse_qs(urlsplit(pipe_request["path"]).query)["dynamic"] == ["source"], "Pipes dynamic query differs")
    app.wait(lambda: sqs.get_queue_attributes(QueueUrl=source, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"] == {
        "ApproximateNumberOfMessages": "0", "ApproximateNumberOfMessagesNotVisible": "0"}, "Pipes successful acknowledgment", advance=1)
    print(json.dumps({"case": "pipes-shared-http-owner", "attempts": 2, "source_acknowledged": True}), flush=True)

    pipes.delete_pipe(Name=prefix)
    app.advance(1)
    events.remove_targets(EventBusName=prefix, Rule=prefix, Ids=["http"])
    events.delete_rule(EventBusName=prefix, Name=prefix)
    events.delete_event_bus(Name=prefix)
    events.delete_api_destination(Name=prefix)
    events.delete_connection(Name=prefix)
    app.advance(1)
    for name in ("invoke", "source"):
        iam.delete_role_policy(RoleName=prefix, PolicyName=name)
    iam.delete_role(RoleName=prefix)
    sqs.delete_queue(QueueUrl=queue)
    sqs.delete_queue(QueueUrl=source)
    for operation, missing in (
        (events.describe_api_destination, "ResourceNotFoundException"),
        (events.describe_connection, "ResourceNotFoundException"),
        (pipes.describe_pipe, "NotFoundException"),
    ):
        try:
            operation(Name=prefix)
        except ClientError as error:
            require(error.response["Error"]["Code"] == missing, "unexpected cleanup outcome")
        else:
            raise AssertionError("owned resource remains after cleanup")
    print(json.dumps({"case": "cleanup", "owned_controls_absent": True, "controllers": len(app.controller.runs)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    arguments = parser.parse_args()
    binary = str(Path(arguments.binary).resolve())
    with tempfile.TemporaryDirectory(prefix="stackd-api-destination-proof-") as directory:
        state = Path(directory)
        receiver = Receiver(state)
        app = Application(binary, state, receiver)
        try:
            app.start()
            run(app)
        finally:
            try:
                app.controller.stop(kill_on_timeout=True)
            finally:
                receiver.close()


if __name__ == "__main__":
    main()
