"""Shared safety, owned-controller lifecycle and signed data-plane assertions."""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

ROOT = Path(__file__).resolve().parents[1]
REGION = "us-east-1"
ACCOUNT = "738492615083"  # Explicit local fixture, not an AWS credential.


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def arguments(description, port):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--port", type=int, default=port)
    parser.add_argument("--stackd", type=Path, default=ROOT / "bin/stackd")
    parser.add_argument("--work-parent", type=Path, help="Existing directory for a new, uniquely owned run directory")
    return parser


def local_endpoint(endpoint):
    parsed = urlsplit(endpoint)
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
            and parsed.port is not None and not parsed.username
            and not parsed.password and parsed.path in ("", "/")
            and not parsed.query and not parsed.fragment,
            f"Refusing non-loopback endpoint: {endpoint}")
    return endpoint


def environment():
    # Never inherit credentials, endpoint overrides, proxy routing or Terraform arguments.
    result = {key: value for key, value in os.environ.items()
              if not key.startswith(("AWS_", "TF_"))
              and key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    result.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                  AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
                  AWS_EC2_METADATA_DISABLED="true", AWS_CONFIG_FILE=os.devnull,
                  AWS_SHARED_CREDENTIALS_FILE=os.devnull, AWS_PAGER="",
                  NO_PROXY="*", TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1")
    return result


def client(service, endpoint):
    return boto3.Session(aws_access_key_id="test", aws_secret_access_key="test",
                         region_name=REGION).client(
        service, endpoint_url=local_endpoint(endpoint),
        config=Config(signature_version="s3v4" if service == "s3" else "v4",
                      connect_timeout=3, read_timeout=60, proxies={},
                      retries={"max_attempts": 0}, s3={"addressing_style": "path"}))


def workspace(args, example):
    root = Path(tempfile.mkdtemp(prefix=f"stackd-{example}-", dir=args.work_parent)).resolve()
    # Lambda's read-only bind mount must be traversable by runtime UID 993.
    root.chmod(0o755)
    print(f"Owned run directory (retained for inspection): {root}", flush=True)
    return root


@contextlib.contextmanager
def controller(args, root, extra=(), containers=False):
    require(args.stackd.is_file(), f"Build the controller first: make build ({args.stackd})")
    require(1024 <= args.port <= 65535, "Choose an unprivileged port in 1024..65535")
    # Reject an occupied port before starting; never accidentally use somebody else's server.
    with socket.socket() as probe:
        probe.bind(("0.0.0.0" if containers else "127.0.0.1", args.port))
    endpoint = local_endpoint(f"http://127.0.0.1:{args.port}")
    command = [str(args.stackd.resolve()), "-listen",
               f"{'0.0.0.0' if containers else '127.0.0.1'}:{args.port}",
               "-account-id", ACCOUNT, "-public-endpoint", endpoint,
               "-database", str(root / "stackd.sqlite"), *extra]
    print("Controller:", " ".join(command), flush=True)
    with (root / "stackd.log").open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=environment())
        try:
            deadline = time.monotonic() + 60
            while True:
                require(process.poll() is None, f"Controller exited; read {root / 'stackd.log'}")
                try:
                    identity = client("sts", endpoint).get_caller_identity()
                    require(identity["Account"] == ACCOUNT, f"Unexpected account: {identity}")
                    require(process.poll() is None, "Owned controller exited during readiness")
                    break
                except EndpointConnectionError:
                    require(time.monotonic() < deadline, f"Controller readiness timed out: {root}")
                    time.sleep(0.25)
            print(f"Signed STS identity: {identity['Arn']}", flush=True)
            yield endpoint
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    # Do not force-kill: graceful shutdown owns runtime-container cleanup.
                    raise RuntimeError(f"Controller PID {process.pid} did not stop; inspect {root / 'stackd.log'}")


def expect_missing(call, codes, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response["Error"]["Code"] in codes, str(error))
    else:
        raise RuntimeError(f"Resource still exists: {kwargs}")


def verify_application(endpoint, outputs, revision):
    """Consume IaC outputs, transfer binary object bytes through a queue manifest."""
    s3, sqs, ssm = (client(service, endpoint) for service in ("s3", "sqs", "ssm"))
    queue = outputs["queue_url"]
    require(urlsplit(queue).netloc == urlsplit(endpoint).netloc,
            f"Refusing queue outside the owned endpoint: {queue}")
    local_endpoint(f"{urlsplit(queue).scheme}://{urlsplit(queue).netloc}")
    parameter = ssm.get_parameter(Name=outputs["parameter_name"])["Parameter"]
    require(parameter["Value"] == revision, f"Unexpected parameter: {parameter}")
    key = f"payload/{uuid.uuid4().hex}.bin"
    payload = b"stackd IaC binary round trip\x00\xff\n" + uuid.uuid4().bytes
    digest = hashlib.sha256(payload).hexdigest()
    body = json.dumps({"bucket": outputs["bucket"], "key": key, "sha256": digest,
                       "revision": revision}, sort_keys=True)
    try:
        s3.put_object(Bucket=outputs["bucket"], Key=key, Body=payload,
                      ContentType="application/octet-stream")
        sent = sqs.send_message(QueueUrl=queue, MessageBody=body)
        messages = sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=1,
                                       WaitTimeSeconds=2).get("Messages", [])
        require(len(messages) == 1, f"Expected one real queue message: {messages}")
        message = messages[0]
        require(message["MessageId"] == sent["MessageId"] and message["Body"] == body,
                f"Message body/identity changed: {message}")
        manifest = json.loads(message["Body"])
        stream = s3.get_object(Bucket=manifest["bucket"], Key=manifest["key"])["Body"]
        try:
            actual = stream.read()
        finally:
            stream.close()
        require(actual == payload and hashlib.sha256(actual).hexdigest() == manifest["sha256"],
                "Object bytes changed between producer and consumer")
        sqs.delete_message(QueueUrl=queue, ReceiptHandle=message["ReceiptHandle"])
        require(not sqs.receive_message(QueueUrl=queue, WaitTimeSeconds=1).get("Messages"),
                "Deleted queue message was still delivered")
        print(f"Verified {revision}: SSM value, SQS message identity/body, S3 {len(payload)} bytes ({digest})", flush=True)
    finally:
        s3.delete_object(Bucket=outputs["bucket"], Key=key)


def verify_deleted(endpoint, outputs):
    expect_missing(client("s3", endpoint).head_bucket, {"404", "NoSuchBucket", "NotFound"},
                   Bucket=outputs["bucket"])
    expect_missing(client("sqs", endpoint).get_queue_attributes,
                   {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"},
                   QueueUrl=outputs["queue_url"], AttributeNames=["QueueArn"])
    expect_missing(client("ssm", endpoint).get_parameter, {"ParameterNotFound"},
                   Name=outputs["parameter_name"])
    print("Verified deletion of bucket, queue and parameter through signed APIs", flush=True)
