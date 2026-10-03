#!/usr/bin/env python3
"""Native, exact-owned SQS -> HTTPS API destination enrichment -> SQS capture.

Requires a separate ethics approval before execution. Public Function URL accepts
only a random connection API key; the handler has only exact audit-queue writes.
Use --cleanup-only with the original capture after interruption.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import signal
import time
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cloudtrail_service_probe import document

REGION = "us-east-1"
SOURCES = [
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/pipes-enrichment.html",
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-target.html",
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html",
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html",
    "https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_PipeEnrichmentHttpParameters.html",
    "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
]
HANDLER = '''import boto3,hmac,json,os,time
from botocore.config import Config
sqs=boto3.client("sqs",config=Config(connect_timeout=1,read_timeout=1,retries={"total_max_attempts":1}))
def handler(event,context):
    headers=event.get("headers",{})
    if not hmac.compare_digest(headers.get("x-owned-key",""),os.environ["KEY"]):
        return {"statusCode":403,"body":"forbidden"}
    if time.time()>float(os.environ["EXPIRES"]):
        return {"statusCode":410,"body":"expired"}
    try: payload=json.loads(event.get("body",""))
    except Exception: return {"statusCode":400,"body":"invalid JSON"}
    rows=payload if isinstance(payload,list) else [payload]
    decoded=[]
    for row in rows:
        body=row.get("body",row)
        if isinstance(body,str): body=json.loads(body)
        if not isinstance(body,dict) or not body.get("marker","").startswith(os.environ["PREFIX"]):
            return {"statusCode":400,"body":"foreign marker"}
        decoded.append(body)
    mode=decoded[0].get("mode","array") if decoded else "empty"
    result=[{"marker":r["marker"],"calculated":int(r["number"])*7+3,"upper":r["text"].upper()} for r in decoded]
    status=503 if mode=="fail" else 200
    body=json.dumps({} if mode=="empty-object" else [] if mode=="empty" else result[0] if mode=="object" else result)
    sqs.send_message(QueueUrl=os.environ["AUDIT"],MessageBody=json.dumps({"request_id":context.aws_request_id,"at":time.time(),"path":event.get("rawPath"),"query":event.get("rawQueryString"),"headers":{k:v for k,v in headers.items() if k in ("x-shared","x-dynamic","x-template","content-type")},"body":event.get("body"),"payload":payload,"response_status":status,"response_body":body}))
    return {"statusCode":status,"headers":{"content-type":"application/json","retry-after":"1"},"body":body}
'''


def now():
    return datetime.now(timezone.utc).isoformat()


def recorded(value):
    if isinstance(value, bytes):
        return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, dict):
        return {k: recorded(v) for k, v in document(value).items()}
    if isinstance(value, list):
        return [recorded(v) for v in value]
    return document(value)


class Probe:
    handler = HANDLER

    def __init__(self, args):
        self.args = args
        self.cleaning = args.cleanup_only
        session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, connect_timeout=5,
                        read_timeout=15, retries={"total_max_attempts": 1})
        self.clients = {s: session.client(s, config=config) for s in
                        ("sts", "iam", "lambda", "sqs", "events", "pipes", "secretsmanager")}
        creds = session.get_credentials().get_frozen_credentials()
        self.key = secrets.token_hex(32)
        self.secret_values = [v for v in (creds.secret_key, creds.token, self.key) if v]
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.args.account or self.data["region"] != REGION:
                raise RuntimeError("Foreign cleanup inventory")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite evidence")
            self.data = {"account": self.args.account, "region": REGION, "started_at": now(),
                "started_epoch": time.time(), "prefix": "stackd-phe-" + uuid.uuid4().hex[:12],
                "sources": SOURCES, "sdk": {"boto3": boto3.__version__},
                "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "ethics_review": {"decision": "allow", "reviewed_at": "2026-10-01",
                    "scope": "Three SQS queues, two exact roles, one 128MB concurrency1 Lambda public Function URL protected by 256-bit API key, connection/destination/Pipe; max20 messages/20min; no standing roles modified"},
                "owned": {}, "calls": [], "messages": [], "cases": {},
                "limitations": ["One sample does not establish undocumented timing or retry counts.",
                    "Bounded non-observation is not permanent absence.",
                    "No CloudTrail data trail; endpoint audit and downstream messages prove execution.",
                    "No private network, OAuth, BASIC, large payload, timeout or concurrency coverage."],
                "cleanup": {"complete": False}}
        self.prefix = self.data["prefix"]
        if not re.fullmatch(r"stackd-phe-[0-9a-f]{12}", self.prefix):
            raise RuntimeError("Invalid owned prefix")
        self.owned = self.data["owned"]
        self.save()
        identity = self.call("identity", "sts", "get_caller_identity")
        if identity["Account"] != self.args.account or identity["Arn"] != ('arn:aws:iam::' + self.args.account + ':user/Delegated'):
            raise RuntimeError("Native writes require exact account and actor")
        self.data["identity"] = identity
        self.save()

    def save(self):
        text = json.dumps(recorded(self.data), indent=2, default=str)
        for value in self.secret_values:
            text = text.replace(value, "<redacted-secret>")
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(text + "\n")

    def call(self, label, service, operation, request=None, optional=False):
        if not self.cleaning and time.time() - self.data["started_epoch"] > 1100:
            raise RuntimeError("Native observation deadline")
        row = {"label": label, "service": service, "operation": operation,
               "input": recorded(request or {}), "at": now(), "phase": "cleanup" if self.cleaning else "workflow"}
        self.data["calls"].append(row)
        try:
            out = getattr(self.clients[service], operation)(**(request or {}))
            row.update(code="Success", output=recorded(out))
        except ClientError as error:
            out = error.response
            row.update(code=out["Error"]["Code"], error=recorded(out))
            if not optional:
                raise
        finally:
            self.save()
        if not label.startswith(("poll-", "read-")):
            print(label + ": " + row["code"], flush=True)
        return out

    def absent(self, label, service, operation, request, codes):
        out = self.call(label, service, operation, request, True)
        return out.get("Error", {}).get("Code") in codes

    def wait_pipe(self, state, seconds=100):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            out = self.call("poll-pipe-" + state, "pipes", "describe_pipe", {"Name": self.prefix})
            if out["CurrentState"] == state:
                return out
            if out["CurrentState"].endswith("FAILED"):
                raise RuntimeError(json.dumps(out, default=str))
            time.sleep(2)
        raise RuntimeError("Pipe state deadline: " + state)

    def role(self, kind, service, statements):
        name = self.prefix + "-" + kind
        if not self.absent("before-role-" + kind, "iam", "get_role", {"RoleName": name}, {"NoSuchEntity"}):
            raise RuntimeError("Role name is occupied")
        self.owned[kind + "_role"] = name
        self.save()
        role = self.call("create-role-" + kind, "iam", "create_role", {"RoleName": name,
            "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": self.prefix}]})["Role"]
        self.call("policy-" + kind, "iam", "put_role_policy", {"RoleName": name,
            "PolicyName": "owned", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})
        return role["Arn"]

    def setup(self):
        self.call("existing-linked-role", "iam", "get_role", {"RoleName": "AWSServiceRoleForAmazonEventBridgeApiDestinations"})
        self.owned["queues"] = {}
        for kind in ("source", "target", "audit"):
            name = self.prefix + "-" + kind
            if not self.absent("before-queue-" + kind, "sqs", "get_queue_url", {"QueueName": name},
                               {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}):
                raise RuntimeError("Queue name is occupied")
            self.owned["queues"][kind] = {"name": name}
            self.save()
            q = self.call("create-queue-" + kind, "sqs", "create_queue", {"QueueName": name,
                "Attributes": {"VisibilityTimeout": "10", "MessageRetentionPeriod": "1200"}, "tags": {"stackd-probe": self.prefix}})
            self.owned["queues"][kind]["url"] = q["QueueUrl"]
            self.owned["queues"][kind]["arn"] = f"arn:aws:sqs:{REGION}:{self.args.account}:{name}"
            self.save()
        arn = self.role("lambda", "lambda.amazonaws.com", [{"Effect": "Allow", "Action": "sqs:SendMessage",
                    "Resource": self.owned["queues"]["audit"]["arn"]}])
        if not self.absent("before-function", "lambda", "get_function", {"FunctionName": self.prefix}, {"ResourceNotFoundException"}):
            raise RuntimeError("Function name occupied")
        self.owned["function"] = self.prefix
        self.save()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            package.writestr("index.py", self.handler)
        for attempt in range(12):
            result = self.call("create-function-" + str(attempt), "lambda", "create_function", {
                "FunctionName": self.prefix, "Runtime": "python3.12", "Role": arn, "Handler": "index.handler",
                "Code": {"ZipFile": archive.getvalue()}, "Timeout": 3, "MemorySize": 128,
                "Environment": {"Variables": {"KEY": self.key, "PREFIX": self.prefix,
                    "EXPIRES": str(self.data["started_epoch"] + 1200), "AUDIT": self.owned["queues"]["audit"]["url"]}},
                "Tags": {"stackd-probe": self.prefix}}, True)
            if "Error" not in result:
                break
            if result["Error"]["Code"] != "InvalidParameterValueException":
                raise RuntimeError(str(result))
            time.sleep(5)
        else:
            raise RuntimeError("Lambda IAM propagation deadline")
        self.call("limit-function", "lambda", "put_function_concurrency", {"FunctionName": self.prefix, "ReservedConcurrentExecutions": 1})
        for _ in range(45):
            out = self.call("poll-function", "lambda", "get_function_configuration", {"FunctionName": self.prefix})
            if out["State"] == "Active":
                break
            time.sleep(2)
        else:
            raise RuntimeError("Lambda readiness deadline")
        url = self.call("create-url", "lambda", "create_function_url_config", {"FunctionName": self.prefix, "AuthType": "NONE"})["FunctionUrl"]
        self.owned["url"] = url
        self.save()
        self.call("permit-url", "lambda", "add_permission", {"FunctionName": self.prefix,
            "StatementId": "owned-url", "Action": "lambda:InvokeFunctionUrl", "Principal": "*", "FunctionUrlAuthType": "NONE"})
        self.call("permit-url-invoke", "lambda", "add_permission", {"FunctionName": self.prefix,
            "StatementId": "owned-url-invoke", "Action": "lambda:InvokeFunction", "Principal": "*", "InvokedViaFunctionUrl": True})
        for resource, describe in (("connection", "describe_connection"), ("destination", "describe_api_destination")):
            if not self.absent("before-" + resource, "events", describe, {"Name": self.prefix}, {"ResourceNotFoundException"}):
                raise RuntimeError(resource + " occupied")
            self.owned[resource] = self.prefix
            self.save()
        con = self.call("create-connection", "events", "create_connection", {"Name": self.prefix,
            "AuthorizationType": "API_KEY", "AuthParameters": {"ApiKeyAuthParameters": {"ApiKeyName": "x-owned-key", "ApiKeyValue": self.key},
                "InvocationHttpParameters": {"HeaderParameters": [{"Key": "x-shared", "Value": "connection"}],
                    "QueryStringParameters": [{"Key": "shared", "Value": "connection"}]}}})
        self.owned["connection_arn"] = con["ConnectionArn"]
        out = self.call("describe-connection", "events", "describe_connection", {"Name": self.prefix})
        self.owned["secret"] = out["SecretArn"]
        self.save()
        dest = self.call("create-destination", "events", "create_api_destination", {"Name": self.prefix,
            "ConnectionArn": con["ConnectionArn"], "InvocationEndpoint": url + "capture/*",
            "HttpMethod": "POST", "InvocationRateLimitPerSecond": 1})["ApiDestinationArn"]
        self.owned["destination_arn"] = dest
        statements = [{"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                       "Resource": self.owned["queues"]["source"]["arn"]},
                      {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": self.owned["queues"]["target"]["arn"]},
                      {"Effect": "Allow", "Action": "events:InvokeApiDestination", "Resource": dest}]
        self.owned["pipe_policy"] = {"Version": "2012-10-17", "Statement": statements}
        self.owned["pipe_role_arn"] = self.role("pipe", "pipes.amazonaws.com", statements)
        if not self.absent("before-pipe", "pipes", "describe_pipe", {"Name": self.prefix}, {"NotFoundException"}):
            raise RuntimeError("Pipe name occupied")
        self.owned["pipe"] = self.prefix
        self.save()
        time.sleep(12)
        self.call("create-pipe", "pipes", "create_pipe", {"Name": self.prefix,
            "RoleArn": self.owned["pipe_role_arn"], "Source": self.owned["queues"]["source"]["arn"],
            "Target": self.owned["queues"]["target"]["arn"], "Enrichment": dest,
            "EnrichmentParameters": {"HttpParameters": {"PathParameterValues": ["initial"]}},
            "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1, "MaximumBatchingWindowInSeconds": 1}},
            "DesiredState": "RUNNING", "Tags": {"stackd-probe": self.prefix}})
        self.wait_pipe("RUNNING")

    def observe(self, case, seconds=35, target_count=None, audit_count=None):
        end = time.monotonic() + seconds
        start = len(self.data["messages"])
        while time.monotonic() < end:
            for kind in ("audit", "target"):
                queue = self.owned["queues"][kind]
                out = self.call("read-" + case + "-" + kind, "sqs", "receive_message", {
                    "QueueUrl": queue["url"], "WaitTimeSeconds": 1, "MaxNumberOfMessages": 10,
                    "MessageSystemAttributeNames": ["All"]})
                for message in out.get("Messages", []):
                    self.data["messages"].append({"case_window": case, "queue": kind, "at": now(),
                        "message_id": message["MessageId"], "body": json.loads(message["Body"]), "attributes": message.get("Attributes")})
                    self.call("ack-" + kind, "sqs", "delete_message", {"QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]})
            current = self.data["messages"][start:]
            matching = [m for m in current if case in json.dumps(m["body"])]
            targets = sum(m["queue"] == "target" for m in matching)
            audits = sum(m["queue"] == "audit" for m in matching)
            if ((target_count is not None and targets >= target_count) or
                    (audit_count is not None and audits >= audit_count)):
                break
        self.data["cases"].setdefault(case, {}).setdefault("windows", []).append({
            "observed": self.data["messages"][start:], "maximum_seconds": seconds,
            "finished_at": now()})
        self.save()

    def send(self, case, mode="array", count=1):
        sent = self.data.setdefault("sent_messages", 0)
        if sent + count > 20:
            raise RuntimeError("Approved message bound")
        entries = [{"Id": str(i), "MessageBody": json.dumps({"marker": self.prefix + "-" + case + "-" + str(i),
            "mode": mode, "number": i + 4, "text": "owned-native", "route": "original-route", "query": "original-query"})} for i in range(count)]
        self.data["sent_messages"] = sent + count
        self.call("send-" + case, "sqs", "send_message_batch", {"QueueUrl": self.owned["queues"]["source"]["url"], "Entries": entries})

    def update(self, case, parameters):
        self.call("update-" + case, "pipes", "update_pipe", {"Name": self.prefix,
            "RoleArn": self.owned["pipe_role_arn"], "EnrichmentParameters": parameters})
        self.data["cases"].setdefault(case, {})["readback"] = self.wait_pipe("RUNNING")
        self.save()

    def run(self):
        self.setup()
        self.send("batch-array", count=2)
        self.observe("batch-array", seconds=75, target_count=2)
        self.send("object", mode="object")
        self.observe("object", seconds=45, target_count=1)
        self.send("empty", mode="empty")
        self.observe("empty", seconds=20)
        self.send("empty-object", mode="empty-object")
        self.observe("empty-object", seconds=20)
        template = '{"marker":<$.body.marker>,"mode":<$.body.mode>,"number":<$.body.number>,"text":<$.body.text>,"route":"template-route","query":"template-query"}'
        self.update("dynamic", {"InputTemplate": template, "HttpParameters": {
            "PathParameterValues": ["$.body.route"], "HeaderParameters": {"x-shared": "pipe", "x-dynamic": "$.body.route"},
            "QueryStringParameters": {"shared": "pipe", "dynamic": "$.body.query"}}})
        self.send("dynamic")
        self.observe("dynamic", seconds=60, target_count=1)
        self.update("remove-http-empty", {"InputTemplate": template, "HttpParameters": {}})
        self.send("remove-http-empty")
        self.observe("remove-http-empty", seconds=45, target_count=1)
        self.update("remove-http-omitted", {"InputTemplate": template})
        self.send("remove-http-omitted")
        self.observe("remove-http-omitted", seconds=45, target_count=1)
        self.update("restore-path", {"InputTemplate": template, "HttpParameters": {"PathParameterValues": ["authority"]}})
        deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "events:InvokeApiDestination", "Resource": self.owned["destination_arn"]}]}
        self.call("deny-current-role", "iam", "put_role_policy", {"RoleName": self.owned["pipe_role"], "PolicyName": "deny", "PolicyDocument": json.dumps(deny)})
        time.sleep(15)
        self.send("role-denied")
        self.observe("role-denied", seconds=25)
        self.call("recover-current-role", "iam", "delete_role_policy", {"RoleName": self.owned["pipe_role"], "PolicyName": "deny"})
        self.observe("role-denied", seconds=70, target_count=1)
        self.call("wrong-connection-key", "events", "update_connection", {"Name": self.prefix, "AuthorizationType": "API_KEY",
            "AuthParameters": {"ApiKeyAuthParameters": {"ApiKeyName": "x-owned-key", "ApiKeyValue": "wrong-owned-key"}}})
        time.sleep(10)
        self.send("connection-denied")
        self.observe("connection-denied", seconds=20)
        self.call("recover-connection-key", "events", "update_connection", {"Name": self.prefix, "AuthorizationType": "API_KEY",
            "AuthParameters": {"ApiKeyAuthParameters": {"ApiKeyName": "x-owned-key", "ApiKeyValue": self.key}}})
        self.send("connection-recovered")
        self.observe("connection-recovered", seconds=60, target_count=1)
        self.send("http-503", mode="fail")
        self.observe("http-503", seconds=35, audit_count=2)

    def cleanup(self):
        self.cleaning = True
        # Turn off publicly reachable execution before asynchronous control teardown.
        if self.owned.get("function"):
            self.call("delete-url", "lambda", "delete_function_url_config", {"FunctionName": self.prefix}, True)
        if self.owned.get("pipe"):
            self.call("stop-pipe", "pipes", "stop_pipe", {"Name": self.prefix}, True)
            for _ in range(60):
                out = self.call("poll-cleanup-pipe", "pipes", "describe_pipe", {"Name": self.prefix}, True)
                if out.get("Error", {}).get("Code") == "NotFoundException":
                    break
                if out.get("CurrentState") in ("STOPPED", "CREATE_FAILED", "UPDATE_FAILED", "START_FAILED", "STOP_FAILED"):
                    break
                time.sleep(2)
            self.call("delete-pipe", "pipes", "delete_pipe", {"Name": self.prefix}, True)
            for _ in range(60):
                if self.absent("poll-absent-pipe", "pipes", "describe_pipe", {"Name": self.prefix}, {"NotFoundException"}):
                    break
                time.sleep(2)
        for kind, method in (("destination", "delete_api_destination"), ("connection", "delete_connection")):
            if self.owned.get(kind):
                self.call("delete-" + kind, "events", method, {"Name": self.prefix}, True)
        if self.owned.get("function"):
            self.call("delete-function", "lambda", "delete_function", {"FunctionName": self.prefix}, True)
        for kind in ("pipe", "lambda"):
            name = self.owned.get(kind + "_role")
            if name:
                if name != self.prefix + "-" + kind:
                    raise RuntimeError("Foreign role cleanup refused")
                for policy in ("deny", "owned"):
                    self.call("delete-policy-" + kind + "-" + policy, "iam", "delete_role_policy", {"RoleName": name, "PolicyName": policy}, True)
                self.call("delete-role-" + kind, "iam", "delete_role", {"RoleName": name}, True)
        for kind, queue in self.owned.get("queues", {}).items():
            if queue["name"] != self.prefix + "-" + kind or kind not in ("source", "target", "audit"):
                raise RuntimeError("Foreign queue cleanup refused")
            out = self.call("lookup-cleanup-queue-" + kind, "sqs", "get_queue_url", {"QueueName": queue["name"]}, True)
            if "QueueUrl" in out:
                self.call("delete-queue-" + kind, "sqs", "delete_queue", {"QueueUrl": out["QueueUrl"]}, True)
        checks = []
        for kind, service, operation, arg, codes in (
            ("pipe", "pipes", "describe_pipe", "Name", {"NotFoundException"}),
            ("destination", "events", "describe_api_destination", "Name", {"ResourceNotFoundException"}),
            ("connection", "events", "describe_connection", "Name", {"ResourceNotFoundException"}),
            ("function", "lambda", "get_function", "FunctionName", {"ResourceNotFoundException"}),
            ("url", "lambda", "get_function_url_config", "FunctionName", {"ResourceNotFoundException"})):
            if self.owned.get(kind):
                checks.append((kind, service, operation, {arg: self.prefix}, codes))
        if self.owned.get("secret"):
            if not self.owned["secret"].startswith(f"arn:aws:secretsmanager:{REGION}:{self.args.account}:secret:events!connection/{self.prefix}/"):
                raise RuntimeError("Foreign secret cleanup inventory")
            checks.append(("secret", "secretsmanager", "describe_secret", {"SecretId": self.owned["secret"]}, {"ResourceNotFoundException"}))
        for kind in ("pipe", "lambda"):
            if self.owned.get(kind + "_role"):
                checks.append((kind + "_role", "iam", "get_role", {"RoleName": self.prefix + "-" + kind}, {"NoSuchEntity"}))
        for kind, queue in self.owned.get("queues", {}).items():
            checks.append(("queue-" + kind, "sqs", "get_queue_url", {"QueueName": queue["name"]}, {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}))
        for name, service, operation, request, codes in checks:
            absent = False
            for _ in range(20):
                absent = self.absent("absent-" + name, service, operation, request, codes)
                if absent:
                    break
                time.sleep(2)
            self.data["cleanup"][name] = absent
        self.data["cleanup"]["complete"] = all(self.data["cleanup"].get(row[0]) for row in checks)
        self.data["cleanup"]["finished_at"] = now()
        self.save()
        if not self.data["cleanup"]["complete"]:
            raise RuntimeError("Exact-owned absence verification incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/pipes/http_enrichment.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    probe = Probe(args)
    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if not args.cleanup_only:
            probe.run()
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        probe.cleanup()
    print(json.dumps({"capture": str(args.output), "cleanup": probe.data["cleanup"]}), flush=True)


if __name__ == "__main__":
    main()
