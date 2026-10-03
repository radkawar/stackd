#!/usr/bin/env python3
"""Capture owned native Parameter Store behavior or replay it against a local endpoint.

Native: env PYTHONPATH=scripts/aws python3 -B -P scripts/aws/ssm_parameter_store_probe.py --account ACCOUNT_ID --output .stackd/probes/ssm/parameter_store.json
Replay: same command with --account LOCAL_ACCOUNT_ID --endpoint http://127.0.0.1:4566 --replay testdata/aws/ssm/parameter_store.json --output /tmp/ssm-replay.json
The shared cloudtrail_events module must be importable for native capture. No
standing service setting or key is modified; values are synthetic public fixtures.
Native collection is bounded positive evidence, not proof of event absence.
"""
import argparse
import ast
from datetime import datetime, timedelta, timezone
import hashlib
from itertools import groupby
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlparse
import uuid

import aws_cli

REGION = "us-east-1"
REFERENCES = [
    "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_" + operation + ".html"
    for operation in ("PutParameter", "GetParameter", "GetParameters", "GetParametersByPath",
                      "GetParameterHistory", "DescribeParameters", "LabelParameterVersion",
                      "UnlabelParameterVersion", "AddTagsToResource", "RemoveTagsFromResource",
                      "ListTagsForResource", "DeleteParameter", "DeleteParameters")
] + ["https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-cwe.html"]
SECRET_KEYS = {"accesskeyid", "secretaccesskey", "sessiontoken", "securitytoken", "authorization", "signature", "receipthandle"}


def now():
    return datetime.now(timezone.utc).isoformat()


def sanitize(value):
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower().replace("-", "") in SECRET_KEYS else sanitize(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "<redacted-access-key>", value)
    return value


def revision(path):
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def require(result):
    if result["code"] != "Success":
        raise RuntimeError("Required request failed: " + json.dumps(result))
    return result["output"]


class Capture:
    def __init__(self, args):
        self.args = args
        self.path = Path(args.output)
        if self.path.exists():
            raise ValueError("Refusing to overwrite existing evidence: " + str(self.path))
        self.env = dict(os.environ, AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
                        AWS_MAX_ATTEMPTS="1", AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off",
                        AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
        if args.endpoint:
            parsed = urlparse(args.endpoint)
            if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("Replay endpoint must be loopback; never forward native credentials")
            for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
                self.env.pop(key, None)
            self.env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_EC2_METADATA_DISABLED="true")
        self.prefix = "/stackd-ssm-" + uuid.uuid4().hex[:16]
        self.name = self.prefix[1:]
        self.owned = set()
        self.queue_url = None
        self.rule_owned = False
        self.phase = "setup"
        self.data = {
            "schema_version": 1, "captured_at": now(), "endpoint": args.endpoint or "native AWS",
            "region": REGION, "prefix": self.prefix, "scenario": args.scenario, "calls": [], "ownership": [],
            "eventbridge": {"events": [], "boundary": "Only observed messages; absence within bounds is not native absence."},
            "cleanup": {"confirmed": False, "remaining": [], "errors": []},
            "sources": {"repository": revision(Path(__file__).resolve().parents[2]),
                        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "sdk_repository": "/home/r/dev/minor/stackd/clones/aws-sdk-go-v2",
                        "sdk_revision": revision("/home/r/dev/minor/stackd/clones/aws-sdk-go-v2"),
                        "references": REFERENCES},
            "safety": {"account_required": self.args.account, "region_required": REGION,
                       "fixture_values_only": True, "kms_key": "alias/aws/ssm (no key mutations)",
                       "standing_settings_mutated": False, "max_owned_parameters": 20,
                       "max_owned_rules": 1, "max_owned_queues": 1},
        }
        self.save()

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(sanitize(self.data), indent=2, sort_keys=True) + "\n")

    def call(self, label, operation, parameters, service="ssm"):
        row = {"label": label, "phase": self.phase, "at": now(), "service": service,
               "operation": operation, "request": parameters}
        self.data["calls"].append(row)
        self.save()
        options = ["--debug", "--region", REGION, "--no-paginate", "--cli-connect-timeout", "10", "--cli-read-timeout", "30"]
        if self.args.endpoint:
            options += ["--endpoint-url", self.args.endpoint]
        try:
            process = aws_cli.run(service, operation, parameters, self.env, options=options, timeout=50)
            result = aws_cli.result(process, debug=True)
            for line in process.stderr.splitlines():
                if "Response headers:" in line:
                    headers = ast.literal_eval(line.split("Response headers:", 1)[1].strip())
                    for key, value in headers.items():
                        if key.lower() in ("x-amzn-requestid", "x-amzn-request-id", "x-amz-request-id"):
                            result["request_id"] = value
                if line.startswith(("b'{", 'b"{')):
                    try:
                        body = json.loads(ast.literal_eval(line))
                    except (ValueError, SyntaxError, UnicodeDecodeError):
                        continue
                    if process.returncode:
                        result["error"] = body
            row["result"] = result
            self.save()
            if process.returncode and result["code"] == "CLIError":
                raise RuntimeError("Non-service CLI failure: " + label + ": " + result.get("message", ""))
            return result
        except Exception as error:
            row["failure"] = {"type": type(error).__name__, "message": str(error)}
            self.save()
            raise

    def raw_put(self, label, operation, parameters):
        """Bypass CLI shape checks; use the existing signer on native AWS."""
        row = {"label": label, "phase": self.phase, "at": now(), "service": "ssm",
               "operation": operation, "request": parameters, "transport": "raw-signed"}
        self.data["calls"].append(row)
        self.save()
        try:
            if self.args.endpoint:
                process = subprocess.run([
                    "curl", "--silent", "--show-error", "--include", "--connect-timeout", "10", "--max-time", "30",
                    "--aws-sigv4", "aws:amz:us-east-1:ssm", "--user", "test:test",
                    "--header", "content-type: application/x-amz-json-1.1",
                    "--header", "x-amz-target: AmazonSSM.PutParameter",
                    "--data-binary", json.dumps(parameters), self.args.endpoint,
                ], capture_output=True, text=True, check=True, env=self.env, timeout=35)
                headers, separator, body = process.stdout.partition("\n\n")
                if not separator:
                    raise RuntimeError("Raw endpoint returned no HTTP header/body boundary")
                status = int(headers.splitlines()[0].split()[1])
                output = json.loads(body)
                request_id = next((line.split(":", 1)[1].strip() for line in headers.splitlines()[1:]
                    if line.lower().startswith(("x-amzn-requestid:", "x-amzn-request-id:"))), None)
                result = {"code": "Success", "output": output} if 200 <= status < 300 else {
                    "code": output["__type"].split("#")[-1], "error": output}
                result.update(http_status=status, request_id=request_id)
            else:
                from signed_requests import signed_post
                response = signed_post("ssm.us-east-1.amazonaws.com", "ssm", json.dumps(parameters).encode(),
                    {"content-type": "application/x-amz-json-1.1", "x-amz-target": "AmazonSSM.PutParameter"}, self.env)
                row["raw_response"] = {"status": response.status, "request_id": response.request_id, "body": response.body.decode("utf-8", "replace")}
                self.save()
                output = json.loads(response.body)
                result = {"code": "Success", "output": output} if 200 <= response.status < 300 else {
                    "code": output["__type"].split("#")[-1], "error": output}
                result.update(http_status=response.status, request_id=response.request_id)
            row["result"] = result
            self.save()
            return result
        except Exception as error:
            row["failure"] = {"type": type(error).__name__, "message": str(error)}
            self.save()
            raise

    def put(self, label, leaf, value, *, bare=False, raw=False, **fields):
        name = self.name + "-" + leaf if bare else self.prefix + "/" + leaf
        fresh = name not in self.owned
        request = dict(Name=name, Value=value, **fields)
        if fresh:
            before = self.call("preflight-" + label, "get-parameter", {"Name": name})
            if before["code"] not in ("ParameterNotFound", "ValidationException"):
                raise RuntimeError("Refusing to mutate an existing or ambiguous parameter " + name)
            request.setdefault("Overwrite", False)
            request.setdefault("Tags", [{"Key": "stackd-probe", "Value": self.name}])
            self.data["ownership"].append({"kind": "parameter", "name": name, "status": "create-attempted", "at": now()})
            self.save()
        result = (self.raw_put if raw else self.call)(label, "put-parameter", request)
        if fresh and result["code"] == "Success":
            self.owned.add(name)
            self.data["ownership"][-1].update(status="created", request_id=result.get("request_id"))
            self.save()
        return result

    def pages(self, label, operation, request, field):
        rows = []
        tokens = set()
        for page in range(25):
            result = self.call(label + "-" + str(page), operation, request)
            if result["code"] != "Success":
                return result
            output = result["output"]
            rows.extend(output.get(field, []))
            token = output.get("NextToken")
            if not token:
                self.data.setdefault("collections", {})[label] = rows
                self.save()
                return result
            if token in tokens:
                raise RuntimeError("Repeated pagination token: " + label)
            tokens.add(token)
            request = dict(request, NextToken=token)
        raise RuntimeError("Pagination exceeded owned small-resource bound: " + label)

    def setup_events(self):
        rule = self.call("preflight-event-rule", "describe-rule", {"Name": self.name}, "events")
        if rule["code"] != "ResourceNotFoundException":
            raise RuntimeError("Rule name not proven absent")
        queue = self.call("preflight-event-queue", "get-queue-url", {"QueueName": self.name}, "sqs")
        if queue["code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise RuntimeError("Queue name not proven absent")
        self.queue_url = require(self.call("create-event-queue", "create-queue", {
            "QueueName": self.name, "Attributes": {"MessageRetentionPeriod": "3600"},
            "tags": {"stackd-probe": self.name}}, "sqs"))["QueueUrl"]
        self.data["ownership"].append({"kind": "queue", "url": self.queue_url, "status": "created"})
        self.save()
        queue_arn = require(self.call("event-queue-arn", "get-queue-attributes", {
            "QueueUrl": self.queue_url, "AttributeNames": ["QueueArn"]}, "sqs"))["Attributes"]["QueueArn"]
        rule_arn = require(self.call("create-event-rule", "put-rule", {
            "Name": self.name, "State": "ENABLED", "EventPattern": json.dumps({
                "source": ["aws.ssm"], "detail-type": ["Parameter Store Change"],
                "detail": {"name": [{"prefix": self.prefix + "/"}]} }),
            "Tags": [{"Key": "stackd-probe", "Value": self.name}]}, "events"))["RuleArn"]
        self.rule_owned = True
        self.data["ownership"].append({"kind": "rule", "name": self.name, "arn": rule_arn, "status": "created"})
        self.save()
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]}
        require(self.call("event-queue-policy", "set-queue-attributes", {
            "QueueUrl": self.queue_url, "Attributes": {"Policy": json.dumps(policy)}}, "sqs"))
        output = require(self.call("event-rule-target", "put-targets", {
            "Rule": self.name, "Targets": [{"Id": "owned-queue", "Arn": queue_arn}]}, "events"))
        if output.get("FailedEntryCount"):
            raise RuntimeError("EventBridge target rejected: " + json.dumps(output))
        time.sleep(self.args.event_settle_seconds)

    def collect_events(self):
        self.phase = "events"
        deadline = time.monotonic() + self.args.event_wait_seconds
        seen = set()
        while time.monotonic() < deadline:
            output = require(self.call("receive-owned-events", "receive-message", {
                "QueueUrl": self.queue_url, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 10,
                "VisibilityTimeout": 60}, "sqs"))
            for message in output.get("Messages", []):
                event = json.loads(message["Body"])
                if event.get("id") not in seen:
                    self.data["eventbridge"]["events"].append(event)
                    seen.add(event.get("id"))
                    self.save()
                require(self.call("ack-owned-event", "delete-message", {
                    "QueueUrl": self.queue_url, "ReceiptHandle": message["ReceiptHandle"]}, "sqs"))
            operations = {event.get("detail", {}).get("operation") for event in self.data["eventbridge"]["events"]}
            if {"Create", "Update", "Delete"} <= operations:
                break
        self.data["eventbridge"]["wait_seconds_bound"] = self.args.event_wait_seconds
        self.save()

    def cleanup(self):
        self.phase = "cleanup"
        remaining = []
        def attempt(label, operation, request, service="ssm"):
            try:
                return self.call(label, operation, request, service)
            except Exception as error:
                self.data["cleanup"]["errors"].append({"label": label, "message": str(error)})
                return {"code": "TransportFailure"}
        for name in sorted(self.owned):
            attempt("cleanup-parameter", "delete-parameter", {"Name": name})
            check = attempt("verify-parameter-absent", "get-parameter", {"Name": name})
            if check["code"] != "ParameterNotFound":
                remaining.append(name)
        if self.rule_owned:
            attempt("cleanup-event-target", "remove-targets", {"Rule": self.name, "Ids": ["owned-queue"]}, "events")
            attempt("cleanup-event-rule", "delete-rule", {"Name": self.name}, "events")
            if attempt("verify-rule-absent", "describe-rule", {"Name": self.name}, "events")["code"] != "ResourceNotFoundException":
                remaining.append("rule:" + self.name)
        if self.queue_url:
            attempt("cleanup-event-queue", "delete-queue", {"QueueUrl": self.queue_url}, "sqs")
            check = attempt("verify-queue-absent", "get-queue-url", {"QueueName": self.name}, "sqs")
            if check["code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
                remaining.append(self.queue_url)
        self.data["cleanup"].update(remaining=remaining, confirmed=not remaining and not self.data["cleanup"]["errors"], finished_at=now())
        self.save()

    def cloudtrail(self):
        from cloudtrail_events import CollectionError, collect_history
        import cloudtrail_events
        self.data["sources"]["cloudtrail_collector"] = {"path": cloudtrail_events.__file__,
            "sha256": hashlib.sha256(Path(cloudtrail_events.__file__).read_bytes()).hexdigest()}
        selected = {row["result"]["request_id"]: row["label"] for row in self.data["calls"]
                    if row["service"] == "ssm" and row["phase"] == "semantics"
                    and row.get("result", {}).get("request_id") and not row["label"].startswith("preflight-")}
        try:
            result = collect_history(lambda request: aws_cli.call("cloudtrail", "lookup-events", request,
                self.env, paginate=False, error_format="json"), selected, start_time=self.data["captured_at"],
                event_sources=("ssm.amazonaws.com",), max_pages=5, rounds=self.args.cloudtrail_rounds,
                wait_seconds=self.args.cloudtrail_wait_seconds)
        except CollectionError as error:
            self.data["cloudtrail"] = error.result
            self.save()
            raise
        self.data["cloudtrail"] = result
        self.save()


def semantics(cap):
    cap.phase = "semantics"
    p = cap.prefix
    call = cap.call
    require(cap.put("create-string", "string", "fixture-one", Type="String", Tier="Standard", Description="fixture description", AllowedPattern="fixture-.*"))
    call("duplicate-string", "put-parameter", {"Name": p + "/string", "Value": "fixture-duplicate", "Type": "String"})
    require(cap.put("create-list", "list", "red, green,blue", Type="StringList", Tier="Standard"))
    require(cap.put("create-secure", "nested/secure", "fixture-public-not-secret", Type="SecureString", KeyId="alias/aws/ssm", Tier="Standard"))
    require(cap.put("create-nested", "nested/string", "fixture-nested", Type="String", Tier="Standard"))
    for label, request in (
        ("get-string", {"Name": p + "/string"}),
        ("get-list", {"Name": p + "/list"}),
        ("get-secure-encrypted", {"Name": p + "/nested/secure"}),
        ("get-secure-decrypted", {"Name": p + "/nested/secure", "WithDecryption": True}),
        ("get-string-arn", {"Name": "arn:aws:ssm:" + REGION + ":" + cap.data["identity"]["Account"] + ":parameter" + p + "/string"}),
    ):
        require(call(label, "get-parameter", request))
    call("label-version-one", "label-parameter-version", {"Name": p + "/string", "ParameterVersion": 1, "Labels": ["stable", "old"]})
    require(cap.put("overwrite-string", "string", "fixture-two", Type="String", Overwrite=True))
    call("label-move", "label-parameter-version", {"Name": p + "/string", "ParameterVersion": 2, "Labels": ["stable"]})
    call("labels-invalid-mixed", "label-parameter-version", {"Name": p + "/string", "Labels": ["valid", "123bad", "awsBad", "ssmBad", "bad label"]})
    call("label-version-missing", "label-parameter-version", {"Name": p + "/string", "ParameterVersion": 99, "Labels": ["uncreated"]})
    for selector in (":1", ":2", ":stable", ":old", ":missing", ":99", ":0", ":-1", ":1:2"):
        call("selector" + selector, "get-parameter", {"Name": p + "/string" + selector})
    call("get-batch", "get-parameters", {"Names": [p + "/string:1", p + "/list", p + "/string", p + "/list", p + "/missing", p + "/string:99", p + "/nested/secure"], "WithDecryption": True})
    cap.pages("history", "get-parameter-history", {"Name": p + "/string", "MaxResults": 1}, "Parameters")
    call("secure-history", "get-parameter-history", {"Name": p + "/nested/secure", "WithDecryption": True})
    call("unlabel-mixed", "unlabel-parameter-version", {"Name": p + "/string", "ParameterVersion": 1, "Labels": ["old", "stable", "missing"]})
    call("unlabel-version-missing", "unlabel-parameter-version", {"Name": p + "/string", "ParameterVersion": 99, "Labels": ["old"]})
    cap.pages("path-shallow", "get-parameters-by-path", {"Path": p, "Recursive": False, "MaxResults": 2, "WithDecryption": True}, "Parameters")
    cap.pages("path-recursive", "get-parameters-by-path", {"Path": p, "Recursive": True, "MaxResults": 2, "WithDecryption": True}, "Parameters")
    for label, key, option, values in (("type", "Type", "Equals", ["String"]), ("label", "Label", "Equals", ["stable"]),
            ("key", "KeyId", "Equals", ["alias/aws/ssm"]), ("invalid-key", "Name", "Equals", [p + "/string"]),
            ("invalid-option", "Type", "Contains", ["String"]), ("label-begins", "Label", "BeginsWith", ["st"])):
        call("path-filter-" + label, "get-parameters-by-path", {"Path": p, "Recursive": True,
            "WithDecryption": True, "ParameterFilters": [{"Key": key, "Option": option, "Values": values}]})
    call("path-invalid-token", "get-parameters-by-path", {"Path": p, "NextToken": "fixture-invalid-token"})
    call("add-tags", "add-tags-to-resource", {"ResourceType": "Parameter", "ResourceId": p + "/string", "Tags": [{"Key": "env", "Value": "one"}, {"Key": "empty", "Value": ""}]})
    call("replace-tag", "add-tags-to-resource", {"ResourceType": "Parameter", "ResourceId": p + "/string", "Tags": [{"Key": "env", "Value": "two"}]})
    call("list-tags", "list-tags-for-resource", {"ResourceType": "Parameter", "ResourceId": p + "/string"})
    call("remove-tags", "remove-tags-from-resource", {"ResourceType": "Parameter", "ResourceId": p + "/string", "TagKeys": ["empty", "absent"]})
    call("list-tags-after-remove", "list-tags-for-resource", {"ResourceType": "Parameter", "ResourceId": p + "/string"})
    call("overwrite-with-tags", "put-parameter", {"Name": p + "/string", "Value": "fixture-three", "Overwrite": True, "Tags": [{"Key": "new", "Value": "bad"}]})
    call("tags-missing", "list-tags-for-resource", {"ResourceType": "Parameter", "ResourceId": p + "/missing"})
    filters = [{"Key": "Name", "Option": "BeginsWith", "Values": [p + "/"]}]
    cap.pages("describe", "describe-parameters", {"ParameterFilters": filters, "MaxResults": 2}, "Parameters")
    call("describe-tag-filter", "describe-parameters", {"ParameterFilters": filters + [{"Key": "tag:env", "Values": ["two"]}]})
    call("describe-path-default", "describe-parameters", {"ParameterFilters": [{"Key": "Path", "Values": [p]}]})
    call("describe-path-recursive", "describe-parameters", {"ParameterFilters": [{"Key": "Path", "Option": "Recursive", "Values": [p]}]})
    call("describe-type-no-values", "describe-parameters", {"ParameterFilters": filters + [{"Key": "Type"}]})
    call("describe-key-no-values", "describe-parameters", {"ParameterFilters": filters + [{"Key": "KeyId"}]})
    call("describe-legacy-prefix", "describe-parameters", {"Filters": [{"Key": "Name", "Values": [p + "/"]}]})
    call("describe-legacy-exact", "describe-parameters", {"Filters": [{"Key": "Name", "Values": [p + "/string"]}]})
    call("path-label-old-version", "get-parameters-by-path", {"Path": p, "Recursive": True, "ParameterFilters": [{"Key": "Label", "Values": ["valid"]}]})
    call("overwrite-pattern-mismatch", "put-parameter", {"Name": p + "/string", "Value": "different", "Overwrite": True})
    cap.put("invalid-pattern", "bad-pattern", "fixture", Type="String", AllowedPattern="[")
    cap.put("invalid-name", "bad name", "fixture", Type="String")
    cap.put("invalid-data-type", "bad-data-type", "fixture", Type="String", DataType="bad")
    cap.put("integration-data-type", "integration-data-type", "fixture", Type="String", DataType="aws:ssm:integration")
    cap.put("invalid-type", "bad-type", "fixture", Type="BadType")
    cap.put("invalid-stringlist", "bad-list", "a,,b", Type="StringList", Tier="Standard")
    call("get-empty-list-elements", "get-parameter", {"Name": p + "/bad-list"})
    call("overwrite-list-spaces", "put-parameter", {"Name": p + "/list", "Value": " red , ,blue, ", "Overwrite": True})
    call("get-list-spaces", "get-parameter", {"Name": p + "/list"})
    cap.put("invalid-template-value", "template", "{{ssm:fixture}}", Type="String")
    cap.put("standard-too-large", "large", "x" * 4097, Type="String", Tier="Standard")
    cap.put("advanced-large", "large", "x" * 4097, Type="String", Tier="Advanced")
    call("advanced-downgrade", "put-parameter", {"Name": p + "/large", "Value": "short", "Type": "String", "Tier": "Standard", "Overwrite": True})
    policy = json.dumps([{"Type": "Expiration", "Version": "1.0", "Attributes": {"Timestamp": (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}},
                         {"Type": "NoChangeNotification", "Version": "1.0", "Attributes": {"After": "1", "Unit": "Days"}}])
    cap.put("standard-policy", "policy-standard", "fixture-policy", Type="String", Tier="Standard", Policies=policy)
    require(cap.put("advanced-policy", "policy", "fixture-policy", Type="String", Tier="Advanced", Policies=policy))
    call("describe-policy", "describe-parameters", {"ParameterFilters": [{"Key": "Name", "Values": [p + "/policy"]}]})
    call("policy-history", "get-parameter-history", {"Name": p + "/policy"})
    call("invalid-policy-type", "put-parameter", {"Name": p + "/policy", "Value": "fixture-policy", "Overwrite": True, "Policies": '[{"Type":"BadType","Version":"1.0","Attributes":{}}]'})
    call("invalid-policy-json", "put-parameter", {"Name": p + "/policy", "Value": "fixture-policy", "Overwrite": True, "Policies": "not-json"})
    for label, policies in (
        ("policy-after-zero", [{"Type": "NoChangeNotification", "Version": "1.0", "Attributes": {"After": "0", "Unit": "Days"}}]),
        ("policy-after-fraction", [{"Type": "NoChangeNotification", "Version": "1.0", "Attributes": {"After": "0.5", "Unit": "Days"}}]),
        ("policy-expiration-duplicate", [json.loads(policy)[0], json.loads(policy)[0]]),
        ("policy-empty-object", [{}]),
    ):
        call(label, "put-parameter", {"Name": p + "/policy", "Value": "fixture-policy", "Overwrite": True, "Policies": json.dumps(policies)})
    call("clear-policies", "put-parameter", {"Name": p + "/policy", "Value": "fixture-policy-cleared", "Overwrite": True, "Policies": "[]"})
    call("describe-cleared-policy", "describe-parameters", {"ParameterFilters": [{"Key": "Name", "Values": [p + "/policy"]}]})
    require(cap.put("create-secure-advanced", "secure-advanced", "fixture-advanced-public", Type="SecureString", Tier="Advanced", KeyId="alias/aws/ssm"))
    call("get-secure-advanced-encrypted", "get-parameter", {"Name": p + "/secure-advanced"})
    call("get-secure-advanced-decrypted", "get-parameter", {"Name": p + "/secure-advanced", "WithDecryption": True})
    call("promote-standard", "put-parameter", {"Name": p + "/string", "Value": "fixture-promoted", "Overwrite": True, "Tier": "Advanced"})
    call("string-to-list", "put-parameter", {"Name": p + "/nested/string", "Value": "fixture-a,fixture-b", "Type": "StringList", "Overwrite": True})
    call("get-string-to-list", "get-parameter", {"Name": p + "/nested/string"})
    call("secure-overwrite-omitted-fields", "put-parameter", {"Name": p + "/nested/secure", "Value": "fixture-public-updated", "Overwrite": True})
    call("secure-history-after-overwrite", "get-parameter-history", {"Name": p + "/nested/secure", "WithDecryption": True})
    call("secure-to-string", "put-parameter", {"Name": p + "/nested/secure", "Value": "fixture-public-converted", "Type": "String", "Overwrite": True})
    call("get-secure-to-string", "get-parameter", {"Name": p + "/nested/secure", "WithDecryption": True})
    call("describe-after-overwrites", "describe-parameters", {"ParameterFilters": filters})
    call("delete-batch", "delete-parameters", {"Names": [p + "/list", p + "/nested/string", p + "/missing"]})
    for name in (p + "/list", p + "/nested/string"):
        check = call("verify-batch-deleted-" + name.rsplit("/", 1)[-1], "get-parameter", {"Name": name})
        if check["code"] == "ParameterNotFound":
            cap.owned.discard(name)
    call("delete-missing", "delete-parameter", {"Name": p + "/missing"})
    call("get-missing", "get-parameter", {"Name": p + "/missing"})
    cap.data["semantic_workflow_completed"] = True
    cap.save()


def selector_edges(cap):
    cap.phase = "semantics"
    p = cap.prefix
    name = p + "/selectors"
    call = cap.call
    require(cap.put("edge-create-string", "selectors", "fixture-history-one", Type="String", Tier="Standard"))
    require(call("edge-label-first", "label-parameter-version", {"Name": name, "Labels": ["historical"]}))
    require(cap.put("edge-update-string", "selectors", "fixture-history-two", Overwrite=True))
    require(call("edge-label-second", "label-parameter-version", {"Name": name, "Labels": ["current"]}))
    call("edge-path-historical-label", "get-parameters-by-path", {"Path": p, "ParameterFilters": [{"Key": "Label", "Values": ["historical"]}]})
    call("edge-path-both-labels", "get-parameters-by-path", {"Path": p, "ParameterFilters": [{"Key": "Label", "Values": ["historical", "current"]}]})
    for selector in (":", ":01", ":2147483648"):
        call("edge-selector" + selector, "get-parameter", {"Name": name + selector})
    call("edge-batch-invalid-order", "get-parameters", {"Names": [p + "/z-missing", p + "/a-missing", p + "/z-missing", name + ":no-label", name + ":999"]})
    arn = "arn:aws:ssm:" + REGION + ":" + cap.data["identity"]["Account"] + ":parameter" + name
    call("edge-batch-selectors-aliases", "get-parameters", {"Names": [name + ":2", name, name + ":1", name + ":2", arn]})
    call("edge-label-invalid-duplicates", "label-parameter-version", {"Name": name, "Labels": ["bad label", "bad label", "AWSbad", "Ssmbad", "current", "current"]})
    call("edge-label-all-invalid", "label-parameter-version", {"Name": name, "Labels": ["1number", "bad:colon"]})
    call("edge-label-too-long", "label-parameter-version", {"Name": name, "Labels": ["x" * 101]})
    call("edge-labels-history", "get-parameter-history", {"Name": name})
    call("edge-unlabel-invalid", "unlabel-parameter-version", {"Name": name, "ParameterVersion": 2, "Labels": ["bad label", "1number"]})
    require(cap.put("edge-create-bare", "bare", "fixture-bare", bare=True, Type="String", Tier="Standard"))
    bare = cap.name + "-bare"
    call("edge-get-bare", "get-parameter", {"Name": bare})
    call("edge-get-bare-leading-slash", "get-parameter", {"Name": "/" + bare})
    call("edge-batch-bare-aliases", "get-parameters", {"Names": ["/" + bare, bare]})
    call("edge-describe-bare", "describe-parameters", {"ParameterFilters": [{"Key": "Name", "Values": [bare]}]})
    cap.data["semantic_workflow_completed"] = True
    cap.save()


def write_edges(cap):
    cap.phase = "semantics"
    require(cap.put("write-edge-create-string", "conversion", "fixture-plain-conversion", Type="String", Tier="Standard"))
    cap.put("write-edge-string-to-secure", "conversion", "fixture-secret-conversion", Type="SecureString",
            KeyId="alias/aws/ssm", Overwrite=True)
    cap.call("write-edge-read-converted", "get-parameter", {"Name": cap.prefix + "/conversion", "WithDecryption": True})
    cap.call("write-edge-conversion-history", "get-parameter-history", {"Name": cap.prefix + "/conversion", "WithDecryption": True})
    cap.data["semantic_workflow_completed"] = True
    cap.save()


def empty_value(cap):
    cap.phase = "semantics"
    cap.put("empty-value-create", "empty", "", raw=True, Type="String", Tier="Standard")
    cap.call("empty-value-read", "get-parameter", {"Name": cap.prefix + "/empty"})
    cap.data["semantic_workflow_completed"] = True
    cap.save()


def comparable(result, prefix, identity, operation=None):
    def walk(value, field=None):
        if isinstance(value, dict):
            normalized = {key: walk(item, key) for key, item in value.items()
                          if key not in ("LastModifiedDate", "LastModifiedUser", "NextToken")}
            if value.get("Type") == "SecureString" and value.get("Value") and not value["Value"].startswith("fixture-"):
                normalized["Value"] = "<ciphertext>"
            return normalized
        if isinstance(value, list):
            items = [walk(item) for item in value]
            if field in (None, "Parameters") and operation in ("describe-parameters", "get-parameters-by-path"):
                return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
            if field == "Parameters" and operation == "get-parameters":
                return [item for _, group in groupby(items, key=lambda item: item.get("Name"))
                        for item in sorted(group, key=lambda item: json.dumps(item, sort_keys=True))]
            return sorted(items, key=lambda item: json.dumps(item, sort_keys=True)) if field in ("TagList", "Tags", "Labels", "InvalidLabels", "Policies") else items
        if isinstance(value, str):
            if field == "PolicyText":
                return walk(json.loads(value))
            if field == "Timestamp":
                return "<deadline>"
            return value.replace(prefix, "<owned-prefix>").replace(prefix.lstrip("/"), "<owned-name>").replace(identity["Account"], "<account>")
        return value
    return {"code": result["code"], **({"output": walk(result["output"])} if result["code"] == "Success" else {})}


def compare(cap, source):
    expected = json.loads(Path(source).read_text())
    if "identity" not in cap.data:
        cap.data["replay"] = {"fixture": str(source), "passed": False, "error": "Local identity setup failed; no semantic replay occurred."}
        cap.save()
        return False
    def rows(data):
        return {row["label"]: row for row in data["calls"] if row["phase"] == "semantics"
                and not row["label"].startswith("preflight-")
                and not re.search(r"-(?:\d+)$", row["label"])}
    actual = rows(cap.data)
    mismatches = []
    unobserved = []
    for label, row in rows(expected).items():
        if "result" not in row:
            unobserved.append(label)
            continue
        if label not in actual or "result" not in actual[label]:
            mismatches.append({"label": label, "error": "missing local response"})
            continue
        want = comparable(row["result"], expected["prefix"], expected["identity"], row["operation"])
        got = comparable(actual[label]["result"], cap.prefix, cap.data["identity"], row["operation"])
        if want != got:
            mismatches.append({"label": label, "expected": want, "actual": got})
    for label, values in expected.get("collections", {}).items():
        operation = next(row["operation"] for row in expected["calls"] if row["label"] == label + "-0")
        want = comparable({"code": "Success", "output": values}, expected["prefix"], expected["identity"], operation)
        got = comparable({"code": "Success", "output": cap.data.get("collections", {}).get(label)}, cap.prefix, cap.data["identity"], operation)
        if want != got:
            mismatches.append({"label": label, "expected": want, "actual": got})
    cap.data["replay"] = {"fixture": str(source), "mismatches": mismatches, "passed": not mismatches,
        "native_transport_failures_not_compared": unobserved,
        "comparison": "Native error codes and decoded outputs; unordered Describe/ByPath members, tag/label/policy sets and equal-name batch ties normalized with run-specific identity/time/token/ciphertext. GetParameters name order, history order, cardinality, field presence, and plaintext decryption remain compared."}
    cap.save()
    return not mismatches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--endpoint")
    parser.add_argument("--replay")
    parser.add_argument("--scenario", choices=("semantics", "selector-edges", "write-edges", "empty-value"), default="semantics")
    parser.add_argument("--events", action="store_true", help="Also exercise EventBridge/SQS on the local endpoint")
    parser.add_argument("--event-settle-seconds", type=float, default=15)
    parser.add_argument("--event-wait-seconds", type=float, default=120)
    parser.add_argument("--cloudtrail-rounds", type=int, default=8)
    parser.add_argument("--cloudtrail-wait-seconds", type=float, default=30)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.replay and not args.endpoint:
        parser.error("--replay requires an explicit loopback --endpoint")
    if args.replay:
        args.scenario = json.loads(Path(args.replay).read_text()).get("scenario", "semantics")
    cap = Capture(args)
    try:
        identity = require(cap.call("identity", "get-caller-identity", {}, "sts"))
        cap.data["identity"] = identity
        cap.save()
        if identity["Account"] != args.account:
            raise RuntimeError("Native account mismatch; refusing mutations")
        if (not args.endpoint and args.scenario == "semantics") or args.events:
            cap.setup_events()
        if args.scenario == "selector-edges":
            selector_edges(cap)
        elif args.scenario == "write-edges":
            write_edges(cap)
        elif args.scenario == "empty-value":
            empty_value(cap)
        else:
            semantics(cap)
        if cap.queue_url:
            cap.collect_events()
    except Exception as error:
        cap.data["failure"] = {"type": type(error).__name__, "message": str(error)}
        cap.save()
    finally:
        cap.cleanup()
    if not args.endpoint and "identity" in cap.data and cap.data["identity"]["Account"] == args.account:
        try:
            cap.cloudtrail()
        except Exception as error:
            cap.data["collection_failure"] = {"type": type(error).__name__, "message": str(error)}
            cap.save()
    passed = compare(cap, args.replay) if args.replay else True
    print(json.dumps({"output": str(cap.path), "semantic_workflow_completed": cap.data.get("semantic_workflow_completed", False),
                      "cleanup": cap.data["cleanup"], "eventbridge_events": len(cap.data["eventbridge"]["events"]),
                      "cloudtrail_events": len(cap.data.get("cloudtrail", {}).get("events", [])), "replay_passed": passed if args.replay else None}, indent=2))
    if cap.data.get("failure") or cap.data.get("collection_failure") or not cap.data["cleanup"]["confirmed"] or not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
