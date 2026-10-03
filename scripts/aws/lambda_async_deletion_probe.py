#!/usr/bin/env python3
"""Exact-owned native async deletion/recreation calibration; --cleanup-only recovers.

Requires an ethics-reviewed run. Refuses existing evidence, foreign account/actor,
endpoint overrides, or unverified cleanup ownership. Native IAM denials are not
bypassed. The JSON output is the durable inventory and raw observation ledger.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import threading
import time
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudtrail_service_probe import REGION, document, now


SOURCES = [
    "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html",
    "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html",
    "https://docs.aws.amazon.com/lambda/latest/api/API_PutFunctionEventInvokeConfig.html",
    "https://docs.aws.amazon.com/lambda/latest/dg/configuration-aliases.html",
]
HANDLER = '''import json,os,time,boto3
from botocore.config import Config
sqs=boto3.client("sqs",config=Config(connect_timeout=3,read_timeout=5,retries={"total_max_attempts":1}))
DEPLOYMENT=DEPLOYMENT_VALUE

def handler(event,context):
    marker={"case":event["case"],"event":event,"deployment":DEPLOYMENT,
            "version":context.function_version,"invoked_arn":context.invoked_function_arn,
            "request_id":context.aws_request_id,"started_at":time.time()}
    def send(phase):
        sqs.send_message(QueueUrl=os.environ["MARKER_QUEUE"],MessageBody=json.dumps(dict(marker,phase=phase,at=time.time())))
    send("entry")
    time.sleep(min(float(event.get("sleep",0)),130))
    send("exit")
    if event.get("mode")=="fail":
        raise RuntimeError("owned-calibration-failure:"+event["case"])
    return marker
'''


def recorded(value):
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode(), "bytes": len(value)}
    if isinstance(value, dict):
        return {key: "<redacted-receipt>" if key == "ReceiptHandle" else recorded(item)
                for key, item in document(value).items()}
    if isinstance(value, list):
        return [recorded(item) for item in value]
    if isinstance(value, str) and value.startswith(("https://", "http://")):
        url = urlsplit(value)
        query = parse_qsl(url.query, keep_blank_values=True)
        sensitive = {"x-amz-security-token", "x-amz-credential", "x-amz-signature",
                     "awsaccesskeyid", "signature", "securitytoken"}
        if any(key.lower() in sensitive for key, _ in query):
            return urlunsplit(url._replace(query=urlencode([
                (key, "<redacted-capability>" if key.lower() in sensitive else item)
                for key, item in query])))
    return document(value)


class Probe:
    def __init__(self, args):
        self.args, self.lock = args, threading.RLock()
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        self.cleaning = False
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, connect_timeout=5,
                        read_timeout=180, retries={"total_max_attempts": 1})
        self.clients = {name: self.session.client(name, config=config)
                        for name in ("sts", "iam", "lambda", "sqs")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.account or self.data["region"] != REGION:
                raise RuntimeError("Cleanup inventory has foreign account/region")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite existing native evidence")
            self.data = {"account": self.account, "region": REGION, "captured_at": now(),
                "started_epoch": time.time(), "prefix": "stackd-adel-" + uuid.uuid4().hex[:12],
                "source": "Native boto3 public endpoints; configured endpoint overrides disabled",
                "sdk": {"boto3": boto3.__version__}, "sources": SOURCES,
                "ethics_review": {"decision": "allow", "reviewed_at": "2026-09-30",
                    "scope": "Three 128MiB functions, one owned least-privilege role, three SQS queues; no shared policies; at most 22500s terminal window and 24000s total; actor verified before writes"},
                "bounds": {"functions": 3, "queues": 3, "roles": 1,
                    "memory_mb": 128, "maximum_reserved_concurrency": 5,
                    "maximum_async_events": 30, "maximum_queue_reads": 2000,
                    "terminal_seconds": args.terminal_seconds, "total_seconds": 24000},
                "prior_evidence": "testdata/aws/lambda/qualified_deletion_retry.json",
                "prior_evidence_limit": "Applied retry2/age240 controls; no deleted-alias marker or terminal through 664.141s; correlated redispatch is not handler entry or terminal proof",
                "owned": {"queues": {}, "functions": {}}, "calls": [], "messages": [],
                "events": {}, "controls": {}, "findings": {}, "cleanup": {"complete": False},
                "limitations": ["Absence during a bounded window is not proof of pending state, permanent loss, or terminal timing.",
                    "No CloudTrail data trail is created; runtime markers and destinations are direct execution evidence.",
                    "One sample per lifecycle cannot establish universal undocumented counts or timing.",
                    "New destination API readback is not an applied-settings barrier; post-mutation deliveries are separately observed."]}
        self.save()
        identity = self.call("verify-identity", "sts", "get_caller_identity")
        if identity["Account"] != self.account or identity["Arn"] != self.actor:
            raise RuntimeError("Native writes require exact authorized account and Delegated actor")
        self.data["identity"] = identity
        self.save()

    def save(self):
        with self.lock:
            text = json.dumps(recorded(self.data), indent=2)
            for secret in (self.credentials.secret_key, self.credentials.token):
                if secret:
                    text = text.replace(secret, "<redacted-credential>")
            self.args.output.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.args.output.with_suffix(self.args.output.suffix + ".tmp")
            with temporary.open("w") as stream:
                stream.write(text + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.args.output)

    def call(self, label, service, operation, request=None, *, expect="Success"):
        with self.lock:
            row = {"label": label, "service": service, "operation": operation,
                "input": recorded(request or {}), "started_at": now(),
                "elapsed_start_seconds": round(time.time() - self.data["started_epoch"], 3),
                "phase": "cleanup" if self.cleaning else "workflow", "code": "Pending"}
            self.data["calls"].append(row)
            self.save()
        try:
            output = getattr(self.clients[service], operation)(**(request or {}))
            metadata = output.pop("ResponseMetadata", {})
            if hasattr(output.get("Payload"), "read"):
                stream = output["Payload"]
                try:
                    raw = stream.read()
                    output["Payload"] = json.loads(raw) if raw else None
                finally:
                    stream.close()
            with self.lock:
                row.update(code="Success", output=recorded(output), metadata=document(metadata))
        except ClientError as error:
            output = {}
            with self.lock:
                row.update(code=error.response["Error"]["Code"], error=error.response["Error"],
                           metadata=document(error.response.get("ResponseMetadata", {})))
        except BaseException as error:
            with self.lock:
                row.update(code=type(error).__name__, error=str(error))
            raise
        finally:
            with self.lock:
                row.update(finished_at=now(), elapsed_end_seconds=round(time.time()-self.data["started_epoch"], 3))
                self.save()
        if not label.startswith("poll-"):
            print(label + ": " + row["code"], flush=True)
        expected = (expect,) if isinstance(expect, str) else expect
        if row["code"] not in expected:
            raise RuntimeError(label + ": " + json.dumps(row.get("error", row["code"])))
        return output

    def function_request(self, key, qualifier=None):
        value = {"FunctionName": self.data["owned"]["functions"][key]["name"]}
        if qualifier:
            value["Qualifier"] = qualifier
        return value

    def target(self, case):
        key = "aliases" if case.startswith("alias-") else case
        qualifier = case if key == "aliases" else None
        return self.function_request(key, qualifier)

    def ready(self, key):
        for attempt in range(90):
            out = self.call("ready-" + key, "lambda", "get_function_configuration", self.function_request(key))
            if out.get("State") == "Active" and out.get("LastUpdateStatus", "Successful") == "Successful":
                self.data["owned"]["functions"][key]["revision"] = out["RevisionId"]
                self.save()
                return
            if out.get("State") == "Failed" or out.get("LastUpdateStatus") == "Failed":
                raise RuntimeError("Owned function failed readiness")
            time.sleep(2)
        raise RuntimeError("Owned function readiness deadline exceeded")

    def package(self, deployment):
        source = HANDLER.replace("DEPLOYMENT_VALUE", repr(deployment))
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            entry = zipfile.ZipInfo("handler.py", (2026, 1, 1, 0, 0, 0))
            package.writestr(entry, source)
        raw = archive.getvalue()
        self.data.setdefault("artifacts", {})[deployment] = {"source": source,
            "zip_base64": base64.b64encode(raw).decode(),
            "sha256_base64": base64.b64encode(hashlib.sha256(raw).digest()).decode()}
        self.save()
        return raw

    def create_function(self, key, deployment):
        owned = self.data["owned"]
        function = owned["functions"][key]
        self.call("absent-before-create-" + key, "lambda", "get_function", self.function_request(key),
                  expect="ResourceNotFoundException")
        function["creation_planned"] = deployment
        self.save()
        output = self.call("create-" + key + "-" + deployment, "lambda", "create_function", {
            **self.function_request(key), "Role": owned["role"]["arn"], "Runtime": "python3.12",
            "Handler": "handler.handler", "Code": {"ZipFile": self.package(deployment)},
            "Timeout": 170, "MemorySize": 128, "Publish": True,
            "Environment": {"Variables": {"MARKER_QUEUE": owned["queues"]["marker"]["url"]}},
            "Tags": {"stackd-probe": self.data["prefix"]}})
        function.update(arn=output["FunctionArn"], revision=output["RevisionId"])
        function.setdefault("incarnations", []).append({"deployment": deployment,
            "revision": output["RevisionId"], "version": output["Version"], "created_at": now()})
        self.save()
        self.ready(key)
        return output["Version"]

    def configure(self, case, destination="old"):
        arn = self.data["owned"]["queues"][destination]["arn"]
        request = {**self.target(case), "MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 180,
                   "DestinationConfig": {"OnSuccess": {"Destination": arn}, "OnFailure": {"Destination": arn}}}
        self.call("configure-" + case + "-" + destination, "lambda", "put_function_event_invoke_config", request)
        self.call("readback-" + case, "lambda", "get_function_event_invoke_config", self.target(case))

    def setup_dependencies(self, queue_keys=("marker", "old", "new")):
        prefix, owned = self.data["prefix"], self.data["owned"]
        for key in queue_keys:
            queue = owned["queues"][key] = {"name": prefix + "-" + key}
            self.save()
            self.call("absent-queue-" + key, "sqs", "get_queue_url", {"QueueName": queue["name"]},
                      expect=("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
            queue["creation_planned"] = True
            self.save()
            queue["url"] = self.call("create-queue-" + key, "sqs", "create_queue", {
                "QueueName": queue["name"], "Attributes": {"MessageRetentionPeriod": "86400",
                    "SqsManagedSseEnabled": "false"}, "tags": {"stackd-probe": prefix}})["QueueUrl"]
            queue["arn"] = self.call("queue-arn-" + key, "sqs", "get_queue_attributes", {
                "QueueUrl": queue["url"], "AttributeNames": ["QueueArn", "CreatedTimestamp"]})["Attributes"]["QueueArn"]
            self.save()
        role = owned["role"] = {"name": prefix + "-role", "policy": "owned-send-only"}
        self.save()
        self.call("absent-role", "iam", "get_role", {"RoleName": role["name"]}, expect="NoSuchEntity")
        role["creation_planned"] = True
        self.save()
        created = self.call("create-role", "iam", "create_role", {"RoleName": role["name"],
            "Tags": [{"Key": "stackd-probe", "Value": prefix}],
            "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})})["Role"]
        role.update(arn=created["Arn"], id=created["RoleId"])
        self.save()
        self.call("put-exact-send-policy", "iam", "put_role_policy", {"RoleName": role["name"],
            "PolicyName": role["policy"], "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Action": "sqs:SendMessage",
                "Resource": [queue["arn"] for queue in owned["queues"].values()]}]})})
        time.sleep(15)

    def setup(self):
        self.setup_dependencies()
        prefix, owned = self.data["prefix"], self.data["owned"]
        for key in ("aliases", "function-delete", "function-recreate"):
            owned["functions"][key] = {"name": prefix + "-" + key}
            self.save()
            self.create_function(key, "one")
            self.call("concurrency-" + key, "lambda", "put_function_concurrency", {
                **self.function_request(key), "ReservedConcurrentExecutions": 3 if key == "aliases" else 1})
        output = self.call("publish-second", "lambda", "update_function_code", {
            **self.function_request("aliases"), "ZipFile": self.package("two"), "Publish": True})
        self.data["second_version"] = output["Version"]
        self.ready("aliases")
        for case in ("alias-delete", "alias-recreate", "alias-refresh"):
            alias = self.call("create-" + case, "lambda", "create_alias", {
                **self.function_request("aliases"), "Name": case, "FunctionVersion": "1",
                "Description": prefix})
            owned["functions"]["aliases"].setdefault("aliases", {})[case] = alias
            self.save()
        self.data["cases"] = ["alias-delete", "alias-recreate", "alias-refresh", "function-delete", "function-recreate"]
        for case in self.data["cases"]:
            self.configure(case)
        # Propagation pause is not evidence; completed controls below are required.
        time.sleep(120)

    def invoke(self, case, event_id, mode="success", sleep=0):
        if len(self.data["events"]) >= 30:
            raise RuntimeError("Async event count bound reached")
        event = {"case": event_id, "mode": mode, "sleep": sleep}
        self.data["events"][event_id] = {"target": case, "payload": event, "admitted_epoch": time.time()}
        self.save()
        out = self.call("admit-" + event_id, "lambda", "invoke", {
            **self.target(case), "InvocationType": "Event", "Payload": json.dumps(event).encode()})
        if out["StatusCode"] != 202:
            raise RuntimeError("Event was not accepted202")
        self.data["events"][event_id]["admitted_at"] = now()
        self.save()

    def poll(self):
        for key, queue in self.data["owned"]["queues"].items():
            self.data["queue_reads"] = self.data.get("queue_reads", 0) + 1
            if self.data["queue_reads"] > 2000:
                raise RuntimeError("Queue read bound reached")
            out = self.call("poll-" + key, "sqs", "receive_message", {"QueueUrl": queue["url"],
                "MaxNumberOfMessages": 10, "WaitTimeSeconds": 1, "VisibilityTimeout": 30,
                "MessageSystemAttributeNames": ["SentTimestamp"]})
            for message in out.get("Messages", []):
                decoded = json.loads(message["Body"])
                self.data["messages"].append({"queue": key, "message_id": message["MessageId"],
                    "observed_at": now(), "observed_epoch": time.time(),
                    "attributes": message.get("Attributes", {}), "body": decoded})
                self.save()
                self.call("consume-owned-message", "sqs", "delete_message", {
                    "QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]})

    def messages(self, event_id, marker=False):
        rows = []
        for item in self.data["messages"]:
            body = item["body"]
            if marker and item["queue"] == "marker" and body.get("case") == event_id:
                rows.append(item)
            elif not marker and item["queue"] != "marker" and body.get("requestPayload", {}).get("case") == event_id:
                rows.append(item)
        return rows

    def wait_until(self, condition, seconds, interval=3):
        deadline = time.monotonic() + seconds
        while True:
            self.poll()
            if condition():
                return True
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(interval, remaining))

    def controls(self):
        for kind, sleep, expected_condition, count in (
                ("retry", 0, "RetriesExhausted", 2), ("age", 130, "EventAgeExceeded", 1)):
            ids = [case + "-control-" + kind for case in self.data["cases"]]
            for case, event_id in zip(self.data["cases"], ids):
                self.invoke(case, event_id, "fail", sleep)
            def completed():
                # SQS queues are independent and standard delivery is unordered.
                # Receiving a destination does not drain all runtime markers.
                return all(self.messages(event_id) and
                    len([item for item in self.messages(event_id, True)
                         if item["body"]["phase"] == "entry"]) >= count for event_id in ids)
            if not self.wait_until(completed, 420):
                raise RuntimeError("Applied " + kind + " controls/markers did not complete within420s")
            for case, event_id in zip(self.data["cases"], ids):
                records = self.messages(event_id)
                entries = [item for item in self.messages(event_id, True) if item["body"]["phase"] == "entry"]
                context = records[0]["body"]["requestContext"]
                if (context["condition"] != expected_condition or context["approximateInvokeCount"] != count
                        or len(entries) != count or records[0]["queue"] != "old"):
                    raise RuntimeError("Applied control mismatch: " + event_id)
                self.data["controls"].setdefault(case, {})[kind] = {"event": event_id,
                    "condition": context["condition"], "count": count, "entries": len(entries),
                    "completed_at": records[0]["observed_at"]}
            self.save()

    def owned_function(self, key):
        current = self.call("verify-owned-" + key, "lambda", "get_function", self.function_request(key),
                            expect=("Success", "ResourceNotFoundException"))
        if not current:
            return False
        entry = self.data["owned"]["functions"][key]
        if current.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
            raise RuntimeError("Foreign function ownership tag; refusing deletion")
        if current["Configuration"]["FunctionArn"] != entry.get("arn", current["Configuration"]["FunctionArn"]):
            raise RuntimeError("Function ARN ownership mismatch")
        return True

    def delete_function(self, key):
        if self.owned_function(key):
            self.call("delete-owned-" + key, "lambda", "delete_function", self.function_request(key))
        self.call("absent-owned-" + key, "lambda", "get_function", self.function_request(key),
                  expect="ResourceNotFoundException")

    def mutate(self):
        for key in self.data["owned"]["functions"]:
            self.call("single-slot-" + key, "lambda", "put_function_concurrency", {
                **self.function_request(key), "ReservedConcurrentExecutions": 1})
        with ThreadPoolExecutor(max_workers=3) as executor:
            for key, cases in (("aliases", self.data["cases"][:3]),
                               ("function-delete", ["function-delete"]),
                               ("function-recreate", ["function-recreate"])):
                blocker_id = key + "-blocker"
                future = executor.submit(self.call, "blocker-" + key, "lambda", "invoke", {
                    **self.function_request(key), "InvocationType": "RequestResponse",
                    "Payload": json.dumps({"case": blocker_id, "mode": "success", "sleep": 45}).encode()})
                if not self.wait_until(lambda: bool(self.messages(blocker_id, True)), 20, 1):
                    raise RuntimeError("Blocker did not positively enter runtime")
                self.call("occupied429-" + key, "lambda", "invoke", {
                    **self.function_request(key), "InvocationType": "RequestResponse",
                    "Payload": json.dumps({"case": key + "-busy-check"}).encode()}, expect="TooManyRequestsException")
                for case in cases:
                    self.invoke(case, case + "-queued")
                if key == "aliases":
                    for case in ("alias-delete", "alias-recreate"):
                        request = {**self.function_request(key), "Name": case}
                        alias = self.call("identity-before-delete-" + case, "lambda", "get_alias", request)
                        if alias.get("Description") != self.data["prefix"]:
                            raise RuntimeError("Alias ownership mismatch")
                        self.call("delete-" + case, "lambda", "delete_alias", request)
                        self.call("absent-" + case, "lambda", "get_alias", request, expect="ResourceNotFoundException")
                    self.call("recreate-alias", "lambda", "create_alias", {
                        **self.function_request(key), "Name": "alias-recreate",
                        "Description": self.data["prefix"], "FunctionVersion": self.data["second_version"]})
                    self.configure("alias-recreate", "new")
                    alias = self.call("get-refresh-before-update", "lambda", "get_alias", {
                        **self.function_request(key), "Name": "alias-refresh"})
                    self.call("refresh-qualified-version", "lambda", "update_alias", {
                        **self.function_request(key), "Name": "alias-refresh",
                        "FunctionVersion": self.data["second_version"], "RevisionId": alias["RevisionId"]})
                    self.configure("alias-refresh", "new")
                else:
                    self.delete_function(key)
                    if key == "function-recreate":
                        self.create_function(key, "two")
                        self.call("recreated-single-slot", "lambda", "put_function_concurrency", {
                            **self.function_request(key), "ReservedConcurrentExecutions": 1})
                        self.configure(key, "new")
                output = future.result(timeout=170)
                if output.get("FunctionError"):
                    raise RuntimeError("Synchronous blocker failed")
                self.data.setdefault("blockers", {})[key] = output
                self.save()

    def summarize(self):
        for case in self.data.get("cases", []):
            event_id = case + "-queued"
            event = self.data["events"].get(event_id)
            if not event:
                continue
            markers, terminals = self.messages(event_id, True), self.messages(event_id)
            self.data["findings"][case] = {"event": event_id,
                "observed_through_seconds_after_admission": round(time.time()-event["admitted_epoch"], 3),
                "runtime_entries": [item for item in markers if item["body"]["phase"] == "entry"],
                "terminal_destinations": terminals,
                "outcome": "terminal_observed" if terminals else "bounded_inconclusive_no_terminal_observed"}
        self.save()

    def run(self):
        self.setup()
        self.controls()
        self.mutate()
        print("EARLY_RECREATION_OBSERVATION", flush=True)
        self.wait_until(lambda: all(self.messages(case + "-queued") for case in
            ("alias-recreate", "alias-refresh", "function-recreate")), 360, 5)
        self.summarize()
        self.data["early_findings"] = json.loads(json.dumps(self.data["findings"]))
        self.data["early_findings_at"] = now()
        self.save()
        print("EARLY_FINDINGS " + json.dumps(self.data["early_findings"]), flush=True)
        for case in ("alias-recreate", "alias-refresh", "function-recreate"):
            self.invoke(case, case + "-post-mutation-control")
        self.wait_until(lambda: all(self.messages(case + "-post-mutation-control") for case in
            ("alias-recreate", "alias-refresh", "function-recreate")), 360, 5)
        admitted = max(event["admitted_epoch"] for key, event in self.data["events"].items() if key.endswith("-queued"))
        deadline = admitted + self.args.terminal_seconds
        self.data["terminal_observation_deadline_epoch"] = deadline
        self.save()
        print("TERMINAL_WAIT " + json.dumps({"deadline_epoch": deadline, "output": str(self.args.output)}), flush=True)
        while time.time() < deadline:
            if all(self.messages(case + "-queued") for case in self.data["cases"]):
                break
            self.poll()
            self.summarize()
            time.sleep(min(120, max(0, deadline-time.time())))
        self.poll()
        self.summarize()
        self.data.update(workflow_complete=True, finished_at=now())
        self.save()

    def cleanup(self):
        self.cleaning = True
        errors, owned = [], self.data["owned"]
        self.data["cleanup"].setdefault("attempts", []).append({"started_at": now()})
        self.save()
        def attempt(label, operation):
            try:
                operation()
            except Exception as error:
                errors.append({"resource": label, "error": str(error)})
                self.save()
        for key in owned["functions"]:
            attempt(key, lambda key=key: self.delete_function(key))
        def remove_role():
            role = owned["role"]
            current = self.call("cleanup-role-identity", "iam", "get_role", {"RoleName": role["name"]},
                                expect=("Success", "NoSuchEntity"))
            if current:
                value = current["Role"]
                tags = {item["Key"]: item["Value"] for item in value.get("Tags", [])}
                if tags.get("stackd-probe") != self.data["prefix"] or value["RoleId"] != role.get("id", value["RoleId"]):
                    raise RuntimeError("Refusing cleanup of foreign role identity")
                attached = self.call("cleanup-role-attached", "iam", "list_attached_role_policies", {"RoleName": role["name"]})
                policies = self.call("cleanup-role-inline", "iam", "list_role_policies", {"RoleName": role["name"]})
                if attached["AttachedPolicies"] or set(policies["PolicyNames"]) - {role["policy"]}:
                    raise RuntimeError("Unexpected policies on owned role; refusing shared-policy mutation")
                if role["policy"] in policies["PolicyNames"]:
                    self.call("cleanup-exact-inline-policy", "iam", "delete_role_policy", {
                        "RoleName": role["name"], "PolicyName": role["policy"]})
                self.call("cleanup-delete-role", "iam", "delete_role", {"RoleName": role["name"]})
            self.call("cleanup-role-absent", "iam", "get_role", {"RoleName": role["name"]}, expect="NoSuchEntity")
        if "role" in owned:
            attempt("role", remove_role)
        for key, queue in owned["queues"].items():
            def remove_queue(key=key, queue=queue):
                out = self.call("cleanup-locate-" + key, "sqs", "get_queue_url", {"QueueName": queue["name"]},
                    expect=("Success", "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
                if out:
                    url = out["QueueUrl"]
                    tags = self.call("cleanup-tags-" + key, "sqs", "list_queue_tags", {"QueueUrl": url})
                    if tags.get("Tags", {}).get("stackd-probe") != self.data["prefix"] or url != queue.get("url", url):
                        raise RuntimeError("Refusing cleanup of unowned queue")
                    self.call("cleanup-delete-" + key, "sqs", "delete_queue", {"QueueUrl": url})
                self.call("cleanup-absent-" + key, "sqs", "get_queue_url", {"QueueName": queue["name"]},
                    expect=("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
            attempt("queue-" + key, remove_queue)
        self.data["cleanup"].update(complete=not errors, errors=errors, finished_at=now())
        self.save()
        if errors:
            raise RuntimeError("Exact-owned cleanup incomplete; use --cleanup-only")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--terminal-seconds", type=int, default=22500)
    args = parser.parse_args()
    if not 21600 <= args.terminal_seconds <= 22500:
        parser.error("Terminal window must span default six-hour age, bounded at22500s")
    probe = Probe(args)
    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.alarm(24000)
    try:
        if not args.cleanup_only:
            probe.run()
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        signal.alarm(0)
        probe.cleanup()


if __name__ == "__main__":
    main()
