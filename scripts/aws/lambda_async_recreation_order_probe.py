#!/usr/bin/env python3
"""Reviewed exact-owned recreation: new-route receipt precedes old-handler release."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import signal
import time
import zipfile

from lambda_async_deletion_probe import Probe, HANDLER, REGION, now
from lambda_async_deleted_dlq_probe import DeletedDLQProbe


class RecreationOrderProbe(DeletedDLQProbe):
    messages = Probe.messages

    def __init__(self, args):
        Probe.__init__(self, args)
        if args.cleanup_only:
            if self.data.get("probe") != "recreation-ordered-route":
                raise RuntimeError("Foreign cleanup inventory")
        else:
            self.data.update(probe="recreation-ordered-route", ethics_review={
                "decision": "allow", "reviewed_at": "2026-10-01", "actor": self.actor, "region": REGION,
                "scope": "One exact-tagged function recreated once;128MiB Python3.12 timeout170 reserve<=2;four tagged queues, one exact-owned send/receive-gate role;<=8 async,<=2 sync blockers,<=700 queue reads,<=750s including cleanup. New-route control before old accepted handler release. No shared mutation or permission bypass."},
                bounds={"functions": 1, "queues": 4, "roles": 1, "maximum_async_events": 8,
                    "maximum_queue_reads": 700, "maximum_observer_queue_reads": 310,
                    "maximum_gate_reads_per_attempt": 130, "total_seconds": 750})
            self.save()

    def package(self, deployment):
        source = HANDLER.replace("DEPLOYMENT_VALUE", repr(deployment)).replace(
            '    time.sleep(min(float(event.get("sleep",0)),130))',
            '''    if event.get("gate"):
        deadline=time.monotonic()+130
        for _ in range(130):
            if time.monotonic()>=deadline: raise RuntimeError("owned gate deadline")
            rows=sqs.receive_message(QueueUrl=os.environ["GATE_QUEUE"],WaitTimeSeconds=1,MaxNumberOfMessages=1).get("Messages",[])
            if rows:
                release=json.loads(rows[0]["Body"])
                if release["case"]!=event["case"]: raise RuntimeError("foreign release")
                sqs.delete_message(QueueUrl=os.environ["GATE_QUEUE"],ReceiptHandle=rows[0]["ReceiptHandle"])
                break
        else: raise RuntimeError("owned gate receive bound")
    time.sleep(min(float(event.get("sleep",0)),130))''')
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            package.writestr("handler.py", source)
        raw = archive.getvalue()
        self.data.setdefault("artifacts", {})[deployment] = {"source": source,
            "zip_base64": base64.b64encode(raw).decode(),
            "sha256_base64": base64.b64encode(hashlib.sha256(raw).digest()).decode()}
        self.save()
        return raw

    def create_function(self, key, deployment):
        owned = self.data["owned"]
        function = owned["functions"][key]
        self.call("absent-before-create-" + deployment, "lambda", "get_function",
                  self.function_request(key), expect="ResourceNotFoundException")
        function["creation_planned"] = deployment
        self.save()
        output = self.call("create-" + deployment, "lambda", "create_function", {
            **self.function_request(key), "Role": owned["role"]["arn"], "Runtime": "python3.12",
            "Handler": "handler.handler", "Code": {"ZipFile": self.package(deployment)},
            "Timeout": 170, "MemorySize": 128, "Publish": True,
            "Environment": {"Variables": {"MARKER_QUEUE": owned["queues"]["marker"]["url"],
                "GATE_QUEUE": owned["queues"]["gate"]["url"]}}, "Tags": {"stackd-probe": self.data["prefix"]}})
        function.update(arn=output["FunctionArn"], revision=output["RevisionId"])
        function.setdefault("incarnations", []).append({"deployment": deployment, "version": output["Version"], "revision": output["RevisionId"]})
        self.save()
        self.ready(key)

    def admit(self, label, gate=False):
        if len(self.data["events"]) >= 8:
            raise RuntimeError("Async event bound reached")
        event = {"case": label, "mode": "success", "gate": gate}
        self.data["events"][label] = {"payload": event, "admitted_epoch": time.time()}
        self.save()
        output = self.call("admit-" + label, "lambda", "invoke", {
            **self.function_request("function-recreate"), "InvocationType": "Event", "Payload": json.dumps(event).encode()})
        if output["StatusCode"] != 202:
            raise RuntimeError("Missing async acceptance")

    def poll(self):
        # The gate is consumed only by the actual handler, never by observation.
        for key in ("marker", "old", "new"):
            queue = self.data["owned"]["queues"][key]
            self.data["queue_reads"] = self.data.get("queue_reads", 0) + 1
            if self.data["queue_reads"] > self.data["bounds"]["maximum_observer_queue_reads"]:
                raise RuntimeError("Observer queue read bound reached")
            output = self.call("poll-" + key, "sqs", "receive_message", {
                "QueueUrl": queue["url"], "MaxNumberOfMessages": 10, "WaitTimeSeconds": 1,
                "MessageSystemAttributeNames": ["All"], "MessageAttributeNames": ["All"]})
            for message in output.get("Messages", []):
                self.data["messages"].append({"queue": key, "message_id": message["MessageId"],
                    "observed_at": now(), "observed_epoch": time.time(), "body": json.loads(message["Body"]),
                    "attributes": message.get("Attributes", {})})
                self.save()
                self.call("consume-owned-message", "sqs", "delete_message", {
                    "QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]})

    def run(self):
        self.setup_dependencies()
        owned = self.data["owned"]
        queue = owned["queues"]["gate"] = {"name": self.data["prefix"] + "-gate"}
        self.save()
        self.call("absent-gate", "sqs", "get_queue_url", {"QueueName": queue["name"]},
                  expect=("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
        queue["creation_planned"] = True
        self.save()
        queue["url"] = self.call("create-gate", "sqs", "create_queue", {
            "QueueName": queue["name"], "Attributes": {"MessageRetentionPeriod": "86400", "SqsManagedSseEnabled": "false"},
            "tags": {"stackd-probe": self.data["prefix"]}})["QueueUrl"]
        queue["arn"] = self.call("gate-arn", "sqs", "get_queue_attributes", {
            "QueueUrl": queue["url"], "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        self.save()
        self.call("owned-gate-policy", "iam", "put_role_policy", {"RoleName": owned["role"]["name"],
            "PolicyName": owned["role"]["policy"], "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": [owned["queues"][k]["arn"] for k in ("marker", "old", "new")]},
                {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"], "Resource": queue["arn"]}]})})
        owned["functions"]["function-recreate"] = {"name": self.data["prefix"] + "-function-recreate"}
        self.save()
        self.create_function("function-recreate", "one")
        self.call("original-slot", "lambda", "put_function_concurrency", {
            **self.function_request("function-recreate"), "ReservedConcurrentExecutions": 1})
        self.configure("function-recreate")
        time.sleep(100)
        self.admit("old-route-control")
        if not self.wait_until(lambda: bool(self.messages("old-route-control")), 60, 1):
            raise RuntimeError("Old-route applied control absent")
        if self.messages("old-route-control")[0]["queue"] != "old":
            raise RuntimeError("Old route control mismatch")
        with ThreadPoolExecutor(max_workers=1) as executor:
            blocker = executor.submit(self.call, "original-blocker", "lambda", "invoke", {
                **self.function_request("function-recreate"), "InvocationType": "RequestResponse",
                "Payload": json.dumps({"case": "blocker", "mode": "success", "sleep": 60}).encode()})
            if not self.wait_until(lambda: bool(self.messages("blocker", True)), 25, 1):
                raise RuntimeError("Original blocker did not enter")
            self.call("occupied429", "lambda", "invoke", {**self.function_request("function-recreate"),
                "InvocationType": "RequestResponse", "Payload": b'{"case":"busy"}'}, expect="TooManyRequestsException")
            self.admit("old-accepted", gate=True)
            self.delete_function("function-recreate")
            self.create_function("function-recreate", "two")
            self.call("replacement-slots", "lambda", "put_function_concurrency", {
                **self.function_request("function-recreate"), "ReservedConcurrentExecutions": 2})
            self.configure("function-recreate", "new")
            time.sleep(100)
            self.admit("new-route-control")
            if not self.wait_until(lambda: bool(self.messages("new-route-control")) and
                    bool(self.messages("old-accepted", True)), 30, 1):
                raise RuntimeError("Replacement entry/new-route control ordering unproven")
            control = self.messages("new-route-control")[0]
            if control["queue"] != "new" or control["body"]["requestContext"]["condition"] != "Success":
                raise RuntimeError("Fresh control did not establish applied NEW route")
            if self.messages("old-accepted"):
                raise RuntimeError("Old event terminated before applied NEW-route barrier")
            self.data["new_route_barrier"] = control
            self.data["release_at"] = now()
            self.save()
            self.call("release-old-handler", "sqs", "send_message", {"QueueUrl": queue["url"],
                "MessageBody": json.dumps({"case": "old-accepted"})})
            if not self.wait_until(lambda: bool(self.messages("old-accepted")), 60, 1):
                raise RuntimeError("Old event terminal absent after actual release")
            self.data["findings"] = {"old_accepted": self.messages("old-accepted"),
                "old_runtime": self.messages("old-accepted", True), "new_control": self.messages("new-route-control"),
                "limit": "Establishes new-route delivery before old-handler completion, not necessarily before its replacement dispatch; propagation versus dispatch-snapshot remains distinguished from acceptance lifetime ownership."}
            result = blocker.result(timeout=170)
            if result.get("FunctionError"):
                raise RuntimeError("Original blocker failed")
        self.data.update(workflow_complete=True, finished_at=now())
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    args.terminal_seconds = 600
    probe = RecreationOrderProbe(args)
    def interrupted(signum, frame):
        raise RuntimeError("Reviewed workflow interrupted:" + str(signum))
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.alarm(600)
    try:
        if not args.cleanup_only:
            probe.run()
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        signal.alarm(150 if args.cleanup_only else max(1, int(750-(time.time()-probe.data["started_epoch"]))))
        try:
            probe.cleanup()
        finally:
            signal.alarm(0)


if __name__ == "__main__":
    main()
