#!/usr/bin/env python3
"""One reviewed exact-owned DLQ metadata/effective-routing calibration.

Requires a new ethics review before another native run. Reuses Probe's durable
recorder, exact actor verification, dependency setup and ownership-safe cleanup.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
import signal
import time

from botocore.config import Config

from lambda_async_deletion_probe import REGION, Probe, now


class TerminalObservationDeadline(BaseException):
    # Botocore wraps Exception during transport reads; this must survive intact.
    pass


class WorkflowDeadline(BaseException):
    pass


class TotalDeadline(BaseException):
    pass


class Deadlines:
    def __init__(self):
        self.started = time.monotonic()
        self.total = self.started + 1200
        self.workflow = self.started + 1050
        self.phase = None
        signal.signal(signal.SIGALRM, self.expired)
        self.arm()

    def arm(self):
        deadlines = [self.total]
        if self.workflow is not None:
            deadlines.append(self.workflow)
        if self.phase is not None:
            deadlines.append(self.phase)
        signal.setitimer(signal.ITIMER_REAL, max(0.001, min(deadlines)-time.monotonic()))

    def expired(self, signum, frame):
        current = time.monotonic()
        if current >= self.total:
            raise TotalDeadline("Reviewed 1200s total deadline reached")
        if self.workflow is not None and current >= self.workflow:
            raise WorkflowDeadline("Workflow stopped with 150s reserved for cleanup")
        raise TerminalObservationDeadline("Reviewed 180s observation phase deadline reached")

    @contextmanager
    def observation(self):
        self.phase = time.monotonic() + 180
        self.arm()
        try:
            yield
        finally:
            self.phase = None
            # The absolute total deadline never moves or becomes disabled.
            self.arm()

    def cleaning(self):
        self.phase = self.workflow = None
        self.arm()


def redact_download_queries(value):
    if isinstance(value, dict):
        for key, item in value.items():
            value[key] = redact_download_queries(item)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            value[index] = redact_download_queries(item)
    elif isinstance(value, str) and value.startswith(("https://", "http://")):
        path, separator, query = value.partition("?")
        if separator and any(key in query.lower() for key in (
                "x-amz-security-token=", "x-amz-credential=", "x-amz-signature=")):
            return path + "?<redacted-presigned-query>"
    return value


class DLQOwnershipProbe(Probe):
    def save(self):
        with self.lock:
            redact_download_queries(self.data)
            self.data["redactions"] = {
                "presigned_download_urls": "Entire bearer query removed from every nested GetFunction Code.Location; scheme, host and path retained.",
                "payloads": "Original invocation bytes, SQS bodies and message attributes retained; this is not an unredacted HTTP transport capture."}
            super().save()

    def __init__(self, args, deadlines):
        self.deadlines = deadlines
        super().__init__(args)
        if args.cleanup_only:
            if self.data.get("probe") != "function-dlq-ownership":
                raise RuntimeError("Cleanup requires this probe's inventory")
        else:
            self.data.update(probe="function-dlq-ownership",
                prefix=self.data["prefix"].replace("stackd-adel-", "stackd-dlqown-"),
                ethics_review={"decision": "allow", "reviewed_at": "2026-10-01",
                    "actor": self.actor, "region": REGION,
                    "scope": "One tagged Python3.12 128MiB function timeout170, concurrency<=2; one version, one alias; five standard queues; one role granting ONLY sqs:SendMessage to those exact queues. <=15 async events, <=2000 queue reads, <=1200s total including cleanup, each observation<=180s. No Logs, CloudTrail, public URLs, provisioned concurrency, shared mutation or denial bypass. No second run without new review."},
                bounds={"functions": 1, "published_versions": 1, "aliases": 1,
                    "queues": 5, "roles": 1, "memory_mb": 128, "timeout_seconds": 170,
                    "maximum_reserved_concurrency": 2, "maximum_async_events": 15,
                    "maximum_queue_reads": 2000, "observation_phase_seconds": 180,
                    "total_seconds": 1200, "maximum_blocker_seconds": 90},
                config_histories={}, observation_phases=[], deviations=[], queue_reads=0,
                limitations=["API readback is metadata, not proof of applied asynchronous controls.",
                    "Only positively observed runtime markers and actual queue receipts establish delivery.",
                    "A bounded missing receipt is inconclusive, never evidence of permanent loss.",
                    "One queued event sample cannot establish universal configuration-update timing."])
            self.data["sources"].append("https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html")
            self.data.pop("prior_evidence", None)
            self.data.pop("prior_evidence_limit", None)
            self.save()
        for service in ("sts", "iam", "lambda", "sqs"):
            self.clients[service] = self.session.client(service, config=Config(
                ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=20,
                retries={"total_max_attempts": 1}))
        self.clients["lambda_blocker"] = self.session.client("lambda", config=Config(
            ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=110,
            retries={"total_max_attempts": 1}))

    def target(self, ref):
        return self.function_request("function", None if ref == "latest" else
            self.data["owned"]["functions"]["function"]["published_version"] if ref == "version1" else "owned")

    def setup(self):
        self.setup_dependencies(("marker", "onfailure", "dlq-a", "dlq-b", "dlq-c"))
        owned = self.data["owned"]
        function = owned["functions"]["function"] = {"name": self.data["prefix"] + "-function"}
        self.save()
        self.call("absent-before-create", "lambda", "get_function", self.target("latest"),
                  expect="ResourceNotFoundException")
        function["creation_planned"] = "immutable-version-one"
        self.save()
        created = self.call("create-function-with-a", "lambda", "create_function", {
            **self.target("latest"), "Role": owned["role"]["arn"], "Runtime": "python3.12",
            "Handler": "handler.handler", "Code": {"ZipFile": self.package("immutable-version-one")},
            "Timeout": 170, "MemorySize": 128, "Publish": True,
            "DeadLetterConfig": {"TargetArn": owned["queues"]["dlq-a"]["arn"]},
            "Environment": {"Variables": {"MARKER_QUEUE": owned["queues"]["marker"]["url"]}},
            "Tags": {"stackd-probe": self.data["prefix"]}})
        function.update(arn=created["FunctionArn"], revision=created["RevisionId"],
                        published_version=created["Version"])
        self.save()
        self.ready("function")
        self.call("two-slots", "lambda", "put_function_concurrency", {
            **self.target("latest"), "ReservedConcurrentExecutions": 2})
        alias = self.call("create-only-alias", "lambda", "create_alias", {
            **self.target("latest"), "Name": "owned", "FunctionVersion": created["Version"],
            "Description": self.data["prefix"]})
        function["aliases"] = {"owned": alias}
        self.save()
        for ref in ("latest", "version1", "alias"):
            self.call("configure-retry0-" + ref, "lambda", "put_function_event_invoke_config", {
                **self.target(ref), "MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 300,
                "DestinationConfig": {"OnFailure": {"Destination": owned["queues"]["onfailure"]["arn"]}}})
            self.call("retry0-readback-" + ref, "lambda", "get_function_event_invoke_config", self.target(ref))
        self.readbacks("initial-a")
        # A pause is not an applied-settings claim: all three positive controls follow.
        time.sleep(90)

    def readbacks(self, label):
        history = self.data["config_histories"][label] = {"started_at": now(), "refs": {}}
        for ref in ("latest", "version1", "alias"):
            history["refs"][ref] = {
                "GetFunctionConfiguration": self.call(label + "-configuration-" + ref,
                    "lambda", "get_function_configuration", self.target(ref)),
                "GetFunction": self.call(label + "-function-" + ref,
                    "lambda", "get_function", self.target(ref))}
        history["ListVersionsByFunction"] = self.call(label + "-list-versions", "lambda",
            "list_versions_by_function", self.target("latest"))
        history["finished_at"] = now()
        self.save()

    def update_root(self, queue):
        self.call("root-only-update-" + queue, "lambda", "update_function_configuration", {
            **self.target("latest"), "DeadLetterConfig": {"TargetArn": self.data["owned"]["queues"][queue]["arn"]}})
        self.ready("function")
        self.readbacks("root-" + queue)

    def invoke(self, ref, event_id):
        if len(self.data["events"]) >= 15:
            raise RuntimeError("Reviewed async event bound reached")
        event = {"case": event_id, "mode": "fail", "sleep": 0, "probe": self.data["prefix"],
                 "original": {"unicode": "payload-λ", "integer": 17}}
        raw = json.dumps(event, ensure_ascii=False, indent=1) + "\n"
        self.data["events"][event_id] = {"target": ref, "payload": event, "payload_raw": raw,
            "admitted_epoch": time.time()}
        self.save()
        label = "admit-" + event_id
        output = self.call(label, "lambda", "invoke", {
            **self.target(ref), "InvocationType": "Event", "Payload": raw.encode()})
        call = next(row for row in reversed(self.data["calls"]) if row["label"] == label)
        self.data["events"][event_id].update(status=output["StatusCode"],
            accepted_request_id=call["metadata"]["RequestId"], admitted_at=now())
        self.save()
        if output["StatusCode"] != 202:
            raise RuntimeError("Async event not accepted202")

    def poll(self):
        for key, queue in self.data["owned"]["queues"].items():
            if self.data["queue_reads"] >= 2000:
                raise RuntimeError("Reviewed queue read bound reached")
            self.data["queue_reads"] += 1
            output = self.call("poll-" + key, "sqs", "receive_message", {
                "QueueUrl": queue["url"], "MaxNumberOfMessages": 10, "WaitTimeSeconds": 1,
                "VisibilityTimeout": 30, "MessageSystemAttributeNames": ["All"],
                "MessageAttributeNames": ["All"]})
            self.data["last_queue_read_finished_epoch"] = time.time()
            for message in output.get("Messages", []):
                self.data["messages"].append({"queue": key, "message_id": message["MessageId"],
                    "observed_at": now(), "observed_epoch": time.time(), "body_raw": message["Body"],
                    "body": json.loads(message["Body"]), "raw_message": message,
                    "attributes": message.get("Attributes", {}),
                    "message_attributes": message.get("MessageAttributes", {})})
                self.save()
                self.call("consume-owned-message", "sqs", "delete_message", {
                    "QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]})

    def rows(self, event_id, queue):
        return [row for row in self.data["messages"] if row["queue"] == queue and
            (row["body"].get("requestPayload", {}) if queue == "onfailure" else
             row["body"]).get("case") == event_id]

    def entries(self, event_id):
        return [row for row in self.rows(event_id, "marker") if row["body"]["phase"] == "entry"]

    def complete(self, event_id):
        return bool(self.entries(event_id) and self.rows(event_id, "onfailure") and
                    any(self.rows(event_id, queue) for queue in ("dlq-a", "dlq-b", "dlq-c")))

    def observe(self, label, condition):
        phase = {"label": label, "started_at": now(), "started_epoch": time.time(), "cutoff_seconds": 180}
        self.data["observation_phases"].append(phase)
        self.save()
        try:
            with self.deadlines.observation():
                while not condition():
                    self.poll()
                    if not condition():
                        time.sleep(2)
        except TerminalObservationDeadline:
            phase["hard_cutoff_reached"] = True
        finally:
            phase.update(finished_at=now(), duration_seconds=round(time.time()-phase["started_epoch"], 3),
                         condition_observed=bool(condition()))
            self.save()
        # No final poll after a phase deadline.
        return phase["condition_observed"]

    def record_delivery(self, event_id, expected_queue=None, require_dlq=True):
        if not (self.complete(event_id) if require_dlq else self.entries(event_id) and self.rows(event_id, "onfailure")):
            raise RuntimeError("Incomplete positive delivery evidence: " + event_id)
        event = self.data["events"][event_id]
        entries = self.entries(event_id)
        destinations = self.rows(event_id, "onfailure")
        routes = {queue: self.rows(event_id, queue) for queue in ("dlq-a", "dlq-b", "dlq-c")
                  if self.rows(event_id, queue)}
        versions = sorted({row["body"]["version"] for row in entries})
        expected_version = "$LATEST" if event["target"] == "latest" else self.data["owned"]["functions"]["function"]["published_version"]
        if versions != [expected_version]:
            raise RuntimeError("Unexpected actual runtime version: " + event_id)
        if any(row["body"]["requestContext"]["condition"] != "RetriesExhausted" or
               row["body"]["requestContext"]["approximateInvokeCount"] != 1 for row in destinations):
            raise RuntimeError("Retry0 was not positively applied: " + event_id)
        for rows in routes.values():
            for row in rows:
                if row["body"] != event["payload"] or not {"RequestID", "ErrorCode", "ErrorMessage"} <= row["message_attributes"].keys():
                    raise RuntimeError("DLQ payload/attribute mismatch: " + event_id)
        finding = {"event": event_id, "target": event["target"], "accepted_request_id": event["accepted_request_id"],
            "runtime_versions": versions, "runtime_request_ids": sorted({row["body"]["request_id"] for row in entries}),
            "actual_dlq_queues": sorted(routes), "onfailure_observed": True,
            "onfailure_request_contexts": [row["body"]["requestContext"] for row in destinations],
            "original_bytes_preserved": all(row["body_raw"] == event["payload_raw"] for rows in routes.values() for row in rows) if routes else None,
            "dlq_outcome": "actual_receipt_observed" if routes else "bounded_absence_inconclusive",
            "receipt_ids": {queue: [row["message_id"] for row in rows] for queue, rows in routes.items()},
            "completed_at": now(), "seconds_after_admission": round(time.time()-event["admitted_epoch"], 3)}
        self.data["findings"][event_id] = finding
        self.save()
        print("NATIVE_POSITIVE " + json.dumps(finding), flush=True)
        if expected_queue is not None and sorted(routes) != [expected_queue]:
            return False
        return True

    def latest_control(self, queue):
        for attempt in range(1, 4):
            event_id = "latest-" + queue + "-applied-" + str(attempt)
            self.invoke("latest", event_id)
            if not self.observe(event_id, lambda: self.complete(event_id)):
                raise RuntimeError("Latest applied control inconclusive: " + queue)
            if self.record_delivery(event_id, queue):
                self.data["controls"][queue] = event_id
                self.save()
                return
            time.sleep(30)
        raise RuntimeError("No positively applied latest control for " + queue)

    def queued_sample(self):
        self.call("one-queued-slot", "lambda", "put_function_concurrency", {
            **self.target("latest"), "ReservedConcurrentExecutions": 1})
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self.call, "version1-synchronous-blocker", "lambda_blocker", "invoke", {
            **self.target("version1"), "InvocationType": "RequestResponse",
            "Payload": json.dumps({"case": "queued-blocker", "mode": "success", "sleep": 90}).encode()})
        try:
            if not self.observe("blocker-entry", lambda: bool(self.entries("queued-blocker"))):
                raise RuntimeError("Blocker entry inconclusive")
            self.call("occupied-slot429", "lambda", "invoke", {**self.target("version1"),
                "InvocationType": "RequestResponse", "Payload": b'{"case":"occupied-check"}'},
                expect="TooManyRequestsException")
            self.invoke("alias", "alias-queued-under-b-update-c")
            self.update_root("dlq-c")
            self.data["queued_sample"] = {"root_c_update_finished_at": now(),
                "blocker_still_running_after_update": not future.done(),
                "entry": self.entries("queued-blocker"), "single_sample_only": True}
            self.save()
            if future.done():
                raise RuntimeError("Blocker finished before root C mutation completed")
            completed = self.observe("queued-terminal", lambda: self.complete("alias-queued-under-b-update-c") and future.done())
            result = future.result(timeout=1)
            self.data["queued_sample"]["blocker_result"] = result
            self.save()
            if result.get("FunctionError"):
                raise RuntimeError("Synchronous blocker failed")
            if completed:
                self.record_delivery("alias-queued-under-b-update-c")
            else:
                self.data["deviations"].append("Queued event terminal inconclusive at hard cutoff; no timing inference")
            self.latest_control("dlq-c")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def removal_sample(self):
        self.call("root-only-remove-empty-object", "lambda", "update_function_configuration", {
            **self.target("latest"), "DeadLetterConfig": {}})
        self.ready("function")
        self.readbacks("root-removal-empty-object")
        config = self.data["config_histories"]["root-removal-empty-object"]["refs"]["latest"]["GetFunctionConfiguration"]
        print("NATIVE_REMOVAL_READBACK " + json.dumps({
            "input": {}, "latest": config.get("DeadLetterConfig"),
            "readbacks": self.summary()["readbacks"]["root-removal-empty-object"]}), flush=True)
        if config.get("DeadLetterConfig", {}).get("TargetArn"):
            self.call("root-only-remove-explicit-empty-target", "lambda", "update_function_configuration", {
                **self.target("latest"), "DeadLetterConfig": {"TargetArn": ""}})
            self.ready("function")
            self.readbacks("root-removal-empty-target")
            print("NATIVE_REMOVAL_READBACK " + json.dumps({
                "input": {"TargetArn": ""},
                "readbacks": self.summary()["readbacks"]["root-removal-empty-target"]}), flush=True)
        events = ["latest-after-root-removal", "alias-after-root-removal"]
        for ref, event_id in zip(("latest", "alias"), events):
            self.invoke(ref, event_id)
        if not self.observe("removal-onfailure-completion", lambda: all(
                self.entries(event_id) and self.rows(event_id, "onfailure") for event_id in events)):
            raise RuntimeError("Removal OnFailure completion inconclusive")
        for event_id in events:
            self.record_delivery(event_id, require_dlq=False)

    def run(self):
        self.setup()
        initial = [ref + "-initial-a" for ref in ("latest", "version1", "alias")]
        for ref, event_id in zip(("latest", "version1", "alias"), initial):
            self.invoke(ref, event_id)
        if not self.observe("initial-positive-controls", lambda: all(self.complete(event_id) for event_id in initial)):
            raise RuntimeError("Initial three-reference controls inconclusive")
        for event_id in initial:
            if not self.record_delivery(event_id, "dlq-a"):
                raise RuntimeError("Initial DLQ A control mismatch")
        self.update_root("dlq-b")
        self.latest_control("dlq-b")
        for ref in ("version1", "alias"):
            self.invoke(ref, ref + "-after-root-b")
        if not self.observe("qualified-after-root-b", lambda: all(self.complete(ref + "-after-root-b") for ref in ("version1", "alias"))):
            raise RuntimeError("Qualified post-update delivery inconclusive")
        for ref in ("version1", "alias"):
            self.record_delivery(ref + "-after-root-b")
        if self.deadlines.workflow-time.monotonic() > 570 and len(self.data["events"]) <= 9:
            self.queued_sample()
        else:
            self.data["deviations"].append("Optional queued sample skipped to preserve reviewed total/cleanup bounds")
        if self.deadlines.workflow-time.monotonic() > 210 and len(self.data["events"]) <= 13:
            self.removal_sample()
        else:
            self.data["deviations"].append("Root removal sample skipped to preserve reviewed total/cleanup bounds")
        self.data.update(workflow_complete=True, finished_at=now())
        self.save()

    def cleanup(self):
        identity = self.call("verify-cleanup-identity", "sts", "get_caller_identity")
        if identity["Account"] != self.account or identity["Arn"] != self.actor:
            raise RuntimeError("Cleanup requires exact authorized actor")
        self.data["cleanup"]["identity"] = identity
        self.save()
        super().cleanup()
        self.data["cleanup"]["complete"] = False
        self.save()
        for key in self.data["owned"]["functions"]:
            self.call("independent-absent-function", "lambda", "get_function", self.function_request(key),
                expect="ResourceNotFoundException")
        if "role" in self.data["owned"]:
            self.call("independent-absent-role", "iam", "get_role", {
                "RoleName": self.data["owned"]["role"]["name"]}, expect="NoSuchEntity")
        for key, queue in self.data["owned"]["queues"].items():
            self.call("independent-absent-" + key, "sqs", "get_queue_url", {"QueueName": queue["name"]},
                expect=("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
        self.data["cleanup"].update(complete=True, independent_absence_verified=True,
            total_duration_seconds=round(time.monotonic()-self.deadlines.started, 3))
        self.data["counters"] = {"async_events": len(self.data["events"]), "queue_reads": self.data["queue_reads"],
            "api_calls": len(self.data["calls"]), "runtime_entry_messages": sum(
                row["queue"] == "marker" and row["body"].get("phase") == "entry" for row in self.data["messages"])}
        self.save()

    def summary(self):
        readbacks = {}
        for label, history in self.data["config_histories"].items():
            readbacks[label] = {ref: {"GetFunctionConfiguration": values["GetFunctionConfiguration"].get("DeadLetterConfig"),
                "GetFunction": values["GetFunction"]["Configuration"].get("DeadLetterConfig")}
                for ref, values in history["refs"].items()}
            readbacks[label]["ListVersionsByFunction"] = {row["Version"]: row.get("DeadLetterConfig")
                for row in history.get("ListVersionsByFunction", {}).get("Versions", [])}
        return {"raw_capture": str(self.args.output), "probe": self.data["probe"],
            "workflow_complete": self.data.get("workflow_complete", False), "failure": self.data.get("failure"),
            "readbacks": readbacks, "positive_actual_deliveries": self.data["findings"],
            "counters": self.data.get("counters"), "deviations": self.data["deviations"],
            "observation_phases": self.data["observation_phases"], "cleanup": self.data["cleanup"],
            "redactions": self.data["redactions"],
            "limitations": self.data["limitations"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    args.terminal_seconds = 180
    summary_path = args.output.with_name(args.output.stem + "_summary.json")
    if summary_path.exists() and not args.cleanup_only:
        parser.error("Refusing to overwrite existing summary")
    deadlines = Deadlines()
    probe = None
    try:
        probe = DLQOwnershipProbe(args, deadlines)
        if not args.cleanup_only:
            probe.run()
    except BaseException as error:
        if probe is not None:
            probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
            probe.save()
        raise
    finally:
        deadlines.cleaning()
        try:
            if probe is not None:
                probe.cleanup()
        finally:
            if probe is not None:
                summary_path.write_text(json.dumps(probe.summary(), indent=2) + "\n")
                print("NATIVE_SUMMARY " + str(summary_path), flush=True)
            signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == "__main__":
    main()
