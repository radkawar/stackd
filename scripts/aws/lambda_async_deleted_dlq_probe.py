#!/usr/bin/env python3
"""Reviewed one-function native deleted-alias legacy DLQ calibration.

Uses the deletion probe's durable recorder, exact actor check, dependency setup,
and exact-owned cleanup. Never rerun the base probe's six-hour workflow.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import signal
import time

from botocore.config import Config

from lambda_async_deletion_probe import REGION, Probe, SOURCES, now

CASES = ("alias-retry0", "alias-retry1")
METRICS = ("Invocations", "Errors", "Throttles", "AsyncEventsReceived",
           "AsyncEventsDropped", "DeadLetterErrors", "DestinationDeliveryFailures")


class TerminalObservationDeadline(BaseException):
    # Control flow, not a transport failure: botocore wraps Exception subclasses
    # raised during socket reads, which would bypass observe's deadline boundary.
    pass


class DeletedDLQProbe(Probe):
    def __init__(self, args):
        # The base constructor performs only local recording and a fresh STS read.
        super().__init__(args)
        if args.cleanup_only:
            if self.data.get("probe") != "deleted-alias-legacy-dlq":
                raise RuntimeError("Cleanup requires this probe's reviewed inventory")
        else:
            self.data.update(probe="deleted-alias-legacy-dlq", ethics_review={
                "decision": "allow", "reviewed_at": "2026-10-01",
                "actor": self.actor, "region": REGION,
                "scope": "One tagged Python3.12 128MiB Lambda, timeout170, reservation<=3; one exact owned IAM role with inline sqs:SendMessage only to three owned queues; <=4 aliases/versions; <=24 async events; <=3000 queue reads; <=1800s total including <=900s terminal observation. No log grant, CloudTrail, provisioned concurrency, shared mutation, denial bypass or public endpoint."},
                bounds={"functions": 1, "queues": 3, "roles": 1,
                    "memory_mb": 128, "runtime": "python3.12", "timeout_seconds": 170,
                    "maximum_reserved_concurrency": 3, "maximum_aliases_and_versions": 4,
                    "maximum_async_events": 24, "maximum_queue_reads": 3000,
                    "terminal_seconds": args.terminal_seconds, "total_seconds": 1800},
                sources=SOURCES + [
                    "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html",
                    "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-view.html",
                    "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html"],
                cases=list(CASES), maximum_event_age_seconds=90)
            self.data.pop("prior_evidence", None)
            self.data.pop("prior_evidence_limit", None)
            self.data["limitations"].append("Missing CloudWatch datapoints remain absent; deltas require data in both snapshots. FunctionName totals include controls and synchronous blockers; Resource dimensions and time windows are retained separately.")
            self.save()
        self.clients["cloudwatch"] = self.session.client("cloudwatch", config=Config(
            ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=20,
            retries={"total_max_attempts": 1}))

    def setup(self):
        self.setup_dependencies(("marker", "onfailure", "legacy"))
        owned = self.data["owned"]
        function = owned["functions"]["aliases"] = {"name": self.data["prefix"] + "-aliases"}
        self.save()
        self.call("absent-before-create-aliases", "lambda", "get_function",
                  self.function_request("aliases"), expect="ResourceNotFoundException")
        function["creation_planned"] = "legacy-before-publish"
        self.save()
        output = self.call("create-legacy-before-publish", "lambda", "create_function", {
            **self.function_request("aliases"), "Role": owned["role"]["arn"],
            "Runtime": "python3.12", "Handler": "handler.handler",
            "Code": {"ZipFile": self.package("legacy-before-publish")},
            "Timeout": 170, "MemorySize": 128, "Publish": True,
            "DeadLetterConfig": {"TargetArn": owned["queues"]["legacy"]["arn"]},
            "Environment": {"Variables": {"MARKER_QUEUE": owned["queues"]["marker"]["url"]}},
            "Tags": {"stackd-probe": self.data["prefix"]}})
        function.update(arn=output["FunctionArn"], revision=output["RevisionId"],
                        published_version=output["Version"])
        self.save()
        self.ready("aliases")
        self.call("two-control-slots", "lambda", "put_function_concurrency", {
            **self.function_request("aliases"), "ReservedConcurrentExecutions": 2})
        self.call("published-legacy-readback", "lambda", "get_function_configuration", {
            **self.function_request("aliases", output["Version"])})
        for retry, case in enumerate(CASES):
            alias = self.call("create-" + case, "lambda", "create_alias", {
                **self.function_request("aliases"), "Name": case,
                "FunctionVersion": output["Version"], "Description": self.data["prefix"]})
            function.setdefault("aliases", {})[case] = alias
            self.save()
            self.call("configure-" + case, "lambda", "put_function_event_invoke_config", {
                **self.target(case), "MaximumRetryAttempts": retry,
                "MaximumEventAgeInSeconds": 90, "DestinationConfig": {"OnFailure": {
                    "Destination": owned["queues"]["onfailure"]["arn"]}}})
            self.call("config-readback-" + case, "lambda", "get_function_event_invoke_config",
                      self.target(case))
        # Not an applied-settings claim: runtime/route controls below are mandatory.
        time.sleep(90)

    def invoke(self, case, event_id, mode="fail", sleep=0):
        if len(self.data["events"]) >= self.data["bounds"]["maximum_async_events"]:
            raise RuntimeError("Async event count bound reached")
        event = {"case": event_id, "mode": mode, "sleep": sleep,
                 "probe": self.data["prefix"], "original": {"unicode": "payload-\u03bb", "integer": 17}}
        raw = json.dumps(event, separators=(",", ":"))
        self.data["events"][event_id] = {"target": case, "payload": event,
            "payload_raw": raw, "admitted_epoch": time.time()}
        self.save()
        out = self.call("admit-" + event_id, "lambda", "invoke", {
            **self.target(case), "InvocationType": "Event", "Payload": raw.encode()})
        if out["StatusCode"] != 202:
            raise RuntimeError("Async event was not accepted202")
        self.data["events"][event_id]["admitted_at"] = now()
        self.save()

    def poll(self):
        for key, queue in self.data["owned"]["queues"].items():
            self.data["queue_reads"] = self.data.get("queue_reads", 0) + 1
            if self.data["queue_reads"] > self.data["bounds"]["maximum_queue_reads"]:
                raise RuntimeError("Queue read bound reached")
            out = self.call("poll-" + key, "sqs", "receive_message", {
                "QueueUrl": queue["url"], "MaxNumberOfMessages": 10,
                "WaitTimeSeconds": 1, "VisibilityTimeout": 30,
                "MessageSystemAttributeNames": ["All"], "MessageAttributeNames": ["All"]})
            self.data["last_queue_read_finished_epoch"] = time.time()
            for message in out.get("Messages", []):
                decoded = json.loads(message["Body"])
                row = {"queue": key, "message_id": message["MessageId"],
                    "observed_at": now(), "observed_epoch": time.time(),
                    "body_raw": message["Body"], "body": decoded,
                    "attributes": message.get("Attributes", {}),
                    "message_attributes": message.get("MessageAttributes", {}),
                    "raw_message": message}
                self.data["messages"].append(row)
                self.save()
                if key == "legacy" and decoded.get("case", "").endswith("-deleted-before-entry"):
                    print("NATIVE_DELETED_ALIAS_DLQ " + json.dumps({
                        "event": decoded["case"], "message_attributes": row["message_attributes"],
                        "body_raw": row["body_raw"], "observed_at": row["observed_at"]}), flush=True)
                self.call("consume-owned-message", "sqs", "delete_message", {
                    "QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]})

    def rows(self, event_id, queue):
        return [row for row in self.data["messages"] if row["queue"] == queue and
                (row["body"].get("requestPayload", {}) if queue == "onfailure" else
                 row["body"]).get("case") == event_id]

    def messages(self, event_id, marker=False):
        return self.rows(event_id, "marker" if marker else "onfailure")

    def entries(self, event_id):
        return [row for row in self.rows(event_id, "marker") if row["body"]["phase"] == "entry"]

    def both_routes(self, event_id):
        return bool(self.rows(event_id, "onfailure") and self.rows(event_id, "legacy"))

    def record_control(self, case, kind, count, condition):
        event_id = case + "-control-" + kind
        destination, legacy = self.rows(event_id, "onfailure"), self.rows(event_id, "legacy")
        contexts = [row["body"]["requestContext"] for row in destination]
        entries = self.entries(event_id)
        if not destination or not legacy:
            raise RuntimeError("Both control routes not positively observed: " + event_id)
        if any(row["condition"] != condition or row["approximateInvokeCount"] != count for row in contexts):
            raise RuntimeError("Applied control destination mismatch: " + event_id)
        if len({row["body"]["request_id"] for row in entries}) != count:
            # Retried invocations may reuse a request ID; count unique marker messages instead.
            if len({row["message_id"] for row in entries}) != count:
                raise RuntimeError("Applied control entry mismatch: " + event_id)
        event = self.data["events"][event_id]
        if any(row["body"] != event["payload"] for row in legacy):
            raise RuntimeError("Legacy DLQ did not preserve original event: " + event_id)
        required = {"RequestID", "ErrorCode", "ErrorMessage"}
        if any(not required <= row["message_attributes"].keys() for row in legacy):
            raise RuntimeError("Legacy DLQ attributes missing: " + event_id)
        self.data["controls"].setdefault(case, {})[kind] = {
            "event": event_id, "condition": condition, "count": count,
            "runtime_entries": entries, "onfailure": destination, "legacy_dlq": legacy,
            "completed_at": now(), "seconds_after_admission": round(time.time()-event["admitted_epoch"], 3)}
        self.save()

    def blocker(self, executor, event_id, seconds):
        future = executor.submit(self.call, "blocker-" + event_id, "lambda", "invoke", {
            **self.function_request("aliases"), "InvocationType": "RequestResponse",
            "Payload": json.dumps({"case": event_id, "mode": "success", "sleep": seconds}).encode()})
        if not self.wait_until(lambda: bool(self.entries(event_id)), 25, 1):
            raise RuntimeError("Synchronous blocker did not positively enter")
        self.call("occupied429-" + event_id, "lambda", "invoke", {
            **self.function_request("aliases"), "InvocationType": "RequestResponse",
            "Payload": json.dumps({"case": event_id + "-429-check"}).encode()},
            expect="TooManyRequestsException")
        return future

    def finish_blocker(self, event_id, future):
        output = future.result(timeout=175)
        if output.get("FunctionError"):
            raise RuntimeError("Synchronous blocker failed: " + event_id)
        self.data.setdefault("blockers", {})[event_id] = output
        self.save()

    def controls(self):
        for case in CASES:
            self.invoke(case, case + "-control-retry")
        if not self.wait_until(lambda: all(self.both_routes(case + "-control-retry") and
                len(self.entries(case + "-control-retry")) >= retry+1
                for retry, case in enumerate(CASES)), 240, 3):
            raise RuntimeError("Ordinary handler controls did not positively establish both routes")
        for retry, case in enumerate(CASES):
            self.record_control(case, "retry", retry+1, "RetriesExhausted")
        self.call("single-control-slot", "lambda", "put_function_concurrency", {
            **self.function_request("aliases"), "ReservedConcurrentExecutions": 1})
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = self.blocker(executor, "age-control-blocker", 130)
            for case in CASES:
                self.invoke(case, case + "-control-age")
            # Poll while occupied so terminal timing does not become blocker completion timing.
            self.wait_until(lambda: all(self.both_routes(case + "-control-age") for case in CASES), 260, 3)
            self.finish_blocker("age-control-blocker", future)
        for case in CASES:
            self.record_control(case, "age", 0, "EventAgeExceeded")
        self.data["controls_completed_at"] = now()
        self.save()
        print("NATIVE_CONTROLS_COMPLETE", flush=True)

    def metrics(self, label, start=None):
        name = self.data["owned"]["functions"]["aliases"]["name"]
        dimensions = {"FunctionName": [{"Name": "FunctionName", "Value": name}]}
        for resource in ("$LATEST", *CASES):
            dimensions[resource] = [{"Name": "FunctionName", "Value": name},
                                    {"Name": "Resource", "Value": name + ":" + resource}]
        queries, identities = [], {}
        for dimension_key, values in dimensions.items():
            for metric in METRICS:
                key = "m" + str(len(queries))
                identities[key] = {"metric": metric, "dimension_key": dimension_key,
                                   "dimensions": values}
                queries.append({"Id": key, "MetricStat": {"Metric": {"Namespace": "AWS/Lambda",
                    "MetricName": metric, "Dimensions": values}, "Period": 60, "Stat": "Sum"},
                    "ReturnData": True})
        start_epoch = self.data["started_epoch"] if start is None else start
        request = {"MetricDataQueries": queries,
            "StartTime": datetime.fromtimestamp(math.floor(start_epoch/60)*60, timezone.utc),
            "EndTime": datetime.now(timezone.utc), "ScanBy": "TimestampAscending"}
        output = self.call("metrics-" + label, "cloudwatch", "get_metric_data", request,
                           expect=("Success", "AccessDenied", "AccessDeniedException"))
        snapshot = {"captured_at": now(), "requested_start_epoch": start_epoch,
                    "identities": identities, "raw": output, "series": {}}
        for row in output.get("MetricDataResults", []):
            snapshot["series"][row["Id"]] = {**identities[row["Id"]],
                "datapoints": [{"timestamp": timestamp, "value": value}
                    for timestamp, value in zip(row.get("Timestamps", []), row.get("Values", []))],
                "observed_sum": sum(row["Values"]) if row.get("Values") else None,
                "status": row.get("StatusCode"), "messages": row.get("Messages", [])}
        self.data.setdefault("metrics", {})[label] = snapshot
        if label == "final" and "baseline" in self.data["metrics"]:
            before = self.data["metrics"]["baseline"]["series"]
            self.data["metrics"]["deltas"] = {
                key: {**identities[key], "before": before.get(key, {}).get("observed_sum"),
                    "after": row["observed_sum"], "delta": row["observed_sum"] - before[key]["observed_sum"]
                    if row["observed_sum"] is not None and before.get(key, {}).get("observed_sum") is not None
                    else None} for key, row in snapshot["series"].items()}
        self.save()

    def mutate(self):
        self.metrics("baseline")
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = self.blocker(executor, "deletion-blocker", 90)
            self.data["mutation_started_epoch"] = time.time()
            for case in CASES:
                self.invoke(case, case + "-deleted-before-entry")
            for case in CASES:
                request = {**self.function_request("aliases"), "Name": case}
                alias = self.call("identity-before-delete-" + case, "lambda", "get_alias", request)
                if alias.get("Description") != self.data["prefix"] or alias["AliasArn"] != self.data["owned"]["functions"]["aliases"]["aliases"][case]["AliasArn"]:
                    raise RuntimeError("Alias ownership mismatch")
                self.call("delete-" + case, "lambda", "delete_alias", request)
                self.call("absent-" + case, "lambda", "get_alias", request,
                          expect="ResourceNotFoundException")
                self.data["events"][case + "-deleted-before-entry"]["alias_absent_at"] = now()
                self.save()
            self.wait_until(lambda: future.done(), 110, 2)
            self.finish_blocker("deletion-blocker", future)
        self.summarize()

    def summarize(self):
        for case in CASES:
            event_id = case + "-deleted-before-entry"
            event = self.data["events"].get(event_id)
            if not event:
                continue
            terminals, legacy = self.rows(event_id, "onfailure"), self.rows(event_id, "legacy")
            self.data["findings"][case] = {"event": event_id,
                "observed_through_seconds_after_admission": round(
                    self.data.get("last_queue_read_finished_epoch", event["admitted_epoch"])-event["admitted_epoch"], 3),
                "runtime_entries": self.entries(event_id), "onfailure": terminals, "legacy_dlq": legacy,
                "onfailure_outcome": "record_observed" if terminals else "bounded_absence_inconclusive",
                "legacy_dlq_outcome": "record_observed" if legacy else "bounded_absence_inconclusive"}
        self.save()

    def observe(self):
        admitted = min(self.data["events"][case + "-deleted-before-entry"]["admitted_epoch"] for case in CASES)
        deadline = admitted + self.args.terminal_seconds
        self.data["terminal_observation_deadline_epoch"] = deadline
        self.save()
        if time.time() >= deadline:
            return
        previous_handler = signal.getsignal(signal.SIGALRM)
        workflow_remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        entered = time.monotonic()
        terminal_remaining = max(0.001, deadline-time.time())
        workflow_expires_first = bool(workflow_remaining and workflow_remaining <= terminal_remaining)

        def expired(signum, frame):
            if workflow_expires_first:
                raise RuntimeError("Reviewed total workflow deadline reached")
            raise TerminalObservationDeadline("Reviewed terminal observation deadline reached")

        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL,
            workflow_remaining if workflow_expires_first else terminal_remaining)
        try:
            while time.time() < deadline:
                self.poll()
                self.summarize()
                time.sleep(min(8, max(0, deadline-time.time())))
        except TerminalObservationDeadline:
            pass
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            if workflow_remaining and not workflow_expires_first:
                signal.setitimer(signal.ITIMER_REAL,
                    max(0.001, workflow_remaining-(time.monotonic()-entered)), interval)
        # No unconditional final poll: it would exceed the reviewed observation window.
        self.summarize()

    def run(self):
        self.setup()
        self.controls()
        self.mutate()
        self.observe()
        self.metrics("final")
        self.metrics("lifecycle-window", self.data["mutation_started_epoch"])
        self.data.update(workflow_complete=True, finished_at=now(),
                         workflow_duration_seconds=round(time.time()-self.data["started_epoch"], 3))
        self.save()
        print("NATIVE_OBSERVATION_COMPLETE " + json.dumps(self.data["findings"]), flush=True)

    def cleanup(self):
        # Repeat the exact actor check immediately before cleanup mutations.
        identity = self.call("verify-cleanup-identity", "sts", "get_caller_identity")
        if identity["Account"] != self.account or identity["Arn"] != self.actor:
            raise RuntimeError("Cleanup requires exact authorized actor")
        self.data["cleanup"]["identity"] = identity
        self.save()
        super().cleanup()
        # Independent second absence inventory after the deletion sequence.
        for key in self.data["owned"]["functions"]:
            self.call("independent-absent-function-" + key, "lambda", "get_function",
                      self.function_request(key), expect="ResourceNotFoundException")
        if "role" in self.data["owned"]:
            self.call("independent-absent-role", "iam", "get_role",
                      {"RoleName": self.data["owned"]["role"]["name"]}, expect="NoSuchEntity")
        for key, queue in self.data["owned"]["queues"].items():
            self.call("independent-absent-queue-" + key, "sqs", "get_queue_url", {"QueueName": queue["name"]},
                      expect=("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
        self.data["cleanup"].update(independent_absence_verified=True,
            total_duration_seconds=round(time.time()-self.data["started_epoch"], 3))
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--terminal-seconds", type=int, default=900)
    args = parser.parse_args()
    if not 120 <= args.terminal_seconds <= 900:
        parser.error("Terminal observation must be 120..900 seconds")
    probe = DeletedDLQProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.alarm(1650)
    try:
        if not args.cleanup_only:
            probe.run()
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        remaining = 150 if args.cleanup_only else max(1, int(1800-(time.time()-probe.data["started_epoch"])))
        signal.alarm(remaining)
        try:
            probe.cleanup()
        finally:
            signal.alarm(0)


if __name__ == "__main__":
    main()
