#!/usr/bin/env python3
"""Exact-owned native whole/fixed deletion and failed-handler deletion experiment.

Requires an explicit ethics review. Reuses the retained deletion recorder and
independent ownership cleanup. Bounded absence is never a terminal contract.
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

from lambda_async_deletion_probe import Probe, REGION, now
from lambda_async_deleted_dlq_probe import DeletedDLQProbe, METRICS, TerminalObservationDeadline

TARGETS = {
    "function-retry0": ("whole0", None, 0),
    "function-retry1": ("whole1", None, 1),
    "version-retry0": ("fixed", "1", 0),
    "version-retry1": ("fixed", "2", 1),
    "function-failed": ("wholefail", None, 1),
    "version-failed": ("fixed", "3", 1),
    "alias-failed": ("fixed", "failed", 1),
}


class DeletedTargetsProbe(DeletedDLQProbe):
    def __init__(self, args):
        Probe.__init__(self, args)
        if args.cleanup_only:
            if self.data.get("probe") != "deleted-whole-fixed-postfailure":
                raise RuntimeError("Cleanup requires this probe's exact inventory")
        else:
            self.data.update(probe="deleted-whole-fixed-postfailure", ethics_review={
                "decision": "allow", "reviewed_at": "2026-10-01", "actor": self.actor,
                "region": REGION, "scope": "Four tagged128MiB Python3.12 functions, timeout170, reservation total<=7; <=4 fixed versions and one alias; three tagged SQS queues; one tagged exact-send-only role; <=28 async events, <=2000 queue reads, <=8 metric calls, <=1500s workflow, <=600s terminal observation; exact-owned cleanup and independent absence."},
                bounds={"functions": 4, "queues": 3, "roles": 1, "memory_mb": 128,
                    "maximum_reserved_concurrency": 7, "maximum_async_events": 28,
                    "maximum_queue_reads": 2000, "maximum_metric_calls": 8,
                    "terminal_seconds": args.terminal_seconds, "total_seconds": 1500},
                cases=list(TARGETS), maximum_event_age_seconds=90)
            self.data.pop("prior_evidence", None)
            self.data.pop("prior_evidence_limit", None)
            self.save()
        self.clients["cloudwatch"] = self.session.client("cloudwatch", config=Config(
            ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=20,
            retries={"total_max_attempts": 1}))

    def target(self, case):
        key, qualifier, _ = TARGETS[case]
        return self.function_request(key, qualifier)

    def setup(self):
        self.setup_dependencies(("marker", "onfailure", "legacy"))
        owned = self.data["owned"]
        for key in ("whole0", "whole1", "wholefail", "fixed"):
            function = owned["functions"][key] = {"name": self.data["prefix"] + "-" + key}
            self.save()
            self.call("absent-before-create-" + key, "lambda", "get_function",
                      self.function_request(key), expect="ResourceNotFoundException")
            function["creation_planned"] = True
            self.save()
            result = self.call("create-" + key, "lambda", "create_function", {
                **self.function_request(key), "Runtime": "python3.12", "Handler": "handler.handler",
                "Role": owned["role"]["arn"], "Code": {"ZipFile": self.package("one")},
                "Timeout": 170, "MemorySize": 128, "Publish": key == "fixed",
                "DeadLetterConfig": {"TargetArn": owned["queues"]["legacy"]["arn"]},
                "Environment": {"Variables": {"MARKER_QUEUE": owned["queues"]["marker"]["url"]}},
                "Tags": {"stackd-probe": self.data["prefix"]}})
            function.update(arn=result["FunctionArn"], revision=result["RevisionId"])
            self.save()
            self.ready(key)
            self.call("concurrency-" + key, "lambda", "put_function_concurrency", {
                **self.function_request(key), "ReservedConcurrentExecutions": 4 if key == "fixed" else 1})
        for deployment, version in (("two", "2"), ("three", "3")):
            result = self.call("publish-" + deployment, "lambda", "update_function_code", {
                **self.function_request("fixed"), "ZipFile": self.package(deployment), "Publish": True})
            if result["Version"] != version:
                raise RuntimeError("Unexpected publication identity")
            self.ready("fixed")
        alias = self.call("create-failed-alias", "lambda", "create_alias", {
            **self.function_request("fixed"), "Name": "failed", "FunctionVersion": "3",
            "Description": self.data["prefix"]})
        owned["functions"]["fixed"]["aliases"] = {"failed": alias}
        for case, (_, _, retries) in TARGETS.items():
            self.call("configure-" + case, "lambda", "put_function_event_invoke_config", {
                **self.target(case), "MaximumRetryAttempts": retries, "MaximumEventAgeInSeconds": 90,
                "DestinationConfig": {"OnFailure": {"Destination": owned["queues"]["onfailure"]["arn"]}}})
            self.call("readback-" + case, "lambda", "get_function_event_invoke_config", self.target(case))
        self.save()
        time.sleep(90)

    def blockers(self, executor, label):
        futures = {}
        for key in ("whole0", "whole1", "wholefail", "fixed"):
            self.call("single-slot-" + key, "lambda", "put_function_concurrency", {
                **self.function_request(key), "ReservedConcurrentExecutions": 1})
            event_id = label + "-" + key
            futures[event_id] = executor.submit(self.call, "blocker-" + event_id, "lambda", "invoke", {
                **self.function_request(key), "InvocationType": "RequestResponse",
                "Payload": json.dumps({"case": event_id, "mode": "success", "sleep": 130}).encode()})
        if not self.wait_until(lambda: all(self.entries(event_id) for event_id in futures), 30, 1):
            raise RuntimeError("Blockers did not positively enter")
        for key in ("whole0", "whole1", "wholefail", "fixed"):
            self.call("occupied429-" + label + "-" + key, "lambda", "invoke", {
                **self.function_request(key), "InvocationType": "RequestResponse",
                "Payload": json.dumps({"case": label + "-busy-" + key}).encode()}, expect="TooManyRequestsException")
        return futures

    def controls(self):
        for case in TARGETS:
            self.invoke(case, case + "-control-retry")
        if not self.wait_until(lambda: all(self.both_routes(case + "-control-retry") and
                len(self.entries(case + "-control-retry")) >= retries+1
                for case, (_, _, retries) in TARGETS.items()), 240, 2):
            raise RuntimeError("Exact-target failure controls incomplete")
        for case, (_, _, retries) in TARGETS.items():
            self.record_control(case, "retry", retries+1, "RetriesExhausted")
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = self.blockers(executor, "age")
            for case in TARGETS:
                self.invoke(case, case + "-control-age")
            if not self.wait_until(lambda: all(self.both_routes(case + "-control-age") for case in TARGETS), 240, 2):
                raise RuntimeError("Exact-target age controls incomplete")
            for event_id, future in futures.items():
                self.finish_blocker(event_id, future)
        for case in TARGETS:
            self.record_control(case, "age", 0, "EventAgeExceeded")
        self.data["controls_completed_at"] = now()
        self.save()

    def delete_target(self, case):
        key, qualifier, _ = TARGETS[case]
        if qualifier is None:
            self.delete_function(key)
        else:
            if not self.owned_function(key):
                raise RuntimeError("Missing exact-owned version parent")
            if case == "alias-failed":
                request = {**self.function_request(key), "Name": qualifier}
                alias = self.call("identity-" + case, "lambda", "get_alias", request)
                if alias.get("Description") != self.data["prefix"]:
                    raise RuntimeError("Foreign alias")
                self.call("delete-" + case, "lambda", "delete_alias", request)
                self.call("absent-" + case, "lambda", "get_alias", request, expect="ResourceNotFoundException")
            else:
                self.call("delete-" + case, "lambda", "delete_function", self.target(case))
                self.call("absent-" + case, "lambda", "get_function", self.target(case), expect="ResourceNotFoundException")
        self.data["events"][case + "-deleted-before-entry"]["target_absent_at"] = now()
        self.save()

    def mutate(self):
        self.metrics("baseline")
        self.data["mutation_started_epoch"] = time.time()
        # These three events enter and raise before deletion; the event suffix is
        # shared only to reuse bounded observation, not a pre-entry claim.
        for case in ("function-failed", "alias-failed", "version-failed"):
            event_id = case + "-deleted-before-entry"
            self.invoke(case, event_id)
            if not self.wait_until(lambda: any(row["body"]["phase"] == "exit"
                    for row in self.rows(event_id, "marker")), 25, 1):
                raise RuntimeError("Failure attempt did not reach actual runtime exit marker")
            time.sleep(2)
            self.delete_target(case)
        # Wholefail was already deleted; only the three remaining parents need
        # blockers. Build these explicitly so no absent function is invoked.
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for key in ("whole0", "whole1", "fixed"):
                event_id = "queued-" + key
                futures[event_id] = executor.submit(self.call, "blocker-" + event_id, "lambda", "invoke", {
                    **self.function_request(key), "InvocationType": "RequestResponse",
                    "Payload": json.dumps({"case": event_id, "mode": "success", "sleep": 45}).encode()})
            if not self.wait_until(lambda: all(self.entries(event_id) for event_id in futures), 25, 1):
                raise RuntimeError("Queued blockers did not enter")
            for key in ("whole0", "whole1", "fixed"):
                self.call("occupied429-queued-" + key, "lambda", "invoke", {
                    **self.function_request(key), "InvocationType": "RequestResponse",
                    "Payload": json.dumps({"case": "queued-busy-" + key}).encode()}, expect="TooManyRequestsException")
            for case in ("function-retry0", "function-retry1", "version-retry0", "version-retry1"):
                self.invoke(case, case + "-deleted-before-entry", mode="success")
                self.delete_target(case)
            for event_id, future in futures.items():
                self.finish_blocker(event_id, future)
        self.summarize()

    def metrics(self, label, start=None):
        queries, identities = [], {}
        for case, (key, qualifier, _) in TARGETS.items():
            name = self.data["owned"]["functions"][key]["name"]
            dimensions = [{"Name": "FunctionName", "Value": name}]
            if qualifier:
                dimensions.append({"Name": "Resource", "Value": name + ":" + qualifier})
            for metric in METRICS:
                query_id = "m" + str(len(queries))
                identities[query_id] = {"case": case, "metric": metric, "dimensions": dimensions}
                queries.append({"Id": query_id, "MetricStat": {"Metric": {"Namespace": "AWS/Lambda",
                    "MetricName": metric, "Dimensions": dimensions}, "Period": 60, "Stat": "Sum"}, "ReturnData": True})
        start_epoch = self.data["started_epoch"] if start is None else start
        output = self.call("metrics-" + label, "cloudwatch", "get_metric_data", {
            "MetricDataQueries": queries, "StartTime": datetime.fromtimestamp(math.floor(start_epoch/60)*60, timezone.utc),
            "EndTime": datetime.now(timezone.utc), "ScanBy": "TimestampAscending"},
            expect=("Success", "AccessDenied", "AccessDeniedException"))
        self.data.setdefault("metrics", {})[label] = {"identities": identities, "raw": output, "captured_at": now()}
        self.save()

    def summarize(self):
        for case in TARGETS:
            event_id = case + "-deleted-before-entry"
            event = self.data["events"].get(event_id)
            if not event:
                continue
            self.data["findings"][case] = {"event": event_id, "deleted_after_handler_exit": case.endswith("failed"),
                "observed_through_seconds_after_admission": round(self.data.get("last_queue_read_finished_epoch", event["admitted_epoch"])-event["admitted_epoch"], 3),
                "runtime_entries": self.entries(event_id), "onfailure": self.rows(event_id, "onfailure"),
                "legacy_dlq": self.rows(event_id, "legacy"),
                "outcome": "terminal_observed" if self.both_routes(event_id) else "bounded_absence_inconclusive"}
        self.save()

    def observe(self):
        admitted = min(self.data["events"][case + "-deleted-before-entry"]["admitted_epoch"] for case in TARGETS)
        deadline = admitted + self.args.terminal_seconds
        self.data["terminal_observation_deadline_epoch"] = deadline
        self.save()
        previous_handler = signal.getsignal(signal.SIGALRM)
        workflow_remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        entered = time.monotonic()
        remaining = max(.001, deadline-time.time())
        workflow_first = bool(workflow_remaining and workflow_remaining <= remaining)
        def expired(signum, frame):
            if workflow_first:
                raise RuntimeError("Reviewed total workflow deadline reached")
            raise TerminalObservationDeadline()
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, workflow_remaining if workflow_first else remaining)
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
            if workflow_remaining and not workflow_first:
                signal.setitimer(signal.ITIMER_REAL, max(.001, workflow_remaining-(time.monotonic()-entered)), interval)
        self.summarize()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--terminal-seconds", type=int, default=600)
    args = parser.parse_args()
    if not 120 <= args.terminal_seconds <= 600:
        parser.error("Reviewed terminal window is120..600 seconds")
    probe = DeletedTargetsProbe(args)
    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.alarm(1350)
    try:
        if not args.cleanup_only:
            probe.run()
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        signal.alarm(150 if args.cleanup_only else max(1, int(1500-(time.time()-probe.data["started_epoch"]))))
        try:
            probe.cleanup()
        finally:
            signal.alarm(0)


if __name__ == "__main__":
    main()
