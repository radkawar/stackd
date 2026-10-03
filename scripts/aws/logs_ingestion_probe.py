#!/usr/bin/env python3
"""Capture owned CloudWatch Logs ingestion; run from the repository root.

Uses shared AWS CLI transport, disables retries, and never lists outside its
unique group/stream prefixes. Large requests use a temporary CLI input file and
shared run/result decoding to avoid the operating system's argument-size limit.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

from aws_cli import ProbeResult, call, observe, result, run


REGION = "us-east-1"
HOUR = 3_600_000
DAY = 24 * HOUR
REFERENCES = [
    "CreateLogGroup", "DeleteLogGroup", "CreateLogStream", "DeleteLogStream",
    "PutRetentionPolicy", "DeleteRetentionPolicy", "TagResource",
    "ListTagsForResource", "UntagResource", "DescribeLogGroups",
    "PutLogEvents", "GetLogEvents", "DescribeLogStreams", "RejectedLogEventsInfo",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard")
    identity = call("sts", "get-caller-identity", env=env)
    account = identity["Account"]
    if account != args.account:
        raise RuntimeError("Unexpected AWS account; no resources created")
    group = "/stackd/native-logs-ingestion-" + uuid.uuid4().hex
    group_input = {"logGroupName": group}
    arn = f"arn:aws:logs:{REGION}:{account}:log-group:{group}"
    anchor = time.time_ns() // 1_000_000
    path = Path(".stackd/probes/logs/ingestion.json")
    capture = {
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": REGION,
        "scope": "One uniquely owned group and five owned streams; direct Logs API ingestion, not Lambda invocation; no existing resources changed or unrelated resources listed",
        "primary_references": ["https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_" + name + ".html" for name in REFERENCES],
        "identity_relationships": {
            "caller_account": "123456789012", "group_account_matches_caller": True,
            "substitutions": "Caller account becomes 123456789012; caller ARN/UserId are not retained; unique group becomes /stackd/native-logs-ingestion-owned. Opaque tokens and all timestamps are unchanged, preserving equality and order.",
        },
        "clock_anchor_ms": anchor,
        "clock_design": "All event timestamps are anchor plus the recorded offset. Rejection probes use at least one hour beyond the future limit and at least a day beyond the 14-day limit; no exact racing wall-clock cutoff is inferred. The 24-hour span cases compare event timestamps, not wall time.",
        "limitations": [
            "Single account, region and run; not a claim of parity for the 57 pinned Logs operations.",
            "No concurrent ingestion, token expiry, 10000-event boundary, Lambda delivery, retention-time deletion, or long-horizon visibility probe.",
            "Large byte-budget events are deliberately 16 days old to avoid retaining megabytes. Their success means request admitted with per-event rejection, not large-event ingestion. Inputs are deterministic construction summaries, not literal API requests.",
            "Large requests use shared run/result text-error decoding; these results preserve native code/message but not JSON error envelopes. Other requests use shared observe and retain native JSON errors.",
            "PutLogEvents success is admission evidence, not proof every event is readable. Explicit-range terminal pagination retains the actual messages observed; absence during this bounded capture is not a claim of permanent loss or a reason to reinterpret native rejection indices.",
            "DescribeLogStreams metadata can lag up to an hour or longer per AWS; bounded polling records visibility and does not assert immediate consistency.",
        ],
        "request_counts": {"sts": 1, "logs": 0, "total": 1, "automatic_retries": False},
        "observations": [], "cleanup": {"verified": False},
    }
    owned = False

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(capture, indent=2, ensure_ascii=False)
        path.write_text(encoded.replace(account, "123456789012").replace(group, "/stackd/native-logs-ingestion-owned") + "\n")

    def request(label, operation, parameters, *, summary=None) -> ProbeResult:
        capture["request_counts"]["logs"] += 1
        capture["request_counts"]["total"] += 1
        started = time.time_ns() // 1_000_000
        if summary is None:
            response = observe("logs", operation, parameters, env, paginate=False)
        else:
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", encoding="utf-8") as source:
                json.dump(parameters, source, ensure_ascii=False)
                source.flush()
                process = run("logs", operation, env=env, options=[
                    "--cli-input-json", "file://" + source.name, "--no-paginate",
                    "--cli-connect-timeout", "10", "--cli-read-timeout", "30",
                ], timeout=50)
            response = result(process)
            if response["code"] == "CLIError":
                raise RuntimeError("Large request transport/client failure; not native evidence")
        capture["observations"].append({
            "label": label, "service": "logs", "operation": operation,
            "input": parameters if summary is None else summary,
            "request_started_ms": started, "request_finished_ms": time.time_ns() // 1_000_000,
            "result": response,
        })
        save()
        print(label + ": " + response["code"], flush=True)
        return response

    def require(response):
        if response["code"] != "Success":
            raise RuntimeError("Required owned setup/read failed: " + response["code"])
        return response["output"]

    def stream(name):
        return dict(group_input, logStreamName="owned-" + name)

    def events(rows):
        return [{"timestamp": anchor + offset, "message": message} for offset, message in rows]

    def put(label, name, rows, **extra):
        return request(label, "put-log-events", dict(stream(name), logEvents=events(rows), **extra))

    def describe(label):
        return request(label, "describe-log-groups", {"logGroupNamePrefix": group})

    try:
        created = request("create-group", "create-log-group", dict(group_input, tags={"owner": "stackd-probe", "phase": "created"}))
        require(created)
        owned = True
        request("create-group-duplicate", "create-log-group", group_input)
        describe("describe-group-defaults")
        for label, operation, parameters in [
            ("tags-created", "list-tags-for-resource", {"resourceArn": arn}),
            ("tags-merge-replace", "tag-resource", {"resourceArn": arn, "tags": {"phase": "updated", "extra": "value"}}),
            ("tags-updated", "list-tags-for-resource", {"resourceArn": arn}),
            ("untag-existing-and-missing", "untag-resource", {"resourceArn": arn, "tagKeys": ["phase", "absent"]}),
            ("tags-after-untag", "list-tags-for-resource", {"resourceArn": arn}),
            ("retention-one-day", "put-retention-policy", dict(group_input, retentionInDays=1)),
        ]:
            require(request(label, operation, parameters))
        describe("describe-retention-one-day")
        for name in ["sequence", "mixed", "span", "bytes", "lifecycle"]:
            require(request("create-stream-" + name, "create-log-stream", stream(name)))
        request("create-stream-duplicate", "create-log-stream", stream("sequence"))
        request("describe-stream-before-ingestion", "describe-log-streams", dict(group_input, logStreamNamePrefix="owned-sequence"))
        for label, operation, parameters in [
            ("create-stream-missing-group", "create-log-stream", {"logGroupName": group + "-missing", "logStreamName": "owned-missing"}),
            ("delete-missing-group", "delete-log-group", {"logGroupName": group + "-missing"}),
            ("delete-missing-stream", "delete-log-stream", stream("missing")),
            ("delete-stream-missing-group", "delete-log-stream", {"logGroupName": group + "-missing", "logStreamName": "owned-missing"}),
            ("put-missing-stream", "put-log-events", dict(stream("missing"), logEvents=events([(-HOUR, "missing")]))),
            ("put-missing-group", "put-log-events", {"logGroupName": group + "-missing", "logStreamName": "owned-missing", "logEvents": events([(-HOUR, "missing")])}),
            ("get-missing-stream", "get-log-events", stream("missing")),
            ("delete-stream", "delete-log-stream", stream("lifecycle")),
            ("delete-stream-again", "delete-log-stream", stream("lifecycle")),
            ("get-deleted-stream", "get-log-events", stream("lifecycle")),
        ]:
            request(label, operation, parameters)

        base = -10 * 60_000
        original = [(base, "A"), (base + 1000, "B"), (base + 2000, "C")]
        first = require(put("sequence-omitted-first", "sequence", original))
        stale = first.get("nextSequenceToken")
        require(put("sequence-arbitrary-ignored", "sequence", [(base + 3000, "D")], sequenceToken="not-a-valid-sequence-token"))
        require(put("sequence-omitted-after-write", "sequence", [(base + 4000, "E")]))
        if stale is None:
            raise RuntimeError("No sequence token returned; cannot capture stale-token case")
        require(put("sequence-stale-token", "sequence", [(base + 5000, "F")], sequenceToken=stale))
        require(put("sequence-duplicate-original-batch", "sequence", original, sequenceToken=stale))
        request("describe-stream-immediate", "describe-log-streams", dict(group_input, logStreamNamePrefix="owned-sequence"))
        put("chronological-order-reversed", "sequence", [(base + 7000, "reversed-late"), (base + 6000, "reversed-early")])
        mixed = [(-16 * DAY, "too-old-0"), (-15 * DAY, "too-old-1"),
                 (-2 * DAY, "retention-expired-2"), (-36 * HOUR, "retention-expired-3"),
                 (-2 * HOUR, "valid-4"), (-HOUR, "valid-5"),
                 (3 * HOUR, "too-new-6"), (4 * HOUR, "too-new-7")]
        put("mixed-retention-old-valid-future", "mixed", mixed)
        request("get-mixed-retention", "get-log-events", dict(stream("mixed"), startFromHead=True))
        require(request("delete-retention", "delete-retention-policy", group_input))
        describe("describe-retention-removed")
        request("delete-retention-again", "delete-retention-policy", group_input)
        for label, rows in [
            ("mixed-old-valid-future-no-retention", [(-16 * DAY, "old-0"), (-15 * DAY, "old-1"), (-2 * HOUR, "valid-2"), (-HOUR, "valid-3"), (3 * HOUR, "future-4"), (4 * HOUR, "future-5")]),
            ("span-exactly-24h", [(-26 * HOUR, "span-exact-first"), (-2 * HOUR, "span-exact-last")]),
            ("span-24h-plus-1ms", [(-26 * HOUR - 1, "span-over-first"), (-2 * HOUR, "span-over-last")]),
            ("span-valid-23h-with-rejected-extremes", [(-16 * DAY, "span-old"), (-25 * HOUR, "span-valid-first"), (-2 * HOUR, "span-valid-last"), (3 * HOUR, "span-future")]),
        ]:
            put(label, "mixed" if label.startswith("mixed") else "span", rows)
        for label, unit, repetitions in [
            ("byte-ascii-same-character-count", "a", 524276),
            ("byte-utf8-exact-batch-budget", "é", 524275),
            ("byte-utf8-two-bytes-over-budget", "é", 524276),
        ]:
            message = unit * repetitions
            encoded = message.encode("utf-8")
            construction = {"repeat": unit, "count": repetitions, "utf8_bytes": len(encoded)}
            summary = dict(stream("bytes"), logEvents=[{"timestamp": anchor - 16 * DAY, "messageConstruction": construction}],
                           batch_bytes_including_26_per_event=len(encoded) + 26)
            request(label, "put-log-events", dict(stream("bytes"), logEvents=[{"timestamp": anchor - 16 * DAY, "message": message}]), summary=summary)

        visible = False
        metadata_visible = False
        for attempt, delay in enumerate([0, 2, 4, 8, 10, 10, 10, 10]):
            time.sleep(delay)
            got = require(request(f"visibility-events-{attempt}", "get-log-events", dict(stream("sequence"), startFromHead=True)))
            described = require(request(f"visibility-metadata-{attempt}", "describe-log-streams", dict(group_input, logStreamNamePrefix="owned-sequence")))
            messages = [event["message"] for event in got.get("events", [])]
            visible = sorted(messages) == sorted(list("ABCDEFABC"))
            metadata_visible = any(item.get("lastEventTimestamp") == anchor + base + 5000 and "lastIngestionTime" in item for item in described.get("logStreams", []))
            if visible and metadata_visible:
                break
        capture["visibility"] = {"attempts": attempt + 1, "events_visible": visible,
                                 "metadata_visible": metadata_visible, "maximum_sleep_seconds": 54}
        capture["pagination"] = {}
        for direction, head, token_key in [("forward", True, "nextForwardToken"), ("backward", False, "nextBackwardToken")]:
            token = None
            pages = []
            terminal = False
            for page in range(10):
                parameters = dict(stream("sequence"), startFromHead=head, limit=3,
                                  startTime=anchor + base, endTime=anchor + base + 5001)
                if token is not None:
                    parameters["nextToken"] = token
                output = require(request(f"get-{direction}-page-{page}", "get-log-events", parameters))
                pages.append(output.get("events", []))
                next_token = output.get(token_key)
                terminal = token is not None and next_token == token
                token = next_token
                if terminal:
                    break
            capture["pagination"][direction] = {"pages": len(pages), "event_counts": [len(page) for page in pages],
                                                 "terminal_token_equals_input": terminal,
                                                 "messages_in_page_order": [[event["message"] for event in page] for page in pages]}
        for label, start, end in [
            ("boundaries-inclusive-start-exclusive-end", base + 1000, base + 2000),
            ("boundaries-one-millisecond-at-event", base + 2000, base + 2001),
            ("boundaries-one-millisecond-before-event", base + 1999, base + 2000),
            ("boundaries-equal-start-end", base + 1000, base + 1000),
        ]:
            request(label, "get-log-events", dict(stream("sequence"), startFromHead=True, startTime=anchor + start, endTime=anchor + end))
        for name in ["mixed", "span", "bytes"]:
            request("get-final-" + name, "get-log-events", dict(stream(name), startFromHead=True))
            token = None
            retrieved = []
            terminal = False
            for page in range(6):
                parameters = dict(stream(name), startFromHead=True,
                                  startTime=anchor - 17 * DAY, endTime=anchor + 5 * HOUR)
                if token is not None:
                    parameters["nextToken"] = token
                output = require(request(f"get-explicit-range-{name}-{page}", "get-log-events", parameters))
                retrieved.extend(output.get("events", []))
                next_token = output.get("nextForwardToken")
                terminal = token is not None and next_token == token
                token = next_token
                if terminal:
                    break
            capture["pagination"][name + "_explicit_range"] = {
                "pages": page + 1, "terminal_token_equals_input": terminal,
                "messages_in_page_order": [event["message"] for event in retrieved],
                "reason": "Default-start single pages are samples, not completeness evidence; explicit range pagination checks old and mixed partial acceptance.",
            }
        request("describe-streams-final", "describe-log-streams", dict(group_input, logStreamNamePrefix="owned-"))
        request("delete-group", "delete-log-group", group_input)
        request("delete-group-again", "delete-log-group", group_input)
        request("get-after-group-deletion", "get-log-events", stream("sequence"))
    finally:
        if owned:
            deleted = request("cleanup-delete-group", "delete-log-group", group_input)
            absent = describe("cleanup-owned-prefix")
            streams_absent = request("cleanup-streams-missing-group", "describe-log-streams", dict(group_input, logStreamNamePrefix="owned-"))
            capture["cleanup"] = {
                "verified": deleted["code"] in ("Success", "ResourceNotFoundException")
                and absent["code"] == "Success" and absent["output"].get("logGroups") == []
                and "nextToken" not in absent["output"] and streams_absent["code"] == "ResourceNotFoundException",
                "verification_labels": ["cleanup-delete-group", "cleanup-owned-prefix", "cleanup-streams-missing-group"],
                "group_count": 1, "stream_count_created": 5,
            }
        save()
        print("requests: " + json.dumps(capture["request_counts"]), flush=True)
        print("cleanup: " + str(capture["cleanup"]["verified"]), flush=True)
        if owned and not capture["cleanup"]["verified"]:
            raise RuntimeError("Owned cleanup not verified")


if __name__ == "__main__":
    main()
