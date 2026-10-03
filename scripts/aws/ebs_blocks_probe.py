#!/usr/bin/env python3
"""Capture real synthetic EBS block bytes and lifecycle, with owned-only cleanup.

Requires boto3 and configured AWS CLI credentials. No volumes/instances are made.
SDK credentials, raw request signing, and block bytes remain in memory. Only
response headers, modeled responses/errors and compact payload recipes are saved.
Use --wait-token-expiry only when a potentially multi-day capture is intended.
Use --lineage for remaining lineage, pagination, failed-completion and timeout
gaps without replaying validation cases in blocks.json/blocks_supplement.json.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import call
from cloudtrail_events import CollectionError, collect_history


BLOCK_SIZE = 524288
CONFIG = Config(parameter_validation=False, retries={"max_attempts": 0}, connect_timeout=10, read_timeout=60)
DOC_ROOT = "https://docs.aws.amazon.com/ebs/latest/"
SOURCES = {name: DOC_ROOT + "userguide/" + name + ".html" for name in (
    "ebs-accessing-snapshot", "ebsapi-elements", "ebs-snapshots", "writesnapshots", "readsnapshots",
    "ebsapis-using-checksums", "ebs-direct-api-idempotency", "logging-ebs-apis-using-cloudtrail")}
SOURCES.update({name: DOC_ROOT + "APIReference/API_" + name + ".html" for name in (
    "StartSnapshot", "PutSnapshotBlock", "CompleteSnapshot", "ListSnapshotBlocks", "ListChangedBlocks", "ChangedBlock", "GetSnapshotBlock")})


def now():
    return dt.datetime.now(dt.timezone.utc)


def checksum(value):
    return base64.b64encode(hashlib.sha256(value).digest()).decode()


def payload(name):
    if name == "zero":
        return bytes(BLOCK_SIZE)
    seed = ("stackd-ebs-synthetic-" + name + "\n").encode()
    return (seed * (BLOCK_SIZE // len(seed) + 1))[:BLOCK_SIZE]


def recipe(name):
    return {"recipe": "zero" if name == "zero" else "repeat_utf8_truncate", "seed": None if name == "zero" else "stackd-ebs-synthetic-" + name + "\n", "length": BLOCK_SIZE, "sha256_base64": checksum(payload(name))}


def serial(value):
    if isinstance(value, dt.datetime):
        return value.isoformat()
    raise TypeError(type(value).__name__)


class Capture:
    def __init__(self, args):
        self.args = args
        self.session = boto3.Session(region_name=args.region)
        self.clients = {service: self.session.client(service, config=CONFIG) for service in ("ebs", "ec2", "cloudtrail")}
        self.owned = set()
        self.deleted = set()
        self.wire = {}
        for client in self.clients.values():
            client.meta.events.register("after-call.*.*", self.capture_wire)
        prefix = "stackd-ebs-blocks-" + uuid.uuid4().hex[:12]
        self.evidence = {"account": args.account, "region": args.region, "prefix": prefix, "captured_at": now().isoformat(),
            "sources": SOURCES, "payloads": {name: recipe(name) for name in ("a", "b", "c", "zero")},
            "capture_contract": "Native boto3 requests with client parameter validation and retries disabled. No request debug logs or credentials retained. Binary bodies verified in memory then represented by deterministic recipe and digest. Raw response bodies retained for non-streaming operations; streaming-operation errors retain native parsed fields. Status and response headers retained.",
            "calls": [], "snapshots": {}, "observations": [], "boundaries": [
                "CloudTrail data events (ListSnapshotBlocks, ListChangedBlocks, GetSnapshotBlock, PutSnapshotBlock) are documented but not captured: no trail or account selectors are changed.",
                "No cross-account principal is available in this probe; region scope is measured and account IAM scope is delegated to the encryption/IAM capture.",
                "Only a few sparse blocks per 1 GiB snapshot are uploaded; an actual multipage nonempty traversal is not forced by uploading 101 blocks."],
            "cleanup": {"deleted_ids": [], "remaining_owned": None}}

    def capture_wire(self, http_response, parsed, model, **kwargs):
        self.wire = {"http_status": http_response.status_code, "headers": dict(http_response.headers)}
        if not model.has_streaming_output:
            self.wire["raw_response_body"] = http_response.content.decode("utf-8")

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(self.evidence, indent=2, default=serial) + "\n")

    def observe(self, label, service, operation, parameters, *, expected_payload=None, client=None):
        self.wire = {}
        row = {"sequence": len(self.evidence["calls"]) + 1, "label": label, "service": service,
               "operation": operation, "input": {k: v for k, v in parameters.items() if k != "BlockData"}, "started_at": now().isoformat()}
        if "BlockData" in parameters:
            data = parameters["BlockData"]
            row["input"]["BlockData"] = {"length": len(data), "sha256_base64": checksum(data),
                "payload": next((name for name in self.evidence["payloads"] if data == payload(name)), None)}
        try:
            output = getattr(client or self.clients[service], operation)(**parameters)
            row["code"] = "Success"
            if operation == "start_snapshot":
                self.owned.add(output["SnapshotId"])
            if operation == "delete_snapshot":
                self.deleted.add(parameters["SnapshotId"])
            if "BlockData" in output:
                stream = output.pop("BlockData")
                try:
                    body = stream.read()
                finally:
                    stream.close()
                row["bytes_verification"] = {"length": len(body), "sha256_base64": checksum(body),
                    "native_checksum_matches": checksum(body) == output.get("Checksum"), "expected_payload": expected_payload,
                    "expected_bytes_match": None if expected_payload is None else body == payload(expected_payload)}
                if not row["bytes_verification"]["native_checksum_matches"] or (expected_payload is not None and not row["bytes_verification"]["expected_bytes_match"]):
                    raise RuntimeError("Native bytes failed checksum/recipe verification: " + label)
            output.pop("ResponseMetadata", None)
            row["output"] = output
        except ClientError as error:
            output = error.response.copy()
            output.pop("ResponseMetadata", None)
            row["code"] = output["Error"]["Code"]
            row["error"] = output
        row.update(self.wire)
        self.evidence["calls"].append(row)
        self.save()
        print(json.dumps({"label": label, "code": row["code"], "status": row.get("http_status")}), flush=True)
        return row

    def ebs(self, label, operation, **parameters):
        return self.observe(label, "ebs", operation, parameters)

    def start(self, label, **parameters):
        request = {"VolumeSize": 1, "Description": self.evidence["prefix"] + "/" + label,
                   "ClientToken": self.evidence["prefix"] + "-" + label,
                   "Tags": [{"Key": "stackd-probe", "Value": self.evidence["prefix"]}], **parameters}
        row = self.ebs(label, "start_snapshot", **request)
        if row["code"] != "Success":
            raise RuntimeError("Required snapshot creation failed: " + label)
        sid = row["output"]["SnapshotId"]
        self.evidence["snapshots"][label] = sid
        return sid

    def put(self, label, sid, index, name, **parameters):
        data = payload(name)
        return self.ebs(label, "put_snapshot_block", **{"SnapshotId": sid, "BlockIndex": index, "BlockData": data,
            "DataLength": len(data), "Checksum": checksum(data), "ChecksumAlgorithm": "SHA256", **parameters})

    def describe(self, label, sid):
        return self.observe(label, "ec2", "describe_snapshots", {"SnapshotIds": [sid]})

    def wait_terminal(self, label, sid, seconds=240):
        deadline = time.monotonic() + seconds
        attempt = 0
        while True:
            row = self.describe(label + "-" + str(attempt), sid)
            if row["code"] == "Success":
                state = row["output"]["Snapshots"][0]["State"]
                if state != "pending":
                    return state
            if time.monotonic() >= deadline:
                return "pending"
            attempt += 1
            time.sleep(10)

    def complete(self, label, sid, names=None, count=None, **parameters):
        request = {"SnapshotId": sid, "ChangedBlocksCount": len(names) if count is None else count, **parameters}
        if names is not None:
            aggregate = b"".join(hashlib.sha256(payload(name)).digest() for _, name in sorted(names.items()))
            request.update(Checksum=checksum(aggregate), ChecksumAlgorithm="SHA256", ChecksumAggregationMethod="LINEAR")
        return self.ebs(label, "complete_snapshot", **request)

    def wait_readable(self, label, sid, **parameters):
        deadline = time.monotonic() + 300
        attempt = 0
        while True:
            row = self.ebs(label + ("" if attempt == 0 else "-readiness-" + str(attempt)), "list_snapshot_blocks", SnapshotId=sid, **parameters)
            if row["code"] != "ResourceNotFoundException" or time.monotonic() >= deadline:
                break
            attempt += 1
            time.sleep(10)
        return row

    def read_blocks(self, label, sid, expected):
        row = self.wait_readable(label + "-list", sid)
        if row["code"] == "Success":
            for block in row["output"].get("Blocks", []):
                index = block["BlockIndex"]
                self.observe(label + "-get-" + str(index), "ebs", "get_snapshot_block",
                    {"SnapshotId": sid, **block}, expected_payload=expected.get(index))
        return row

    def pages(self, label, operation, **parameters):
        field = "Blocks" if operation == "list_snapshot_blocks" else "ChangedBlocks"
        rows = []
        while True:
            row = self.ebs(label + "-page-" + str(len(rows) + 1), operation, **parameters)
            if row["code"] != "Success":
                raise RuntimeError("Required page failed: " + row["label"])
            rows.append(row)
            token = row["output"].get("NextToken")
            if not token:
                break
            parameters["NextToken"] = token
        indices = [block["BlockIndex"] for row in rows for block in row["output"][field]]
        if indices != sorted(set(indices)):
            raise RuntimeError("Pagination repeated or reordered blocks: " + label)
        self.evidence.setdefault("traversals", {})[label] = {
            "pages": [row["label"] for row in rows],
            "page_sizes": [len(row["output"][field]) for row in rows],
            "block_indices": indices, "terminal_next_token": rows[-1]["output"].get("NextToken"),
        }
        self.save()
        return rows

    def cleanup(self):
        for sid in sorted(self.owned - self.deleted):
            self.observe("cleanup-delete-" + sid, "ec2", "delete_snapshot", {"SnapshotId": sid})
        remaining = []
        for sid in sorted(self.owned):
            row = self.describe("cleanup-confirm-" + sid, sid)
            if row["code"] != "InvalidSnapshot.NotFound":
                remaining.append(sid)
        self.evidence["cleanup"] = {"deleted_ids": sorted(self.deleted), "remaining_owned": remaining}
        self.save()
        if remaining:
            raise RuntimeError("Owned snapshots remain: " + ", ".join(remaining))


def capture_audit(capture):
    evidence = capture.evidence
    ids = {}
    for row in evidence["calls"]:
        headers = row.get("headers", {})
        request_id = headers.get("x-amzn-requestid") or headers.get("x-amzn-request-id")
        if request_id:
            ids[request_id] = row["label"]
    since = dt.datetime.fromisoformat(evidence["captured_at"]) - dt.timedelta(minutes=1)
    previous = evidence.get("cloudtrail", {})
    metadata = {row["event_id"]: row for row in previous.get("event_metadata", [])}
    previous = {**previous, "events": [
        {**{key: value for key, value in metadata.get(event.get("eventID"), {}).items() if key != "event_id"},
         "call_label": event.get("capture_case"),
         "event": {key: value for key, value in event.items() if key != "capture_case"}}
        for event in previous.get("events", [])]}
    markers = [evidence["prefix"], *evidence["snapshots"].values()]

    def owned_event(event):
        text = json.dumps(event)
        return any(marker in text for marker in markers)

    def redacted(value):
        if isinstance(value, dict):
            return {key: "<redacted>" if key.lower() in (
                "accesskeyid", "secretaccesskey", "sessiontoken", "securitytoken", "sourceipaddress") and child is not None
                else redacted(child) for key, child in value.items()}
        if isinstance(value, (list, tuple)):
            return [redacted(child) for child in value]
        return value

    audit = None
    try:
        audit = collect_history(
            lambda parameters: capture.clients["cloudtrail"].lookup_events(**parameters),
            ids, start_time=since, event_sources=("ebs.amazonaws.com", "ec2.amazonaws.com"),
            max_pages=20, related=owned_event, previous=previous)
    except CollectionError as error:
        audit = error.result
        raise
    finally:
        if audit is not None:
            audit = redacted(audit)
            matches = audit["events"]
            audit["event_metadata"] = [
                {"event_id": row["event"].get("eventID"),
                 **{key: value for key, value in row.items() if key != "event"}}
                for row in matches]
            audit["events"] = sorted(
                ({**row["event"], "capture_case": row["call_label"]} for row in matches),
                key=lambda event: (event["eventTime"], event["eventID"]))
            audit.update(queried_at=now().isoformat(), data_events_measured=False,
                redaction="Credential and source IP values redacted in place; native field presence and session context retained.")
            evidence["cloudtrail"] = audit
            capture.save()


def workflow(c):
    default = c.observe("read-encryption-default", "ec2", "get_ebs_encryption_by_default", {})
    encrypted = default["output"]["EbsEncryptionByDefault"]
    c.evidence["encryption_default"] = encrypted
    c.evidence["unencrypted_case"] = "Explicit Encrypted=false after reading disabled default" if not encrypted else "Unavailable without mutating account default; case uses existing default"
    start_options = {} if encrypted else {"Encrypted": False}
    timeout = c.start("timeout-no-writes", Timeout=10, **start_options)
    timeout_start = time.monotonic()
    root = c.start("root", Timeout=60, **start_options)
    root_request = next(row["input"] for row in c.evidence["calls"] if row["label"] == "root")
    c.ebs("start-idempotent-same-pending", "start_snapshot", **root_request)
    c.ebs("start-idempotent-conflict", "start_snapshot", **{**root_request, "Description": root_request["Description"] + "-changed"})
    c.describe("describe-pending-root", root)
    c.ebs("list-pending-root", "list_snapshot_blocks", SnapshotId=root)
    c.ebs("get-pending-root-invalid-token", "get_snapshot_block", SnapshotId=root, BlockIndex=0, BlockToken="invalid")
    c.ebs("changed-pending-root", "list_changed_blocks", SecondSnapshotId=root)
    c.ebs("start-pending-parent", "start_snapshot", VolumeSize=1, ParentSnapshotId=root, ClientToken=c.evidence["prefix"] + "-pending-parent")
    c.put("put-a", root, 0, "a", Progress=10)
    c.put("put-a-identical-retry", root, 0, "a")
    c.put("overwrite-a-with-b", root, 0, "b")
    c.put("put-sparse-a", root, 3, "a")
    c.put("put-explicit-zero", root, 7, "zero")
    c.put("put-last-block", root, 2047, "c", Progress=99)
    c.describe("describe-progress", root)
    validation = c.start("put-validation", **start_options)
    for label, overrides in (
        ("put-checksum-mismatch", {"Checksum": checksum(payload("c"))}),
        ("put-short-body", {"BlockData": b"short", "DataLength": 5, "Checksum": checksum(b"short")}),
        ("put-short-body-full-length-header", {"BlockData": b"short", "Checksum": checksum(b"short")}),
        ("put-length-header-mismatch", {"DataLength": 1}),
        ("put-negative-index", {"BlockIndex": -1}),
        ("put-past-volume", {"BlockIndex": 2048}),
        ("put-progress-negative", {"Progress": -1}),
        ("put-progress-over-100", {"Progress": 101}),
        ("put-algorithm-invalid", {"ChecksumAlgorithm": "SHA1"}),
        ("put-checksum-invalid-base64", {"Checksum": "not-base64!"})):
        c.put(label, validation, 9, "a", **overrides)
    c.complete("complete-root-distinct-count-and-binary-digest-aggregate", root, {0: "b", 3: "a", 7: "zero", 2047: "c"})
    c.put("put-after-sealing", root, 9, "a")
    c.complete("complete-immediate-retry", root, count=4)
    c.wait_terminal("root-terminal", root)
    c.complete("complete-completed-same-count", root, count=4)
    c.complete("complete-completed-different-count", root, count=1)
    c.ebs("start-idempotent-same-completed", "start_snapshot", **root_request)
    root_list = c.read_blocks("root", root, {0: "b", 3: "a", 7: "zero", 2047: "c"})
    tokens = {block["BlockIndex"]: block["BlockToken"] for block in root_list.get("output", {}).get("Blocks", [])}
    if not tokens:
        raise RuntimeError("Root did not yield readable blocks")
    old_token = tokens[0]
    expiry = root_list["output"]["ExpiryTime"]
    c.evidence["block_token_lifetime_seconds"] = (expiry - dt.datetime.fromisoformat(root_list["started_at"])).total_seconds()
    c.ebs("root-relist", "list_snapshot_blocks", SnapshotId=root)
    c.observe("old-token-after-relist", "ebs", "get_snapshot_block", {"SnapshotId": root, "BlockIndex": 0, "BlockToken": old_token}, expected_payload="b")
    for label, params in (
        ("list-page-size-1", {"MaxResults": 1}), ("list-page-size-99", {"MaxResults": 99}),
        ("list-page-size-100", {"MaxResults": 100}), ("list-page-size-10001", {"MaxResults": 10001}),
        ("list-start-gap", {"StartingBlockIndex": 1}), ("list-start-last", {"StartingBlockIndex": 2047}),
        ("list-start-past-volume", {"StartingBlockIndex": 2048}), ("list-start-negative", {"StartingBlockIndex": -1}),
        ("list-invalid-next-token", {"NextToken": "invalid"}),
        ("list-token-versus-start-precedence", {"NextToken": "invalid", "StartingBlockIndex": -1})):
        c.ebs(label, "list_snapshot_blocks", SnapshotId=root, **params)
    for label, index, token in (("get-token-wrong-index", 3, old_token), ("get-unwritten-block", 1, old_token),
                               ("get-malformed-token", 0, "invalid"), ("get-token-empty", 0, ""),
                               ("get-negative-index", -1, old_token), ("get-past-volume", 2048, old_token)):
        c.ebs(label, "get_snapshot_block", SnapshotId=root, BlockIndex=index, BlockToken=token)
    other_region = "us-west-2" if c.args.region != "us-west-2" else "us-east-1"
    other = c.session.client("ebs", region_name=other_region, config=CONFIG)
    other.meta.events.register("after-call.*.*", c.capture_wire)
    c.observe("region-isolation-list", "ebs", "list_snapshot_blocks", {"SnapshotId": root}, client=other)
    c.evidence["other_region"] = other_region
    child = c.start("child", ParentSnapshotId=root)
    c.put("child-clear-parent-block-with-zero", child, 0, "zero")
    c.put("child-rewrite-identical-parent-block", child, 3, "a")
    c.put("child-add-block", child, 5, "b")
    c.complete("complete-child-count-includes-identical-and-zero-writes", child, {0: "zero", 3: "a", 5: "b"})
    sibling = c.start("sibling", ParentSnapshotId=root)
    c.put("sibling-change-block", sibling, 3, "c")
    c.complete("complete-sibling", sibling, {3: "c"})
    empty = c.start("empty-independent", **start_options)
    c.complete("complete-empty", empty, count=0)
    bad_count = c.start("bad-count", **start_options)
    c.put("bad-count-put-one", bad_count, 0, "a")
    c.complete("complete-bad-count-accepted-or-rejected", bad_count, count=2)
    bad_checksum = c.start("bad-aggregate", **start_options)
    c.put("bad-aggregate-put-one", bad_checksum, 0, "a")
    c.complete("complete-wrong-aggregate", bad_checksum, count=1, Checksum=checksum(b"wrong"), ChecksumAlgorithm="SHA256", ChecksumAggregationMethod="LINEAR")
    for label, sid in (("child", child), ("sibling", sibling), ("empty", empty), ("bad-count", bad_count), ("bad-aggregate", bad_checksum)):
        c.wait_terminal(label + "-terminal", sid)
    c.read_blocks("child", child, {0: "zero", 3: "a", 5: "b", 7: "zero", 2047: "c"})
    c.read_blocks("sibling", sibling, {0: "b", 3: "c", 7: "zero", 2047: "c"})
    c.read_blocks("empty", empty, {})
    c.ebs("get-parent-token-on-child", "get_snapshot_block", SnapshotId=child, BlockIndex=0, BlockToken=old_token)
    for label, params in (
        ("changed-root-child", {"FirstSnapshotId": root, "SecondSnapshotId": child}),
        ("changed-child-root-reverse", {"FirstSnapshotId": child, "SecondSnapshotId": root}),
        ("changed-siblings", {"FirstSnapshotId": child, "SecondSnapshotId": sibling}),
        ("changed-self", {"FirstSnapshotId": root, "SecondSnapshotId": root}),
        ("changed-independent-lineage", {"FirstSnapshotId": root, "SecondSnapshotId": empty}),
        ("changed-first-omitted-child", {"SecondSnapshotId": child}),
        ("changed-first-omitted-root", {"SecondSnapshotId": root}),
        ("changed-page-size-too-small", {"FirstSnapshotId": root, "SecondSnapshotId": child, "MaxResults": 1}),
        ("changed-start-gap", {"FirstSnapshotId": root, "SecondSnapshotId": child, "StartingBlockIndex": 1}),
        ("changed-invalid-next-token", {"FirstSnapshotId": root, "SecondSnapshotId": child, "NextToken": "invalid"})):
        row = c.ebs(label, "list_changed_blocks", **params)
        if row["code"] == "Success" and label == "changed-root-child":
            expected = {root: {0: "b", 3: "a", 7: "zero", 2047: "c"}, child: {0: "zero", 3: "a", 5: "b", 7: "zero", 2047: "c"}}
            for block in row["output"].get("ChangedBlocks", []):
                for field, sid in (("FirstBlockToken", root), ("SecondBlockToken", child)):
                    if block.get(field):
                        c.observe(label + "-get-" + field + "-" + str(block["BlockIndex"]), "ebs", "get_snapshot_block",
                            {"SnapshotId": sid, "BlockIndex": block["BlockIndex"], "BlockToken": block[field]}, expected_payload=expected[sid].get(block["BlockIndex"]))
    c.observe("old-token-after-changed-list", "ebs", "get_snapshot_block", {"SnapshotId": root, "BlockIndex": 0, "BlockToken": old_token}, expected_payload="b")
    for sid, state in ((bad_count, "bad-count"), (bad_checksum, "bad-aggregate")):
        c.ebs("list-error-" + state, "list_snapshot_blocks", SnapshotId=sid)
        c.put("put-error-" + state, sid, 0, "a")
        c.complete("complete-error-" + state, sid, count=1)
        c.ebs("start-error-parent-" + state, "start_snapshot", VolumeSize=1, ParentSnapshotId=sid, ClientToken=c.evidence["prefix"] + "-error-" + state)
    for label, params in (("start-size-zero", {"VolumeSize": 0}), ("start-size-negative", {"VolumeSize": -1}),
        ("start-timeout-too-short", {"Timeout": 9}), ("start-timeout-too-long", {"Timeout": 4321}),
        ("start-token-whitespace", {"ClientToken": "has space"}), ("start-token-65", {"ClientToken": "x" * 65 + c.evidence["prefix"]}),
        ("start-description-too-long", {"Description": "x" * 256}),
        ("start-parent-missing", {"ParentSnapshotId": "snap-00000000000000000"}),
        ("start-parent-malformed", {"ParentSnapshotId": "not-a-snapshot"})):
        c.ebs(label, "start_snapshot", **{"VolumeSize": 1, "Description": c.evidence["prefix"] + "/" + label,
            "ClientToken": c.evidence["prefix"] + "-" + label, **params})
    for sid, label in (("snap-00000000000000000", "missing"), ("not-a-snapshot", "malformed")):
        c.ebs("list-" + label, "list_snapshot_blocks", SnapshotId=sid)
        c.ebs("get-" + label, "get_snapshot_block", SnapshotId=sid, BlockIndex=0, BlockToken=old_token)
        c.put("put-" + label, sid, 0, "a")
        c.complete("complete-" + label, sid, count=0)
    pending_delete = c.start("delete-pending", **start_options)
    c.observe("delete-pending-admission", "ec2", "delete_snapshot", {"SnapshotId": pending_delete})
    # The ten-minute inactivity interval is spent on the independent captures above.
    # If work finishes earlier, poll EC2 and delayed management audit rather than
    # hiding the interval in an unconditional ten-minute sleep.
    while time.monotonic() - timeout_start < 780:
        row = c.describe("timeout-state-" + str(round(time.monotonic() - timeout_start)), timeout)
        if row["code"] == "Success" and row["output"]["Snapshots"][0]["State"] != "pending":
            break
        capture_audit(c)
        time.sleep(30)
    c.ebs("list-timeout", "list_snapshot_blocks", SnapshotId=timeout)
    c.put("put-timeout", timeout, 0, "a")
    c.complete("complete-timeout", timeout, count=0)
    if c.args.wait_token_expiry:
        while now() < expiry + dt.timedelta(seconds=5):
            capture_audit(c)
            time.sleep(min(60, max(1, (expiry - now()).total_seconds() + 5)))
        c.ebs("get-token-after-expiry", "get_snapshot_block", SnapshotId=root, BlockIndex=0, BlockToken=old_token)
        c.read_blocks("fresh-token-after-expiry", root, {0: "b", 3: "a", 7: "zero", 2047: "c"})
    else:
        c.evidence["boundaries"].append("Token ExpiryTime measured and pre-expiry token reuse tested; natural expiry not awaited (enable --wait-token-expiry).")
    c.observe("delete-parent-retain-child", "ec2", "delete_snapshot", {"SnapshotId": root})
    c.read_blocks("child-after-parent-deletion", child, {0: "zero", 3: "a", 5: "b", 7: "zero", 2047: "c"})
    c.ebs("changed-siblings-after-parent-deletion", "list_changed_blocks", FirstSnapshotId=child, SecondSnapshotId=sibling)
    c.ebs("get-token-after-delete", "get_snapshot_block", SnapshotId=root, BlockIndex=0, BlockToken=old_token)
    c.ebs("start-idempotent-after-deletion", "start_snapshot", **root_request)
    c.observe("delete-parent-repeat", "ec2", "delete_snapshot", {"SnapshotId": root})


def supplement(c):
    default = c.observe("read-encryption-default", "ec2", "get_ebs_encryption_by_default", {})
    options = {} if default["output"]["EbsEncryptionByDefault"] else {"Encrypted": False}
    timer = c.start("timeout-reset-on-write", Timeout=10, **options)
    started = time.monotonic()
    c.put("timeout-initial-write", timer, 0, "a")
    ready = c.start("completion-control", **options)
    c.put("control-write", ready, 0, "a")
    c.complete("control-complete", ready, {0: "a"})
    aggregate_text = c.start("aggregate-base64-text", **options)
    c.put("text-aggregate-first", aggregate_text, 0, "a")
    c.put("text-aggregate-second", aggregate_text, 2, "b")
    c.complete("complete-aggregate-base64-text", aggregate_text, count=2,
        Checksum=checksum((checksum(payload("a")) + checksum(payload("b"))).encode()),
        ChecksumAlgorithm="SHA256", ChecksumAggregationMethod="LINEAR")
    attempts = c.start("count-upload-attempts", **options)
    c.put("attempt-one", attempts, 0, "a")
    c.put("attempt-identical-two", attempts, 0, "a")
    c.put("attempt-overwrite-three", attempts, 0, "b")
    c.complete("complete-count-three-one-index", attempts, count=3)
    zero = c.start("zero-omitted-from-count", **options)
    c.put("zero-count-write", zero, 0, "zero")
    c.complete("complete-count-zero-one-zero-block", zero, count=0)
    cases = (
        ("checksum-only", {"Checksum": checksum(b"")}),
        ("algorithm-only", {"ChecksumAlgorithm": "SHA256"}),
        ("aggregation-only", {"ChecksumAggregationMethod": "LINEAR"}),
        ("invalid-algorithm", {"Checksum": checksum(b""), "ChecksumAlgorithm": "SHA1", "ChecksumAggregationMethod": "LINEAR"}),
        ("invalid-aggregation", {"Checksum": checksum(b""), "ChecksumAlgorithm": "SHA256", "ChecksumAggregationMethod": "TREE"}),
        ("checksum-invalid-base64", {"Checksum": "invalid!", "ChecksumAlgorithm": "SHA256", "ChecksumAggregationMethod": "LINEAR"}),
        ("empty-valid-aggregate", {"Checksum": checksum(b""), "ChecksumAlgorithm": "SHA256", "ChecksumAggregationMethod": "LINEAR"}),
        ("negative-count", {"ChangedBlocksCount": -1}),
    )
    extras = []
    for label, parameters in cases:
        sid = c.start("complete-validation-" + label, **options)
        row = c.ebs("complete-" + label, "complete_snapshot", **{"SnapshotId": sid, "ChangedBlocksCount": 0, **parameters})
        extras.append((label, sid, row["code"]))
    for label, params in (
        ("missing-volume", {}),
        ("client-token-255", {"VolumeSize": 1, "ClientToken": c.evidence["prefix"] + "x" * (255 - len(c.evidence["prefix"]))}),
        ("client-token-256", {"VolumeSize": 1, "ClientToken": c.evidence["prefix"] + "x" * (256 - len(c.evidence["prefix"]))}),
        ("client-token-empty", {"VolumeSize": 1, "ClientToken": ""}),
        ("timeout-maximum", {"VolumeSize": 1, "Timeout": 4320}),
    ):
        c.ebs("start-" + label, "start_snapshot", **{"Description": c.evidence["prefix"] + "/" + label, **params})
    for label, sid in (("control", ready), ("aggregate-text", aggregate_text), ("upload-attempt-count", attempts), ("zero-count", zero)):
        c.wait_terminal(label + "-terminal", sid)
    c.read_blocks("control-readable", ready, {0: "a"})
    for label, sid, code in extras:
        if code == "Success":
            c.wait_terminal(label + "-terminal", sid)
    while time.monotonic() - started < 300:
        c.describe("timer-before-reset-" + str(round(time.monotonic() - started)), timer)
        capture_audit(c)
        time.sleep(30)
    c.put("timeout-reset-write", timer, 0, "b")
    reset_at = time.monotonic()
    c.evidence["timeout_reset_write_elapsed_seconds"] = reset_at - started
    while time.monotonic() - reset_at < 780:
        elapsed = time.monotonic() - started
        row = c.describe("timer-after-reset-" + str(round(elapsed)), timer)
        if row["code"] == "Success" and row["output"]["Snapshots"][0]["State"] != "pending":
            c.evidence["timeout_reset_terminal_elapsed_seconds"] = elapsed
            break
        capture_audit(c)
        time.sleep(30)
    c.ebs("list-write-timeout", "list_snapshot_blocks", SnapshotId=timer)
    c.put("put-write-timeout", timer, 0, "a")
    c.complete("complete-write-timeout", timer, count=1)


def lineage(c):
    c.evidence["reused_evidence"] = {
        "testdata/aws/ebs/blocks.json": "Existing write, overwrite, checksum, completed admission, bounds, malformed-token and regional cases are not replayed. Fresh uploads below are lineage/pagination prerequisites; all earlier snapshots were deleted.",
        "testdata/aws/ebs/blocks_supplement.json": "Existing completion parameter validation, aggregate-text failure and client-token bounds are not replayed. Earlier bad-count and timeout runs were stopped before terminal observations.",
    }
    c.evidence["boundaries"] = [
        "Natural expiration of block tokens and pagination tokens is not awaited; prior fixture captures block-token ExpiryTime and pre-expiry reuse only.",
        "Only a no-write snapshot configured with Timeout=10 is measured; write-reset inactivity and precise service transition times are not measured.",
        "CloudTrail data events are not captured; no trail/account selectors or Lake resources are created or changed.",
        "Deleted-parent direct reads are sampled immediately; later EBS deletion visibility and token invalidation are not awaited.",
        "This is one-account, one-region synthetic direct-snapshot evidence, not EC2 guest/volume or cross-account execution evidence.",
    ]
    c.evidence["documented"] = [
        {"source": SOURCES["StartSnapshot"], "contract": "Timeout is in minutes, minimum 10; snapshot is cancelled after no writes or inactivity following the last write."},
        {"source": SOURCES["ListChangedBlocks"], "contract": "Both snapshot IDs are required. MaxResults is 100..10000; NextToken overrides StartingBlockIndex."},
        {"source": SOURCES["CompleteSnapshot"], "contract": "ChangedBlocksCount is the number of written blocks; completion seals against further writes."},
        {"source": SOURCES["ChangedBlock"], "contract": "FirstBlockToken is absent if the first snapshot has no changed block at that index."},
        {"source": SOURCES["ebs-snapshots"], "contract": "Deleting a snapshot removes data referenced exclusively by it; data referenced by other snapshots is preserved."},
        {"source": SOURCES["readsnapshots"], "contract": "Changed-block pagination can include empty pages while scanning allocated candidate blocks; continue using NextToken until no token remains."},
    ]
    default = c.observe("lineage-encryption-default", "ec2", "get_ebs_encryption_by_default", {})
    options = {} if default["output"]["EbsEncryptionByDefault"] else {"Encrypted": False}
    timer = c.start("lineage-timeout-no-writes", Timeout=10, **options)
    timer_started = time.monotonic()
    bad = c.start("lineage-bad-count", Timeout=60, **options)
    c.put("lineage-bad-count-put-one", bad, 0, "a")
    c.complete("lineage-bad-count-complete-two", bad, count=2)
    bad_started = time.monotonic()
    c.describe("lineage-bad-count-initial", bad)
    root = c.start("lineage-root", **options)
    root_payloads = {0: "a", 1000: "b", 2047: "c"}
    for index, name in root_payloads.items():
        c.put("lineage-root-put-" + str(index), root, index, name)
    c.complete("lineage-root-complete", root, root_payloads)
    c.wait_terminal("lineage-root-terminal", root)
    root_list = c.read_blocks("lineage-root-ready", root, root_payloads)
    if root_list["code"] != "Success":
        raise RuntimeError("Parent did not reach EBS read readiness")
    root_tokens = {block["BlockIndex"]: block["BlockToken"] for block in root_list["output"]["Blocks"]}
    child = c.start("lineage-child", ParentSnapshotId=root)
    child_writes = {0: "zero", **{index: "b" for index in range(1, 101)}, 1000: "b"}
    for index, name in child_writes.items():
        row = c.put("lineage-child-put-" + str(index), child, index, name)
        if row["code"] != "Success":
            raise RuntimeError("Required child write failed: " + row["label"])
    c.complete("lineage-child-complete", child, child_writes)
    sibling = c.start("lineage-sibling", ParentSnapshotId=root)
    c.put("lineage-sibling-put-1000", sibling, 1000, "c")
    c.complete("lineage-sibling-complete", sibling, {1000: "c"})
    for label, sid in (("child", child), ("sibling", sibling)):
        c.wait_terminal("lineage-" + label + "-terminal", sid)
        if c.wait_readable("lineage-" + label + "-readiness", sid, MaxResults=100)["code"] != "Success":
            raise RuntimeError("Descendant did not reach EBS read readiness: " + label)
    child_pages = c.pages("lineage-child-blocks", "list_snapshot_blocks", SnapshotId=child, MaxResults=100)
    child_tokens = {block["BlockIndex"]: block["BlockToken"] for row in child_pages for block in row["output"]["Blocks"]}
    for index, name in ((0, "zero"), (1, "b"), (100, "b"), (1000, "b"), (2047, "c")):
        c.observe("lineage-child-get-" + str(index), "ebs", "get_snapshot_block",
            {"SnapshotId": child, "BlockIndex": index, "BlockToken": child_tokens[index]}, expected_payload=name)
    changed_pages = c.pages("lineage-root-child-changed", "list_changed_blocks",
        FirstSnapshotId=root, SecondSnapshotId=child, MaxResults=100)
    for row in changed_pages:
        for block in row["output"]["ChangedBlocks"]:
            if block["BlockIndex"] not in (0, 1, 100, 1000):
                continue
            for field, sid, expected in (("FirstBlockToken", root, root_payloads), ("SecondBlockToken", child, child_writes)):
                if block.get(field):
                    c.observe("lineage-changed-get-" + field + "-" + str(block["BlockIndex"]),
                        "ebs", "get_snapshot_block", {"SnapshotId": sid, "BlockIndex": block["BlockIndex"], "BlockToken": block[field]},
                        expected_payload=expected[block["BlockIndex"]])
    for label, first, second in (("reverse", child, root), ("siblings", child, sibling), ("self", child, child)):
        c.pages("lineage-changed-" + label, "list_changed_blocks", FirstSnapshotId=first, SecondSnapshotId=second, MaxResults=100)
    c.ebs("lineage-changed-first-omitted", "list_changed_blocks", SecondSnapshotId=child)
    c.ebs("lineage-changed-start-gap", "list_changed_blocks", FirstSnapshotId=root, SecondSnapshotId=child, StartingBlockIndex=101)
    c.ebs("lineage-get-parent-token-on-child", "get_snapshot_block", SnapshotId=child, BlockIndex=0, BlockToken=root_tokens[0])
    snapshot_page_token = child_pages[0]["output"].get("NextToken")
    changed_page_token = changed_pages[0]["output"].get("NextToken")
    if not snapshot_page_token or not changed_page_token:
        raise RuntimeError("Required nonempty multipage traversal did not produce a token")
    c.ebs("lineage-snapshot-page-token-overrides-start", "list_snapshot_blocks",
        SnapshotId=child, NextToken=snapshot_page_token, StartingBlockIndex=2047, MaxResults=100)
    c.ebs("lineage-snapshot-page-token-on-parent", "list_snapshot_blocks",
        SnapshotId=root, NextToken=snapshot_page_token, MaxResults=100)
    c.ebs("lineage-changed-page-token-overrides-start", "list_changed_blocks",
        FirstSnapshotId=root, SecondSnapshotId=child, NextToken=changed_page_token, StartingBlockIndex=2047, MaxResults=100)
    c.ebs("lineage-changed-page-token-wrong-pair", "list_changed_blocks",
        FirstSnapshotId=child, SecondSnapshotId=sibling, NextToken=changed_page_token, MaxResults=100)
    c.ebs("lineage-snapshot-page-token-as-changed-page", "list_changed_blocks",
        FirstSnapshotId=root, SecondSnapshotId=child, NextToken=snapshot_page_token, MaxResults=100)
    c.ebs("lineage-changed-page-token-as-snapshot-page", "list_snapshot_blocks",
        SnapshotId=child, NextToken=changed_page_token, MaxResults=100)
    c.ebs("lineage-page-token-as-block-token", "get_snapshot_block",
        SnapshotId=child, BlockIndex=100, BlockToken=snapshot_page_token)
    c.ebs("lineage-block-token-as-page-token", "list_snapshot_blocks",
        SnapshotId=child, NextToken=child_tokens[0], MaxResults=100)
    c.observe("lineage-delete-parent", "ec2", "delete_snapshot", {"SnapshotId": root})
    c.describe("lineage-confirm-parent-deleted", root)
    after = c.pages("lineage-child-after-parent-deletion", "list_snapshot_blocks", SnapshotId=child, MaxResults=100)
    for row in after:
        for block in row["output"]["Blocks"]:
            if block["BlockIndex"] in (0, 1000, 2047):
                c.observe("lineage-child-after-delete-get-" + str(block["BlockIndex"]), "ebs", "get_snapshot_block",
                    {"SnapshotId": child, **block}, expected_payload={0: "zero", 1000: "b", 2047: "c"}[block["BlockIndex"]])
    c.observe("lineage-inherited-old-token-after-parent-delete", "ebs", "get_snapshot_block",
        {"SnapshotId": child, "BlockIndex": 2047, "BlockToken": child_tokens[2047]}, expected_payload="c")
    c.pages("lineage-siblings-after-parent-deletion", "list_changed_blocks", FirstSnapshotId=child, SecondSnapshotId=sibling, MaxResults=100)
    c.observe("lineage-get-deleted-parent-old-token", "ebs", "get_snapshot_block",
        {"SnapshotId": root, "BlockIndex": 0, "BlockToken": root_tokens[0]}, expected_payload="a")
    pending = {"bad-count": (bad, bad_started), "timeout": (timer, timer_started)}
    deadline = timer_started + 1800
    while pending:
        for label, (sid, started) in list(pending.items()):
            elapsed = time.monotonic() - started
            row = c.describe("lineage-" + label + "-state-" + str(round(elapsed)), sid)
            state = row.get("output", {}).get("Snapshots", [{}])[0].get("State")
            if state and state != "pending":
                c.evidence.setdefault("terminal_observations", {})[label] = {
                    "elapsed_seconds": elapsed, "state": state, "call": row["label"],
                    "timing": "Client elapsed time to this observation; not an exact service transition timestamp."}
                del pending[label]
                c.ebs("lineage-" + label + "-post-terminal-list", "list_snapshot_blocks", SnapshotId=sid)
                c.put("lineage-" + label + "-post-terminal-put", sid, 1, "b")
                c.complete("lineage-" + label + "-post-terminal-complete", sid, count=1 if label == "bad-count" else 0)
                c.ebs("lineage-" + label + "-post-terminal-parent", "start_snapshot", VolumeSize=1,
                    ParentSnapshotId=sid, ClientToken=c.evidence["prefix"] + "-post-" + label,
                    Description=c.evidence["prefix"] + "/post-" + label,
                    Tags=[{"Key": "stackd-probe", "Value": c.evidence["prefix"]}])
                c.describe("lineage-" + label + "-after-admission", sid)
        if pending:
            if time.monotonic() >= deadline:
                c.evidence["boundaries"].append("Terminal state unobserved after thirty minutes for: " + ", ".join(pending))
                raise RuntimeError("Terminal observation deadline reached")
            time.sleep(20)
    c.evidence["capture_status"] = "Native lineage, paging, byte retention and terminal/post-error observations complete."
    c.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/blocks.json"))
    parser.add_argument("--wait-token-expiry", action="store_true")
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--supplement", action="store_true", help="Capture checksum/count boundaries and write-reset inactivity timeout")
    parser.add_argument("--lineage", action="store_true", help="Capture only remaining lineage, pagination, completion-error and ten-minute timeout gaps")
    args = parser.parse_args()
    identity = call("sts", "get-caller-identity", env=dict(os.environ, AWS_REGION=args.region, AWS_DEFAULT_REGION=args.region))
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside authorized account")
    capture = Capture(args)
    if args.audit_only:
        capture.evidence = json.loads(args.output.read_text())
        if capture.evidence["account"] != args.account or capture.evidence["region"] != args.region:
            raise RuntimeError("Capture scope mismatch")
        capture_audit(capture)
        print(json.dumps({"management_events": len(capture.evidence["cloudtrail"]["events"])}))
        return
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    try:
        (lineage if args.lineage else supplement if args.supplement else workflow)(capture)
    except BaseException as error:
        capture.evidence["capture_failure"] = {"type": type(error).__name__, "message": str(error)}
        capture.save()
        raise
    finally:
        capture.cleanup()
        capture_audit(capture)
    print(json.dumps({"calls": len(capture.evidence["calls"]), "remaining_owned": capture.evidence["cleanup"]["remaining_owned"], "management_events": len(capture.evidence["cloudtrail"]["events"])}))


if __name__ == "__main__":
    main()
