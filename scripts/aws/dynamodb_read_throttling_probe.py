#!/usr/bin/env python3
"""Capture bounded native low-RCU read admission, partial results, and recovery."""
import argparse
import concurrent.futures
import datetime
import json
import os
import pathlib
import secrets
import threading
import time

from aws_cli import ProbeResult, observe
from signed_requests import observe_json

REGION = "us-east-1"
ENDPOINT = "dynamodb.us-east-1.amazonaws.com"


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sized_item(sk, size):
    values = {"pk": "group", "sk": sk, "payload": ""}
    used = sum(len(key) + len(value) for key, value in values.items())
    values["payload"] = "x" * (size - used)
    return {key: {"S": value} for key, value in values.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/read_throttling.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
               AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false",
               AWS_ENDPOINT_URL_DYNAMODB="https://" + ENDPOINT,
               AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    # signed_post's credential loader inherits these settings and caches only in memory.
    os.environ.update(env)
    table = "stackd-ddb-readthrottle-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    capture = {
        "source": "native AWS DynamoDB; aws_cli.observe control calls and signed_requests.signed_post data calls",
        "startedAt": timestamp(), "account": args.account, "region": REGION,
        "ownedTables": [table], "calls": [], "phases": [],
        "cleanup": {"verifiedAbsent": False},
        "experiment": {
            "cliMaxAttempts": 1, "signedPostAttempts": 1,
            "endpoints": {"dynamodb": "https://" + ENDPOINT, "sts": "https://sts.us-east-1.amazonaws.com"},
            "setupBillingMode": "PAY_PER_REQUEST", "pressureReadCapacityUnits": 1,
            "pressureWriteCapacityUnits": 1, "largeItemBytes": 393216,
            "sizeDefinition": "Sum of ASCII attribute names and string values, excluding storage overhead.",
            "projection": "pk, sk only; full stored item still determines read capacity",
            "burst": {"waves": 5, "workers": 16, "requestsPerWave": 21,
                      "schedule": "Each wave submits 8 strong and 8 eventual GetItem plus Query, Scan, BatchGetItem, TransactGetItems, ExecuteStatement; waits for all before next wave."},
            "batchDesign": "Two 393216-byte items and one 4096-byte item, all same partition key; total below 1 MiB partition response threshold before projection.",
            "recoveryIdleSeconds": [3, 8],
        },
        "limitations": [
            "Native one-table observation; throttle ordinals and short-idle recovery are not an exact token-bucket specification.",
            "AWS documents up to 300 seconds of unused capacity, best-effort burst/background use, and adaptive partition capacity.",
            "A provisioned 1-RCU table can have stored burst credit; a large successful read alone does not establish admission against insufficient remaining credit.",
            "Client timestamps bracket single HTTPS calls, not AWS execution. Sequence is dispatch order; completion order may differ.",
            "Raw errors retain native JSON fields including __type; code is normalized from __type, with no invented reason or capacity fields.",
            "No retry of read errors or unprocessed keys; query/scan limits do not request further pages.",
        ],
        "documentation": ["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/burst-adaptive-capacity.html"],
    }
    lock = threading.Lock()
    origin = time.monotonic()

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, operation, parameters, service="dynamodb", raw=False, expected=None, phase=None):
        row = {"label": label, "service": service, "operation": operation, "input": parameters,
               "transport": "signed HTTPS" if raw else "AWS CLI observe", "phase": phase}
        with lock:
            row.update(sequence=len(capture["calls"]) + 1, startedAt=timestamp(),
                       startedOffsetSeconds=round(time.monotonic() - origin, 6))
            capture["calls"].append(row)
        start = time.monotonic()
        try:
            result: ProbeResult
            if raw:
                action = "".join(word.title() for word in operation.split("-"))
                result = observe_json(ENDPOINT, "dynamodb", "DynamoDB_20120810." + action, parameters)
            else:
                result = observe(service, operation, parameters, env, paginate=False)
            row.update(result)
        except Exception as error:
            row.update(code="ClientError", error={"type": type(error).__name__,
                       "message": "Client transport/configuration failure; raw diagnostics discarded"})
            raise
        finally:
            row.update(finishedAt=timestamp(), durationSeconds=round(time.monotonic() - start, 6))
        if expected is not None and row["code"] != expected:
            raise RuntimeError(label + ": " + row["code"])
        return row

    def control(label, operation, parameters, expected="Success", service="dynamodb"):
        try:
            return record(label, operation, parameters, expected=expected, service=service)
        finally:
            save()

    def settled(label, provisioned=False):
        for attempt in range(90):
            row = control(label + "-" + str(attempt), "describe-table", {"TableName": table})
            value = row["output"]["Table"]
            throughput = value.get("ProvisionedThroughput", {})
            if value["TableStatus"] == "ACTIVE" and (not provisioned or (
                    throughput.get("ReadCapacityUnits") == 1 and throughput.get("WriteCapacityUnits") == 1
                    and value.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED") == "PROVISIONED")):
                return row
            time.sleep(2)
        raise RuntimeError("table failed to settle: " + table)

    def key(sk):
        return {"pk": {"S": "group"}, "sk": {"S": sk}}

    def get(sk, strong):
        return {"TableName": table, "Key": key(sk), "ConsistentRead": strong,
                "ProjectionExpression": "pk, sk", "ReturnConsumedCapacity": "TOTAL"}

    created = False
    try:
        caller = control("caller-identity", "get-caller-identity", {}, service="sts")
        if caller["output"]["Account"] != args.account:
            raise RuntimeError("refusing native probe in unapproved account")
        control("create-on-demand-owned-table", "create-table", {
            "TableName": table, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": name, "AttributeType": "S"} for name in ("pk", "sk")],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        })
        created = True
        settled("settled-on-demand")
        for sk, size in (("large0", 393216), ("large1", 393216), ("small", 4096)):
            record("seed-" + sk, "put-item", {"TableName": table, "Item": sized_item(sk, size),
                   "ReturnConsumedCapacity": "TOTAL"}, raw=True, expected="Success", phase="seed-on-demand")
            save()
        record("on-demand-strong-large-cost", "get-item", get("large0", True), raw=True, expected="Success")
        record("on-demand-eventual-large-cost", "get-item", get("large0", False), raw=True, expected="Success")
        control("switch-to-one-rcu", "update-table", {
            "TableName": table, "BillingMode": "PROVISIONED",
            "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        })
        capture["settledProvisioningSequence"] = settled("settled-one-rcu", provisioned=True)["sequence"]
        record("one-rcu-first-large-strong", "get-item", get("large0", True), raw=True, phase="before-burst")
        record("one-rcu-first-large-eventual", "get-item", get("large0", False), raw=True, phase="before-burst")
        common = {"TableName": table, "ConsistentRead": True, "ProjectionExpression": "pk, sk", "ReturnConsumedCapacity": "TOTAL"}
        representatives = [
            ("query", {**common, "KeyConditionExpression": "pk = :pk", "ExpressionAttributeValues": {":pk": {"S": "group"}}, "Limit": 2}),
            ("scan", {**common, "Limit": 2}),
            ("batch-get-item", {"RequestItems": {table: {"Keys": [key(sk) for sk in ("large0", "large1", "small")], "ConsistentRead": True, "ProjectionExpression": "pk, sk"}}, "ReturnConsumedCapacity": "TOTAL"}),
            ("transact-get-items", {"TransactItems": [{"Get": {"TableName": table, "Key": key(sk), "ProjectionExpression": "pk, sk"}} for sk in ("large0", "large1")], "ReturnConsumedCapacity": "TOTAL"}),
            ("execute-statement", {"Statement": 'SELECT pk, sk FROM "' + table + '" WHERE pk=? AND sk=?', "Parameters": [{"S": "group"}, {"S": "large0"}], "ConsistentRead": True, "ReturnConsumedCapacity": "TOTAL"}),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            for wave in range(5):
                phase = {"name": "pressure-wave-" + str(wave), "startedAt": timestamp(), "workers": 16, "requests": 21}
                capture["phases"].append(phase)
                jobs = []
                # Interleave API shapes with strong/eventual point reads rather than only sampling after pressure.
                schedule = [("get-item", get("large0", ordinal % 2 == 0)) for ordinal in range(16)]
                for offset, representative in enumerate(representatives):
                    schedule.insert(offset * 4 + 2, representative)
                for ordinal, (operation, parameters) in enumerate(schedule):
                    jobs.append(executor.submit(record, phase["name"] + "-" + str(ordinal) + "-" + operation,
                                                operation, parameters, raw=True, phase=phase["name"]))
                for job in jobs:
                    job.result()
                phase["finishedAt"] = timestamp()
                save()
        control("post-pressure-settled-control", "describe-table", {"TableName": table})
        for seconds in (3, 8):
            idle = {"name": "idle-" + str(seconds), "seconds": seconds, "startedAt": timestamp()}
            capture["phases"].append(idle)
            time.sleep(seconds)
            idle["finishedAt"] = timestamp()
            # Large-first prevents small-read consumption from explaining large-read rejection.
            for sk, strong in (("large0", True), ("small", True), ("large0", False)):
                record(idle["name"] + "-" + sk + ("-strong" if strong else "-eventual"),
                       "get-item", get(sk, strong), raw=True, phase="recovery")
            save()
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if created:
            deletion = control("delete-owned-table", "delete-table", {"TableName": table}, expected=None)
            if deletion["code"] not in ("Success", "ResourceNotFoundException"):
                capture["cleanup"]["failure"] = "delete failed: " + table + ": " + deletion["code"]
            else:
                for attempt in range(90):
                    absent = control("verify-owned-table-absent-" + str(attempt), "describe-table", {"TableName": table}, expected=None)
                    if absent["code"] == "ResourceNotFoundException":
                        capture["cleanup"] = {"verifiedAbsent": True, "table": table, "sequence": absent["sequence"], "verifiedAt": absent["finishedAt"]}
                        break
                    time.sleep(2)
                else:
                    capture["cleanup"]["failure"] = "absence not verified: " + table
        capture["finishedAt"] = timestamp()
        save()
        if created and not capture["cleanup"]["verifiedAbsent"]:
            raise RuntimeError(capture["cleanup"].get("failure", "cleanup failed: " + table))
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"]}))


if __name__ == "__main__":
    main()
