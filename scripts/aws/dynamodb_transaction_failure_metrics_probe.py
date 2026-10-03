#!/usr/bin/env python3
"""Capture native failed-write size charges in isolated UTC-minute metric windows."""
import argparse
import datetime
import json
import os
import pathlib
import secrets
import time

from aws_cli import observe

REGION = "us-east-1"
SMALL = 512
LARGE = 9216


def timestamp(value=None):
    return datetime.datetime.fromtimestamp(time.time() if value is None else value, datetime.timezone.utc).isoformat()


def epoch(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def sized_item(key, size):
    """Exact logical ASCII bytes, excluding storage overhead."""
    return {"pk": {"S": key}, "payload": {"S": "x" * (size - len(key) - len("pkpayload"))}}


def matrix(table, extended=False):
    def put(key, size, condition=True):
        value = {"TableName": table, "Item": sized_item(key, size)}
        if condition:
            value.update(ConditionExpression="attribute_not_exists(pk)", ReturnValuesOnConditionCheckFailure="ALL_OLD")
        return value

    def update(key, size, condition=True):
        value = {"TableName": table, "Key": {"pk": {"S": key}}, "UpdateExpression": "SET payload = :p",
                 "ExpressionAttributeValues": {":p": sized_item(key, size)["payload"]}}
        if condition:
            value.update(ConditionExpression="attribute_not_exists(pk)", ReturnValuesOnConditionCheckFailure="ALL_OLD")
        return value

    def transaction(actions):
        return {"TransactItems": actions, "ClientRequestToken": secrets.token_hex(16), "ReturnConsumedCapacity": "TOTAL"}

    cases = []
    if extended:
        targets = [
            ("update-grow", "Update", update("small", LARGE, False), SMALL, LARGE),
            ("update-shrink", "Update", update("large", SMALL, False), LARGE, SMALL),
            ("delete", "Delete", {"TableName": table, "Key": {"pk": {"S": "large"}}}, LARGE, 0),
        ]
        for name, kind, prepared, old, new in targets:
            failed = {**prepared, "ConditionExpression": "attribute_not_exists(pk)", "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}
            action = {"kind": kind, "oldBytes": old, "attemptedNewBytes": new, "conditionFails": True}
            cases.append(("transaction-failed-" + name, "transact-write-items", transaction([{kind: failed}]), [action]))
            failure = {"Put": put("failure", SMALL)}
            failure_size = {"kind": "Put", "oldBytes": SMALL, "attemptedNewBytes": SMALL, "conditionFails": True}
            prepared_size = {"kind": kind, "oldBytes": old, "attemptedNewBytes": new, "conditionFails": False}
            for position in ["first", "last"]:
                actions = [failure, {kind: prepared}] if position == "first" else [{kind: prepared}, failure]
                sizes = [failure_size, prepared_size] if position == "first" else [prepared_size, failure_size]
                cases.append(("transaction-prepared-" + name + "-failure-" + position, "transact-write-items", transaction(actions), sizes))
        return cases
    for operation, build in [("put-item", put), ("update-item", update)]:
        for direction, key, old, new in [("grow", "small", SMALL, LARGE), ("shrink", "large", LARGE, SMALL)]:
            cases.append((operation + "-" + direction, operation, {**build(key, new), "ReturnConsumedCapacity": "TOTAL"},
                          [{"kind": operation, "oldBytes": old, "attemptedNewBytes": new, "conditionFails": True}]))
    for name, actions, sizes in [
        ("transaction-put-grow", [{"Put": put("small", LARGE)}], [(SMALL, LARGE, True)]),
        ("transaction-put-shrink", [{"Put": put("large", SMALL)}], [(LARGE, SMALL, True)]),
        ("transaction-failed-small-and-prepared-large", [{"Put": put("small", SMALL)}, {"Put": put("prepared", LARGE, False)}], [(SMALL, SMALL, True), (0, LARGE, False)]),
        ("transaction-two-failures-opposed", [{"Put": put("small", LARGE)}, {"Put": put("large", SMALL)}], [(SMALL, LARGE, True), (LARGE, SMALL, True)]),
    ]:
        cases.append((name, "transact-write-items", transaction(actions),
                      [{"kind": "Put", "oldBytes": old, "attemptedNewBytes": new, "conditionFails": failed} for old, new, failed in sizes]))
    for key, old in [("large", LARGE), ("missing", 0)]:
        check = {"TableName": table, "Key": {"pk": {"S": key}}, "ConditionExpression": "attribute_exists(absent)", "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}
        cases.append(("transaction-false-check-" + key, "transact-write-items", transaction([{"ConditionCheck": check}]),
                      [{"kind": "ConditionCheck", "oldBytes": old, "conditionFails": True}]))
    return cases


def derive(capture):
    calls = {row["sequence"]: row for row in capture["calls"]}
    latest = capture["metricPolls"][-1] if capture["metricPolls"] else None
    windows = {}
    for name, window in capture["windows"].items():
        start = epoch(window["start"])
        rows = [calls[sequence] for sequence in window["callSequences"]]
        metrics = {}
        for key in capture["metricSeries"]:
            observations = []
            for poll in capture["metricPolls"]:
                call = calls[poll["callSequences"][key]]
                points = [point for point in call.get("output", {}).get("Datapoints", []) if epoch(point["Timestamp"]) == start]
                if points:
                    observations.append({"callSequence": call["sequence"], "observedAt": call["finishedAt"], "datapoints": points})
            last = calls[latest["callSequences"][key]] if latest else None
            points = [point for point in last.get("output", {}).get("Datapoints", []) if epoch(point["Timestamp"]) == start] if last else []
            metrics[key] = {"latestCallSequence": last["sequence"] if last else None, "datapoints": points,
                            "sum": sum(point["Sum"] for point in points) if points else None,
                            "firstObservedAt": observations[0]["observedAt"] if observations else None}
        windows[name] = {"callSequences": window["callSequences"],
                         "callsEntirelyInsideWindow": bool(rows) and all(start <= epoch(row["startedAt"]) <= epoch(row["finishedAt"]) < start + 60 for row in rows),
                         "outcomes": [{"callSequence": row["sequence"], "code": row.get("code"),
                                       "returnedCapacity": row.get("output", {}).get("ConsumedCapacity"),
                                       "cancellationReasons": row.get("error", {}).get("CancellationReasons")} for row in rows],
                         "metrics": metrics}
    controls = {}
    for name, metric in [("successful-write-control", "write"), ("successful-read-control", "read")]:
        value = windows.get(name, {}).get("metrics", {}).get(metric, {}).get("sum")
        controls[metric] = {"window": name, "sum": value, "positiveObserved": value is not None and value > 0}
    return {"windows": windows, "positiveControls": controls,
            "missingValues": "null means absent datapoint, never zero; numeric zero is an actual published Sum",
            "publicationPollCount": len(capture["metricPolls"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/transaction_failure_metrics.json"))
    parser.add_argument("--publication-wait-seconds", type=int, default=900)
    parser.add_argument("--extend", action="store_true", help="Append transactional Update/Delete and prepared-action evidence using a new owned table")
    args = parser.parse_args()
    if args.output.exists() and not args.extend:
        parser.error("refusing to overwrite an existing native capture; --extend appends an independent run")
    if args.extend and not args.output.exists():
        parser.error("--extend requires an existing completed capture")
    original = json.loads(args.output.read_text()) if args.extend else None
    if original is not None and (not original.get("finishedAt") or not original.get("cleanup", {}).get("verifiedAbsent") or any(not run.get("cleanup", {}).get("verifiedAbsent") for run in original.get("extensions", []))):
        parser.error("existing capture must have finished and verified every owned table absent")
    if original is not None and (original["account"] != args.account or original["region"] != REGION):
        parser.error("existing capture account/region does not match --account")
    if args.publication_wait_seconds < 180:
        parser.error("publication wait must be at least 180 seconds")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    table = "stackd-ddb-txfail-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    dimensions = [{"Name": "TableName", "Value": table}]
    series = {key: {"MetricName": metric, "Dimensions": dimensions} for key, metric in [
        ("write", "ConsumedWriteCapacityUnits"), ("read", "ConsumedReadCapacityUnits"), ("conditionFailures", "ConditionalCheckFailedRequests")]}
    capture = {"source": "native AWS DynamoDB and CloudWatch through scripts/aws/aws_cli.py observe",
               "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table,
               "documentation": ["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html",
                                 "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html",
                                 "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html"],
               "calls": [], "windows": {}, "metricSeries": series, "metricPolls": [],
               "experiment": {"billingMode": "PAY_PER_REQUEST", "periodSeconds": 60, "cliMaxAttempts": 1,
                              "matrix": "transaction-update-delete-extension" if args.extend else "put-update-conditioncheck-size-distinction",
                              "smallLogicalBytes": SMALL, "largeLogicalBytes": LARGE,
                              "sizeDistinction": "Small=1 write block/1 read block; large=9 write blocks/3 read blocks. Opposed changes distinguish old, max(old,new), and attempted-new sizing.",
                              "publicationWaitSeconds": args.publication_wait_seconds,
                              "dataOperations": "All data calls recorded; one operation per failed window, no unrecorded retries or readiness reads."},
               "limitations": ["One isolated regional on-demand table, without indexes or throttling; one execution per distinguishing case.",
                               "Prepared non-failing charges may be preparation/order-dependent; this capture is not a universal scheduling guarantee.",
                               "Client timestamps bracket requests, not server execution; cross-minute calls cannot establish isolated attribution.",
                               "Metric publication can lag or revise. Missing points are unknown, not zero. SampleCount is not a request count.",
                               "CancellationReasons and ALL_OLD images are retained verbatim; failed calls need not return ConsumedCapacity."],
               "cleanup": {"callSequences": [], "verifiedAbsent": False}}
    if original is not None:
        original.setdefault("extensions", []).append(capture)
    cleanup_required = False

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(original if original is not None else capture, indent=2) + "\n")

    def record(label, service, operation, parameters, expected="Success", window=None, cleanup=False):
        row = {"sequence": len(capture["calls"]) + 1, "label": label, "service": service, "operation": operation,
               "startedAt": timestamp(), "input": parameters}
        capture["calls"].append(row)
        if window:
            capture["windows"][window]["callSequences"].append(row["sequence"])
        if cleanup:
            capture["cleanup"]["callSequences"].append(row["sequence"])
        try:
            row.update(observe(service, operation, parameters, env, paginate=False))
        except Exception as error:
            row["transportError"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            row["finishedAt"] = timestamp()
            save()
        print(label + ": " + row["code"], flush=True)
        if expected is not None and row["code"] != expected:
            raise RuntimeError(label + ": expected " + expected + ", got " + row["code"])
        if window and epoch(row["finishedAt"]) >= epoch(capture["windows"][window]["end"]):
            raise RuntimeError("Request crossed its isolated UTC-minute window: " + label)
        return row

    def run_window(name, operation, parameters, expected="Success", actions=None):
        start = (int(time.time()) // 60 + 1) * 60
        capture["windows"][name] = {"start": timestamp(start), "end": timestamp(start + 60), "callSequences": [], "actions": actions or []}
        save()
        time.sleep(max(0, start + 5 - time.time()))
        record(name, "dynamodb", operation, parameters, expected, window=name)

    try:
        identity = record("caller-identity", "sts", "get-caller-identity", {})["output"]
        capture["identity"] = identity
        if identity["Account"] != args.account:
            raise RuntimeError("Refusing writes in unexpected account " + identity["Account"])
        cleanup_required = True
        record("create-owned-table", "dynamodb", "create-table", {
            "TableName": table, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}]})
        for attempt in range(90):
            description = record("table-ready-" + str(attempt), "dynamodb", "describe-table", {"TableName": table})["output"]["Table"]
            if description["TableStatus"] == "ACTIVE":
                break
            time.sleep(2)
        else:
            raise RuntimeError("Owned table did not become active")
        seeds = [("small", SMALL), ("large", LARGE)] + ([("failure", SMALL)] if args.extend else [])
        run_window("successful-write-control", "batch-write-item", {
            "RequestItems": {table: [{"PutRequest": {"Item": sized_item(key, size)}} for key, size in seeds]},
            "ReturnConsumedCapacity": "TOTAL"})
        if capture["calls"][-1]["output"].get("UnprocessedItems"):
            raise RuntimeError("Seed control returned unprocessed items; refusing ambiguous failures")
        run_window("successful-read-control", "transact-get-items", {
            "TransactItems": [{"Get": {"TableName": table, "Key": {"pk": {"S": key}}}} for key in ["small", "large"]], "ReturnConsumedCapacity": "TOTAL"})
        for name, operation, parameters, actions in matrix(table, args.extend):
            expected = "TransactionCanceledException" if operation == "transact-write-items" else "ConditionalCheckFailedException"
            run_window(name, operation, parameters, expected, actions)
        start = min(epoch(window["start"]) for window in capture["windows"].values())
        end = max(epoch(window["end"]) for window in capture["windows"].values())
        time.sleep(max(0, end + 5 - time.time()))
        capture["publicationStartedAt"] = timestamp()
        deadline = time.monotonic() + args.publication_wait_seconds
        previous_signature = None
        stable = 0
        attempt = 0
        while True:
            poll = {"startedAt": timestamp(), "callSequences": {}}
            for key, metric in series.items():
                row = record("publication-" + str(attempt) + "-" + key, "cloudwatch", "get-metric-statistics", {
                    "Namespace": "AWS/DynamoDB", **metric, "StartTime": timestamp(start), "EndTime": timestamp(end),
                    "Period": 60, "Statistics": ["Sum", "SampleCount", "Minimum", "Maximum", "Average"]})
                poll["callSequences"][key] = row["sequence"]
            poll["finishedAt"] = timestamp()
            capture["metricPolls"].append(poll)
            capture["findings"] = derive(capture)
            signature = {name: {key: metric["sum"] for key, metric in window["metrics"].items()} for name, window in capture["findings"]["windows"].items()}
            stable = stable + 1 if signature == previous_signature else 0
            previous_signature = signature
            controls = all(value["positiveObserved"] for value in capture["findings"]["positiveControls"].values())
            charged = all(any(values[key] is not None and values[key] > 0 for key in ["write", "read"]) for values in signature.values())
            failed_bins_present = all(values[key] is not None for name, values in signature.items() if not name.startswith("successful-") for key in ["write", "read", "conditionFailures"])
            save()
            if controls and charged and failed_bins_present and stable >= 2 and time.time() >= end + 180:
                capture["publicationStopReason"] = "Positive controls and all failed-window read/write/condition-counter bins published, with three equal snapshots at least 60 seconds apart. Unpublished control-series points remain unknown."
                break
            if time.monotonic() >= deadline:
                capture["publicationStopReason"] = "Bounded publication deadline reached; absent datapoints remain unknown, not zero."
                break
            time.sleep(min(60, max(0, deadline - time.monotonic())))
            attempt += 1
        capture["workflowComplete"] = True
    except BaseException as error:
        capture["workflowError"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        try:
            if cleanup_required:
                deleted = record("delete-owned-table", "dynamodb", "delete-table", {"TableName": table}, expected=None, cleanup=True)
                if deleted["code"] not in ("Success", "ResourceNotFoundException"):
                    raise RuntimeError("Owned table deletion failed: " + deleted["code"])
                for attempt in range(90):
                    absent = record("verify-owned-table-absent-" + str(attempt), "dynamodb", "describe-table", {"TableName": table}, expected=None, cleanup=True)
                    if absent["code"] == "ResourceNotFoundException":
                        capture["cleanup"]["verifiedAbsent"] = True
                        break
                    if absent["code"] != "Success":
                        raise RuntimeError("Cannot verify owned table absence: " + absent["code"])
                    time.sleep(2)
                else:
                    raise RuntimeError("Owned table still exists after cleanup polling")
        except BaseException as error:
            capture["cleanup"]["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            capture["finishedAt"] = timestamp()
            capture["findings"] = derive(capture)
            save()
    print(json.dumps({"output": str(args.output), "cleanup": capture["cleanup"], "findings": capture["findings"]}))


if __name__ == "__main__":
    main()
