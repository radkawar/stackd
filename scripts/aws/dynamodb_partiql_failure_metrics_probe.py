#!/usr/bin/env python3
"""Capture native PartiQL failure charges in isolated UTC-minute metric windows."""
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


def statement(table, kind, key, size, failure=True):
    item = sized_item(key, size)
    if kind == "insert":
        result = {"Statement": f"INSERT INTO \"{table}\" VALUE {{'pk':?,'payload':?}}",
                  "Parameters": [item["pk"], item["payload"]]}
    elif kind == "update":
        result = {"Statement": f'UPDATE "{table}" SET payload=? WHERE pk=? AND attribute_not_exists(pk)',
                  "Parameters": [item["payload"], item["pk"]]}
    else:
        result = {"Statement": f'SELECT * FROM "{table}" WHERE pk=?', "Parameters": [item["pk"]], "ConsistentRead": True}
    if failure:
        result["ReturnValuesOnConditionCheckFailure"] = "ALL_OLD"
    return result


def matrix(table):
    targets = [("small", SMALL, LARGE), ("large", LARGE, SMALL)]
    for kind, outcome in [("insert", "DuplicateItemException"), ("update", "ConditionalCheckFailedException")]:
        for key, old, new in targets:
            yield (f"scalar-failed-{kind}-{key}", "execute-statement",
                   {**statement(table, kind, key, new), "ReturnConsumedCapacity": "INDEXES"}, outcome,
                   [{"kind": kind, "key": key, "oldBytes": old, "attemptedNewBytes": new}])
    for kind in ["insert", "update"]:
        yield (f"batch-all-failed-{kind}", "batch-execute-statement",
               {"Statements": [statement(table, kind, key, new) for key, old, new in targets], "ReturnConsumedCapacity": "INDEXES"}, "Success",
               [{"kind": kind, "key": key, "oldBytes": old, "attemptedNewBytes": new} for key, old, new in targets])
    for key, old, new in targets:
        yield (f"transaction-duplicate-insert-{key}", "execute-transaction",
               {"TransactStatements": [statement(table, "insert", key, new)], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)},
               "TransactionCanceledException", [{"kind": "insert", "key": key, "oldBytes": old, "attemptedNewBytes": new}])


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
                                       "batchErrorCodes": [response.get("Error", {}).get("Code") for response in row.get("output", {}).get("Responses", [])],
                                       "cancellationReasons": row.get("error", {}).get("CancellationReasons")} for row in rows],
                         "metrics": metrics}
    controls = {}
    for name, metric in [("successful-write-control", "write"), ("successful-read-control", "read")]:
        value = windows.get(name, {}).get("metrics", {}).get(metric, {}).get("sum")
        controls[metric] = {"window": name, "sum": value, "positiveObserved": value is not None and value > 0}
    return {"windows": windows, "positiveControls": controls,
            "missingValues": "null means absent datapoint, never zero; numeric zero is an actual published Sum",
            "counterInterpretation": "DuplicateItem and ConditionalCheckFailed wire outcomes are distinct; only the isolated published conditionFailures Sum establishes counter behavior.",
            "publicationPollCount": len(capture["metricPolls"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/partiql_failure_metrics.json"))
    parser.add_argument("--publication-wait-seconds", type=int, default=900)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite an existing native capture")
    if args.publication_wait_seconds < 180:
        parser.error("publication wait must be at least 180 seconds")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    native_env = {"AWS_REGION": REGION, "AWS_DEFAULT_REGION": REGION, "AWS_MAX_ATTEMPTS": "1", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true"}
    env.update(native_env)
    table = "stackd-ddb-pqlfail-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    dimensions = [{"Name": "TableName", "Value": table}]
    series = {key: {"MetricName": metric, "Dimensions": dimensions} for key, metric in [
        ("write", "ConsumedWriteCapacityUnits"), ("read", "ConsumedReadCapacityUnits"), ("conditionFailures", "ConditionalCheckFailedRequests")]}
    capture = {"source": "native AWS DynamoDB and CloudWatch through scripts/aws/aws_cli.py observe",
               "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table,
               "nativeEndpointEnvironment": {**native_env, "endpointOverridesRemoved": True,
                                             "expectedServiceEndpoints": {"sts": f"https://sts.{REGION}.amazonaws.com", "dynamodb": f"https://dynamodb.{REGION}.amazonaws.com", "cloudwatch": f"https://monitoring.{REGION}.amazonaws.com"}},
               "documentation": ["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html",
                                 "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html",
                                 "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html",
                                 "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteTransaction.html"],
               "calls": [], "windows": {}, "metricSeries": series, "metricPolls": [],
               "experiment": {"billingMode": "PAY_PER_REQUEST", "periodSeconds": 60, "cliMaxAttempts": 1,
                              "smallLogicalBytes": SMALL, "largeLogicalBytes": LARGE,
                              "sizeDistinction": "Small=1 write block/1 read block; large=9 write blocks/3 read blocks. Opposed changes distinguish old, max(old,new), and attempted-new sizing.",
                              "publicationWaitSeconds": args.publication_wait_seconds,
                              "dataOperations": "All data calls recorded; one request per isolated window, no unrecorded retries or readiness reads. Positive write control creates the two distinct pre-existing items; positive read control verifies their exact contents before failures."},
               "limitations": ["One isolated regional on-demand table, without indexes or throttling; one execution per distinguishing case.",
                               "Client timestamps bracket requests, not server execution; cross-minute calls cannot establish isolated attribution.",
                               "Metric publication can lag or revise. Missing points are unknown, not zero. SampleCount is not a request count.",
                               "ALL_OLD and all native error fields are retained verbatim; requested ALL_OLD does not guarantee an image on DuplicateItem.",
                               "Canceled transactions contain one duplicate INSERT each; these measurements do not establish charges for prepared successful companion actions."],
               "cleanup": {"callSequences": [], "verifiedAbsent": False}}
    cleanup_required = False

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

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
            row.update(code="TransportError", error={"type": type(error).__name__, "message": str(error)})
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
        return record(name, "dynamodb", operation, parameters, expected, window=name)

    try:
        if any(key.startswith("AWS_ENDPOINT_URL") for key in env) or env["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] != "true":
            raise RuntimeError("Native endpoint isolation was not established")
        identity = record("caller-identity", "sts", "get-caller-identity", {})["output"]
        capture["identity"] = identity
        if identity["Account"] != args.account or identity["Arn"] != f"arn:aws:iam::{args.account}:user/Delegated":
            raise RuntimeError("Refusing mutation for unexpected caller " + identity["Arn"])
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
        seeds = [("small", SMALL), ("large", LARGE)]
        written = run_window("successful-write-control", "batch-execute-statement", {
            "Statements": [statement(table, "insert", key, size, False) for key, size in seeds], "ReturnConsumedCapacity": "INDEXES"})
        if len(written["output"].get("Responses", [])) != 2 or any("Error" in response for response in written["output"]["Responses"]):
            raise RuntimeError("Positive write control did not create both items")
        read = run_window("successful-read-control", "batch-execute-statement", {
            "Statements": [statement(table, "select", key, size, False) for key, size in seeds], "ReturnConsumedCapacity": "INDEXES"})
        actual = {response.get("Item", {}).get("pk", {}).get("S"): response.get("Item") for response in read["output"].get("Responses", [])}
        if actual != {key: sized_item(key, size) for key, size in seeds}:
            raise RuntimeError("Positive read control did not verify exact pre-existing item sizes")
        for name, operation, parameters, expected, actions in matrix(table):
            row = run_window(name, operation, parameters, expected, actions)
            if operation == "batch-execute-statement":
                wanted = "DuplicateItem" if name.endswith("insert") else "ConditionalCheckFailed"
                codes = [response.get("Error", {}).get("Code") for response in row["output"].get("Responses", [])]
                if codes != [wanted, wanted]:
                    raise RuntimeError("Batch did not fail both distinct items: " + str(codes))
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
            failed_bins_present = all(value is not None for name, values in signature.items() if not name.startswith("successful-") for value in values.values())
            poll["consecutiveEqualSnapshots"] = stable + 1
            save()
            if controls and failed_bins_present and stable >= 2 and time.time() >= end + 180:
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
