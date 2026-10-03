#!/usr/bin/env python3
"""Capture sustained native admission and partial batches using two owned tables."""
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
ITEM_BYTES = 350 * 1024
CADENCE_SECONDS = 12
WINDOW_SECONDS = 360


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def key(sk, pk="group"):
    return {"pk": {"S": pk}, "sk": {"S": sk}}


def large_item(sk):
    item = {**key(sk), "mark": {"S": "seed"}, "payload": {"S": ""}}
    used = sum(len(name.encode()) + len(value["S"].encode()) for name, value in item.items())
    item["payload"]["S"] = "x" * (ITEM_BYTES - used)
    return item


def update(table, sk, marker):
    return {"TableName": table, "Key": key(sk), "UpdateExpression": "SET #m = :v",
            "ExpressionAttributeNames": {"#m": marker}, "ExpressionAttributeValues": {":v": {"S": "applied"}},
            "ReturnConsumedCapacity": "INDEXES"}


def throttle_metrics(tables, start_time, environment):
    """One bounded metric snapshot; unpublished series are unknown, not zero."""
    queries = []
    for table in tables:
        dimensions = [{"Name": "TableName", "Value": table}]
        metrics = [(name, dimensions) for name in ("ReadThrottleEvents", "WriteThrottleEvents")]
        metrics += [("ThrottledRequests", dimensions + [{"Name": "Operation", "Value": operation}])
                    for operation in ("UpdateItem", "GetItem", "BatchWriteItem", "BatchGetItem", "ExecuteTransaction")]
        for name, metric_dimensions in metrics:
            queries.append({"Id": "m" + str(len(queries)), "MetricStat": {
                "Metric": {"Namespace": "AWS/DynamoDB", "MetricName": name, "Dimensions": metric_dimensions},
                "Period": 60, "Stat": "Sum"}, "ReturnData": True})
    parameters = {"MetricDataQueries": queries, "StartTime": start_time, "EndTime": timestamp(),
                  "ScanBy": "TimestampAscending", "MaxDatapoints": 1000}
    row = {"label": "cloudwatch-before-cleanup", "service": "cloudwatch", "operation": "get-metric-data",
           "input": parameters, "startedAt": timestamp(), "transport": "aws_cli.observe",
           "endpoint": "https://monitoring.us-east-1.amazonaws.com",
           "limitation": "One snapshot without publication polling; absent series are not zero; metric minutes aggregate requests and cannot establish individual request accounting."}
    try:
        row.update(observe("cloudwatch", "get-metric-data", parameters, environment, paginate=False))
    except Exception as error:
        row.update(code="ClientTransportError", transportErrorType=type(error).__name__)
    row["finishedAt"] = timestamp()
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/throughput_boundaries.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture")
    environment = {name: value for name, value in os.environ.items() if not name.startswith("AWS_ENDPOINT_URL")}
    environment.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
                       AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false", AWS_ENDPOINT_URL_DYNAMODB="https://" + ENDPOINT,
                       AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com",
                       AWS_ENDPOINT_URL_CLOUDWATCH="https://monitoring.us-east-1.amazonaws.com")
    os.environ.clear()
    os.environ.update(environment)
    prefix = "stackd-ddb-boundaries-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    fresh, batch = prefix + "-fresh", prefix + "-batch"
    origin = time.monotonic()
    lock = threading.Lock()
    owned = []
    active = {}
    capture = {
        "source": "Native AWS; aws_cli.observe for STS and signed_requests.observe_json for DynamoDB; no request retries",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "ownedTables": [fresh, batch],
        "calls": [], "phases": [], "cleanup": {}, "mutationChecks": [],
        "experiment": {
            "endpoints": {"sts": "https://sts.us-east-1.amazonaws.com", "dynamodb": "https://" + ENDPOINT},
            "cliMaxAttempts": 1, "signedRequestAttempts": 1, "largeItemBytes": ITEM_BYTES,
            "sizeDefinition": "UTF-8 attribute-name and string-value bytes; all seeded attributes are strings",
            "fresh": {"billingMode": "PROVISIONED", "readCapacityUnits": 1, "writeCapacityUnits": 1,
                      "cadenceSeconds": CADENCE_SECONDS, "windowSeconds": WINDOW_SECONDS, "seedAttempts": 1},
            "batch": {"setupBillingMode": "PAY_PER_REQUEST", "pressureReadCapacityUnits": 1, "pressureWriteCapacityUnits": 1,
                      "phaseOffsetsSeconds": [20, 170, 320], "readWaves": 4, "readConcurrency": 16,
                      "writeWaves": 3, "writeConcurrency": 8, "smallItemsPerBatch": 25,
                      "largeDeleteBatches": 12, "largeDeleteConcurrency": 12},
            "timing": "Monotonic invocation/completion offsets; sequence is invocation order, not completion order. No retries of failed/unprocessed data requests. Control polls and independent verification reads are labeled.",
            "verification": "Each mutation owns a unique attribute or key. Strong projected reads verify markers and batch siblings; unsuccessful reads leave explicit uncertainty.",
        },
        "limitations": [
            "This bounded capture does not reveal remaining credits, physical partitions, exact refill algorithms, or deterministic throttle ordinals.",
            "ACTIVE and reported throughput are control metadata, not proof of instantaneous internal convergence.",
            "The cadence table is fresh PROVISIONED; the batch table is seeded on-demand before switching to PROVISIONED.",
            "BatchGet pressure requests contain two 350-KiB items and two small/absent keys, below both 1-MiB-per-partition and 16-MiB response thresholds even before projection.",
            "Key-only projections still charge for full stored items. Client timing brackets requests, not exact server execution.",
            "Strong verification reads also consume capacity. Errors and unprocessed verification keys are not evidence of absence.",
        ],
    }

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, operation, parameters, service="dynamodb", expected=None, phase=None):
        start = time.monotonic()
        row = {"label": label, "operation": operation, "service": service, "input": parameters,
               "startedAt": timestamp(), "startedOffsetSeconds": round(start - origin, 6)}
        if phase is not None:
            row["phase"] = phase
        table = parameters.get("TableName")
        if table in active:
            row["secondsSinceObservedActive"] = round(start - active[table], 6)
        with lock:
            row["sequence"] = len(capture["calls"]) + 1
            capture["calls"].append(row)
        try:
            result: ProbeResult
            if service == "sts":
                row["transport"] = "aws_cli.observe"
                result = observe(service, operation, parameters, environment, paginate=False)
            else:
                row["transport"] = "signed_requests.observe_json"
                target = "DynamoDB_20120810." + "".join(part.capitalize() for part in operation.split("-"))
                result = observe_json(ENDPOINT, "dynamodb", target, parameters)
            row.update(result)
        except Exception as error:
            # Transport diagnostics can contain credentials; retain only the exception class.
            row.update(code="ClientTransportError", transportErrorType=type(error).__name__)
            raise RuntimeError(label + ": transport " + type(error).__name__) from None
        finally:
            row.update(finishedAt=timestamp(), durationSeconds=round(time.monotonic() - start, 6),
                       finishedOffsetSeconds=round(time.monotonic() - origin, 6))
        if expected is not None and row["code"] != expected:
            raise RuntimeError(label + ": " + row["code"])
        return row

    def settled(table, provisioned=False):
        for attempt in range(90):
            row = record("active-" + table.rsplit("-", 1)[-1] + "-" + str(attempt), "describe-table", {"TableName": table}, expected="Success")
            metadata = row["output"]["Table"]
            if metadata["TableStatus"] == "ACTIVE" and (not provisioned or metadata["ProvisionedThroughput"]["WriteCapacityUnits"] == 1):
                if metadata["TableArn"].split(":")[3:5] != [REGION, args.account]:
                    raise RuntimeError("unexpected native table region/account")
                active[table] = time.monotonic()
                return row
            time.sleep(2)
        raise RuntimeError("table failed to become ACTIVE: " + table)

    def read_item(label, table, sk, projection="pk, sk, mark", names=None):
        parameters = {"TableName": table, "Key": key(sk), "ConsistentRead": True,
                      "ProjectionExpression": projection, "ReturnConsumedCapacity": "INDEXES"}
        if names:
            parameters["ExpressionAttributeNames"] = names
        return record(label, "get-item", parameters)

    def parallel(requests, workers, phase):
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(record, label, operation, parameters, phase=phase) for label, operation, parameters in requests]
            return [future.result() for future in futures]

    def cadence(seed_success):
        start = time.monotonic()
        capture["cadenceStartedAt"] = timestamp()
        capture["cadenceStartedOffsetSeconds"] = round(start - origin, 6)
        if not seed_success:
            capture["cadenceSkipped"] = "The single fresh large seed did not succeed; small UpdateItem would not test a large image. Window retained for batch observations."
            time.sleep(WINDOW_SECONDS)
            return
        markers = []
        for ordinal in range(WINDOW_SECONDS // CADENCE_SECONDS + 1):
            target = start + ordinal * CADENCE_SECONDS
            time.sleep(max(0, target - time.monotonic()))
            marker = f"cadence{ordinal:03}"
            markers.append(marker)
            row = record(marker, "update-item", update(fresh, "large", marker), phase="sustained-cadence")
            row["scheduledOffsetSeconds"] = round(target - origin, 6)
            names = {"#m": marker}
            check = read_item(marker + "-strong-check", fresh, "large", "pk, sk, #m", names)
            capture["mutationChecks"].append({"mutationSequence": row["sequence"], "verificationSequence": check["sequence"],
                                               "marker": marker, "readSucceeded": check["code"] == "Success",
                                               "markerObserved": marker in check.get("output", {}).get("Item", {}) if check["code"] == "Success" else None})
        names = {f"#m{i}": marker for i, marker in enumerate(markers)}
        read_item("cadence-final-all-markers", fresh, "large", "pk, sk, " + ", ".join(names), names)
        capture["cadenceFinishedAt"] = timestamp()
        capture["cadenceDurationSeconds"] = round(time.monotonic() - start, 6)

    def batch_phase(stage):
        phase = "batch-stage-" + str(stage)
        details = {"name": phase, "startedAt": timestamp(), "startedOffsetSeconds": round(time.monotonic() - origin, 6)}
        capture["phases"].append(details)
        get_parameters = {"RequestItems": {batch: {"Keys": [key(sk) for sk in ("read0", "read1", "small", "absent")],
                          "ConsistentRead": True, "ProjectionExpression": "pk, sk, mark"}}, "ReturnConsumedCapacity": "INDEXES"}
        for wave in range(4):
            requests = [(f"{phase}-read-{wave}-{slot}", "batch-get-item", get_parameters) for slot in range(16)]
            requests += [(f"{phase}-scalar-read-{wave}", "get-item", {"TableName": batch, "Key": key("read0"),
                          "ConsistentRead": True, "ProjectionExpression": "pk, sk", "ReturnConsumedCapacity": "INDEXES"})]
            parallel(requests, 16, phase)
        pressure = [(f"{phase}-large-update-{slot}", "update-item", update(batch, "hot", f"stage{stage}slot{slot}")) for slot in range(16)]
        parallel(pressure, 16, phase)
        if stage == 0:
            requests = []
            for slot in range(12):
                marker = f"deleteSibling{slot:02}"
                parameters = {"RequestItems": {batch: [
                    {"DeleteRequest": {"Key": key(f"delete{slot:02}")}},
                    {"PutRequest": {"Item": {**key(marker, "small"), "mark": {"S": marker}}}},
                ]}, "ReturnConsumedCapacity": "INDEXES"}
                requests.append((f"{phase}-large-delete-{slot}", "batch-write-item", parameters))
            parallel(requests, 12, phase)
        for wave in range(3):
            requests = []
            for slot in range(8):
                marker = f"stage{stage}wave{wave}slot{slot}"
                items = [{"PutRequest": {"Item": {**key(f"{marker}item{item:02}", "small"), "mark": {"S": marker}}}} for item in range(25)]
                requests.append((marker, "batch-write-item", {"RequestItems": {batch: items}, "ReturnConsumedCapacity": "INDEXES"}))
            parallel(requests, 8, phase)
        requests = []
        for slot in range(8):
            marker = f"txstage{stage}slot{slot}"
            parameters = {"TransactStatements": [
                {"Statement": f'UPDATE "{batch}" SET "{marker}"=? WHERE "pk"=? AND "sk"=?',
                 "Parameters": [{"S": "applied"}, {"S": "group"}, {"S": "hot"}]},
                {"Statement": f'INSERT INTO "{batch}" VALUE {{\'pk\':?,\'sk\':?,\'mark\':?}}',
                 "Parameters": [{"S": "small"}, {"S": marker}, {"S": marker}]},
            ], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)}
            requests.append((marker, "execute-transaction", parameters))
        parallel(requests, 8, phase)
        details["finishedAt"] = timestamp()

    try:
        identity = record("caller-identity", "get-caller-identity", {}, service="sts", expected="Success")
        if identity["output"]["Account"] != args.account:
            raise RuntimeError("refusing mutation outside approved account")
        # Prepare the batch table first so the fresh cadence starts immediately after its ACTIVE observation.
        for table in (batch, fresh):
            parameters = {"TableName": table, "AttributeDefinitions": [{"AttributeName": name, "AttributeType": "S"} for name in ("pk", "sk")],
                          "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
                          "BillingMode": "PROVISIONED" if table == fresh else "PAY_PER_REQUEST"}
            if table == fresh:
                parameters["ProvisionedThroughput"] = {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}
            # Track the unique owned name before dispatch so an ambiguous create also receives cleanup.
            owned.append(table)
            record("create-" + table.rsplit("-", 1)[-1], "create-table", parameters, expected="Success")
            settled(table, table == fresh)
            if table == batch:
                for sk in ["read0", "read1", "hot"] + [f"delete{i:02}" for i in range(12)]:
                    record("seed-batch-" + sk, "put-item", {"TableName": batch, "Item": large_item(sk), "ReturnConsumedCapacity": "INDEXES"}, expected="Success")
                record("seed-batch-small", "put-item", {"TableName": batch, "Item": {**key("small"), "mark": {"S": "seed"}}, "ReturnConsumedCapacity": "INDEXES"}, expected="Success")
                record("batch-switch-provisioned", "update-table", {"TableName": batch, "BillingMode": "PROVISIONED",
                       "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}}, expected="Success")
                settled(batch, True)
        seed = record("fresh-single-large-seed", "put-item", {"TableName": fresh, "Item": large_item("large"), "ReturnConsumedCapacity": "INDEXES"})
        capture["freshSeedSequence"] = seed["sequence"]
        window_start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(cadence, seed["code"] == "Success")
            for stage, offset in enumerate((20, 170, 320)):
                time.sleep(max(0, window_start + offset - time.monotonic()))
                batch_phase(stage)
            future.result()
        for table in (fresh, batch):
            record("final-control-" + table.rsplit("-", 1)[-1], "describe-table", {"TableName": table}, expected="Success")
        record("batch-final-strong-small-siblings", "query", {"TableName": batch, "ConsistentRead": True,
               "KeyConditionExpression": "pk = :p", "ExpressionAttributeValues": {":p": {"S": "small"}},
               "ProjectionExpression": "pk, sk, mark", "ReturnConsumedCapacity": "INDEXES"})
        for slot in range(12):
            read_item(f"batch-final-strong-delete{slot:02}", batch, f"delete{slot:02}")
        markers = [f"stage{stage}slot{slot}" for stage in range(3) for slot in range(16)] + [f"txstage{stage}slot{slot}" for stage in range(3) for slot in range(8)]
        names = {f"#m{i}": marker for i, marker in enumerate(markers)}
        read_item("batch-final-strong-hot-markers", batch, "hot", "pk, sk, " + ", ".join(names), names)
        capture["cloudWatchObservations"] = [throttle_metrics([fresh, batch], capture["startedAt"], environment)]
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for table in owned:
            cleanup = {"verifiedAbsent": False}
            capture["cleanup"][table] = cleanup
            try:
                row = record("delete-owned-" + table.rsplit("-", 1)[-1], "delete-table", {"TableName": table})
                if row["code"] not in ("Success", "ResourceNotFoundException"):
                    raise RuntimeError("delete rejected: " + row["code"])
                for attempt in range(90):
                    row = record("verify-absent-" + table.rsplit("-", 1)[-1] + "-" + str(attempt), "describe-table", {"TableName": table})
                    if row["code"] == "ResourceNotFoundException":
                        cleanup.update(verifiedAbsent=True, verificationSequence=row["sequence"], verifiedAt=row["finishedAt"])
                        break
                    time.sleep(2)
            except Exception as error:
                cleanup["error"] = str(error)
        capture["leftoverTables"] = [table for table, result in capture["cleanup"].items() if not result["verifiedAbsent"]]
        capture["finishedAt"] = timestamp()
        save()
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"], "leftoverTables": capture["leftoverTables"]}))
    if capture["leftoverTables"]:
        raise RuntimeError("owned resources not verified absent: " + ", ".join(capture["leftoverTables"]))


if __name__ == "__main__":
    main()
