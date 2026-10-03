#!/usr/bin/env python3
"""Capture native configured on-demand controls and bounded admission evidence."""
import argparse
import concurrent.futures
import datetime
import json
import os
import pathlib
import secrets
import threading
import time

from aws_cli import observe
from signed_requests import observe_json

REGION = "us-east-1"
ENDPOINT = "dynamodb.us-east-1.amazonaws.com"
ITEM_BYTES = 350 * 1024


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def item(pk, indexed=False):
    value = {"pk": {"S": pk}, "mark": {"S": "seed"}, "note": {"S": "seed"}, "data": {"S": ""}}
    if indexed:
        value["x"] = {"S": "hot"}
    used = sum(len(k.encode()) + len(v["S"].encode()) for k, v in value.items())
    value["data"]["S"] = "x" * (ITEM_BYTES - used)
    return value


def composite_pressure(record, base, indexed, reader):
    """Exercise composite operations alongside scalar checks; never infer errors."""
    effects = []
    for wave in range(4):
        requests = []
        pending = {}
        for table, kind in ((base, "table"), (indexed, "index")):
            for operation in ("update-item", "batch-write-item", "transact-write-items", "execute-transaction", "batch-execute-statement"):
                marker = f"composite{kind}{wave}{operation.replace('-', '')}"
                key = {"pk": {"S": "large"}}
                update = {"TableName": table, "Key": key, "UpdateExpression": "SET #m = :v",
                          "ExpressionAttributeNames": {"#m": marker},
                          "ExpressionAttributeValues": {":v": {"S": marker}}}
                statement = {"Statement": f'UPDATE "{table}" SET "{marker}"=? WHERE "pk"=?',
                             "Parameters": [{"S": marker}, {"S": "large"}]}
                checks = [{"table": table, "key": key, "attribute": marker, "expected": {"S": marker}}]
                if operation == "update-item":
                    parameters = {**update, "ReturnConsumedCapacity": "INDEXES"}
                elif operation == "batch-write-item":
                    value = item(marker, table == indexed)
                    parameters = {"RequestItems": {table: [{"PutRequest": {"Item": value}}]},
                                  "ReturnConsumedCapacity": "INDEXES"}
                    checks = [{"table": table, "key": {"pk": {"S": marker}}, "attribute": "mark", "expected": {"S": "seed"}}]
                elif operation == "transact-write-items":
                    sibling = marker + "sibling"
                    parameters = {"TransactItems": [{"Update": update}, {"Put": {"TableName": table, "Item": {"pk": {"S": sibling}, "mark": {"S": marker}}}}],
                                  "ClientRequestToken": secrets.token_hex(16), "ReturnConsumedCapacity": "INDEXES"}
                    checks.append({"table": table, "key": {"pk": {"S": sibling}}, "attribute": "mark", "expected": {"S": marker}})
                elif operation == "execute-transaction":
                    sibling = marker + "sibling"
                    parameters = {"TransactStatements": [statement, {
                        "Statement": f'INSERT INTO "{table}" VALUE {{\'pk\':?,\'mark\':?}}',
                        "Parameters": [{"S": sibling}, {"S": marker}],
                    }], "ClientRequestToken": secrets.token_hex(16), "ReturnConsumedCapacity": "INDEXES"}
                    checks.append({"table": table, "key": {"pk": {"S": sibling}}, "attribute": "mark", "expected": {"S": marker}})
                else:
                    parameters = {"Statements": [statement], "ReturnConsumedCapacity": "INDEXES"}
                label = marker
                requests.append((label, operation, parameters))
                pending[label] = checks
        requests.append((f"composite-read-{wave}", "batch-execute-statement", {
            "Statements": [{"Statement": f'SELECT pk FROM "{reader}" WHERE pk=?',
                            "Parameters": [{"S": "large"}], "ConsistentRead": True}],
            "ReturnConsumedCapacity": "INDEXES",
        }))
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            rows = list(pool.map(lambda request: record(*request), requests))
        for row in rows:
            for check in pending.get(row["label"], []):
                effects.append({**check, "mutationSequence": row["sequence"], "operation": row["operation"]})
        time.sleep(3)
    return effects


def verify_composite_effects(record, effects):
    results = []
    for effect in effects:
        row = record("verify-composite-" + str(effect["mutationSequence"]) + "-" + effect["key"]["pk"]["S"],
                     "get-item", {"TableName": effect["table"], "Key": effect["key"], "ConsistentRead": True,
                                  "ProjectionExpression": "pk, #m", "ExpressionAttributeNames": {"#m": effect["attribute"]}})
        results.append({**effect, "verificationSequence": row["sequence"], "readSucceeded": row["code"] == "Success",
                        "observed": row.get("output", {}).get("Item", {}).get(effect["attribute"]) if row["code"] == "Success" else None})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/on_demand_limits.json"))
    parser.add_argument("--pressure-waves", type=int, default=12)
    parser.add_argument("--wave-interval", type=float, default=10)
    parser.add_argument("--metric-wait", type=float, default=360, help="minimum experiment age for final metric snapshot")
    parser.add_argument("--post-cleanup-metric-wait", type=float, default=300, help="publication wait after all owned tables are gone")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture")
    if not 1 <= args.pressure_waves <= 12 or not 0 <= args.wave_interval <= 30 or not 0 <= args.metric_wait <= 600:
        parser.error("bounded experiment arguments exceeded")
    if not 0 <= args.post_cleanup_metric_wait <= 600:
        parser.error("post-cleanup metric wait exceeds bounded experiment")
    environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_ENDPOINT_URL")}
    environment.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
                       AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false", AWS_ENDPOINT_URL_DYNAMODB="https://" + ENDPOINT,
                       AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com",
                       AWS_ENDPOINT_URL_CLOUDWATCH="https://monitoring.us-east-1.amazonaws.com")
    os.environ.clear()
    os.environ.update(environment)
    prefix = "stackd-ddb-ondemand-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    base, reader, indexed = [prefix + "-" + suffix for suffix in ("base", "read", "gsi")]
    owned = []
    origin = time.monotonic()
    lock = threading.Lock()
    capture = {
        "source": "Native AWS signed_requests.observe_json (DynamoDB); aws_cli.observe (STS/CloudWatch)",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "calls": [], "cleanup": {},
        "ownedTables": owned, "mutationChecks": [], "phases": [],
        "experiment": {"cliMaxAttempts": 1, "signedRequestAttempts": 1, "itemBytes": ITEM_BYTES,
                       "pressureWaves": args.pressure_waves, "waveIntervalSeconds": args.wave_interval,
                       "pressureConcurrency": 12, "metricMinimumAgeSeconds": args.metric_wait,
                       "controlPacingSeconds": 2, "mixedWriteWaves": 8, "mixedWaveIntervalSeconds": 10,
                       "postCleanupMetricWaitSeconds": args.post_cleanup_metric_wait,
                       "sizeDefinition": "Sum of UTF-8 string attribute names and values; no storage overhead",
                       "endpoints": {"dynamodb": "https://" + ENDPOINT, "sts": "https://sts.us-east-1.amazonaws.com", "cloudwatch": "https://monitoring.us-east-1.amazonaws.com"}},
        "limitations": [
            "Configured maxima are best-effort targets with burst allowance, not exact per-second ceilings.",
            "No inference about AWS private allocation, partition credits, refill, deterministic throttle ordinals or instantaneous control convergence.",
            "Sequence numbers are invocation order. Concurrent completion order is retained by timestamps.",
            "Projected reads charge the whole stored image. Failed verification reads leave mutation state unknown.",
            "Absent metric data is unpublished/unknown, never a fabricated zero; gauges aggregate over five minutes.",
            "Only owned synthetic data is used. Data requests are not retried; distinct pressure attempts are labeled.",
        ],
    }

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, operation, parameters, service="dynamodb", expected=None):
        start = time.monotonic()
        row = {"label": label, "operation": operation, "service": service, "input": parameters,
               "startedAt": timestamp(), "startedOffsetSeconds": round(start - origin, 6)}
        with lock:
            row["sequence"] = len(capture["calls"]) + 1
            capture["calls"].append(row)
        try:
            if service == "dynamodb":
                row["transport"] = "signed_requests.observe_json"
                target = "DynamoDB_20120810." + "".join(part.capitalize() for part in operation.split("-"))
                row.update(observe_json(ENDPOINT, service, target, parameters))
            else:
                row["transport"] = "aws_cli.observe"
                row.update(observe(service, operation, parameters, environment, paginate=False))
        except Exception as error:
            row.update(code="ClientTransportError", transportErrorType=type(error).__name__)
            raise RuntimeError(label + ": transport " + type(error).__name__) from None
        finally:
            row.update(finishedAt=timestamp(), durationSeconds=round(time.monotonic() - start, 6))
        if expected is not None and row["code"] != expected:
            raise RuntimeError(label + ": " + row["code"])
        return row

    def settled(table):
        for attempt in range(120):
            row = record("settled-" + table.rsplit("-", 1)[-1] + "-" + str(attempt), "describe-table", {"TableName": table}, expected="Success")
            metadata = row["output"]["Table"]
            if metadata["TableArn"].split(":")[3:5] != [REGION, args.account]:
                raise RuntimeError("unexpected table account/region")
            if metadata["TableStatus"] == "ACTIVE" and all(i["IndexStatus"] == "ACTIVE" for i in metadata.get("GlobalSecondaryIndexes", [])):
                return row
            time.sleep(2)
        raise RuntimeError("table failed to settle")

    def control(label, table, **fields):
        # Control-plane rate limits are separate from data-plane admission.
        time.sleep(2)
        row = record(label, "update-table", dict(TableName=table, **fields))
        if row["code"] == "Success":
            settled(table)
        save()
        return row

    def index_control(label, **maximum):
        return control(label, indexed, GlobalSecondaryIndexUpdates=[{"Update": {"IndexName": "pressure", "OnDemandThroughput": maximum}}])

    def create_parameters(table):
        return {"TableName": table, "BillingMode": "PAY_PER_REQUEST", "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}]}

    def update(table, marker, projected=False):
        return {"TableName": table, "Key": {"pk": {"S": "large"}}, "UpdateExpression": "SET #m = :v",
                "ExpressionAttributeNames": {"#m": "mark" if projected else marker},
                "ExpressionAttributeValues": {":v": {"S": marker}}, "ReturnConsumedCapacity": "INDEXES"}

    def get(table, projection="pk"):
        return {"TableName": table, "Key": {"pk": {"S": "large"}}, "ConsistentRead": True,
                "ProjectionExpression": projection, "ReturnConsumedCapacity": "INDEXES"}

    def query(index):
        return {"TableName": indexed, "IndexName": index, "KeyConditionExpression": "x = :x",
                "ExpressionAttributeValues": {":x": {"S": "hot"}}, "ProjectionExpression": "pk", "ReturnConsumedCapacity": "INDEXES"}

    def parallel(requests):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            return list(pool.map(lambda request: record(*request), requests))

    def metrics(label):
        queries = []
        for table, index in [(base, None), (reader, None), (indexed, None), (indexed, "pressure"), (indexed, "unlimited")]:
            dimensions = [{"Name": "TableName", "Value": table}]
            if index:
                dimensions.append({"Name": "GlobalSecondaryIndexName", "Value": index})
            for name in ("OnDemandMaxReadRequestUnits", "OnDemandMaxWriteRequestUnits", "ReadMaxOnDemandThroughputThrottleEvents", "WriteMaxOnDemandThroughputThrottleEvents", "ReadThrottleEvents", "WriteThrottleEvents"):
                gauge = name.startswith("OnDemandMax")
                queries.append({"Id": "m" + str(len(queries)), "MetricStat": {"Metric": {"Namespace": "AWS/DynamoDB", "MetricName": name, "Dimensions": dimensions}, "Period": 300 if gauge else 60, "Stat": "Maximum" if gauge else "Sum"}, "ReturnData": True})
        row = record(label, "get-metric-data", {"MetricDataQueries": queries, "StartTime": capture["startedAt"], "EndTime": timestamp(), "ScanBy": "TimestampAscending", "MaxDatapoints": 2000}, service="cloudwatch")
        capture.setdefault("metricSnapshots", []).append(row["sequence"])
        save()

    def remove_table(table):
        cleanup = capture["cleanup"].setdefault(table, {"verifiedAbsent": False})
        row = record("delete-owned-" + table.rsplit("-", 1)[-1], "delete-table", {"TableName": table})
        if row["code"] not in ("Success", "ResourceNotFoundException"):
            raise RuntimeError("delete rejected: " + row["code"])
        for attempt in range(120):
            row = record("verify-absent-" + table.rsplit("-", 1)[-1] + "-" + str(attempt), "describe-table", {"TableName": table})
            if row["code"] == "ResourceNotFoundException":
                cleanup.update(verifiedAbsent=True, verificationSequence=row["sequence"], verifiedAt=row["finishedAt"])
                return
            time.sleep(2)
        raise RuntimeError("owned table absence not observed")

    try:
        identity = record("caller-identity", "get-caller-identity", {}, service="sts", expected="Success")
        if identity["output"]["Account"] != args.account:
            raise RuntimeError("refusing native mutation outside approved account")
        capture["actor"] = identity["output"]
        for table in (base, reader, indexed):
            parameters = create_parameters(table)
            if table == reader:
                parameters["OnDemandThroughput"] = {"MaxReadRequestUnits": 17}
            if table == indexed:
                parameters["OnDemandThroughput"] = {"MaxWriteRequestUnits": 29}
                parameters["AttributeDefinitions"].append({"AttributeName": "x", "AttributeType": "S"})
                parameters["GlobalSecondaryIndexes"] = [
                    {"IndexName": "pressure", "KeySchema": [{"AttributeName": "x", "KeyType": "HASH"}], "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["data", "mark"]}, "OnDemandThroughput": {"MaxReadRequestUnits": 11, "MaxWriteRequestUnits": 13}},
                    {"IndexName": "unlimited", "KeySchema": [{"AttributeName": "x", "KeyType": "HASH"}], "Projection": {"ProjectionType": "KEYS_ONLY"}},
                ]
            owned.append(table)
            record("create-" + table.rsplit("-", 1)[-1], "create-table", parameters, expected="Success")
            settled(table)
        for suffix, maximum in [("empty", {}), ("zero", {"MaxReadRequestUnits": 0}), ("negative", {"MaxWriteRequestUnits": -2}), ("removed", {"MaxWriteRequestUnits": -1}), ("provisioned", {"MaxReadRequestUnits": 1})]:
            table = prefix + "-invalid-" + suffix
            parameters = create_parameters(table)
            parameters["OnDemandThroughput"] = maximum
            if suffix == "provisioned":
                parameters.update(BillingMode="PROVISIONED", ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1})
            owned.append(table)
            row = record("create-maximum-" + suffix, "create-table", parameters)
            if row["code"] == "Success":
                settled(table)
                remove_table(table)
        negative_index = {"IndexName": "sentinel-index", "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
                          "Projection": {"ProjectionType": "ALL"}, "OnDemandThroughput": {"MaxReadRequestUnits": -1, "MaxWriteRequestUnits": 3}}
        invalid_index_table = prefix + "-invalid-index-removal"
        parameters = create_parameters(invalid_index_table)
        parameters["AttributeDefinitions"].append({"AttributeName": "gpk", "AttributeType": "S"})
        parameters["GlobalSecondaryIndexes"] = [negative_index]
        owned.append(invalid_index_table)
        time.sleep(2)
        record("create-table-index-removal-sentinel", "create-table", parameters, expected="ValidationException")
        time.sleep(2)
        record("update-create-index-removal-sentinel", "update-table", {
            "TableName": base, "AttributeDefinitions": [{"AttributeName": "gpk", "AttributeType": "S"}],
            "GlobalSecondaryIndexUpdates": [{"Create": negative_index}],
        }, expected="ValidationException")
        for label, maximum in [("read-only", {"MaxReadRequestUnits": 19}), ("partial-write", {"MaxWriteRequestUnits": 23}), ("partial-read", {"MaxReadRequestUnits": 31}), ("remove-read", {"MaxReadRequestUnits": -1}), ("empty", {}), ("zero-read", {"MaxReadRequestUnits": 0}), ("zero-write", {"MaxWriteRequestUnits": 0}), ("invalid-negative", {"MaxWriteRequestUnits": -2}), ("remove-write", {"MaxWriteRequestUnits": -1})]:
            control("update-" + label, base, OnDemandThroughput=maximum)
        control("maximum-above-40000", base, OnDemandThroughput={"MaxWriteRequestUnits": 40001})
        index_control("gsi-maximum-above-40000", MaxReadRequestUnits=40001)
        index_control("gsi-partial-read", MaxReadRequestUnits=7)
        index_control("gsi-remove-write", MaxWriteRequestUnits=-1)
        index_control("gsi-empty")
        index_control("gsi-zero", MaxReadRequestUnits=0)
        index_control("gsi-negative", MaxWriteRequestUnits=-2)
        index_control("gsi-remove-read", MaxReadRequestUnits=-1)
        for table in (reader, indexed):
            control("remove-before-seeding-" + table.rsplit("-", 1)[-1], table, OnDemandThroughput={"MaxReadRequestUnits": -1, "MaxWriteRequestUnits": -1})
        for table in (base, reader, indexed):
            record("seed-" + table.rsplit("-", 1)[-1], "put-item", {"TableName": table, "Item": item("large", table == indexed), "ReturnConsumedCapacity": "INDEXES"}, expected="Success")
        record("seed-delete-target", "put-item", {"TableName": base, "Item": item("delete"), "ReturnConsumedCapacity": "INDEXES"}, expected="Success")
        control("table-write-pressure-maximum", base, OnDemandThroughput={"MaxWriteRequestUnits": 1})
        control("table-read-pressure-maximum", reader, OnDemandThroughput={"MaxReadRequestUnits": 1})
        index_control("gsi-pressure-maximum", MaxReadRequestUnits=1, MaxWriteRequestUnits=1)
        capture["controlsCapturedAt"] = timestamp()
        save()
        print(json.dumps({"phase": "controls-captured", "calls": len(capture["calls"]), "output": str(args.output)}), flush=True)
        mutation_rows = []
        pressure_start = time.monotonic()
        for wave in range(args.pressure_waves):
            time.sleep(max(0, pressure_start + wave * args.wave_interval - time.monotonic()))
            requests = []
            for slot in range(6):
                marker = f"w{wave:02}s{slot:02}"
                requests.extend([(marker + "-base-write", "update-item", update(base, marker)),
                                 (marker + "-base-read", "get-item", get(reader)),
                                 (marker + "-gsi-write", "update-item", update(indexed, marker, True)),
                                 (marker + "-gsi-read", "query", query("pressure"))])
            rows = parallel(requests)
            mutation_rows.extend(row for row in rows if row["operation"] == "update-item" and row["input"]["TableName"] == base)
            # Interleave unprojected writes while actual GSI pressure is active.
            unchanged = record(f"wave{wave}-unchanged-projection", "update-item", update(indexed, f"unchanged{wave}"))
            mutation_rows.append(unchanged)
            record(f"wave{wave}-unlimited-index-read", "query", query("unlimited"))
            capture["phases"].append({"name": "pressure-wave-" + str(wave), "sequences": [r["sequence"] for r in rows], "codes": {code: sum(r["code"] == code for r in rows) for code in sorted({r["code"] for r in rows})}})
            if any(r["code"] != "Success" for r in rows):
                tx_update = update(base, "tx" + str(wave))
                tx_update.pop("ReturnConsumedCapacity")
                tx = record(f"wave{wave}-transaction", "transact-write-items", {"TransactItems": [{"Update": tx_update}, {"Put": {"TableName": base, "Item": {"pk": {"S": "txSibling" + str(wave)}}}}], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)})
                mutation_rows.append(tx)
                record(f"wave{wave}-batch-write", "batch-write-item", {"RequestItems": {base: [{"DeleteRequest": {"Key": {"pk": {"S": "delete"}}}}, {"PutRequest": {"Item": {"pk": {"S": "batchSibling" + str(wave)}}}}]}, "ReturnConsumedCapacity": "INDEXES"})
                record(f"wave{wave}-batch-read", "batch-get-item", {"RequestItems": {reader: {"Keys": [{"pk": {"S": "large"}}, {"pk": {"S": "absent"}}], "ConsistentRead": True, "ProjectionExpression": "pk"}}, "ReturnConsumedCapacity": "INDEXES"})
            save()
            print(json.dumps(capture["phases"][-1]), flush=True)
        composite_effects = composite_pressure(record, base, indexed, reader)
        metrics("cloudwatch-after-pressure")
        # Increase the table write maximum and remove read/GSI maxima; keep recovery observations distinct.
        control("increase-write-for-recovery", base, OnDemandThroughput={"MaxWriteRequestUnits": 10000})
        control("remove-read-for-recovery", reader, OnDemandThroughput={"MaxReadRequestUnits": -1})
        index_control("remove-gsi-for-recovery", MaxReadRequestUnits=-1, MaxWriteRequestUnits=-1)
        for attempt in range(3):
            if attempt:
                time.sleep(10)
            record(f"recovery-{attempt}-base-write", "update-item", update(base, "recovery" + str(attempt)))
            record(f"recovery-{attempt}-base-read", "get-item", get(reader))
            record(f"recovery-{attempt}-gsi-write", "update-item", update(indexed, "recovery" + str(attempt), True))
            record(f"recovery-{attempt}-gsi-read", "query", query("pressure"))
        capture["compositeMutationChecks"] = verify_composite_effects(record, composite_effects)
        for row in mutation_rows:
            if row["operation"] == "transact-write-items":
                parameters = row["input"]["TransactItems"][0]["Update"]
            else:
                parameters = row["input"]
            marker = parameters["ExpressionAttributeNames"]["#m"]
            check = record("verify-mutation-" + str(row["sequence"]), "get-item", {**get(parameters["TableName"], "pk, #m"), "ExpressionAttributeNames": {"#m": marker}})
            capture["mutationChecks"].append({"mutationSequence": row["sequence"], "verificationSequence": check["sequence"], "attribute": marker,
                                               "readSucceeded": check["code"] == "Success", "markerObserved": marker in check.get("output", {}).get("Item", {}) if check["code"] == "Success" else None})
        record("verify-batch-delete-target", "get-item", {"TableName": base, "Key": {"pk": {"S": "delete"}}, "ProjectionExpression": "pk", "ConsistentRead": True})
        for wave in range(args.pressure_waves):
            for kind in ("txSibling", "batchSibling"):
                record("verify-" + kind + str(wave), "get-item", {"TableName": base, "Key": {"pk": {"S": kind + str(wave)}}, "ProjectionExpression": "pk", "ConsistentRead": True})
        control("configure-before-mode-transition", base, OnDemandThroughput={"MaxReadRequestUnits": 37, "MaxWriteRequestUnits": 41})
        control("provisioned-with-maximum-rejection", base, BillingMode="PROVISIONED", ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}, OnDemandThroughput={"MaxReadRequestUnits": 3})
        control("switch-to-provisioned", base, BillingMode="PROVISIONED", ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1})
        control("maximum-on-provisioned-rejection", base, OnDemandThroughput={"MaxWriteRequestUnits": 2})
        control("empty-on-provisioned", base, OnDemandThroughput={})
        control("remove-on-provisioned", base, OnDemandThroughput={"MaxReadRequestUnits": -1})
        control("roundtrip-on-demand-omitted", base, BillingMode="PAY_PER_REQUEST")
        for label, maximum in [
            ("paced-read", {"MaxReadRequestUnits": 53}),
            ("paced-partial-write", {"MaxWriteRequestUnits": 59}),
            ("paced-partial-read", {"MaxReadRequestUnits": 61}),
            ("paced-remove-read", {"MaxReadRequestUnits": -1}),
            ("paced-remove-write", {"MaxWriteRequestUnits": -1}),
            ("paced-empty", {}),
        ]:
            control(label, base, OnDemandThroughput=maximum)
        control("set-mixed-write-maxima", indexed, OnDemandThroughput={"MaxWriteRequestUnits": 1},
                GlobalSecondaryIndexUpdates=[{"Update": {"IndexName": "pressure", "OnDemandThroughput": {"MaxReadRequestUnits": 7, "MaxWriteRequestUnits": 1}}}])
        mixed_start = time.monotonic()
        for wave in range(8):
            time.sleep(max(0, mixed_start + wave * 10 - time.monotonic()))
            for slot in range(6):
                record(f"mixed-wave{wave}-write{slot}", "update-item", update(indexed, f"mixed{wave}-{slot}", True))
            record(f"mixed-wave{wave}-unchanged", "update-item", update(indexed, f"mixedNote{wave}"))
        time.sleep(2)
        transition = record("indexed-switch-provisioned", "update-table", {
            "TableName": indexed, "BillingMode": "PROVISIONED",
            "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            "GlobalSecondaryIndexUpdates": [{"Update": {"IndexName": name, "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}}} for name in ("pressure", "unlimited")],
        })
        record("caps-while-updating", "update-table", {"TableName": indexed, "OnDemandThroughput": {"MaxWriteRequestUnits": 2}})
        if transition["code"] == "Success":
            settled(indexed)
        control("indexed-roundtrip-omitted-caps", indexed, BillingMode="PAY_PER_REQUEST")
        capture["pressureFinishedAt"] = timestamp()
        save()
        print(json.dumps({"phase": "data-and-transitions-captured", "calls": len(capture["calls"])}), flush=True)
        time.sleep(max(0, args.metric_wait - (time.monotonic() - origin)))
        metrics("cloudwatch-final-publication-snapshot")
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for table in owned:
            if capture["cleanup"].get(table, {}).get("verifiedAbsent"):
                continue
            try:
                remove_table(table)
            except Exception as error:
                capture["cleanup"].setdefault(table, {"verifiedAbsent": False})["error"] = str(error)
        capture["leftoverTables"] = [table for table in owned if not capture["cleanup"].get(table, {}).get("verifiedAbsent")]
        capture["finishedAt"] = timestamp()
        save()
    if capture["leftoverTables"]:
        raise RuntimeError("owned resources remain; inspect cleanup evidence")
    time.sleep(args.post_cleanup_metric_wait)
    metrics("cloudwatch-delayed-after-verified-cleanup")
    capture["finishedAt"] = timestamp()
    save()
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "leftoverTables": capture["leftoverTables"]}), flush=True)


if __name__ == "__main__":
    main()
