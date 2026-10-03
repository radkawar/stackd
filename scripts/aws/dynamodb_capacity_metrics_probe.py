#!/usr/bin/env python3
"""Capture native DynamoDB capacity publication in isolated UTC minute windows."""
import argparse
import datetime
import json
import os
import pathlib
import secrets
import time

from aws_cli import observe


REGION = "us-east-1"
SOURCES = [
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html",
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStatistics.html",
]


def timestamp(epoch=None):
    return datetime.datetime.fromtimestamp(time.time() if epoch is None else epoch, datetime.timezone.utc).isoformat()


def epoch(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def sleep_until(target):
    time.sleep(max(0, target - time.time()))


def derive(capture):
    """Index original observations; absent datapoints remain null, not zero."""
    calls = {call["sequence"]: call for call in capture["calls"]}
    latest = capture["metricPolls"][-1] if capture["metricPolls"] else None
    result = {"windows": {}, "positiveControls": {}, "publication": {}}
    for name, window in capture["windows"].items():
        start = epoch(window["start"])
        rows = [calls[sequence] for sequence in window["callSequences"]]
        entry = {
            "callSequences": window["callSequences"],
            "callsEntirelyInsideWindow": all(start <= epoch(row["startedAt"]) <= epoch(row["finishedAt"]) < start + 60 for row in rows),
            "returnedCapacity": {row["label"]: row.get("output", {}).get("ConsumedCapacity") for row in rows},
            "metrics": {},
        }
        for key in capture["metricSeries"]:
            observations = []
            for poll in capture["metricPolls"]:
                sequence = poll["callSequences"][key]
                row = calls[sequence]
                points = [point for point in row.get("output", {}).get("Datapoints", []) if epoch(point["Timestamp"]) == start]
                if points:
                    observations.append({"callSequence": sequence, "observedAt": row["finishedAt"], "datapoints": points})
            last_sequence = latest["callSequences"][key] if latest else None
            last_points = [point for point in calls[last_sequence].get("output", {}).get("Datapoints", []) if epoch(point["Timestamp"]) == start] if latest else []
            entry["metrics"][key] = {
                "latestCallSequence": last_sequence,
                "datapoints": last_points,
                "sum": sum(point["Sum"] for point in last_points) if last_points else None,
                "firstObservedAt": observations[0]["observedAt"] if observations else None,
                "firstObservedCallSequence": observations[0]["callSequence"] if observations else None,
                "firstObservedSecondsAfterWindowEnd": epoch(observations[0]["observedAt"]) - start - 60 if observations else None,
            }
        result["windows"][name] = entry
    for series, window in [("tableWrite", "successful-transaction"), ("indexWrite", "successful-transaction"), ("tableRead", "successful-read-controls"), ("indexRead", "successful-read-controls")]:
        value = result["windows"].get(window, {}).get("metrics", {}).get(series, {}).get("sum")
        result["positiveControls"][series] = {"window": window, "sum": value, "positiveObserved": value is not None and value > 0}
    result["publication"] = {
        "pollCount": len(capture["metricPolls"]),
        "firstPollAt": capture["metricPolls"][0]["startedAt"] if latest else None,
        "lastPollAt": latest["finishedAt"] if latest else None,
        "missingValues": "null means no datapoint in the latest query, never zero; numeric zero is an actual published Sum",
        "sampleCount": "Publication samples, not request counts; idle zero samples may affect Average and SampleCount.",
        "attribution": "UTC request intervals and exact metric dimensions are recorded. Publication can lag, and observations do not prove a general timing guarantee.",
    }
    return result


def collect_dimensions(capture, record):
    """Record actual published dimension sets, including write Source variants."""
    discovery = {"startedAt": timestamp(), "listingCallSequences": [], "writeVariants": []}
    capture["dimensionDiscovery"] = discovery
    parameters = {"Namespace": "AWS/DynamoDB", "Dimensions": [{"Name": "TableName", "Value": capture["table"]}]}
    metrics = []
    while True:
        row = record("published-dimensions-" + str(len(discovery["listingCallSequences"])), "cloudwatch", "list-metrics", parameters)
        discovery["listingCallSequences"].append(row["sequence"])
        metrics.extend(row["output"].get("Metrics", []))
        token = row["output"].get("NextToken")
        if not token:
            break
        parameters = {**parameters, "NextToken": token}
    start = min(epoch(window["start"]) for window in capture["windows"].values())
    end = max(epoch(window["end"]) for window in capture["windows"].values())
    for metric in metrics:
        if metric["MetricName"] != "ConsumedWriteCapacityUnits" or not any(dimension["Name"] == "Source" for dimension in metric["Dimensions"]):
            continue
        row = record("published-write-source-" + str(len(discovery["writeVariants"])), "cloudwatch", "get-metric-statistics", {
            **metric, "StartTime": timestamp(start), "EndTime": timestamp(end), "Period": 60,
            "Statistics": capture["experiment"]["statistics"],
        })
        discovery["writeVariants"].append({
            "callSequence": row["sequence"], "dimensions": metric["Dimensions"],
            "windowSums": {
                name: sum(point["Sum"] for point in points) if points else None
                for name, window in capture["windows"].items()
                for points in [[point for point in row["output"].get("Datapoints", []) if epoch(point["Timestamp"]) == epoch(window["start"])]]
            },
        })
    discovery["finishedAt"] = timestamp()
    discovery["bound"] = "ListMetrics discovery is eventually consistent. An unlisted dimension combination is not evidence that it is never published; absent GetMetricStatistics datapoints are not zero."


def cancellation_extensions(table):
    seed = {"pk": {"S": "seed"}, "g": {"S": "group"}, "payload": {"S": "x" * 5000}}
    small = {"pk": {"S": "transaction"}, "g": {"S": "group"}, "payload": {"S": "small"}}

    def failed_put(item):
        return {"Put": {"TableName": table, "Item": item, "ConditionExpression": "attribute_not_exists(pk)", "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}}

    return {
        "canceled-transaction-mixed": {
            "TransactItems": [
                failed_put(seed),
                {"Put": {"TableName": table, "Item": {"pk": {"S": "canceled-new"}, "g": {"S": "group"}, "payload": {"S": "small"}}}},
            ],
            "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16),
        },
        "canceled-transaction-two-failures": {
            "TransactItems": [failed_put(seed), failed_put(small)],
            "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/capacity_metrics.json"))
    parser.add_argument("--publication-wait-seconds", type=int, default=900)
    args = parser.parse_args()
    if args.publication_wait_seconds < 180:
        parser.error("publication wait must be at least 180 seconds")
    if args.output.exists():
        parser.error("refusing to overwrite an existing native capture; choose another output path")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    table = "stackd-ddb-capmetrics-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    index = "by-g"
    table_dimensions = [{"Name": "TableName", "Value": table}]
    index_dimensions = table_dimensions + [{"Name": "GlobalSecondaryIndexName", "Value": index}]
    series = {
        "tableRead": {"MetricName": "ConsumedReadCapacityUnits", "Dimensions": table_dimensions},
        "tableWrite": {"MetricName": "ConsumedWriteCapacityUnits", "Dimensions": table_dimensions},
        "indexRead": {"MetricName": "ConsumedReadCapacityUnits", "Dimensions": index_dimensions},
        "indexWrite": {"MetricName": "ConsumedWriteCapacityUnits", "Dimensions": index_dimensions},
        "conditionFailures": {"MetricName": "ConditionalCheckFailedRequests", "Dimensions": table_dimensions},
    }
    capture = {
        "source": "native AWS DynamoDB and CloudWatch through scripts/aws/aws_cli.py observe",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table, "index": index,
        "documentation": SOURCES, "calls": [], "windows": {}, "metricSeries": series, "metricPolls": [],
        "experiment": {
            "billingMode": "PAY_PER_REQUEST", "indexProjection": "KEYS_ONLY", "periodSeconds": 60,
            "cliMaxAttempts": 1, "publicationWaitSeconds": args.publication_wait_seconds,
            "dataOperations": "Every data operation is recorded. No readiness reads, console data browsing, unrecorded retries, or throughput load.",
            "transactionReplay": "Original success near minute end; identical token replay directly next minute, with no intervening AWS call. Actual gap is recorded.",
            "statistics": ["Sum", "SampleCount", "Minimum", "Maximum", "Average"],
        },
        "limitations": [
            "One owned regional on-demand table and KEYS_ONLY GSI; no LSI, global table, throttling, or account-wide metric experiment.",
            "Standalone failed conditions target an existing item with a 5000-byte string payload; missing-item and item-size boundary charges are not measured.",
            "Canceled transactions probe one failed Put, one failed plus one nonfailing Put, and two failed Puts. A single execution per case does not determine all preparation/order-dependent charges.",
            "Client timestamps bracket calls, not internal AWS execution. Cross-minute calls are explicitly marked and must not be treated as isolated.",
            "Polling bounds observation, not publication latency guarantees. No datapoint is not zero. Metric samples are not request counts.",
            "Source write-dimension variants are queried when discovered by the bounded ListMetrics observation; unlisted combinations remain unmeasured.",
        ],
        "cleanup": {"callSequences": [], "verifiedAbsent": False},
    }
    owned = False

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, service, operation, parameters, expected="Success", window=None, cleanup=False):
        row = {"sequence": len(capture["calls"]) + 1, "label": label, "service": service, "operation": operation, "startedAt": timestamp(), "input": parameters}
        capture["calls"].append(row)
        if window:
            capture["windows"][window]["callSequences"].append(row["sequence"])
        if cleanup:
            capture["cleanup"]["callSequences"].append(row["sequence"])
        try:
            row.update(observe(service, operation, parameters, env, paginate=False))
        except Exception as error:
            row["transportError"] = str(error)
            raise
        finally:
            row["finishedAt"] = timestamp()
            save()
        print(label + ": " + row["code"], flush=True)
        if expected is not None and row["code"] != expected:
            raise RuntimeError(label + ": expected " + expected + ", got " + row["code"])
        return row

    def window(name, start):
        capture["windows"][name] = {"start": timestamp(start), "end": timestamp(start + 60), "callSequences": []}
        save()

    def poll(label, start, end):
        observation = {"label": label, "startedAt": timestamp(), "callSequences": {}}
        for key, metric in series.items():
            row = record(label + "-" + key, "cloudwatch", "get-metric-statistics", {
                "Namespace": "AWS/DynamoDB", **metric, "StartTime": timestamp(start), "EndTime": timestamp(end),
                "Period": 60, "Statistics": capture["experiment"]["statistics"],
            })
            observation["callSequences"][key] = row["sequence"]
        observation["finishedAt"] = timestamp()
        capture["metricPolls"].append(observation)
        capture["findings"] = derive(capture)
        save()

    try:
        identity = record("caller-identity", "sts", "get-caller-identity", {})["output"]
        capture["identity"] = identity
        if identity["Account"] != args.account:
            raise RuntimeError("Refusing writes in unexpected account " + identity["Account"])
        record("create-owned-table", "dynamodb", "create-table", {
            "TableName": table, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": name, "AttributeType": "S"} for name in ["pk", "g"]],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "GlobalSecondaryIndexes": [{"IndexName": index, "KeySchema": [{"AttributeName": "g", "KeyType": "HASH"}], "Projection": {"ProjectionType": "KEYS_ONLY"}}],
        })
        owned = True
        for attempt in range(90):
            description = record("table-ready-" + str(attempt), "dynamodb", "describe-table", {"TableName": table})["output"]["Table"]
            if description["TableStatus"] == "ACTIVE" and all(entry["IndexStatus"] == "ACTIVE" for entry in description.get("GlobalSecondaryIndexes", [])):
                break
            time.sleep(2)
        else:
            raise RuntimeError("Table and GSI did not become active")
        start = (int(time.time()) // 60 + 1) * 60
        names = ["successful-write-control", "successful-read-controls", "failed-put-condition", "failed-update-condition", "failed-delete-condition", "canceled-transaction", "successful-transaction", "identical-token-replay", "idle-control"]
        for offset, name in enumerate(names):
            window(name, start + offset * 60)
        seed = {"pk": {"S": "seed"}, "g": {"S": "group"}, "payload": {"S": "x" * 5000}}
        key = {"pk": {"S": "seed"}}
        sleep_until(start + 5)
        record(names[0], "dynamodb", "batch-write-item", {"RequestItems": {table: [{"PutRequest": {"Item": seed}}]}, "ReturnConsumedCapacity": "INDEXES"}, window=names[0])
        sleep_until(start + 65)
        record("transactional-read-control", "dynamodb", "transact-get-items", {"TransactItems": [{"Get": {"TableName": table, "Key": key}}], "ReturnConsumedCapacity": "INDEXES"}, window=names[1])
        record("index-read-control", "dynamodb", "query", {"TableName": table, "IndexName": index, "KeyConditionExpression": "g = :g", "ExpressionAttributeValues": {":g": {"S": "group"}}, "ReturnConsumedCapacity": "INDEXES"}, window=names[1])
        for offset, operation in enumerate(["put-item", "update-item", "delete-item"], 2):
            sleep_until(start + offset * 60 + 5)
            parameters = {"TableName": table, "ConditionExpression": "attribute_not_exists(pk)", "ReturnConsumedCapacity": "INDEXES", "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}
            if operation == "put-item":
                parameters["Item"] = seed
            else:
                parameters["Key"] = key
            if operation == "update-item":
                parameters.update(UpdateExpression="SET payload = :p", ExpressionAttributeValues={":p": {"S": "replacement"}})
            record(names[offset], "dynamodb", operation, parameters, "ConditionalCheckFailedException", window=names[offset])
        sleep_until(start + 305)
        record(names[5], "dynamodb", "transact-write-items", {"TransactItems": [{"Put": {"TableName": table, "Item": seed, "ConditionExpression": "attribute_not_exists(pk)", "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}}], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)}, "TransactionCanceledException", window=names[5])
        transaction = {"TransactItems": [{"Put": {"TableName": table, "Item": {"pk": {"S": "transaction"}, "g": {"S": "group"}, "payload": {"S": "small"}}}}], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)}
        sleep_until(start + 6 * 60 + 56)
        original = record(names[6], "dynamodb", "transact-write-items", transaction, window=names[6])
        sleep_until(start + 7 * 60 + 1)
        replay = record(names[7], "dynamodb", "transact-write-items", transaction, window=names[7])
        capture["experiment"]["replayGapSeconds"] = epoch(replay["startedAt"]) - epoch(original["finishedAt"])
        for offset, (name, parameters) in enumerate(cancellation_extensions(table).items(), len(names)):
            window(name, start + offset * 60)
            sleep_until(start + offset * 60 + 5)
            record(name, "dynamodb", "transact-write-items", parameters, "TransactionCanceledException", window=name)
        names = list(capture["windows"])
        end = start + len(names) * 60
        sleep_until(end + 5)
        capture["publicationStartedAt"] = timestamp()
        deadline = time.monotonic() + args.publication_wait_seconds
        previous_signature = None
        stable = 0
        attempt = 0
        while True:
            poll("publication-" + str(attempt), start, end)
            findings = capture["findings"]
            signature = {name: {key: value["sum"] for key, value in entry["metrics"].items()} for name, entry in findings["windows"].items()}
            stable = stable + 1 if signature == previous_signature else 0
            previous_signature = signature
            controls_seen = all(control["positiveObserved"] for control in findings["positiveControls"].values())
            charged = all(any(signature[name][key] is not None and signature[name][key] > 0 for key in ["tableRead", "tableWrite"]) for name in names[2:] if name != "idle-control")
            capacity_bins_present = all(signature[name][key] is not None for name in names for key in ["tableRead", "tableWrite", "indexRead", "indexWrite"])
            if controls_seen and charged and capacity_bins_present and stable >= 2 and time.time() >= end + 180:
                capture["publicationStopReason"] = "Positive controls and charge bins observed; all capacity bins present; three consecutive equal Sum snapshots at least 60 seconds apart. This is an observation bound, not a publication guarantee."
                break
            if time.monotonic() >= deadline:
                capture["publicationStopReason"] = "Bounded publication polling deadline reached; absent or ambiguous bins remain unmeasured, not zero."
                break
            time.sleep(min(60, max(0, deadline - time.monotonic())))
            attempt += 1
        collect_dimensions(capture, record)
        capture["workflowComplete"] = True
    except BaseException as error:
        capture["workflowError"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if owned:
            try:
                deletion = record("delete-owned-table", "dynamodb", "delete-table", {"TableName": table}, expected=None, cleanup=True)
                if deletion["code"] not in ("Success", "ResourceNotFoundException"):
                    raise RuntimeError("Owned table deletion failed: " + deletion["code"])
                for attempt in range(90):
                    absent = record("verify-owned-table-absent-" + str(attempt), "dynamodb", "describe-table", {"TableName": table}, expected=None, cleanup=True)
                    if absent["code"] == "ResourceNotFoundException":
                        capture["cleanup"]["verifiedAbsent"] = True
                        break
                    if absent["code"] != "Success":
                        raise RuntimeError("Cannot verify owned table deletion: " + absent["code"])
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
        else:
            capture["finishedAt"] = timestamp()
            save()


if __name__ == "__main__":
    main()
