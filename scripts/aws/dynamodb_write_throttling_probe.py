#!/usr/bin/env python3
"""Capture bounded native write admission and GSI backpressure, without retries."""
import argparse
import concurrent.futures
import datetime
import json
import math
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


def size(item):
    return sum(len(name.encode()) + len(value["S"].encode()) for name, value in item.items())


def sized_item(pk, total, indexed=False):
    item = {"pk": {"S": pk}, "mark": {"S": "seed0000"}, "note": {"S": "seed0000"}, "data": {"S": ""}}
    if indexed:
        item["x"] = {"S": "hot"}
    item["data"]["S"] = "a" * (total - size(item))
    assert size(item) == total
    return item


def mixed_pressure(record, table):
    """Unique attributes let post-wave reads prove rejected writes stayed absent."""
    for wave in range(2):
        requests = []
        names = []
        for i in range(12):
            name = f"probe{wave}{i:02}"
            names.append(name)
            update = {"TableName": table, "Key": {"pk": {"S": "scalar00"}}, "UpdateExpression": "SET #a = :v", "ExpressionAttributeNames": {"#a": name}, "ExpressionAttributeValues": {":v": {"S": "applied"}}}
            statement = {"Statement": f'UPDATE "{table}" SET "{name}"=? WHERE "pk"=?', "Parameters": [{"S": "applied"}, {"S": "scalar00"}]}
            if i % 4 == 0:
                operation, parameters = "update-item", {**update, "ReturnValues": "NONE", "ReturnConsumedCapacity": "INDEXES"}
            elif i % 4 == 1:
                operation, parameters = "transact-write-items", {"TransactItems": [{"Update": update}], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)}
            elif i % 4 == 2:
                operation, parameters = "execute-statement", {**statement, "ReturnConsumedCapacity": "INDEXES"}
            else:
                operation, parameters = "batch-execute-statement", {"Statements": [statement], "ReturnConsumedCapacity": "INDEXES"}
            requests.append((f"mixed-pressure-{wave}-{i}", operation, parameters))
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            futures = [pool.submit(record, *request) for request in requests]
            for future in futures:
                future.result()
        record(f"mixed-pressure-{wave}-mutation-check", "get-item", {"TableName": table, "Key": {"pk": {"S": "scalar00"}}, "ConsistentRead": True, "ProjectionExpression": "pk," + ",".join(names), "ReturnConsumedCapacity": "INDEXES"})
    record("mixed-batch-three-large-deletes-small-sibling", "batch-write-item", {"RequestItems": {table: [{"DeleteRequest": {"Key": {"pk": {"S": pk}}}} for pk in ("scalar00", "partiql0", "transact")] + [{"PutRequest": {"Item": {"pk": {"S": "mixsmall"}, "mark": {"S": "applied"}}}}]}, "ReturnConsumedCapacity": "INDEXES"})
    for pk in ("scalar00", "partiql0", "transact", "mixsmall"):
        record("mixed-batch-mutation-check-" + pk, "get-item", {"TableName": table, "Key": {"pk": {"S": pk}}, "ConsistentRead": True, "ProjectionExpression": "pk", "ReturnConsumedCapacity": "INDEXES"})


def fresh_pressure(record, table):
    """Observe low-capacity admission without retained on-demand history."""
    item = {"pk": {"S": "large"}, "payload": {"S": ""}}
    item["payload"]["S"] = "x" * (350 * 1024 - size(item))
    first = record("cold-first-350k-put", "put-item", {
        "TableName": table, "Item": item, "ReturnConsumedCapacity": "INDEXES"})
    if first["code"] == "Success":
        key = {"pk": {"S": "large"}}
        record("cold-first-large-strong-get", "get-item", {
            "TableName": table, "Key": key, "ProjectionExpression": "pk",
            "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES"})
        record("cold-first-small-update-large-image", "update-item", {
            "TableName": table, "Key": key, "UpdateExpression": "SET note = :v",
            "ExpressionAttributeValues": {":v": {"S": "first"}}, "ReturnConsumedCapacity": "INDEXES"})
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            for wave in range(3):
                futures = [pool.submit(record, f"cold-wave-{wave}-update-{slot}", "update-item", {
                    "TableName": table, "Key": key, "UpdateExpression": "SET #marker = :v",
                    "ExpressionAttributeNames": {"#marker": f"w{wave}s{slot}"},
                    "ExpressionAttributeValues": {":v": {"N": "1"}},
                    "ReturnConsumedCapacity": "INDEXES"}) for slot in range(12)]
                for future in futures:
                    future.result()
        record("cold-observe-success-markers", "get-item", {
            "TableName": table, "Key": key,
            "ProjectionExpression": ", ".join(["pk", "note"] + [f"w{wave}s{slot}" for wave in range(3) for slot in range(12)]),
            "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES"})
    time.sleep(3)
    record("cold-small-put-after-idle", "put-item", {
        "TableName": table, "Item": {"pk": {"S": "small"}, "v": {"N": "1"}},
        "ReturnConsumedCapacity": "INDEXES"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--fresh", action="store_true", help="create directly at 1 RCU/1 WCU instead of transitioning seeded tables")
    args = parser.parse_args()
    if args.output is None:
        args.output = pathlib.Path(".stackd/probes/dynamodb/" + ("fresh_provisioned_throttling.json" if args.fresh else "write_throttling.json"))
    if args.output.exists():
        parser.error("refusing to overwrite a native capture")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false",
               AWS_ENDPOINT_URL_DYNAMODB="https://" + ENDPOINT, AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    # signed_post uses this process environment and caches exported credentials.
    os.environ.clear()
    os.environ.update(env)
    prefix = "stackd-ddb-wthrottle-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    base, indexed = prefix + "-base", prefix + "-gsi"
    capture = {
        "source": "native AWS DynamoDB through aws_cli.observe and signed_requests.signed_post for oversized JSON",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "ownedTables": [base, indexed], "calls": [],
        "experiment": {
            "cliMaxAttempts": 1, "endpoints": {"dynamodb": "https://" + ENDPOINT, "sts": "https://sts.us-east-1.amazonaws.com"},
            "sizeDefinition": "UTF-8 attribute-name plus string-value bytes, excluding storage overhead; all attributes are strings.",
            "base": {"itemBytes": 350 * 1024, "readCapacityUnits": 10, "writeCapacityUnits": 1, "maxPressureWaves": 4, "concurrency": 8},
            "gsi": {"itemBytes": 64 * 1024, "baseReadCapacityUnits": 10, "baseWriteCapacityUnits": 32, "indexReadCapacityUnits": 1, "indexWriteCapacityUnits": 1, "maxPressureWaves": 4, "concurrency": 8, "projection": "INCLUDE(data,mark); note is unprojected"},
            "mixedPressure": {"waves": 2, "concurrency": 12, "initialItemBytes": 350 * 1024, "bytesAddedPerSuccessfulUniqueAttribute": 15, "maxItemBytes": 350 * 1024 + 24 * 15, "verification": "Each request owns a unique attribute. Wave-end strong reads distinguish successful mutations from rejected absent attributes, including per-statement errors."},
            "timing": "Sequence numbers are assigned at invocation, not completion; pressure waves await all calls, with no SDK retries. Control polls sleep two seconds.",
        },
        "limitations": [
            "A bounded regional capture does not identify deterministic throttle ordinals or exact refill/burst algorithms.",
            "AWS documents up to 300 seconds of unused capacity, best-effort burst/background consumption, and adaptive partition capacity: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/burst-adaptive-capacity.html",
            "Projected reads still consume capacity for the full underlying item. Verification uses strongly consistent base-table reads and retains actual capacity.",
            "Native asynchronous GSI pressure is attributed only by returned resource/reason fields, never merely by request timing.",
            "Both tables are seeded on-demand before switching to provisioned throughput. Fresh cold PROVISIONED 1 WCU admission is not measured; ACTIVE describes settled control state, not a guarantee of immediate internal admission convergence.",
            "Serial control reads add elapsed time. A sparse write succeeding after an indexed write throttles does not prove sparse exemption during continuously active GSI pressure.",
        ], "cleanup": {}, "mutationChecks": [],
    }
    if args.fresh:
        capture["ownedTables"] = [base]
        capture["experiment"] = {
            "setupBillingMode": "PROVISIONED", "readCapacityUnits": 1, "writeCapacityUnits": 1,
            "itemBytes": 350 * 1024, "waves": 3, "concurrency": 12, "recoveryIdleSeconds": 3,
            "timing": capture["experiment"]["timing"], "cliMaxAttempts": 1,
            "verification": "Each update owns one attribute; a strong projected read observes applied and absent markers.",
        }
        capture["limitations"] = capture["limitations"][:4]
    lock = threading.Lock()
    created = []

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, operation, parameters, service="dynamodb", expected=None, evidence=None):
        row = {"label": label, "service": service, "operation": operation, "input": parameters, "startedAt": timestamp()}
        if evidence is not None:
            row["experiment"] = evidence
        start = time.monotonic()
        with lock:
            row["sequence"] = len(capture["calls"]) + 1
            capture["calls"].append(row)
        try:
            body = json.dumps(parameters, separators=(",", ":")).encode()
            result: ProbeResult
            if service == "dynamodb" and len(body) > 100000:
                target = "DynamoDB_20120810." + "".join(part.capitalize() for part in operation.split("-"))
                result = observe_json(ENDPOINT, "dynamodb", target, parameters)
                row["transport"] = "signed_post"
            else:
                result = observe(service, operation, parameters, env, paginate=False)
                row["transport"] = "aws_cli.observe"
            row.update(result)
        except Exception as error:
            row.update(code="ClientTransportError", error={"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            row["finishedAt"] = timestamp()
            row["durationSeconds"] = round(time.monotonic() - start, 6)
            with lock:
                save()
        if expected is not None and row["code"] != expected:
            raise RuntimeError(label + ": " + row["code"])
        return row

    def ready(table, provisioned=False):
        for attempt in range(120):
            row = record("settled-" + table.rsplit("-", 1)[-1] + "-" + str(attempt), "describe-table", {"TableName": table}, expected="Success")
            description = row["output"]["Table"]
            indexes = description.get("GlobalSecondaryIndexes", [])
            if description["TableStatus"] == "ACTIVE" and all(index["IndexStatus"] == "ACTIVE" for index in indexes):
                if not provisioned or (description["ProvisionedThroughput"]["WriteCapacityUnits"] == (1 if table == base else 32) and all(index["ProvisionedThroughput"]["WriteCapacityUnits"] == 1 for index in indexes)):
                    return row
            time.sleep(2)
        raise RuntimeError("table did not settle: " + table)

    def update(table, pk, token, attribute="mark"):
        return {"TableName": table, "Key": {"pk": {"S": pk}}, "UpdateExpression": "SET #a = :v", "ExpressionAttributeNames": {"#a": attribute}, "ExpressionAttributeValues": {":v": {"S": token}}, "ReturnValues": "NONE", "ReturnConsumedCapacity": "INDEXES"}

    def verify(label, table, pk):
        return record(label, "get-item", {"TableName": table, "Key": {"pk": {"S": pk}}, "ConsistentRead": True, "ProjectionExpression": "pk, #m, #n", "ExpressionAttributeNames": {"#m": "mark", "#n": "note"}, "ReturnConsumedCapacity": "INDEXES"})

    def checked(label, operation, parameters, table, pk, token, attribute="mark"):
        before = verify(label + "-before", table, pk)
        row = record(label, operation, parameters)
        after = verify(label + "-after", table, pk)
        capture["mutationChecks"].append({"label": label, "mutationSequence": row["sequence"], "beforeSequence": before["sequence"], "afterSequence": after["sequence"], "attribute": attribute, "attemptedValue": token, "observedBefore": before.get("output", {}).get("Item"), "observedAfter": after.get("output", {}).get("Item"), "verificationReadsSucceeded": before["code"] == after["code"] == "Success"})
        return row

    def wave(table, pk, label, number):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(record, label + "-" + str(number) + "-" + str(i), "update-item", update(table, pk, f"w{number:03}{i:04}")) for i in range(8)]
            return [future.result() for future in futures]

    try:
        identity = record("caller-identity", "get-caller-identity", {}, service="sts", expected="Success")
        if identity["output"]["Account"] != args.account:
            raise RuntimeError("refusing native mutation in unapproved account")
        for table in ([base] if args.fresh else (base, indexed)):
            parameters = {"TableName": table, "BillingMode": "PAY_PER_REQUEST", "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}], "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}]}
            if table == indexed:
                parameters["AttributeDefinitions"].append({"AttributeName": "x", "AttributeType": "S"})
                parameters["GlobalSecondaryIndexes"] = [{"IndexName": "pressure", "KeySchema": [{"AttributeName": "x", "KeyType": "HASH"}], "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["data", "mark"]}}]
            if args.fresh:
                parameters["BillingMode"] = "PROVISIONED"
                parameters["ProvisionedThroughput"] = {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}
            record("create-" + table.rsplit("-", 1)[-1], "create-table", parameters, expected="Success")
            created.append(table)
            ready(table)
            if args.fresh:
                fresh_pressure(record, table)
                continue
            keys = ("scalar00", "partiql0", "transact", "batch000") if table == base else ("indexed0",)
            for pk in keys:
                item = sized_item(pk, (350 if table == base else 64) * 1024, table == indexed)
                evidence = {"itemBytes": size(item), "writeUnitsFromSize": math.ceil(size(item) / 1024)}
                if table == indexed:
                    evidence["indexEntryBytes"] = size({k: v for k, v in item.items() if k != "note"})
                record("seed-" + pk, "put-item", {"TableName": table, "Item": item, "ReturnValues": "NONE", "ReturnConsumedCapacity": "INDEXES"}, expected="Success", evidence=evidence)
            if table == indexed:
                record("seed-sparse", "put-item", {"TableName": table, "Item": {"pk": {"S": "sparse00"}, "mark": {"S": "seed0000"}}, "ReturnConsumedCapacity": "INDEXES"}, expected="Success")
            parameters = {"TableName": table, "BillingMode": "PROVISIONED", "ProvisionedThroughput": {"ReadCapacityUnits": 10, "WriteCapacityUnits": 1 if table == base else 32}}
            if table == indexed:
                parameters["GlobalSecondaryIndexUpdates"] = [{"Update": {"IndexName": "pressure", "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}}}]
            record("switch-provisioned-" + table.rsplit("-", 1)[-1], "update-table", parameters, expected="Success")
            ready(table, provisioned=True)
            if table == base:
                checked("large-single-small-update-1wcu", "update-item", update(base, "scalar00", "single00"), base, "scalar00", "single00")
                item = sized_item("scalar00", 350 * 1024)
                item["mark"] = {"S": "put00000"}
                checked("large-single-put-1wcu", "put-item", {"TableName": base, "Item": item, "ReturnValues": "NONE", "ReturnConsumedCapacity": "INDEXES"}, base, "scalar00", "put00000")
                for number in range(4):
                    rows = wave(base, "scalar00", "base-pressure", number)
                    if any(row["code"] != "Success" for row in rows):
                        break
                checked("scalar-under-pressure", "update-item", update(base, "scalar00", "reject00"), base, "scalar00", "reject00")
                conditional = update(base, "scalar00", "cond0000")
                conditional["ConditionExpression"] = "attribute_not_exists(pk)"
                checked("false-condition-under-pressure", "update-item", conditional, base, "scalar00", "cond0000")
                batch = record("batch-large-delete-small-sibling", "batch-write-item", {"RequestItems": {base: [{"DeleteRequest": {"Key": {"pk": {"S": "batch000"}}}}, {"PutRequest": {"Item": {"pk": {"S": "sibling0"}, "mark": {"S": "batch000"}}}}]}, "ReturnConsumedCapacity": "INDEXES"})
                batch_large = verify("batch-large-mutation-check", base, "batch000")
                batch_small = verify("batch-sibling-mutation-check", base, "sibling0")
                capture["mutationChecks"].append({"label": "batch-large-delete-small-sibling", "mutationSequence": batch["sequence"], "verificationSequences": [batch_large["sequence"], batch_small["sequence"]]})
                transaction = update(base, "transact", "trans000")
                transaction.pop("ReturnValues")
                transaction.pop("ReturnConsumedCapacity")
                checked("transaction-under-pressure", "transact-write-items", {"TransactItems": [{"Update": transaction}, {"Put": {"TableName": base, "Item": {"pk": {"S": "txsibling"}, "mark": {"S": "trans000"}}}}], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)}, base, "transact", "trans000")
                verify("transaction-sibling-mutation-check", base, "txsibling")
                statement = {"Statement": f'UPDATE "{base}" SET "mark"=? WHERE "pk"=?', "Parameters": [{"S": "part0000"}, {"S": "partiql0"}], "ReturnConsumedCapacity": "INDEXES"}
                checked("partiql-under-pressure", "execute-statement", statement, base, "partiql0", "part0000")
                record("partiql-batch-under-pressure", "batch-execute-statement", {"Statements": [{"Statement": statement["Statement"], "Parameters": [{"S": "part0001"}, {"S": "partiql0"}]}], "ReturnConsumedCapacity": "INDEXES"})
                verify("partiql-batch-mutation-check", base, "partiql0")
                statement.pop("ReturnConsumedCapacity")
                statement["Parameters"][0] = {"S": "part0002"}
                record("partiql-transaction-under-pressure", "execute-transaction", {"TransactStatements": [statement], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)})
                verify("partiql-transaction-mutation-check", base, "partiql0")
                mixed_pressure(record, base)
            else:
                for number in range(4):
                    rows = wave(indexed, "indexed0", "gsi-pressure", number)
                    if any(row["code"] != "Success" for row in rows):
                        break
                for attempt in range(3):
                    checked("gsi-projected-under-pressure-" + str(attempt), "update-item", update(indexed, "indexed0", f"proj{attempt:04}"), indexed, "indexed0", f"proj{attempt:04}")
                    checked("gsi-unchanged-projection-" + str(attempt), "update-item", update(indexed, "indexed0", f"note{attempt:04}", "note"), indexed, "indexed0", f"note{attempt:04}", "note")
                    checked("gsi-sparse-under-pressure-" + str(attempt), "update-item", update(indexed, "sparse00", f"sprs{attempt:04}"), indexed, "sparse00", f"sprs{attempt:04}")
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = str(error)
        raise
    finally:
        for table in created:
            cleanup = {"verifiedAbsent": False}
            capture["cleanup"][table] = cleanup
            try:
                row = record("delete-owned-" + table.rsplit("-", 1)[-1], "delete-table", {"TableName": table})
                if row["code"] not in ("Success", "ResourceNotFoundException"):
                    raise RuntimeError("deletion rejected: " + row["code"])
                for attempt in range(90):
                    row = record("verify-absent-" + table.rsplit("-", 1)[-1] + "-" + str(attempt), "describe-table", {"TableName": table})
                    if row["code"] == "ResourceNotFoundException":
                        cleanup.update(verifiedAbsent=True, callSequence=row["sequence"], verifiedAt=row["finishedAt"])
                        break
                    time.sleep(2)
                if not cleanup["verifiedAbsent"]:
                    raise RuntimeError("absence was not observed")
            except Exception as error:
                cleanup["error"] = str(error)
        capture["finishedAt"] = timestamp()
        save()
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"]}))
    if any(not row["verifiedAbsent"] for row in capture["cleanup"].values()):
        raise RuntimeError("owned-resource cleanup failed; see exact table identifiers in fixture")


if __name__ == "__main__":
    main()
