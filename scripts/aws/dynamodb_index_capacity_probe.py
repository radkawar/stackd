#!/usr/bin/env python3
"""Capture bounded native table/LSI/GSI write and transaction capacity evidence."""
import argparse
import copy
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
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LSI.html#LSI.ThroughputConsiderations.Writes",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html#GSI.ThroughputConsiderations.Writes",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html",
]


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def size(item):
    """These inputs contain ASCII string attributes only, not storage overhead."""
    return sum(len(name.encode()) + len(value["S"].encode()) for name, value in item.items())


def sizes(item):
    if item is None:
        return None
    result = {"table": size(item), "indexEntries": None}
    if "x" in item:
        result["indexEntries"] = {
            "keys": size({key: item[key] for key in ("pk", "sk", "x")}),
            "include": size({key: item[key] for key in ("pk", "sk", "x", "p") if key in item}),
            "all": size(item),
        }
    return result


def item(pk, total=None, projected=None, x=None, p="a", q=None):
    result = {"pk": {"S": pk}, "sk": {"S": "0"}, "p": {"S": p}}
    if x is not None:
        result["x"] = {"S": x}
    if projected is not None:
        result["p"] = {"S": "a" * (projected - size(result) + len(p))}
    if q is not None:
        result["q"] = {"S": q}
    if total is not None:
        result["p"] = {"S": "a" * (total - size(result) + len(result["p"]["S"]))}
    if total is not None and size(result) != total:
        raise ValueError("invalid exact-size input")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/index_capacity.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    table = "stackd-ddb-indexcap-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    capture = {
        "source": "native AWS DynamoDB through scripts/aws/aws_cli.py observe",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table,
        "documentation": SOURCES, "calls": [], "cleanup": {"verifiedAbsent": False},
        "experiment": {
            "billingMode": "PAY_PER_REQUEST", "cliMaxAttempts": 1,
            "indexDesign": "Three LSIs and three GSIs share x as index key; each family has KEYS_ONLY, INCLUDE(p), ALL. Their projected entry bytes match across families.",
            "sizeDefinition": "Sum of UTF-8 attribute-name and string-value bytes; all input strings are ASCII. No 100-byte storage overhead is added. Null old/new means absent item; null indexEntries means sparse exclusion.",
            "comparison": "scalar00, batch000, trans000 have equal-length keys and identical state transitions. updsca00 and updtxn00 likewise compare scalar UpdateItem with transactional Update.",
            "publication": "Not queried; this fixture captures returned capacity only.",
        },
        "limitations": [
            "One small on-demand regional table; no throttling, global tables, multi-attribute GSI keys, or metric publication.",
            "Missing capacity fields or missing index entries in a response remain unknown, not synthetic zero.",
            "Observed factors apply only to the recorded successful actions and item/index sizes; canceled transaction capacity is not inferred from success.",
            "Read/write direction is recorded only when AWS returns directional fields; scalar API CapacityUnits fields are preserved without invented direction fields.",
            "Client timestamps bracket CLI calls, not internal AWS execution. Identical-token replay occurs within the documented ten-minute window.",
        ],
    }

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, operation, parameters, service="dynamodb", expected="Success", evidence=None):
        row = {"sequence": len(capture["calls"]) + 1, "label": label, "service": service,
               "operation": operation, "startedAt": timestamp(), "input": copy.deepcopy(parameters)}
        if evidence is not None:
            row["experiment"] = evidence
        capture["calls"].append(row)
        try:
            row.update(observe(service, operation, parameters, env, paginate=False))
        finally:
            row["finishedAt"] = timestamp()
            save()
        if expected is not None and row["code"] != expected:
            raise RuntimeError(label + ": " + row["code"])
        if row.get("output", {}).get("UnprocessedItems"):
            raise RuntimeError(label + ": unprocessed items; do not infer complete capacity")
        return row

    state = {}

    def write_action(label, mode, action, pk, new=None):
        old = state.get(pk)
        key = {"pk": {"S": pk}, "sk": {"S": "0"}}
        body = {"TableName": table}
        if action == "Put":
            body["Item"] = new
        else:
            body["Key"] = key
        if action == "Update":
            names, values, sets, removes = {}, {}, [], []
            for name in sorted((set(old or {}) | set(new)) - {"pk", "sk"}):
                names["#" + name] = name
                if name in new:
                    values[":" + name] = new[name]
                    sets.append("#" + name + " = :" + name)
                else:
                    removes.append("#" + name)
            body["UpdateExpression"] = " ".join(part for part in ["SET " + ", ".join(sets) if sets else "", "REMOVE " + ", ".join(removes) if removes else ""] if part)
            body["ExpressionAttributeNames"] = names
            if values:
                body["ExpressionAttributeValues"] = values
        if mode == "scalar":
            operation = {"Put": "put-item", "Update": "update-item", "Delete": "delete-item"}[action]
            parameters = {**body, "ReturnConsumedCapacity": "INDEXES"}
        elif mode == "batch":
            operation = "batch-write-item"
            parameters = {"RequestItems": {table: [{action + "Request": {key: value for key, value in body.items() if key != "TableName"}}]}, "ReturnConsumedCapacity": "INDEXES"}
        else:
            operation = "transact-write-items"
            parameters = {"TransactItems": [{action: body}], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)}
        row = record(label, operation, parameters, evidence={"before": sizes(old), "after": sizes(new)})
        state[pk] = new
        return row

    created = False
    try:
        caller = record("caller-identity", "get-caller-identity", {}, service="sts")
        if caller["output"]["Account"] != args.account:
            raise RuntimeError("refusing native probe in unapproved account")
        schema = [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}]
        definitions = [{"AttributeName": name, "AttributeType": "S"} for name in ("pk", "sk", "x")]
        indexes = {"LocalSecondaryIndexes": [], "GlobalSecondaryIndexes": []}
        for family, field in [("lsi", "LocalSecondaryIndexes"), ("gsi", "GlobalSecondaryIndexes")]:
            for name, projection in [("keys", {"ProjectionType": "KEYS_ONLY"}), ("include", {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["p"]}), ("all", {"ProjectionType": "ALL"})]:
                keys = [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "x", "KeyType": "RANGE"}] if family == "lsi" else [{"AttributeName": "x", "KeyType": "HASH"}]
                indexes[field].append({"IndexName": family + "-" + name, "KeySchema": keys, "Projection": projection})
        result = record("create-owned-table", "create-table", {"TableName": table, "BillingMode": "PAY_PER_REQUEST", "AttributeDefinitions": definitions, "KeySchema": schema, **indexes}, expected=None)
        created = result["code"] == "Success"
        if not created:
            raise RuntimeError("table creation failed: " + result["code"])
        for attempt in range(90):
            description = record("table-ready-" + str(attempt), "describe-table", {"TableName": table})["output"]["Table"]
            if description["TableStatus"] == "ACTIVE" and all(index["IndexStatus"] == "ACTIVE" for index in description.get("GlobalSecondaryIndexes", [])):
                break
            time.sleep(2)
        else:
            raise RuntimeError("table readiness timed out")

        # Sparse base-table boundaries isolate table charges from index maintenance.
        pk = "base0000"
        for label, action, new in [
            ("insert-1024", "Put", item(pk, total=1024)),
            ("overwrite-grow-1025", "Put", item(pk, total=1025)),
            ("overwrite-shrink-1024", "Put", item(pk, total=1024)),
            ("overwrite-identical-1024", "Put", item(pk, total=1024)),
            ("update-grow-1025", "Update", item(pk, total=1025)),
            ("update-shrink-1024", "Update", item(pk, total=1024)),
            ("update-identical-1024", "Update", item(pk, total=1024)),
            ("delete-1024", "Delete", None), ("delete-missing", "Delete", None),
        ]:
            write_action("base-" + label, "scalar", action, pk, new)

        for mode, pk in [("scalar", "scalar00"), ("batch", "batch000"), ("transaction", "trans000")]:
            small = item(pk, projected=1024, x="A", q="q" * 500)
            large = item(pk, projected=2049, x="B", q="q" * 500)
            unprojected = copy.deepcopy(small)
            unprojected["q"] = {"S": "r" * 500}
            for label, action, new in [
                ("insert-include1024", "Put", small),
                ("overwrite-identical", "Put", small),
                ("overwrite-nonprojected-change", "Put", unprojected),
                ("move-key-grow-include2049", "Put", large),
                ("move-key-shrink-include1024", "Put", small),
                ("sparse-leave", "Put", {key: value for key, value in small.items() if key != "x"}),
                ("sparse-enter", "Put", small),
                ("delete-indexed", "Delete", None),
                ("delete-missing", "Delete", None),
            ]:
                write_action(mode + "-" + label, mode, action, pk, new)

        for mode, pk in [("scalar", "updsca00"), ("transaction", "updtxn00")]:
            small = item(pk, projected=1024, x="A", q="q" * 500)
            changed = copy.deepcopy(small)
            changed["p"] = {"S": "b" * len(changed["p"]["S"])}
            nonprojected = copy.deepcopy(small)
            nonprojected["q"] = {"S": "r" * 500}
            for label, action, new in [
                ("seed-include1024", "Put", small),
                ("identical-values", "Update", small),
                ("nonprojected-change", "Update", nonprojected),
                ("projected-change-same-size", "Update", changed),
                ("projected-grow-1025", "Update", item(pk, projected=1025, x="A", q="q" * 500)),
                ("projected-shrink-1024", "Update", small),
                ("move-key-grow-2049", "Update", item(pk, projected=2049, x="B", q="q" * 500)),
                ("move-key-shrink-1024", "Update", small),
                ("sparse-leave", "Update", {key: value for key, value in small.items() if key != "x"}),
                ("sparse-enter", "Update", small),
            ]:
                write_action(mode + "-update-" + label, mode, action, pk, new)

        pk = "allbound"
        for boundary in (1024, 1025):
            write_action("all-projection-put-" + str(boundary), "scalar", "Put", pk, item(pk, total=boundary, x="A"))
        write_action("all-projection-delete-1025", "scalar", "Delete", pk)

        for boundary in (4096, 4097):
            pk = "read" + str(boundary)
            write_action("condition-seed-" + str(boundary), "scalar", "Put", pk, item(pk, total=boundary))
            key = {"pk": {"S": pk}, "sk": {"S": "0"}}
            record("strong-get-" + str(boundary), "get-item", {"TableName": table, "Key": key, "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES"})
            record("transaction-condition-only-" + str(boundary), "transact-write-items", {
                "TransactItems": [{"ConditionCheck": {"TableName": table, "Key": key, "ConditionExpression": "attribute_exists(pk)"}}],
                "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16),
            })
        record("transaction-condition-missing", "transact-write-items", {
            "TransactItems": [{"ConditionCheck": {"TableName": table, "Key": {"pk": {"S": "missing0"}, "sk": {"S": "0"}}, "ConditionExpression": "attribute_not_exists(pk)"}}],
            "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16),
        })
        mixed = {
            "TransactItems": [
                {"Put": {"TableName": table, "Item": item("mixedput", total=1025, x="A")}},
                {"Update": {"TableName": table, "Key": {"pk": {"S": "updsca00"}, "sk": {"S": "0"}}, "UpdateExpression": "SET q = :q", "ExpressionAttributeValues": {":q": {"S": "z" * 500}}}},
                {"Delete": {"TableName": table, "Key": {"pk": {"S": "updtxn00"}, "sk": {"S": "0"}}}},
                {"ConditionCheck": {"TableName": table, "Key": {"pk": {"S": "read4097"}, "sk": {"S": "0"}}, "ConditionExpression": "attribute_exists(pk)"}},
            ],
            "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16),
        }
        record("transaction-mixed-put-update-delete-condition", "transact-write-items", mixed)
        record("transaction-identical-token-replay", "transact-write-items", mixed)
        mismatch = copy.deepcopy(mixed)
        mismatch["TransactItems"][0]["Put"]["Item"]["p"]["S"] = "changed"
        record("transaction-changed-payload-token-mismatch", "transact-write-items", mismatch, expected="IdempotentParameterMismatchException")
        failed = {"TransactItems": [{"ConditionCheck": {"TableName": table, "Key": {"pk": {"S": "read4097"}, "sk": {"S": "0"}}, "ConditionExpression": "attribute_not_exists(pk)", "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}}], "ReturnConsumedCapacity": "INDEXES", "ClientRequestToken": secrets.token_hex(16)}
        record("transaction-condition-failed-4097", "transact-write-items", failed, expected="TransactionCanceledException")
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = str(error)
        raise
    finally:
        if created:
            result = record("delete-owned-table", "delete-table", {"TableName": table}, expected=None)
            if result["code"] not in ("Success", "ResourceNotFoundException"):
                raise RuntimeError("owned table deletion failed: " + result["code"])
            for attempt in range(90):
                result = record("verify-owned-table-absent-" + str(attempt), "describe-table", {"TableName": table}, expected=None)
                if result["code"] == "ResourceNotFoundException":
                    capture["cleanup"] = {"verifiedAbsent": True, "callSequence": result["sequence"], "verifiedAt": result["finishedAt"]}
                    break
                time.sleep(2)
            else:
                raise RuntimeError("owned table absence was not verified")
        capture["observations"] = [
            {"sequence": row["sequence"], "label": row["label"], "code": row.get("code"), "consumedCapacity": row.get("output", {}).get("ConsumedCapacity")}
            for row in capture["calls"] if row["input"].get("ReturnConsumedCapacity") == "INDEXES"
        ]
        capture["finishedAt"] = timestamp()
        save()
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"]}))


if __name__ == "__main__":
    main()
