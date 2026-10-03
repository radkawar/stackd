#!/usr/bin/env python3
"""Capture bounded native PartiQL capacity; --summarize reads a capture offline."""
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
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LSI.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteTransaction.html",
]


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sized_item(pk, sk, size, indexed=False):
    """All-string ASCII item: exact logical bytes, excluding storage overhead."""
    values = {"pk": pk, "sk": sk, "payload": ""}
    if indexed:
        values.update(g="group", l=sk, flag="yes" if int(sk) % 2 else "no")
    used = sum(len(key.encode()) + len(value.encode()) for key, value in values.items())
    if size < used:
        raise ValueError("item size smaller than attributes")
    values["payload"] = "x" * (size - used)
    return {key: {"S": value} for key, value in values.items()}


def summarize(capture):
    """Copy native capacity fields; never turn an omitted field into zero."""
    result = []
    for row in capture["calls"]:
        if row["operation"] not in ("execute-statement", "batch-execute-statement", "execute-transaction", "query", "scan", "get-item"):
            continue
        out = row.get("output", {})
        result.append({
            "sequence": row["sequence"], "label": row["label"], "code": row["code"],
            "capacity": out.get("ConsumedCapacity"),
            "itemCount": len(out["Items"]) if "Items" in out else None,
            "responseErrors": [response.get("Error") for response in out.get("Responses", [])],
            "hasNextToken": "NextToken" in out, "hasLastEvaluatedKey": "LastEvaluatedKey" in out,
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", help="Required for native capture; unused by --summarize")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/partiql_capacity.json"))
    parser.add_argument("--summarize", type=pathlib.Path, help="offline: print observed capacity without AWS calls")
    args = parser.parse_args()
    if args.summarize:
        print(json.dumps(summarize(json.loads(args.summarize.read_text())), indent=2))
        return
    if not args.account:
        parser.error("--account is required for native capture")
    if args.output.exists():
        parser.error("refusing to overwrite a native capture; choose a new --output")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    table = "stackd-pql-cap-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    quoted = '"' + table + '"'
    capture = {
        "source": "native AWS DynamoDB through scripts/aws/aws_cli.py observe",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table,
        "documentation": SOURCES, "calls": [], "pages": {}, "cleanup": {},
        "experiment": {
            "billingMode": "PAY_PER_REQUEST", "gsi": "by-g", "gsiProjection": "KEYS_ONLY",
            "lsi": "by-l", "lsiProjection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["flag"]},
            "cliMaxAttempts": 1, "pagination": "CLI autopagination disabled; NextToken copied verbatim into bounded subsequent requests",
            "itemSizes": {"A": [1023, 1024, 1025, 4095, 4096, 4097], "B": [1500, 1500]},
            "sizeRule": "All seed attributes are ASCII strings. Size is sum of UTF-8 attribute-name and value bytes; storage/index overhead is not included.",
        },
        "limitations": [
            "Raw requests and modeled responses are CLI JSON, not HTTP bytes. Missing ConsumedCapacity is unknown, never zero.",
            "No CloudWatch observations: failure-path capacity omitted by native responses cannot be inferred here.",
            "A single tiny table does not establish physical-partition scan overhead for large or sparse tables.",
            "Only recorded ASCII-string sizes, access paths and predicates were exercised; not arbitrary PartiQL semantic equivalence.",
            "Limit pages are covered; no 1 MiB response/evaluated-data boundary is exercised.",
            "GSI reads are eventually consistent; readiness observations and returned counts are recorded, not assumed.",
        ],
    }

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, operation, parameters, service="dynamodb"):
        row = {"sequence": len(capture["calls"]) + 1, "label": label, "service": service,
               "operation": operation, "input": parameters, "startedAt": timestamp()}
        capture["calls"].append(row)
        start = time.monotonic()
        try:
            row.update(observe(service, operation, parameters, env, paginate=False))
        except Exception as error:
            row.update(code="CaptureError", captureError=str(error))
            raise
        finally:
            row.update(finishedAt=timestamp(), durationSeconds=round(time.monotonic() - start, 6))
            save()
        return row

    def require(row):
        if row["code"] != "Success":
            raise RuntimeError(row["label"] + ": " + row["code"])
        return row["output"]

    def statement(text, parameters=None, **extra):
        request = {"Statement": text, **extra}
        if parameters:
            request["Parameters"] = parameters
        return request

    def execute(label, text, parameters=None, **extra):
        return record(label, "execute-statement", statement(text, parameters, ReturnConsumedCapacity="INDEXES", **extra))

    def pages(label, text, **extra):
        sequences = []
        capture["pages"][label] = sequences
        token = None
        for number in range(12):
            request = dict(extra)
            if token:
                request["NextToken"] = token
            row = execute(label + "-page-" + str(number + 1), text, **request)
            sequences.append(row["sequence"])
            output = require(row)
            token = output.get("NextToken")
            if not token:
                return
        raise RuntimeError("pagination bound exceeded: " + label)

    created = False
    try:
        identity = require(record("caller-identity", "get-caller-identity", {}, "sts"))
        if identity["Account"] != args.account:
            raise RuntimeError("refusing unapproved AWS account")
        require(record("create-owned-table", "create-table", {
            "TableName": table, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": key, "AttributeType": "S"} for key in ("pk", "sk", "g", "l")],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            "GlobalSecondaryIndexes": [{"IndexName": "by-g", "KeySchema": [{"AttributeName": "g", "KeyType": "HASH"}], "Projection": {"ProjectionType": "KEYS_ONLY"}}],
            "LocalSecondaryIndexes": [{"IndexName": "by-l", "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "l", "KeyType": "RANGE"}], "Projection": capture["experiment"]["lsiProjection"]}],
        }))
        created = True
        for attempt in range(45):
            description = require(record("table-ready-" + str(attempt), "describe-table", {"TableName": table}))["Table"]
            if description["TableStatus"] == "ACTIVE" and all(index["IndexStatus"] == "ACTIVE" for index in description.get("GlobalSecondaryIndexes", [])):
                break
            time.sleep(2)
        else:
            raise RuntimeError("table readiness bound exceeded")
        for pk, sizes in capture["experiment"]["itemSizes"].items():
            for number, size in enumerate(sizes, 1):
                require(record("seed-" + pk + "-" + str(number) + "-bytes-" + str(size), "put-item", {
                    "TableName": table, "Item": sized_item(pk, f"{number:02}", size, indexed=True), "ReturnConsumedCapacity": "INDEXES",
                }))
        for attempt in range(15):
            out = require(execute("gsi-ready-" + str(attempt), f'SELECT pk, sk FROM {quoted}."by-g" WHERE g=\'group\''))
            if len(out.get("Items", [])) == 8:
                break
            time.sleep(1)
        else:
            raise RuntimeError("GSI visibility bound exceeded")

        # Full-key equality, partition query and scan are deliberately distinct.
        for number in range(1, 7):
            execute("point-A-" + str(number) + "-strong", f"SELECT * FROM {quoted} WHERE pk='A' AND sk='{number:02}'", ConsistentRead=True)
        execute("point-A-6-eventual", f"SELECT * FROM {quoted} WHERE pk='A' AND sk='06'")
        execute("point-A-6-projected", f"SELECT pk FROM {quoted} WHERE pk='A' AND sk='06'", ConsistentRead=True)
        execute("point-A-6-filter-none", f"SELECT pk FROM {quoted} WHERE pk='A' AND sk='06' AND flag='never'", ConsistentRead=True)
        execute("point-missing-strong", f"SELECT * FROM {quoted} WHERE pk='A' AND sk='missing'", ConsistentRead=True)
        execute("point-missing-eventual", f"SELECT * FROM {quoted} WHERE pk='missing' AND sk='missing'")
        execute("partition-missing", f"SELECT * FROM {quoted} WHERE pk='missing'", ConsistentRead=True)
        for label, where in (("partition-A", " WHERE pk='A'"), ("partition-B", " WHERE pk='B'"), ("scan", "")):
            for suffix, projection, predicate in (("full", "*", ""), ("projected", "pk, sk", ""), ("filter-some", "pk, sk", "flag='yes'"), ("filter-none", "pk, sk", "flag='never'")):
                clause = where + ((" AND " if where else " WHERE ") + predicate if predicate else "")
                execute(label + "-" + suffix + "-strong", f"SELECT {projection} FROM {quoted}{clause}", ConsistentRead=True)
            execute(label + "-projected-eventual", f"SELECT pk, sk FROM {quoted}{where}")
        pages("partition-A-limit2-full", f"SELECT * FROM {quoted} WHERE pk='A'", ConsistentRead=True, Limit=2)
        pages("partition-A-limit2-projected", f"SELECT pk, sk FROM {quoted} WHERE pk='A'", ConsistentRead=True, Limit=2)
        pages("partition-A-limit2-filter-none", f"SELECT pk FROM {quoted} WHERE pk='A' AND flag='never'", ConsistentRead=True, Limit=2)
        pages("scan-limit2-filter-none", f"SELECT pk FROM {quoted} WHERE flag='never'", ConsistentRead=True, Limit=2)
        pages("in-partitions", f"SELECT pk, sk FROM {quoted} WHERE pk IN ['A','B']", ConsistentRead=True)
        pages("in-point-keys", f"SELECT pk, sk FROM {quoted} WHERE pk IN ['A','B'] AND sk='01'", ConsistentRead=True)
        for index, where in (("by-g", "g='group'"), ("by-l", "pk='A'")):
            for suffix, projection, predicate in (("full", "*", ""), ("keys", "pk, sk", ""), ("payload", "pk, payload", ""), ("filter-none", "pk", " AND flag='never'")):
                execute(index + "-" + suffix, f'SELECT {projection} FROM {quoted}."{index}" WHERE {where}{predicate}', **({"ConsistentRead": True} if index == "by-l" else {}))
            pages(index + "-limit2-keys", f'SELECT pk, sk FROM {quoted}."{index}" WHERE {where}', Limit=2, **({"ConsistentRead": True} if index == "by-l" else {}))
        execute("by-l-payload-eventual", f'SELECT payload FROM {quoted}."by-l" WHERE pk=\'A\'')
        execute("by-l-payload-filter-none", f'SELECT payload FROM {quoted}."by-l" WHERE pk=\'A\' AND flag=\'never\'', ConsistentRead=True)
        record("classic-lsi-fetch-control", "query", {"TableName": table, "IndexName": "by-l", "KeyConditionExpression": "pk=:pk", "ExpressionAttributeValues": {":pk": {"S": "A"}}, "ProjectionExpression": "payload", "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES"})

        reads = [statement(f"SELECT pk FROM {quoted} WHERE pk='A' AND sk='{sk}'", ConsistentRead=True) for sk in ("01", "06", "missing")]
        record("batch-reads-strong", "batch-execute-statement", {"Statements": reads, "ReturnConsumedCapacity": "INDEXES"})
        record("batch-reads-eventual", "batch-execute-statement", {"Statements": [{**read, "ConsistentRead": False} for read in reads], "ReturnConsumedCapacity": "INDEXES"})
        record("transaction-reads", "execute-transaction", {"TransactStatements": [{key: value for key, value in read.items() if key != "ConsistentRead"} for read in reads], "ReturnConsumedCapacity": "INDEXES"})

        def insert(pk, sk, size):
            item = sized_item(pk, sk, size)
            return statement(f"INSERT INTO {quoted} VALUE {{'pk': ?, 'sk': ?, 'payload': ?}}", [item["pk"], item["sk"], item["payload"]])

        write = insert("W", "01", 1024)
        execute("insert-1024", write["Statement"], write["Parameters"])
        execute("insert-duplicate", write["Statement"], write["Parameters"], ReturnValuesOnConditionCheckFailure="ALL_OLD")
        execute("update-grow-4097-returning", f"UPDATE {quoted} SET payload=? WHERE pk='W' AND sk='01' RETURNING ALL NEW *", [sized_item("W", "01", 4097)["payload"]])
        execute("update-condition-failure", f"UPDATE {quoted} SET payload='no' WHERE pk='W' AND sk='01' AND payload='no'", ReturnValuesOnConditionCheckFailure="ALL_OLD")
        execute("update-shrink-1023-returning", f"UPDATE {quoted} SET payload=? WHERE pk='W' AND sk='01' RETURNING ALL OLD *", [sized_item("W", "01", 1023)["payload"]])
        execute("delete-1023-returning", f"DELETE FROM {quoted} WHERE pk='W' AND sk='01' RETURNING ALL OLD *")
        execute("delete-missing", f"DELETE FROM {quoted} WHERE pk='W' AND sk='01'")
        record("batch-inserts-boundary", "batch-execute-statement", {"Statements": [insert("BW", "01", 1024), insert("BW", "02", 1025)], "ReturnConsumedCapacity": "INDEXES"})
        record("batch-update-delete-returning", "batch-execute-statement", {"Statements": [statement(f"UPDATE {quoted} SET payload='x' WHERE pk='BW' AND sk='01' RETURNING ALL OLD *"), statement(f"DELETE FROM {quoted} WHERE pk='BW' AND sk='02' RETURNING ALL OLD *")], "ReturnConsumedCapacity": "INDEXES"})
        record("batch-partial-condition-failure", "batch-execute-statement", {"Statements": [statement(f"UPDATE {quoted} SET payload='bad' WHERE pk='BW' AND sk='01' AND payload='never'", ReturnValuesOnConditionCheckFailure="ALL_OLD"), insert("BW", "03", 1025)], "ReturnConsumedCapacity": "INDEXES"})
        record("transaction-inserts-boundary", "execute-transaction", {"TransactStatements": [insert("TW", "01", 1024), insert("TW", "02", 1025)], "ReturnConsumedCapacity": "INDEXES"})
        record("transaction-update-delete", "execute-transaction", {"TransactStatements": [statement(f"UPDATE {quoted} SET payload='x' WHERE pk='TW' AND sk='01'"), statement(f"DELETE FROM {quoted} WHERE pk='TW' AND sk='02'")], "ReturnConsumedCapacity": "INDEXES"})
        record("transaction-condition-failure", "execute-transaction", {"TransactStatements": [statement(f"UPDATE {quoted} SET payload='bad' WHERE pk='TW' AND sk='01' AND payload='never'", ReturnValuesOnConditionCheckFailure="ALL_OLD"), insert("TW", "03", 1025)], "ReturnConsumedCapacity": "INDEXES"})
        execute("transaction-cancellation-state", f"SELECT * FROM {quoted} WHERE pk='TW'", ConsistentRead=True)
        capture["completedAt"] = timestamp()
    finally:
        try:
            if created:
                deletion = record("delete-owned-table", "delete-table", {"TableName": table})
                capture["cleanup"]["deleteCallSequence"] = deletion["sequence"]
                for attempt in range(45):
                    absent = record("verify-owned-table-absent-" + str(attempt), "describe-table", {"TableName": table})
                    if absent["code"] == "ResourceNotFoundException":
                        capture["cleanup"].update(verifiedAbsent=True, verificationCallSequence=absent["sequence"], verifiedAt=absent["finishedAt"])
                        break
                    time.sleep(2)
                else:
                    raise RuntimeError("owned table deletion not verified")
        finally:
            capture["summary"] = summarize(capture)
            capture["finishedAt"] = timestamp()
            save()
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"]}))


if __name__ == "__main__":
    main()
