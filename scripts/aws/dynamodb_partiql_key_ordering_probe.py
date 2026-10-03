#!/usr/bin/env python3
"""Capture native PartiQL ordered-page capacity and concrete key-expression admission."""
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
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.insert.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.size.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html",
]


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/partiql_key_ordering.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture; choose a new --output")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
               AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false",
               AWS_ENDPOINT_URL_DYNAMODB="https://dynamodb.us-east-1.amazonaws.com",
               AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    table = "stackd-pql-key-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    quoted = '"' + table + '"'
    capture = {
        "source": "native AWS DynamoDB through scripts/aws/aws_cli.py observe",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table,
        "documentation": SOURCES, "calls": [], "pages": {}, "keyForms": [], "cleanup": {},
        "experiment": {
            "billingMode": "PAY_PER_REQUEST", "keySchema": {"pk": "S", "sk": "N"},
            "nativeEnvironment": {key: env[key] for key in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_MAX_ATTEMPTS", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "AWS_ENDPOINT_URL_DYNAMODB", "AWS_ENDPOINT_URL_STS")},
            "seedPayloadBytesBySortKey": {"10": 1000, "20": 2000, "30": 8000, "40": 12000},
            "seedFlagBySortKey": {"10": "yes", "20": "no", "30": "yes", "40": "no"},
            "pagination": "CLI autopagination disabled; every NextToken copied verbatim into a bounded subsequent request",
            "expressionScope": "Only primary-key admission: documented addition/subtraction, scalar controls, and one concatenation, SIZE, and CAST boundary each. SQL concatenation and CAST are not advertised in DynamoDB's supported operator/function lists; SIZE documents a path argument, not a literal. Rejections are not support.",
        },
        "limitations": [
            "Native CLI JSON inputs/responses, not raw HTTP bytes. Absent capacity is unknown, never zero.",
            "No CloudWatch observations or inference about rejected-request capacity.",
            "Payload byte counts exclude attribute names and other attribute values; capacity is the exact native response, not inferred from payload alone.",
            "Only recorded concrete expressions are established; no general PartiQL evaluator or arbitrary equivalence is inferred.",
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
            row.update(code="CaptureError", error={"Message": str(error)})
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
        for number in range(10):
            request = dict(extra)
            if token:
                request["NextToken"] = token
            row = execute(label + "-page-" + str(number + 1), text, **request)
            sequences.append(row["sequence"])
            token = require(row).get("NextToken")
            if not token:
                return
        raise RuntimeError("pagination bound exceeded: " + label)

    def read_key(label, pk, sk):
        return record(label, "get-item", {"TableName": table, "Key": {"pk": {"S": pk}, "sk": {"N": str(sk)}},
                                            "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES"})

    created = False
    try:
        identity = require(record("caller-identity", "get-caller-identity", {}, "sts"))
        if identity["Account"] != args.account or identity["Arn"].split("/")[-1] != "Delegated":
            raise RuntimeError("refusing unapproved account or caller")
        capture["nativeEndpointVerifiedBeforeMutation"] = dict(capture["experiment"]["nativeEnvironment"])
        require(record("create-owned-table", "create-table", {
            "TableName": table, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "N"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        }))
        created = True
        for attempt in range(45):
            if require(record("table-ready-" + str(attempt), "describe-table", {"TableName": table}))["Table"]["TableStatus"] == "ACTIVE":
                break
            time.sleep(2)
        else:
            raise RuntimeError("table readiness bound exceeded")
        for sk, size in capture["experiment"]["seedPayloadBytesBySortKey"].items():
            require(record("seed-order-" + sk, "put-item", {"TableName": table, "Item": {
                "pk": {"S": "order"}, "sk": {"N": sk}, "payload": {"S": "x" * size},
                "flag": {"S": capture["experiment"]["seedFlagBySortKey"][sk]},
            }, "ReturnConsumedCapacity": "INDEXES"}))
        require(execute("seed-state", f"SELECT pk, sk, flag FROM {quoted} WHERE pk='order'", ConsistentRead=True))
        for direction in ("ASC", "DESC"):
            pages("order-" + direction.lower() + "-limit1-full", f"SELECT * FROM {quoted} WHERE pk='order' ORDER BY sk {direction}", ConsistentRead=True, Limit=1)
            pages("order-" + direction.lower() + "-limit2-projected", f"SELECT pk, sk FROM {quoted} WHERE pk='order' ORDER BY sk {direction}", ConsistentRead=True, Limit=2)
            pages("order-" + direction.lower() + "-limit2-filter-empty", f"SELECT pk, sk FROM {quoted} WHERE pk='order' AND flag='never' ORDER BY sk {direction}", ConsistentRead=True, Limit=2)
            pages("order-" + direction.lower() + "-limit1-sort-only", f"SELECT sk FROM {quoted} WHERE pk='order' ORDER BY sk {direction}", ConsistentRead=True, Limit=1)
        pages("order-desc-limit1-filter-some", f"SELECT pk, sk FROM {quoted} WHERE pk='order' AND flag='yes' ORDER BY sk DESC", ConsistentRead=True, Limit=1)
        pages("order-desc-limit2-projected-eventual", f"SELECT pk, sk FROM {quoted} WHERE pk='order' ORDER BY sk DESC", Limit=2)
        for ascending in (True, False):
            record("classic-query-" + ("asc" if ascending else "desc") + "-first-page", "query", {
                "TableName": table, "KeyConditionExpression": "pk=:pk", "ExpressionAttributeValues": {":pk": {"S": "order"}},
                "ScanIndexForward": ascending, "Limit": 2, "ProjectionExpression": "pk, sk", "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES",
            })

        inserts = [
            ("literal-control", "'literal'", "100", None, "literal", 100),
            ("parameter-control", "?", "?", [{"S": "parameter"}, {"N": "100"}], "parameter", 100),
            ("numeric-add", "'numeric-add'", "100 + 1", None, "numeric-add", 101),
            ("numeric-parameter-add", "?", "? + ?", [{"S": "numeric-param"}, {"N": "100"}, {"N": "2"}], "numeric-param", 102),
            ("numeric-subtract", "'numeric-subtract'", "105 - 2", None, "numeric-subtract", 103),
            ("parenthesized-literal", "('parenthesized')", "(104)", None, "parenthesized", 104),
            ("string-concat-boundary", "'string-' || 'concat'", "105", None, "string-concat", 105),
            ("size-function-boundary", "'size-function'", "size('abcd')", None, "size-function", 4),
            ("cast-boundary", "CAST(106 AS STRING)", "106", None, "106", 106),
        ]
        for label, pkexpr, skexpr, parameters, pk, sk in inserts:
            row = execute("insert-" + label, f"INSERT INTO {quoted} VALUE {{'pk': {pkexpr}, 'sk': {skexpr}, 'payload': 'inserted'}}", parameters)
            state = read_key("insert-" + label + "-state", pk, sk)
            require(state)
            capture["keyForms"].append({"family": "insert", "form": label, "callSequence": row["sequence"], "stateCallSequence": state["sequence"]})
        require(record("seed-batch-control", "put-item", {"TableName": table, "Item": {
            "pk": {"S": "batch"}, "sk": {"N": "201"}, "payload": {"S": "before"},
        }, "ReturnConsumedCapacity": "INDEXES"}))
        forms = [
            ("literal-control", "pk='batch' AND sk=201", None),
            ("parameter-control", "pk=? AND sk=?", [{"S": "batch"}, {"N": "201"}]),
            ("parenthesized-equality", "(pk='batch') AND (sk=201)", None),
            ("reversed-equality", "'batch'=pk AND 201=sk", None),
            ("or-wrapped-partition-equality", "(pk='batch' OR pk='batch') AND sk=201", None),
            ("or-wrapped-full-key-equality", "(pk='batch' AND sk=201) OR (pk='batch' AND sk=201)", None),
            ("singleton-partition-in", "pk IN ['batch'] AND sk=201", None),
            ("singleton-sort-in", "pk='batch' AND sk IN [201]", None),
            ("singleton-both-in", "pk IN ['batch'] AND sk IN [201]", None),
            ("parameter-singleton-in", "pk IN [?] AND sk IN [?]", [{"S": "batch"}, {"N": "201"}]),
        ]
        for label, where, parameters in forms:
            row = record("batch-read-" + label, "batch-execute-statement", {"Statements": [statement(f"SELECT * FROM {quoted} WHERE {where}", parameters, ConsistentRead=True)], "ReturnConsumedCapacity": "INDEXES"})
            capture["keyForms"].append({"family": "batch-read", "form": label, "callSequence": row["sequence"]})
            update = record("batch-update-" + label, "batch-execute-statement", {"Statements": [statement(f"UPDATE {quoted} SET payload='{label}' WHERE {where}", parameters)], "ReturnConsumedCapacity": "INDEXES"})
            state = read_key("batch-update-" + label + "-state", "batch", 201)
            require(state)
            capture["keyForms"].append({"family": "batch-update", "form": label, "callSequence": update["sequence"], "stateCallSequence": state["sequence"]})
        require(record("final-state", "scan", {"TableName": table, "ProjectionExpression": "pk, sk", "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES"}))
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
                    require(absent)
                    time.sleep(2)
                else:
                    raise RuntimeError("owned table deletion not verified")
        finally:
            capture["finishedAt"] = timestamp()
            save()
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"]}))


if __name__ == "__main__":
    main()
