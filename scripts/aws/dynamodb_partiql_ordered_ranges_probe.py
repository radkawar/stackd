#!/usr/bin/env python3
"""Capture native ordered finite sort-key ranges, evaluation limits, and capacity."""
import argparse
import datetime
import json
import os
import pathlib
import secrets
import time

from aws_cli import observe


REGION = "us-east-1"


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/partiql_ordered_ranges.json"))
    parser.add_argument("--cases", choices=("ranges", "compound"), default="ranges")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture; choose a new --output")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
               AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false",
               AWS_ENDPOINT_URL_DYNAMODB="https://dynamodb.us-east-1.amazonaws.com",
               AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    table = "stackd-pql-ranges-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    quoted = '"' + table + '"'
    capture = {
        "source": "native AWS DynamoDB through scripts/aws/aws_cli.py observe",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table,
        "ownedTables": [table], "calls": [], "pages": {}, "cleanup": {},
        "documentation": [
            "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html",
            "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html",
            "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html",
        ],
        "experiment": {
            "caseGroup": args.cases,
            "billingMode": "PAY_PER_REQUEST", "keySchema": {"pk": "S", "sk": "N"},
            "partitions": ["a", "b"],
            "seedPayloadBytesBySortKey": {"-2": 1000, "2": 4200, "10": 8100, "20": 12500},
            "seedFlagBySortKey": {"-2": "yes", "2": "no", "10": "yes", "20": "no"},
            "nativeEnvironment": {key: env[key] for key in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_MAX_ATTEMPTS", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "AWS_ENDPOINT_URL_DYNAMODB", "AWS_ENDPOINT_URL_STS")},
            "pagination": "CLI autopagination disabled; native NextToken copied verbatim; at most 24 requests per chain. Rejected first requests end their chain without asserting support.",
        },
        "limitations": [
            "Native CLI JSON inputs/responses, not raw HTTP bytes; absent capacity is unknown, never zero.",
            "No CloudWatch observations or inferred minimum charges for missing keys.",
            "Payload byte counts exclude attribute names and other values; capacity remains the exact native response.",
            "Only concrete recorded predicates establish admission; OR and IN are not assumed equivalent.",
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

    def pages(label, where, order="sk ASC", parameters=None, projection="pk, sk", **extra):
        text = f"SELECT {projection} FROM {quoted} WHERE {where}"
        if order is not None:
            text += " ORDER BY " + order
        request = {"Statement": text, "ReturnConsumedCapacity": "INDEXES", "ConsistentRead": True, **extra}
        if parameters is not None:
            request["Parameters"] = parameters
        sequences = []
        capture["pages"][label] = sequences
        for number in range(24):
            row = record(label + "-page-" + str(number + 1), "execute-statement", dict(request))
            sequences.append(row["sequence"])
            if row["code"] != "Success":
                if number:
                    raise RuntimeError("continuation rejected: " + label)
                return
            token = row["output"].get("NextToken")
            if not token:
                return
            request["NextToken"] = token
        raise RuntimeError("pagination bound exceeded: " + label)

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
        for pk in capture["experiment"]["partitions"]:
            for sk, size in capture["experiment"]["seedPayloadBytesBySortKey"].items():
                require(record("seed-" + pk + "-" + sk, "put-item", {"TableName": table, "Item": {
                    "pk": {"S": pk}, "sk": {"N": sk}, "payload": {"S": "x" * size},
                    "flag": {"S": capture["experiment"]["seedFlagBySortKey"][sk]},
                }, "ReturnConsumedCapacity": "INDEXES"}))
            pages("seed-state-" + pk, f"pk='{pk}'", projection="pk, sk, flag")

        if args.cases == "compound":
            for label, where in [
                ("strict-bounds", "pk='a' AND sk>-2 AND sk<20"),
                ("inclusive-bounds", "pk='a' AND sk>=2 AND sk<=10"),
                ("mixed-bounds", "pk='a' AND sk>2 AND sk<=20"),
                ("redundant-lower-bound", "pk='a' AND sk>2 AND sk>10"),
                ("between-and-bound", "pk='a' AND sk BETWEEN -2 AND 20 AND sk<10"),
                ("contradictory-bounds", "pk='a' AND sk>20 AND sk<2"),
                ("same-sort-equality", "pk='a' AND sk=2 AND sk=2"),
                ("equivalent-sort-equality", "pk='a' AND sk=2 AND sk=2.0"),
                ("different-sort-equality", "pk='a' AND sk=2 AND sk=10"),
                ("equality-and-bound", "pk='a' AND sk=2 AND sk>=2"),
                ("sort-in-and-bound", "pk='a' AND sk IN [-2,2,10,20] AND sk>2"),
                ("same-hash-equality", "pk='a' AND pk='a'"),
                ("different-hash-equality", "pk='a' AND pk='b'"),
                ("hash-in-and-equality", "pk IN ['a','b'] AND pk='a'"),
                ("disjoint-intervals", "pk='a' AND (sk<3 OR sk>=10)"),
                ("overlapping-intervals", "pk='a' AND (sk<=10 OR sk>=10)"),
                ("between-overlap", "pk='a' AND (sk BETWEEN -2 AND 10 OR sk=10)"),
                ("negated-sort-equality", "pk='a' AND NOT sk=2"),
                ("unequal-sort-key", "pk='a' AND sk<>2"),
                ("mixed-key-filter-or", "pk='a' AND (sk=10 OR flag='yes')"),
                ("branch-local-filters", "(pk='a' AND sk=2 AND flag='no') OR (pk='b' AND sk=10 AND flag='yes')"),
                ("same-sort-in", "pk='a' AND sk IN [2,10] AND sk IN [2,10]"),
                ("reordered-sort-in", "pk='a' AND sk IN [2,10] AND sk IN [10,2]"),
                ("equivalent-sort-in", "pk='a' AND sk IN [2,10] AND sk IN [2.0,10.0]"),
                ("intersecting-sort-in", "pk='a' AND sk IN [2,10] AND sk IN [10,20]"),
                ("same-hash-in", "pk IN ['a','b'] AND pk IN ['a','b']"),
                ("reordered-hash-in", "pk IN ['a','b'] AND pk IN ['b','a']"),
                ("singleton-hash-in-and-equality", "pk IN ['a'] AND pk='a'"),
                ("singleton-sort-in-and-equality", "pk='a' AND sk IN [2] AND sk=2"),
                ("equivalent-lower-bound", "pk='a' AND sk>2 AND sk>2.0"),
            ]:
                pages(label, where, "pk ASC, sk ASC")
                pages(label + "-unordered", where, None)
        else:
            for direction in ("ASC", "DESC"):
                suffix = direction.lower()
                pages("sparse-in-" + suffix, "pk='a' AND sk IN [20,-2]", "sk " + direction)
                pages("sparse-in-" + suffix + "-limit1", "pk='a' AND sk IN [20,-2]", "sk " + direction, Limit=1)
                pages("sparse-between-" + suffix + "-limit1", "pk='a' AND sk BETWEEN -2 AND 20", "sk " + direction, Limit=1)
                pages("missing-only-" + suffix, "pk='a' AND sk IN [7,8]", "sk " + direction, Limit=1)
                for variant, where, parameters in [
                    ("unsorted", "pk='a' AND sk IN [20,2,-2,10]", None),
                    ("duplicates-missing", "pk='a' AND sk IN [20,7,2,-2,2,10,7]", None),
                    ("numeric-equivalent", "pk='a' AND sk IN [2,2.0,2e0,20,-2]", None),
                    ("missing", "pk='a' AND sk IN [20,7,2,-2,10]", None),
                    ("parameterized", "pk=? AND sk IN [?,?,?,?,?]", [{"S": "a"}, {"N": "20"}, {"N": "7"}, {"N": "2.0"}, {"N": "-2"}, {"N": "10"}]),
                    ("parameterized-duplicates", "pk=? AND sk IN [?,?,?]", [{"S": "a"}, {"N": "2"}, {"N": "2.0"}, {"N": "2e0"}]),
                ]:
                    pages(variant + "-" + suffix, where, "sk " + direction, parameters)
                    for limit in (1, 2):
                        pages(variant + "-" + suffix + "-limit" + str(limit), where, "sk " + direction, parameters, Limit=limit)
                for limit in (1, 2):
                    pages("filtered-empty-" + suffix + "-limit" + str(limit), "pk='a' AND sk IN [20,7,2,-2,10] AND flag='never'", "sk " + direction, Limit=limit)
                pages("filtered-some-" + suffix + "-limit1", "pk='a' AND sk IN [20,7,2,-2,10] AND flag='yes'", "sk " + direction, Limit=1)
                pages("combined-pk-sk-in-" + suffix + "-limit2", "pk IN ['b','a'] AND sk IN [20,7,-2]", "pk " + direction + ", sk " + direction, Limit=2)
                pages("sort-or-" + suffix + "-limit1", "pk='a' AND (sk=20 OR sk=-2)", "sk " + direction, Limit=1)
                pages("sort-or-duplicate-" + suffix, "pk='a' AND (sk=20 OR sk=-2 OR sk=20)", "sk " + direction)
                pages("full-key-or-" + suffix + "-limit1", "(pk='a' AND sk=20) OR (pk='a' AND sk=-2)", "sk " + direction, Limit=1)
                pages("sparse-in-" + suffix + "-eventual-limit1", "pk='a' AND sk IN [20,-2]", "sk " + direction, ConsistentRead=False)

            for label, where, order in [
                ("sparse-in-unordered", "pk='a' AND sk IN [20,-2]", None),
                ("singleton-sort-in", "pk='a' AND sk IN [2]", "sk ASC"),
                ("empty-sort-in", "pk='a' AND sk IN []", "sk ASC"),
                ("wrong-type-sort-in", "pk='a' AND sk IN ['2']", "sk ASC"),
                ("nonkey-order", "pk='a' AND sk IN [2,20]", "flag ASC"),
                ("sk-only-order-multiple-pk", "pk IN ['b','a'] AND sk IN [20,-2]", "sk ASC"),
                ("no-order-sort-or", "pk='a' AND (sk=20 OR sk=-2)", None),
            ]:
                pages(label, where, order)
            for sk in (-2, 2, 10, 20, 7):
                pages("point-equality-" + str(sk), f"pk='a' AND sk={sk}", None)
            pages("missing-partition-sort-in", "pk='missing' AND sk IN [20,-2,7]", "sk ASC", Limit=1)
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
