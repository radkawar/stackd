#!/usr/bin/env python3
"""Capture native PartiQL ordered partition-IN traversal and per-page consumption."""
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
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/partiql_ordered_partitions.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture; choose a new --output")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
               AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false",
               AWS_ENDPOINT_URL_DYNAMODB="https://dynamodb.us-east-1.amazonaws.com",
               AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    suffix = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    table = "stackd-pql-partitions-" + suffix
    numeric_table = "stackd-pql-numeric-" + suffix
    quoted = '"' + table + '"'
    numeric_quoted = '"' + numeric_table + '"'
    seeds = [("B", 30, 5000), ("A", 10, 4200), ("B", 2, 12500),
             ("A", 30, 8400), ("B", 10, 1000), ("A", 2, 100)]
    capture = {
        "source": "native AWS DynamoDB through scripts/aws/aws_cli.py observe",
        "startedAt": timestamp(), "account": args.account, "region": REGION,
        "table": table, "ownedTables": [table, numeric_table], "calls": [], "pages": {}, "cleanup": {},
        "experiment": {
            "billingMode": "PAY_PER_REQUEST", "keySchema": {"pk": "S", "sk": "N"},
            "numericTable": numeric_table, "numericKeySchema": {"pk": "N", "sk": "N"},
            "nativeEnvironment": {key: env[key] for key in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_MAX_ATTEMPTS", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "AWS_ENDPOINT_URL_DYNAMODB", "AWS_ENDPOINT_URL_STS")},
            "seedInsertionOrder": [{"pk": pk, "sk": sk, "payloadBytes": size, "flag": "yes" if sk == 10 else "no"} for pk, sk, size in seeds],
            "missingStringPartition": "AA", "missingNumericPartition": 3,
            "pagination": "CLI autopagination disabled; NextToken copied verbatim into bounded subsequent requests; each chain records exact call sequences",
        },
        "limitations": [
            "Native CLI JSON inputs/responses, not raw HTTP bytes. Absent capacity is unknown, never zero.",
            "No CloudWatch observations or inference about rejected-request capacity.",
            "Payload bytes exclude attribute names and other values; exact native capacity is retained rather than inferred from payload alone.",
            "Small primary-key tables only; no index, large 1MiB page, concurrent mutation, or token expiry claims.",
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

    def pages(label, text, **extra):
        sequences = []
        capture["pages"][label] = sequences
        token = None
        for number in range(32):
            request = {"Statement": text, "ReturnConsumedCapacity": "INDEXES", **extra}
            if token:
                request["NextToken"] = token
            row = record(label + "-page-" + str(number + 1), "execute-statement", request)
            sequences.append(row["sequence"])
            if row["code"] != "Success":
                return
            token = row["output"].get("NextToken")
            if not token:
                return
        raise RuntimeError("pagination bound exceeded: " + label)

    created = []
    try:
        identity = require(record("caller-identity", "get-caller-identity", {}, "sts"))
        if identity["Account"] != args.account or identity["Arn"].split("/")[-1] != "Delegated":
            raise RuntimeError("refusing unapproved account or caller")
        capture["nativeEndpointVerifiedBeforeMutation"] = dict(capture["experiment"]["nativeEnvironment"])
        for owned, key_type in ((table, "S"), (numeric_table, "N")):
            require(record("create-" + key_type + "-owned-table", "create-table", {
                "TableName": owned, "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": key_type}, {"AttributeName": "sk", "AttributeType": "N"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            }))
            created.append(owned)
            for attempt in range(45):
                if require(record("ready-" + key_type + "-" + str(attempt), "describe-table", {"TableName": owned}))["Table"]["TableStatus"] == "ACTIVE":
                    break
                time.sleep(2)
            else:
                raise RuntimeError("table readiness bound exceeded")
        for pk, sk, size in seeds:
            require(record("seed-string-" + pk + "-" + str(sk), "put-item", {
                "TableName": table, "Item": {"pk": {"S": pk}, "sk": {"N": str(sk)},
                    "payload": {"S": "x" * size}, "flag": {"S": "yes" if sk == 10 else "no"}},
                "ReturnConsumedCapacity": "INDEXES",
            }))
        for pk, sk in ((10, 10), (2, 2), (-2, 10), (10, 2), (2, 10), (-2, 2)):
            require(record("seed-numeric-" + str(pk) + "-" + str(sk), "put-item", {
                "TableName": numeric_table, "Item": {"pk": {"N": str(pk)}, "sk": {"N": str(sk)}},
                "ReturnConsumedCapacity": "INDEXES",
            }))
        base = f"FROM {quoted} WHERE pk IN ['B','AA','A']"
        for pk_direction, sk_direction in (("ASC", "ASC"), ("ASC", "DESC"), ("DESC", "ASC"), ("DESC", "DESC")):
            pages("string-full-" + pk_direction.lower() + "-" + sk_direction.lower(),
                  f"SELECT * {base} ORDER BY pk {pk_direction}, sk {sk_direction}", ConsistentRead=True)
        pages("string-pk-only-asc", f"SELECT pk, sk {base} ORDER BY pk ASC", ConsistentRead=True)
        pages("string-pk-only-desc", f"SELECT pk, sk {base} ORDER BY pk DESC", ConsistentRead=True)
        pages("string-pk-only-default-limit2", f"SELECT pk, sk {base} ORDER BY pk", ConsistentRead=True, Limit=2)
        pages("string-sk-only", f"SELECT pk, sk {base} ORDER BY sk ASC", ConsistentRead=True)
        pages("string-limit1-asc-asc", f"SELECT * {base} ORDER BY pk ASC, sk ASC", ConsistentRead=True, Limit=1)
        pages("string-limit1-desc-desc", f"SELECT pk, sk {base} ORDER BY pk DESC, sk DESC", ConsistentRead=True, Limit=1)
        pages("string-limit2-asc-desc", f"SELECT pk, sk {base} ORDER BY pk ASC, sk DESC", ConsistentRead=True, Limit=2)
        pages("string-limit2-desc-asc", f"SELECT pk, sk {base} ORDER BY pk DESC, sk ASC", ConsistentRead=True, Limit=2)
        pages("string-limit2-filter-empty", f"SELECT pk, sk {base} AND flag='never' ORDER BY pk ASC, sk DESC", ConsistentRead=True, Limit=2)
        pages("string-limit2-filter-some", f"SELECT sk {base} AND flag='yes' ORDER BY pk ASC, sk DESC", ConsistentRead=True, Limit=2)
        pages("string-limit2-eventual", f"SELECT pk, sk {base} ORDER BY pk ASC, sk DESC", ConsistentRead=False, Limit=2)
        pages("string-full-eventual", f"SELECT pk, sk {base} ORDER BY pk ASC, sk DESC", ConsistentRead=False)
        pages("string-duplicate-list-limit2", f"SELECT pk, sk FROM {quoted} WHERE pk IN ['B','A','AA','A','B','AA'] ORDER BY pk ASC, sk ASC", ConsistentRead=True, Limit=2)
        pages("string-parameter-elements-limit2", f"SELECT pk, sk FROM {quoted} WHERE pk IN [?,?,?] ORDER BY pk DESC, sk ASC", ConsistentRead=True, Limit=2, Parameters=[{"S": "A"}, {"S": "AA"}, {"S": "B"}])
        pages("string-parameter-list", f"SELECT pk, sk FROM {quoted} WHERE pk IN ? ORDER BY pk ASC, sk DESC", ConsistentRead=True, Parameters=[{"L": [{"S": "B"}, {"S": "AA"}, {"S": "A"}]}])
        pages("missing-only-strong-limit1", f"SELECT pk, sk FROM {quoted} WHERE pk IN ['AA','Z'] ORDER BY pk ASC, sk ASC", ConsistentRead=True, Limit=1)
        pages("missing-only-eventual", f"SELECT pk, sk FROM {quoted} WHERE pk IN ['AA','Z'] ORDER BY pk ASC, sk ASC", ConsistentRead=False)
        pages("control-single-partition", f"SELECT pk, sk FROM {quoted} WHERE pk='A' ORDER BY sk DESC", ConsistentRead=True)
        pages("control-no-missing-partition", f"SELECT pk, sk FROM {quoted} WHERE pk IN ['B','A'] ORDER BY pk ASC, sk DESC", ConsistentRead=True)
        or_base = f"FROM {quoted} WHERE pk='B' OR pk='AA' OR pk='A'"
        pages("string-or-full", f"SELECT pk, sk {or_base} ORDER BY pk ASC, sk DESC", ConsistentRead=True)
        pages("string-or-limit2", f"SELECT pk, sk {or_base} ORDER BY pk ASC, sk DESC", ConsistentRead=True, Limit=2)
        pages("control-scan-order", f"SELECT pk, sk FROM {quoted} ORDER BY pk ASC, sk ASC", ConsistentRead=True)
        pages("control-nonkey-order", f"SELECT pk, sk {base} ORDER BY pk ASC, flag ASC", ConsistentRead=True)
        pages("control-reversed-order-keys", f"SELECT pk, sk {base} ORDER BY sk ASC, pk ASC", ConsistentRead=True)
        numeric_base = f"FROM {numeric_quoted} WHERE pk IN [10,3,2,-2]"
        pages("numeric-full-asc-desc", f"SELECT * {numeric_base} ORDER BY pk ASC, sk DESC", ConsistentRead=True)
        pages("numeric-limit2-desc-asc", f"SELECT * {numeric_base} ORDER BY pk DESC, sk ASC", ConsistentRead=True, Limit=2)
        capture["pageObservations"] = {
            label: [{"callSequence": sequence, "code": capture["calls"][sequence - 1]["code"],
                     **({"keysInReturnedOrder": [{key: item[key] for key in ("pk", "sk") if key in item} for item in capture["calls"][sequence - 1]["output"].get("Items", [])],
                         "outputFields": list(capture["calls"][sequence - 1]["output"]),
                         "consumedCapacity": capture["calls"][sequence - 1]["output"].get("ConsumedCapacity")}
                        if capture["calls"][sequence - 1]["code"] == "Success" else {})}
                    for sequence in sequences]
            for label, sequences in capture["pages"].items()
        }
        capture["completedAt"] = timestamp()
    finally:
        cleanup_errors = []
        for owned in reversed(created):
            cleanup = capture["cleanup"].setdefault(owned, {})
            try:
                deletion = record("delete-" + owned, "delete-table", {"TableName": owned})
                cleanup["deleteCallSequence"] = deletion["sequence"]
                for attempt in range(45):
                    absent = record("verify-absent-" + owned + "-" + str(attempt), "describe-table", {"TableName": owned})
                    if absent["code"] == "ResourceNotFoundException":
                        cleanup.update(verifiedAbsent=True, verificationCallSequence=absent["sequence"], verifiedAt=absent["finishedAt"])
                        break
                    require(absent)
                    time.sleep(2)
                else:
                    raise RuntimeError("owned table deletion not verified")
            except Exception as error:
                cleanup["error"] = str(error)
                cleanup_errors.append(str(error))
            finally:
                capture["finishedAt"] = timestamp()
                save()
        capture["finishedAt"] = timestamp()
        save()
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"]}))


if __name__ == "__main__":
    main()
