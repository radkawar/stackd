#!/usr/bin/env python3
"""Capture native transaction token identity and retained replay capacity, or summarize offline."""
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
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteTransaction.html",
]


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sized_item(pk, size):
    """Exact ASCII logical bytes, excluding storage overhead; only string values."""
    return {"pk": {"S": pk}, "payload": {"S": "x" * (size - len(pk) - len("pkpayload"))}}


def reverse_maps(value):
    if isinstance(value, dict):
        return {key: reverse_maps(item) for key, item in reversed(list(value.items()))}
    if isinstance(value, list):
        return [reverse_maps(item) for item in value]
    return value


def summarize(capture):
    return [{"sequence": row["sequence"], "label": row["label"], "code": row["code"],
             "capacity": row.get("output", {}).get("ConsumedCapacity")}
            for row in capture["calls"] if row["operation"] in ("transact-write-items", "execute-transaction")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", help="Required for native capture; unused by --summarize")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/transaction_tokens.json"))
    parser.add_argument("--summarize", type=pathlib.Path, help="offline: emit recorded transaction results")
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
    # Service-specific endpoints take precedence even over environment/config overrides.
    env.update(AWS_ENDPOINT_URL_DYNAMODB="https://dynamodb.us-east-1.amazonaws.com", AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    prefix = "stackd-tx-token-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    tables = [prefix + "-a", prefix + "-b"]
    table = tables[0]
    capture = {
        "source": "native AWS DynamoDB through scripts/aws/aws_cli.py observe",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "table": table, "tables": tables,
        "documentation": SOURCES, "calls": [], "cleanup": {},
        "experiment": {
            "billingMode": "PAY_PER_REQUEST", "cliMaxAttempts": 1,
            "endpoints": {"dynamodb": env["AWS_ENDPOINT_URL_DYNAMODB"], "sts": env["AWS_ENDPOINT_URL_STS"]},
            "sizeRule": "ASCII string attribute names and values summed; excludes storage overhead.",
            "retentionMatrix": "Individual Put/Update/Delete/ConditionCheck at 4096 and 4097 bytes; immediate replay, scalar overwrite with 16385 bytes, replay, scalar removal, replay. Update shrinks to 100 bytes. Mixed transaction has distinct before/after sizes.",
        },
        "limitations": [
            "CLI input JSON and modeled native output/errors, not raw HTTP bytes. Map insertion order is preserved in recorded inputs.",
            "No capacity is assumed on errors or when ConsumedCapacity is omitted; CloudWatch failure-path consumption is not measured.",
            "Ten-minute expiry is documented, not wall-clock tested. All comparisons must be interpreted with their recorded timestamps.",
            "Only the approved account and region were tested; no cross-account, cross-region, index, in-flight, or expiry scope inference.",
            "Equivalent numeric strings and map order are sampled; this is not an exhaustive semantic canonicalization specification.",
        ],
    }

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, operation, parameters, service="dynamodb"):
        row = {"sequence": len(capture["calls"]) + 1, "label": label, "service": service,
               "operation": operation, "input": copy.deepcopy(parameters), "startedAt": timestamp()}
        capture["calls"].append(row)
        started = time.monotonic()
        try:
            row.update(observe(service, operation, parameters, env, paginate=False))
        except Exception as error:
            row.update(code="CaptureError", captureError=str(error))
            raise
        finally:
            row.update(finishedAt=timestamp(), durationSeconds=round(time.monotonic() - started, 6))
            save()
        return row

    def require(row):
        if row["code"] != "Success":
            raise RuntimeError(row["label"] + ": " + row["code"])
        return row["output"]

    def key(pk):
        return {"pk": {"S": pk}}

    def put(label, pk, size):
        return require(record(label, "put-item", {"TableName": table, "Item": sized_item(pk, size), "ReturnConsumedCapacity": "INDEXES"}))

    def remove(label, pk):
        return require(record(label, "delete-item", {"TableName": table, "Key": key(pk), "ReturnConsumedCapacity": "INDEXES"}))

    def read_state(label, pk):
        return require(record(label, "get-item", {"TableName": table, "Key": key(pk), "ConsistentRead": True, "ReturnConsumedCapacity": "INDEXES"}))

    def tx(actions, **extra):
        return {"TransactItems": actions, "ClientRequestToken": secrets.token_hex(16), "ReturnConsumedCapacity": "INDEXES", **extra}

    def action(kind, pk, size):
        value = {"TableName": table}
        if kind == "Put":
            value["Item"] = sized_item(pk, size)
        else:
            value["Key"] = key(pk)
        if kind == "Update":
            value.update(UpdateExpression="SET payload=:p", ExpressionAttributeValues={":p": sized_item(pk, 100)["payload"]})
        if kind == "ConditionCheck":
            value["ConditionExpression"] = "attribute_exists(pk)"
        return {kind: value}

    def classic(label, request):
        return record(label, "transact-write-items", request)

    def pql_request(pk, token=None, target=None):
        return {"ClientRequestToken": token or secrets.token_hex(16), "ReturnConsumedCapacity": "INDEXES",
                "TransactStatements": [{"Statement": 'INSERT INTO "' + (target or table) + '" VALUE {\'pk\': ?, \'n\': ?, \'meta\': ?}',
                                        "Parameters": [{"S": pk}, {"N": "1"}, {"M": {"a": {"S": "A"}, "b": {"S": "B"}}}]}]}

    def pql(label, request):
        return record(label, "execute-transaction", request)

    owned = []
    try:
        identity = require(record("caller-identity", "get-caller-identity", {}, "sts"))
        if identity["Account"] != args.account:
            raise RuntimeError("refusing unapproved AWS account")
        for target in tables:
            created = record("create-owned-table-" + target[-1], "create-table", {
                "TableName": target, "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            })
            require(created)
            owned.append(target)
            for attempt in range(45):
                description = require(record("table-ready-" + target[-1] + "-" + str(attempt), "describe-table", {"TableName": target}))
                if description["Table"]["TableStatus"] == "ACTIVE":
                    break
                time.sleep(2)
            else:
                raise RuntimeError("table readiness bound exceeded")

        # Different old/new sizes distinguish before-image, after-image and max-write-size retention.
        for pk, size in (("mixed-put", 8193), ("mixed-update", 4097), ("mixed-delete", 8193), ("mixed-check", 4097)):
            put("seed-" + pk, pk, size)
        mixed = tx([action("Put", "mixed-put", 4095), action("Update", "mixed-update", 100),
                    action("Delete", "mixed-delete", 0), action("ConditionCheck", "mixed-check", 0)])
        require(classic("mixed-initial", mixed))
        require(classic("mixed-replay-immediate", mixed))
        for pk in ("mixed-put", "mixed-update", "mixed-delete", "mixed-check"):
            put("external-grow-" + pk, pk, 16385)
        require(classic("mixed-replay-after-external-grow", mixed))
        for pk in ("mixed-put", "mixed-update", "mixed-delete", "mixed-check"):
            read_state("mixed-state-after-grow-replay-" + pk, pk)
            remove("external-remove-" + pk, pk)
        require(classic("mixed-replay-after-external-remove", mixed))
        for pk in ("mixed-put", "mixed-update", "mixed-delete", "mixed-check"):
            read_state("mixed-state-after-remove-replay-" + pk, pk)

        for kind in ("Put", "Update", "Delete", "ConditionCheck"):
            for size in (4096, 4097):
                label = kind.lower() + "-" + str(size)
                if kind != "Put":
                    put(label + "-seed", label, size)
                request = tx([action(kind, label, size)])
                require(classic(label + "-initial", request))
                require(classic(label + "-replay-immediate", request))
                put(label + "-external-grow", label, 16385)
                require(classic(label + "-replay-after-grow", request))
                remove(label + "-external-remove", label)
                require(classic(label + "-replay-after-remove", request))
                read_state(label + "-state-after-remove-replay", label)

        base = tx([{"Put": {"TableName": table, "Item": {"pk": {"S": "equality"}, "n": {"N": "1"},
                                                                      "meta": {"M": {"a": {"S": "A"}, "b": {"S": "B"}}}}}},
                   {"Delete": {"TableName": table, "Key": key("equality-missing")}}])
        require(classic("equality-initial", base))
        classic("equality-reversed-maps", reverse_maps(base))
        for mode in ("TOTAL", "NONE"):
            classic("equality-capacity-" + mode.lower(), {**base, "ReturnConsumedCapacity": mode})
        for mode in ("NONE", "SIZE"):
            classic("equality-collection-" + mode.lower(), {**base, "ReturnItemCollectionMetrics": mode})
        explicit = copy.deepcopy(base)
        for operation in explicit["TransactItems"]:
            next(iter(operation.values()))["ReturnValuesOnConditionCheckFailure"] = "NONE"
        classic("equality-condition-return-explicit-none", explicit)
        for number in ("1.0", "1e0", "01", "+1"):
            changed = copy.deepcopy(base)
            changed["TransactItems"][0]["Put"]["Item"]["n"]["N"] = number
            classic("equality-number-" + number, changed)
        classic("equality-item-order-reversed", {**base, "TransactItems": list(reversed(base["TransactItems"]))})
        classic("equality-original-after-variants", base)
        default = tx([action("Put", "defaults", 100)])
        default.pop("ReturnConsumedCapacity")
        require(classic("defaults-omitted-initial", default))
        classic("defaults-capacity-explicit-none", {**default, "ReturnConsumedCapacity": "NONE"})
        classic("defaults-collection-explicit-none", {**default, "ReturnItemCollectionMetrics": "NONE"})
        classic("defaults-capacity-added-indexes", {**default, "ReturnConsumedCapacity": "INDEXES"})

        # Same token, different table; then both API orderings with different items.
        scoped = tx([action("Put", "table-scope", 100)])
        require(classic("scope-table-a-initial", scoped))
        changed = copy.deepcopy(scoped)
        changed["TransactItems"][0]["Put"]["TableName"] = tables[1]
        classic("scope-table-b-same-token", changed)
        shared = tx([action("Put", "namespace-classic-first", 100)])
        require(classic("namespace-classic-first", shared))
        other = pql_request("namespace-pql-second", shared["ClientRequestToken"])
        pql("namespace-pql-after-classic-same-token", other)
        classic("namespace-classic-original-replay", shared)
        other = pql_request("namespace-pql-first")
        require(pql("namespace-pql-first", other))
        shared = tx([action("Put", "namespace-classic-second", 100)], ClientRequestToken=other["ClientRequestToken"])
        classic("namespace-classic-after-pql-same-token", shared)
        pql("namespace-pql-original-replay", other)

        pbase = pql_request("pql-equality")
        require(pql("pql-equality-initial", pbase))
        pql("pql-equality-replay", pbase)
        pql("pql-equality-reversed-maps", reverse_maps(pbase))
        for mode in ("TOTAL", "NONE"):
            pql("pql-equality-capacity-" + mode.lower(), {**pbase, "ReturnConsumedCapacity": mode})
        for number in ("1.0", "1e0", "01", "+1"):
            changed = copy.deepcopy(pbase)
            changed["TransactStatements"][0]["Parameters"][1]["N"] = number
            pql("pql-equality-number-" + number, changed)
        changed = copy.deepcopy(pbase)
        changed["TransactStatements"][0]["ReturnValuesOnConditionCheckFailure"] = "NONE"
        pql("pql-equality-condition-return-explicit-none", changed)
        changed = copy.deepcopy(pbase)
        changed["TransactStatements"][0]["Statement"] += " "
        pql("pql-equality-statement-trailing-space", changed)
        pdefault = pql_request("pql-defaults")
        pdefault.pop("ReturnConsumedCapacity")
        require(pql("pql-defaults-omitted-initial", pdefault))
        pql("pql-defaults-capacity-explicit-none", {**pdefault, "ReturnConsumedCapacity": "NONE"})
        pql("pql-defaults-capacity-added-indexes", {**pdefault, "ReturnConsumedCapacity": "INDEXES"})
        porder = pql_request("pql-order-a")
        porder["TransactStatements"] += pql_request("pql-order-b")["TransactStatements"]
        require(pql("pql-order-initial", porder))
        pql("pql-order-reversed", {**porder, "TransactStatements": list(reversed(porder["TransactStatements"]))})
        pql("pql-order-original-replay", porder)
        changed = copy.deepcopy(pbase)
        changed["TransactStatements"][0]["Statement"] = changed["TransactStatements"][0]["Statement"].replace(table, tables[1])
        pql("pql-scope-table-b-same-token", changed)

        # PartiQL replay retention on a >4KiB item, then independently changed and removed.
        large = pql_request("pql-retention")
        large["TransactStatements"] = [{"Statement": 'INSERT INTO "' + table + '" VALUE {\'pk\': ?, \'payload\': ?}',
                                        "Parameters": [key("pql-retention")["pk"], sized_item("pql-retention", 4097)["payload"]]}]
        require(pql("pql-retention-initial-4097", large))
        require(pql("pql-retention-replay-immediate", large))
        put("pql-retention-external-grow", "pql-retention", 16385)
        require(pql("pql-retention-replay-after-grow", large))
        read_state("pql-retention-state-after-grow-replay", "pql-retention")
        remove("pql-retention-external-remove", "pql-retention")
        require(pql("pql-retention-replay-after-remove", large))
        read_state("pql-retention-state-after-remove-replay", "pql-retention")

        for mode in ("same", "changed"):
            pk = "canceled-" + mode
            canceled = tx([{"Put": {"TableName": table, "Item": sized_item(pk, 100), "ConditionExpression": "attribute_exists(pk)"}}])
            classic(pk + "-first", canceled)
            if mode == "same":
                put(pk + "-external-seed", pk, 100)
                corrected = canceled
            else:
                corrected = copy.deepcopy(canceled)
                corrected["TransactItems"][0]["Put"].pop("ConditionExpression")
            classic(pk + "-reuse", corrected)
            classic(pk + "-replay", corrected)
            if mode == "changed":
                put(pk + "-repair-original-condition", pk, 100)
                classic(pk + "-original-after-state-repair", canceled)
        invalid = tx([{"Update": {"TableName": table, "Key": key("validation"), "UpdateExpression": "SET"}}])
        classic("validation-first", invalid)
        corrected = tx([action("Put", "validation", 100)], ClientRequestToken=invalid["ClientRequestToken"])
        classic("validation-reuse", corrected)
        classic("validation-replay", corrected)

        for mode in ("same", "changed"):
            pk = "pql-canceled-" + mode
            put(pk + "-seed", pk, 100)
            canceled = pql_request(pk)
            pql(pk + "-first", canceled)
            if mode == "same":
                remove(pk + "-external-remove", pk)
                corrected = canceled
            else:
                corrected = copy.deepcopy(canceled)
                corrected["TransactStatements"][0]["Parameters"][0]["S"] += "-new"
            pql(pk + "-reuse", corrected)
            pql(pk + "-replay", corrected)
            if mode == "changed":
                remove(pk + "-repair-original-condition", pk)
                pql(pk + "-original-after-state-repair", canceled)
        invalid = pql_request("pql-validation")
        invalid["TransactStatements"][0]["Statement"] = "NOT A VALID STATEMENT"
        pql("pql-validation-first", invalid)
        corrected = pql_request("pql-validation", invalid["ClientRequestToken"])
        pql("pql-validation-reuse", corrected)
        pql("pql-validation-replay", corrected)
        capture["completedAt"] = timestamp()
    finally:
        try:
            cleanup_errors = []
            for target in owned:
                status = capture["cleanup"].setdefault(target, {})
                try:
                    deletion = record("delete-owned-table-" + target[-1], "delete-table", {"TableName": target})
                    status["deleteCallSequence"] = deletion["sequence"]
                    for attempt in range(45):
                        absent = record("verify-owned-table-absent-" + target[-1] + "-" + str(attempt), "describe-table", {"TableName": target})
                        if absent["code"] == "ResourceNotFoundException":
                            status.update(verifiedAbsent=True, verificationCallSequence=absent["sequence"], verifiedAt=absent["finishedAt"])
                            break
                        time.sleep(2)
                    else:
                        raise RuntimeError("owned table deletion not verified: " + target)
                except Exception as error:
                    status["error"] = str(error)
                    cleanup_errors.append(str(error))
            if cleanup_errors:
                raise RuntimeError("; ".join(cleanup_errors))
        finally:
            capture["summary"] = summarize(capture)
            capture["finishedAt"] = timestamp()
            save()
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "cleanup": capture["cleanup"]}))


if __name__ == "__main__":
    main()
