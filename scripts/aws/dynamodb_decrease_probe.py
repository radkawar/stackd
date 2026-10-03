#!/usr/bin/env python3
"""Capture native provisioned decrease quotas, metadata, and atomic rejection."""
import argparse
import datetime
import json
import os
import pathlib
import secrets
import time

from dynamodb_probe import DynamoDBProbe, timestamp

REGION = "us-east-1"
ENDPOINT = "dynamodb.us-east-1.amazonaws.com"
INDEXES = ("quota", "sibling")




def throughput(read, write):
    return {"ReadCapacityUnits": read, "WriteCapacityUnits": write}


def index_update(name, read, write):
    return {"Update": {"IndexName": name, "ProvisionedThroughput": throughput(read, write)}}


def metadata(output):
    table = output.get("Table", output.get("TableDescription", {}))
    return {
        "table": {key: table[key] for key in ("TableStatus", "BillingModeSummary", "ProvisionedThroughput") if key in table},
        "indexes": {index["IndexName"]: {key: index[key] for key in ("IndexStatus", "ProvisionedThroughput") if key in index}
                    for index in table.get("GlobalSecondaryIndexes", [])},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/decrease_limits.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    environment.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
                       AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false", AWS_ENDPOINT_URL_DYNAMODB="https://" + ENDPOINT,
                       AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    os.environ.clear()
    os.environ.update(environment)
    table = "stackd-ddb-decrease-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    owned = []
    capture = {
        "source": "Native AWS signed_requests.observe_json (DynamoDB); aws_cli.observe (STS)",
        "startedAt": timestamp(), "account": args.account, "region": REGION, "ownedTables": owned,
        "calls": [], "updates": [], "cleanup": {},
        "experiment": {"table": table, "indexes": list(INDEXES), "initialProvisionedThroughput": throughput(16, 16),
                       "cliMaxAttempts": 1, "signedRequestAttempts": 1, "controlPacingSeconds": 2,
                       "endpoints": {"dynamodb": "https://" + ENDPOINT, "sts": "https://sts.us-east-1.amazonaws.com"}},
        "documentation": {"source": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html",
                          "claims": ["Four initially available decreases; one recovered each hour, capped at four available.",
                                     "UTC day boundary; at most 27 decreases over a full day.",
                                     "Table and GSI quotas are independent; combined rejection is not partially processed."]},
        "limitations": ["Only this owned empty table and its two GSIs were mutated; no application data requests.",
                        "Response objects preserve field absence and raw service timestamp precision.",
                        "All requests are sequential; unsuccessful requests remain evidence, not assumed outcomes.",
                        "No UTC-day or delayed hourly-recovery wait: day reset and actual refill remain docs-only.",
                        "Any recovery deadline in an error is a service statement, not proof a later request succeeds.",
                        "A short run cannot distinguish all hourly refill anchoring models or idle credit accumulation."],
    }
    probe = DynamoDBProbe(args.output, capture, environment)


    def control(label, **fields):
        before = probe.ready(table, label + "-before")
        time.sleep(2)
        row = probe.call(label, "update-table", {"TableName": table, **fields})
        after = probe.ready(table, label + "-after")
        snapshot = {"label": label, "updateSequence": row["sequence"], "code": row["code"],
                    "beforeSequence": before["sequence"], "settledSequence": after["sequence"],
                    "before": metadata(before["output"]), "settled": metadata(after["output"])}
        if row["code"] == "Success":
            snapshot["immediate"] = metadata(row["output"])
        else:
            snapshot["unchangedAfterRejection"] = snapshot["before"] == snapshot["settled"]
        capture["updates"].append(snapshot)
        probe.save()
        print(json.dumps({"label": label, "code": row["code"], "elapsedSeconds": round(time.monotonic() - probe.origin)}), flush=True)
        return row


    try:
        identity = probe.call("caller-identity", "get-caller-identity", {}, service="sts")
        if identity["code"] != "Success" or identity["output"]["Account"] != args.account:
            raise RuntimeError("refusing native mutation outside approved account")
        capture["actor"] = identity["output"]
        parameters = {"TableName": table, "BillingMode": "PROVISIONED", "ProvisionedThroughput": throughput(16, 16),
                      "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                      "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "x", "AttributeType": "S"}],
                      "GlobalSecondaryIndexes": [{"IndexName": name, "KeySchema": [{"AttributeName": "x", "KeyType": "HASH"}],
                                                  "Projection": {"ProjectionType": "KEYS_ONLY"}, "ProvisionedThroughput": throughput(16, 16)} for name in INDEXES]}
        # Track the unique attempted name before the network call, including an ambiguous transport outcome.
        owned.append(table)
        created = probe.call("create-provisioned", "create-table", parameters)
        if created["code"] != "Success":
            if created["code"] == "ResourceInUseException":
                owned.remove(table)
            raise RuntimeError("create: " + created["code"])
        initial = probe.ready(table, "initial-active")
        capture["initial"] = {"createSequence": created["sequence"], "settledSequence": initial["sequence"],
                              "immediate": metadata(created["output"]), "settled": metadata(initial["output"])}
        control("table-unchanged-initial", ProvisionedThroughput=throughput(16, 16))
        control("gsi-unchanged-initial", GlobalSecondaryIndexUpdates=[index_update("quota", 16, 16)])
        for label, read, write in [("table-read-only-decrease-1", 15, 16), ("table-write-only-decrease-2", 15, 15),
                                   ("table-both-decrease-3", 14, 14), ("table-mixed-decrease-increase-4", 13, 15)]:
            control(label, ProvisionedThroughput=throughput(read, write))
        control("table-fifth-decrease", ProvisionedThroughput=throughput(12, 15))
        control("table-unchanged-exhausted", ProvisionedThroughput=throughput(13, 15))
        control("table-increase-exhausted", ProvisionedThroughput=throughput(14, 16))
        control("blocked-table-with-eligible-gsi", ProvisionedThroughput=throughput(13, 16),
                GlobalSecondaryIndexUpdates=[index_update("quota", 15, 16)])
        for label, read, write in [("gsi-read-only-decrease-1", 15, 16), ("gsi-write-only-decrease-2", 15, 15),
                                   ("gsi-both-decrease-3", 14, 14), ("gsi-mixed-decrease-increase-4", 13, 15)]:
            control(label, GlobalSecondaryIndexUpdates=[index_update("quota", read, write)])
        control("gsi-fifth-decrease", GlobalSecondaryIndexUpdates=[index_update("quota", 12, 15)])
        control("gsi-unchanged-exhausted", GlobalSecondaryIndexUpdates=[index_update("quota", 13, 15)])
        control("gsi-increase-exhausted", GlobalSecondaryIndexUpdates=[index_update("quota", 14, 16)])
        control("blocked-gsi-with-eligible-table-increase", ProvisionedThroughput=throughput(15, 17),
                GlobalSecondaryIndexUpdates=[index_update("quota", 13, 16)])
        control("blocked-gsi-first-with-eligible-sibling", GlobalSecondaryIndexUpdates=[index_update("quota", 13, 16), index_update("sibling", 15, 16)])
        control("blocked-gsi-last-with-eligible-sibling", GlobalSecondaryIndexUpdates=[index_update("sibling", 15, 16), index_update("quota", 13, 16)])
        control("both-table-and-gsi-blocked", ProvisionedThroughput=throughput(13, 16),
                GlobalSecondaryIndexUpdates=[index_update("quota", 13, 16)])
        control("table-noop-with-eligible-sibling", ProvisionedThroughput=throughput(14, 16),
                GlobalSecondaryIndexUpdates=[index_update("sibling", 15, 16)])
        control("gsi-noop-with-eligible-table-increase", ProvisionedThroughput=throughput(15, 17),
                GlobalSecondaryIndexUpdates=[index_update("quota", 14, 16)])
        control("table-increase-with-blocked-gsi-after-rejected-noop", ProvisionedThroughput=throughput(15, 17),
                GlobalSecondaryIndexUpdates=[index_update("quota", 13, 16)])
        control("switch-on-demand", BillingMode="PAY_PER_REQUEST")
        control("roundtrip-provisioned", BillingMode="PROVISIONED", ProvisionedThroughput=throughput(16, 18),
                GlobalSecondaryIndexUpdates=[index_update(name, 16, 18) for name in INDEXES])
        control("table-decrease-after-roundtrip", ProvisionedThroughput=throughput(15, 18))
        control("gsi-decrease-after-roundtrip", GlobalSecondaryIndexUpdates=[index_update("quota", 15, 18)])
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for name in owned:
            try:
                probe.delete(name)
            except Exception as error:
                capture["cleanup"].setdefault(name, {"verifiedAbsent": False})["error"] = str(error)
        capture["leftoverTables"] = [name for name in owned if not capture["cleanup"].get(name, {}).get("verifiedAbsent")]
        capture["finishedAt"] = timestamp()
        probe.save()
    if capture["leftoverTables"]:
        raise RuntimeError("owned resources remain; inspect cleanup evidence")
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "leftoverTables": capture["leftoverTables"]}), flush=True)


if __name__ == "__main__":
    main()
