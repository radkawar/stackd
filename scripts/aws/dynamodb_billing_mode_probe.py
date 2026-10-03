#!/usr/bin/env python3
"""Observe rolling billing-mode switch admission on two low-capacity owned tables."""
import argparse
import json
import os
import pathlib
import secrets
import time

from dynamodb_probe import DynamoDBProbe, timestamp

REGION = "us-east-1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/billing_mode_limits.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite a native capture")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_ENDPOINT_URL")}
    environment.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1",
                       AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false",
                       AWS_ENDPOINT_URL_DYNAMODB="https://dynamodb.us-east-1.amazonaws.com",
                       AWS_ENDPOINT_URL_STS="https://sts.us-east-1.amazonaws.com")
    os.environ.clear()
    os.environ.update(environment)
    prefix = "stackd-ddb-billing-" + secrets.token_hex(6)
    owned = []
    capture = {
        "source": "Native AWS through shared DynamoDBProbe and signed_requests/aws_cli transports",
        "startedAt": timestamp(), "account": args.account, "region": REGION,
        "ownedTables": owned, "calls": [], "updates": [], "cleanup": {},
        "documentation": ["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-switching-capacity-modes.html"],
        "experiment": {"initialModes": ["PROVISIONED", "PAY_PER_REQUEST"],
                       "provisionedUnits": {"ReadCapacityUnits": 2, "WriteCapacityUnits": 2},
                       "maximumSwitchAttemptsPerTable": 6, "controlPacingSeconds": 2,
                       "dataOperations": False},
        "limitations": ["No 24-hour recovery wait. Reported deadlines are retained, not claimed as successful recovery.",
                        "Only these empty tables are mutated; no global tables, GSIs, scaling policies or quota changes."],
    }
    probe = DynamoDBProbe(args.output, capture, environment)

    def control(table, label, **fields):
        before = probe.ready(table, label + "-before")
        time.sleep(2)
        result = probe.call(label, "update-table", {"TableName": table, **fields})
        after = probe.ready(table, label + "-after")
        row = {"label": label, "table": table, "updateSequence": result["sequence"], "code": result["code"],
               "beforeSequence": before["sequence"], "settledSequence": after["sequence"]}
        if result["code"] != "Success":
            row["unchangedAfterRejection"] = before["output"] == after["output"]
        capture["updates"].append(row)
        probe.save()
        print(json.dumps(row), flush=True)
        return result

    try:
        identity = probe.call("caller-identity", "get-caller-identity", {}, service="sts")
        if identity["code"] != "Success" or identity["output"]["Account"] != args.account:
            raise RuntimeError("refusing native mutation outside approved account")
        capture["actor"] = identity["output"]
        for initial in capture["experiment"]["initialModes"]:
            table = prefix + ("-provisioned" if initial == "PROVISIONED" else "-ondemand")
            create = {"TableName": table, "BillingMode": initial,
                      "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                      "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}]}
            if initial == "PROVISIONED":
                create["ProvisionedThroughput"] = {"ReadCapacityUnits": 2, "WriteCapacityUnits": 2}
            owned.append(table)
            created = probe.call(initial + "-create", "create-table", create)
            if created["code"] != "Success":
                if created["code"] == "ResourceInUseException":
                    owned.remove(table)
                raise RuntimeError("create rejected: " + created["code"])
            probe.ready(table, initial + "-initial")
            if initial == "PAY_PER_REQUEST":
                control(table, initial + "-initial-noop", BillingMode="PAY_PER_REQUEST")
                restored = control(table, initial + "-initial-provisioned", BillingMode="PROVISIONED",
                                   ProvisionedThroughput={"ReadCapacityUnits": 2, "WriteCapacityUnits": 2})
                if restored["code"] != "Success":
                    raise RuntimeError("initial provisioned transition rejected: " + restored["code"])
            control(table, initial + "-provisioned-noop", BillingMode="PROVISIONED")
            for attempt in range(1, 7):
                label = initial + "-switch-" + str(attempt)
                switched = control(table, label, BillingMode="PAY_PER_REQUEST")
                if switched["code"] != "Success":
                    break
                control(table, label + "-noop", BillingMode="PAY_PER_REQUEST")
                restored = control(table, label + "-restore", BillingMode="PROVISIONED",
                                   ProvisionedThroughput={"ReadCapacityUnits": 2, "WriteCapacityUnits": 2})
                if restored["code"] != "Success":
                    raise RuntimeError("provisioned transition rejected: " + restored["code"])
            control(table, initial + "-provisioned-noop-after-loop", BillingMode="PROVISIONED")
            control(table, initial + "-increase-after-loop",
                    ProvisionedThroughput={"ReadCapacityUnits": 3, "WriteCapacityUnits": 3})
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for table in owned:
            try:
                probe.delete(table)
            except Exception as error:
                capture["cleanup"].setdefault(table, {"verifiedAbsent": False})["error"] = str(error)
        capture["leftoverTables"] = [table for table in owned if not capture["cleanup"].get(table, {}).get("verifiedAbsent")]
        capture["finishedAt"] = timestamp()
        probe.save()
    if capture["leftoverTables"]:
        raise RuntimeError("owned resources remain; inspect cleanup evidence")
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "leftoverTables": capture["leftoverTables"]}), flush=True)


if __name__ == "__main__":
    main()
