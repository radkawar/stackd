#!/usr/bin/env python3
"""Capture real AWS on-demand snapshots, restore data/configuration, and owned cleanup."""
import argparse
import json
import os
import pathlib
import secrets
import time

from dynamodb_probe import DynamoDBProbe, timestamp

REGION = "us-east-1"
UNITS = {"ReadCapacityUnits": 2, "WriteCapacityUnits": 2}


def require(row):
    if row["code"] != "Success":
        raise RuntimeError(row["label"] + ": " + row["code"])
    return row["output"]


def canonical(value):
    """Attribute-value sets have no response ordering guarantee."""
    if isinstance(value, dict):
        return {key: sorted(item) if key in ("SS", "NS", "BS") else canonical(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/dynamodb/backups.json"))
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
    prefix = "stackd-ddb-backup-" + secrets.token_hex(6)
    source, default, excluded = (prefix + suffix for suffix in ("-source", "-default", "-excluded"))
    owned, backups, intents = [], [], []
    capture = {
        "source": "Native AWS through DynamoDBProbe signed_requests/aws_cli transports",
        "startedAt": timestamp(), "account": args.account, "region": REGION,
        "ownedTables": owned, "ownedBackupArns": backups, "backupIntents": intents,
        "calls": [], "cleanup": {}, "backupCleanup": {}, "waits": [], "checks": [],
        "documentation": ["https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_" + name + ".html"
                          for name in ("CreateBackup", "DescribeBackup", "ListBackups", "RestoreTableFromBackup", "DeleteBackup")],
        "experiment": {"prefix": prefix, "provisionedThroughput": UNITS, "maximumRestoreTargets": 2,
                       "noncausalEnvelopeGuardSeconds": 65, "regionFixedBySharedSigningTransport": REGION},
        "limitations": ["No PITR, AWS Backup vault, customer-managed KMS, cross-account, or quota changes.",
                        "Native table/index ItemCount and size metadata may lag real data; scan/query results are the data evidence.",
                        "Backup consistency is noncausal within one minute on either side; writes are outside that envelope."]}
    probe = DynamoDBProbe(args.output, capture, environment)
    guarded = False

    def check(name, passed, **details):
        capture["checks"].append(dict(name=name, passed=passed, **details))
        probe.save()
        if not passed:
            raise RuntimeError("observation failed: " + name)

    def pause(label):
        row = {"label": label, "startedAt": timestamp(), "minimumSeconds": 65}
        capture["waits"].append(row)
        probe.save()
        start = time.monotonic()
        time.sleep(65)
        row.update(finishedAt=timestamp(), elapsedSeconds=time.monotonic() - start)
        probe.save()

    def backup_ready(arn, label):
        for attempt in range(180):
            row = probe.call(label + "-" + str(attempt), "describe-backup", {"BackupArn": arn})
            details = require(row)["BackupDescription"]["BackupDetails"]
            if details["BackupStatus"] == "AVAILABLE":
                return row
            if details["BackupStatus"] != "CREATING":
                raise RuntimeError("unexpected backup state: " + details["BackupStatus"])
            time.sleep(2)
        raise RuntimeError("backup readiness deadline exceeded")

    def create_backup(label, name):
        intents.append({"TableName": source, "BackupName": name})
        row = probe.call(label, "create-backup", intents[-1])
        if row["code"] == "Success":
            arn = row["output"]["BackupDetails"]["BackupArn"]
            if arn not in backups:
                backups.append(arn)
            probe.save()
        return row

    def restore(label, table, arn, **fields):
        if table not in owned:
            owned.append(table)
        row = probe.call(label, "restore-table-from-backup", dict(TargetTableName=table, BackupArn=arn, **fields))
        # A collision with a preexisting table must never transfer ownership to us.
        if row["code"] == "TableAlreadyExistsException":
            owned.remove(table)
            raise RuntimeError("unexpected target collision; refusing deletion")
        return row

    def data(table, label, expected, indexes=True):
        row = probe.call(label + "-scan", "scan", {"TableName": table, "ConsistentRead": True})
        result = require(row)
        actual = sorted((canonical(item) for item in result["Items"]), key=lambda item: item["sk"]["N"])
        check(label + "-snapshot-items", actual == expected, sequence=row["sequence"], count=result["Count"])
        if indexes:
            for index, key, value, consistent in (("by-group", "gpk", "group", False), ("by-rank", "pk", "partition", True)):
                for attempt in range(30):
                    query = probe.call(label + "-" + index + "-" + str(attempt), "query",
                                       {"TableName": table, "IndexName": index, "KeyConditionExpression": "#key = :value",
                                        "ExpressionAttributeNames": {"#key": key}, "ExpressionAttributeValues": {":value": {"S": value}},
                                        "ConsistentRead": consistent})
                    output = require(query)
                    items = sorted((canonical(item) for item in output["Items"]), key=lambda item: item["sk"]["N"])
                    if items == expected:
                        break
                    time.sleep(2)
                check(label + "-" + index + "-items", items == expected, sequence=query["sequence"], count=output["Count"])

    def config(table, label):
        row = probe.ready(table, label + "-active")
        arn = row["output"]["Table"]["TableArn"]
        require(probe.call(label + "-tags", "list-tags-of-resource", {"ResourceArn": arn}))
        require(probe.call(label + "-ttl", "describe-time-to-live", {"TableName": table}))
        return row

    def delete_backup(arn):
        state = capture["backupCleanup"].setdefault(arn, {"verifiedAbsent": False})
        for attempt in range(180):
            row = probe.call("delete-owned-backup-" + str(attempt), "delete-backup", {"BackupArn": arn})
            if row["code"] in ("Success", "BackupNotFoundException"):
                break
            if row["code"] != "BackupInUseException":
                raise RuntimeError("delete backup: " + row["code"])
            time.sleep(2)
        else:
            raise RuntimeError("backup deletion admission deadline exceeded")
        for attempt in range(180):
            row = probe.call("verify-backup-absent-" + str(attempt), "describe-backup", {"BackupArn": arn})
            if row["code"] == "BackupNotFoundException":
                state.update(verifiedAbsent=True, verificationSequence=row["sequence"], verifiedAt=row["finishedAt"])
                probe.save()
                return
            require(row)
            time.sleep(2)
        raise RuntimeError("backup absence not observed")

    try:
        identity = probe.call("caller-identity", "get-caller-identity", {}, service="sts")
        if identity["code"] != "Success" or identity["output"]["Account"] != args.account:
            raise RuntimeError("refusing native mutation outside approved account")
        guarded = True
        capture["actor"] = identity["output"]
        probe.call("missing-source-create-backup", "create-backup", {"TableName": prefix + "-missing", "BackupName": prefix + "-missing"})
        probe.call("missing-source-list-backups", "list-backups", {"TableName": prefix + "-missing"})
        owned.append(source)
        created = probe.call("create-source", "create-table", {
            "TableName": source, "BillingMode": "PROVISIONED", "ProvisionedThroughput": UNITS,
            "AttributeDefinitions": [{"AttributeName": key, "AttributeType": kind} for key, kind in (("pk", "S"), ("sk", "N"), ("gpk", "S"), ("rank", "N"))],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            "GlobalSecondaryIndexes": [{"IndexName": "by-group", "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
                                        "Projection": {"ProjectionType": "ALL"}, "ProvisionedThroughput": UNITS}],
            "LocalSecondaryIndexes": [{"IndexName": "by-rank", "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "rank", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "ALL"}}],
            "StreamSpecification": {"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
            "Tags": [{"Key": "stackd-probe", "Value": "backup"}]})
        if created["code"] == "ResourceInUseException":
            owned.remove(source)
        require(created)
        probe.ready(source, "source-created")
        ttl = probe.call("source-enable-ttl", "update-time-to-live", {"TableName": source, "TimeToLiveSpecification": {"Enabled": True, "AttributeName": "expires"}})
        if ttl["code"] not in ("Success", "AccessDeniedException"):
            require(ttl)
        future = str(int(time.time()) + 86400 * 30)
        items = [{"pk": {"S": "partition"}, "sk": {"N": str(n)}, "gpk": {"S": "group"}, "rank": {"N": str(n * 10)},
                  "version": {"S": "before"}, "expires": {"N": future}} for n in (1, 2, 3)]
        items[0].update(blob={"B": "AAEC/w=="}, number={"N": "-12.5"}, strings={"SS": ["alpha", "beta"]},
                        numbers={"NS": ["1", "2.5"]}, binaries={"BS": ["AAE=", "AgM="]}, flag={"BOOL": True},
                        nothing={"NULL": True}, nested={"M": {"list": {"L": [{"S": "value"}, {"N": "7"}, {"BOOL": False}]}}})
        expected = [canonical(item) for item in items]
        for n, item in enumerate(items):
            require(probe.call("seed-" + str(n), "put-item", {"TableName": source, "Item": item}))
            time.sleep(1)
        data(source, "source-seeded", expected)
        pause("seed-to-backup-envelope")
        config(source, "source-before-backup")
        first = create_backup("create-backup", prefix + "-snapshot")
        arn = require(first)["BackupDetails"]["BackupArn"]
        backup_ready(arn, "backup-ready")
        duplicate = create_backup("duplicate-backup-name", prefix + "-snapshot")
        if duplicate["code"] == "Success":
            second_arn = duplicate["output"]["BackupDetails"]["BackupArn"]
            backup_ready(second_arn, "duplicate-backup-ready")
        else:
            # Still need two owned backups to measure genuine pagination.
            second = create_backup("create-second-backup", prefix + "-second")
            second_arn = require(second)["BackupDetails"]["BackupArn"]
            backup_ready(second_arn, "second-backup-ready")
        pause("last-backup-acceptance-to-source-mutation-envelope")
        for kind in ("USER", "SYSTEM", "ALL"):
            require(probe.call("list-filter-" + kind, "list-backups", {"TableName": source, "BackupType": kind}))
            time.sleep(0.3)
        cursor = None
        for page in range(10):
            parameters = {"TableName": source, "BackupType": "USER", "Limit": 1}
            if cursor:
                parameters["ExclusiveStartBackupArn"] = cursor
            output = require(probe.call("list-page-" + str(page), "list-backups", parameters))
            cursor = output.get("LastEvaluatedBackupArn")
            if not cursor:
                break
            time.sleep(0.3)
        check("pagination-terminated", not cursor)
        instant = first["output"]["BackupDetails"]["BackupCreationDateTime"]
        for label, fields in (("inclusive-lower", {"TimeRangeLowerBound": instant}),
                              ("exclusive-upper", {"TimeRangeUpperBound": instant}),
                              ("bounded-window", {"TimeRangeLowerBound": instant - 1, "TimeRangeUpperBound": instant + 1})):
            time.sleep(0.3)
            require(probe.call("list-" + label, "list-backups", dict(TableName=source, **fields)))
        require(probe.call("source-change-item", "update-item", {"TableName": source, "Key": {"pk": {"S": "partition"}, "sk": {"N": "1"}},
                           "UpdateExpression": "SET #v = :v", "ExpressionAttributeNames": {"#v": "version"}, "ExpressionAttributeValues": {":v": {"S": "after"}}}))
        time.sleep(1)
        require(probe.call("source-delete-item", "delete-item", {"TableName": source, "Key": {"pk": {"S": "partition"}, "sk": {"N": "2"}}}))
        time.sleep(1)
        late = dict(items[2], sk={"N": "4"}, rank={"N": "40"}, version={"S": "late"})
        require(probe.call("source-late-item", "put-item", {"TableName": source, "Item": late}))
        require(probe.call("source-mutated-scan", "scan", {"TableName": source, "ConsistentRead": True}))
        # Invalid native wire requests reuse the first reserved target; accepted surprises remain owned.
        accepted = False
        for label, fields in (("invalid-billing-mode", {"BillingModeOverride": "INVALID"}),
                              ("invalid-throughput", {"ProvisionedThroughputOverride": {"ReadCapacityUnits": 0, "WriteCapacityUnits": 2}})):
            validation = restore(label, default, arn, **fields)
            if validation["code"] == "Success":
                capture["unexpectedAcceptedRestore"] = validation["sequence"]
                accepted = True
                break
        if not accepted:
            require(restore("restore-default", default, arn))
        config(default, "restored-default")
        data(default, "restored-default", expected)
        probe.call("restore-existing-target", "restore-table-from-backup", {"TargetTableName": default, "BackupArn": arn})
        # An already-owned target avoids allocating additional successful restore targets.
        # These calls also expose whether ARN admission precedes target-name collision.
        for label, altered in (("different-account", arn.replace(":" + args.account + ":", ":000000000000:")),
                               ("different-region", arn.replace(":" + REGION + ":", ":us-west-2:"))):
            probe.call(label + "-describe-backup", "describe-backup", {"BackupArn": altered})
            probe.call(label + "-restore-backup", "restore-table-from-backup",
                       {"BackupArn": altered, "TargetTableName": default})
        probe.delete(source)
        require(probe.call("backup-after-source-deletion", "describe-backup", {"BackupArn": arn}))
        require(probe.call("list-after-source-deletion", "list-backups", {"TableName": source}))
        require(restore("restore-excluding-indexes-after-source-deletion", excluded, arn, BillingModeOverride="PAY_PER_REQUEST",
                        GlobalSecondaryIndexOverride=[], LocalSecondaryIndexOverride=[],
                        OnDemandThroughputOverride={"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 10}))
        config(excluded, "restored-excluded")
        data(excluded, "restored-excluded", expected, indexes=False)
        probe.call("excluded-index-query", "query", {"TableName": excluded, "IndexName": "by-group", "KeyConditionExpression": "gpk = :g",
                   "ExpressionAttributeValues": {":g": {"S": "group"}}})
        for backup in backups:
            delete_backup(backup)
        probe.call("delete-missing-backup", "delete-backup", {"BackupArn": arn})
        # Existing owned target is removed first: missing backup must not be masked by name collision.
        probe.delete(excluded)
        missing_restore = restore("restore-missing-backup", excluded, arn)
        check("deleted-backup-not-restorable", missing_restore["code"] == "BackupNotFoundException", sequence=missing_restore["sequence"])
        probe.call("list-after-backup-deletion", "list-backups", {"TableName": source})
        capture["completedAt"] = timestamp()
    except BaseException as error:
        capture["captureError"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if guarded:
            # Discover successful but ambiguous CreateBackup calls from the pre-recorded owned names.
            try:
                cursor = None
                for page in range(100):
                    parameters = {"TableName": source, "BackupType": "USER"}
                    if cursor:
                        parameters["ExclusiveStartBackupArn"] = cursor
                    output = require(probe.call("cleanup-discover-backups-" + str(page), "list-backups", parameters))
                    for summary in output.get("BackupSummaries", []):
                        if any(intent["BackupName"] == summary["BackupName"] for intent in intents) and summary["BackupArn"] not in backups:
                            backups.append(summary["BackupArn"])
                    cursor = output.get("LastEvaluatedBackupArn")
                    if not cursor:
                        break
                    time.sleep(0.3)
                if cursor:
                    raise RuntimeError("cleanup discovery pagination exceeded")
            except Exception as error:
                capture["backupDiscoveryError"] = str(error)
            for table in owned:
                try:
                    probe.delete(table)
                except Exception as error:
                    capture["cleanup"].setdefault(table, {"verifiedAbsent": False})["error"] = str(error)
            for backup in backups:
                try:
                    delete_backup(backup)
                except Exception as error:
                    capture["backupCleanup"].setdefault(backup, {"verifiedAbsent": False})["error"] = str(error)
        capture["leftoverTables"] = [table for table in owned if not capture["cleanup"].get(table, {}).get("verifiedAbsent")]
        capture["leftoverBackups"] = [arn for arn in backups if not capture["backupCleanup"].get(arn, {}).get("verifiedAbsent")]
        capture["finishedAt"] = timestamp()
        probe.save()
    if capture["leftoverTables"] or capture["leftoverBackups"] or capture.get("backupDiscoveryError"):
        raise RuntimeError("cleanup incomplete; inspect native capture")
    print(json.dumps({"output": str(args.output), "calls": len(capture["calls"]), "leftoverTables": capture["leftoverTables"], "leftoverBackups": capture["leftoverBackups"]}), flush=True)


if __name__ == "__main__":
    main()
