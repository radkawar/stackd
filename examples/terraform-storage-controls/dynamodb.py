"""Owned Terraform controls with real DynamoDB Local snapshots and consumers."""
import base64
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from urllib.request import Request, ProxyHandler, build_opener
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from local import client, expect_missing, local_endpoint, require


HTTP = build_opener(ProxyHandler({}))
REPLICA_REGION = "us-west-2"


def _private(path, value):
    data = value if isinstance(value, bytes) else value.encode()
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as stream:
        stream.write(data)
    Path(path).chmod(0o600)


def _clock(endpoint, advance=None):
    request = Request(local_endpoint(endpoint) + "/_stackd/clock",
                      data=None if advance is None else json.dumps({"advance": advance}).encode(),
                      headers={"Content-Type": "application/json"})
    with HTTP.open(request, timeout=30) as response:
        return json.load(response)["time"]


@contextmanager
def _ticks(endpoint, on_advance=None):
    # Only the current owned Terraform API command gets a ticker. It stops
    # before historical snapshot points and deliberate capacity assertions.
    stop = threading.Event()
    failures = []

    def tick():
        while not stop.wait(0.25):
            try:
                advanced = _clock(endpoint, "1s")
                if on_advance is not None:
                    on_advance(advanced)
            except Exception as error:
                failures.append(error)
                return

    thread = threading.Thread(target=tick, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()
    if failures:
        raise failures[0]


def _regional(service, endpoint, region, key="test", secret="test"):
    # The shared client owns endpoint validation and the ordinary region. An
    # explicit region is necessary to sign an independently scoped replica read.
    return boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret,
                         region_name=region).client(
        service, endpoint_url=local_endpoint(endpoint),
        config=Config(signature_version="v4", connect_timeout=3, read_timeout=60,
                      proxies={}, retries={"max_attempts": 0}))


def run(args, root: Path, endpoint: str, terraform, variables: dict, stages: list):
    directory = root / "dynamodb"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    _private(directory / "main.tf", Path(__file__).with_suffix(".tf").read_bytes())
    values = {key: variables[key] for key in ("name", "endpoint", "region", "account_id")}
    values.update(revision="initial", pitr_enabled=False, replicas_enabled=False,
                  restores_enabled=False, backup_arn="", restore_time="", deletion_protection_enabled=False,
                  separate_replica_enabled=False, separate_source_name="", separate_source_arn="")
    active_endpoint = endpoint
    clock_events = directory / "clock-events.jsonl"
    _private(clock_events, "")
    outputs = {}
    backup_arn = None
    incarnations = {}
    original = b"snapshot-binary\x00\xff\n" + uuid.uuid4().bytes
    live = original + b"-source-mutated"
    source_key = {"pk": {"S": "snapshot"}}

    def save():
        values["endpoint"] = active_endpoint
        _private(directory / "local.auto.tfvars.json", json.dumps(values, sort_keys=True))

    def record_clock(command, phase, advanced):
        with clock_events.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": list(command), "phase": phase,
                                     "advance": "1s", "time": advanced}, sort_keys=True) + "\n")

    def tf(*command, check=True):
        save()
        try:
            if command[0] in {"apply", "destroy", "plan", "import", "refresh"}:
                # Every import/plan also reads data sources. Frozen time would
                # exhaust ListBackups' real5TPS budget across otherwise fast
                # commands. Refill at admission and keep time moving during
                # retries/waiters; direct throttling probes remain controlled.
                record_clock(command, "before", _clock(active_endpoint, "1s"))
                with _ticks(active_endpoint, lambda advanced: record_clock(command, "during", advanced)):
                    return terraform(list(command), directory, check=check)
            return terraform(list(command), directory, check=check)
        finally:
            for path in directory.glob("*.tfstate*"):
                if path.is_file():
                    path.chmod(0o600)

    def refresh_outputs():
        outputs.update(json.loads(tf("output", "-json").stdout)["dynamodb"]["value"])

    def reconcile_restore_tags():
        # Restore does not copy tags. The pinned provider creates these tables
        # before it applies their declared tags. Admit only that exact update.
        # Refresh observations after both restore waiters finish. This is not
        # the later strict no-change check and does not write any table tags.
        tf("apply", "-refresh-only", "-input=false", "-auto-approve")
        plan_file = directory / "restore-tags.tfplan"
        tf("plan", "-input=false", "-out=" + str(plan_file))
        plan_file.chmod(0o600)
        plan = json.loads(tf("show", "-json", str(plan_file)).stdout)
        changed = [entry for entry in plan.get("resource_changes", [])
                   if entry["change"]["actions"] != ["no-op"]]
        allowed = {"aws_dynamodb_table.backup[0]", "aws_dynamodb_table.pitr[0]"}
        expected_tags = {"Fixture": values["name"], "Revision": values["revision"]}

        def unknown(value):
            if isinstance(value, dict):
                return any(unknown(item) for item in value.values())
            if isinstance(value, list):
                return any(unknown(item) for item in value)
            return value is True

        for entry in changed:
            change = entry["change"]
            require(entry["address"] in allowed and change["actions"] == ["update"],
                    "Restore tag reconciliation has an unrelated resource change")
            before, after = dict(change["before"]), dict(change["after"])
            for field in ("tags", "tags_all"):
                require(before.pop(field, None) in (None, {}) and after.pop(field, None) == expected_tags,
                        "Restore tag reconciliation is not the declared empty-to-configured tag update")
            require(before == after and not unknown(change.get("after_unknown", {})),
                    "Restore tag reconciliation changes an unrelated or unknown attribute")
        require(all(entry["actions"] == ["no-op"] for entry in plan.get("output_changes", {}).values()),
                "Restore tag reconciliation changes an unrelated output")
        tf("apply", "-input=false", str(plan_file))
        refresh_outputs()
        stages.append({"stage": "dynamodb-restore-configured-tag-reconciliation", "status": "passed",
                       "changed_resources": [entry["address"] for entry in changed]})

    def wait(read, predicate, message, missing=()):
        deadline = time.monotonic() + 180
        while True:
            try:
                result = read()
            except ClientError as error:
                if error.response["Error"]["Code"] not in missing:
                    raise
            else:
                if predicate(result):
                    return result
            require(time.monotonic() < deadline, message)
            _clock(active_endpoint, "1s")
            time.sleep(0.25)

    def item(ddb, table, key=source_key):
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    def expect_payload(ddb, table, payload, key=source_key):
        actual = item(ddb, table, key)
        require(actual is not None and actual["payload"] == {"B": payload},
                f"Native binary item differs in {table}")

    def put(ddb, table, payload, key=source_key):
        ddb.put_item(TableName=table, Item=dict(key, group={"S": "native"}, payload={"B": payload}))

    def remember(ddb, table, label):
        description = ddb.describe_table(TableName=table)["Table"]
        identity = description["TableId"]
        require(description["TableStatus"] == "ACTIVE", f"Native table not ACTIVE: {label}")
        if label in incarnations:
            require(incarnations[label] == identity, f"Table incarnation unexpectedly changed: {label}")
        else:
            incarnations[label] = identity
        return identity

    def unchanged(label):
        tf("apply", "-refresh-only", "-input=false", "-auto-approve")
        result = tf("plan", "-input=false", "-detailed-exitcode", check=False)
        require(result.returncode == 0, f"DynamoDB {label} refresh was not a no-change plan")
        stages.append({"stage": "dynamodb-no-change-" + label, "status": "passed"})

    def authority(ddb):
        iam = client("iam", active_endpoint)
        key = iam.create_access_key(UserName=outputs["reader"])["AccessKey"]
        signed = _regional("dynamodb", active_endpoint, values["region"],
                           key["AccessKeyId"], key["SecretAccessKey"])
        deny_present = False
        try:
            expect_payload(signed, outputs["source"], live)
            # A current identity explicit deny must override the resource grant,
            # and removing it must immediately restore access with the SAME key.
            iam.put_user_policy(UserName=outputs["reader"], PolicyName="current-deny",
                                PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                                    "Effect": "Deny", "Action": "dynamodb:GetItem", "Resource": outputs["source_arn"]}]}))
            deny_present = True
            expect_missing(signed.get_item, {"AccessDeniedException"},
                           TableName=outputs["source"], Key=source_key)
            iam.delete_user_policy(UserName=outputs["reader"], PolicyName="current-deny")
            deny_present = False
            expect_payload(signed, outputs["source"], live)
            expect_missing(signed.put_item, {"AccessDeniedException"},
                           TableName=outputs["source"], Item=dict(source_key, payload={"B": b"unauthorized"}))
        finally:
            try:
                if deny_present:
                    iam.delete_user_policy(UserName=outputs["reader"], PolicyName="current-deny")
            finally:
                iam.delete_access_key(UserName=outputs["reader"], AccessKeyId=key["AccessKeyId"])
        expect_payload(ddb, outputs["source"], live)

    def consume_changes(ddb):
        marker = "consumer-" + uuid.uuid4().hex
        marker_key = {"pk": {"S": marker}}
        payload = b"signed-kinesis-image\x00\xff" + uuid.uuid4().bytes
        put(ddb, outputs["source"], payload, marker_key)
        kinesis = client("kinesis", active_endpoint)
        description = kinesis.describe_stream(StreamName=outputs["kinesis_name"])["StreamDescription"]
        iterators = [kinesis.get_shard_iterator(StreamName=outputs["kinesis_name"],
                     ShardId=shard["ShardId"], ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
                     for shard in description["Shards"]]
        found = False
        deadline = time.monotonic() + 90
        while iterators and not found:
            next_iterators = []
            for iterator in iterators:
                page = kinesis.get_records(ShardIterator=iterator, Limit=1000)
                for record in page["Records"]:
                    change = json.loads(record["Data"])
                    if change.get("dynamodb", {}).get("Keys") != marker_key or change["eventName"] != "INSERT":
                        continue
                    image = change["dynamodb"]["NewImage"]
                    # The native destination envelope uses the documented double
                    # base64 binary layer; Kinesis itself returns real record bytes.
                    actual = base64.b64decode(base64.b64decode(image["payload"]["B"]))
                    require(actual == payload, "Signed Kinesis consumer lost binary image bytes")
                    require(change["tableName"] == outputs["source"] and change["awsRegion"] == values["region"]
                            and change["dynamodb"]["ApproximateCreationDateTimePrecision"] == "MICROSECOND",
                            "Kinesis destination envelope/precision differs")
                    found = True
                if page.get("NextShardIterator"):
                    next_iterators.append(page["NextShardIterator"])
            require(found or time.monotonic() < deadline, "Real Kinesis destination did not deliver native mutation")
            iterators = next_iterators
            if not found:
                _clock(active_endpoint, "1s")
                time.sleep(0.25)
        require(found, "No live Kinesis shards delivered the DynamoDB mutation")
        streams = client("dynamodbstreams", active_endpoint)
        shards = streams.describe_stream(StreamArn=outputs["stream_arn"])["StreamDescription"]["Shards"]
        def stream_marker():
            for shard in shards:
                iterator = streams.get_shard_iterator(StreamArn=outputs["stream_arn"], ShardId=shard["ShardId"],
                                                     ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
                while iterator:
                    page = streams.get_records(ShardIterator=iterator, Limit=1000)
                    for record in page["Records"]:
                        image = record.get("dynamodb", {}).get("NewImage", {})
                        if image.get("pk") == marker_key["pk"] and image.get("payload") == {"B": payload}:
                            return True
                    if not page["Records"]:
                        break
                    iterator = page.get("NextShardIterator")
            return False
        wait(stream_marker, bool, "Real DynamoDB Streams did not deliver the binary image")
        ddb.delete_item(TableName=outputs["source"], Key=marker_key)

    def capacity(ddb):
        expected = 1 if values["revision"] == "initial" else 2
        for label, setting, units, code in (
                ("capacity", "ProvisionedThroughput", "WriteCapacityUnits", "ProvisionedThroughputExceededException"),
                ("limited", "OnDemandThroughput", "MaxWriteRequestUnits", "ThrottlingException")):
            _clock(active_endpoint, "600s")
            table = outputs[label]
            description = ddb.describe_table(TableName=table)["Table"]
            require(description[setting][units] == expected, "Terraform requested throughput update differs")
            # Native large-item writes spend actual WCUs. Freeze service time to
            # exhaust the bounded burst; a rejected mutation must not land.
            blob = b"capacity\x00\xff" * 26215
            throttled = False
            keys = []
            try:
                for index in range(8):
                    key = {"pk": {"S": "capacity-" + str(index)}}
                    try:
                        result = ddb.put_item(TableName=table, Item=dict(key, payload={"B": blob}), ReturnConsumedCapacity="TOTAL")
                    except ClientError as error:
                        require(error.response["Error"]["Code"] == code, str(error))
                        require(item(ddb, table, key) is None, "Rejected throughput write nevertheless reached native storage")
                        throttled = True
                        break
                    require(result["ConsumedCapacity"]["CapacityUnits"] > 200, "Native write did not report actual item-sized capacity")
                    keys.append(key)
                require(throttled, "Requested throughput had no enforced native admission effect")
            finally:
                for key in keys:
                    _clock(active_endpoint, "600s")
                    ddb.delete_item(TableName=table, Key=key)
            _clock(active_endpoint, "600s")

    def rejected_settings(ddb):
        table = outputs["limited"]
        before = ddb.describe_table(TableName=table)["Table"]
        for settings in (
                {"SSESpecification": {"Enabled": True, "SSEType": "KMS"}},
                {"WarmThroughput": {"ReadUnitsPerSecond": 100, "WriteUnitsPerSecond": 100}},
                {"TableClass": "STANDARD_INFREQUENT_ACCESS"}):
            expect_missing(ddb.update_table, {"NotImplementedException"}, TableName=table, **settings)
        after = ddb.describe_table(TableName=table)["Table"]
        require(after["TableId"] == before["TableId"] and after["TableStatus"] == "ACTIVE"
                and not after.get("SSEDescription") and after.get("TableClassSummary") == before.get("TableClassSummary"),
                "Rejected native settings changed retained table intent")
        expect_missing(ddb.create_global_table, {"ValidationException"}, GlobalTableName=outputs["source"],
                       ReplicationGroup=[{"RegionName": values["region"]}])
        expect_missing(ddb.describe_global_table, {"GlobalTableNotFoundException"}, GlobalTableName=outputs["source"])
        if values["deletion_protection_enabled"]:
            expect_missing(ddb.delete_table, {"ValidationException"}, TableName=outputs["source"])
            expect_payload(ddb, outputs["source"], live)

    def verify(endpoint=None):
        nonlocal active_endpoint
        active_endpoint = local_endpoint(endpoint or active_endpoint)
        ddb = client("dynamodb", active_endpoint)
        replica = _regional("dynamodb", active_endpoint, REPLICA_REGION)
        refresh_outputs()
        require(outputs["source_lookup_arn"] == outputs["source_arn"], "Terraform table lookup differs")
        require(outputs["item"]["revision"] == {"S": values["revision"]}, "Terraform item data source differs")
        require({outputs["source"], outputs["capacity"]}.issubset(outputs["table_names"]), "Terraform table inventory omits owned IDs")
        require(backup_arn in {value["backup_arn"] for value in outputs["backups"]}, "Terraform backup lookup omits immutable snapshot")
        identities = {remember(ddb, outputs[label], label) for label in ("source", "capacity", "limited", "backup", "pitr")}
        identities.add(remember(replica, outputs["source"], "replica"))
        require(len(identities) == 6, "Restores/replica alias the source table incarnation")
        expect_payload(ddb, outputs["source"], live)
        expect_payload(ddb, outputs["backup"], original)
        expect_payload(ddb, outputs["pitr"], original)
        wait(lambda: item(replica, outputs["source"]), lambda value: value and value["payload"] == {"B": live},
             "Regional replica did not independently read current binary data")
        for label in ("backup", "pitr"):
            table = outputs[label]
            require(not ddb.describe_table(TableName=table)["Table"].get("StreamSpecification", {}).get("StreamEnabled"),
                    "Restore silently inherited operational streams")
            require(ddb.describe_time_to_live(TableName=table)["TimeToLiveDescription"]["TimeToLiveStatus"] == "DISABLED",
                    "Restore silently inherited TTL")
            require(ddb.describe_continuous_backups(TableName=table)["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "DISABLED",
                    "Restore silently inherited PITR")
        isolation = {"pk": {"S": "restore-isolation"}}
        try:
            put(ddb, outputs["backup"], b"backup-private\x00\xff", isolation)
            require(item(ddb, outputs["source"], isolation) is None and item(ddb, outputs["pitr"], isolation) is None,
                    "Backup target mutation leaked into source/PITR storage")
            put(ddb, outputs["pitr"], b"pitr-private\x00\xff", isolation)
            expect_payload(ddb, outputs["backup"], b"backup-private\x00\xff", isolation)
            require(item(ddb, outputs["source"], isolation) is None, "PITR target mutation leaked into source")
        finally:
            for label in ("backup", "pitr"):
                ddb.delete_item(TableName=outputs[label], Key=isolation)
        regional_key = {"pk": {"S": "regional-writer"}}
        try:
            put(replica, outputs["source"], b"west-to-east\x00\xff", regional_key)
            wait(lambda: item(ddb, outputs["source"], regional_key),
                 lambda value: value and value["payload"] == {"B": b"west-to-east\x00\xff"}, "Replica write did not replicate back")
            require(item(ddb, outputs["backup"], regional_key) is None and item(ddb, outputs["pitr"], regional_key) is None,
                    "Live replica mutation changed frozen restores")
        finally:
            replica.delete_item(TableName=outputs["source"], Key=regional_key)
        recovery = ddb.describe_continuous_backups(TableName=outputs["source"])["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
        require(recovery["PointInTimeRecoveryStatus"] == "ENABLED" and recovery["RecoveryPeriodInDays"] == (3 if values["revision"] == "initial" else 4),
                "PITR retention update differs")
        tags = {tag["Key"]: tag["Value"] for tag in ddb.list_tags_of_resource(ResourceArn=outputs["source_arn"])["Tags"]}
        require(tags["Revision"] == values["revision"] and tags["SeparateOwner"] == values["revision"], "Independent tag resource update differs")
        for label in ("backup", "pitr"):
            restored_arn = ddb.describe_table(TableName=outputs[label])["Table"]["TableArn"]
            restored_tags = {tag["Key"]: tag["Value"] for tag in ddb.list_tags_of_resource(ResourceArn=restored_arn)["Tags"]}
            require(restored_tags == {"Fixture": values["name"], "Revision": values["revision"]},
                    "Declared restored-table tags differ")
        policy = json.loads(ddb.get_resource_policy(ResourceArn=outputs["source_arn"])["Policy"])
        require(policy["Statement"][0]["Sid"] == "Read" + values["revision"], "Terraform resource policy update differs")
        _clock(active_endpoint, "300s")
        rows = wait(lambda: ddb.query(TableName=outputs["capacity"], IndexName="by-group", KeyConditionExpression="#g = :g",
                    ExpressionAttributeNames={"#g": "group"}, ExpressionAttributeValues={":g": {"S": "fixture"}}),
                    lambda result: result.get("Items") and result["Items"][0]["revision"] == {"S": values["revision"]},
                    "Standalone native GSI did not return the updated Terraform item")
        require(rows["Items"][0]["pk"] == {"S": "terraform"}, "Standalone GSI key differs")
        capacity(ddb)
        rejected_settings(ddb)
        authority(ddb)
        consume_changes(ddb)
        if outputs.get("separate"):
            separate_key = {"pk": {"S": "separate-native"}}
            put(ddb, outputs["separate"], b"separate-replica\x00\xff", separate_key)
            wait(lambda: item(replica, outputs["separate"], separate_key),
                 lambda value: value and value["payload"] == {"B": b"separate-replica\x00\xff"}, "Separate resource replica has no native item")
            require(remember(ddb, outputs["separate"], "separate-source") != remember(replica, outputs["separate"], "separate-replica"),
                    "Separate replica aliases its source incarnation")
        # Advance by actual service time, not a 24-hour wall sleep, and observe
        # TTL removal from both independent regional native readers.
        ttl_key = {"pk": {"S": "ttl-native"}}
        now = datetime.fromisoformat(_clock(active_endpoint).replace("Z", "+00:00"))
        ddb.put_item(TableName=outputs["source"], Item=dict(ttl_key, payload={"B": b"expires\x00\xff"}, expires={"N": str(int(now.timestamp()) + 120)}))
        wait(lambda: item(replica, outputs["source"], ttl_key), bool, "TTL item did not first replicate")
        _clock(active_endpoint, "180s")
        wait(lambda: (item(ddb, outputs["source"], ttl_key), item(replica, outputs["source"], ttl_key)),
             lambda result: result == (None, None), "TTL did not remove native regional items")
        _private(directory / "native-evidence.json", json.dumps({"table_incarnations": incarnations,
                 "source_sha256": hashlib.sha256(live).hexdigest(),
                 "snapshot_sha256": hashlib.sha256(original).hexdigest(),
                 "backup_arn": backup_arn, "restore_time": values["restore_time"]}, sort_keys=True, indent=2))
        stages.append({"stage": "dynamodb-native-restores-replicas-consumers-" + values["revision"], "status": "passed"})
        unchanged("verify-" + values["revision"])

    def cleanup(endpoint=None):
        nonlocal active_endpoint
        active_endpoint = local_endpoint(endpoint or active_endpoint)
        # A source that added replicas is protected for 24 service-time hours.
        _clock(active_endpoint, "24h")
        if values["deletion_protection_enabled"]:
            values["deletion_protection_enabled"] = False
            tf("apply", "-input=false", "-auto-approve")
        tf("destroy", "-input=false", "-auto-approve")
        ddb = client("dynamodb", active_endpoint)
        if values["separate_source_name"]:
            ddb.delete_table(TableName=values["separate_source_name"])
            wait(lambda: ddb.list_tables(), lambda result: values["separate_source_name"] not in result["TableNames"],
                 "Owned direct source table did not retire")
        # Deleting a PITR source creates real SYSTEM snapshots in each region.
        # Delete user backups, but let SYSTEM backups reach their stated expiry:
        # their DeleteBackup API correctly rejects user deletion.
        owned_names = {values["name"] + "-ddb-" + suffix for suffix in ("source", "capacity", "limited", "backup", "pitr", "separate")}
        system_backups = []
        now = datetime.fromisoformat(_clock(active_endpoint).replace("Z", "+00:00"))
        expiry_seconds = 25 * 60 * 60  # Closed Streams retain native data for24h.
        for region in (values["region"], REPLICA_REGION):
            regional = _regional("dynamodb", active_endpoint, region)
            # List once per region, then filter exact owned names. Six rapid
            # per-table requests exceed ListBackups' account request budget.
            backups = []
            for page in regional.get_paginator("list_backups").paginate(BackupType="ALL"):
                backups.extend(backup for backup in page.get("BackupSummaries", [])
                               if backup["TableName"] in owned_names)
            for backup in backups:
                if backup["BackupType"] == "SYSTEM":
                    require(backup.get("BackupExpiryDateTime") is not None, "Owned system backup has no expiry")
                    expiry_seconds = max(expiry_seconds, int((backup["BackupExpiryDateTime"] - now).total_seconds()) + 1)
                    system_backups.append((regional, backup["BackupArn"]))
                else:
                    regional.delete_backup(BackupArn=backup["BackupArn"])
                    expect_missing(regional.describe_backup, {"BackupNotFoundException"}, BackupArn=backup["BackupArn"])
        _clock(active_endpoint, str(expiry_seconds) + "s")
        for regional, arn in system_backups:
            expect_missing(regional.describe_backup, {"BackupNotFoundException"}, BackupArn=arn)
        for label in ("source", "capacity", "limited", "backup", "pitr", "separate"):
            if outputs.get(label):
                expect_missing(ddb.describe_table, {"ResourceNotFoundException"}, TableName=outputs[label])
        for table in (outputs.get("source"), outputs.get("separate")):
            if table:
                expect_missing(_regional("dynamodb", active_endpoint, REPLICA_REGION).describe_table,
                               {"ResourceNotFoundException"}, TableName=table)
        if outputs.get("kinesis_name"):
            expect_missing(client("kinesis", active_endpoint).describe_stream, {"ResourceNotFoundException"}, StreamName=outputs["kinesis_name"])
        _clock(active_endpoint, "301s")
        state = json.loads(tf("show", "-json").stdout)
        require(not state.get("values", {}).get("root_module", {}).get("resources"), "Owned DynamoDB Terraform state is not empty")
        stages.append({"stage": "dynamodb-destroy-exact-owned-cleanup", "status": "passed"})

    try:
        tf("init", "-input=false")
        tf("apply", "-input=false", "-auto-approve")
        refresh_outputs()
        _clock(active_endpoint, "10s")
        values["pitr_enabled"] = True
        tf("apply", "-input=false", "-auto-approve")
        ddb = client("dynamodb", active_endpoint)
        put(ddb, outputs["source"], original)
        backup_arn = ddb.create_backup(TableName=outputs["source"], BackupName=values["name"] + "-immutable")["BackupDetails"]["BackupArn"]
        wait(lambda: ddb.describe_backup(BackupArn=backup_arn)["BackupDescription"]["BackupDetails"],
             lambda value: value["BackupStatus"] == "AVAILABLE", "Native snapshot never became available")
        # Select a historical point strictly before the source mutation, rather
        # than relying on the five-minute sampled latest-restorable watermark.
        values["restore_time"] = _clock(active_endpoint, "1s")
        _clock(active_endpoint, "2s")
        put(ddb, outputs["source"], live)
        values.update(backup_arn=backup_arn, restores_enabled=True, replicas_enabled=True)
        try:
            managed = _regional("kms", active_endpoint, REPLICA_REGION).describe_key(KeyId="alias/aws/dynamodb")["KeyMetadata"]
        except ClientError as error:
            require(error.response["Error"]["Code"] == "NotFoundException", str(error))
            stages.append({"stage": "dynamodb-separate-replica-prerequisite", "status": "unverified",
                           "reason": "Provider Read requires real us-west-2 alias/aws/dynamodb; the existing DDB owner cannot provision it"})
        else:
            require(managed["KeyManager"] == "AWS", "Refusing a manufactured DynamoDB service alias")
            separate_name = values["name"] + "-ddb-separate"
            created = ddb.create_table(TableName=separate_name, BillingMode="PAY_PER_REQUEST",
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"})["TableDescription"]
            values.update(separate_source_name=separate_name, separate_source_arn=created["TableArn"])
            wait(lambda: ddb.describe_table(TableName=separate_name)["Table"],
                 lambda value: value["TableStatus"] == "ACTIVE", "Owned separate replica source did not become native-ready")
            _clock(active_endpoint, "10s")
            values["separate_replica_enabled"] = True
        tf("apply", "-input=false", "-auto-approve")
        reconcile_restore_tags()
        verify()
        values.update(revision="updated", deletion_protection_enabled=True)
        tf("apply", "-input=false", "-auto-approve")
        refresh_outputs()
        verify()
        # Back up OWNED state bytes before every destructive state operation.
        # Restored tables are intentionally excluded: their create-only PITR
        # timestamp cannot be recovered by the current provider's Import Read.
        imports = {
            "aws_dynamodb_table.source": outputs["source"],
            "aws_dynamodb_table.capacity": outputs["capacity"],
            "aws_dynamodb_table.limited": outputs["limited"],
            "aws_dynamodb_global_secondary_index.group": outputs["capacity"] + ",by-group",
            "aws_dynamodb_table_item.item": outputs["capacity"] + ",terraform",
            "aws_dynamodb_resource_policy.reader": outputs["source_arn"],
            "aws_dynamodb_tag.separate": outputs["source_arn"] + ",SeparateOwner",
            "aws_dynamodb_kinesis_streaming_destination.changes": outputs["source"] + "," + outputs["kinesis_arn"],
            "aws_iam_user.reader": outputs["reader"],
            "aws_kinesis_stream.changes": outputs["kinesis_name"],
        }
        if outputs.get("separate"):
            imports["aws_dynamodb_table_replica.separate[0]"] = outputs["separate"] + ":" + values["region"]
        state_path = directory / "terraform.tfstate"
        for index, (address, identity) in enumerate(imports.items()):
            prior = state_path.read_bytes()
            _private(directory / f"before-import-{index}.tfstate", prior)
            try:
                tf("state", "rm", address)
                tf("import", "-input=false", address, identity)
            except Exception:
                _private(state_path, prior)
                raise
        tf("apply", "-input=false", "-auto-approve")
        unchanged("import")
        # A removed/re-added replica must get a new incarnation; old delivery
        # cursors and native tables cannot masquerade as the replacement.
        old_replica = incarnations.pop("replica")
        _clock(active_endpoint, "24h")
        values["replicas_enabled"] = False
        tf("apply", "-input=false", "-auto-approve")
        expect_missing(_regional("dynamodb", active_endpoint, REPLICA_REGION).describe_table,
                       {"ResourceNotFoundException"}, TableName=outputs["source"])
        values["replicas_enabled"] = True
        tf("apply", "-input=false", "-auto-approve")
        refresh_outputs()
        new_replica = remember(_regional("dynamodb", active_endpoint, REPLICA_REGION), outputs["source"], "replica")
        require(new_replica != old_replica, "Re-added replica reused a retired native incarnation")
        incarnations["retired-replica"] = old_replica
        stages.append({"stage": "dynamodb-replica-incarnation-replacement", "status": "passed"})
        verify()
        return verify, cleanup
    except Exception:
        cleanup()
        raise
