"""Terraform DocDB control lifecycle with real TLS/SCRAM MongoDB consumers.

The native image is MongoDB 7.0.43, not AWS DocumentDB. Daily backups are cold
physical copies and may stop connections. Continuous backup/PITR is not claimed.
"""
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid

import boto3
from botocore.config import Config

from local import client, environment, expect_missing, require


def run(args, root, endpoint, terraform, variables, stages):
    try:
        from bson.binary import Binary
        from pymongo import MongoClient
        from pymongo.errors import OperationFailure
    except ImportError as error:
        raise RuntimeError("Install pymongo before the DocDB native example") from error
    shutil.copyfile(Path(__file__).with_name("docdb.tf"), root / "main.tf")
    namespace = "stackd-docdb-" + hashlib.sha256(str(root.parent / "stackd.sqlite").encode()).hexdigest()[:24]
    passwords = {"source": "local-" + uuid.uuid4().hex, "restore": None}
    passwords["restore"] = passwords["source"]
    ports = []
    # Keep reservations together so source and restore cannot select the same port.
    with socket.socket() as source_port, socket.socket() as restore_port:
        for reservation in (source_port, restore_port):
            reservation.bind(("127.0.0.1", 0))
            ports.append(reservation.getsockname()[1])
    values = {key: variables[key] for key in ("endpoint", "region", "name")}
    values.update(password=passwords["source"], native_port=ports[0], restore_port=ports[1],
                  retention=1, backup_window="09:00-09:30", restore_snapshot="", revision="one")
    outputs = None
    payload = b"native docdb binary proof\x00\xff" + uuid.uuid4().bytes

    def stage(name):
        stages.append({"stage": "docdb-" + name, "status": "passed"})
        print("Completed DocDB stage:", name, flush=True)

    def tf(*command, check=True):
        return terraform(list(command), root, check=check)

    def save():
        path = root / "local.auto.tfvars.json"
        path.write_text(json.dumps(values))
        path.chmod(0o600)

    def current_outputs():
        return json.loads(tf("output", "-json", "clusters").stdout)

    def poll(observation, complete, message):
        deadline = time.monotonic() + 360
        while True:
            result = observation()
            if complete(result):
                return result
            require(time.monotonic() < deadline, message)
            time.sleep(0.5)

    def advance(duration):
        request = urllib.request.Request(endpoint + "/_stackd/clock", data=json.dumps({"advance": duration}).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
            require(response.status == 200, "Manual service-time advance failed")
            response.read()

    def describe(name):
        return client("docdb", endpoint).describe_db_clusters(DBClusterIdentifier=name)["DBClusters"][0]

    def available(name):
        return poll(lambda: describe(name), lambda c: c["Status"] == "available" and bool(c.get("Endpoint"))
                    and len(c.get("DBClusterMembers", [])) == 1, "Native DocDB writer did not become available")

    def native(which, password=None):
        output = outputs[which]
        require(output["address"] in ("localhost", "127.0.0.1"), "Refusing a non-local document endpoint")
        cluster = available(output["id"])
        native_id = cluster["DbClusterResourceId"].removeprefix("cluster-")
        command = ["docker", "--host", "unix:///var/run/docker.sock", "ps", "-q", "--filter",
                   "label=stackd.docdb.namespace=" + namespace, "--filter", "label=stackd.docdb.id=" + native_id,
                   "--filter", "label=stackd.docdb.role=database"]
        result = subprocess.run(command, env=environment(), capture_output=True, text=True, check=True)
        identifiers = result.stdout.split()
        require(len(identifiers) == 1, "No exact-owned native DocDB writer exists")
        result = subprocess.run(["docker", "--host", "unix:///var/run/docker.sock", "exec", identifiers[0],
                                 "cat", "/data/db/security/ca.pem"], env=environment(), capture_output=True, check=True)
        ca = root / (which + "-ca.pem")
        ca.write_bytes(result.stdout)
        ca.chmod(0o600)
        connection = MongoClient(output["address"], output["port"], username="storageowner",
                                 password=password or passwords[which], authSource="admin", replicaSet="stackd",
                                 tls=True, tlsCAFile=str(ca), retryWrites=False,
                                 serverSelectionTimeoutMS=10000, connectTimeoutMS=5000)
        try:
            connection.admin.command("ping")
        except BaseException:
            connection.close()
            raise
        return connection

    def rows(which):
        with native(which) as connection:
            return list(connection.proof.records.find({}, {"_id": 1, "note": 1, "payload": 1}).sort("_id"))

    def check_rows(which, identifiers):
        actual = rows(which)
        require([row["_id"] for row in actual] == identifiers, "Native document commit/rollback or snapshot cut changed")
        require(actual[0]["note"] == "committed" and bytes(actual[0]["payload"]) == payload,
                "Native document bytes changed")
        with native(which) as connection:
            require("note_1" in connection.proof.records.index_information(), "Physical snapshot did not retain the native index")

    def wrong_password(which, password):
        try:
            connection = native(which, password=password)
        except OperationFailure as error:
            require(error.code == 18, "Unexpected native authentication error")
        else:
            connection.close()
            raise RuntimeError("Native document endpoint accepted a wrong or retired password")

    def no_change():
        for options in (("-refresh-only",), ()):
            result = tf("plan", "-input=false", "-detailed-exitcode", *options, check=False)
            require(result.returncode == 0, "DocDB refresh or ordinary plan contains unmanaged drift")

    def authority():
        iam = client("iam", endpoint)
        name = values["name"] + "-docdb-consumer"
        key = None
        iam.create_user(UserName=name)
        try:
            key = iam.create_access_key(UserName=name)["AccessKey"]
            consumer = boto3.Session(aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"],
                                     region_name=values["region"]).client("docdb", endpoint_url=endpoint,
                                         config=Config(connect_timeout=3, read_timeout=30, proxies={}, retries={"max_attempts": 0}))
            document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "rds:DescribeDBClusters", "Resource": outputs["source"]["arn"]}]}
            iam.put_user_policy(UserName=name, PolicyName="current-source", PolicyDocument=json.dumps(document))
            require(consumer.describe_db_clusters(DBClusterIdentifier=outputs["source"]["id"])["DBClusters"][0]["DBClusterArn"] == outputs["source"]["arn"], "Current scoped authority failed")
            document["Statement"][0]["Effect"] = "Deny"
            iam.put_user_policy(UserName=name, PolicyName="current-source", PolicyDocument=json.dumps(document))
            expect_missing(consumer.describe_db_clusters, {"AccessDenied", "AccessDeniedException"}, DBClusterIdentifier=outputs["source"]["id"])
        finally:
            if key is not None:
                iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
            # This owned user may have failed before policy admission.
            for policy in iam.list_user_policies(UserName=name).get("PolicyNames", []):
                iam.delete_user_policy(UserName=name, PolicyName=policy)
            iam.delete_user(UserName=name)
        stage("current-iam-allow-then-revoked")

    def snapshots():
        return client("docdb", endpoint).describe_db_cluster_snapshots(
            DBClusterIdentifier=outputs["source"]["id"], SnapshotType="automated").get("DBClusterSnapshots", [])

    def verify(reopened=None):
        nonlocal endpoint, outputs
        endpoint = reopened or endpoint
        values["endpoint"] = endpoint
        save()
        for which in ("source", "restore"):
            available(outputs[which]["id"])
        refreshed = current_outputs()
        require(refreshed == outputs, "Reopen changed DocDB native identity, endpoint or configuration")
        no_change()
        check_rows("source", [1, 3])
        check_rows("restore", [1])
        authority()
        stage("refresh-reopen-retained-native-documents")

    def cleanup(reopened=None):
        nonlocal endpoint
        endpoint = reopened or endpoint
        values["endpoint"] = endpoint
        save()
        tf("destroy", "-input=false", "-auto-approve")
        if outputs is not None:
            for output in outputs.values():
                if output is None:
                    continue
                expect_missing(client("docdb", endpoint).describe_db_clusters, {"DBClusterNotFoundFault"}, DBClusterIdentifier=output["id"])
                expect_missing(client("docdb", endpoint).describe_db_instances, {"DBInstanceNotFound"}, DBInstanceIdentifier=output["writer_id"])
        state = json.loads(tf("show", "-json").stdout)
        require(not state.get("values", {}).get("root_module", {}).get("resources"), "DocDB Terraform state retains resources")
        stage("destroy-and-signed-absence")

    try:
        save()
        tf("init", "-input=false")
        tf("apply", "-input=false", "-auto-approve")
        # The cluster exists before its writer. Observe the real ready endpoint
        # after that dependency starts; later no-op checks remain strict.
        tf("apply", "-refresh-only", "-input=false", "-auto-approve")
        outputs = current_outputs()
        with native("source") as connection:
            require(connection.admin.command("buildInfo")["version"] == "7.0.43", "Native compatibility binary is not pinned MongoDB 7.0.43")
            collection = connection.proof.records
            collection.create_index("note")
            with connection.start_session() as session:
                with session.start_transaction():
                    collection.insert_one({"_id": 1, "note": "committed", "payload": Binary(payload)}, session=session)
                session.start_transaction()
                collection.insert_one({"_id": 2, "note": "rolled back"}, session=session)
                session.abort_transaction()
        check_rows("source", [1])
        wrong_password("source", "wrong-" + uuid.uuid4().hex)
        stage("terraform-create-native-tls-scram-transactions-bytes")
        advance("2m")
        copies = poll(snapshots, lambda items: len(items) == 1 and items[0]["Status"] == "available", "Daily native automated snapshot did not complete")
        first = copies[0]["DBClusterSnapshotIdentifier"]
        available(outputs["source"]["id"])
        with native("source") as connection:
            connection.proof.records.insert_one({"_id": 3, "note": "after snapshot"})
        values["restore_snapshot"] = first
        save()
        tf("apply", "-input=false", "-auto-approve")
        tf("apply", "-refresh-only", "-input=false", "-auto-approve")
        outputs = current_outputs()
        check_rows("source", [1, 3])
        check_rows("restore", [1])
        stage("daily-cold-backup-and-independent-native-restore")
        old = passwords["source"]
        passwords["source"] = "rotated-" + uuid.uuid4().hex
        values.update(password=passwords["source"], retention=2, backup_window="09:05-09:35", revision="two")
        save()
        tf("apply", "-input=false", "-auto-approve")
        outputs = current_outputs()
        wrong_password("source", old)
        check_rows("source", [1, 3])
        check_rows("restore", [1])
        require(describe(outputs["source"]["id"])["BackupRetentionPeriod"] == 2, "Backup retention change was not retained")
        require(describe(outputs["source"]["id"])["PreferredBackupWindow"] == "09:05-09:35", "Backup window change was not retained")
        stage("password-tags-retention-window-update")
        advance("24h")
        poll(snapshots, lambda items: len(items) == 2 and all(item["Status"] == "available" for item in items), "Updated daily backup schedule did not create a real second snapshot")
        available(outputs["source"]["id"])
        values["retention"] = 1
        save()
        tf("apply", "-input=false", "-auto-approve")
        poll(snapshots, lambda items: len(items) == 1 and items[0]["DBClusterSnapshotIdentifier"] != first,
             "Shorter retention did not retire the exact expired native snapshot")
        check_rows("restore", [1])
        stage("retention-expiry-preserves-independent-restored-bytes")
        # ApplyImmediately is not a setting change. It must return this owned
        # instance without restarting the real native writer.
        api = client("docdb", endpoint)
        before = api.describe_db_instances(DBInstanceIdentifier=outputs["source"]["writer_id"])["DBInstances"][0]
        native_id = outputs["source"]["resource_id"].removeprefix("cluster-")
        native_containers = subprocess.run(
            ["docker", "--host", "unix:///var/run/docker.sock", "ps", "-q", "--filter",
             "label=stackd.docdb.namespace=" + namespace, "--filter", "label=stackd.docdb.id=" + native_id,
             "--filter", "label=stackd.docdb.role=database"],
            env=environment(), text=True, capture_output=True, check=True).stdout.split()
        require(len(native_containers) == 1, "No exact-owned native writer exists before instance reassertion")
        inspect = ["docker", "--host", "unix:///var/run/docker.sock", "inspect", "--format",
                   "{{.Id}} {{.State.Pid}} {{.State.StartedAt}}", native_containers[0]]
        process = subprocess.run(inspect, env=environment(), text=True, capture_output=True, check=True).stdout
        updated = api.modify_db_instance(DBInstanceIdentifier=outputs["source"]["writer_id"],
                                         ApplyImmediately=True)["DBInstance"]
        require(updated == before, "No-change instance update altered actual instance fields or timestamps")
        require(subprocess.run(inspect, env=environment(), text=True, capture_output=True, check=True).stdout == process,
                "No-change instance update restarted or replaced the native process")
        stage("instance-reassertion-preserves-native-process-and-timestamps")
        for address, identifier in (("aws_docdb_cluster.source", outputs["source"]["id"]),
                                    ("aws_docdb_cluster_instance.source", outputs["source"]["writer_id"])):
            tf("state", "rm", address)
            tf("import", "-input=false", address, identifier)
        # Imported passwords are not readable. Apply restores ordinary configured
        # authority; no ignored attributes or silent drift exemption is used.
        tf("apply", "-input=false", "-auto-approve")
        outputs = current_outputs()
        no_change()
        check_rows("source", [1, 3])
        check_rows("restore", [1])
        authority()
        stage("import-update-refresh-no-change")
        return verify, cleanup
    except BaseException:
        cleanup()
        raise
