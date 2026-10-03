#!/usr/bin/env python3
"""Signed CLI + real TLS/SCRAM MongoDB compatibility-engine workflow.

Requires boto3, pymongo, Docker, the explicitly installed pinned Mongo image,
an actual built stackd executable and an empty owned state directory. Never uses
ambient AWS credentials or provisions an AWS engine.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from stackd_process import StackdProcess


def require(ok, message):
    if not ok:
        raise AssertionError(message)


class Workflow:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state / "docdb.sqlite"
        require(not self.database.exists(), "state already contains docdb.sqlite")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        self.env.update(AWS_EC2_METADATA_DISABLED="true", AWS_MAX_ATTEMPTS="1")
        self.controller = StackdProcess(self.state)
        self.password = "Owned!" + uuid.uuid4().hex
        self.prefix = "docdb-proof-" + uuid.uuid4().hex[:8]
        self.clusters, self.instances, self.snapshots = [], [], []
        self.namespace = None
        self.report = {"observations": {}, "cleanup": {}, "controllers": self.controller.runs}
        self.api = self.client("docdb")

    def client(self, service, key="test", secret="test", region="us-east-1"):
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region,
                            aws_access_key_id=key, aws_secret_access_key=secret,
                            config=Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=90))

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"127.0.0.1:{self.port}",
            "-database", str(self.database), "-docker-host", self.args.docker_host, "-docdb-runtime",
            "-compute-endpoint", f"http://host.docker.internal:{self.port}"]
        if self.args.with_rds:
            command.append("-rds-runtime")
        self.controller.start(command, self.endpoint, environment=self.env, timeout=90)

    def rejected(self, call, codes):
        try:
            call()
        except ClientError as error:
            code = error.response["Error"]["Code"]
            require(code in codes, "unexpected modeled error: " + code)
            return code
        raise AssertionError("operation unexpectedly succeeded")

    def wait(self, kind, name, status="available"):
        method, field, rows, state = {
            "cluster": ("describe_db_clusters", "DBClusterIdentifier", "DBClusters", "Status"),
            "instance": ("describe_db_instances", "DBInstanceIdentifier", "DBInstances", "DBInstanceStatus"),
            "snapshot": ("describe_db_cluster_snapshots", "DBClusterSnapshotIdentifier", "DBClusterSnapshots", "Status"),
        }[kind]
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            try:
                row = getattr(self.api, method)(**{field: name})[rows][0]
            except ClientError as error:
                if status == "deleted" and "NotFound" in error.response["Error"]["Code"]:
                    return None
                raise
            if row[state] == status:
                return row
            require(row[state] != "failed", "native lifecycle failed: " + name)
            time.sleep(0.2)
        raise TimeoutError(f"{kind} {name} -> {status}")

    def document_client(self, row, password=None, **options):
        identity = row["DbClusterResourceId"].removeprefix("cluster-")
        containers = subprocess.check_output(["docker", "ps", "-q", "--filter", "label=stackd.docdb.id=" + identity,
                                              "--filter", "label=stackd.docdb.role=database"], text=True).split()
        require(len(containers) == 1, "native owner is not unique")
        inspect = json.loads(subprocess.check_output(["docker", "inspect", containers[0]], text=True))[0]
        self.namespace = inspect["Config"]["Labels"]["stackd.docdb.namespace"]
        bindings = inspect["HostConfig"]["PortBindings"]
        require(all(binding["HostIp"] == "127.0.0.1" for values in bindings.values() for binding in values),
                "document endpoint leaked beyond loopback")
        ca = self.state / (identity + ".ca.pem")
        ca.write_bytes(subprocess.check_output(["docker", "exec", containers[0], "cat", "/data/db/security/ca.pem"]))
        config = dict(host=row["Endpoint"], port=row["Port"], username="dbowner", password=password or self.password,
                      authSource="admin", replicaSet="stackd", tls=True, tlsCAFile=str(ca), retryWrites=False,
                      serverSelectionTimeoutMS=3000, connectTimeoutMS=3000)
        config.update(options)
        client = MongoClient(**config)
        try:
            client.admin.command("ping")
        except Exception:
            client.close()
            raise
        return client

    def create(self, name):
        self.api.create_db_cluster(DBClusterIdentifier=name, Engine="docdb", EngineVersion="5.0",
                                   MasterUsername="dbowner", MasterUserPassword=self.password,
                                   Tags=[{"Key": "owner", "Value": self.prefix}])
        self.clusters.append(name)
        writer = name + "-writer"
        self.api.create_db_instance(DBInstanceIdentifier=writer, DBClusterIdentifier=name, Engine="docdb",
                                    DBInstanceClass="db.t3.medium", AutoMinorVersionUpgrade=False)
        self.instances.append(writer)
        self.wait("instance", writer)
        return self.wait("cluster", name)

    def run(self):
        observed = self.report["observations"]
        missing = self.prefix + "-absent"
        observed["native_fixture_errors"] = [
            self.rejected(lambda: self.api.describe_db_clusters(DBClusterIdentifier=missing), {"DBClusterNotFoundFault"}),
            self.rejected(lambda: self.api.describe_db_instances(DBInstanceIdentifier=missing), {"DBInstanceNotFound"}),
            self.rejected(lambda: self.api.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=missing), {"DBClusterSnapshotNotFoundFault"}),
            self.rejected(lambda: self.api.describe_db_clusters(MaxRecords=1), {"InvalidParameterValue"}),
        ]
        observed["unsupported_network"] = self.rejected(lambda: self.api.create_db_cluster(DBClusterIdentifier=missing,
            Engine="docdb", MasterUsername="dbowner", MasterUserPassword=self.password, VpcSecurityGroupIds=["sg-deadbeef"]),
            {"InvalidParameterCombination"})
        observed["unsupported_engine_catalog"] = self.rejected(
            lambda: self.api.describe_db_engine_versions(Engine="docdb"), {"InvalidParameterCombination"})
        source = self.prefix + "-source"
        row = self.create(source)
        observed["source_arn"] = row["DBClusterArn"]
        observed["official_go_sdk"] = json.loads(subprocess.check_output(
            [str(Path(self.args.sdk_binary).resolve()), "-endpoint", self.endpoint, "-cluster", source],
            env=self.env, text=True, timeout=45))
        observed["unsupported_rds_option"] = self.rejected(lambda: self.client("rds").modify_db_cluster(
            DBClusterIdentifier=source, EnableHttpEndpoint=True), {"InvalidParameterCombination"})
        events = self.client("cloudtrail").lookup_events(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ModifyDBCluster"}])["Events"]
        assert any(json.loads(event["CloudTrailEvent"]).get("errorCode") == "InvalidParameterCombination" for event in events)
        observed["rejected_control_audit"] = True
        if self.args.with_rds:
            observed["shared_name_collision"] = self.rejected(lambda: self.client("rds").create_db_cluster(
                DBClusterIdentifier=source, Engine="aurora-postgresql", MasterUsername="dbowner",
                MasterUserPassword=self.password), {"DBClusterAlreadyExistsFault"})
        observed["region_isolation"] = self.rejected(lambda: self.client("docdb", region="us-west-2").describe_db_clusters(
            DBClusterIdentifier=source), {"DBClusterNotFoundFault"})
        for label, options in [("wrong_password", {"password": "DefinitelyWrong!"}),
                               ("untrusted_tls", {"tlsCAFile": None}),
                               ("plaintext_transport", {"tls": False, "tlsCAFile": None})]:
            try:
                bad = self.document_client(row, **options)
                bad.close()
            except PyMongoError:
                observed[label] = "rejected"
            else:
                raise AssertionError(label + " unexpectedly connected")
        with self.document_client(row) as client:
            collection = client.application.records
            with collection.watch(max_await_time_ms=1000) as stream:
                collection.insert_one({"_id": "before-snapshot", "value": "native UTF-8 λ", "nested": {"n": 7}})
                change = stream.next()
                require(change["operationType"] == "insert" and change["fullDocument"]["nested"]["n"] == 7,
                        "native change stream returned wrong document")
                token = stream.resume_token
            require(collection.find_one({"_id": "before-snapshot"})["value"] == "native UTF-8 λ", "native query mismatch")
        observed["native_insert_query_change_stream"] = True
        snapshot = self.prefix + "-snapshot"
        self.api.create_db_cluster_snapshot(DBClusterIdentifier=source, DBClusterSnapshotIdentifier=snapshot)
        self.snapshots.append(snapshot)
        self.wait("snapshot", snapshot)
        scoped_snapshots = self.api.describe_db_cluster_snapshots(DBClusterIdentifier=source)["DBClusterSnapshots"]
        assert [item["DBClusterSnapshotIdentifier"] for item in scoped_snapshots] == [snapshot]
        observed["source_filtered_snapshot"] = True
        row = self.wait("cluster", source)
        old_password = self.password
        self.password = "Rotated!" + uuid.uuid4().hex
        self.api.modify_db_cluster(DBClusterIdentifier=source, MasterUserPassword=self.password, ApplyImmediately=True)
        row = self.wait("cluster", source)
        try:
            bad = self.document_client(row, password=old_password)
            bad.close()
        except PyMongoError:
            observed["old_password_rejected"] = True
        else:
            raise AssertionError("old master password survived native rotation")
        self.api.stop_db_cluster(DBClusterIdentifier=source)
        self.wait("cluster", source, "stopped")
        with socket.socket() as connection:
            connection.settimeout(2)
            require(connection.connect_ex((row["Endpoint"], row["Port"])) != 0, "stopped native endpoint still accepting")
        self.api.start_db_cluster(DBClusterIdentifier=source)
        row = self.wait("cluster", source)
        before_restart = row["DbClusterResourceId"]
        self.controller.stop(timeout=60, kill_on_timeout=True)
        self.start()
        row = self.wait("cluster", source)
        require(row["DbClusterResourceId"] == before_restart, "controller restart replaced source incarnation")
        with self.document_client(row) as client:
            collection = client.application.records
            require(collection.find_one({"_id": "before-snapshot"})["nested"]["n"] == 7, "restart lost real bytes")
            with collection.watch(resume_after=token, max_await_time_ms=1000) as stream:
                collection.insert_one({"_id": "after-snapshot", "value": "source-only"})
                change = stream.next()
                require(change["documentKey"]["_id"] == "after-snapshot", "resume token lost native progress")
        observed["stop_start_controller_restart_resume"] = True
        restored = self.prefix + "-restored"
        self.api.restore_db_cluster_from_snapshot(DBClusterIdentifier=restored, SnapshotIdentifier=snapshot, Engine="docdb")
        self.clusters.append(restored)
        writer = restored + "-writer"
        self.api.create_db_instance(DBInstanceIdentifier=writer, DBClusterIdentifier=restored, Engine="docdb",
                                    DBInstanceClass="db.t3.medium", AutoMinorVersionUpgrade=False)
        self.instances.append(writer)
        restored_row = self.wait("cluster", restored)
        with self.document_client(restored_row, password=old_password) as client:
            require(client.application.records.find_one({"_id": "before-snapshot"})["nested"]["n"] == 7, "restore lost snapshot bytes")
            require(client.application.records.find_one({"_id": "after-snapshot"}) is None, "snapshot copied subsequent writes")
            client.application.records.insert_one({"_id": "restored-only"})
        self.api.delete_db_instance(DBInstanceIdentifier=source + "-writer")
        self.wait("instance", source + "-writer", "deleted")
        self.instances.remove(source + "-writer")
        self.api.delete_db_cluster(DBClusterIdentifier=source, SkipFinalSnapshot=True)
        self.wait("cluster", source, "deleted")
        self.clusters.remove(source)
        with self.document_client(restored_row, password=old_password) as client:
            require(client.application.records.find_one({"_id": "restored-only"}) is not None, "source deletion destroyed restore")
        observed["independent_physical_snapshot_restore"] = True
        iam = self.client("iam")
        user = self.prefix + "-denied"
        iam.create_user(UserName=user)
        access = iam.create_access_key(UserName=user)["AccessKey"]
        try:
            denied = self.client("docdb", access["AccessKeyId"], access["SecretAccessKey"])
            observed["iam_denial"] = self.rejected(lambda: denied.describe_db_clusters(DBClusterIdentifier=restored),
                                                   {"AccessDenied", "AccessDeniedException"})
        finally:
            iam.delete_access_key(UserName=user, AccessKeyId=access["AccessKeyId"])
            iam.delete_user(UserName=user)

    def cleanup(self):
        failures = []
        for name in reversed(self.instances[:]):
            try:
                self.api.delete_db_instance(DBInstanceIdentifier=name)
                self.wait("instance", name, "deleted")
                self.instances.remove(name)
            except Exception as error:
                failures.append(f"instance {name}: {type(error).__name__}")
        for name in reversed(self.clusters[:]):
            try:
                self.api.delete_db_cluster(DBClusterIdentifier=name, SkipFinalSnapshot=True)
                self.wait("cluster", name, "deleted")
                self.clusters.remove(name)
            except Exception as error:
                failures.append(f"cluster {name}: {type(error).__name__}")
        for name in self.snapshots[:]:
            try:
                self.api.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=name)
                self.wait("snapshot", name, "deleted")
                self.snapshots.remove(name)
            except Exception as error:
                failures.append(f"snapshot {name}: {type(error).__name__}")
        if self.namespace:
            for kind, command in [("containers", ["docker", "ps", "-aq"]), ("volumes", ["docker", "volume", "ls", "-q"])]:
                remaining = subprocess.check_output(command + ["--filter", "label=stackd.docdb.namespace=" + self.namespace], text=True).split()
                self.report["cleanup"][kind] = remaining
                if remaining:
                    failures.append("owned " + kind + " remain")
        self.report["cleanup"]["failures"] = failures
        require(not failures, "cleanup incomplete: " + "; ".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--sdk-binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--with-rds", action="store_true", help="also load pinned SQL images to prove the shared identifier namespace")
    args = parser.parse_args()
    workflow = Workflow(args)
    try:
        workflow.start()
        workflow.run()
    finally:
        try:
            if workflow.controller.process and workflow.controller.process.poll() is None:
                workflow.cleanup()
        finally:
            try:
                workflow.controller.stop(timeout=60, kill_on_timeout=True)
            finally:
                (workflow.state / "report.json").write_text(json.dumps(workflow.report, indent=2) + "\n")
    print(json.dumps(workflow.report, indent=2))


if __name__ == "__main__":
    main()
