#!/usr/bin/env python3
"""Local signed SDK/real-engine proof; never uses ambient AWS credentials.

Requires an explicitly built stackd binary, an empty owned state directory and
installed pinned database images. Native clients run in disposable Docker
containers against the actual returned local TCP endpoints.
"""
import argparse
import base64
import datetime
import hashlib
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

import rds_smoke_observations as observations
from stackd_process import StackdProcess

PG = "postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652"
MYSQL = "mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Application:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state / "rds.sqlite"
        require(not self.database.exists(), "state directory already contains rds.sqlite")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        self.env.update(AWS_EC2_METADATA_DISABLED="true", AWS_MAX_ATTEMPTS="1")
        self.controller = StackdProcess(self.state)
        self.password = "Owned!" + uuid.uuid4().hex
        self.prefix = "rds-proof-" + uuid.uuid4().hex[:8]
        self.instances, self.clusters, self.snapshots, self.secrets = [], [], [], []
        self.cluster_snapshots = []
        self.parameter_groups, self.cluster_parameter_groups = [], []
        self.report = {"endpoint": self.endpoint, "observations": {}, "cleanup": {}, "controllers": self.controller.runs}
        self.clock_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.bucket = self.trail = self.queue = self.rule = None
        self.rds, self.data, self.sm, self.iam = [self.client(s) for s in ("rds", "rds-data", "secretsmanager", "iam")]

    def client(self, service, key="test", secret="test", region="us-east-1"):
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region,
                            aws_access_key_id=key, aws_secret_access_key=secret,
                            config=Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=90))

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"127.0.0.1:{self.port}",
            "-database", str(self.database), "-docker-host", self.args.docker_host, "-rds-runtime",
            "-clock-start", self.clock_start,
            "-compute-endpoint", f"http://host.docker.internal:{self.port}"]
        self.controller.start(command, self.endpoint, environment=self.env, timeout=90)

    def wait_instance(self, name, status="available"):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            row = self.rds.describe_db_instances(DBInstanceIdentifier=name)["DBInstances"][0]
            state = row["DBInstanceStatus"]
            if state == status:
                return row
            require(state != "failed", "database failed native initialization: " + name)
            time.sleep(0.25)
        raise TimeoutError("instance transition " + name + " -> " + status)

    def wait_cluster(self, name, status="available"):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            row = self.rds.describe_db_clusters(DBClusterIdentifier=name)["DBClusters"][0]
            if row["Status"] == status:
                return row
            require(row["Status"] != "failed", "cluster native initialization failed")
            time.sleep(0.25)
        raise TimeoutError("cluster transition " + name)

    def native(self, engine, endpoint, sql, password=None):
        env = dict(self.env)
        if "postgres" in engine:
            env["PGPASSWORD"] = password or self.password
            command = ["docker", "run", "--rm", "--network", "host", "--env", "PGPASSWORD", PG,
                       "psql", "-Xq", "-v", "ON_ERROR_STOP=1", "-h", endpoint["Address"], "-p", str(endpoint["Port"]),
                       "-U", "dbowner", "-d", "appdb", "-tAc", sql]
        else:
            env["MYSQL_PWD"] = password or self.password
            command = ["docker", "run", "--rm", "--network", "host", "--env", "MYSQL_PWD", MYSQL,
                       "mysql", "--protocol=TCP", "--host=" + endpoint["Address"], "--port=" + str(endpoint["Port"]),
                       "--user=dbowner", "--database=appdb", "--batch", "--skip-column-names", "-e", sql]
        process = subprocess.run(command, env=env, capture_output=True, text=True, timeout=45)
        if process.returncode:
            raise RuntimeError("native database client failed: " + process.stderr.replace(self.password, "[REDACTED]"))
        return process.stdout.strip()

    def rejected(self, fn, allowed):
        try:
            fn()
        except ClientError as error:
            code = error.response["Error"]["Code"]
            require(code in allowed, "unexpected modeled error: " + code)
            return code
        raise AssertionError("operation unexpectedly succeeded")

    def execute(self, cluster, secret, sql, **options):
        return self.data.execute_statement(resourceArn=cluster, secretArn=secret, database="appdb", sql=sql, **options)

    def workflows(self):
        standalone = {}
        cluster_rows = {}
        for engine in ("postgres", "mysql"):
            name = self.prefix + "-" + engine
            self.instances.append(name)
            self.rds.create_db_instance(DBInstanceIdentifier=name, Engine=engine, DBInstanceClass="db.t3.small",
                DBName="appdb", MasterUsername="dbowner", MasterUserPassword=self.password)
            row = self.wait_instance(name)
            endpoint = row["Endpoint"]
            require(self.native(engine, endpoint, "CREATE TABLE durable (id INTEGER PRIMARY KEY); INSERT INTO durable VALUES (11); SELECT id FROM durable") == "11", "native committed row missing")
            require(self.native(engine, endpoint, "BEGIN; INSERT INTO durable VALUES (12); ROLLBACK; SELECT COUNT(*) FROM durable") == "1", "native rollback failed")
            standalone[engine] = row
            self.report["observations"][engine + "-endpoint"] = endpoint
            self.rds.stop_db_instance(DBInstanceIdentifier=name)
            self.wait_instance(name, "stopped")
            self.rds.start_db_instance(DBInstanceIdentifier=name)
            restarted = self.wait_instance(name)
            require(self.native(engine, restarted["Endpoint"], "SELECT id FROM durable") == "11", "stop/start lost bytes")

            cluster_name = self.prefix + "-aurora-" + engine
            self.clusters.append(cluster_name)
            self.rds.create_db_cluster(DBClusterIdentifier=cluster_name, Engine="aurora-" + ("postgresql" if engine == "postgres" else "mysql"),
                DatabaseName="appdb", MasterUsername="dbowner", MasterUserPassword=self.password, EnableHttpEndpoint=True)
            writer = cluster_name + "-writer"
            self.instances.append(writer)
            self.rds.create_db_instance(DBInstanceIdentifier=writer, DBClusterIdentifier=cluster_name,
                Engine="aurora-" + ("postgresql" if engine == "postgres" else "mysql"), DBInstanceClass="db.t3.small")
            self.wait_instance(writer)
            cluster = self.wait_cluster(cluster_name)
            secret = self.sm.create_secret(Name=cluster_name, SecretString=json.dumps({"username": "dbowner", "password": self.password}))
            self.secrets.append(secret["ARN"])
            arn = cluster["DBClusterArn"]
            cluster_rows[engine] = (cluster, secret["ARN"])
            self.execute(arn, secret["ARN"], "CREATE TABLE records (id INTEGER PRIMARY KEY, amount DECIMAL(20,4), note VARCHAR(100))")
            bound = [{"name": "id", "value": {"longValue": 1}}, {"name": "amount", "typeHint": "DECIMAL", "value": {"stringValue": "123456789012.3456"}}, {"name": "note", "value": {"isNull": True}}]
            self.execute(arn, secret["ARN"], "INSERT INTO records VALUES (:id,:amount,:note)", parameters=bound)
            self.data.batch_execute_statement(resourceArn=arn, secretArn=secret["ARN"], database="appdb",
                sql="INSERT INTO records (id,note) VALUES (:id,:note)", parameterSets=[
                    [{"name":"id","value":{"longValue":2}}, {"name":"note","value":{"stringValue":"bound:literal"}}],
                    [{"name":"id","value":{"longValue":3}}, {"name":"note","value":{"stringValue":"batch"}}]])
            tx = self.data.begin_transaction(resourceArn=arn, secretArn=secret["ARN"], database="appdb")["transactionId"]
            self.execute(arn, secret["ARN"], "INSERT INTO records (id) VALUES (4)", transactionId=tx)
            self.data.rollback_transaction(resourceArn=arn, secretArn=secret["ARN"], transactionId=tx)
            count = self.execute(arn, secret["ARN"], "SELECT COUNT(*) FROM records")["records"][0][0]["longValue"]
            require(count == 3, "Data API rollback leaked write")
            tx = self.data.begin_transaction(resourceArn=arn, secretArn=secret["ARN"], database="appdb")["transactionId"]
            self.execute(arn, secret["ARN"], "INSERT INTO records (id) VALUES (4)", transactionId=tx)
            self.data.commit_transaction(resourceArn=arn, secretArn=secret["ARN"], transactionId=tx)
            typed = self.execute(arn, secret["ARN"], "SELECT amount,note FROM records WHERE id=1", includeResultMetadata=True)
            require(typed["records"][0] == [{"stringValue":"123456789012.3456"},{"isNull":True}], "decimal/null projection changed")
            blob_sql = "SELECT CAST(:payload AS BYTEA)" if engine == "postgres" else "SELECT CAST(:payload AS BINARY)"
            blob = self.execute(arn, secret["ARN"], blob_sql, parameters=[{"name":"payload","value":{"blobValue":b"\x00\x01\xfe\xff"}}])
            require(blob["records"][0][0]["blobValue"] == b"\x00\x01\xfe\xff", "blob bytes changed")
            formatted = self.execute(arn, secret["ARN"], "SELECT id,note FROM records WHERE id=2", formatRecordsAs="JSON")
            require(json.loads(formatted["formattedRecords"]) == [{"id":2,"note":"bound:literal"}], "formatted results changed")
            self.rejected(lambda: self.execute(arn, secret["ARN"], "SELECT * FROM stackd_missing_table"), {"DatabaseErrorException", "BadRequestException"})
            self.rejected(lambda: self.execute(arn, secret["ARN"], "INSERT INTO records (id) VALUES (1)"), {"DatabaseErrorException", "BadRequestException"})
            self.rejected(lambda: self.execute(row["DBInstanceArn"], secret["ARN"], "SELECT 1"), {"BadRequestException", "InvalidResourceStateException", "HttpEndpointNotEnabledException"})
            self.report["observations"][engine + "-data-api"] = {"committed_count":4,"rollback_count":3,"decimal":"123456789012.3456","blob_base64":base64.b64encode(b"\x00\x01\xfe\xff").decode(),"errors":True}

        cluster, secret = cluster_rows["postgres"]
        arn = cluster["DBClusterArn"]
        user = self.prefix + "-limited"
        self.iam.create_user(UserName=user)
        key = self.iam.create_access_key(UserName=user)["AccessKey"]
        limited = self.client("rds-data", key["AccessKeyId"], key["SecretAccessKey"])
        policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds-data:*","Resource":arn}]}
        self.iam.put_user_policy(UserName=user, PolicyName="data", PolicyDocument=json.dumps(policy))
        denied = self.rejected(lambda: limited.execute_statement(resourceArn=arn,secretArn=secret,database="appdb",sql="SELECT 1"), {"AccessDeniedException", "ForbiddenException"})
        policy["Statement"].append({"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":secret})
        self.iam.put_user_policy(UserName=user, PolicyName="data", PolicyDocument=json.dumps(policy))
        require(limited.execute_statement(resourceArn=arn,secretArn=secret,database="appdb",sql="SELECT 7")["records"][0][0]["longValue"] == 7, "authorized secret failed")
        policy["Statement"].append({"Effect":"Deny","Action":"rds-data:ExecuteStatement","Resource":arn})
        self.iam.put_user_policy(UserName=user, PolicyName="data", PolicyDocument=json.dumps(policy))
        self.rejected(lambda: limited.execute_statement(resourceArn=arn,secretArn=secret,database="appdb",sql="SELECT 1"), {"AccessDeniedException", "ForbiddenException"})
        self.report["observations"]["iam"] = {"secret_denial":denied,"data_denial":True,"allow_after_policy":True}
        self.iam.delete_access_key(UserName=user,AccessKeyId=key["AccessKeyId"])
        self.iam.delete_user_policy(UserName=user,PolicyName="data")
        self.iam.delete_user(UserName=user)
        for region,keyid in (("us-west-2","test"),("us-east-1","111111111111")):
            scoped = self.client("rds",key=keyid,region=region)
            require(scoped.describe_db_instances()["DBInstances"] == [], "resource scope leaked")
            other = self.client("rds-data",key=keyid,region=region)
            self.rejected(lambda: other.execute_statement(resourceArn=arn,secretArn=secret,database="appdb",sql="SELECT 1"), {"AccessDeniedException","BadRequestException","InvalidResourceStateException","HttpEndpointNotEnabledException"})
        self.report["observations"]["scope_isolation"] = True

        unfinished = self.data.begin_transaction(resourceArn=arn,secretArn=secret,database="appdb")["transactionId"]
        self.execute(arn,secret,"INSERT INTO records (id) VALUES (99)",transactionId=unfinished)
        self.controller.stop(timeout=45, kill_on_timeout=True)
        self.start()
        for engine,row in standalone.items():
            current = self.wait_instance(row["DBInstanceIdentifier"])
            require(self.native(engine,current["Endpoint"],"SELECT id FROM durable") == "11", "controller restart lost native data")
        for engine,(cluster,credential) in cluster_rows.items():
            self.wait_cluster(cluster["DBClusterIdentifier"])
            require(self.execute(cluster["DBClusterArn"],credential,"SELECT COUNT(*) FROM records")["records"][0][0]["longValue"] == 4,"restart lost committed rows or committed unfinished transaction")
        self.rejected(lambda: self.data.commit_transaction(resourceArn=arn,secretArn=secret,transactionId=unfinished), {"TransactionNotFoundException","NotFoundException"})
        self.report["observations"]["controller_restart"] = {"committed_bytes_retained":True,"unfinished_transaction_rolled_back":True}

        for engine,row in standalone.items():
            snapshot = row["DBInstanceIdentifier"] + "-snapshot"
            self.snapshots.append(snapshot)
            self.rds.create_db_snapshot(DBInstanceIdentifier=row["DBInstanceIdentifier"],DBSnapshotIdentifier=snapshot)
            deadline=time.monotonic()+180
            while time.monotonic()<deadline:
                status=self.rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot)["DBSnapshots"][0]["Status"]
                if status=="available": break
                require(status != "failed","native snapshot failed")
                time.sleep(.25)
            else: raise TimeoutError("snapshot readiness")
            restored=row["DBInstanceIdentifier"]+"-restored"
            self.instances.append(restored)
            self.rds.restore_db_instance_from_db_snapshot(DBInstanceIdentifier=restored,DBSnapshotIdentifier=snapshot,DBInstanceClass="db.t3.small")
            target=self.wait_instance(restored)
            require(self.native(engine,target["Endpoint"],"SELECT id FROM durable")=="11","snapshot restore lost native bytes")
            self.native(engine,target["Endpoint"],"INSERT INTO durable VALUES (22)")
            require(self.native(engine,self.wait_instance(row["DBInstanceIdentifier"])["Endpoint"],"SELECT COUNT(*) FROM durable")=="1","restored volume aliases source")
            self.report["observations"][engine+"-snapshot"]={"restored":True,"independent":True}
            replacement = "Changed!" + uuid.uuid4().hex
            self.rds.modify_db_instance(DBInstanceIdentifier=row["DBInstanceIdentifier"],
                MasterUserPassword=replacement, ApplyImmediately=True, DeletionProtection=True)
            modified = self.wait_instance(row["DBInstanceIdentifier"])
            require(self.native(engine, modified["Endpoint"], "SELECT id FROM durable", replacement) == "11",
                    "modified native database credential was not applied")
            try:
                self.native(engine, modified["Endpoint"], "SELECT 1")
            except RuntimeError:
                pass
            else:
                raise AssertionError("old database credential remained valid")
            self.rejected(lambda: self.rds.delete_db_instance(DBInstanceIdentifier=row["DBInstanceIdentifier"],
                SkipFinalSnapshot=True), {"InvalidParameterCombination", "InvalidDBInstanceState", "InvalidParameterValue"})
            self.rds.modify_db_instance(DBInstanceIdentifier=row["DBInstanceIdentifier"],
                DeletionProtection=False, ApplyImmediately=True)
            self.wait_instance(row["DBInstanceIdentifier"])
            require(replacement.encode() not in self.database.read_bytes(), "modified password retained in plaintext")
            self.report["observations"][engine + "-modify"] = {"password_rotated": True, "old_password_denied": True,
                "deletion_protection": True}
        for engine, (cluster, credential) in cluster_rows.items():
            name = cluster["DBClusterIdentifier"]
            self.rds.stop_db_cluster(DBClusterIdentifier=name)
            self.wait_cluster(name, "stopped")
            self.rejected(lambda: self.execute(cluster["DBClusterArn"], credential, "SELECT 1"),
                          {"DatabaseUnavailableException", "InvalidResourceStateException"})
            self.rds.start_db_cluster(DBClusterIdentifier=name)
            self.wait_cluster(name)
            snapshot = name + "-snapshot"
            self.cluster_snapshots.append(snapshot)
            self.rds.create_db_cluster_snapshot(DBClusterIdentifier=name, DBClusterSnapshotIdentifier=snapshot)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                status = self.rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot)["DBClusterSnapshots"][0]["Status"]
                if status == "available":
                    break
                require(status != "failed", "native cluster snapshot failed")
                time.sleep(.25)
            else:
                raise TimeoutError("cluster snapshot readiness")
            restored = name + "-restored"
            self.clusters.append(restored)
            self.rds.restore_db_cluster_from_snapshot(DBClusterIdentifier=restored,
                SnapshotIdentifier=snapshot, Engine=cluster["Engine"])
            writer = restored + "-writer"
            self.instances.append(writer)
            self.rds.create_db_instance(DBInstanceIdentifier=writer, DBClusterIdentifier=restored,
                DBInstanceClass="db.t3.small", Engine=cluster["Engine"])
            target = self.wait_instance(writer)
            require(self.native(engine, target["Endpoint"], "SELECT COUNT(*) FROM records") == "4",
                    "cluster snapshot lost native records")
            self.native(engine, target["Endpoint"], "INSERT INTO records (id) VALUES (22)")
            self.wait_cluster(name)
            require(self.execute(cluster["DBClusterArn"], credential, "SELECT COUNT(*) FROM records")["records"][0][0]["longValue"] == 4,
                    "restored cluster aliases source")
            self.report["observations"][engine + "-cluster-snapshot"] = {"stop_start": True, "restored": True, "independent": True}
        observations.verify(self, *cluster_rows["postgres"])

    def cleanup(self):
        failures=[]
        if self.controller.process is not None and self.controller.process.poll() is None:
            for name in reversed(self.instances):
                try:
                    self.rds.delete_db_instance(DBInstanceIdentifier=name,SkipFinalSnapshot=True)
                    deadline=time.monotonic()+90
                    while time.monotonic()<deadline:
                        try: self.rds.describe_db_instances(DBInstanceIdentifier=name)
                        except ClientError as error:
                            if error.response["Error"]["Code"]=="DBInstanceNotFound": break
                            raise
                        time.sleep(.2)
                    else: raise TimeoutError("instance cleanup "+name)
                except Exception as error: failures.append(type(error).__name__+":"+name)
            for name in reversed(self.clusters):
                try: self.rds.delete_db_cluster(DBClusterIdentifier=name,SkipFinalSnapshot=True)
                except Exception as error: failures.append(type(error).__name__+":"+name)
            for name in self.snapshots:
                try: self.rds.delete_db_snapshot(DBSnapshotIdentifier=name)
                except Exception as error: failures.append(type(error).__name__+":"+name)
            for name in self.cluster_snapshots:
                try: self.rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=name)
                except Exception as error: failures.append(type(error).__name__+":"+name)
            for secret in self.secrets:
                try: self.sm.delete_secret(SecretId=secret,ForceDeleteWithoutRecovery=True)
                except Exception as error: failures.append(type(error).__name__+":secret")
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                if (not self.rds.describe_db_clusters()["DBClusters"]
                        and not self.rds.describe_db_snapshots()["DBSnapshots"]
                        and not self.rds.describe_db_cluster_snapshots()["DBClusterSnapshots"]):
                    break
                time.sleep(.2)
            else: failures.append("retained database resources not deleted")
            for name in self.parameter_groups:
                try: self.rds.delete_db_parameter_group(DBParameterGroupName=name)
                except Exception as error: failures.append(type(error).__name__+":"+name)
            for name in self.cluster_parameter_groups:
                try: self.rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name)
                except Exception as error: failures.append(type(error).__name__+":"+name)
            observations.cleanup(self)
        self.controller.stop(timeout=45, kill_on_timeout=True)
        namespace="stackd-rds-"+hashlib.sha256(str(self.database).encode()).hexdigest()[:24]
        containers=subprocess.run(["docker","ps","-aq","--filter","label=stackd.rds.namespace="+namespace],capture_output=True,text=True,check=True).stdout.split()
        volumes=subprocess.run(["docker","volume","ls","-q","--filter","label=stackd.rds.namespace="+namespace],capture_output=True,text=True,check=True).stdout.split()
        self.report["cleanup"]={"failures":failures,"containers":containers,"volumes":volumes,"namespace":namespace}
        require(not failures and not containers and not volumes,"owned cleanup incomplete; see report")

    def run(self):
        try:
            self.start()
            observations.setup(self)
            self.workflows()
        finally:
            try: self.cleanup()
            finally:
                (self.state/"report.json").write_text(json.dumps(self.report,indent=2,default=str)+"\n")
        for logfile in self.state.glob("controller-*.log"):
            text=logfile.read_text()
            require("DATA RACE" not in text,"controller race detector failure")
            require(self.password not in text,"database password leaked in controller log")
        require(self.password.encode() not in self.database.read_bytes(),"plaintext database password retained in SQLite")
        print(json.dumps({"report":str(self.state/"report.json"),"observations":self.report["observations"],"cleanup":self.report["cleanup"]},default=str))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",required=True)
    parser.add_argument("--state-directory",required=True)
    parser.add_argument("--docker-host",default="unix:///var/run/docker.sock")
    Application(parser.parse_args()).run()


if __name__=="__main__": main()
