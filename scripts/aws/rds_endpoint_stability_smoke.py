#!/usr/bin/env python3
"""Bounded local RDS endpoint regression with real PostgreSQL and signed reads.

Requires an explicit stackd executable, a fresh/empty owned state directory,
Linux local Docker, AWS CLI, boto3/botocore and host psql. Install both PG and
MYSQL digests from rds_executable_smoke first: the RDS runtime requires both,
although this proof creates only two PostgreSQL databases. Nothing is pulled.

During both fault windows the service clock stays frozen, so periodic health
reconciliation cannot race this request-path proof. Each exact-owned SQL
container is paused in turn; concurrent Describe requests must retain available
endpoints despite SQL being unresponsive. Public CA extraction and verify-full
TLS SQL prove real identity, authentication and committed data before/after.
After unpausing, a clock advance exercises periodic reconciliation, then both
databases undergo real stop/start. Upload only <state-directory>/report.json;
the SQLite database, public CA files and controller logs remain private.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import aws_cli
from rds_executable_smoke import Application, MYSQL, PG, require


WORKERS = 4
ROUNDS = 8


class EndpointStabilityApplication(Application):
    def __init__(self, args):
        state = Path(args.state_directory).absolute()
        require(not state.is_symlink(), "state directory must not be a symlink")
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not any(state.iterdir()), "state directory must be fresh and empty")
        state.chmod(0o700)
        binary = Path(args.binary).resolve()
        require(binary.is_file() and os.access(binary, os.X_OK), "explicit binary is not executable")
        require(args.docker_host.startswith("unix:///"), "requires an explicit local Unix Docker socket")
        for executable in ("docker", "aws", "psql"):
            require(shutil.which(executable), "missing prerequisite: " + executable)
        super().__init__(args)
        self.env = {key: value for key, value in self.env.items()
                    if not key.startswith(("PG", "MYSQL", "DOCKER_", "BOTO_"))
                    and key.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        self.env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                        AWS_DEFAULT_REGION="us-east-1", AWS_CONFIG_FILE=os.devnull,
                        AWS_SHARED_CREDENTIALS_FILE=os.devnull, AWS_PAGER="",
                        AWS_CLI_AUTO_PROMPT="off", PSQL_HISTORY=os.devnull)
        self.namespace = "stackd-rds-" + hashlib.sha256(str(self.database).encode()).hexdigest()[:24]
        self.targets = []
        self.paused = {}
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.report.update(native_images={"postgres": PG, "mysql": MYSQL},
                           namespace=self.namespace, status="running",
                           scope="Local request-path stability; not AWS/Aurora failover or health-recovery parity")

    def client(self, service, key="test", secret="test", region="us-east-1"):
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region,
                            aws_access_key_id=key, aws_secret_access_key=secret,
                            config=Config(retries={"total_max_attempts": 1}, connect_timeout=2,
                                          read_timeout=10, max_pool_connections=WORKERS + 2, proxies={}))

    def docker(self, *arguments, timeout=20):
        result = subprocess.run(["docker", "--host", self.args.docker_host, *arguments],
                                env=self.env, capture_output=True, text=True, timeout=timeout)
        require(result.returncode == 0, "Docker " + arguments[0] + " failed: " +
                result.stderr.replace(self.password, "[REDACTED]"))
        return result.stdout.strip()

    def clock(self):
        with self.http.open(self.endpoint + "/_stackd/clock", timeout=5) as response:
            return json.load(response)["time"]

    def retained(self, kind, name, arn):
        parts = arn.split(":", 6)
        with closing(sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT kind,name,runtime_id,status,address,port,version,due,ca FROM rds_database "
                "WHERE partition=? AND account_id=? AND region=? AND kind=? AND name=?",
                (parts[1], parts[4], parts[3], kind, name)).fetchone()
        require(row is not None, "missing retained RDS owner: " + name)
        return dict(row)

    def inspect_owned(self, container_id, runtime_id):
        rows = json.loads(self.docker("inspect", container_id))
        require(len(rows) == 1, "native container identity is ambiguous")
        row = rows[0]
        expected = {"stackd.rds.namespace": self.namespace, "stackd.rds.id": runtime_id,
                    "stackd.rds.role": "database", "stackd.rds.layout": "native-v1"}
        require(all(row["Config"]["Labels"].get(key) == value for key, value in expected.items()),
                "refusing a native container without exact retained ownership labels")
        require(row["Id"] == container_id, "native container identity changed")
        require(row["Image"] == self.postgres_image_id, "native PostgreSQL is not the installed pinned image")
        return row

    def native_identity(self, target):
        runtime_id = target["retained"]["runtime_id"]
        ids = self.docker("ps", "-aq", "--no-trunc", "--filter", "label=stackd.rds.namespace=" + self.namespace,
                          "--filter", "label=stackd.rds.id=" + runtime_id,
                          "--filter", "label=stackd.rds.role=database").split()
        require(len(ids) == 1, "expected exactly one container for retained RuntimeID")
        row = self.inspect_owned(ids[0], runtime_id)
        require(row["State"]["Running"] and not row["State"]["Paused"], "native SQL owner is not running")
        return {"container": row["Id"], "runtime_id": runtime_id,
                "started_at": row["State"]["StartedAt"], "restart_count": row["RestartCount"],
                "volumes": sorted(mount["Name"] for mount in row["Mounts"] if mount["Type"] == "volume")}

    def sql(self, target, statement, *, password=None, expect_failure=False):
        endpoint = target["endpoint"]
        require(endpoint["Address"] == "127.0.0.1" and 1024 <= endpoint["Port"] <= 65535,
                "refusing a non-loopback or invalid native SQL endpoint")
        environment = dict(self.env, PGPASSWORD=password or self.password,
                           PGSSLROOTCERT=str(target["ca"]), PGCONNECT_TIMEOUT="3")
        connection = (f"host=127.0.0.1 port={endpoint['Port']} user=dbowner dbname=appdb "
                      "sslmode=verify-full connect_timeout=3")
        result = subprocess.run(["psql", "-XqAt", "-w", "-v", "ON_ERROR_STOP=1", "-d", connection,
                                 "-c", statement], env=environment, capture_output=True, text=True, timeout=10)
        if expect_failure:
            require(result.returncode != 0, "SQL unexpectedly succeeded during a negative native probe")
        else:
            require(result.returncode == 0, "verified TLS SQL failed: " +
                    result.stderr.replace(self.password, "[REDACTED]"))
        return result

    def cli(self, operation, parameters=None):
        result = aws_cli.run("rds", operation, parameters, self.env, timeout=20,
                             options=["--endpoint-url", self.endpoint, "--region", "us-east-1",
                                      "--no-paginate", "--cli-connect-timeout", "2", "--cli-read-timeout", "10"])
        require(result.returncode == 0, "signed AWS CLI " + operation + " failed: " +
                result.stderr.replace(self.password, "[REDACTED]"))
        return json.loads(result.stdout)

    def assert_instances(self, response, names=None):
        rows = {row["DBInstanceIdentifier"]: row for row in response["DBInstances"]}
        expected = set(self.instances if names is None else names)
        require(set(rows) == expected, "DescribeDBInstances lost an owned instance")
        for target in self.targets:
            if target["instance"] in expected:
                row = rows[target["instance"]]
                require(row["DBInstanceStatus"] == "available", "Describe demoted an available instance: " + target["instance"])
                require(row.get("Endpoint") == target["endpoint"], "Describe changed or dropped a published instance endpoint")

    def assert_clusters(self, response):
        rows = response["DBClusters"]
        require(len(rows) == 1 and rows[0]["DBClusterIdentifier"] == self.clusters[0],
                "DescribeDBClusters lost the owned cluster")
        row = rows[0]
        target = self.targets[1]
        require(row["Status"] == "available", "Describe demoted the available cluster")
        endpoint = {key: row.get(key) for key in ("Endpoint", "ReaderEndpoint", "Port")}
        require(endpoint == target["cluster_endpoint"], "Describe changed or dropped a published cluster endpoint")

    def provision(self):
        name = self.prefix + "-postgres"
        self.instances.append(name)
        self.rds.create_db_instance(DBInstanceIdentifier=name, Engine="postgres", DBInstanceClass="db.t3.small",
                                    DBName="appdb", MasterUsername="dbowner", MasterUserPassword=self.password,
                                    AllocatedStorage=20)
        row = self.wait_instance(name)
        self.targets.append({"instance": name, "endpoint": row["Endpoint"],
                             "arn": row["DBInstanceArn"], "kind": "db", "name": name})
        cluster = self.prefix + "-aurora-postgresql"
        self.clusters.append(cluster)
        self.rds.create_db_cluster(DBClusterIdentifier=cluster, Engine="aurora-postgresql", DatabaseName="appdb",
                                  MasterUsername="dbowner", MasterUserPassword=self.password)
        writer = cluster + "-writer"
        self.instances.append(writer)
        self.rds.create_db_instance(DBInstanceIdentifier=writer, DBClusterIdentifier=cluster,
                                   Engine="aurora-postgresql", DBInstanceClass="db.t3.small")
        row = self.wait_instance(writer)
        cluster_row = self.wait_cluster(cluster)
        endpoint = {key: cluster_row.get(key) for key in ("Endpoint", "ReaderEndpoint", "Port")}
        require(endpoint["Endpoint"] == row["Endpoint"]["Address"] and endpoint["Port"] == row["Endpoint"]["Port"],
                "Aurora writer and cluster did not publish the same native SQL endpoint")
        self.targets.append({"instance": writer, "endpoint": row["Endpoint"], "arn": cluster_row["DBClusterArn"],
                             "kind": "cluster", "name": cluster, "cluster_endpoint": endpoint,
                             "member_arn": row["DBInstanceArn"]})
        for target in self.targets:
            retained = self.retained(target["kind"], target["name"], target["arn"])
            require(retained["status"] == "available" and retained["runtime_id"] and retained["ca"],
                    "native readiness did not retain status, RuntimeID and public TLS trust")
            require((retained["address"], retained["port"]) ==
                    (target["endpoint"]["Address"], target["endpoint"]["Port"]), "published endpoint differs from SQLite")
            target["retained"] = retained
            if target["kind"] == "cluster":
                member = self.retained("db", target["instance"], target["member_arn"])
                require(member["runtime_id"] == retained["runtime_id"], "Aurora writer does not share cluster RuntimeID")
                target["member_retained"] = member
            target["identity"] = self.native_identity(target)
            public_ca = self.docker("exec", target["identity"]["container"], "cat",
                                    "/var/lib/postgresql/data/security/ca.pem") + "\n"
            require(public_ca.encode() == retained["ca"], "owned native CA differs from retained public trust")
            target["ca"] = self.state / (retained["runtime_id"] + "-ca.pem")
            target["ca"].write_text(public_ca)
            target["ca"].chmod(0o600)
            rejected = self.sql(target, "SELECT 1", password="Wrong!" + uuid.uuid4().hex, expect_failure=True)
            require("password authentication failed" in rejected.stderr, "native database did not verify its password")
            target["marker"] = uuid.uuid4().hex
            self.sql(target, "CREATE TABLE endpoint_stability (id INTEGER PRIMARY KEY, note TEXT NOT NULL); "
                     f"INSERT INTO endpoint_stability VALUES (1, '{target['marker']}');")
            target["proof_query"] = ("SELECT current_user, s.ssl, d.note, pg_postmaster_start_time()::text "
                                     "FROM endpoint_stability d CROSS JOIN pg_stat_ssl s WHERE s.pid=pg_backend_pid()")
            target["sql_before"] = self.sql(target, target["proof_query"]).stdout.strip()
            require(target["sql_before"].startswith("dbowner|t|" + target["marker"] + "|"),
                    "native SQL did not establish authenticated TLS and committed data")
        self.assert_instances(self.cli("describe-db-instances"))
        self.assert_clusters(self.cli("describe-db-clusters"))

    def unpause_owned(self, container_id, runtime_id):
        row = self.inspect_owned(container_id, runtime_id)
        if row["State"]["Paused"]:
            self.docker("unpause", container_id)
        require(not self.inspect_owned(container_id, runtime_id)["State"]["Paused"], "owned SQL container remains paused")
        self.paused.pop(container_id, None)

    def fault_window(self, target):
        container_id = target["identity"]["container"]
        runtime_id = target["identity"]["runtime_id"]
        before_clock = self.clock()
        started = time.monotonic()
        self.inspect_owned(container_id, runtime_id)
        self.paused[container_id] = runtime_id
        try:
            self.docker("pause", container_id)
            require(self.inspect_owned(container_id, runtime_id)["State"]["Paused"], "native SQL fault was not installed")
            # This is a real verified-TLS connection attempt to the paused SQL server.
            # connect_timeout is shorter than the subprocess bound; no fake SQL is used.
            self.sql(target, "SELECT 1", expect_failure=True)

            def reader(index):
                deadline = time.monotonic() + 40
                completed = 0
                for round_index in range(ROUNDS):
                    require(time.monotonic() < deadline, "concurrent Describe round exceeded its wall-time budget")
                    if (index + round_index) % 2:
                        self.assert_instances(self.rds.describe_db_instances(DBInstanceIdentifier=target["instance"]),
                                              [target["instance"]])
                        self.assert_clusters(self.rds.describe_db_clusters(DBClusterIdentifier=self.clusters[0]))
                    else:
                        self.assert_instances(self.rds.describe_db_instances())
                        self.assert_clusters(self.rds.describe_db_clusters())
                    completed += 2
                    time.sleep(0.5)
                return completed

            def cli_reader():
                self.assert_instances(self.cli("describe-db-instances", {"DBInstanceIdentifier": target["instance"]}),
                                      [target["instance"]])
                self.assert_clusters(self.cli("describe-db-clusters", {"DBClusterIdentifier": self.clusters[0]}))
                return 2

            with ThreadPoolExecutor(max_workers=WORKERS + 1) as pool:
                reads = [pool.submit(reader, index) for index in range(WORKERS)]
                reads.append(pool.submit(cli_reader))
                counts = [future.result() for future in reads]
            require(self.clock() == before_clock, "manual service clock advanced during the SQL fault")
            require(self.inspect_owned(container_id, runtime_id)["State"]["Paused"], "SQL fault disappeared during Describe reads")
            for current in self.targets:
                require(self.retained(current["kind"], current["name"], current["arn"]) == current["retained"],
                        "Describe changed retained readiness, endpoint, trust or native ownership")
                if current["kind"] == "cluster":
                    require(self.retained("db", current["instance"], current["member_arn"]) == current["member_retained"],
                            "Describe changed retained Aurora writer state")
            self.report["observations"][target["instance"]] = {
                "endpoint": target["endpoint"], "cluster_endpoint": target.get("cluster_endpoint"),
                "native_owner": target["identity"], "ca_sha256": hashlib.sha256(target["retained"]["ca"]).hexdigest(),
                "clock": before_clock, "sql_unresponsive_while_paused": True,
                "available_endpoint_retained": True, "concurrent_sdk_reads": sum(counts[:-1]),
                "cli_reads": counts[-1], "pause_seconds": round(time.monotonic() - started, 3)}
        finally:
            self.unpause_owned(container_id, runtime_id)
        require(self.native_identity(target) == target["identity"], "fault replaced or restarted native PostgreSQL")
        require(self.sql(target, target["proof_query"]).stdout.strip() == target["sql_before"],
                "fault changed authenticated TLS SQL, committed data or PostgreSQL start time")
        self.assert_instances(self.rds.describe_db_instances())
        self.assert_clusters(self.rds.describe_db_clusters())
        self.report["observations"][target["instance"]].update(
            unpaused=True, verified_tls_sql=True, password_authentication=True,
            committed_row_retained=True, same_native_process=True)

    def reconcile_and_restart(self):
        # Only after both fault windows: make the real scheduled health jobs due.
        request = urllib.request.Request(self.endpoint + "/_stackd/clock",
                                         data=b'{"advance":"31s"}',
                                         headers={"Content-Type": "application/json"})
        with self.http.open(request, timeout=10) as response:
            advanced = json.load(response)["time"]
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = [self.retained(target["kind"], target["name"], target["arn"]) for target in self.targets]
            if all(row["status"] == "available" and row["version"] > target["retained"]["version"]
                   and row["due"] != target["retained"]["due"] for row, target in zip(rows, self.targets)):
                break
            require(all(row["status"] != "failed" for row in rows), "periodic native reconciliation failed")
            time.sleep(0.25)
        else:
            raise TimeoutError("periodic native reconciliation did not complete after clock advance")
        for target in self.targets:
            require(self.native_identity(target) == target["identity"], "periodic health check replaced native SQL")
            require(self.sql(target, target["proof_query"]).stdout.strip() == target["sql_before"],
                    "periodic native health reconciliation lost SQL identity or data")
        self.assert_instances(self.rds.describe_db_instances())
        self.assert_clusters(self.rds.describe_db_clusters())
        self.report["observations"]["periodic_reconciliation"] = {
            "advanced_clock": advanced, "native_jobs_completed": len(rows),
            "same_native_processes": True, "verified_tls_sql": True}

        for target in self.targets:
            cluster = target["kind"] == "cluster"
            if cluster:
                self.rds.stop_db_cluster(DBClusterIdentifier=target["name"])
                stopped = self.wait_cluster(target["name"], "stopped")
                require(not stopped.get("Endpoint") and not stopped.get("ReaderEndpoint"),
                        "stopped cluster exposed a SQL endpoint")
            else:
                self.rds.stop_db_instance(DBInstanceIdentifier=target["instance"])
            stopped_member = self.wait_instance(target["instance"], "stopped")
            require(not stopped_member.get("Endpoint"), "stopped instance exposed a SQL endpoint")
            native = self.inspect_owned(target["identity"]["container"], target["identity"]["runtime_id"])
            require(not native["State"]["Running"], "Stop did not stop the exact-owned native SQL container")
            if cluster:
                self.rds.start_db_cluster(DBClusterIdentifier=target["name"])
                self.wait_cluster(target["name"])
            else:
                self.rds.start_db_instance(DBInstanceIdentifier=target["instance"])
            self.wait_instance(target["instance"])
            self.assert_instances(self.rds.describe_db_instances())
            self.assert_clusters(self.rds.describe_db_clusters())
            current = self.retained(target["kind"], target["name"], target["arn"])
            require(current["runtime_id"] == target["retained"]["runtime_id"]
                    and current["ca"] == target["retained"]["ca"], "Stop/start changed retained native ownership or trust")
            identity = self.native_identity(target)
            require(identity["container"] == target["identity"]["container"]
                    and identity["volumes"] == target["identity"]["volumes"], "Stop/start replaced native data ownership")
            proof = self.sql(target, target["proof_query"]).stdout.strip()
            require(proof.startswith("dbowner|t|" + target["marker"] + "|") and proof != target["sql_before"],
                    "Stop/start did not preserve authenticated TLS data across a real PostgreSQL restart")
            self.report["observations"][target["instance"]]["stop_start"] = {
                "stopped_endpoint_hidden": True, "native_stopped": True, "native_restarted": True,
                "same_container_and_volume": True, "same_endpoint_and_trust": True,
                "committed_row_retained": True, "verified_tls_sql": True}

    def cleanup(self):
        failures = []
        for container_id, runtime_id in list(self.paused.items()):
            try:
                self.unpause_owned(container_id, runtime_id)
            except Exception as error:
                failures.append("unpause: " + str(error))
        try:
            if self.controller.process is not None and self.controller.process.poll() is None:
                for kind, names, delete, describe, missing in (
                        ("instance", self.instances, self.rds.delete_db_instance,
                         self.rds.describe_db_instances, "DBInstanceNotFound"),
                        ("cluster", self.clusters, self.rds.delete_db_cluster,
                         self.rds.describe_db_clusters, "DBClusterNotFoundFault")):
                    parameter = "DBInstanceIdentifier" if kind == "instance" else "DBClusterIdentifier"
                    for name in reversed(names):
                        try:
                            try:
                                delete(**{parameter: name}, SkipFinalSnapshot=True)
                            except ClientError as error:
                                if error.response["Error"]["Code"] != missing:
                                    raise
                            deadline = time.monotonic() + 90
                            while time.monotonic() < deadline:
                                try:
                                    describe(**{parameter: name})
                                except ClientError as error:
                                    if error.response["Error"]["Code"] == missing:
                                        break
                                    raise
                                time.sleep(0.2)
                            else:
                                raise TimeoutError("resource deletion: " + name)
                        except Exception as error:
                            failures.append(kind + " " + name + ": " + str(error))
                require(not self.rds.describe_db_instances()["DBInstances"], "instances survived deletion")
                require(not self.rds.describe_db_clusters()["DBClusters"], "clusters survived deletion")
        except Exception as error:
            failures.append("resource cleanup: " + str(error))
        finally:
            try:
                self.controller.stop(timeout=45, kill_on_timeout=True)
            except Exception as error:
                failures.append("controller shutdown: " + str(error))
        containers = volumes = None
        try:
            containers = self.docker("ps", "-aq", "--filter", "label=stackd.rds.namespace=" + self.namespace).split()
            volumes = self.docker("volume", "ls", "-q", "--filter", "label=stackd.rds.namespace=" + self.namespace).split()
            if containers or volumes:
                failures.append("owned native resources survived deletion")
            if self.database.exists():
                with closing(sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
                    require(connection.execute("SELECT count(*) FROM rds_database").fetchone()[0] == 0,
                            "retained RDS database owners survived deletion")
        except Exception as error:
            failures.append("native/retained cleanup: " + str(error))
        self.report["cleanup"] = {"failures": failures, "containers": containers, "volumes": volumes,
                                  "namespace": self.namespace, "controller_stopped": self.controller.process is None}
        require(not failures, "owned cleanup incomplete; see report.json")

    def run(self):
        try:
            installed = {}
            for label, image in (("postgres", PG), ("mysql", MYSQL)):
                rows = json.loads(self.docker("image", "inspect", image))
                require(len(rows) == 1 and rows[0]["Os"] == "linux", "requires installed pinned Linux " + label + " image")
                installed[label] = rows[0]["Id"]
            self.postgres_image_id = installed["postgres"]
            self.report["installed_image_ids"] = installed
            self.start()  # Application supplies -clock-start; frozen throughout both faults.
            self.provision()
            for target in self.targets:
                self.fault_window(target)
            self.reconcile_and_restart()
            self.report["status"] = "passed"
        except BaseException as error:
            self.report["status"] = "failed"
            self.report["error"] = (type(error).__name__ + ": " + str(error)).replace(self.password, "[REDACTED]")
            raise
        finally:
            try:
                self.cleanup()
            except BaseException:
                self.report["status"] = "failed"
                raise
            finally:
                receipt = json.dumps(self.report, indent=2, default=str).replace(self.password, "[REDACTED]")
                (self.state / "report.json").write_text(receipt + "\n")
        print(json.dumps({"report": str(self.state / "report.json"), "status": self.report["status"],
                          "observations": self.report["observations"], "cleanup": self.report["cleanup"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    EndpointStabilityApplication(parser.parse_args()).run()


if __name__ == "__main__":
    main()
