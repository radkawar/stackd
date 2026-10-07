#!/usr/bin/env python3
"""Signed official-SDK controls and real Valkey protocol proof, never AWS fallback."""
import argparse
import datetime as dt
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

from stackd_process import StackdProcess

IMAGE = "valkey/valkey@sha256:1cb6b20b70d927560cc4cc5397b5f045e74aa603ff7696274778880bb6fadc75"


def require(value, message):
    if not value:
        raise AssertionError(message)


class Application:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state / "valkey.sqlite"
        require(not self.database.exists(), "state directory already contains valkey.sqlite")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        self.env.update(AWS_EC2_METADATA_DISABLED="true", AWS_MAX_ATTEMPTS="1")
        self.prefix = "valkey-proof-" + uuid.uuid4().hex[:8]
        self.password = "Owned!" + uuid.uuid4().hex
        self.changed_password = "Changed!" + uuid.uuid4().hex
        self.namespace = "stackd-valkey-" + hashlib.sha256(str(self.database).encode()).hexdigest()[:24]
        self.controller = StackdProcess(self.state)
        self.owned = []
        self.network = {"subnets": []}
        self.report = {"endpoint": self.endpoint, "namespace": self.namespace, "observations": {}, "controllers": self.controller.runs, "cleanup": {}}
        self.ec, self.md, self.iam = [self.client(s) for s in ("elasticache", "memorydb", "iam")]
        self.cert = self.state / "valkey.crt"
        self.key = self.state / "valkey.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=stackd-valkey-proof", "-addext", "subjectAltName=IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(self.key), "-out", str(self.cert)],
            check=True, capture_output=True)
        self.key.chmod(0o600)

    def client(self, service, key="test", secret="test", region="us-east-1"):
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region,
            aws_access_key_id=key, aws_secret_access_key=secret,
            config=Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=120))

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"127.0.0.1:{self.port}",
            "-database", str(self.database), "-docker-host", self.args.docker_host, "-valkey-runtime",
            "-valkey-tls-cert", str(self.cert), "-valkey-tls-key", str(self.key),
            "-compute-endpoint", f"http://host.docker.internal:{self.port}"]
        self.controller.start(command, self.endpoint, environment=self.env, timeout=90)

    def own(self, service, kind, name, region="us-east-1"):
        self.owned.append((service, kind, name, region))

    def native(self, endpoint, *command, user="default", password=None, tls=True, reject=False, cluster=True):
        env = dict(self.env)
        args = ["docker", "--host", self.args.docker_host, "run", "--rm", "--pull", "never", "--network", "host", "--label", "stackd.valkey.probe=" + self.prefix]
        if password is not False:
            env["REDISCLI_AUTH"] = self.password if password is None else password
            args += ["--env", "REDISCLI_AUTH"]
        if tls:
            args += ["--mount", f"type=bind,src={self.cert},dst=/proof.crt,readonly"]
        args += [IMAGE, "valkey-cli", "-e", "--json", "-2", "-h", endpoint["Address"], "-p", str(endpoint["Port"]), "--user", user]
        if cluster:
            args += ["-c"]
        if tls:
            args += ["--tls", "--cacert", "/proof.crt"]
        args += [str(v) for v in command]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40)
        combined = result.stdout + result.stderr
        if reject:
            require(result.returncode != 0 or any(v in combined for v in ("NOAUTH", "WRONGPASS", "NOPERM", "READONLY")), "native rejection unexpectedly succeeded")
            return combined.strip()
        require(result.returncode == 0, "native client failed: " + combined.replace(self.password, "<redacted>").replace(self.changed_password, "<redacted>"))
        # valkey-cli prints INFO as raw bulk text even with --json.
        if command[0].upper() == "INFO":
            return result.stdout
        return json.loads(result.stdout)

    def wait(self, service, kind, name, client=None):
        client = client or (self.ec if service == "elasticache" else self.md)
        operation, field, key, status = {
            ("elasticache", "cache"): ("describe_cache_clusters", "CacheClusters", "CacheClusterId", "CacheClusterStatus"),
            ("elasticache", "replication"): ("describe_replication_groups", "ReplicationGroups", "ReplicationGroupId", "Status"),
            ("elasticache", "snapshot"): ("describe_snapshots", "Snapshots", "SnapshotName", "SnapshotStatus"),
            ("memorydb", "cluster"): ("describe_clusters", "Clusters", "ClusterName", "Status"),
            ("memorydb", "snapshot"): ("describe_snapshots", "Snapshots", "SnapshotName", "Status"),
        }[(service, kind)]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            extra = {"ShowCacheNodeInfo": True} if kind == "cache" else {}
            row = getattr(client, operation)(**{key: name}, **extra)[field][0]
            if row[status] == "available":
                return row
            require(row[status] not in ("failed", "create-failed", "snapshot-failed"), "native lifecycle failed: " + json.dumps(row, default=str))
            time.sleep(.2)
        raise TimeoutError("native lifecycle " + name)

    def denied(self, fn, codes):
        try:
            fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            require(code in codes, "unexpected API rejection: " + code)
            return code
        raise AssertionError("API authority unexpectedly granted")

    def data(self, endpoint, user="default", tls=True):
        call = lambda *cmd: self.native(endpoint, *cmd, user=user, tls=tls, password=None if tls else False)
        require(call("PING") == "PONG", "native ping")
        require(call("HSET", "app:hash", "one", "1", "two", "2") == 2, "native hash")
        require(call("HGET", "app:hash", "two") == "2", "native hash read")
        require(call("LPUSH", "app:list", "first", "second") == 2, "native list")
        require(call("LRANGE", "app:list", 0, -1) == ["second", "first"], "native list order")
        require(call("ZADD", "app:rank", 2, "silver", 1, "gold") == 2, "native sorted set")
        require(call("ZRANGE", "app:rank", 0, -1) == ["gold", "silver"], "native sorted set order")
        require(call("SET", "app:ttl", "expires", "PX", 1500) == "OK", "native TTL set")
        ttl = call("PTTL", "app:ttl")
        require(0 < ttl <= 1500, "native TTL clock")
        time.sleep(1.6)
        require(call("GET", "app:ttl") is None, "native expiry")
        for key in ("app:durable", "app:{other}:durable"):
            require(call("SET", key, "retained-byte-value") == "OK", "durable write")

    def workflows(self):
        p = self.prefix
        defaults = self.ec.describe_cache_parameters(CacheParameterGroupName="default.valkey8.cluster.on")["Parameters"]
        require(next(v["ParameterValue"] for v in defaults if v["ParameterName"] == "timeout") == "0", "builtin native timeout default")
        try:
            self.ec.modify_cache_parameter_group(CacheParameterGroupName="default.valkey8.cluster.on", ParameterNameValues=[{"ParameterName": "timeout", "ParameterValue": "20"}])
        except ClientError as error:
            self.report["observations"]["builtin_parameter_mutation_denied"] = error.response["Error"]["Code"]
        else:
            raise AssertionError("builtin parameter group was mutable")
        defaults = self.ec.describe_cache_parameters(CacheParameterGroupName="default.valkey8.cluster.on")["Parameters"]
        require(next(v["ParameterValue"] for v in defaults if v["ParameterName"] == "timeout") == "0", "rejected builtin mutation changed configuration")
        ec2 = self.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.222.0.0/16")["Vpc"]["VpcId"]
        self.network["vpc"] = vpc
        for number in (1, 2):
            self.network["subnets"].append(ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.222.{number}.0/24")["Subnet"]["SubnetId"])
        self.own("elasticache", "subnets", p + "-subnets")
        self.ec.create_cache_subnet_group(CacheSubnetGroupName=p + "-subnets", CacheSubnetGroupDescription="current EC2 authority", SubnetIds=self.network["subnets"])
        self.own("memorydb", "subnets", p + "-subnets")
        self.md.create_subnet_group(SubnetGroupName=p + "-subnets", Description="current EC2 authority", SubnetIds=self.network["subnets"])
        require({v["SubnetIdentifier"] for v in self.ec.describe_cache_subnet_groups(CacheSubnetGroupName=p + "-subnets")["CacheSubnetGroups"][0]["Subnets"]} == set(self.network["subnets"]), "cache subnet authority")
        require({v["Identifier"] for v in self.md.describe_subnet_groups(SubnetGroupName=p + "-subnets")["SubnetGroups"][0]["Subnets"]} == set(self.network["subnets"]), "MemoryDB subnet authority")
        self.report["observations"]["subnet_groups"] = {"vpc": vpc, "subnets": self.network["subnets"], "attachments": "unsupported, not fabricated VPC networking"}
        self.own("elasticache", "cache", p + "-single")
        self.ec.create_cache_cluster(CacheClusterId=p + "-single", Engine="redis", EngineVersion="7.2", CacheNodeType="cache.t4g.micro", NumCacheNodes=1)
        single = self.wait("elasticache", "cache", p + "-single")
        single_ep = single["CacheNodes"][0]["Endpoint"]
        self.data(single_ep, tls=False)
        self.ec.reboot_cache_cluster(CacheClusterId=p + "-single", CacheNodeIdsToReboot=["0001"])
        self.wait("elasticache", "cache", p + "-single")
        require(self.native(single_ep, "GET", "app:durable", password=False, tls=False) == "retained-byte-value", "AOF bytes after native reboot")
        self.report["observations"]["standalone"] = {"endpoint": single_ep, "native_reboot_retained": True, "structures_ttl": True}

        for suffix, username, access in (("-default", "default", "on ~* +@all"), ("-reader", "reader", "on ~app:* +@read +ping")):
            self.own("elasticache", "user", p + suffix)
            self.ec.create_user(UserId=p + suffix, UserName=username, Engine="VALKEY", AccessString=access, Passwords=[self.password])
        self.own("elasticache", "users", p + "-users")
        self.ec.create_user_group(UserGroupId=p + "-users", Engine="VALKEY", UserIds=[p + "-default", p + "-reader"])
        self.own("elasticache", "parameters", p + "-parameters")
        self.ec.create_cache_parameter_group(CacheParameterGroupName=p + "-parameters", CacheParameterGroupFamily="valkey8", Description="real native settings")
        self.ec.modify_cache_parameter_group(CacheParameterGroupName=p + "-parameters", ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lru"}])
        self.own("elasticache", "replication", p + "-replicated")
        self.ec.create_replication_group(ReplicationGroupId=p + "-replicated", ReplicationGroupDescription="real replica", Engine="valkey", EngineVersion="8.1.6", CacheNodeType="cache.t4g.micro", NumCacheClusters=2, TransitEncryptionEnabled=True, UserGroupIds=[p + "-users"], CacheParameterGroupName=p + "-parameters")
        rg = self.wait("elasticache", "replication", p + "-replicated")
        rg_ep = rg["NodeGroups"][0]["PrimaryEndpoint"]
        self.data(rg_ep)
        require("maxmemory_policy:allkeys-lru" in self.native(rg_ep, "INFO", "memory"), "configured parameter did not reach native server")
        self.ec.modify_cache_parameter_group(CacheParameterGroupName=p + "-parameters", ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lfu"}])
        self.wait("elasticache", "replication", p + "-replicated")
        require("maxmemory_policy:allkeys-lfu" in self.native(rg_ep, "INFO", "memory"), "live parameter mutation was inert")
        replica = next(v["ReadEndpoint"] for v in rg["NodeGroups"][0]["NodeGroupMembers"] if v["CurrentRole"] == "replica")
        require(self.native(replica, "GET", "app:durable") == "retained-byte-value", "native replica lacks primary bytes")
        require("READONLY" in self.native(replica, "SET", "app:write", "denied", reject=True), "replica accepted primary writes")
        self.ec.add_tags_to_resource(ResourceName=rg["ARN"], Tags=[{"Key": "proof", "Value": "current"}])
        require({"Key": "proof", "Value": "current"} in self.ec.list_tags_for_resource(ResourceName=rg["ARN"])["TagList"], "cache tags not retained")
        auth_error = self.native(rg_ep, "PING", password="incorrect", reject=True)
        acl_error = self.native(rg_ep, "SET", "app:denied", "value", user="reader", reject=True)
        require("WRONGPASS" in auth_error and "NOPERM" in acl_error, "native authentication/ACL denials")
        self.ec.modify_user(UserId=p + "-reader", AccessString="on ~app:* +@read +@write +ping", Passwords=[self.changed_password])
        self.wait("elasticache", "replication", p + "-replicated")
        require(self.native(rg_ep, "SET", "app:now-allowed", "changed", user="reader", password=self.changed_password) == "OK", "native ACL/password update")
        self.native(rg_ep, "PING", user="reader", password=self.password, reject=True)
        self.report["observations"]["elasticache_acl"] = {"endpoint": rg_ep, "authentication_denied": True, "write_denied_then_allowed": True, "old_password_denied": True, "native_nodes": len(rg["NodeGroups"][0].get("NodeGroupMembers", []))}

        self.own("memorydb", "user", p + "-writer")
        self.md.create_user(UserName=p + "-writer", AccessString="on ~* +@all", AuthenticationMode={"Type": "password", "Passwords": [self.password]})
        self.own("memorydb", "acl", p + "-acl")
        self.md.create_acl(ACLName=p + "-acl", UserNames=[p + "-writer"])
        self.own("memorydb", "parameters", p + "-md-parameters")
        self.md.create_parameter_group(ParameterGroupName=p + "-md-parameters", Family="memorydb_valkey7", Description="native settings")
        self.md.update_parameter_group(ParameterGroupName=p + "-md-parameters", ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lru"}])
        self.own("memorydb", "cluster", p + "-cluster")
        # Omitting TLSEnabled must preserve the real AWS default: TLS on.
        self.md.create_cluster(ClusterName=p + "-cluster", NodeType="db.t4g.small", ACLName=p + "-acl", Engine="valkey", NumShards=2, NumReplicasPerShard=1, ParameterGroupName=p + "-md-parameters")
        md = self.wait("memorydb", "cluster", p + "-cluster")
        md_ep = md["ClusterEndpoint"]
        require(md["TLSEnabled"], "MemoryDB default TLS was silently disabled")
        self.data(md_ep, user=p + "-writer")
        topology = self.native(md_ep, "CLUSTER", "SLOTS", user=p + "-writer")
        require(len(topology) == 2 and sum(int(v[1]) - int(v[0]) + 1 for v in topology) == 16384, "genuine native slot topology")
        require(all(len(v) >= 4 for v in topology), "native replica missing from shard topology")
        self.report["observations"]["memorydb_topology"] = {"endpoint": md_ep, "tls_default": True, "shards": 2, "replicas_per_shard": 1, "slots": 16384}
        self.native(md_ep, "PING", user=p + "-writer", tls=False, reject=True)
        require("maxmemory_policy:allkeys-lru" in self.native(md_ep, "INFO", "memory", user=p + "-writer"), "MemoryDB parameter was inert")
        self.md.tag_resource(ResourceArn=md["ARN"], Tags=[{"Key": "proof", "Value": "current"}])
        require({"Key": "proof", "Value": "current"} in self.md.list_tags(ResourceArn=md["ARN"])["TagList"], "MemoryDB tags not retained")
        self.md.describe_clusters(ClusterName=p + "-cluster")
        samples = self.client("cloudwatch").get_metric_statistics(Namespace="AWS/MemoryDB", MetricName="BytesUsedForMemoryDB", Dimensions=[{"Name": "ClusterName", "Value": p + "-cluster"}], StartTime=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5), EndTime=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1), Period=60, Statistics=["Maximum"])["Datapoints"]
        require(any(v["Maximum"] > 0 for v in samples), "actual native memory metric missing")
        self.report["observations"]["native_memory_metrics"] = samples

        for service, source, endpoint, user in (("elasticache", p + "-replicated", rg_ep, "default"), ("memorydb", p + "-cluster", md_ep, p + "-writer")):
            client = self.ec if service == "elasticache" else self.md
            snapshot = p + ("-ec-snapshot" if service == "elasticache" else "-md-snapshot")
            self.own(service, "snapshot", snapshot)
            client.create_snapshot(**({"ReplicationGroupId": source} if service == "elasticache" else {"ClusterName": source}), SnapshotName=snapshot)
            self.wait(service, "snapshot", snapshot)
            copy = snapshot + "-copy"
            self.own(service, "snapshot", copy)
            client.copy_snapshot(SourceSnapshotName=snapshot, TargetSnapshotName=copy)
            self.wait(service, "snapshot", copy)
            restored = p + ("-ec-copy" if service == "elasticache" else "-md-copy")
            if service == "elasticache":
                self.own(service, "replication", restored)
                client.create_replication_group(ReplicationGroupId=restored, ReplicationGroupDescription="snapshot restore", Engine="valkey", EngineVersion="8.1.6", CacheNodeType="cache.t4g.micro", NumCacheClusters=2, TransitEncryptionEnabled=True, UserGroupIds=[p + "-users"], SnapshotName=copy)
                row = self.wait(service, "replication", restored)
                target = row["NodeGroups"][0]["PrimaryEndpoint"]
            else:
                self.own(service, "cluster", restored)
                client.create_cluster(ClusterName=restored, NodeType="db.t4g.small", ACLName=p + "-acl", Engine="valkey", NumShards=2, NumReplicasPerShard=1, SnapshotName=copy)
                target = self.wait(service, "cluster", restored)["ClusterEndpoint"]
            require(self.native(target, "GET", "app:durable", user=user) == "retained-byte-value", "restored physical bytes")
            require(self.native(target, "HGET", "app:hash", "two", user=user) == "2", "restored non-string data")
            self.native(target, "SET", "app:durable", "independent-restored", user=user)
            require(self.native(endpoint, "GET", "app:durable", user=user) == "retained-byte-value", "restore shares mutable data with source")
            self.report["observations"][service + "_snapshot"] = {"copy_restored": True, "independent_bytes": True, "endpoint": target}

        # Equal names in another Region own separate native processes and data.
        west = self.client("elasticache", region="us-west-2")
        self.own("elasticache", "cache", p + "-single", "us-west-2")
        west.create_cache_cluster(CacheClusterId=p + "-single", Engine="redis", CacheNodeType="cache.t4g.micro", NumCacheNodes=1)
        west_ep = self.wait("elasticache", "cache", p + "-single", client=west)["CacheNodes"][0]["Endpoint"]
        require(west_ep != single_ep and self.native(west_ep, "GET", "app:durable", tls=False, password=False) is None, "scopes leaked native bytes")
        self.report["observations"]["scope_isolation"] = {"east": single_ep, "west": west_ep}
        self.iam.create_user(UserName=p + "-caller")
        key = self.iam.create_access_key(UserName=p + "-caller")["AccessKey"]
        policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["elasticache:DescribeCacheClusters", "memorydb:DescribeClusters"], "Resource": "*"}]})
        self.iam.put_user_policy(UserName=p + "-caller", PolicyName="current", PolicyDocument=policy)
        reader = self.client("memorydb", key=key["AccessKeyId"], secret=key["SecretAccessKey"])
        reader.describe_clusters(ClusterName=p + "-cluster")
        self.iam.delete_user_policy(UserName=p + "-caller", PolicyName="current")
        denied = self.denied(lambda: reader.describe_clusters(ClusterName=p + "-cluster"), {"AccessDenied", "AccessDeniedException"})
        self.iam.delete_access_key(UserName=p + "-caller", AccessKeyId=key["AccessKeyId"])
        self.iam.delete_user(UserName=p + "-caller")
        self.report["observations"]["current_iam"] = denied
        self.controller.stop(timeout=60)
        require(self.native(md_ep, "GET", "app:durable", user=p + "-writer") == "retained-byte-value", "controller shutdown stopped native data")
        self.start()
        require(self.wait("memorydb", "cluster", p + "-cluster")["ClusterEndpoint"] == md_ep, "controller restart changed endpoint")
        require(self.native(md_ep, "GET", "app:durable", user=p + "-writer") == "retained-byte-value", "controller restart lost data")
        self.report["observations"]["controller_restart"] = {"retained_endpoint": md_ep, "data_live_while_detached": True}

    def cleanup(self):
        errors = []
        # Clusters must retire before their source snapshots, users and settings.
        order = {"cache": 0, "replication": 0, "cluster": 0, "snapshot": 1, "users": 2, "acl": 2, "user": 3, "parameters": 4, "subnets": 4}
        for service, kind, name, region in sorted(self.owned, key=lambda v: order[v[1]]):
            client = self.client(service, region=region)
            operation, parameters, describe, field = {
                ("elasticache", "cache"): ("delete_cache_cluster", {"CacheClusterId": name}, "describe_cache_clusters", "CacheClusterId"),
                ("elasticache", "replication"): ("delete_replication_group", {"ReplicationGroupId": name, "RetainPrimaryCluster": False}, "describe_replication_groups", "ReplicationGroupId"),
                ("elasticache", "snapshot"): ("delete_snapshot", {"SnapshotName": name}, "describe_snapshots", "SnapshotName"),
                ("elasticache", "users"): ("delete_user_group", {"UserGroupId": name}, "describe_user_groups", "UserGroupId"),
                ("elasticache", "user"): ("delete_user", {"UserId": name}, "describe_users", "UserId"),
                ("elasticache", "parameters"): ("delete_cache_parameter_group", {"CacheParameterGroupName": name}, "describe_cache_parameter_groups", "CacheParameterGroupName"),
                ("elasticache", "subnets"): ("delete_cache_subnet_group", {"CacheSubnetGroupName": name}, "describe_cache_subnet_groups", "CacheSubnetGroupName"),
                ("memorydb", "cluster"): ("delete_cluster", {"ClusterName": name}, "describe_clusters", "ClusterName"),
                ("memorydb", "snapshot"): ("delete_snapshot", {"SnapshotName": name}, "describe_snapshots", "SnapshotName"),
                ("memorydb", "acl"): ("delete_acl", {"ACLName": name}, "describe_acls", "ACLName"),
                ("memorydb", "user"): ("delete_user", {"UserName": name}, "describe_users", "UserName"),
                ("memorydb", "parameters"): ("delete_parameter_group", {"ParameterGroupName": name}, "describe_parameter_groups", "ParameterGroupName"),
                ("memorydb", "subnets"): ("delete_subnet_group", {"SubnetGroupName": name}, "describe_subnet_groups", "SubnetGroupName"),
            }[(service, kind)]
            try:
                try:
                    getattr(client, operation)(**parameters)
                except ClientError as error:
                    if "NotFound" not in error.response["Error"]["Code"]:
                        raise
                deadline = time.monotonic() + 180
                while True:
                    try:
                        getattr(client, describe)(**{field: name})
                    except ClientError as error:
                        if "NotFound" in error.response["Error"]["Code"]:
                            break
                        raise
                    if time.monotonic() > deadline:
                        raise TimeoutError("resource deletion " + name)
                    time.sleep(.2)
            except Exception as error:
                errors.append(str(error))
        ec2 = self.client("ec2")
        for subnet in self.network["subnets"]:
            try:
                ec2.delete_subnet(SubnetId=subnet)
            except Exception as error:
                errors.append(str(error))
        if "vpc" in self.network:
            try:
                ec2.delete_vpc(VpcId=self.network["vpc"])
            except Exception as error:
                errors.append(str(error))
        self.report["cleanup"]["errors"] = errors
        self.controller.stop(timeout=60)
        containers = subprocess.check_output(["docker", "--host", self.args.docker_host, "ps", "-aq", "--filter", "label=stackd.valkey.namespace=" + self.namespace], text=True).split()
        volumes = subprocess.check_output(["docker", "--host", self.args.docker_host, "volume", "ls", "-q", "--filter", "label=stackd.valkey.namespace=" + self.namespace], text=True).split()
        clients = subprocess.check_output(["docker", "--host", self.args.docker_host, "ps", "-aq", "--filter", "label=stackd.valkey.probe=" + self.prefix], text=True).split()
        self.report["cleanup"].update(native_containers=containers, native_volumes=volumes, client_containers=clients)
        require(not errors and not containers and not volumes and not clients, "exact-owned cleanup incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    app = Application(parser.parse_args())
    try:
        app.start()
        from valkey_controls_replay import replay
        replay(app)
        app.workflows()
    finally:
        try:
            app.cleanup()
        finally:
            (app.state / "report.json").write_text(json.dumps(app.report, indent=2, default=str) + "\n")
    print(json.dumps(app.report, default=str))


if __name__ == "__main__":
    main()
