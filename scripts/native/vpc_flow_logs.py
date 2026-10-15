#!/usr/bin/env python3
"""Run the pinned Terraform provider, SDK, and real native VPC Flow Logs path.

Prepare bin/stackd, Terraform >=1.5,<2, boto3, Docker, the pinned stackd toolkit,
and python:3.12-alpine. Use rootful Linux Docker with systemd and cgroup v2.
No image is pulled. No AWS endpoint or ambient AWS credentials are used.

  python3 scripts/native/vpc_flow_logs.py --binary bin/stackd \
    --state-directory /tmp/flow-logs-UNIQUE

The fixture uses real 60-second aggregation and five-minute S3 publication.
It does not advance service time or change packet timestamps. The retained
report and SQLite file give ordinary graceful-restart evidence, not crash
exactly-once claims. Capture uses one unique namespace across restart.
Use --remove-owned-capture to remove an idle collector after owned API cleanup.
Without that option, the report names the retained native evidence container.
"""
import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples"))
sys.path.insert(0, str(ROOT / "scripts/aws"))
from local import ACCOUNT, client, environment, expect_missing, require
from stackd_process import StackdProcess

TOOLKIT = "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61"
FIELDS = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status vpc-id subnet-id flow-direction".split()
SERVER = '''import json,select,socket
sockets=[]
for port in (33000,33001,33002):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port));sockets.append(s)
print('READY',flush=True)
while True:
 for s in select.select(sockets,[],[],1)[0]:
  data,peer=s.recvfrom(4096)
  print(json.dumps({'port':s.getsockname()[1],'peer':peer,'payload':data.hex()}),flush=True)
  s.sendto(data,peer)
'''
SEND = '''import json,socket,sys,time
address,sport,dport,payload=sys.argv[1:]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',int(sport)));s.settimeout(1)
started=time.time();data=bytes.fromhex(payload);s.sendto(data,(address,int(dport)))
try:
 actual,peer=s.recvfrom(4096);result={'received':actual.hex(),'peer':peer}
except socket.timeout:
 result={'received':None}
result.update(started=started,finished=time.time(),sent=len(data));print(json.dumps(result))
'''


class Consumer:
    def __init__(self, args):
        self.args = args
        self.work = args.state_directory.resolve()
        self.work.mkdir(parents=True, exist_ok=False)
        self.name = "stackd-flow-" + uuid.uuid4().hex[:12]
        self.namespace = self.name
        self.capture_name = "stackd-flows-" + hashlib.sha256(self.namespace.encode()).hexdigest()
        self.env = environment()
        self.database = self.work / "stackd.sqlite"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", args.port))
            self.port = listener.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.controller = StackdProcess(self.work)
        self.clients = {name: client(name, self.endpoint) for name in ("ec2", "ecs", "logs", "s3", "iam", "sts")}
        self.outputs = {}
        self.tasks = []
        self.definition = self.cluster = None
        self.tf_ready = False
        self.variables = {}
        self.report = {"scope": "Local real Docker, Terraform AWS 6.68.0 and SDK; not native AWS calibration",
                       "completed": False, "name": self.name, "endpoint": self.endpoint,
                       "controllers": self.controller.runs, "packets": [], "records": {},
                       "capture": {"namespace": self.namespace, "container": self.capture_name,
                                   "volume": self.capture_name, "retained": None}, "cleanup": {}}
        self.save()

    def save(self):
        (self.work / "report.json").write_text(json.dumps(self.report, indent=2, default=str) + "\n")

    def docker(self, *args, timeout=45):
        result = subprocess.run(["docker", "--host", self.args.docker_host, *args], env=self.env,
                                text=True, capture_output=True, timeout=timeout)
        require(result.returncode == 0, f"Docker {args[0]} failed ({result.returncode}): {result.stderr.strip()}")
        return result.stdout.strip()

    def wait(self, label, predicate, timeout=100, interval=.5):
        deadline = time.monotonic() + timeout
        while True:
            value = predicate()
            if value:
                return value
            require(time.monotonic() < deadline, f"Timed out: {label}; inspect {self.work}")
            time.sleep(interval)

    def start(self):
        command = [str(self.args.binary.resolve()), "-listen", f"0.0.0.0:{self.port}",
                   "-public-endpoint", self.endpoint, "-account-id", ACCOUNT,
                   "-database", str(self.database), "-docker-host", self.args.docker_host,
                   "-ecs-runtime", "-compute-endpoint", f"http://host.docker.internal:{self.port}",
                   "--vpc-flow-logs-runtime", "docker", "--vpc-flow-logs-namespace", self.namespace]
        self.controller.start(command, self.endpoint, environment=self.env, timeout=90)
        require(self.clients["sts"].get_caller_identity()["Account"] == ACCOUNT, "Unexpected controller account")
        capture = json.loads(self.docker("inspect", self.capture_name))[0]
        require(capture["Config"]["Labels"].get("stackd.network.flows.namespace") == self.namespace,
                "Native capture namespace differs")
        self.report["capture"].update(retained=True, id=capture["Id"], pid=capture["State"]["Pid"],
                                       labels=capture["Config"]["Labels"])
        self.save()

    def terraform(self, *args, capture=False, check=True):
        print("terraform", *args, flush=True)
        result = subprocess.run(["terraform", *args], cwd=self.work, env=self.env,
                                check=check, text=True, capture_output=capture, timeout=300)
        if capture:
            (self.work / "terraform-last-output.txt").write_text(result.stdout + result.stderr)
        return result

    def prepare(self):
        require(self.args.binary.is_file(), "Build bin/stackd first; --binary must name the assembled executable")
        require(shutil.which("terraform") and shutil.which("docker"), "Install Terraform and Docker CLI first")
        for image in (TOOLKIT, self.args.image):
            self.docker("image", "inspect", image)
        info = json.loads(self.docker("info", "--format", "{{json .}}"))
        require(info["OSType"] == "linux" and not any(
            word in option for option in info.get("SecurityOptions", []) for word in ("rootless", "userns")),
            "Native capture requires rootful Linux Docker without user namespace remapping")
        source = ROOT / "examples/terraform"
        shutil.copyfile(source / "vpc-flow-logs/main.tf", self.work / "main.tf")
        shutil.copyfile(source / "vpc-flow-logs/.terraform.lock.hcl", self.work / ".terraform.lock.hcl")
        config = "disable_checkpoint = true\n"
        if self.args.provider_mirror:
            require(self.args.provider_mirror.is_dir(), "Provider mirror does not exist")
            config += ('provider_installation {\n filesystem_mirror {\n path = '
                       + json.dumps(str(self.args.provider_mirror.resolve()))
                       + '\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\n')
        (self.work / "terraform.rc").write_text(config)
        self.env["TF_CLI_CONFIG_FILE"] = str(self.work / "terraform.rc")
        network = ipaddress.ip_network(self.args.cidr)
        require(network.version == 4 and network.prefixlen == 24 and network.is_private,
                "--cidr must be a private IPv4 /24 not used by another native workload")
        subnets = list(network.subnets(new_prefix=28))
        self.variables = {"endpoint": self.endpoint, "name": self.name, "cidr": str(network),
                          "source_cidr": str(subnets[0]), "destination_cidr": str(subnets[1]),
                          "eni_id": "", "revision": "initial"}
        self.write_variables()
        self.terraform("init", "-input=false", "-lockfile=readonly")
        self.tf_ready = True

    def write_variables(self):
        (self.work / "local.auto.tfvars.json").write_text(json.dumps(self.variables, indent=2) + "\n")

    def apply(self):
        self.write_variables()
        self.terraform("apply", "-input=false", "-auto-approve")
        self.outputs = json.loads(self.terraform("output", "-json", "fixture", capture=True).stdout)
        self.report["outputs"] = self.outputs
        self.save()

    def task(self, subnet, group):
        ecs = self.clients["ecs"]
        result = ecs.run_task(cluster=self.cluster, taskDefinition=self.definition, launchType="FARGATE",
                              networkConfiguration={"awsvpcConfiguration": {"subnets": [subnet], "securityGroups": [group]}})
        require(not result.get("failures") and len(result.get("tasks", [])) == 1, f"RunTask failed: {result}")
        arn = result["tasks"][0]["taskArn"]
        self.tasks.append(arn)
        self.report["tasks"] = self.tasks
        self.save()
        def running():
            result = ecs.describe_tasks(cluster=self.cluster, tasks=[arn])
            require(not result.get("failures") and len(result.get("tasks", [])) == 1, "Owned task disappeared")
            task = result["tasks"][0]
            require(task["lastStatus"] != "STOPPED", f"Native task failed: {task}")
            return task if task["lastStatus"] == "RUNNING" else None
        task = self.wait("native ECS task RUNNING", running)
        enis = [detail["value"] for attachment in task.get("attachments", [])
                for detail in attachment.get("details", []) if detail["name"] == "networkInterfaceId"]
        require(len(enis) == 1, f"Task lacks one authoritative ENI: {task}")
        eni = self.clients["ec2"].describe_network_interfaces(NetworkInterfaceIds=enis)["NetworkInterfaces"][0]
        require(eni["SubnetId"] == subnet and eni["VpcId"] == self.outputs["vpc_id"], "Task ENI scope changed")
        ids = self.docker("ps", "-aq", "--filter", "label=stackd.ecs.task=" + arn,
                          "--filter", "label=stackd.ecs.role=container").split()
        require(len(ids) == 1, f"Expected one owned application container: {ids}")
        container = json.loads(self.docker("inspect", ids[0]))[0]
        require(container["Config"]["Labels"]["stackd.ecs.task"] == arn, "Container ownership differs")
        self.wait("UDP listener readiness", lambda: "READY" in self.docker("logs", container["Id"]))
        return {"task": arn, "eni": enis[0], "address": eni["PrivateIpAddress"], "container": container["Id"],
                "pid": container["State"]["Pid"], "subnet": subnet}

    def provision_tasks(self):
        ecs = self.clients["ecs"]
        self.cluster = ecs.create_cluster(clusterName=self.name)["cluster"]["clusterArn"]
        definition = ecs.register_task_definition(family=self.name, networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"], cpu="256", memory="512", containerDefinitions=[{
                "name": "udp", "image": self.args.image, "essential": True,
                "entryPoint": ["python3", "-u", "-c"], "command": [SERVER]}])
        self.definition = definition["taskDefinition"]["taskDefinitionArn"]
        self.report.update(cluster=self.cluster, definition=self.definition)
        self.save()
        o = self.outputs
        self.source = self.task(o["source_subnet"], o["source_group"])
        self.destination = self.task(o["destination_subnet"], o["destination_group"])
        self.report.update(source=self.source, destination=self.destination)
        self.variables.update(eni_id=self.destination["eni"], revision="refreshed")
        self.apply()
        self.wait("native flow log binding readiness", self.active)
        self.terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
        plan = self.terraform("plan", "-input=false", "-detailed-exitcode", "-out=noop.tfplan", check=False)
        require(plan.returncode == 0, f"Provider refresh has drift: exit {plan.returncode}")
        self.terraform("apply", "-input=false", "-auto-approve", "noop.tfplan")
        rows = self.clients["ec2"].describe_flow_logs(FlowLogIds=self.outputs["flow_logs"])["FlowLogs"]
        expected = {self.outputs["vpc_id"], self.outputs["destination_subnet"], self.destination["eni"]}
        require({r["ResourceId"] for r in rows} == expected, "VPC/subnet/ENI selectors differ")
        for row in rows:
            require({t["Key"]: t["Value"] for t in row.get("Tags", [])}.get("Revision") == "refreshed",
                    f"Provider did not refresh flow log tags: {row}")
        self.report["flow_logs"] = rows
        policy = json.loads(self.clients["s3"].get_bucket_policy(Bucket=self.outputs["bucket"])["Policy"])
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        require(any(s.get("Principal", {}).get("Service") == "delivery.logs.amazonaws.com"
                    and "s3:PutObject" in s.get("Action", []) for s in statements),
                "CreateFlowLogs did not attach an S3 delivery policy")
        self.report["automatic_bucket_policy"] = policy
        self.report["delivery_role_policy"] = self.clients["iam"].get_role_policy(
            RoleName=self.outputs["role"], PolicyName="delivery")["PolicyDocument"]
        self.save()

    def active(self):
        rows = self.clients["ec2"].describe_flow_logs(FlowLogIds=self.outputs["flow_logs"])["FlowLogs"]
        return len(rows) == 3 and all(row.get("FlowLogStatus") == "ACTIVE" for row in rows)

    def checkpoint(self):
        with sqlite3.connect(f"file:{self.database}?mode=ro", uri=True) as db:
            row = db.execute("SELECT cursor, due, hex(version) FROM ec2_flow_log_capture WHERE singleton=1").fetchone()
        return dict(zip(("cursor", "due", "version"), row)) if row else {}

    def await_packet_checkpoint(self):
        expected = {packet["source_port"] for packet in self.report["packets"]}
        def committed():
            with sqlite3.connect(f"file:{self.database}?mode=ro", uri=True) as db:
                ports = {row[0] for row in db.execute(
                    "SELECT source_port FROM ec2_flow_log_aggregates "
                    "WHERE interface_id=? AND direction='ingress' AND protocol=17 AND lost=0",
                    (self.destination["eni"],))}
                lines = [row[0] for row in db.execute(
                    "SELECT message FROM ec2_flow_log_delivery_lines WHERE interface_id=?",
                    (self.destination["eni"],))]
            for line in lines:
                fields = dict(zip(FIELDS, line.split()))
                if fields.get("log-status") == "OK" and fields.get("flow-direction") == "ingress":
                    ports.add(int(fields["srcport"]))
            if not expected <= ports:
                for row in self.read_records()["all"]:
                    if (row["interface-id"] == self.destination["eni"] and row["log-status"] == "OK"
                            and row["flow-direction"] == "ingress"):
                        ports.add(int(row["srcport"]))
            return self.checkpoint() if expected <= ports else None
        checkpoint = self.wait("real packet tuples committed with native cursor", committed, timeout=45, interval=2)
        require(checkpoint.get("cursor"), "Packet aggregates have no committed native cursor")
        self.report.setdefault("durable_packet_checkpoints", []).append(
            {"source_ports": sorted(expected), "checkpoint": checkpoint})
        self.save()

    def packets(self, phase):
        for index, (label, port, allowed) in enumerate((("allow", 33000, True), ("security-group-deny", 33001, False),
                                                        ("network-acl-deny", 33002, False))):
            sport = 32000 + phase * 10 + index
            payload = (self.name + f"-{phase}-{label}").encode()
            result = json.loads(self.docker("exec", self.source["container"], "python3", "-c", SEND,
                                           self.destination["address"], str(sport), str(port), payload.hex()))
            require(result["sent"] == len(payload), "Socket did not send the full UDP datagram")
            require(result["received"] == (payload.hex() if allowed else None), f"Wrong real packet admission: {label}: {result}")
            self.report["packets"].append(dict(result, label=label, phase=phase, source_port=sport,
                destination_port=port, payload=payload.hex(), expected_action="ACCEPT" if allowed else "REJECT",
                expected_ip_bytes=28 + len(payload)))
            self.save()
        logs = self.docker("logs", self.destination["container"])
        for packet in self.report["packets"]:
            require((packet["payload"] in logs) == (packet["expected_action"] == "ACCEPT"),
                    f"Listener receipt differs from native admission: {packet['label']}")
        self.report["listener_log"] = logs
        self.save()

    def restart(self):
        self.await_packet_checkpoint()
        self.controller.stop(timeout=90)
        retained = self.checkpoint()
        require(retained.get("cursor"), "No retained capture cursor")
        collector = json.loads(self.docker("inspect", self.capture_name))[0]
        self.start()
        self.wait("flow logs ACTIVE after restart", self.active)
        resumed = self.checkpoint()
        require(resumed.get("cursor") and int(resumed["version"], 16) >= int(retained["version"], 16),
                "Restart lost the SQLite capture checkpoint")
        for endpoint in (self.source, self.destination):
            row = json.loads(self.docker("inspect", endpoint["container"]))[0]
            require(row["State"]["Pid"] == endpoint["pid"] and row["State"]["Running"], "Restart replaced the native task")
        after = json.loads(self.docker("inspect", self.capture_name))[0]
        require(after["Id"] == collector["Id"] and after["State"]["Pid"] == collector["State"]["Pid"],
                "Restart replaced the retained native receiver")
        self.report["restart"] = {"retained_checkpoint": retained, "resumed_checkpoint": resumed,
                                  "same_task_pids": True, "same_collector_pid": True,
                                  "contract": "Ordinary graceful restart with commit-before-ack; not crash exactly-once"}
        self.save()


    def read_records(self):
        result = {"all": [], "reject": [], "accept": []}
        events = {"all": [], "reject": []}
        for kind, group in (("all", self.outputs["all_group"]), ("reject", self.outputs["reject_group"])):
            token = None
            while True:
                args = {"logGroupName": group}
                if token:
                    args["nextToken"] = token
                page = self.clients["logs"].filter_log_events(**args)
                events[kind].extend(page.get("events", []))
                result[kind].extend(event["message"] for event in page.get("events", []))
                following = page.get("nextToken")
                if not following or following == token:
                    break
                token = following
        objects = []
        for page in self.clients["s3"].get_paginator("list_objects_v2").paginate(Bucket=self.outputs["bucket"], Prefix="records/"):
            for item in page.get("Contents", []):
                key = item["Key"]
                marker = f"records/AWSLogs/aws-account-id={ACCOUNT}/"
                if key == marker:
                    obj = self.clients["s3"].get_object(Bucket=self.outputs["bucket"], Key=key)
                    try:
                        require(obj["Body"].read() == b"" and obj["ContentLength"] == 0
                                and obj.get("ContentType") == "application/octet-stream",
                                "Native S3 admission marker is not the expected empty object")
                    finally:
                        obj["Body"].close()
                    self.report["admission_marker"] = {"key": key, "bytes": 0,
                        "content_type": obj["ContentType"], "encryption": obj.get("ServerSideEncryption"),
                        "etag": obj.get("ETag")}
                    continue
                require(key.endswith(".log.gz") and "/aws-account-id=" in key and "/hour=" in key,
                        f"Wrong gzip/Hive/hour object key: {key}")
                obj = self.clients["s3"].get_object(Bucket=self.outputs["bucket"], Key=key)
                try:
                    body = obj["Body"].read()
                finally:
                    obj["Body"].close()
                require(body[:2] == b"\x1f\x8b" and obj.get("ContentEncoding") == "gzip"
                        and obj.get("ContentType") == "text/plain", f"Wrong gzip metadata: {key}")
                lines = gzip.decompress(body).decode().splitlines()
                require(lines and lines[0].split() == FIELDS, f"Custom S3 field header differs: {key}")
                result["accept"].extend(lines[1:])
                digest = hashlib.sha256(body).hexdigest()
                artifact = self.work / "s3" / (digest + ".log.gz")
                if not artifact.exists():
                    artifact.parent.mkdir(exist_ok=True)
                    artifact.write_bytes(body)
                objects.append({"key": key, "sha256": digest, "bytes": len(body), "lines": lines,
                                "artifact": str(artifact), "content_type": obj["ContentType"],
                                "content_encoding": obj["ContentEncoding"], "etag": obj.get("ETag")})
        self.report.update(records=result, objects=objects, cloudwatch_events=events)
        self.save()
        return {kind: [dict(zip(FIELDS, line.split())) for line in lines if self.valid_line(line)]
                for kind, lines in result.items()}

    @staticmethod
    def valid_line(line):
        require(len(line.split()) == len(FIELDS), f"Wrong custom record field count: {line}")
        return True

    def verify_records(self):
        rows = self.read_records()
        for kind, action in (("accept", "ACCEPT"), ("reject", "REJECT")):
            require(all(row["action"] == action for row in rows[kind] if row["log-status"] == "OK"),
                    f"Traffic filter admitted the wrong action into {kind}")
        for packet in self.report["packets"]:
            def matches(row):
                return (row["interface-id"] == self.destination["eni"] and row["srcaddr"] == self.source["address"]
                        and row["dstaddr"] == self.destination["address"] and row["srcport"] == str(packet["source_port"])
                        and row["dstport"] == str(packet["destination_port"]) and row["protocol"] == "17"
                        and row["flow-direction"] == "ingress")
            for kind in ("all", "accept" if packet["expected_action"] == "ACCEPT" else "reject"):
                found = [r for r in rows[kind] if matches(r)]
                if not found:
                    return False
                require(len(found) == 1, f"Duplicate tuple after ordinary restart in {kind}: {found}")
                row = found[0]
                require(row["version"] == "5" and row["log-status"] == "OK"
                        and row["action"] == packet["expected_action"], f"False packet evidence: {row}")
                require(int(row["packets"]) == 1 and int(row["bytes"]) == packet["expected_ip_bytes"], f"Native UDP counters differ: {row}")
                require(row["account-id"] == ACCOUNT and row["vpc-id"] == self.outputs["vpc_id"]
                        and row["subnet-id"] == self.outputs["destination_subnet"], f"Authoritative ENI scope differs: {row}")
                require(int(packet["started"]) - 1 <= int(row["start"]) <= int(row["end"]) <= int(packet["finished"]) + 1,
                        f"Record has fabricated or unrelated packet time: {row}")
            excluded = "reject" if packet["expected_action"] == "ACCEPT" else "accept"
            require(not any(matches(r) for r in rows[excluded]), f"Traffic filter leaked a tuple into {excluded}")
        return True

    def cleanup(self):
        errors = []
        def attempt(label, fn):
            try:
                return fn()
            except Exception as error:
                errors.append(label + ": " + str(error))
        live = self.controller.process is not None and self.controller.process.poll() is None
        if not live and (self.tasks or self.cluster or (self.work / "terraform.tfstate").exists()):
            errors.append("Controller unavailable; owned API cleanup is not verified. Retain the state and report.")
        if self.controller.process is not None and self.controller.process.poll() is None:
            ecs = self.clients["ecs"]
            for task in self.tasks:
                attempt("stop task", lambda task=task: ecs.stop_task(cluster=self.cluster, task=task))
            if self.tasks:
                def stopped():
                    result = ecs.describe_tasks(cluster=self.cluster, tasks=self.tasks)
                    require(not result.get("failures") and len(result.get("tasks", [])) == len(self.tasks),
                            f"Cannot prove owned task retirement: {result}")
                    return all(task["lastStatus"] == "STOPPED" for task in result["tasks"])
                attempt("wait task retirement", lambda: self.wait("owned tasks STOPPED", stopped))
                for task in self.tasks:
                    attempt("wait native task cleanup", lambda task=task: self.wait(
                        "owned native task containers removed", lambda: not self.docker(
                            "ps", "-aq", "--filter", "label=stackd.ecs.task=" + task)))
                if self.outputs:
                    attempt("wait ENI retirement", lambda: self.wait("owned task ENIs removed", lambda: not self.clients["ec2"].describe_network_interfaces(
                        Filters=[{"Name": "vpc-id", "Values": [self.outputs["vpc_id"]]}])["NetworkInterfaces"]))
            if self.definition:
                attempt("deregister task definition", lambda: ecs.deregister_task_definition(taskDefinition=self.definition))
                attempt("delete task definition", lambda: ecs.delete_task_definitions(taskDefinitions=[self.definition]))
            if self.cluster:
                attempt("delete cluster", lambda: ecs.delete_cluster(cluster=self.cluster))
            if self.tf_ready:
                attempt("Terraform destroy", lambda: self.terraform("destroy", "-input=false", "-auto-approve"))
                def absent():
                    state = json.loads(self.terraform("show", "-json", capture=True).stdout)
                    require(not state.get("values", {}).get("root_module", {}).get("resources"), "Terraform state still has resources")
                    if self.outputs:
                        rows = self.clients["ec2"].describe_flow_logs(Filters=[{"Name": "flow-log-id", "Values": self.outputs["flow_logs"]}])["FlowLogs"]
                        require(not rows, f"Flow log resources survived destroy: {rows}")
                        expect_missing(self.clients["s3"].head_bucket, {"404", "NoSuchBucket", "NotFound"}, Bucket=self.outputs["bucket"])
                attempt("verify owned absence", absent)
            if self.args.remove_owned_capture and self.report["capture"]["retained"]:
                # Let the service commit and acknowledge endpoint retirement.
                # The later native handshake still rejects any unread evidence.
                time.sleep(12)
        attempt("stop controller", lambda: self.controller.stop(timeout=90))
        self.report["cleanup"] = {"errors": errors, "verified": not errors, "state_retained": str(self.database)}
        if self.args.remove_owned_capture and self.report["capture"]["retained"] and not errors:
            attempt("remove idle owned capture", self.remove_capture)
        self.report["cleanup"]["errors"] = errors
        self.report["cleanup"]["verified"] = not errors
        self.save()
        require(not errors, "Owned cleanup failed; inspect report: " + "; ".join(errors))

    def remove_capture(self):
        # Reuse the runtime's exact lock and bootstrap. Do not make a second
        # cleanup protocol or infer idleness from container labels alone.
        engine = json.loads(self.docker("info", "--format", "{{json .}}"))
        native = ROOT / "compute/network"
        lock_source = (native / "native_lock_daemon.go").read_text()
        marker = "const nativeDaemonLockScript = `"
        require(lock_source.count(marker) == 1, "Cannot locate the native daemon lock")
        lock = lock_source.split(marker, 1)[1].split("`", 1)[0]
        labels = {"stackd.network.flows.namespace": self.namespace,
                  "stackd.network.flows.engine": engine["ID"], "stackd.network.flows.version": "1"}
        config = {
            "Image": TOOLKIT, "Entrypoint": ["python3", "-c", (native / "flows_receiver.py").read_text()],
            "Cmd": ["--stackd-flow-receiver"], "User": "0:0",
            "Env": ["FLOW_NAMESPACE=" + self.namespace, "FLOW_ENGINE_ID=" + engine["ID"], "PYTHONDONTWRITEBYTECODE=1"],
            "Labels": labels,
            "HostConfig": {
                "NetworkMode": "host", "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                "CapAdd": ["NET_ADMIN"], "SecurityOpt": ["no-new-privileges:true"],
                "Mounts": [{"Type": "volume", "Source": self.capture_name, "Target": "/flows", "VolumeOptions": {"NoCopy": True}}],
                "Memory": 128 << 20, "MemorySwap": 128 << 20, "PidsLimit": 32, "LogConfig": {"Type": "none"},
            },
        }
        receipt = self.docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--mount", "type=bind,src=/run,dst=/stackd-host-run",
            "--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly",
            "--env", "NATIVE_ENGINE_ID=" + engine["ID"], "--env", "FLOW_CLEANUP=1",
            "--env", "FLOW_NAME=" + self.capture_name, "--env", "FLOW_VOLUME=" + self.capture_name,
            "--env", "FLOW_CONFIG=" + base64.b64encode(json.dumps(config).encode()).decode(),
            "--env", "FLOW_BOOTSTRAP=" + (native / "flows_bootstrap.py").read_text(),
            "--entrypoint", "python3", TOOLKIT, "-c", lock, 'exec python3 -c "$FLOW_BOOTSTRAP"', timeout=60)
        require("STACKD_FLOW_COLLECTOR_IDLE_REMOVED" in receipt or "STACKD_FLOW_COLLECTOR_ALREADY_ABSENT" in receipt,
                f"Collector gave no native idle removal receipt: {receipt}")
        self.report["capture"].update(idle_receipt=receipt, retained=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/stackd")
    parser.add_argument("--state-directory", type=Path, required=True, help="New owned directory; retain logs, SQLite, state, and report")
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    parser.add_argument("--image", default="python:3.12-alpine", help="Installed image with python3; never pulled")
    parser.add_argument("--provider-mirror", type=Path, help="Prepared hashicorp/aws 6.68.0 mirror; disables direct downloads")
    parser.add_argument("--cidr", default="10.254.244.0/24", help="Unused private /24 for two native subnets")
    parser.add_argument("--port", type=int, default=0, help="Owned listener port; 0 selects a free port")
    parser.add_argument("--publication-timeout", type=float, default=480, help="Real seconds to wait for CW/S3 records")
    parser.add_argument("--remove-owned-capture", action="store_true", help="Remove only exact-owned collector with native idle receipt; otherwise retain it")
    args = parser.parse_args()
    consumer = Consumer(args)
    try:
        consumer.prepare()
        consumer.start()
        consumer.apply()
        consumer.provision_tasks()
        consumer.packets(0)
        consumer.restart()
        consumer.packets(1)
        consumer.await_packet_checkpoint()
        consumer.wait("actual CW and S3 tuple counters", consumer.verify_records,
                      timeout=args.publication_timeout, interval=5)
        consumer.report["completed"] = True
        consumer.save()
    except BaseException:
        consumer.report["failure"] = traceback.format_exc()
        consumer.save()
        raise
    finally:
        consumer.cleanup()
    print(f"Real flow log consumer passed; owned evidence: {consumer.work}", flush=True)


if __name__ == "__main__":
    main()
