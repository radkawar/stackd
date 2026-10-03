#!/usr/bin/env python3
"""Exercise the real official SSM agent in a firmware-booted local EC2 guest.

Requires an already installed stackd binary, QEMU/KVM/Docker/SeaBIOS, an official
Ubuntu raw cloud image and official amazon-ssm-agent Debian package. Inputs are
read-only. All customer shell code goes through Run Command to the guest agent;
there is no SSH executor, fake poller or in-process execution adapter.
"""
import argparse
import base64
import concurrent.futures
import functools
import hashlib
import http.server
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

REGION = "us-east-1"
BLOCK = 512 * 1024
TERMINAL = {"Success", "Failed", "Cancelled", "TimedOut"}


def safe(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    raise TypeError(type(value).__name__)


class Smoke:
    def __init__(self, args):
        self.args = args
        self.account = args.account or f"{uuid.uuid4().int % 10**12:012d}"
        self.state = args.state_directory.resolve()
        self.state.mkdir(parents=True, exist_ok=False)
        self.prefix = "stackd-ssm-guest-" + uuid.uuid4().hex[:10]
        self.endpoint = f"https://127.0.0.1:{args.port}"
        self.guest_endpoint = f"https://{args.gateway}:{args.port}"
        self.process = None
        self.artifacts = None
        self.log = None
        self.clients = {}
        self.owned = {}
        self.data = {"source": "local actual CLI + signed SDK + official agent in QEMU/KVM guest",
                     "prefix": self.prefix, "calls": [], "observations": {}, "owned": self.owned,
                     "account": self.account,
                     "agent_package_sha256": hashlib.sha256(args.agent_package.read_bytes()).hexdigest(),
                     "raw_image": str(args.raw_image), "cleanup": {}}
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(self.data, indent=2, default=safe) + "\n")

    def client(self, service, creds=None):
        if creds is None and service in self.clients:
            return self.clients[service]
        creds = creds or {"AccessKeyId": "test", "SecretAccessKey": "test"}
        client = boto3.client(service, region_name=REGION, endpoint_url=self.endpoint,
                              aws_access_key_id=creds["AccessKeyId"],
                              aws_secret_access_key=creds["SecretAccessKey"],
                              aws_session_token=creds.get("SessionToken"),
                              verify=str(self.state / "server.crt"),
                              config=Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=180,
                                            max_pool_connections=8, s3={"addressing_style": "path"}))
        if creds["AccessKeyId"] == "test":
            self.clients[service] = client
        return client

    def call(self, label, service, method, client=None, **kwargs):
        row = {"label": label, "service": service, "operation": method, "input": kwargs}
        self.data["calls"].append(row)
        try:
            out = getattr(client or self.client(service), method)(**kwargs)
            row.update(code="Success", output=out, request_id=out.get("ResponseMetadata", {}).get("RequestId"))
            return out
        except ClientError as err:
            row.update(code=err.response["Error"]["Code"], error=err.response["Error"],
                       request_id=err.response.get("ResponseMetadata", {}).get("RequestId"))
            raise
        finally:
            self.save()

    def expect(self, label, code, service, method, **kwargs):
        try:
            self.call(label, service, method, **kwargs)
        except ClientError as err:
            assert err.response["Error"]["Code"] == code, (label, err.response)
            return
        raise AssertionError(label + " unexpectedly succeeded")

    def wait(self, label, fn, predicate, seconds=120, delay=1):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            last = fn()
            if predicate(last):
                return last
            time.sleep(delay)
        raise TimeoutError(f"{label}: {last}")

    def start(self):
        self.log = (self.state / "controller.log").open("ab")
        command = [str(self.args.binary), "-listen", f"0.0.0.0:{self.args.port}",
                   "-database", str(self.state / "state.sqlite"), "-docker-host", "unix:///var/run/docker.sock",
                   "-account-id", self.account,
                   "-ec2-state-directory", str(self.state / "guests"),
                   "-ec2-bios", str(self.args.bios), "-tls-cert", str(self.state / "server.crt"),
                   "-tls-key", str(self.state / "server.key"), "-public-endpoint", self.endpoint,
                   "-compute-endpoint", self.guest_endpoint]
        command.extend(getattr(self, "controller_args", ()))
        self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT)
        def ready():
            if self.process.poll() is not None:
                raise RuntimeError("controller exited: " + (self.state / "controller.log").read_text()[-8000:])
            try:
                return self.client("sts").get_caller_identity()["Account"] == self.account
            except Exception:
                return False
        self.wait("controller ready", ready, bool, 60)

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=60)
        self.process = None
        if self.log:
            self.log.close()
            self.log = None

    def prepare(self):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=stackd-ssm-guest", "-addext",
                        f"subjectAltName=IP:127.0.0.1,IP:{self.args.gateway},DNS:localhost,DNS:s3.{REGION}.amazonaws.com,DNS:*.s3.{REGION}.amazonaws.com",
                        "-keyout", str(self.state / "server.key"), "-out", str(self.state / "server.crt")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = self.state / "bootstrap"
        public.mkdir()
        # Serve only the immutable package; never expose controller private keys.
        os.symlink(self.args.agent_package.resolve(), public / "amazon-ssm-agent.deb")
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(public))
        self.artifacts = http.server.ThreadingHTTPServer(("0.0.0.0", self.args.artifact_port), handler)
        threading.Thread(target=self.artifacts.serve_forever, daemon=True).start()
        self.start()

    def import_image(self):
        ebs = self.client("ebs")
        size = self.args.raw_image.stat().st_size
        snapshot = ebs.start_snapshot(VolumeSize=math.ceil(size / (1 << 30)), Description=self.prefix)["SnapshotId"]
        self.owned["snapshot"] = snapshot
        self.save()
        def upload(index, data):
            ebs.put_snapshot_block(SnapshotId=snapshot, BlockIndex=index, BlockData=data, DataLength=BLOCK,
                                   Checksum=base64.b64encode(hashlib.sha256(data).digest()).decode(),
                                   ChecksumAlgorithm="SHA256")
        count = 0
        with self.args.raw_image.open("rb") as image, concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            pending = set()
            for index in range(math.ceil(size / BLOCK)):
                data = image.read(BLOCK).ljust(BLOCK, b"\0")
                if not data.strip(b"\0"):
                    continue
                pending.add(pool.submit(upload, index, data))
                count += 1
                if len(pending) >= 8:
                    done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        future.result()
            for future in pending:
                future.result()
        self.data["observations"]["image_import"] = {"snapshot": snapshot, "nonzero_blocks": count,
                                                     "bytes": size, "protocol": "signed EBS direct APIs"}
        self.call("complete-root-snapshot", "ebs", "complete_snapshot", SnapshotId=snapshot, ChangedBlocksCount=count)
        self.wait("snapshot completed", lambda: self.client("ec2").describe_snapshots(SnapshotIds=[snapshot]),
                  lambda r: r["Snapshots"][0]["State"] == "completed", 120)
        image = self.call("register-firmware-image", "ec2", "register_image", Name=self.prefix,
                          Architecture="x86_64", RootDeviceName="/dev/sda1", VirtualizationType="hvm",
                          BootMode="legacy-bios", EnaSupport=True,
                          BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": snapshot,
                           "VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}])["ImageId"]
        self.owned["image"] = image
        self.save()

    def boot(self):
        vpc = self.call("create-owned-vpc", "ec2", "create_vpc", CidrBlock=self.args.cidr)["Vpc"]["VpcId"]
        self.owned["vpc"] = vpc
        subnet = self.call("create-owned-subnet", "ec2", "create_subnet", VpcId=vpc,
                           CidrBlock=self.args.subnet, AvailabilityZone=REGION + "a")["Subnet"]["SubnetId"]
        self.owned["subnet"] = subnet
        sg = self.call("create-owned-security-group", "ec2", "create_security_group", VpcId=vpc,
                       GroupName=self.prefix, Description="Official SSM guest smoke")["GroupId"]
        self.owned["sg"] = sg
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role = self.call("create-agent-role", "iam", "create_role", RoleName=self.prefix,
                         AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        self.owned["role"] = self.prefix
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["ssm:UpdateInstanceInformation", "ssmmessages:CreateControlChannel",
              "ssmmessages:OpenControlChannel", "s3:*", "logs:*"], "Resource": "*"},
            {"Effect": "Deny", "Action": "ec2messages:*", "Resource": "*"}]}
        self.call("allow-current-message-channel", "iam", "put_role_policy", RoleName=self.prefix,
                  PolicyName="agent", PolicyDocument=json.dumps(policy))
        self.call("create-profile", "iam", "create_instance_profile", InstanceProfileName=self.prefix)
        self.owned["profile"] = self.prefix
        self.call("bind-profile", "iam", "add_role_to_instance_profile", InstanceProfileName=self.prefix, RoleName=self.prefix)
        cfg = {"Agent": {"Region": REGION, "SelfUpdate": False},
               "Ssm": {"Endpoint": self.guest_endpoint, "HealthFrequencyMinutes": 1},
               "Mgs": {"Region": REGION, "Endpoint": self.guest_endpoint},
               "Mds": {"Endpoint": self.guest_endpoint},
               "S3": {"Endpoint": f"s3.{REGION}.amazonaws.com:{self.args.port}", "Region": REGION},
               "CloudWatchLogs": {"Endpoint": self.guest_endpoint, "Region": REGION}}
        cert = base64.b64encode((self.state / "server.crt").read_bytes()).decode()
        config = base64.b64encode(json.dumps(cfg).encode()).decode()
        userdata = f'''#!/bin/bash
set -eux
exec > >(tee /var/log/stackd-ssm-bootstrap.log /dev/console) 2>&1
systemctl stop amazon-ssm-agent.service snap.amazon-ssm-agent.amazon-ssm-agent.service || true
mkdir -p /etc/amazon/ssm /usr/local/share/ca-certificates
printf %s '{cert}' | base64 -d > /usr/local/share/ca-certificates/stackd-ssm.crt
update-ca-certificates
printf %s '{config}' | base64 -d > /etc/amazon/ssm/amazon-ssm-agent.json
printf '%s\\n' '{self.args.gateway} s3.{REGION}.amazonaws.com {self.prefix}.s3.{REGION}.amazonaws.com' >> /etc/hosts
curl --fail --retry 3 http://{self.args.gateway}:{self.args.artifact_port}/amazon-ssm-agent.deb -o /var/tmp/amazon-ssm-agent.deb
dpkg -i /var/tmp/amazon-ssm-agent.deb
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
amazon-ssm-agent -version
printf 'STACKD_OFFICIAL_AGENT_BOOTSTRAPPED\\n'
(for delay in 25 35 60; do sleep "$delay"; cat /var/log/amazon/ssm/amazon-ssm-agent.log > /dev/console; done) &
'''
        launched = self.call("launch-real-guest", "ec2", "run_instances", ImageId=self.owned["image"],
                             InstanceType="t3.micro", MinCount=1, MaxCount=1,
                             SubnetId=subnet, SecurityGroupIds=[sg],
                             IamInstanceProfile={"Name": self.prefix}, UserData=userdata,
                             MetadataOptions={"HttpEndpoint": "enabled", "HttpTokens": "required"},
                             TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "suite", "Value": self.prefix}]}])
        self.owned["instance"] = launched["Instances"][0]["InstanceId"]
        self.save()
        self.wait("official agent registers", lambda: self.client("ssm").describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [self.owned["instance"]]}]),
            lambda r: r["InstanceInformationList"] and r["InstanceInformationList"][0]["PingStatus"] == "Online", 240, 2)
        running = self.call("record-running-guest-attachments", "ec2", "describe_instances",
                            InstanceIds=[self.owned["instance"]])["Reservations"][0]["Instances"][0]
        self.owned["volumes"] = [v["Ebs"]["VolumeId"] for v in running.get("BlockDeviceMappings", [])]
        self.owned["enis"] = [v["NetworkInterfaceId"] for v in running.get("NetworkInterfaces", [])]
        self.save()

    def send(self, label, commands, **options):
        args = {"DocumentName": "AWS-RunShellScript", "InstanceIds": [self.owned["instance"]],
                "Parameters": {"commands": commands, "executionTimeout": ["30"]}, "TimeoutSeconds": 30}
        args.update(options)
        return self.call(label, "ssm", "send_command", **args)["Command"]["CommandId"]

    def result(self, label, command, plugin=None, seconds=120):
        args = {"CommandId": command, "InstanceId": self.owned["instance"]}
        if plugin:
            args["PluginName"] = plugin
        states = []
        def observe():
            out = self.client("ssm").get_command_invocation(**args)
            if not states or states[-1] != out["Status"]:
                states.append(out["Status"])
            return out
        result = self.wait(label, observe, lambda r: r["Status"] in TERMINAL, seconds)
        self.data["observations"][label] = {"states": states, "result": result}
        self.save()
        self.call(label + "-invocation", "ssm", "get_command_invocation", **args)
        self.call(label + "-command", "ssm", "list_commands", CommandId=command)
        self.call(label + "-plugins", "ssm", "list_command_invocations", CommandId=command, Details=True)
        return result

    def exercise(self):
        self.admission()
        marker = self.prefix + "-marker"
        self.owned["bucket"] = self.prefix
        self.call("create-output-bucket", "s3", "create_bucket", Bucket=self.prefix)
        self.owned["log_group"] = "/stackd/ssm/" + self.prefix
        self.call("create-output-log-group", "logs", "create_log_group", logGroupName=self.owned["log_group"])
        first = self.send("marker-write-read", [f"printf '%s\\n' '{marker}' > /var/tmp/ssm-marker", "cat /var/tmp/ssm-marker",
                          "cat /proc/sys/kernel/random/boot_id", "amazon-ssm-agent -version", "printf 'guest-stderr\\n' >&2"],
                          OutputS3BucketName=self.prefix, OutputS3KeyPrefix="commands",
                          CloudWatchOutputConfig={"CloudWatchOutputEnabled": True, "CloudWatchLogGroupName": self.owned["log_group"]})
        out = self.result("marker", first)
        assert out["Status"] == "Success" and marker in out["StandardOutputContent"] and "guest-stderr" in out["StandardErrorContent"]
        boot = out["StandardOutputContent"].splitlines()[1]
        failed = self.result("nonzero", self.send("exit-seven", ["printf 'failure-out\\n'; printf 'failure-err\\n' >&2; exit 7"]))
        assert failed["Status"] == "Failed" and failed["ResponseCode"] == 7 and "failure-out" in failed["StandardOutputContent"] and "exit status 7" in failed["StandardErrorContent"]
        timeout = self.result("execution-timeout", self.send("timeout-five", ["echo before-timeout; sleep 20; echo forbidden-after-timeout"],
            Parameters={"commands": ["echo before-timeout; sleep 20; echo forbidden-after-timeout"], "executionTimeout": ["5"]}))
        assert timeout["Status"] == "TimedOut" and "forbidden-after-timeout" not in timeout["StandardOutputContent"]
        cancelled = self.send("cancel-live", ["echo before-cancel; sleep 120; echo forbidden-after-cancel"],
                              Parameters={"commands": ["echo before-cancel; sleep 120; echo forbidden-after-cancel"], "executionTimeout": ["180"]})
        self.wait("command delivered", lambda: self.client("ssm").list_command_invocations(CommandId=cancelled),
                  lambda r: r["CommandInvocations"][0]["Status"] == "InProgress")
        time.sleep(2)
        self.call("cancel-command", "ssm", "cancel_command", CommandId=cancelled)
        result = self.result("cancelled", cancelled)
        assert result["Status"] == "Cancelled" and "forbidden-after-cancel" not in result["StandardOutputContent"]
        self.documents()
        self.expect("missing-node", "InvalidInstanceId", "ssm", "send_command", DocumentName="AWS-RunShellScript",
                    InstanceIds=["i-00000000000000000"], Parameters={"commands": ["true"]})
        self.iam_denial()
        # Official agent executes the once-only marker; controller restart never runs customer code.
        # Upstream MGS persists replies on disconnect and scans that queue every
        # two minutes. This command's delivery budget must cover that real scan.
        running = self.send("restart-inflight", ["printf 'once\\n' >> /var/tmp/ssm-once; sleep 8; cat /var/tmp/ssm-once"],
                            TimeoutSeconds=300,
                            Parameters={"commands": ["printf 'once\\n' >> /var/tmp/ssm-once; sleep 8; cat /var/tmp/ssm-once"], "executionTimeout": ["30"]})
        time.sleep(2)
        self.stop()
        self.start()
        result = self.result("controller-restart-inflight", running, seconds=300)
        assert result["Status"] == "Success" and result["StandardOutputContent"] == "once\n"
        check = self.result("controller-restart-retained", self.send("check-retained-guest", ["cat /proc/sys/kernel/random/boot_id", "cat /var/tmp/ssm-once", "cat /var/tmp/ssm-marker"]))
        assert check["StandardOutputContent"].splitlines() == [boot, "once", marker]
        recovered = self.call("completed-result-recovered", "ssm", "get_command_invocation", CommandId=first, InstanceId=self.owned["instance"])
        assert recovered["StandardOutputContent"] == out["StandardOutputContent"]
        self.outputs(first, marker)
        self.call("reboot-retained-guest", "ec2", "reboot_instances", InstanceIds=[self.owned["instance"]])
        time.sleep(5)
        def rebooted():
            return self.result("guest-reboot-result", self.send("read-retained-after-reboot",
                ["cat /proc/sys/kernel/random/boot_id", "cat /var/tmp/ssm-marker", "cat /var/tmp/ssm-once"]), seconds=120)
        after_reboot = self.wait("fresh guest boot identity", rebooted,
            lambda r: r["Status"] == "Success" and r["StandardOutputContent"].splitlines()[0] != boot, 180, 3)
        lines = after_reboot["StandardOutputContent"].splitlines()
        assert lines[1:] == [marker, "once"]
        self.data["observations"]["guest_reboot_retains_bytes"] = {"before_boot_id": boot, "after_boot_id": lines[0], "marker": lines[1:]}
        boot = lines[0]
        self.save()
        # Agent outage, not a stopped EC2 node: same durable guest reconnects later.
        # systemd's default minute-level timer coalescing is not an agent outage.
        offline = self.send("schedule-agent-outage", ["systemd-run --unit=ssm-smoke-stop --timer-property=AccuracySec=100ms --on-active=3 /bin/systemctl stop amazon-ssm-agent", "systemd-run --unit=ssm-smoke-start --timer-property=AccuracySec=100ms --on-active=70 /bin/systemctl start amazon-ssm-agent"])
        assert self.result("schedule-outage", offline)["Status"] == "Success"
        time.sleep(15)
        undelivered = self.send("offline-delivery", ["echo forbidden > /var/tmp/ssm-offline"],
                                Parameters={"commands": ["echo forbidden > /var/tmp/ssm-offline"], "executionTimeout": ["5"]})
        delivery = self.result("delivery-timeout", undelivered, seconds=50)
        assert delivery["Status"] == "TimedOut" and delivery["StatusDetails"] == "DeliveryTimedOut"
        time.sleep(25)
        back = self.result("agent-reconnect", self.send("verify-no-expired-side-effect", ["test ! -e /var/tmp/ssm-offline || exit 11", "cat /proc/sys/kernel/random/boot_id"]), seconds=120)
        assert back["Status"] == "Success" and back["StandardOutputContent"].strip() == boot
        self.audit()

    def admission(self):
        # A rejected oversized command must not disconnect the real agent or
        # prevent the ordinary command immediately behind it from executing.
        self.expect("oversized-list-rejected", "MaxDocumentSizeExceeded", "ssm", "send_command",
                    DocumentName="AWS-RunShellScript", InstanceIds=[self.owned["instance"]],
                    Parameters={"commands": [""] * 210000})
        key = self.prefix + "-empty-value"
        absent = self.call("empty-tag-does-not-select-untagged", "ssm", "send_command",
                          DocumentName="AWS-RunShellScript", Targets=[{"Key": "tag:" + key, "Values": [""]}],
                          Parameters={"commands": ["echo forbidden > /var/tmp/ssm-wrong-tag"]})
        assert absent["Command"]["TargetCount"] == 0
        assert absent["Command"]["Status"] == "Pending" and absent["Command"]["StatusDetails"] == "Pending"
        settled = self.wait("empty-target command settles", lambda: self.client("ssm").list_commands(CommandId=absent["Command"]["CommandId"]),
                            lambda r: r["Commands"][0]["Status"] == "Success")
        assert settled["Commands"][0]["StatusDetails"] == "NoInstancesInTag"
        self.data["observations"]["zero_target_lifecycle"] = {
            "admission": absent["Command"], "settled": settled["Commands"][0]}
        fleet = self.call("empty-fleet-tag-does-not-select-untagged", "ssm", "describe_instance_information",
                          Filters=[{"Key": "tag-key", "Values": [key]}])
        assert not fleet["InstanceInformationList"]
        self.call("apply-actual-empty-tag", "ec2", "create_tags", Resources=[self.owned["instance"]],
                  Tags=[{"Key": key, "Value": ""}])
        fleet = self.call("empty-fleet-tag-selects-present", "ssm", "describe_instance_information",
                          Filters=[{"Key": "tag-key", "Values": [key]}])
        assert [row["InstanceId"] for row in fleet["InstanceInformationList"]] == [self.owned["instance"]]
        admitted = self.call("empty-tag-selects-present", "ssm", "send_command", DocumentName="AWS-RunShellScript",
                             Targets=[{"Key": "tag:" + key, "Values": [""]}],
                             Parameters={"commands": ["test ! -e /var/tmp/ssm-wrong-tag || exit 11; printf 'after-size-rejection\\n'"]})
        assert admitted["Command"]["TargetCount"] == 1
        output = self.result("actual-delivery-after-size-rejection", admitted["Command"]["CommandId"])
        assert output["Status"] == "Success" and output["StandardOutputContent"] == "after-size-rejection\n"
        self.call("remove-owned-empty-tag", "ec2", "delete_tags", Resources=[self.owned["instance"]], Tags=[{"Key": key}])

    def audit(self):
        events = []
        request = {"LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": "ssm.amazonaws.com"}]}
        for _ in range(100):
            page = self.client("cloudtrail").lookup_events(**request)
            events.extend(json.loads(row["CloudTrailEvent"]) for row in page["Events"])
            if not page.get("NextToken"):
                break
            request["NextToken"] = page["NextToken"]
        else:
            raise RuntimeError("bounded audit history was truncated")
        by_request = {row["requestID"]: row for row in events}
        checked = {}
        document_ids = {}
        for call in self.data["calls"]:
            if call["service"] != "ssm":
                continue
            event = by_request[call["request_id"]]
            action = self.client("ssm").meta.method_to_api_mapping[call["operation"]]
            assert event["eventName"] == action and event["eventCategory"] == "Management"
            assert not event.get("resources")
            assert event["readOnly"] == action.startswith(("Get", "List", "Describe"))
            if call["code"] == "Success":
                if action in ("CreateDocument", "UpdateDocument"):
                    assert event["requestParameters"]["content"] == "HIDDEN_DUE_TO_SECURITY_REASONS"
                    assert event["responseElements"]["documentDescription"]["status"] == call["output"]["DocumentDescription"]["Status"]
                    name = call["input"]["Name"]
                    document_id = event["responseElements"]["documentDescription"]["documentId"]
                    assert uuid.UUID(document_id).version == 4
                    if action == "CreateDocument":
                        assert document_ids.get(name) != document_id
                        document_ids[name] = document_id
                    else:
                        assert document_ids[name] == document_id
                elif action == "UpdateDocumentDefaultVersion":
                    assert event["responseElements"]["description"]["defaultVersion"] == call["output"]["Description"]["DefaultVersion"]
                elif action == "SendCommand":
                    command = event["responseElements"]["command"]
                    actual = call["output"]["Command"]
                    assert command["commandId"] == actual["CommandId"]
                    assert command["status"] == actual["Status"] and command["statusDetails"] == actual["StatusDetails"]
                    assert command["parameters"] == "HIDDEN_DUE_TO_SECURITY_REASONS"
                    if call["input"].get("Parameters"):
                        assert event["requestParameters"]["parameters"] == "HIDDEN_DUE_TO_SECURITY_REASONS"
                else:
                    assert event["responseElements"] is None
            else:
                assert event["responseElements"] is None
            checked[action] = checked.get(action, 0) + 1
        heartbeats = [row for row in events if row["eventName"] == "UpdateInstanceInformation"]
        assert heartbeats
        assert any("iPAddress" in row["requestParameters"] for row in heartbeats)
        for row in heartbeats:
            request = row["requestParameters"]
            assert row["eventCategory"] == "Management" and row["readOnly"] is False
            assert not row.get("resources") and row["responseElements"] is None
            assert request["instanceId"] == self.owned["instance"]
            if "iPAddress" in request:
                assert request["iPAddress"] == "HIDDEN_DUE_TO_SECURITY_REASONS"
            assert "IPAddress" not in request and "InstanceID" not in request
        self.data["observations"]["actual_cloudtrail_audit"] = {
            "checked_public_calls": checked, "official_agent_heartbeats": len(heartbeats), "events": events,
            "native_source": "testdata/aws/ssm/managed_execution_audit.json",
            "lifecycle": "Actual accepted Creating/Updating/Pending snapshots match journal; shared durable jobs settle versions/zero-target commands."}
        self.save()

    def documents(self):
        name = self.prefix + "-document"
        def content(text):
            return json.dumps({"schemaVersion": "2.2", "description": "real official agent steps",
                "parameters": {"message": {"type": "String", "allowedPattern": "^[a-z-]+$"}},
                "mainSteps": [{"action": "aws:runShellScript", "name": "writeMarker", "inputs": {
                    "runCommand": [f"printf '{text}:%s\\n' '{{{{ message }}}}' > /var/tmp/ssm-document", "cat /var/tmp/ssm-document"], "timeoutSeconds": "10"}},
                    {"action": "aws:runShellScript", "name": "failStep", "inputs": {"runCommand": ["echo second-stderr >&2; exit 9"], "timeoutSeconds": "10"}}]})
        created = self.call("create-customer-document", "ssm", "create_document", Name=name, Content=content("one"), DocumentType="Command", DocumentFormat="JSON")
        self.owned["document"] = name
        assert created["DocumentDescription"]["Status"] == "Creating"
        self.wait("document version one active", lambda: self.client("ssm").describe_document(Name=name, DocumentVersion="1"),
                  lambda r: r["Document"]["Status"] == "Active")
        updated = self.call("create-document-version-two", "ssm", "update_document", Name=name, Content=content("two"), DocumentVersion="$LATEST")
        assert updated["DocumentDescription"]["Status"] == "Updating"
        self.wait("document version two active", lambda: self.client("ssm").describe_document(Name=name, DocumentVersion="2"),
                  lambda r: r["Document"]["Status"] == "Active")
        self.data["observations"]["document_lifecycle"] = {
            "create_status": created["DocumentDescription"]["Status"], "update_status": updated["DocumentDescription"]["Status"]}
        self.call("set-default-version-two", "ssm", "update_document_default_version", Name=name, DocumentVersion="2")
        self.call("describe-customer-document", "ssm", "describe_document", Name=name)
        self.call("list-customer-document-versions", "ssm", "list_document_versions", Name=name)
        self.call("list-owned-documents", "ssm", "list_documents", Filters=[{"Key": "Owner", "Values": ["Self"]}])
        self.call("get-customer-document", "ssm", "get_document", Name=name, DocumentVersion="1")
        self.expect("missing-required-document-parameter", "InvalidParameters", "ssm", "send_command", DocumentName=name, InstanceIds=[self.owned["instance"]])
        for version, text in (("1", "one"), ("$DEFAULT", "two")):
            command = self.call("execute-document-version-" + version, "ssm", "send_command", DocumentName=name,
                                DocumentVersion=version, InstanceIds=[self.owned["instance"]], Parameters={"message": ["customer"]})["Command"]["CommandId"]
            one = self.result("plugin-write-" + version, command, "writeMarker")
            two = self.result("plugin-failure-" + version, command, "failStep")
            assert one["Status"] == "Success" and one["StandardOutputContent"] == text + ":customer\n"
            assert two["Status"] == "Failed" and two["ResponseCode"] == 9
        env = {**os.environ, "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_SESSION_TOKEN": "", "AWS_DEFAULT_REGION": REGION,
               "AWS_CA_BUNDLE": str(self.state / "server.crt"), "AWS_EC2_METADATA_DISABLED": "true"}
        cli = subprocess.run(["aws", "--endpoint-url", self.endpoint, "ssm", "get-document", "--name", name, "--document-version", "1"], env=env,
                             capture_output=True, text=True, check=True, timeout=30)
        actual = json.loads(cli.stdout)
        assert actual["DocumentVersion"] == "1" and actual["Content"] == content("one")
        self.data["observations"]["actual_aws_cli_get_document"] = actual
        self.call("delete-document-incarnation", "ssm", "delete_document", Name=name)
        recreated = self.call("recreate-document-incarnation", "ssm", "create_document",
                              Name=name, Content=content("recreated"), DocumentType="Command")
        assert recreated["DocumentDescription"]["Status"] == "Creating"
        self.wait("recreated document active", lambda: self.client("ssm").describe_document(Name=name),
                  lambda r: r["Document"]["Status"] == "Active")
        self.save()

    def iam_denial(self):
        role = self.prefix + "-caller"
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.account}:root"}, "Action": "sts:AssumeRole"}]}
        arn = self.call("create-caller-role", "iam", "create_role", RoleName=role, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        self.owned["caller_role"] = role
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": "*"}]}
        self.call("allow-caller-command", "iam", "put_role_policy", RoleName=role, PolicyName="command", PolicyDocument=json.dumps(policy))
        # Credentials are transient and never retained in evidence.
        creds = self.client("sts").assume_role(RoleArn=arn, RoleSessionName="ssm-live-authority")["Credentials"]
        client = self.client("ssm", creds)
        admitted = self.call("same-session-allowed", "ssm", "send_command", client=client, DocumentName="AWS-RunShellScript", InstanceIds=[self.owned["instance"]], Parameters={"commands": ["echo allowed"]})
        self.result("same-session-allowed-result", admitted["Command"]["CommandId"])
        policy["Statement"] = [
            {"Effect": "Allow", "Action": "ssm:SendCommand",
             "Resource": f"arn:aws:ec2:{REGION}:{self.account}:instance/{self.owned['instance']}"},
            {"Effect": "Allow", "Action": "ssm:SendCommand",
             "Resource": f"arn:aws:ssm:{REGION}::document/AWS-RunShellScript",
             "Condition": {"StringEquals": {"aws:ResourceAccount": "187340769485"}}}]
        self.call("allow-native-builtin-owner", "iam", "put_role_policy", RoleName=role, PolicyName="command", PolicyDocument=json.dumps(policy))
        admitted = self.call("native-builtin-owner-allowed", "ssm", "send_command", client=client,
                             DocumentName="AWS-RunShellScript", InstanceIds=[self.owned["instance"]],
                             Parameters={"commands": ["printf 'provider-owned-document\\n'"]})
        actual = self.result("native-builtin-owner-executed", admitted["Command"]["CommandId"])
        assert actual["Status"] == "Success" and actual["StandardOutputContent"] == "provider-owned-document\n"
        policy["Statement"][1]["Condition"]["StringEquals"]["aws:ResourceAccount"] = self.account
        self.call("require-caller-owned-document", "iam", "put_role_policy", RoleName=role, PolicyName="command", PolicyDocument=json.dumps(policy))
        self.expect("builtin-is-not-caller-owned", "AccessDeniedException", "ssm", "send_command", client=client,
                    DocumentName="AWS-RunShellScript", InstanceIds=[self.owned["instance"]], Parameters={"commands": ["echo forbidden"]})
        policy["Statement"].append({"Effect": "Deny", "Action": "ssm:SendCommand", "Resource": "*"})
        self.call("deny-current-caller-command", "iam", "put_role_policy", RoleName=role, PolicyName="command", PolicyDocument=json.dumps(policy))
        self.expect("same-session-current-iam-denied", "AccessDeniedException", "ssm", "send_command", client=client, DocumentName="AWS-RunShellScript", InstanceIds=[self.owned["instance"]], Parameters={"commands": ["echo forbidden"]})

    def outputs(self, command, marker):
        def objects():
            return self.client("s3").list_objects_v2(Bucket=self.prefix, Prefix="commands/" + command).get("Contents", [])
        rows = self.wait("agent S3 output", objects, lambda r: any(x["Key"].endswith("stdout") for x in r), 60)
        outputs = {}
        for row in rows:
            outputs[row["Key"]] = self.client("s3").get_object(Bucket=self.prefix, Key=row["Key"])["Body"].read().decode()
        assert any(marker in v for v in outputs.values()) and any("guest-stderr" in v for v in outputs.values())
        def events():
            return self.client("logs").filter_log_events(logGroupName=self.owned["log_group"]).get("events", [])
        logged = self.wait("agent CloudWatch output", events, lambda r: any(marker in x["message"] for x in r) and any("guest-stderr" in x["message"] for x in r), 90)
        self.data["observations"]["real_agent_s3_outputs"] = outputs
        self.data["observations"]["real_agent_cloudwatch_events"] = logged
        self.save()

    def cleanup(self):
        errors = []
        absent = {}
        def attempt(label, service, method, **kwargs):
            try:
                return self.call(label, service, method, **kwargs)
            except Exception as err:
                errors.append({"label": label, "error": str(err)})
        if self.process is not None:
            if iid := self.owned.get("instance"):
                attempt("terminate-owned-guest", "ec2", "terminate_instances", InstanceIds=[iid])
                try:
                    self.wait("guest terminated", lambda: self.client("ec2").describe_instances(InstanceIds=[iid]),
                              lambda r: r["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated", 120)
                except Exception as err:
                    errors.append({"label": "guest-termination", "error": str(err)})
            if value := self.owned.get("document"):
                attempt("delete-owned-document", "ssm", "delete_document", Name=value)
            if value := self.owned.get("image"):
                attempt("deregister-owned-image", "ec2", "deregister_image", ImageId=value)
            if value := self.owned.get("snapshot"):
                attempt("delete-owned-snapshot", "ec2", "delete_snapshot", SnapshotId=value)
            if self.owned.get("profile"):
                attempt("unbind-owned-profile", "iam", "remove_role_from_instance_profile", InstanceProfileName=self.prefix, RoleName=self.prefix)
                attempt("delete-owned-profile", "iam", "delete_instance_profile", InstanceProfileName=self.prefix)
            for key, policy in (("role", "agent"), ("caller_role", "command")):
                if role := self.owned.get(key):
                    attempt("delete-" + key + "-policy", "iam", "delete_role_policy", RoleName=role, PolicyName=policy)
                    attempt("delete-" + key, "iam", "delete_role", RoleName=role)
            if bucket := self.owned.get("bucket"):
                try:
                    rows = self.client("s3").list_objects_v2(Bucket=bucket).get("Contents", [])
                    for row in rows:
                        self.client("s3").delete_object(Bucket=bucket, Key=row["Key"])
                except Exception as err:
                    errors.append({"label": "output-objects", "error": str(err)})
                attempt("delete-output-bucket", "s3", "delete_bucket", Bucket=bucket)
            if group := self.owned.get("log_group"):
                attempt("delete-output-log-group", "logs", "delete_log_group", logGroupName=group)
            for key, method, field in (("sg", "delete_security_group", "GroupId"), ("subnet", "delete_subnet", "SubnetId"), ("vpc", "delete_vpc", "VpcId")):
                if value := self.owned.get(key):
                    attempt("delete-owned-" + key, "ec2", method, **{field: value})
            def verify_absence(key, code, service, method, **kwargs):
                try:
                    self.expect("absence-" + key, code, service, method, **kwargs)
                    absent[key] = True
                except Exception as err:
                    errors.append({"label": "absence-" + key, "error": str(err)})
            for key, service, method, field, code in (
                ("document", "ssm", "describe_document", "Name", "InvalidDocument"),
                ("profile", "iam", "get_instance_profile", "InstanceProfileName", "NoSuchEntity"),
                ("role", "iam", "get_role", "RoleName", "NoSuchEntity"),
                ("caller_role", "iam", "get_role", "RoleName", "NoSuchEntity"),
                ("bucket", "s3", "head_bucket", "Bucket", "404"),
            ):
                if value := self.owned.get(key):
                    verify_absence(key, code, service, method, **{field: value})
            for key, method, field, code in (
                ("snapshot", "describe_snapshots", "SnapshotIds", "InvalidSnapshot.NotFound"),
                ("sg", "describe_security_groups", "GroupIds", "InvalidGroup.NotFound"),
                ("subnet", "describe_subnets", "SubnetIds", "InvalidSubnetID.NotFound"),
                ("vpc", "describe_vpcs", "VpcIds", "InvalidVpcID.NotFound"),
            ):
                if value := self.owned.get(key):
                    verify_absence(key, code, "ec2", method, **{field: [value]})
            for key, method, field, code in (
                ("volumes", "describe_volumes", "VolumeIds", "InvalidVolume.NotFound"),
                ("enis", "describe_network_interfaces", "NetworkInterfaceIds", "InvalidNetworkInterfaceID.NotFound"),
            ):
                for value in self.owned.get(key, []):
                    verify_absence(value, code, "ec2", method, **{field: [value]})
            if iid := self.owned.get("instance"):
                result = attempt("absence-running-guest", "ec2", "describe_instances", InstanceIds=[iid])
                absent["nonterminal_instance"] = bool(result and result["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated")
            if image := self.owned.get("image"):
                result = attempt("absence-image", "ec2", "describe_images", ImageIds=[image])
                absent["image"] = bool(result is not None and not result.get("Images"))
            if group := self.owned.get("log_group"):
                result = attempt("absence-log-group", "logs", "describe_log_groups", logGroupNamePrefix=group)
                absent["log_group"] = bool(result is not None and not result.get("logGroups"))
            if self.data.get("passed"):
                try:
                    self.audit()
                except Exception as err:
                    errors.append({"label": "actual-cloudtrail-audit", "error": str(err)})
            for key, gone in absent.items():
                if not gone:
                    errors.append({"label": "absence-" + key, "error": "resource still present"})
        self.data["cleanup"] = {"errors": errors, "absent": absent, "resource_deletes_completed": not errors,
            "retained_history": "Command/invocation and API history remain in SQLite; no public delete-command API exists.",
            "shared_inputs": "Original Ubuntu raw/qcow2 and official agent package were never modified or deleted."}
        self.save()
        self.stop()
        if self.artifacts:
            self.artifacts.shutdown()
            self.artifacts.server_close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--raw-image", type=Path, required=True)
    p.add_argument("--agent-package", type=Path, required=True)
    p.add_argument("--state-directory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--account", help="Dedicated local AWS account (default: unique per run)")
    p.add_argument("--bios", type=Path, default=Path("/usr/share/seabios/bios-256k.bin"))
    p.add_argument("--port", type=int, default=48566)
    p.add_argument("--artifact-port", type=int, default=48567)
    p.add_argument("--cidr", default="10.193.0.0/16")
    p.add_argument("--subnet", default="10.193.1.0/24")
    p.add_argument("--gateway", default="10.193.0.1")
    args = p.parse_args()
    for name in ("binary", "raw_image", "agent_package", "bios"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    smoke = Smoke(args)
    try:
        smoke.prepare()
        smoke.import_image()
        smoke.boot()
        smoke.exercise()
        smoke.data["passed"] = True
    except BaseException as err:
        smoke.data["failure"] = {"type": type(err).__name__, "message": str(err)}
        if smoke.owned.get("instance"):
            try:
                smoke.call("failure-real-console", "ec2", "get_console_output", InstanceId=smoke.owned["instance"], Latest=True)
            except Exception:
                pass
        raise
    finally:
        smoke.cleanup()
    if not smoke.data["cleanup"]["resource_deletes_completed"]:
        raise RuntimeError("owned resource cleanup failed: " + json.dumps(smoke.data["cleanup"]["errors"]))
    print(json.dumps({"passed": smoke.data["passed"], "observations": list(smoke.data["observations"]),
                      "cleanup_verified": smoke.data["cleanup"]["absent"]}, sort_keys=True))


if __name__ == "__main__":
    main()
