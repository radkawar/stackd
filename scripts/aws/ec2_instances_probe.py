#!/usr/bin/env python3
"""Capture real owned EC2 guests, launch IAM, image lineage and complete cleanup.

At most two t3.nano Linux instances, one isolated VPC/subnet/security group,
8-GiB gp3 roots and 1-GiB gp3 data disks. No public networking, package installs,
account-default changes or existing role mutations. SDK credentials/IMDS tokens
never enter evidence; guest credential metadata retains only Code/Type/Expiration.
The output is the durable ownership ledger; --cleanup-only resumes interrupted
cleanup. SIGTERM, SIGINT and a bounded experiment alarm enter finally cleanup.
Use --audit-only after cleanup to retain matching CloudTrail events and regenerate
a compact adjacent instances_*_handoff.json from the actual captured calls.
"""
import argparse
import base64
import copy
import datetime
import json
from pathlib import Path
import re
import signal
import time
import uuid

import boto3
from botocore.exceptions import ClientError

from ebs_encryption_probe import CONFIG, Capture, allow, now, policy, safe
from ebs_volume_controls_probe import sanitized

OPERATIONS = (
    "RunInstances", "DescribeInstances", "DescribeInstanceStatus", "DescribeInstanceAttribute",
    "StopInstances", "StartInstances", "RebootInstances", "TerminateInstances", "GetConsoleOutput",
    "CreateImage", "RegisterImage", "DescribeImages", "DescribeImageAttribute", "DeregisterImage",
    "AttachVolume", "DetachVolume", "ModifyInstanceAttribute",
)
DOCS = ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + name + ".html" for name in OPERATIONS] + [
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/supported-iam-actions-tagging.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/permission-to-pass-iam-roles.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-instance-state-changes.html",
    "https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html",
]

# This script never prints request headers, token bodies or unfiltered credentials.
GUEST = r'''#!/usr/bin/python3
import glob, json, os, pathlib, subprocess, time, urllib.request, urllib.error
base = "http://169.254.169.254/latest/"
def request(path, method="GET", token=None, ttl=None):
    headers = {}
    if token is not None: headers["X-aws-ec2-metadata-token"] = token
    if ttl is not None: headers["X-aws-ec2-metadata-token-ttl-seconds"] = str(ttl)
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers, method=method), timeout=3) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, ""
    except Exception:
        return 0, ""
def command(args):
    return subprocess.check_output(args, timeout=15, stderr=subprocess.DEVNULL).decode().strip()
record = {"kernel": os.uname().release, "machine": os.uname().machine, "cpus": os.cpu_count(),
          "mem_total_kib": int(pathlib.Path("/proc/meminfo").read_text().splitlines()[0].split()[1]),
          "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
p = pathlib.Path("/var/lib/stackd-probe-boot-count")
record["boot_count"] = int(p.read_text()) + 1 if p.exists() else 1
p.write_text(str(record["boot_count"]))
record["root_device"] = command(["findmnt", "-n", "-o", "SOURCE", "/"])
record["block_devices"] = json.loads(command(["lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,SERIAL,MOUNTPOINT"]))
try:
    disks = ["/dev/" + pathlib.Path(v).parent.name for v in glob.glob("/sys/block/nvme*n*/size") if pathlib.Path(v).read_text().strip() == "2097152"]
    if len(disks) == 1:
        device = disks[0]
        if subprocess.run(["blkid", device], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode:
            command(["mkfs.ext4", "-F", "-q", device])
        mount = pathlib.Path("/var/lib/stackd-probe-data")
        mount.mkdir(exist_ok=True)
        command(["mount", device, str(mount)])
        data = mount / "boot-count"
        record["data_previous_count"] = int(data.read_text()) if data.exists() else 0
        record["data_boot_count"] = record["data_previous_count"] + 1
        data.write_text(str(record["data_boot_count"]))
        os.sync()
        command(["umount", str(mount)])
    else:
        record["data_disk_count"] = len(disks)
except Exception as error:
    record["data_error_type"] = type(error).__name__
record["imds_v1_code"] = request("meta-data/instance-id")[0]
record["invalid_token_code"] = request("meta-data/instance-id", token="invalid")[0]
record["ttl_zero_code"] = request("api/token", "PUT", ttl=0)[0]
record["ttl_too_large_code"] = request("api/token", "PUT", ttl=21601)[0]
code, token = request("api/token", "PUT", ttl=60)
record["token_code"] = code
if code == 200:
    for key in ("instance-id", "ami-id", "instance-type", "local-ipv4", "placement/availability-zone", "reservation-id"):
        code, value = request("meta-data/" + key, token=token)
        record[key] = {"code": code, "value": value}
    code, body = request("dynamic/instance-identity/document", token=token)
    record["identity_code"] = code
    if code == 200:
        identity = json.loads(body)
        record["identity"] = {key: identity.get(key) for key in ("accountId", "architecture", "imageId", "instanceId", "instanceType", "privateIp", "region", "availabilityZone", "pendingTime")}
    code, role = request("meta-data/iam/security-credentials/", token=token)
    record["role_name_code"] = code
    if code == 200:
        code, body = request("meta-data/iam/security-credentials/" + role.strip(), token=token)
        record["credentials_code"] = code
        if code == 200:
            credentials = json.loads(body)
            record["credential_metadata"] = {key: credentials.get(key) for key in ("Code", "Type", "Expiration")}
            del credentials, body
    del token
code, token = request("api/token", "PUT", ttl=1)
if code == 200:
    time.sleep(2)
    record["expired_token_code"] = request("meta-data/instance-id", token=token)[0]
    del token
os.sync()
with open("/dev/console", "w") as console:
    console.write("STACKD_GUEST " + json.dumps(record, separators=(",", ":")) + "\n")
'''


def console_records(text):
    # Native serial output inserts ISO timestamps even inside one guest JSON line.
    # Retain the SDK Output verbatim; remove those transport annotations only here.
    text = re.sub(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]", "", text)
    for match in re.finditer(r"STACKD_GUEST (\{[^\r\n]+\})", text):
        try:
            yield json.loads(match[1])
        except json.JSONDecodeError:
            continue


def userdata():
    encoded = base64.b64encode(GUEST.encode()).decode()
    return """#!/bin/bash
set -eu
umask 077
printf '%s' '""" + encoded + """' | base64 -d > /usr/local/sbin/stackd-guest-probe
chmod 700 /usr/local/sbin/stackd-guest-probe
cat > /etc/systemd/system/stackd-guest-probe.service <<'UNIT'
[Unit]
Description=Bounded owned EC2 guest evidence
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/stackd-guest-probe
TimeoutStartSec=90
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable stackd-guest-probe.service
systemctl start stackd-guest-probe.service
"""


class InstanceCapture(Capture):
    def __init__(self, args):
        self.cleaning = False
        self.deadline = None
        super().__init__(args)
        self.clients["ssm"] = self.session.client("ssm", config=CONFIG)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(prefix="stackd-ec2-instances-" + uuid.uuid4().hex[:12], documentation=DOCS,
                scope="At most two owned t3.nano Linux guests; isolated owned VPC/subnet/SG, gp3 8-GiB roots and 1-GiB data, owned roles/profile/images/snapshots; no existing resource/default changes",
                bounds={"max_simultaneous_instances": 2, "experiment_seconds": args.live_seconds,
                    "cleanup_wait_seconds": 600, "instance_type": "t3.nano", "public_network": False},
                guest_program=GUEST, guest_observations=[], transitions=[])
            self.data.pop("payload", None)
        for name in ("instances", "volumes", "enis", "images", "roles", "profiles"):
            self.data["owned"].setdefault(name, [])
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.args.output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(sanitized(self.data), indent=2) + "\n")
        temporary.replace(self.args.output)

    def own(self, kind, identifier):
        if identifier and identifier not in self.data["owned"].setdefault(kind, []):
            self.data["owned"][kind].append(identifier)

    def check_time(self):
        if not self.cleaning and self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError("Bounded live experiment window expired")

    def observe(self, label, service, method, parameters=None, **kwargs):
        self.check_time()
        result = super().observe(label, service, method, parameters, **kwargs)
        row = self.data["calls"][-1]
        encoded = re.search(r"Encoded authorization failure message: (\S+)", row.get("error", {}).get("Message") or "")
        if encoded:
            try:
                decoded = self.clients["sts"].decode_authorization_message(EncodedMessage=encoded[1])
                row["decoded_authorization"] = safe(json.loads(decoded["DecodedMessage"]))
            except ClientError as error:
                row["decode_error"] = error.response["Error"]["Code"]
        if method == "create_role" and result:
            self.own("roles", result["Role"]["RoleName"])
        if method == "create_instance_profile" and result:
            self.own("profiles", result["InstanceProfile"]["InstanceProfileName"])
        if method in ("create_image", "register_image") and result:
            self.own("images", result["ImageId"])
        if method == "create_volume" and result:
            self.own("volumes", result["VolumeId"])
        if method in ("run_instances", "describe_instances"):
            instances = result.get("Instances", []) + [item for reservation in result.get("Reservations", []) for item in reservation.get("Instances", [])]
            for item in instances:
                self.own("instances", item["InstanceId"])
                for mapping in item.get("BlockDeviceMappings", []):
                    self.own("volumes", mapping.get("Ebs", {}).get("VolumeId"))
                for eni in item.get("NetworkInterfaces", []):
                    self.own("enis", eni["NetworkInterfaceId"])
                self.data.setdefault("transitions", []).append({"call": label, "instance": item["InstanceId"], "state": item["State"], "observed_at": row["finished_at"]})
        if method == "describe_images":
            for image in result.get("Images", []):
                if image["ImageId"] in self.data["owned"]["images"]:
                    for mapping in image.get("BlockDeviceMappings", []):
                        self.own("snapshots", mapping.get("Ebs", {}).get("SnapshotId"))
        self.save()
        return result

    def ec2(self, label, method, parameters=None, **kwargs):
        return self.observe(label, "ec2", method, parameters, **kwargs)

    def tags(self, *kinds):
        return [{"ResourceType": kind, "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]} for kind in kinds]

    def state(self, iid, desired, label, seconds=240):
        deadline = time.monotonic() + seconds
        attempt = 0
        while True:
            output = self.ec2(label + "-" + str(attempt), "describe_instances", {"InstanceIds": [iid]})
            instances = [item for reservation in output.get("Reservations", []) for item in reservation["Instances"]]
            if instances and instances[0]["State"]["Name"] == desired:
                return instances[0]
            if self.cleaning and self.data["calls"][-1]["code"] == "InvalidInstanceID.NotFound" and desired == "terminated":
                return {"InstanceId": iid, "State": {"Name": "terminated"}}
            if time.monotonic() >= deadline:
                raise TimeoutError(label + " state observation expired")
            time.sleep(5)
            attempt += 1

    def console(self, iid, count, label, seconds=240):
        deadline = time.monotonic() + seconds
        attempt = 0
        while True:
            result = self.ec2(label + "-" + str(attempt), "get_console_output", {"InstanceId": iid, "Latest": True})
            text = result.get("Output", "")
            # Botocore decodes GetConsoleOutput's base64 member before returning it.
            for record in console_records(text):
                if not any(row["guest"]["boot_id"] == record["boot_id"] for row in self.data["guest_observations"]):
                    self.data["guest_observations"].append({"instance": iid, "call": label + "-" + str(attempt), "guest": record})
                self.save()
                if record["boot_count"] >= count:
                    return record
            if time.monotonic() >= deadline:
                self.data["gaps"].append(label + ": no matching guest console marker inside bounded wait")
                self.save()
                return None
            time.sleep(10)
            attempt += 1

    def setup(self):
        p = self.data["prefix"]
        for method in ("get_ebs_encryption_by_default", "get_ebs_default_kms_key_id", "get_instance_metadata_defaults"):
            self.ec2("account-before-" + method, method)
        parameter = self.observe("official-amazon-linux-parameter", "ssm", "get_parameter",
            {"Name": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}, required=True)
        image_id = parameter["Parameter"]["Value"]
        image = self.ec2("official-amazon-linux-image", "describe_images", {"ImageIds": [image_id], "Owners": ["amazon"]}, required=True)["Images"][0]
        if image["Architecture"] != "x86_64" or image["RootDeviceType"] != "ebs" or image["VirtualizationType"] != "hvm" or image.get("ProductCodes") or image.get("Platform") == "windows":
            raise RuntimeError("Refusing nonordinary official Linux image")
        if next(mapping["Ebs"]["VolumeSize"] for mapping in image["BlockDeviceMappings"] if mapping["DeviceName"] == image["RootDeviceName"]) > 8:
            raise RuntimeError("Official image root exceeds bounded 8-GiB root")
        self.data["source_image"] = image
        self.ec2("instance-type-hardware", "describe_instance_types", {"InstanceTypes": ["t3.nano"]}, required=True)
        zones = self.ec2("available-zones", "describe_availability_zones", {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(zone["ZoneName"] for zone in zones["AvailabilityZones"] if zone["State"] == "available")
        self.save()
        vpc = self.ec2("owned-vpc", "create_vpc", {"CidrBlock": "10.237.0.0/24", "TagSpecifications": self.tags("vpc")}, required=True)["Vpc"]["VpcId"]
        self.data["owned"]["vpc"] = vpc
        self.save()
        subnet = self.ec2("owned-subnet", "create_subnet", {"VpcId": vpc, "CidrBlock": "10.237.0.0/27", "AvailabilityZone": self.data["zone"], "TagSpecifications": self.tags("subnet")}, required=True)["Subnet"]["SubnetId"]
        self.data["owned"]["subnet"] = subnet
        self.save()
        group = self.ec2("owned-group", "create_security_group", {"VpcId": vpc, "GroupName": p, "Description": "Isolated owned EC2 guest evidence", "TagSpecifications": self.tags("security-group")}, required=True)["GroupId"]
        self.data["owned"]["group"] = group
        self.save()
        self.ec2("owned-group-remove-egress", "revoke_security_group_egress", {"GroupId": group, "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}, required=True)
        for label, method, key in (("routes", "describe_route_tables", "RouteTables"), ("acls", "describe_network_acls", "NetworkAcls"), ("groups", "describe_security_groups", "SecurityGroups")):
            self.ec2("isolated-vpc-" + label, method, {"Filters": [{"Name": "vpc-id", "Values": [vpc]}]}, required=True)
        guest = p + "-guest"
        launcher = p + "-launcher"
        self.observe("owned-guest-role", "iam", "create_role", {"RoleName": guest, "AssumeRolePolicyDocument": json.dumps(policy([
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}])), "Tags": self.tags("role")[0]["Tags"]}, required=True)
        self.observe("owned-profile", "iam", "create_instance_profile", {"InstanceProfileName": guest, "Tags": self.tags("role")[0]["Tags"]}, required=True)
        self.observe("owned-profile-role", "iam", "add_role_to_instance_profile", {"InstanceProfileName": guest, "RoleName": guest}, required=True)
        self.observe("owned-launcher-role", "iam", "create_role", {"RoleName": launcher, "AssumeRolePolicyDocument": json.dumps(policy([
            {"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}])), "Tags": self.tags("role")[0]["Tags"]}, required=True)
        root = "arn:aws:ec2:" + self.args.region + ":" + self.args.account + ":"
        self.resources = {
            "image": "arn:aws:ec2:" + self.args.region + "::image/" + image_id,
            "instance": root + "instance/*", "volume": root + "volume/*", "network-interface": root + "network-interface/*",
            "subnet": root + "subnet/" + subnet, "security-group": root + "security-group/" + group,
        }
        self.tag_statement = allow("ec2:CreateTags", [self.resources[kind] for kind in ("instance", "volume", "network-interface")],
            {"StringEquals": {"ec2:CreateAction": "RunInstances", "aws:RequestTag/suite": p}})
        self.pass_statement = allow("iam:PassRole", "arn:aws:iam::" + self.args.account + ":role/" + guest, {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}})
        self.launch_statements = [allow("ec2:RunInstances", list(self.resources.values())), self.tag_statement, self.pass_statement]
        self.observe("bounded-launcher-policy", "iam", "put_role_policy", {"RoleName": launcher, "PolicyName": "owned-launches", "PolicyDocument": json.dumps(policy(self.launch_statements))}, required=True)
        self.data["launcher_role"] = launcher
        self.data["guest_role"] = guest
        self.data["iam_resources"] = self.resources
        self.save()
        time.sleep(15)

    def assumed(self, label, statements):
        document = policy(statements)
        self.data["sessions"][label] = document
        self.save()
        for attempt in range(10):
            self.check_time()
            try:
                response = self.clients["sts"].assume_role(RoleArn="arn:aws:iam::" + self.args.account + ":role/" + self.data["launcher_role"],
                    RoleSessionName=label, DurationSeconds=900, Policy=json.dumps(document, separators=(",", ":")))
                credentials = response["Credentials"]
                session = boto3.Session(region_name=self.args.region, aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
                self.observe(label + "-identity", "sts", "get_caller_identity", client=session.client("sts", config=CONFIG), caller=label, required=True)
                return session.client("ec2", config=CONFIG)
            except ClientError as error:
                if error.response["Error"]["Code"] != "AccessDenied" or attempt == 9:
                    raise
                time.sleep(3)

    def request(self):
        image = self.data["source_image"]
        return {"ImageId": image["ImageId"], "InstanceType": "t3.nano", "MinCount": 1, "MaxCount": 1,
            "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": self.data["owned"]["subnet"], "Groups": [self.data["owned"]["group"]], "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
            "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"], "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": False}},
                {"DeviceName": "/dev/sdf", "Ebs": {"VolumeSize": 1, "VolumeType": "gp3", "DeleteOnTermination": False}}],
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1, "InstanceMetadataTags": "enabled"},
            "IamInstanceProfile": {"Name": self.data["guest_role"]}, "CreditSpecification": {"CpuCredits": "standard"},
            "TagSpecifications": self.tags("instance", "volume", "network-interface"), "UserData": userdata(),
            "ClientToken": self.data["prefix"] + "-primary"}

    def launch(self, label, request, **kwargs):
        if not request.get("DryRun"):
            if request.get("InstanceType") != "t3.nano" or request.get("MinCount") != 1 or request.get("MaxCount") != 1:
                raise RuntimeError("Refusing nonbounded actual launch")
            live = self.ec2(label + "-owned-live-guard", "describe_instances", {"Filters": [
                {"Name": "tag:suite", "Values": [self.data["prefix"]]}, {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}]}, required=True)
            count = sum(len(row["Instances"]) for row in live.get("Reservations", []))
            if count >= 2:
                raise RuntimeError("Two-instance live ownership limit reached")
        self.data.setdefault("launch_intents", []).append({"label": label, "client_token": request.get("ClientToken"), "dry_run": request.get("DryRun", False)})
        self.save()
        return self.ec2(label, "run_instances", request, **kwargs)

    def iam_admission(self, request):
        self.launch("run-owner-dry", dict(request, DryRun=True))
        for label, extra in (("bad-image", {"ImageId": "bad"}), ("missing-image", {"ImageId": ""}),
            ("min-greater-max", {"MinCount": 2}), ("zero-min", {"MinCount": 0}), ("zero-max", {"MaxCount": 0}),
            ("token-too-long", {"ClientToken": "x" * 65}), ("bad-metadata-token-option", {"MetadataOptions": {"HttpTokens": "bad"}}),
            ("subnet-interface-conflict", {"SubnetId": self.data["owned"]["subnet"]})):
            self.launch("admission-dry-" + label, dict(request, **extra, DryRun=True))
        for missing in ("image", "instance", "volume", "network-interface", "subnet", "security-group"):
            statements = [allow("ec2:RunInstances", [arn for kind, arn in self.resources.items() if kind != missing]), self.tag_statement, self.pass_statement]
            client = self.assumed("missing-run-" + missing, statements)
            self.launch("iam-missing-run-" + missing, dict(request, DryRun=True), client=client, caller="missing-run-" + missing)
        for action in ("ec2:CreateVolume", "ec2:CreateNetworkInterface", "ec2:CreateTags", "iam:PassRole"):
            label = "deny-" + action.split(":")[1]
            statements = self.launch_statements + [{"Effect": "Deny", "Action": action, "Resource": "*"}]
            client = self.assumed(label, statements)
            self.launch("iam-" + label + "-dry", dict(request, DryRun=True), client=client, caller=label)
            if action in ("ec2:CreateTags", "iam:PassRole"):
                output = self.launch("iam-" + label + "-actual", dict(request, ClientToken=self.data["prefix"] + "-" + label), client=client, caller=label)
                if output.get("Instances"):
                    iid = output["Instances"][0]["InstanceId"]
                    self.ec2("unexpected-iam-success-terminate", "terminate_instances", {"InstanceIds": [iid]}, required=True)
                    self.state(iid, "terminated", "unexpected-iam-success-terminal")
        for label, condition in (("type-match", {"StringEquals": {"ec2:InstanceType": "t3.nano"}}),
            ("type-mismatch", {"StringEquals": {"ec2:InstanceType": "t3.micro"}}),
            ("metadata-required", {"StringEquals": {"ec2:MetadataHttpTokens": "required"}})):
            statements = [allow("ec2:RunInstances", [arn for kind, arn in self.resources.items() if kind != "instance"]),
                allow("ec2:RunInstances", self.resources["instance"], condition), self.tag_statement, self.pass_statement]
            client = self.assumed(label, statements)
            self.launch("iam-condition-" + label, dict(request, DryRun=True), client=client, caller=label)
        statements = self.launch_statements + [{"Effect": "Deny", "Action": ["ec2:CreateVolume", "ec2:CreateNetworkInterface"], "Resource": "*"}]
        return self.assumed("deny-internal-create-actions", statements)

    def projections(self, iid, phase):
        self.ec2(phase + "-status", "describe_instance_status", {"InstanceIds": [iid], "IncludeAllInstances": True})
        self.ec2(phase + "-status-default", "describe_instance_status", {"InstanceIds": [iid]})
        for attribute in ("instanceType", "imageId", "rootDeviceName", "blockDeviceMapping", "groupSet", "sourceDestCheck", "disableApiTermination", "instanceInitiatedShutdownBehavior", "userData"):
            self.ec2(phase + "-attribute-" + attribute, "describe_instance_attribute", {"InstanceId": iid, "Attribute": attribute})
        self.ec2(phase + "-volumes", "describe_volumes", {"Filters": [{"Name": "attachment.instance-id", "Values": [iid]}]})
        self.ec2(phase + "-enis", "describe_network_interfaces", {"Filters": [{"Name": "attachment.instance-id", "Values": [iid]}]})

    def images(self, iid):
        p = self.data["prefix"]
        image_id = self.ec2("create-image-stopped", "create_image", {"InstanceId": iid, "Name": p,
            "NoReboot": True, "TagSpecifications": self.tags("image", "snapshot")}, required=True)["ImageId"]
        deadline = time.monotonic() + 360
        attempt = 0
        image = None
        while time.monotonic() < deadline:
            result = self.ec2("created-image-state-" + str(attempt), "describe_images", {"ImageIds": [image_id]})
            if result.get("Images"):
                image = result["Images"][0]
                if image["State"] == "available":
                    break
                if image["State"] in ("failed", "error"):
                    raise RuntimeError("Owned image failed creation")
            time.sleep(10)
            attempt += 1
        if not image or image["State"] != "available":
            self.data["gaps"].append("CreateImage did not become available within 360 seconds; registered-image boot unobserved")
            self.save()
            return None
        for attribute in ("blockDeviceMapping", "launchPermission", "description", "sriovNetSupport", "bootMode", "imdsSupport"):
            self.ec2("created-image-attribute-" + attribute, "describe_image_attribute", {"ImageId": image_id, "Attribute": attribute})
        self.ec2("created-image-snapshots", "describe_snapshots", {"SnapshotIds": self.data["owned"]["snapshots"]}, required=True)
        self.ec2("snapshot-delete-while-registered", "delete_snapshot", {"SnapshotId": self.data["owned"]["snapshots"][0]})
        mappings = [{"DeviceName": mapping["DeviceName"], "Ebs": {key: value for key, value in mapping["Ebs"].items()
            if key in ("SnapshotId", "VolumeSize", "VolumeType", "DeleteOnTermination")}} for mapping in image["BlockDeviceMappings"] if "Ebs" in mapping]
        request = {"Name": p + "-registered", "Architecture": "x86_64", "RootDeviceName": image["RootDeviceName"],
            "VirtualizationType": "hvm", "EnaSupport": True, "ImdsSupport": "v2.0", "BlockDeviceMappings": mappings, "TagSpecifications": self.tags("image")}
        if image.get("BootMode"):
            request["BootMode"] = image["BootMode"]
        registered = self.ec2("register-owned-image", "register_image", request, required=True)["ImageId"]
        self.ec2("registered-image", "describe_images", {"ImageIds": [registered]}, required=True)
        self.ec2("deregister-created-image", "deregister_image", {"ImageId": image_id}, required=True)
        self.ec2("created-image-after-deregister", "describe_images", {"ImageIds": [image_id]})
        self.ec2("snapshots-after-deregister", "describe_snapshots", {"SnapshotIds": self.data["owned"]["snapshots"]}, required=True)
        self.ec2("snapshot-delete-still-registered", "delete_snapshot", {"SnapshotId": self.data["owned"]["snapshots"][0]})
        return registered

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        self.data["experiment_deadline"] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.args.live_seconds)).isoformat()
        self.save()
        signal.alarm(self.args.live_seconds)
        self.setup()
        request = self.request()
        launcher = self.iam_admission(request)
        result = self.launch("run-denied-internal-create-actions", request, client=launcher, caller="deny-internal-create-actions", required=True)
        iid = result["Instances"][0]["InstanceId"]
        self.data["primary_instance"] = iid
        self.save()
        self.launch("run-token-identical-replay", request, client=launcher, caller="deny-internal-create-actions")
        changed = copy.deepcopy(request)
        changed["MetadataOptions"]["HttpPutResponseHopLimit"] = 2
        self.launch("run-token-changed-metadata", changed)
        running = self.state(iid, "running", "primary-running")
        self.data["primary_running"] = running
        self.save()
        self.projections(iid, "running")
        first = self.console(iid, 1, "first-guest")
        for method in ("stop_instances", "start_instances", "reboot_instances", "terminate_instances"):
            self.ec2("dry-" + method, method, {"InstanceIds": [iid], "DryRun": True})
        self.ec2("start-already-running", "start_instances", {"InstanceIds": [iid]})
        self.ec2("stop-primary", "stop_instances", {"InstanceIds": [iid]}, required=True)
        stopped = self.state(iid, "stopped", "primary-stopped")
        self.projections(iid, "stopped")
        self.ec2("stop-already-stopped", "stop_instances", {"InstanceIds": [iid]})
        self.ec2("reboot-stopped", "reboot_instances", {"InstanceIds": [iid]})
        self.ec2("start-primary", "start_instances", {"InstanceIds": [iid]}, required=True)
        restarted = self.state(iid, "running", "primary-restarted")
        second = self.console(iid, 2, "restart-guest")
        self.ec2("reboot-primary", "reboot_instances", {"InstanceIds": [iid]}, required=True)
        self.ec2("immediate-reboot-state", "describe_instances", {"InstanceIds": [iid]})
        third = self.console(iid, 3, "reboot-guest")
        self.ec2("post-reboot-status", "describe_instance_status", {"InstanceIds": [iid], "IncludeAllInstances": True})
        self.data["retention_observations"] = {"running": running["BlockDeviceMappings"], "stopped": stopped["BlockDeviceMappings"],
            "restarted": restarted["BlockDeviceMappings"], "guest_boot_counts": [row["boot_count"] if row else None for row in (first, second, third)]}
        self.save()
        self.ec2("stop-for-image", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "stopped", "image-source-stopped")
        registered = self.images(iid)
        self.ec2("terminate-primary", "terminate_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "terminated", "primary-terminated")
        self.ec2("terminate-again", "terminate_instances", {"InstanceIds": [iid]})
        for method in ("start_instances", "stop_instances", "reboot_instances"):
            self.ec2("terminated-" + method, method, {"InstanceIds": [iid]})
        self.ec2("retained-volumes-after-termination", "describe_volumes", {"VolumeIds": self.data["owned"]["volumes"]}, required=True)
        if registered:
            child_request = copy.deepcopy(request)
            child_request.update(ImageId=registered, ClientToken=self.data["prefix"] + "-derived")
            for mapping in child_request["BlockDeviceMappings"]:
                mapping["Ebs"]["DeleteOnTermination"] = True
            child = self.launch("run-registered-owned-image", child_request, required=True)["Instances"][0]["InstanceId"]
            self.data["derived_instance"] = child
            self.save()
            self.state(child, "running", "derived-running")
            self.console(child, 4, "derived-image-guest")
            self.projections(child, "derived")
            self.ec2("terminate-derived", "terminate_instances", {"InstanceIds": [child]}, required=True)
            self.state(child, "terminated", "derived-terminated")
        self.data["gaps"].extend([
            "No universal HVM/AMI/Firecracker compatibility inference: this ordinary official x86_64 Amazon Linux image boots on native t3 Nitro hardware; firmware, ENA/NVMe and kernel/root-filesystem drivers remain explicit runtime constraints.",
            "No hibernation, Spot, Windows, licensing, public networking, arbitrary account catalogs, IMDS credential-use or key injection capture.",
            "Data disk is attached at launch and exercised by the guest; live hotplug and detach are unobserved.",
            "Polling observes state projections, not every internal transition or an AWS latency guarantee; no EventBridge subscription was created.",
        ])
        self.data["capture_complete_at"] = now()
        self.save()

    def discover_owned(self):
        # Capture persists the SDK outcome before this subclass updates its ledger.
        # Recover IAM IDs from that outcome if interruption fell between those saves.
        for row in self.data["calls"]:
            output = row.get("output", {})
            if row["operation"] == "CreateRole" and output.get("Role"):
                self.own("roles", output["Role"]["RoleName"])
            if row["operation"] == "CreateInstanceProfile" and output.get("InstanceProfile"):
                self.own("profiles", output["InstanceProfile"]["InstanceProfileName"])
        filters = [{"Name": "tag:suite", "Values": [self.data["prefix"]]}]
        self.ec2("cleanup-discover-instances", "describe_instances", {"Filters": filters})
        for method, key, idkey, owned in (("describe_volumes", "Volumes", "VolumeId", "volumes"),
            ("describe_network_interfaces", "NetworkInterfaces", "NetworkInterfaceId", "enis"),
            ("describe_snapshots", "Snapshots", "SnapshotId", "snapshots"), ("describe_images", "Images", "ImageId", "images")):
            request = {"Filters": filters}
            if method == "describe_images": request["Owners"] = ["self"]
            if method == "describe_snapshots": request["OwnerIds"] = [self.args.account]
            result = self.ec2("cleanup-discover-" + owned, method, request)
            for row in result.get(key, []):
                self.own(owned, row[idkey])
        for method, key, idkey, owned in (("describe_vpcs", "Vpcs", "VpcId", "vpc"),
            ("describe_subnets", "Subnets", "SubnetId", "subnet"), ("describe_security_groups", "SecurityGroups", "GroupId", "group")):
            result = self.ec2("cleanup-discover-" + owned, method, {"Filters": filters})
            for row in result.get(key, []):
                self.data["owned"][owned] = row[idkey]
        self.save()

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        self.data["cleanup"]["started_at"] = now()
        self.save()
        failures = []
        self.discover_owned()
        owned = self.data["owned"]
        for iid in owned["instances"]:
            self.ec2("cleanup-terminate-" + iid, "terminate_instances", {"InstanceIds": [iid]})
        for iid in owned["instances"]:
            try:
                self.state(iid, "terminated", "cleanup-terminal-" + iid, seconds=300)
            except Exception as error:
                failures.append({"instance": iid, "error": type(error).__name__})
        for image in owned["images"]:
            self.ec2("cleanup-image-snapshots-" + image, "describe_images", {"ImageIds": [image]})
            self.ec2("cleanup-deregister-" + image, "deregister_image", {"ImageId": image})
        deadline = time.monotonic() + 240
        pending = {"volumes": set(owned["volumes"]), "enis": set(owned["enis"]), "snapshots": set(owned["snapshots"])}
        absent = self.data["cleanup"].setdefault("absent", {})
        attempt = 0
        while any(pending.values()):
            for kind, delete, describe, singular, plural, key, absent_code in (
                ("volumes", "delete_volume", "describe_volumes", "VolumeId", "VolumeIds", "Volumes", "InvalidVolume.NotFound"),
                ("enis", "delete_network_interface", "describe_network_interfaces", "NetworkInterfaceId", "NetworkInterfaceIds", "NetworkInterfaces", "InvalidNetworkInterfaceID.NotFound"),
                ("snapshots", "delete_snapshot", "describe_snapshots", "SnapshotId", "SnapshotIds", "Snapshots", "InvalidSnapshot.NotFound")):
                for identifier in list(pending[kind]):
                    self.ec2("cleanup-delete-" + identifier + "-" + str(attempt), delete, {singular: identifier})
                    result = self.ec2("cleanup-absence-" + identifier + "-" + str(attempt), describe, {plural: [identifier]})
                    code = self.data["calls"][-1]["code"]
                    if code == absent_code or (code == "Success" and not result.get(key)):
                        pending[kind].remove(identifier)
                        absent.setdefault(kind, [])
                        if identifier not in absent[kind]: absent[kind].append(identifier)
            if time.monotonic() >= deadline:
                break
            if any(pending.values()):
                time.sleep(5)
            attempt += 1
        for kind, values in pending.items():
            failures.extend({kind: identifier} for identifier in values)
        for image in owned["images"]:
            result = self.ec2("cleanup-image-absence-" + image, "describe_images", {"ImageIds": [image]})
            if self.data["calls"][-1]["code"] in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable") or (self.data["calls"][-1]["code"] == "Success" and not result.get("Images")):
                absent.setdefault("images", []).append(image)
            else:
                failures.append({"image": image})
        for profile in owned["profiles"]:
            self.observe("cleanup-profile-remove-role", "iam", "remove_role_from_instance_profile", {"InstanceProfileName": profile, "RoleName": profile})
            self.observe("cleanup-profile-delete", "iam", "delete_instance_profile", {"InstanceProfileName": profile})
            self.observe("cleanup-profile-absence", "iam", "get_instance_profile", {"InstanceProfileName": profile})
            if self.data["calls"][-1]["code"] != "NoSuchEntity": failures.append({"profile": profile})
            else: absent.setdefault("profiles", []).append(profile)
        for role in owned["roles"]:
            if role.endswith("-launcher"):
                self.observe("cleanup-launcher-policy", "iam", "delete_role_policy", {"RoleName": role, "PolicyName": "owned-launches"})
            self.observe("cleanup-role-delete", "iam", "delete_role", {"RoleName": role})
            self.observe("cleanup-role-absence", "iam", "get_role", {"RoleName": role})
            if self.data["calls"][-1]["code"] != "NoSuchEntity": failures.append({"role": role})
            else: absent.setdefault("roles", []).append(role)
        for kind, delete, describe, singular, plural, code in (
            ("group", "delete_security_group", "describe_security_groups", "GroupId", "GroupIds", "InvalidGroup.NotFound"),
            ("subnet", "delete_subnet", "describe_subnets", "SubnetId", "SubnetIds", "InvalidSubnetID.NotFound"),
            ("vpc", "delete_vpc", "describe_vpcs", "VpcId", "VpcIds", "InvalidVpcID.NotFound")):
            if owned.get(kind):
                self.ec2("cleanup-delete-" + kind, delete, {singular: owned[kind]})
                self.ec2("cleanup-absence-" + kind, describe, {plural: [owned[kind]]})
                if self.data["calls"][-1]["code"] != code: failures.append({kind: owned[kind]})
                else: absent[kind] = owned[kind]
        if owned.get("vpc"):
            for method in ("describe_route_tables", "describe_network_acls", "describe_security_groups", "describe_network_interfaces", "describe_subnets"):
                self.ec2("cleanup-vpc-dependents-" + method, method, {"Filters": [{"Name": "vpc-id", "Values": [owned["vpc"]]}]})
        active = self.ec2("cleanup-no-nonterminal-instances", "describe_instances", {"Filters": [
            {"Name": "tag:suite", "Values": [self.data["prefix"]]}, {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}]})
        if self.data["calls"][-1]["code"] != "Success" or active.get("Reservations"):
            failures.append({"instances": "nonterminal absence unverified"})
        self.data["cleanup"]["instance_boundary"] = "Terminated tombstones remain DescribeInstances-visible temporarily; all owned instances must be terminated and no nonterminal owned instance may remain. Stopped is not cleanup."
        for method in ("get_ebs_encryption_by_default", "get_ebs_default_kms_key_id", "get_instance_metadata_defaults"):
            self.ec2("account-after-" + method, method)
        self.data["cleanup"].update(failures=failures, finished_at=now(), complete=not failures)
        self.save()
        if failures:
            raise RuntimeError("Owned cleanup incomplete; use --cleanup-only with the same output")

    def handoff(self):
        calls = self.data["calls"]
        guests = []
        seen = set()
        for row in calls:
            if row["operation"] != "GetConsoleOutput":
                continue
            for record in console_records(row.get("output", {}).get("Output", "")):
                key = (record["boot_id"], record["boot_count"], record.get("observation_id"))
                if key not in seen:
                    seen.add(key)
                    guests.append({"instance": row["input"]["InstanceId"], "call": row["label"], "guest": record})
        self.data["guest_observations"] = guests
        self.data["guest_decoding"] = {
            "boundary": "SDK console Output remains verbatim. Derived JSON removes native bracketed ISO timestamps inserted inside guest console lines.",
            "counter_boundary": "The disk counter counts probe service invocations. observation_id distinguishes repeated samples, not kernel boots. Historical probes may suffix boot_id with an iteration; only the underlying kernel boot UUID establishes a separate boot."}
        self.save()
        summary = {
            "source_fixture": str(self.args.output), "account": self.data["account"], "region": self.data["region"],
            "identity": self.data["identity"], "documentation": list(dict.fromkeys(self.data["documentation"] + DOCS)),
            "owned": self.data["owned"], "cleanup": self.data["cleanup"], "gaps": self.data["gaps"],
            "source_image": {key: self.data.get("source_image", {}).get(key) for key in
                ("ImageId", "OwnerId", "Name", "Architecture", "VirtualizationType", "RootDeviceType", "RootDeviceName", "BootMode", "EnaSupport", "ImdsSupport", "BlockDeviceMappings")},
            "iam_resources": self.data.get("iam_resources", {}), "launch_and_iam": [],
            "commands": [], "guest_observations": self.data.get("guest_observations", []),
            "retention_observations": self.data.get("retention_observations"),
            "guest_decoding": self.data["guest_decoding"],
            "image_lineage": {}, "volume_lineage": {}, "snapshot_lineage": {},
            "image_and_snapshot_calls": [], "cloudtrail": [],
            "owner_permission_boundaries": [{key: row.get(key) for key in ("label", "code", "error")}
                for row in calls if row["caller"] == "owner" and row["code"] in ("AuthFailure", "AccessDenied", "AccessDeniedException")],
            "cloudtrail_boundary": {
                "missing_management_calls": self.data.get("cloudtrail", {}).get("missing_management_calls", []),
                "meaning": "Positive delivered records only; missing eventual records do not prove absence or exclude an internal service action."},
            "causality_boundary": "SDK request IDs join delivered CloudTrail events. Poll timestamps bound observed state transitions, not service latency guarantees or every internal transition. No native EventBridge subscription.",
            "runtime_boundary": "Native t3.nano boots an ordinary official x86_64 HVM Amazon Linux EBS image using its actual firmware/kernel/root disk and Nitro devices. This is not proof that Firecracker direct-kernel boot supports this AMI, its firmware, ENA or NVMe devices; adapter capabilities must be explicit.",
        }
        if any(row["guest"].get("ttl_zero_code") == 200 for row in guests):
            summary["imds_ttl_boundary"] = "Native TTL=0 token issuance returned HTTP 200 despite the documented minimum of 1 second. The zero-TTL token was never used and its usable lifetime is unobserved; do not infer expiration behavior from issuance."
        for row in calls:
            if row["operation"] == "RunInstances":
                entry = {key: row.get(key) for key in ("label", "caller", "code", "request_id")}
                output = row.get("output", {})
                if output:
                    entry["reservation"] = {key: output.get(key) for key in ("ReservationId", "OwnerId", "Groups")}
                    entry["instances"] = [{key: instance.get(key) for key in
                        ("InstanceId", "ImageId", "State", "ClientToken", "RootDeviceName", "BlockDeviceMappings", "MetadataOptions")}
                        for instance in output.get("Instances", [])]
                context = row.get("decoded_authorization", {}).get("context")
                if context:
                    entry["authorization_context"] = {
                        "action": context.get("action"), "resource": context.get("resource"),
                        "conditions": {item["key"]: [value["value"] for value in item["values"]["items"]]
                            for item in context.get("conditions", {}).get("items", [])}}
                summary["launch_and_iam"].append(entry)
            if row["operation"] in ("StopInstances", "StartInstances", "RebootInstances", "TerminateInstances") and not row["input"].get("DryRun") and not row["label"].startswith("cleanup"):
                summary["commands"].append({key: row.get(key) for key in ("label", "operation", "code", "output", "error", "request_id")})
            if row["operation"] in ("CreateImage", "RegisterImage", "DeregisterImage", "DeleteSnapshot") and not row["label"].startswith("cleanup"):
                summary["image_and_snapshot_calls"].append({key: row.get(key) for key in ("label", "operation", "code", "output", "error", "request_id")})
            for result_key, id_key, target, fields in (
                ("Images", "ImageId", "image_lineage", ("ImageId", "State", "SourceInstanceId", "RootDeviceName", "Architecture", "BootMode", "VirtualizationType", "ImdsSupport", "BlockDeviceMappings")),
                ("Volumes", "VolumeId", "volume_lineage", ("VolumeId", "SnapshotId", "Size", "VolumeType", "Encrypted", "Attachments")),
                ("Snapshots", "SnapshotId", "snapshot_lineage", ("SnapshotId", "VolumeId", "VolumeSize", "State", "Description"))):
                for item in row.get("output", {}).get(result_key, []):
                    if item[id_key] not in summary[target]:
                        summary[target][item[id_key]] = {"call": row["label"], **{key: item.get(key) for key in fields}}
        summary["observed_states"] = sorted({(row["state"]["Code"], row["state"]["Name"]) for row in self.data.get("transitions", [])})
        for row in self.data.get("cloudtrail", {}).get("events", []):
            event = row["event"]
            summary["cloudtrail"].append({"call_label": row.get("call_label"), **{key: event.get(key) for key in ("eventID", "eventName", "eventTime", "requestID", "errorCode")}})
        if self.data.get("failure"):
            summary["failure"] = self.data["failure"]
        path = self.args.output.with_name(self.args.output.stem + "_handoff.json")
        path.write_text(json.dumps(sanitized(summary), indent=2) + "\n")


def interrupt(signum, frame):
    raise TimeoutError("Probe deadline or signal " + str(signum) + "; entering owned cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/instances_lifecycle.json"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--audit-only", action="store_true", help="Read-only scoped CloudTrail harvest after cleanup")
    parser.add_argument("--live-seconds", type=int, default=1500, choices=range(300, 1501), metavar="300..1500")
    args = parser.parse_args()
    capture = InstanceCapture(args)
    if args.audit_only:
        if not capture.data["cleanup"].get("complete"):
            raise RuntimeError("Complete owned cleanup before read-only audit harvest")
        capture.audit()
        capture.handoff()
        return
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only:
            capture.run()
    except Exception as error:
        capture.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        capture.save()
        raise
    finally:
        capture.cleanup()
        capture.handoff()


if __name__ == "__main__":
    main()
