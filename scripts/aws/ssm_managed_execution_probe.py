#!/usr/bin/env python3
"""Capture Documents and real official-agent Run Command, never Parameter Store writes.

Native: one owned t3.micro, 8-GiB gp3 root, one public IPv4, isolated VPC,
role/profile, S3 bucket and log group in the requested account/us-east-1. An official
published Amazon Linux AMI is used unchanged; user data installs the current
regional AWS SSM Agent package. No SSH or standing host-management changes.

Local: --endpoint URL --instance-id ID uses only explicit synthetic credentials
and an already provisioned official-agent guest; it never creates/deletes that
instance or IAM/network/output resources. Native and local evidence are separate.

The atomic output is the ownership ledger. --cleanup-only --output SAME resumes
cleanup. SIGINT/SIGTERM and the bounded live alarm enter finally cleanup. Command
history, terminated EC2 tombstones and stale fleet records are not deletable
resources and are reported, not claimed erased. Provider errors/scripts are kept;
only actual credential fields are redacted. No test suite is part of this probe.
"""
import argparse
import base64
import datetime
import json
from pathlib import Path
import re
import signal
import time
import uuid
from urllib.parse import urlsplit
from urllib.request import urlopen

import boto3
from botocore.exceptions import ClientError

from ebs_encryption_probe import CONFIG, allow, now, policy

REGION = "us-east-1"
UPSTREAM = "c8fa314de8050cd5dcb3740a29c3ce769f533dcd"
REFERENCES = [
    "https://github.com/aws/amazon-ssm-agent/tree/" + UPSTREAM,
    "https://docs.aws.amazon.com/systems-manager/latest/userguide/monitor-commands.html",
    "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html",
    "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-rc-setting-up-cwlogs.html",
] + ["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_" + name + ".html" for name in (
    "CreateDocument", "UpdateDocument", "UpdateDocumentDefaultVersion", "GetDocument",
    "DescribeDocument", "ListDocuments", "ListDocumentVersions", "DeleteDocument",
    "SendCommand", "GetCommandInvocation", "ListCommands", "ListCommandInvocations",
    "CancelCommand", "DescribeInstanceInformation")]
TERMINAL = {"Success", "Failed", "Cancelled", "TimedOut", "Undeliverable", "Terminated"}
SETTING = "/ssm/managed-instance/default-ec2-instance-management-role"
USERDATA = """#!/bin/bash
set -eu
exec > /dev/console 2>&1
trap 'printf "STACKD_BOOTSTRAP_EXIT=%s\\n" "$?"' EXIT
# A controller failure still stops the sole guest within the authorized hour.
shutdown -h +50
systemctl stop amazon-ssm-agent || true
curl --fail --retry 2 --max-time 90 -o /tmp/amazon-ssm-agent.rpm https://s3.us-east-1.amazonaws.com/amazon-ssm-us-east-1/latest/linux_amd64/amazon-ssm-agent.rpm
rpm -Uvh --replacepkgs /tmp/amazon-ssm-agent.rpm
systemctl enable --now amazon-ssm-agent
amazon-ssm-agent -version > /dev/console
"""


def serial(value):
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower() in ("accesskeyid", "secretaccesskey", "sessiontoken", "tokenvalue") else serial(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [serial(child) for child in value]
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode()}
    return value


def interrupt(signum, unused):
    raise TimeoutError("Capture interrupted by signal " + str(signum))


def document(version="one", **extra):
    content = {"schemaVersion": "2.2", "description": "Owned native evidence " + version,
        "parameters": {
            "commands": {"type": "StringList", "description": "Verbatim shell lines", "default": ["printf 'version-" + version + "\\n'"]},
            "executionTimeout": {"type": "String", "default": "10", "allowedPattern": "^[0-9]+$"}},
        "mainSteps": [{"action": "aws:runShellScript", "name": "runShell",
            "inputs": {"runCommand": "{{ commands }}", "timeoutSeconds": "{{ executionTimeout }}"}}]}
    content.update(extra)
    return json.dumps(content, indent=2)


class Capture:
    def __init__(self, args):
        self.args = args
        self.cleaning = False
        self.deadline = time.monotonic() + args.live_seconds
        self.cleanup_deadline = None
        if args.endpoint:
            endpoint = urlsplit(args.endpoint)
            if endpoint.scheme not in ("http", "https") or not endpoint.hostname or endpoint.hostname.endswith("amazonaws.com"):
                raise ValueError("Local endpoint must be an explicit non-AWS HTTP(S) URL")
            self.session = boto3.Session(region_name=REGION, aws_access_key_id="test", aws_secret_access_key="test")
        else:
            self.session = boto3.Session(region_name=REGION)
        self.clients = {name: self.session.client(name, config=CONFIG, **({"endpoint_url": args.endpoint} if args.endpoint else {})) for name in ("ssm", "ec2", "iam", "sts", "s3", "logs")}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != self.args.account:
            raise RuntimeError("Refusing native writes outside authorized account")
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != identity["Account"] or self.data["endpoint"] != args.endpoint or self.data["region"] != REGION:
                raise RuntimeError("Cleanup ownership scope mismatch")
            self.data.setdefault("cleanup_identities", []).append(serial(identity))
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite existing evidence; choose a new path")
            if args.endpoint and args.output.name.startswith("managed_execution_native"):
                raise RuntimeError("Local capture must not replace native evidence")
            self.data = {"account": identity["Account"], "region": REGION, "endpoint": args.endpoint,
                "source": "local synthetic credentials" if args.endpoint else "native AWS",
                "identity": serial(identity), "captured_at": now(),
                "prefix": "stackd-ssm-managed-" + uuid.uuid4().hex[:12],
                "references": REFERENCES, "upstream_revision": UPSTREAM, "sdk": {"boto3": boto3.__version__},
                "bounds": {"max_instances": 1, "instance_type": "t3.micro", "root_gib": 8,
                    "live_seconds": args.live_seconds, "cleanup_seconds": 600, "public_ipv4": 1,
                    "standing_resources_mutated": False, "host_management_setting_mutated": False},
                "owned": {"documents": [], "commands": [], "instances": [], "volumes": [], "enis": []},
                "calls": [], "cleanup": {}, "nonobservations": [], "guest_userdata": USERDATA}
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.args.output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(serial(self.data), indent=2) + "\n")
        temporary.replace(self.args.output)

    def own(self, key, identifier):
        values = self.data["owned"].setdefault(key, [])
        if identifier not in values:
            values.append(identifier)

    def call(self, label, service, method, parameters=None, *, required=False, client=None, caller="owner", throttle_attempt=0):
        if not self.cleaning and time.monotonic() >= self.deadline:
            raise TimeoutError("Bounded capture window expired")
        if self.cleaning and self.cleanup_deadline is not None and time.monotonic() >= self.cleanup_deadline:
            raise TimeoutError("Bounded cleanup window expired; resume with --cleanup-only")
        client = client or self.clients[service]
        row = {"label": label, "service": service, "operation": client.meta.method_to_api_mapping[method],
            "input": serial(parameters or {}), "caller": caller, "started_at": now()}
        try:
            output = getattr(client, method)(**(parameters or {}))
            metadata = output.pop("ResponseMetadata", {})
            if "Body" in output:
                stream = output["Body"]
                output["Body"] = stream.read().decode("utf-8", errors="replace")
                stream.close()
            row.update(code="Success", output=serial(output))
            owned = self.data["owned"]
            for operation, key, path in (
                ("create_vpc", "vpc", ("Vpc", "VpcId")),
                ("create_subnet", "subnet", ("Subnet", "SubnetId")),
                ("create_security_group", "group", ("GroupId",)),
                ("create_internet_gateway", "gateway", ("InternetGateway", "InternetGatewayId")),
                ("create_route_table", "routes", ("RouteTable", "RouteTableId"))):
                if method == operation:
                    value = output
                    for part in path:
                        value = value[part]
                    owned[key] = value
            if method == "associate_route_table":
                owned["route_association"] = output["AssociationId"]
            if method == "send_command":
                self.own("commands", output["Command"]["CommandId"])
            if method in ("run_instances", "describe_instances"):
                instances = output.get("Instances", []) + [i for r in output.get("Reservations", []) for i in r.get("Instances", [])]
                for instance in instances:
                    self.own("instances", instance["InstanceId"])
                    for item in instance.get("BlockDeviceMappings", []):
                        if item.get("Ebs", {}).get("VolumeId"):
                            self.own("volumes", item["Ebs"]["VolumeId"])
                    for item in instance.get("NetworkInterfaces", []):
                        self.own("enis", item["NetworkInterfaceId"])
        except ClientError as error:
            output = {}
            metadata = error.response.get("ResponseMetadata", {})
            row.update(code=error.response["Error"]["Code"], error=serial({k: v for k, v in error.response.items() if k != "ResponseMetadata"}))
        except Exception as error:
            row.update(code=type(error).__name__, transport_error=str(error), finished_at=now())
            self.data["calls"].append(row)
            self.save()
            raise
        row.update(request_id=metadata.get("RequestId"), http_status=metadata.get("HTTPStatusCode"), finished_at=now())
        self.data["calls"].append(row)
        self.save()
        print(label + ": " + row["code"], flush=True)
        # Native document writes have a low rate quota. Preserve each actual
        # rejection and request ID, then retry only an explicit provider throttle.
        if row["code"] in ("ThrottlingException", "Throttling", "TooManyRequestsException") and throttle_attempt < 3:
            time.sleep(2 ** (throttle_attempt + 1))
            return self.call(label + "-throttle-retry", service, method, parameters,
                required=required, client=client, caller=caller, throttle_attempt=throttle_attempt + 1)
        if required and row["code"] != "Success":
            raise RuntimeError(label + ": " + row["code"])
        return output

    def ssm(self, label, method, parameters=None, **kwargs):
        return self.call(label, "ssm", method, parameters, **kwargs)

    def poll(self, label, service, method, parameters, predicate, seconds=120, interval=3):
        deadline = time.monotonic() + seconds
        attempt = 0
        while True:
            output = self.call(label + "-" + str(attempt), service, method, parameters)
            if predicate(output):
                return output
            if time.monotonic() >= deadline:
                self.data["nonobservations"].append({"label": label, "window_seconds": seconds, "last_code": self.data["calls"][-1]["code"]})
                self.save()
                return None
            time.sleep(interval)
            attempt += 1

    def control_edges(self):
        iid = "i-00000000000000000"
        cid = "00000000-0000-4000-8000-000000000000"
        filters = [{"Key": "InstanceIds", "Values": [iid]}]
        for label, method, request in (
            ("fleet-missing-id", "describe_instance_information", {"Filters": filters}),
            ("fleet-invalid-key", "describe_instance_information", {"Filters": [{"Key": "UnknownKey", "Values": [iid]}]}),
            ("fleet-empty-values", "describe_instance_information", {"Filters": [{"Key": "InstanceIds", "Values": []}]}),
            ("fleet-mixed-filters", "describe_instance_information", {"Filters": filters, "InstanceInformationFilterList": [{"key": "InstanceIds", "valueSet": [iid]}]}),
            ("fleet-tag-and-id", "describe_instance_information", {"Filters": filters + [{"Key": "tag:suite", "Values": [self.data["prefix"]]}]}),
            ("fleet-page-too-small", "describe_instance_information", {"Filters": filters, "MaxResults": 4}),
            ("fleet-invalid-next-token", "describe_instance_information", {"Filters": filters, "NextToken": "not-a-page-token"}),
            ("connection-missing-id", "get_connection_status", {"Target": iid}),
            ("cancel-missing-command", "cancel_command", {"CommandId": cid}),
            ("cancel-malformed-command", "cancel_command", {"CommandId": "invalid"}),
            ("list-missing-command", "list_commands", {"CommandId": cid}),
            ("list-missing-invocations", "list_command_invocations", {"CommandId": cid, "Details": True}),
            ("invocation-invalid-id", "get_command_invocation", {"CommandId": cid, "InstanceId": "invalid"}),
        ):
            self.ssm(label, method, request)

    def documents(self):
        name = self.data["prefix"]
        for method in ("get_document", "describe_document"):
            self.ssm("published-shell-" + method, method, {"Name": "AWS-RunShellScript"})
        self.ssm("document-preflight", "describe_document", {"Name": name})
        if self.data["calls"][-1]["code"] != "InvalidDocument":
            raise RuntimeError("Owned document name not proven absent")
        self.own("documents", name)
        self.save()
        self.ssm("document-create", "create_document", {"Name": name, "DocumentType": "Command", "DocumentFormat": "JSON", "VersionName": "one", "Content": document(), "Tags": [{"Key": "suite", "Value": name}]}, required=True)
        self.ssm("document-create-duplicate", "create_document", {"Name": name, "DocumentType": "Command", "Content": document()})
        self.poll("document-active", "ssm", "describe_document", {"Name": name}, lambda r: r.get("Document", {}).get("Status") == "Active", seconds=30)
        for label, params in (
            ("unchanged-omitted", {"Content": document()}),
            ("update-omitted", {"Content": document("two"), "VersionName": "two"}),
            ("update-version-one", {"Content": document("three"), "DocumentVersion": "1", "VersionName": "three"}),
            ("update-stale-version-one", {"Content": document("stale"), "DocumentVersion": "1"}),
            ("update-latest", {"Content": document("four"), "DocumentVersion": "$LATEST", "VersionName": "four"}),
            ("unchanged-latest", {"Content": document("four"), "DocumentVersion": "$LATEST"}),
            ("update-default-symbol", {"Content": document("default"), "DocumentVersion": "$DEFAULT"}),
            ("older-identical-content", {"Content": document(), "DocumentVersion": "$LATEST"}),
            ("duplicate-version-name", {"Content": document("five"), "DocumentVersion": "$LATEST", "VersionName": "one"})):
            self.ssm("document-" + label, "update_document", {"Name": name, "DocumentFormat": "JSON", **params})
            self.poll("document-settled-" + label, "ssm", "describe_document", {"Name": name}, lambda r: r.get("Document", {}).get("Status") == "Active", seconds=30)
        self.ssm("document-versions", "list_document_versions", {"Name": name})
        self.ssm("document-default-two", "update_document_default_version", {"Name": name, "DocumentVersion": "2"})
        for selector in (None, "1", "2", "$DEFAULT", "$LATEST", "999"):
            for method in ("get_document", "describe_document"):
                self.ssm("document-" + method + "-" + str(selector), method, {"Name": name, **({"DocumentVersion": selector} if selector else {})})
        self.ssm("document-get-version-name", "get_document", {"Name": name, "VersionName": "one"})
        self.ssm("document-get-yaml", "get_document", {"Name": name, "DocumentFormat": "YAML"})
        self.ssm("document-list-owned", "list_documents", {"Filters": [{"Key": "Name", "Values": [name]}]})
        self.ssm("document-default-missing", "update_document_default_version", {"Name": name, "DocumentVersion": "999"})
        self.ssm("document-delete-default-version", "delete_document", {"Name": name, "DocumentVersion": "2"})
        self.ssm("document-delete-version-one", "delete_document", {"Name": name, "DocumentVersion": "1"})
        self.ssm("document-delete-latest-symbol", "delete_document", {"Name": name, "DocumentVersion": "$LATEST"})
        self.ssm("document-after-version-deletes", "list_document_versions", {"Name": name})
        self.ssm("document-describe-after-version-deletes", "describe_document", {"Name": name})
        self.ssm("document-update-after-latest-delete", "update_document", {"Name": name, "DocumentVersion": "$LATEST", "Content": document("after-delete"), "VersionName": "after-delete"})
        self.poll("document-after-delete-update-active", "ssm", "describe_document", {"Name": name, "DocumentVersion": "$LATEST"}, lambda r: r.get("Document", {}).get("Status") == "Active", seconds=30)
        self.ssm("document-versions-after-reupdate", "list_document_versions", {"Name": name})
        variants = {
            "malformed": "{",
            "no-steps": json.dumps({"schemaVersion": "2.2", "description": "no steps"}),
            "unknown-plugin": document(mainSteps=[{"action": "aws:notAPlugin", "name": "unknown", "inputs": {}}]),
            "unknown-type": document(parameters={"bad": {"type": "Number", "default": 1}}),
            "list-default-string": document(parameters={"commands": {"type": "StringList", "default": "echo hello"}, "executionTimeout": {"type": "String", "default": "10"}}),
            "pattern-default": document(parameters={"commands": {"type": "StringList", "default": ["echo hello"]}, "executionTimeout": {"type": "String", "default": "abc", "allowedPattern": "^[0-9]+$"}}),
        }
        for suffix, content in variants.items():
            invalid = name + "-" + suffix
            self.ssm("document-preflight-" + suffix, "describe_document", {"Name": invalid})
            if self.data["calls"][-1]["code"] != "InvalidDocument":
                raise RuntimeError("Variant name not absent")
            self.own("documents", invalid)
            self.save()
            self.ssm("document-invalid-" + suffix, "create_document", {"Name": invalid, "DocumentType": "Command", "Content": content})
        self.ssm("document-delete-absent", "delete_document", {"Name": name + "-absent"})

    def document_schema_edges(self):
        variants = {
            "null-string-default": document(parameters={"value": {"type": "String", "default": None}},
                mainSteps=[{"action": "aws:runShellScript", "name": "runShell", "inputs": {
                    "runCommand": ["printf '%s\\n' '{{ value }}'"], "timeoutSeconds": "10"}}]),
            "undeclared-reference": document(parameters={}, mainSteps=[{
                "action": "aws:runShellScript", "name": "runShell", "inputs": {
                    "runCommand": "{{ missing }}", "timeoutSeconds": "10"}}]),
            "arbitrary-literal-timeout": document(parameters={}, mainSteps=[{
                "action": "aws:runShellScript", "name": "runShell", "inputs": {
                    "runCommand": ["true"], "timeoutSeconds": "not-a-number"}}]),
        }
        for suffix, content in variants.items():
            name = self.data["prefix"] + "-" + suffix
            self.ssm("schema-preflight-" + suffix, "describe_document", {"Name": name})
            if self.data["calls"][-1]["code"] != "InvalidDocument":
                raise RuntimeError("Schema document not proven absent")
            self.own("documents", name)
            self.save()
            self.ssm("schema-create-" + suffix, "create_document",
                {"Name": name, "DocumentType": "Command", "Content": content})

    def document_expiry(self):
        p = self.data["prefix"]
        for suffix, parameter, timeouts in (
            ("hardcoded", None, ["5"]),
            ("arbitrary", "t", ["{{ t }}"]),
            ("execution", "executionTimeout", ["{{ executionTimeout }}"]),
            ("two-steps", None, ["5", "7"]),
        ):
            name = p + "-expiry-" + suffix
            content = {"schemaVersion": "2.2", "description": "Owned expiry admission",
                "parameters": {parameter: {"type": "String", "default": "5"}} if parameter else {},
                "mainSteps": [{"action": "aws:runShellScript", "name": "step" + str(i),
                    "inputs": {"runCommand": ["true"], "timeoutSeconds": value}} for i, value in enumerate(timeouts)]}
            self.ssm("expiry-preflight-" + suffix, "describe_document", {"Name": name})
            if self.data["calls"][-1]["code"] != "InvalidDocument":
                raise RuntimeError("Expiry document not proven absent")
            self.own("documents", name)
            self.save()
            self.ssm("expiry-create-" + suffix, "create_document", {"Name": name, "DocumentType": "Command", "Content": json.dumps(content)}, required=True)
            self.poll("expiry-active-" + suffix, "ssm", "describe_document", {"Name": name},
                lambda r: r.get("Document", {}).get("Status") == "Active", seconds=30)
            for mode, parameters in [("omitted", {})] + ([("supplied", {parameter: ["7"]})] if parameter else []):
                self.ssm("expiry-send-" + suffix + "-" + mode, "send_command", {
                    "DocumentName": name, "TimeoutSeconds": 30, "Parameters": parameters,
                    "Targets": [{"Key": "tag:suite", "Values": [p + "-no-node"]}]}, required=True)

    def tags(self, *types):
        return [{"ResourceType": kind, "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]} for kind in types]

    def setup_native(self):
        p = self.data["prefix"]
        o = self.data["owned"]
        version_url = "https://s3.us-east-1.amazonaws.com/amazon-ssm-us-east-1/latest/VERSION"
        with urlopen(version_url, timeout=15) as response:
            self.data["regional_agent_package"] = {"url": version_url,
                "version": response.read().decode().strip(),
                "request_id": response.headers.get("x-amz-request-id"), "observed_at": now()}
        self.save()
        self.ssm("standing-host-management-before", "get_service_setting", {"SettingId": SETTING})
        parameter = self.ssm("published-amazon-linux", "get_parameter", {"Name": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}, required=True)
        image_id = parameter["Parameter"]["Value"]
        images = self.call("published-image", "ec2", "describe_images", {"ImageIds": [image_id], "Owners": ["amazon"]}, required=True)["Images"]
        if len(images) != 1 or images[0]["Architecture"] != "x86_64" or images[0]["RootDeviceType"] != "ebs" or images[0].get("ProductCodes"):
            raise RuntimeError("Refusing unsuitable published image")
        image = images[0]
        root_size = next(v["Ebs"]["VolumeSize"] for v in image["BlockDeviceMappings"] if v["DeviceName"] == image["RootDeviceName"])
        if root_size > 8:
            raise RuntimeError("Published root exceeds 8-GiB budget")
        self.data["image"] = image
        for service, method, request, absent in (
            ("iam", "get_role", {"RoleName": p}, "NoSuchEntity"),
            ("iam", "get_instance_profile", {"InstanceProfileName": p}, "NoSuchEntity"),
            ("s3", "head_bucket", {"Bucket": p}, "404")):
            self.call("preflight-" + method, service, method, request)
            if self.data["calls"][-1]["code"] != absent:
                raise RuntimeError("Owned resource name not proven absent: " + method)
        log_group = "/stackd/ssm/" + p
        logs = self.call("preflight-log-group", "logs", "describe_log_groups", {"logGroupNamePrefix": log_group}, required=True)
        if logs.get("logGroups"):
            raise RuntimeError("Owned log group not absent")
        o.update(role=p, profile=p, bucket=p, log_group=log_group)
        self.save()
        trust = policy([{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com", "AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}])
        self.call("create-role", "iam", "create_role", {"RoleName": p, "AssumeRolePolicyDocument": json.dumps(trust), "Tags": self.tags("role")[0]["Tags"]}, required=True)
        self.call("create-profile", "iam", "create_instance_profile", {"InstanceProfileName": p}, required=True)
        self.call("add-profile-role", "iam", "add_role_to_instance_profile", {"InstanceProfileName": p, "RoleName": p}, required=True)
        statements = [
            allow(["ssm:UpdateInstanceInformation", "ssm:GetDocument", "ssm:DescribeDocument", "ssm:ListAssociations", "ssm:ListInstanceAssociations", "ssm:UpdateAssociationStatus", "ssm:UpdateInstanceAssociationStatus", "ssm:PutInventory", "ssm:PutComplianceItems", "ssm:GetManifest", "ssm:PutConfigurePackageResult"], "*"),
            allow(["ssmmessages:CreateControlChannel", "ssmmessages:OpenControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenDataChannel"], "*"),
            {"Effect": "Deny", "Action": "ec2messages:*", "Resource": "*"},
            allow("s3:PutObject", "arn:aws:s3:::" + p + "/*"),
            allow("s3:GetBucketLocation", "arn:aws:s3:::" + p),
            allow("logs:DescribeLogGroups", "*"),
            allow(["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"], "arn:aws:logs:" + REGION + ":" + self.args.account + ":log-group:" + o["log_group"] + ":*")]
        self.data["role_statements"] = statements
        self.call("agent-role-policy", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-agent", "PolicyDocument": json.dumps(policy(statements))}, required=True)
        self.call("create-output-bucket", "s3", "create_bucket", {"Bucket": p}, required=True)
        self.call("create-output-log-group", "logs", "create_log_group", {"logGroupName": o["log_group"], "tags": {"suite": p}}, required=True)
        offerings = self.call("supported-t3-placements", "ec2", "describe_instance_type_offerings",
            {"LocationType": "availability-zone", "Filters": [{"Name": "instance-type", "Values": ["t3.micro"]}]}, required=True)
        zones = sorted(v["Location"] for v in offerings["InstanceTypeOfferings"])
        if not zones:
            raise RuntimeError("No supported t3.micro availability zone")
        self.call("create-vpc", "ec2", "create_vpc", {"CidrBlock": "10.239.0.0/24", "TagSpecifications": self.tags("vpc")}, required=True)
        self.call("create-subnet", "ec2", "create_subnet", {"VpcId": o["vpc"], "CidrBlock": "10.239.0.0/27", "AvailabilityZone": zones[0], "TagSpecifications": self.tags("subnet")}, required=True)
        self.call("create-security-group", "ec2", "create_security_group", {"VpcId": o["vpc"], "GroupName": p, "Description": "Owned SSM evidence; no inbound", "TagSpecifications": self.tags("security-group")}, required=True)
        self.call("create-internet-gateway", "ec2", "create_internet_gateway", {"TagSpecifications": self.tags("internet-gateway")}, required=True)
        self.call("attach-internet-gateway", "ec2", "attach_internet_gateway", {"InternetGatewayId": o["gateway"], "VpcId": o["vpc"]}, required=True)
        self.call("create-route-table", "ec2", "create_route_table", {"VpcId": o["vpc"], "TagSpecifications": self.tags("route-table")}, required=True)
        self.call("associate-route-table", "ec2", "associate_route_table", {"RouteTableId": o["routes"], "SubnetId": o["subnet"]}, required=True)
        self.call("create-default-route", "ec2", "create_route", {"RouteTableId": o["routes"], "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": o["gateway"]}, required=True)
        request = {"ImageId": image_id, "InstanceType": "t3.micro", "MinCount": 1, "MaxCount": 1,
            "ClientToken": p, "IamInstanceProfile": {"Name": p}, "InstanceInitiatedShutdownBehavior": "terminate",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "CreditSpecification": {"CpuCredits": "standard"},
            "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": o["subnet"], "Groups": [o["group"]], "AssociatePublicIpAddress": True, "DeleteOnTermination": True}],
            "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"], "Ebs": {"VolumeType": "gp3", "VolumeSize": 8, "DeleteOnTermination": True}}],
            "UserData": USERDATA, "TagSpecifications": self.tags("instance", "volume", "network-interface")}
        launched = {}
        for attempt in range(12):
            launched = self.call("launch-owned-node-" + str(attempt), "ec2", "run_instances", request)
            if launched.get("Instances"):
                break
            row = self.data["calls"][-1]
            message = row.get("error", {}).get("Error", {}).get("Message", "")
            if row["code"] != "InvalidParameterValue" or "iamInstanceProfile.name" not in message:
                break
            time.sleep(5)
        if not launched.get("Instances"):
            raise RuntimeError("Owned launch was not admitted")
        iid = launched["Instances"][0]["InstanceId"]
        self.data["instance_id"] = iid
        self.save()
        running = self.poll("node-running", "ec2", "describe_instances", {"InstanceIds": [iid]}, lambda r: any(i["State"]["Name"] == "running" for v in r.get("Reservations", []) for i in v["Instances"]), seconds=180)
        if not running:
            raise RuntimeError("Owned node did not run")
        return iid

    def wait_command(self, label, command, iid, plugin=None, seconds=100):
        params = {"CommandId": command, "InstanceId": iid}
        if plugin:
            params["PluginName"] = plugin
        result = self.poll(label + "-invocation", "ssm", "get_command_invocation", params, lambda r: r.get("Status") in TERMINAL, seconds=seconds)
        self.ssm(label + "-commands", "list_commands", {"CommandId": command})
        self.ssm(label + "-plugins", "list_command_invocations", {"CommandId": command, "Details": True})
        return result

    def send(self, label, iid, commands, **extra):
        params = {"DocumentName": "AWS-RunShellScript", "InstanceIds": [iid], "Parameters": {"commands": commands, "executionTimeout": ["10"]}, "TimeoutSeconds": 30, **extra}
        response = self.ssm(label, "send_command", params)
        return response.get("Command", {}).get("CommandId")

    def wait_ready(self, iid):
        expected_version = self.data.get("regional_agent_package", {}).get("version")
        ready = self.poll("managed-node-online", "ssm", "describe_instance_information",
            {"Filters": [{"Key": "InstanceIds", "Values": [iid]}]},
            lambda r: any(i.get("PingStatus") == "Online" and (not expected_version or i.get("AgentVersion") == expected_version) for i in r.get("InstanceInformationList", [])),
            seconds=420, interval=5)
        if not ready:
            if not self.args.endpoint:
                self.call("node-console-not-online", "ec2", "get_console_output", {"InstanceId": iid, "Latest": True})
            raise RuntimeError("Official agent never observed Online")
        connected = self.poll("node-connection-status", "ssm", "get_connection_status", {"Target": iid},
            lambda r: r.get("Status", "").lower() == "connected", seconds=120, interval=5)
        if not connected:
            raise RuntimeError("Current agent control channel never observed connected")

    def commands(self, iid):
        p = self.data["prefix"]
        self.wait_ready(iid)
        script = ["amazon-ssm-agent -version", "cat /proc/sys/kernel/random/boot_id", "printf 'native-stdout\\n'", "printf 'native-stderr\\n' >&2", "id", "printf 'persisted-agent-evidence\\n' > /var/tmp/stackd-ssm-evidence"]
        if self.args.endpoint:
            # Local mode never reboots the caller-owned guest, so it needs no
            # persistent marker file there.
            script.pop()
        output = {} if self.args.endpoint else {"OutputS3BucketName": self.data["owned"]["bucket"], "OutputS3KeyPrefix": "run-command", "CloudWatchOutputConfig": {"CloudWatchOutputEnabled": True, "CloudWatchLogGroupName": self.data["owned"]["log_group"]}}
        command = self.send("command-success-output", iid, script, TimeoutSeconds=120, **output)
        if not command:
            raise RuntimeError("Real command not admitted")
        result = self.wait_command("success", command, iid, seconds=180)
        if not result or result.get("Status") != "Success" or "native-stdout" not in result.get("StandardOutputContent", ""):
            raise RuntimeError("Real guest command did not produce requested output")
        self.data["initial_guest_output"] = result["StandardOutputContent"]
        self.save()
        self.ssm("invocation-wrong-plugin", "get_command_invocation", {"CommandId": command, "InstanceId": iid, "PluginName": "notAPlugin"})
        self.ssm("invocation-missing-command", "get_command_invocation", {"CommandId": "00000000-0000-4000-8000-000000000000", "InstanceId": iid})
        if not self.args.endpoint:
            self.collect_output(command)
        command = self.send("command-exit-seven", iid, ["printf 'failed-stdout\\n'", "printf 'failed-stderr\\n' >&2", "exit 7"])
        if command:
            self.wait_command("failure", command, iid)
        command = self.send("command-execution-timeout", iid, ["printf 'before-timeout\\n'; sleep 20; printf 'must-not-complete\\n'"], Parameters={"commands": ["printf 'before-timeout\\n'; sleep 20; printf 'must-not-complete\\n'"], "executionTimeout": ["5"]})
        if command:
            self.wait_command("execution-timeout", command, iid)
        command = self.send("command-cancellable", iid, ["printf 'before-cancel\\n'; sleep 90; printf 'must-not-complete\\n'"], Parameters={"commands": ["printf 'before-cancel\\n'; sleep 90; printf 'must-not-complete\\n'"], "executionTimeout": ["120"]})
        if command:
            self.poll("cancel-started", "ssm", "get_command_invocation", {"CommandId": command, "InstanceId": iid}, lambda r: r.get("Status") == "InProgress", seconds=30)
            self.ssm("command-cancel", "cancel_command", {"CommandId": command, "InstanceIds": [iid]})
            self.wait_command("cancelled", command, iid)
        base = {"DocumentName": "AWS-RunShellScript", "InstanceIds": [iid], "Parameters": {"commands": ["printf 'validation-accepted\\n'"], "executionTimeout": ["2"]}, "TimeoutSeconds": 30}
        for label, extra in (
            ("timeout-too-small", {"TimeoutSeconds": 1}), ("concurrency-zero", {"MaxConcurrency": "0"}),
            ("concurrency-over-percent", {"MaxConcurrency": "101%"}), ("errors-negative", {"MaxErrors": "-1"}),
            ("errors-over-percent", {"MaxErrors": "101%"}), ("unknown-parameter", {"Parameters": {"commands": ["true"], "unknown": ["x"]}}),
            ("missing-document", {"DocumentName": p + "-missing"}), ("missing-version", {"DocumentVersion": "999999"}),
            ("missing-instance", {"InstanceIds": ["i-00000000000000000"]}),
            ("missing-tag", {"InstanceIds": [], "Targets": [{"Key": "tag:suite", "Values": [p + "-missing"]}]}),
            ("explicit-target-id", {"InstanceIds": [], "Targets": [{"Key": "InstanceIds", "Values": [iid]}], "MaxConcurrency": "1", "MaxErrors": "0"}),
            ("tag-owned-target", {"InstanceIds": [], "Targets": [{"Key": "tag:suite", "Values": [p]}], "MaxConcurrency": "100%", "MaxErrors": "100%"})):
            response = self.ssm("send-" + label, "send_command", {**base, **extra})
            cid = response.get("Command", {}).get("CommandId")
            if cid:
                if label in ("missing-tag", "tag-owned-target") and self.args.endpoint:
                    self.ssm(label + "-list", "list_commands", {"CommandId": cid})
                elif label == "missing-tag":
                    self.poll("missing-tag-terminal", "ssm", "list_commands", {"CommandId": cid}, lambda r: bool(r.get("Commands")) and r["Commands"][0]["Status"] in TERMINAL, seconds=30)
                else:
                    self.wait_command(label, cid, iid, seconds=60)
        for selector in ("$DEFAULT", "$LATEST", "2"):
            response = self.ssm("send-custom-" + selector, "send_command", {"DocumentName": p, "DocumentVersion": selector, "InstanceIds": [iid], "TimeoutSeconds": 30})
            if response.get("Command"):
                self.wait_command("custom-" + selector, response["Command"]["CommandId"], iid, plugin="runShell")
        command = self.send("command-agent-channel-evidence", iid, ["python3 - <<'PY'\nfrom pathlib import Path\nfor line in Path('/var/log/amazon/ssm/amazon-ssm-agent.log').read_text().splitlines():\n    if any(s in line for s in ('Set up control channel successfully', 'SSMConnectionChannel', 'ssmmessages.', 'MDS Stop', 'Stopping MDS', 'AccessDeniedException')):\n        print(line)\nPY"])
        if command:
            self.wait_command("agent-channel-evidence", command, iid)
        if not self.args.endpoint:
            self.role_denial(iid)
            self.restart_and_offline(iid)
        else:
            self.data["nonobservations"].append("Local mode does not mutate the caller-owned guest lifecycle or current IAM role; parent executable integration owns restart/authority proof.")
        self.save()

    def collect_output(self, command):
        o = self.data["owned"]
        objects = self.poll("s3-output-visible", "s3", "list_objects_v2", {"Bucket": o["bucket"], "Prefix": "run-command/" + command}, lambda r: any(v["Key"].endswith("stdout") for v in r.get("Contents", [])) and any(v["Key"].endswith("stderr") for v in r.get("Contents", [])), seconds=75)
        if objects:
            for obj in objects.get("Contents", []):
                self.call("s3-command-bytes-" + obj["Key"], "s3", "get_object", {"Bucket": o["bucket"], "Key": obj["Key"]})
        events = self.poll("cloudwatch-output-visible", "logs", "filter_log_events", {"logGroupName": o["log_group"], "logStreamNamePrefix": command}, lambda r: any("native-stdout" in v["message"] for v in r.get("events", [])) and any("native-stderr" in v["message"] for v in r.get("events", [])), seconds=75)
        self.data["output_observed"] = {"s3": objects is not None, "cloudwatch": events is not None}
        self.save()

    def role_denial(self, iid):
        p = self.data["prefix"]
        resources = ["arn:aws:ssm:" + REGION + "::document/AWS-RunShellScript", "arn:aws:ec2:" + REGION + ":" + self.args.account + ":instance/" + iid]
        statements = self.data["role_statements"] + [allow("ssm:SendCommand", resources)]
        self.call("caller-role-allow", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-agent", "PolicyDocument": json.dumps(policy(statements))}, required=True)
        assumed = self.call("assume-owned-agent-role", "sts", "assume_role", {"RoleArn": "arn:aws:iam::" + self.args.account + ":role/" + p, "RoleSessionName": "managed-native-evidence", "DurationSeconds": 900}, required=True)
        creds = assumed["Credentials"]
        session = boto3.Session(region_name=REGION, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
        client = session.client("ssm", config=CONFIG)
        params = {"DocumentName": "AWS-RunShellScript", "InstanceIds": [iid], "Parameters": {"commands": ["printf 'role-allowed\\n'"], "executionTimeout": ["2"]}, "TimeoutSeconds": 30}
        baseline = None
        for attempt in range(12):
            baseline = self.ssm("role-before-deny-" + str(attempt), "send_command", params, client=client, caller="owned-role")
            if baseline.get("Command"):
                break
            time.sleep(3)
        if baseline and baseline.get("Command"):
            self.wait_command("role-allowed", baseline["Command"]["CommandId"], iid)
        else:
            self.data["nonobservations"].append("Owned-role allowed baseline never admitted within 36s; subsequent deny is not proof of a live revocation transition.")
        statements += [{"Effect": "Deny", "Action": "ssm:SendCommand", "Resource": "*"}]
        self.call("caller-role-live-deny", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-agent", "PolicyDocument": json.dumps(policy(statements))}, required=True)
        for attempt in range(12):
            self.ssm("role-after-deny-" + str(attempt), "send_command", params, client=client, caller="same-owned-role-session")
            if self.data["calls"][-1]["code"] in ("AccessDeniedException", "AccessDenied"):
                return
            time.sleep(3)
        self.data["nonobservations"].append("Same-session live SendCommand denial not observed within 36s.")

    def timeout_edges(self, iid):
        self.wait_ready(iid)
        command = self.send("timeout-minimum-five", iid, ["printf 'before-timeout\\n'; sleep 20; printf 'must-not-complete\\n'"],
            Parameters={"commands": ["printf 'before-timeout\\n'; sleep 20; printf 'must-not-complete\\n'"], "executionTimeout": ["5"]})
        if not command:
            raise RuntimeError("Five-second timeout command was not admitted")
        self.wait_command("minimum-five", command, iid, seconds=90)
        p = self.data["prefix"]
        command = self.send("schedule-owned-agent-stop", iid, [
            "systemd-run --unit=" + p + "-resume --on-active=120 /usr/bin/systemctl start amazon-ssm-agent",
            "systemd-run --unit=" + p + "-stop --on-active=8 /usr/bin/systemctl stop amazon-ssm-agent",
            "printf 'agent-stop-scheduled\\n'"], TimeoutSeconds=120)
        if not command:
            raise RuntimeError("Agent-stop scheduling command was not admitted")
        self.wait_command("agent-stop-scheduled", command, iid)
        self.poll("agent-disconnected", "ssm", "get_connection_status", {"Target": iid},
            lambda r: r.get("Status") == "notconnected", seconds=90, interval=2)
        self.call("offline-agent-ec2-state", "ec2", "describe_instances", {"InstanceIds": [iid]})
        self.ssm("offline-agent-fleet-state", "describe_instance_information", {"Filters": [{"Key": "InstanceIds", "Values": [iid]}]})
        command = self.send("running-node-offline-command", iid, ["printf 'offline-must-not-execute\\n'"],
            Parameters={"commands": ["printf 'offline-must-not-execute\\n'"], "executionTimeout": ["5"]})
        if command:
            self.wait_command("running-node-offline", command, iid, seconds=90)
        self.ssm("offline-agent-fleet-after", "describe_instance_information", {"Filters": [{"Key": "InstanceIds", "Values": [iid]}]})

    def restart_and_offline(self, iid):
        self.call("reboot-owned-node", "ec2", "reboot_instances", {"InstanceIds": [iid]}, required=True)
        time.sleep(15)
        command = self.send("command-after-reboot", iid, ["cat /var/tmp/stackd-ssm-evidence", "cat /proc/sys/kernel/random/boot_id", "amazon-ssm-agent -version"], TimeoutSeconds=120)
        if command:
            result = self.wait_command("after-reboot", command, iid, seconds=180)
            before = re.findall(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", self.data["initial_guest_output"])
            after = re.findall(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", (result or {}).get("StandardOutputContent", ""))
            self.data["reboot_observed"] = bool(before and after and before[0] != after[0] and "persisted-agent-evidence" in result["StandardOutputContent"])
            if not self.data["reboot_observed"]:
                self.data["nonobservations"].append("No changed boot ID plus retained guest bytes witnessed after RebootInstances.")
            self.save()
        self.call("stop-owned-node", "ec2", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.poll("node-stopped", "ec2", "describe_instances", {"InstanceIds": [iid]}, lambda r: any(i["State"]["Name"] == "stopped" for v in r.get("Reservations", []) for i in v["Instances"]), seconds=180)
        self.ssm("stopped-node-ping", "describe_instance_information", {"Filters": [{"Key": "InstanceIds", "Values": [iid]}]})
        command = self.send("command-offline", iid, ["printf 'offline-must-not-execute\\n'"], Parameters={"commands": ["printf 'offline-must-not-execute\\n'"], "executionTimeout": ["2"]})
        if command:
            self.wait_command("offline-delivery", command, iid, seconds=120)
        self.ssm("stopped-node-ping-after", "describe_instance_information", {"Filters": [{"Key": "InstanceIds", "Values": [iid]}]})

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        self.cleanup_deadline = time.monotonic() + 600
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        o = self.data["owned"]
        if self.data.get("cleanup"):
            self.data.setdefault("previous_cleanup", []).append(self.data["cleanup"])
        cleanup = self.data["cleanup"] = {"started_at": now(), "absent": {}, "failures": []}
        self.save()
        def attempt(label, service, method, params):
            try:
                return self.call("cleanup-" + label, service, method, params)
            except Exception as error:
                cleanup["failures"].append({"label": label, "error": str(error)})
                return {}
        def absence(key, service, method, params, code, predicate=None):
            result = attempt("absence-" + key, service, method, params)
            row = self.data["calls"][-1]
            ok = row["code"] == code if predicate is None else row["code"] == "Success" and predicate(result)
            if ok:
                cleanup["absent"][key] = True
            else:
                cleanup["failures"].append({"resource": key, "observed_code": row["code"]})
        # Cancel retained work, but do not claim this removes command history.
        for command in o["commands"]:
            result = attempt("command-state-" + command, "ssm", "list_commands", {"CommandId": command})
            if any(c["Status"] not in TERMINAL for c in result.get("Commands", [])):
                attempt("cancel-" + command, "ssm", "cancel_command", {"CommandId": command})
        if not self.args.endpoint:
            # Recover a successful launch whose response was lost using exact-owned tags.
            result = attempt("discover-instances", "ec2", "describe_instances", {"Filters": [{"Name": "tag:suite", "Values": [self.data["prefix"]]}]})
            for kind, method, collection, identifier in (
                ("vpc", "describe_vpcs", "Vpcs", "VpcId"),
                ("subnet", "describe_subnets", "Subnets", "SubnetId"),
                ("group", "describe_security_groups", "SecurityGroups", "GroupId"),
                ("gateway", "describe_internet_gateways", "InternetGateways", "InternetGatewayId"),
                ("routes", "describe_route_tables", "RouteTables", "RouteTableId")):
                found = attempt("discover-" + kind, "ec2", method, {"Filters": [{"Name": "tag:suite", "Values": [self.data["prefix"]]}]})
                values = found.get(collection, [])
                if len(values) > 1:
                    cleanup["failures"].append({"resource": kind, "reason": "Exact-owned cardinality exceeded"})
                elif values:
                    o[kind] = values[0][identifier]
                    if kind == "routes":
                        for association in values[0].get("Associations", []):
                            if association.get("SubnetId") == o.get("subnet"):
                                o["route_association"] = association["RouteTableAssociationId"]
                self.save()
            for iid in o["instances"]:
                attempt("preterminate-console-" + iid, "ec2", "get_console_output", {"InstanceId": iid, "Latest": True})
                attempt("terminate-" + iid, "ec2", "terminate_instances", {"InstanceIds": [iid]})
            if o["instances"]:
                try:
                    self.poll("cleanup-instances-terminated", "ec2", "describe_instances", {"InstanceIds": o["instances"]}, lambda r: bool(r.get("Reservations")) and all(i["State"]["Name"] == "terminated" for v in r["Reservations"] for i in v["Instances"]), seconds=240, interval=5)
                except Exception as error:
                    cleanup["failures"].append({"resource": "instances", "error": str(error)})
            absence("nonterminal-instances", "ec2", "describe_instances", {"Filters": [{"Name": "tag:suite", "Values": [self.data["prefix"]]}, {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}]}, "Success", lambda r: not r.get("Reservations"))
            for kind, delete, describe, one, many, missing in (
                ("volumes", "delete_volume", "describe_volumes", "VolumeId", "VolumeIds", "InvalidVolume.NotFound"),
                ("enis", "delete_network_interface", "describe_network_interfaces", "NetworkInterfaceId", "NetworkInterfaceIds", "InvalidNetworkInterfaceID.NotFound")):
                for value in o[kind]:
                    attempt("delete-" + value, "ec2", delete, {one: value})
                    absence(value, "ec2", describe, {many: [value]}, missing)
            if o.get("route_association"):
                attempt("route-disassociate", "ec2", "disassociate_route_table", {"AssociationId": o["route_association"]})
            if o.get("gateway") and o.get("vpc"):
                attempt("gateway-detach", "ec2", "detach_internet_gateway", {"InternetGatewayId": o["gateway"], "VpcId": o["vpc"]})
            for kind, delete, describe, one, many, missing in (
                ("routes", "delete_route_table", "describe_route_tables", "RouteTableId", "RouteTableIds", "InvalidRouteTableID.NotFound"),
                ("gateway", "delete_internet_gateway", "describe_internet_gateways", "InternetGatewayId", "InternetGatewayIds", "InvalidInternetGatewayID.NotFound"),
                ("group", "delete_security_group", "describe_security_groups", "GroupId", "GroupIds", "InvalidGroup.NotFound"),
                ("subnet", "delete_subnet", "describe_subnets", "SubnetId", "SubnetIds", "InvalidSubnetID.NotFound"),
                ("vpc", "delete_vpc", "describe_vpcs", "VpcId", "VpcIds", "InvalidVpcID.NotFound")):
                if o.get(kind):
                    attempt("delete-" + kind, "ec2", delete, {one: o[kind]})
                    absence(kind, "ec2", describe, {many: [o[kind]]}, missing)
            if o.get("profile"):
                attempt("profile-remove-role", "iam", "remove_role_from_instance_profile", {"InstanceProfileName": o["profile"], "RoleName": o["role"]})
                attempt("profile-delete", "iam", "delete_instance_profile", {"InstanceProfileName": o["profile"]})
                absence("profile", "iam", "get_instance_profile", {"InstanceProfileName": o["profile"]}, "NoSuchEntity")
            if o.get("role"):
                attempt("policy-delete", "iam", "delete_role_policy", {"RoleName": o["role"], "PolicyName": "owned-agent"})
                attempt("role-delete", "iam", "delete_role", {"RoleName": o["role"]})
                absence("role", "iam", "get_role", {"RoleName": o["role"]}, "NoSuchEntity")
            if o.get("bucket"):
                objects = attempt("bucket-objects", "s3", "list_objects_v2", {"Bucket": o["bucket"]})
                for obj in objects.get("Contents", []):
                    attempt("object-delete-" + obj["Key"], "s3", "delete_object", {"Bucket": o["bucket"], "Key": obj["Key"]})
                attempt("bucket-delete", "s3", "delete_bucket", {"Bucket": o["bucket"]})
                absence("bucket", "s3", "head_bucket", {"Bucket": o["bucket"]}, "404")
            if o.get("log_group"):
                attempt("logs-delete", "logs", "delete_log_group", {"logGroupName": o["log_group"]})
                absence("log-group", "logs", "describe_log_groups", {"logGroupNamePrefix": o["log_group"]}, "Success", lambda r: not r.get("logGroups"))
            attempt("standing-host-management-after", "ssm", "get_service_setting", {"SettingId": SETTING})
        for name in o["documents"]:
            attempt("document-delete-" + name, "ssm", "delete_document", {"Name": name})
            absence(name, "ssm", "describe_document", {"Name": name}, "InvalidDocument")
        cleanup.update(finished_at=now(), complete=not cleanup["failures"], retained_history={
            "commands": o["commands"],
            "boundary": "SSM has no DeleteCommand API. Command history is immutable provider history. EC2 terminated tombstones and SSM stale managed-node records can remain; they are not claimed removed."})
        self.save()
        if cleanup["failures"]:
            raise RuntimeError("Cleanup incomplete; use --cleanup-only with the same output")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--endpoint")
    parser.add_argument("--instance-id", help="Already provisioned local guest only")
    parser.add_argument("--documents-only", action="store_true")
    parser.add_argument("--timeouts-only", action="store_true", help="Native-only focused timeout/agent-disconnection capture")
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--live-seconds", type=int, default=2400)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if not 60 <= args.live_seconds <= 2700:
        parser.error("live-seconds must be 60..2700, reserving cleanup within one hour")
    if args.endpoint and not (args.instance_id or args.documents_only or args.cleanup_only):
        parser.error("local full capture requires --instance-id")
    if not args.endpoint and args.instance_id:
        parser.error("native capture must own its one fresh node")
    if args.timeouts_only and (args.endpoint or args.documents_only):
        parser.error("timeouts-only needs its own native node and cannot combine with documents-only")
    cap = Capture(args)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupt)
    try:
        if not args.cleanup_only:
            signal.alarm(args.live_seconds)
            if args.timeouts_only:
                cap.timeout_edges(cap.setup_native())
            else:
                cap.control_edges()
                cap.documents()
                cap.document_schema_edges()
                cap.document_expiry()
                if not args.documents_only:
                    iid = args.instance_id if args.endpoint else cap.setup_native()
                    cap.commands(iid)
            cap.data["experiment_complete"] = True
            cap.save()
    except Exception as error:
        cap.data["fatal"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        cap.save()
        raise
    finally:
        cap.cleanup()
    print(json.dumps({"evidence": str(args.output), "calls": len(cap.data["calls"]), "experiment_complete": cap.data.get("experiment_complete", False), "cleanup_complete": cap.data["cleanup"]["complete"]}))


if __name__ == "__main__":
    main()
