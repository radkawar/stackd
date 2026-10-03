#!/usr/bin/env python3
"""Capture owned EBS encryption/IAM contracts; never change account defaults.

Credentials and block tokens remain in memory. One synthetic 512-KiB block is
written per data-bearing snapshot. Cleanup deletes snapshots before scheduling
the owned symmetric KMS key for deletion (minimum seven-day waiting period).
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import call
from cloudtrail_events import CollectionError, collect_history


CONFIG = Config(parameter_validation=False, retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)
BLOCK = (b"stackd synthetic EBS encryption evidence\n" * 14000)[:524288]
CHECKSUM = base64.b64encode(hashlib.sha256(BLOCK).digest()).decode()
DOCS = ["https://docs.aws.amazon.com/ebs/latest/userguide/ebsapis-using-encryption.html",
        "https://docs.aws.amazon.com/ebs/latest/userguide/ebsapi-permissions.html",
        "https://servicereference.us-east-1.amazonaws.com/v1/ebs/ebs.json"]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def safe(value):
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower() in ("accesskeyid", "secretaccesskey", "sessiontoken", "sourceipaddress", "blocktoken", "firstblocktoken", "secondblocktoken", "ciphertextblob", "plaintext") else safe(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(child) for child in value]
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    return value


def allow(actions, resources, condition=None):
    statement = {"Effect": "Allow", "Action": actions, "Resource": resources}
    if condition:
        statement["Condition"] = condition
    return statement


def policy(statements):
    return {"Version": "2012-10-17", "Statement": statements}


class Capture:
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.env = dict(os.environ, AWS_REGION=args.region, AWS_DEFAULT_REGION=args.region, AWS_MAX_ATTEMPTS="1")
        identity = call("sts", "get-caller-identity", env=self.env)
        if identity["Account"] != self.args.account:
            raise RuntimeError("Refusing writes outside authorized account")
        self.session = boto3.Session(region_name=args.region)
        self.clients = {service: self.session.client(service, config=CONFIG) for service in ("ebs", "ec2", "kms", "iam", "sts", "cloudtrail")}
        if args.audit_only or args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.args.account or self.data["region"] != args.region:
                raise RuntimeError("Evidence ownership mismatch")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite live evidence")
            prefix = "stackd-ebs-enc-" + uuid.uuid4().hex[:12]
            self.data = {"account": self.args.account, "region": args.region, "prefix": prefix, "captured_at": now(),
                "identity": identity, "documentation": DOCS, "sdk": {"boto3": boto3.__version__},
                "scope": "Owned 1-GiB logical snapshots, one owned symmetric KMS key and one bounded role; no default-encryption, public sharing or existing policy mutations",
                "payload": {"length": len(BLOCK), "sha256": hashlib.sha256(BLOCK).hexdigest(), "recipe": "ASCII 'stackd synthetic EBS encryption evidence\\n' repeated 14000 times, truncated to 524288 bytes"},
                "owned": {"snapshots": []}, "calls": [], "sessions": {}, "cleanup": {}, "gaps": []}
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(safe(self.data), indent=2) + "\n")

    def observe(self, label, service, method, parameters=None, *, client=None, caller="owner", required=False):
        client = client or self.clients[service]
        row = {"label": label, "service": service, "operation": client.meta.method_to_api_mapping[method],
               "input": safe(parameters or {}), "caller": caller, "started_at": now()}
        try:
            output = getattr(client, method)(**(parameters or {}))
            metadata = output.pop("ResponseMetadata", {})
            if "BlockData" in output:
                stream = output["BlockData"]
                output["BlockData"] = stream.read()
                stream.close()
            row.update(code="Success", output=safe(output))
            if service == "ebs" and method == "start_snapshot":
                self.data["owned"]["snapshots"].append(output["SnapshotId"])
            if service == "kms" and method == "create_key":
                self.data["owned"]["key"] = output["KeyMetadata"]["Arn"]
            if service == "iam" and method == "create_role":
                self.data["owned"]["role"] = output["Role"]["RoleName"]
                self.data["owned"]["role_arn"] = output["Role"]["Arn"]
        except ClientError as error:
            output = {}
            metadata = error.response.get("ResponseMetadata", {})
            row.update(code=error.response["Error"]["Code"], error=error.response["Error"])
            if "Reason" in error.response:
                row["reason"] = error.response["Reason"]
        row.update(http_status=metadata.get("HTTPStatusCode"), request_id=metadata.get("RequestId"), finished_at=now())
        self.data["calls"].append(row)
        self.save()
        print(label + ": " + row["code"], flush=True)
        if required and row["code"] != "Success":
            raise RuntimeError(label + ": " + row["code"])
        return output

    def start(self, label, *, client=None, caller="owner", tagged=True, **extra):
        parameters = {"VolumeSize": 1, "Description": self.data["prefix"] + "-" + label, "Timeout": 10}
        if tagged:
            parameters["Tags"] = [{"Key": "suite", "Value": self.data["prefix"]}]
        parameters.update(extra)
        return self.observe(label, "ebs", "start_snapshot", parameters, client=client, caller=caller)

    def finish(self, label, snapshot, *, block=False, readable=False):
        snapshot_id = snapshot["SnapshotId"]
        if block:
            self.observe(label + "-put", "ebs", "put_snapshot_block", {"SnapshotId": snapshot_id, "BlockIndex": 0,
                "BlockData": BLOCK, "DataLength": len(BLOCK), "Checksum": CHECKSUM, "ChecksumAlgorithm": "SHA256"}, required=True)
        self.observe(label + "-complete", "ebs", "complete_snapshot", {"SnapshotId": snapshot_id, "ChangedBlocksCount": int(block)}, required=True)
        for attempt in range(90):
            described = self.observe(label + "-state-" + str(attempt), "ec2", "describe_snapshots", {"SnapshotIds": [snapshot_id]}, required=True)
            state = described["Snapshots"][0]["State"]
            if state == "completed":
                if readable:
                    for read_attempt in range(120):
                        self.observe(label + "-readiness-" + str(read_attempt), "ebs", "list_snapshot_blocks", {"SnapshotId": snapshot_id})
                        if self.data["calls"][-1]["code"] == "Success":
                            return
                        time.sleep(5)
                    raise RuntimeError(label + " did not become EBS-readable")
                return
            if state == "error":
                raise RuntimeError(label + " entered error")
            time.sleep(2)
        raise RuntimeError("Snapshot did not complete within bounded wait")

    def assumed(self, label, statements):
        document = policy(statements)
        self.data["sessions"][label] = document
        self.save()
        for attempt in range(12):
            try:
                response = self.clients["sts"].assume_role(RoleArn=self.data["owned"]["role_arn"], RoleSessionName=label,
                    DurationSeconds=900, Policy=json.dumps(document, separators=(",", ":")))
                credentials = response["Credentials"]
                return boto3.client("ebs", region_name=self.args.region, config=CONFIG,
                    aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
            except ClientError as error:
                if error.response["Error"]["Code"] != "AccessDenied" or attempt == 11:
                    raise
                time.sleep(3)

    def read_block(self, label, snapshot_id, client=None, caller="owner", token=None):
        listed = self.observe(label + "-list", "ebs", "list_snapshot_blocks", {"SnapshotId": snapshot_id}, client=client, caller=caller)
        if listed.get("Blocks"):
            token = listed["Blocks"][0]["BlockToken"]
        if token:
            self.observe(label + "-get", "ebs", "get_snapshot_block", {"SnapshotId": snapshot_id, "BlockIndex": 0, "BlockToken": token}, client=client, caller=caller)
        return token

    def run(self):
        p = self.data["prefix"]
        region = self.args.region
        self.data["scope"] = "Focused authorization and inherited-parent encryption capture; baseline root flags are setup only. One owned key/role; no account defaults, standing resources, public sharing or Lake changes."
        self.observe("encryption-default-before", "ec2", "get_ebs_encryption_by_default", required=True)
        self.observe("default-key-before", "ec2", "get_ebs_default_kms_key_id", required=True)
        self.observe("create-owned-key", "kms", "create_key", {"Description": p, "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT",
            "Tags": [{"TagKey": "suite", "TagValue": p}]}, required=True)
        key = self.data["owned"]["key"]
        self.observe("owned-key-policy", "kms", "get_key_policy", {"KeyId": key, "PolicyName": "default"}, required=True)
        plain = self.start("setup-plain")
        encrypted = self.start("setup-encrypted", Encrypted=True, KmsKeyArn=key)
        for label, snapshot in (("plain", plain), ("encrypted", encrypted)):
            self.finish(label, snapshot, block=True, readable=True)
        plain_id, encrypted_id = plain["SnapshotId"], encrypted["SnapshotId"]
        plain_token = self.read_block("setup-plain-owner", plain_id)
        encrypted_token = self.read_block("setup-encrypted-owner", encrypted_id)
        children = {}
        for label, parent in (("plain", plain_id), ("encrypted", encrypted_id)):
            child = self.start(label + "-parent-inherited", ParentSnapshotId=parent)
            self.finish(label + "-parent-inherited", child, readable=True)
            self.read_block(label + "-child-inherited-data", child["SnapshotId"])
            children[label] = child["SnapshotId"]
            for suffix, extra in (("true", {"Encrypted": True}), ("false", {"Encrypted": False}), ("key", {"KmsKeyArn": key}),
                                  ("true-key", {"Encrypted": True, "KmsKeyArn": key}), ("false-key", {"Encrypted": False, "KmsKeyArn": key})):
                self.complete_if_started(label + "-parent-" + suffix, self.start(label + "-parent-" + suffix, ParentSnapshotId=parent, **extra))
        writable = self.start("setup-write-authorization")
        snapshot_arn = "arn:aws:ec2:" + region + "::snapshot/"
        plain_arn, encrypted_arn = snapshot_arn + plain_id, snapshot_arn + encrypted_id
        reads = ["ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock", "ebs:ListChangedBlocks"]
        writes = ["ebs:PutSnapshotBlock", "ebs:CompleteSnapshot"]
        kms_actions = ["kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKey", "kms:Decrypt", "kms:CreateGrant", "kms:ReEncrypt*"]
        start_allow = allow("ebs:StartSnapshot", snapshot_arn + "*")
        tag_allow = allow("ec2:CreateTags", snapshot_arn + "*")
        deny_ec2 = {"Effect": "Deny", "Action": ["ec2:DescribeSnapshots", "ec2:CopySnapshot", "ec2:CreateVolume"], "Resource": "*"}
        self.observe("create-owned-role", "iam", "create_role", {"RoleName": p, "AssumeRolePolicyDocument": json.dumps(policy([
            {"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}])),
            "Tags": [{"Key": "suite", "Value": p}]}, required=True)
        role_policy = policy([allow("ebs:StartSnapshot", snapshot_arn + "*", {"StringLike": {"ebs:Description": p + "-*"}, "NumericEquals": {"ebs:VolumeSize": "1"}}),
            allow(reads + writes, [snapshot_arn + sid for sid in self.data["owned"]["snapshots"]]),
            allow("ec2:CreateTags", snapshot_arn + "*", {"StringEquals": {"aws:RequestTag/suite": p}}),
            allow(kms_actions, key)])
        self.observe("bound-owned-role", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-snapshots-only", "PolicyDocument": json.dumps(role_policy)}, required=True)
        time.sleep(15)
        for label, resource, condition in (
            ("empty-account-arn", plain_arn, None),
            ("account-filled-arn", snapshot_arn.replace("::snapshot/", ":" + self.args.account + ":snapshot/") + plain_id, None),
            ("resource-tag-match", plain_arn, {"StringEquals": {"aws:ResourceTag/suite": p}}),
            ("resource-tag-mismatch", plain_arn, {"StringEquals": {"aws:ResourceTag/suite": "not-" + p}}),
            ("resource-account-match", plain_arn, {"StringEquals": {"aws:ResourceAccount": self.args.account}}),
            ("resource-account-mismatch", plain_arn, {"StringEquals": {"aws:ResourceAccount": "000000000000"}})):
            client = self.assumed(label, [allow(reads, resource, condition), deny_ec2])
            self.read_block(label, plain_id, client, label, plain_token)
        for action in ("ListSnapshotBlocks", "GetSnapshotBlock"):
            label = "explicit-deny-" + action
            client = self.assumed(label, [allow(reads, plain_arn), {"Effect": "Deny", "Action": "ebs:" + action, "Resource": plain_arn}])
            self.read_block(label, plain_id, client, label, plain_token)
        for label, resources in (("changed-second-only", [snapshot_arn + children["plain"]]),
                                 ("changed-first-only", [plain_arn]), ("changed-both", [plain_arn, snapshot_arn + children["plain"]])):
            client = self.assumed(label, [allow("ebs:ListChangedBlocks", resources)])
            self.observe(label, "ebs", "list_changed_blocks", {"FirstSnapshotId": plain_id, "SecondSnapshotId": children["plain"]}, client=client, caller=label)
        put = {"SnapshotId": writable["SnapshotId"], "BlockIndex": 0, "BlockData": BLOCK, "DataLength": len(BLOCK), "Checksum": CHECKSUM, "ChecksumAlgorithm": "SHA256"}
        for action in writes:
            label = "explicit-deny-" + action.split(":")[1]
            client = self.assumed(label, [allow(writes, snapshot_arn + writable["SnapshotId"]), {"Effect": "Deny", "Action": action, "Resource": "*"}])
            method = "put_snapshot_block" if action.endswith("PutSnapshotBlock") else "complete_snapshot"
            params = put if method == "put_snapshot_block" else {"SnapshotId": writable["SnapshotId"], "ChangedBlocksCount": 0}
            self.observe(label, "ebs", method, params, client=client, caller=label)
        client = self.assumed("write-empty-account-arn", [allow(writes, snapshot_arn + writable["SnapshotId"]), deny_ec2])
        self.observe("write-empty-account-arn-put", "ebs", "put_snapshot_block", put, client=client, caller="write-empty-account-arn", required=True)
        self.observe("write-empty-account-arn-complete", "ebs", "complete_snapshot", {"SnapshotId": writable["SnapshotId"], "ChangedBlocksCount": 1}, client=client, caller="write-empty-account-arn", required=True)
        for label, statements, tagged in (
            ("start-no-tags-no-tag-authority", [start_allow], False),
            ("start-tags-no-tag-authority", [start_allow], True),
            ("start-denied-create-tags", [start_allow, tag_allow, {"Effect": "Deny", "Action": "ec2:CreateTags", "Resource": "*"}], True),
            ("start-denied-ebs-action", [start_allow, tag_allow, {"Effect": "Deny", "Action": "ebs:StartSnapshot", "Resource": "*"}], True),
            ("start-tagged-allowed", [start_allow, tag_allow], True)):
            client = self.assumed(label, statements)
            self.complete_if_started(label, self.start(label, client=client, caller=label, tagged=tagged))
        for label, condition in (
            ("request-tag-match", {"StringEquals": {"aws:RequestTag/suite": p}, "ForAllValues:StringEquals": {"aws:TagKeys": ["suite"]}}),
            ("request-tag-mismatch", {"StringEquals": {"aws:RequestTag/suite": "wrong"}}),
            ("start-resource-tag", {"StringEquals": {"aws:ResourceTag/suite": p}})):
            client = self.assumed(label, [allow("ebs:StartSnapshot", snapshot_arn + "*", condition), tag_allow])
            self.complete_if_started(label, self.start(label, client=client, caller=label))
        for suffix, action in (("start", "StartSnapshot"), ("create", "CreateSnapshot")):
            label = "tag-create-action-" + suffix
            client = self.assumed(label, [start_allow, allow("ec2:CreateTags", snapshot_arn + "*", {"StringEquals": {"ec2:CreateAction": action}})])
            self.complete_if_started(label, self.start(label, client=client, caller=label))
        for label, statements in (
            ("parent-no-read-authority", [start_allow, tag_allow]),
            ("parent-denied-read-actions", [start_allow, tag_allow, {"Effect": "Deny", "Action": reads, "Resource": plain_arn}]),
            ("parent-denied-start-on-parent", [start_allow, tag_allow, {"Effect": "Deny", "Action": "ebs:StartSnapshot", "Resource": plain_arn}]),
            ("parent-condition-match", [allow("ebs:StartSnapshot", snapshot_arn + "*", {"ArnEquals": {"ebs:ParentSnapshot": plain_arn}}), tag_allow]),
            ("parent-condition-mismatch", [allow("ebs:StartSnapshot", snapshot_arn + "*", {"ArnEquals": {"ebs:ParentSnapshot": encrypted_arn}}), tag_allow])):
            client = self.assumed(label, statements + [deny_ec2])
            self.complete_if_started(label, self.start(label, client=client, caller=label, ParentSnapshotId=plain_id))
        kms_cases = [
            ("kms-none", [], None, []),
            ("kms-full", kms_actions, None, []),
            ("kms-deny-generate-data-key", kms_actions, None, ["kms:GenerateDataKey"]),
            ("kms-deny-without-plaintext", kms_actions, None, ["kms:GenerateDataKeyWithoutPlaintext"]),
            ("kms-deny-describe", kms_actions, None, ["kms:DescribeKey"]),
            ("kms-deny-create-grant", kms_actions, None, ["kms:CreateGrant"]),
            ("kms-deny-decrypt", kms_actions, None, ["kms:Decrypt"]),
            ("kms-generate-only", ["kms:GenerateDataKey"], None, []),
            ("kms-decrypt-only", ["kms:Decrypt"], None, []),
            ("kms-via-ec2", kms_actions, {"StringEquals": {"kms:ViaService": "ec2." + region + ".amazonaws.com"}}, []),
            ("kms-via-ebs", kms_actions, {"StringEquals": {"kms:ViaService": "ebs." + region + ".amazonaws.com"}}, []),
            ("kms-context-snapshot-shape", kms_actions, {"StringLike": {"kms:EncryptionContext:aws:ebs:id": "snap-*"}}, []),
            ("kms-context-wrong", kms_actions, {"StringEquals": {"kms:EncryptionContext:aws:ebs:id": "not-a-snapshot"}}, [])]
        for label, actions, condition, denied in kms_cases:
            statements = [start_allow, tag_allow, allow(reads, encrypted_arn)]
            if actions:
                statements.append(allow(actions, key, condition))
            if denied:
                statements.append({"Effect": "Deny", "Action": denied, "Resource": key})
            client = self.assumed(label, statements)
            self.complete_if_started(label + "-start", self.start(label + "-start", client=client, caller=label, Encrypted=True, KmsKeyArn=key))
            self.read_block(label, encrypted_id, client, label, encrypted_token)
            self.complete_if_started(label + "-parent", self.start(label + "-parent", client=client, caller=label, ParentSnapshotId=encrypted_id))
        staged = self.start("setup-before-key-disabled", Encrypted=True, KmsKeyArn=key)
        self.observe("disable-owned-key", "kms", "disable_key", {"KeyId": key}, required=True)
        self.observe("disabled-key-state", "kms", "describe_key", {"KeyId": key}, required=True)
        self.observe("disabled-key-direct-generate", "kms", "generate_data_key", {"KeyId": key, "NumberOfBytes": 64, "EncryptionContext": {"aws:ebs:id": staged["SnapshotId"]}})
        self.complete_if_started("disabled-key-start", self.start("disabled-key-start", Encrypted=True, KmsKeyArn=key))
        self.read_block("disabled-key-owner-read", encrypted_id, token=encrypted_token)
        client = self.assumed("disabled-key-fresh-session", [allow(reads, encrypted_arn), allow(kms_actions, key)])
        self.read_block("disabled-key-fresh-session", encrypted_id, client, "disabled-key-fresh-session")
        self.complete_if_started("disabled-key-parent", self.start("disabled-key-parent", ParentSnapshotId=encrypted_id))
        put["SnapshotId"] = staged["SnapshotId"]
        self.observe("disabled-key-existing-put", "ebs", "put_snapshot_block", put)
        changed = int(self.data["calls"][-1]["code"] == "Success")
        self.observe("disabled-key-existing-complete", "ebs", "complete_snapshot", {"SnapshotId": staged["SnapshotId"], "ChangedBlocksCount": changed})
        self.observe("disabled-key-existing-state", "ec2", "describe_snapshots", {"SnapshotIds": [staged["SnapshotId"]]})
        self.observe("enable-owned-key", "kms", "enable_key", {"KeyId": key}, required=True)
        self.observe("owned-key-grants", "kms", "list_grants", {"KeyId": key}, required=True)
        self.data["gaps"].extend([
            "Cross-account principals, shared/public snapshots and encryption-by-default enabled were not exercised; no standing resources or account defaults changed.",
            "CloudTrail history is eventual and does not include block data events here; no trail selectors, Lake or account audit configuration changed. Missing KMS events do not establish permission absence.",
            "Disabled-key checks are immediate, timestamped observations of the owned key and may reflect service key caching; no universal cache lifetime is inferred.",
            "Parent/root permission comparisons use immutable STS session policies intersected with the recorded owned role policy. No IAM user/access key was needed.",
            "Previously captured root encryption flag matrix is not repeated; two root snapshots are required data-bearing parent/read setup only."])
        self.save()

    def complete_if_started(self, label, snapshot):
        if snapshot:
            self.observe(label + "-complete", "ebs", "complete_snapshot", {"SnapshotId": snapshot["SnapshotId"], "ChangedBlocksCount": 0}, required=True)

    def cleanup(self):
        owned = self.data["owned"]
        deleted = self.data["cleanup"].setdefault("deleted_snapshots", [])
        for snapshot_id in reversed(owned["snapshots"]):
            if snapshot_id in deleted:
                continue
            self.observe("cleanup-delete-" + snapshot_id, "ec2", "delete_snapshot", {"SnapshotId": snapshot_id})
            row = self.data["calls"][-1]
            if row["code"] in ("Success", "InvalidSnapshot.NotFound"):
                deleted.append(snapshot_id)
        remaining = [sid for sid in owned["snapshots"] if sid not in deleted]
        verified = self.observe("cleanup-owned-snapshot-inventory", "ec2", "describe_snapshots", {"OwnerIds": [self.args.account], "Filters": [{"Name": "description", "Values": [self.data["prefix"] + "-*"]}]}, required=True)
        remaining = sorted(set(remaining) | {snapshot["SnapshotId"] for snapshot in verified["Snapshots"]})
        self.data["cleanup"]["remaining_snapshots"] = remaining
        iam_removed = True
        if owned.get("role"):
            self.observe("cleanup-delete-inline-policy", "iam", "delete_role_policy", {"RoleName": owned["role"], "PolicyName": "owned-snapshots-only"})
            self.observe("cleanup-delete-role", "iam", "delete_role", {"RoleName": owned["role"]})
            self.data["cleanup"]["role_deleted"] = self.data["calls"][-1]["code"] in ("Success", "NoSuchEntity")
            self.observe("cleanup-role-absent", "iam", "get_role", {"RoleName": owned["role"]})
            self.data["cleanup"]["role_absent_verified"] = self.data["calls"][-1]["code"] == "NoSuchEntity"
            iam_removed = self.data["cleanup"]["role_absent_verified"]
        if not remaining and iam_removed and owned.get("key") and not self.data["cleanup"].get("key_deletion_scheduled"):
            output = self.observe("cleanup-schedule-owned-key-deletion", "kms", "schedule_key_deletion", {"KeyId": owned["key"], "PendingWindowInDays": 7})
            if output:
                self.data["cleanup"]["key_deletion_scheduled"] = safe(output)
        if owned.get("key"):
            self.observe("cleanup-key-state", "kms", "describe_key", {"KeyId": owned["key"]})
        self.observe("encryption-default-after", "ec2", "get_ebs_encryption_by_default")
        self.observe("default-key-after", "ec2", "get_ebs_default_kms_key_id")
        self.data["cleanup"]["finished_at"] = now()
        self.save()
        if remaining or (owned.get("key") and not self.data["cleanup"].get("key_deletion_scheduled")) or (owned.get("role") and not self.data["cleanup"].get("role_deleted")):
            raise RuntimeError("Owned cleanup incomplete; use --cleanup-only")

    def audit(self, *, previous=None):
        request_ids = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("request_id")}
        owned = self.data["owned"]
        markers = owned["snapshots"] + [self.data["prefix"]] + ([owned["key"], owned["key"].split("/")[-1]] if owned.get("key") else [])

        def owned_event(event):
            text = json.dumps(event)
            return any(marker in text for marker in markers)

        audit = None
        try:
            audit = collect_history(
                lambda parameters: call("cloudtrail", "lookup-events", parameters, env=self.env,
                                        paginate=False, error_format="json"),
                request_ids, start_time=self.data["captured_at"],
                event_sources=("ebs.amazonaws.com", "ec2.amazonaws.com", "kms.amazonaws.com"),
                related=owned_event, previous=previous)
        except CollectionError as error:
            audit = error.result
            raise
        finally:
            if audit is not None:
                audit["captured_at"] = now()
                found = {row["event"].get("requestID") for row in audit["events"]}
                audit["missing_management_calls"] = [row["label"] for row in self.data["calls"] if row["service"] in ("ec2", "kms") or (row["service"] == "ebs" and row["operation"] in ("StartSnapshot", "CompleteSnapshot")) if row.get("request_id") not in found]
                self.data["cloudtrail"] = safe(audit)
                self.save()
        print(json.dumps({"audit_events": len(audit["events"]), "missing_management_calls": len(audit["missing_management_calls"])}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/encryption_authorization.json"))
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    capture = Capture(args)
    if args.audit_only:
        capture.audit()
        return
    if args.cleanup_only:
        capture.cleanup()
        return
    try:
        capture.run()
    finally:
        capture.cleanup()
    capture.audit()


if __name__ == "__main__":
    main()
