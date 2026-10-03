#!/usr/bin/env python3
"""Capture native EC2 CopySnapshot bytes, lineage, encryption and KMS authority.

Only uniquely named synthetic 1-GiB snapshots and owned KMS keys are mutated.
Account defaults and standing roles remain unchanged. STS credentials, block
handles and presigned bearer URLs remain in memory; only URL semantics persist.
All snapshots are deleted and owned CMKs scheduled for deletion in finally.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
import uuid

import boto3

from ebs_encryption_probe import BLOCK, CHECKSUM, CONFIG, Capture, allow, now, policy, safe
from cloudtrail_events import CollectionError, collect_history

DOCS = [
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CopySnapshot.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-copy-snapshot.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/share-kms-key.html",
    "https://docs.aws.amazon.com/ebs/latest/APIReference/API_ListChangedBlocks.html",
]


def sanitized(value):
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower() in (
            "presignedurl", "x-amz-signature", "x-amz-security-token", "x-amz-credential",
            "authorization", "securitytoken") else sanitized(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitized(child) for child in value]
    return safe(value)


class CopyDataCapture(Capture):
    def __init__(self, args):
        self.args = args
        self.session = boto3.Session(region_name=args.region)
        self.sessions = {"owner": self.session}
        self.cache = {}
        self.clients = {service: self.client(service) for service in ("sts", "ec2", "ebs", "kms")}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != self.args.account:
            raise RuntimeError("Refusing writes outside authorized owner account")
        if args.cleanup_only or args.audit_only:
            self.data = json.loads(args.output.read_text())
            if (self.data["account"], self.data["member"], self.data["region"]) != (self.args.account, self.args.member_account, args.region):
                raise RuntimeError("Evidence ownership mismatch")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite live evidence")
            self.data = {"account": self.args.account, "member": self.args.member_account, "region": args.region,
                "cross_region": args.cross_region, "prefix": "stackd-ebs-copy-data-" + uuid.uuid4().hex[:12],
                "captured_at": now(), "identity": safe(identity), "documentation": DOCS,
                "sdk": {"boto3": boto3.__version__},
                "scope": "Owned 1-GiB synthetic sources/copies and owned CMKs only; existing role assumption with transient session policies; no account defaults or standing role mutations",
                "payload": {"length": len(BLOCK), "sha256": hashlib.sha256(BLOCK).hexdigest(),
                    "recipe": "ASCII 'stackd synthetic EBS encryption evidence\\n' repeated 14000 times, truncated to 524288 bytes", "source_block_index": 7, "child_new_block_index": 9},
                "owned": {"snapshots": [], "snapshot_contexts": {}, "keys": []},
                "sessions": {}, "calls": [], "wire_requests": [], "cases": {}, "cleanup": {}, "gaps": []}
        self.assume("member")
        self.save()

    def client(self, service, caller="owner", region=None):
        region = region or self.args.region
        key = (caller, region, service)
        if key not in self.cache:
            client = self.sessions[caller].client(service, region_name=region, config=CONFIG)
            if service == "ec2":
                client.meta.events.register("before-call.ec2.CopySnapshot", self.wire_semantics)
            self.cache[key] = client
        return self.cache[key]

    def wire_semantics(self, params, **kwargs):
        body = params.get("body", {})
        if not isinstance(body, dict):
            return
        url = body.get("PresignedUrl")
        semantics = {"destination_endpoint": urlsplit(params["url"]).netloc,
            "source_region": body.get("SourceRegion"), "source_snapshot_id": body.get("SourceSnapshotId"),
            "presigned_url_present": bool(url), "captured_at": now()}
        if url:
            parsed = urlsplit(url)
            query = parse_qs(parsed.query)
            semantics["presigned"] = {"host": parsed.netloc,
                "query_parameter_names": sorted(query),
                "action": query.get("Action"), "source_region": query.get("SourceRegion"),
                "source_snapshot_id": query.get("SourceSnapshotId"), "destination_region": query.get("DestinationRegion"),
                "algorithm": query.get("X-Amz-Algorithm"), "expires_seconds": query.get("X-Amz-Expires"),
                "has_signature": "X-Amz-Signature" in query, "has_session_token": "X-Amz-Security-Token" in query}
        self.data["wire_requests"].append(semantics)

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(sanitized(safe(self.data)), indent=2) + "\n")

    def assume(self, label, statements=None):
        parameters = {"RoleArn": f"arn:aws:iam::{self.args.member_account}:role/OrganizationAccountAccessRole",
            "RoleSessionName": self.data["prefix"][-12:] + "-" + label, "DurationSeconds": 3600}
        if statements is not None:
            document = policy(statements)
            self.data["sessions"][label] = document
            parameters["Policy"] = json.dumps(document, separators=(",", ":"))
        result = self.clients["sts"].assume_role(**parameters)
        credentials = result["Credentials"]
        self.sessions[label] = boto3.Session(region_name=self.args.region,
            aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"])
        identity = self.observe(label + "-identity", "sts", "get_caller_identity", caller=label, required=True)
        if identity["Account"] != self.args.member_account:
            raise RuntimeError("Recipient identity mismatch")

    def observe(self, label, service, method, parameters=None, *, client=None, caller="owner", region=None, required=False):
        region = region or self.args.region
        result = super().observe(label, service, method, parameters,
            client=client or self.client(service, caller, region), caller=caller, required=required)
        self.data["calls"][-1]["region"] = region
        if result and method in ("start_snapshot", "copy_snapshot"):
            sid = result["SnapshotId"]
            if sid not in self.data["owned"]["snapshots"]:
                self.data["owned"]["snapshots"].append(sid)
            self.data["owned"]["snapshot_contexts"][sid] = {"caller": "owner" if caller == "owner" else "member", "region": region}
        if result and method == "create_key":
            self.data["owned"]["keys"].append({"arn": result["KeyMetadata"]["Arn"], "caller": caller, "region": region})
        self.save()
        return result

    def source(self, label, key=None):
        extra = {"Encrypted": True, "KmsKeyArn": key} if key else {}
        result = self.start(label, **extra)
        sid = result["SnapshotId"]
        self.put(label + "-put", sid, 7)
        self.observe(label + "-complete", "ebs", "complete_snapshot", {"SnapshotId": sid, "ChangedBlocksCount": 1}, required=True)
        return sid

    def put(self, label, sid, index, caller="owner", required=True):
        return self.observe(label, "ebs", "put_snapshot_block", {"SnapshotId": sid, "BlockIndex": index,
            "BlockData": BLOCK, "DataLength": len(BLOCK), "Checksum": CHECKSUM, "ChecksumAlgorithm": "SHA256"}, caller=caller, required=required)

    def wait_all(self, label, snapshots):
        remaining = dict(snapshots)
        states = {}
        deadline = time.monotonic() + self.args.completion_wait
        attempt = 0
        while remaining:
            for name, sid in list(remaining.items()):
                context = self.data["owned"]["snapshot_contexts"][sid]
                result = self.observe(label + "-" + name + "-state-" + str(attempt), "ec2", "describe_snapshots", {"SnapshotIds": [sid]}, **context)
                if not result.get("Snapshots"):
                    continue
                metadata = result["Snapshots"][0]
                if metadata["State"] in ("completed", "error"):
                    states[name] = metadata
                    del remaining[name]
            if not remaining or time.monotonic() >= deadline:
                break
            attempt += 1
            time.sleep(min(15, max(0, deadline - time.monotonic())))
        for name, sid in remaining.items():
            self.data["gaps"].append({"case": name, "snapshot": sid, "reason": "bounded completion observation expired"})
        self.data.setdefault("terminal_states", {}).update(states)
        self.save()
        return states

    def read_data(self, label, sid, *, wait=False):
        context = self.data["owned"]["snapshot_contexts"][sid]
        deadline = time.monotonic() + (self.args.read_wait if wait else 0)
        attempt = 0
        while True:
            result = self.observe(label + "-list-" + str(attempt), "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, **context)
            if self.data["calls"][-1]["code"] == "Success":
                for block in result.get("Blocks", []):
                    self.observe(label + "-get-" + str(block["BlockIndex"]), "ebs", "get_snapshot_block", {
                        "SnapshotId": sid, "BlockIndex": block["BlockIndex"], "BlockToken": block["BlockToken"]}, **context, required=True)
                return result
            if time.monotonic() >= deadline:
                self.data["gaps"].append({"case": label, "reason": "EBS read not available within observation window"})
                self.save()
                return {}
            attempt += 1
            time.sleep(10)

    def copy(self, label, sid, *, caller="owner", region=None, tagged=False, **extra):
        parameters = {"SourceRegion": self.args.region, "SourceSnapshotId": sid,
            "Description": self.data["prefix"] + "-" + label}
        if tagged:
            parameters["TagSpecifications"] = [{"ResourceType": "snapshot", "Tags": [{"Key": "copy-only", "Value": label}]}]
        parameters.update(extra)
        result = self.observe(label, "ec2", "copy_snapshot", parameters, caller=caller, region=region)
        self.data["cases"][label] = {"source": sid, "caller": caller, "region": region or self.args.region,
            "snapshot": result.get("SnapshotId"), "request_code": self.data["calls"][-1]["code"]}
        self.save()
        return result.get("SnapshotId")

    def create_key(self, caller):
        result = self.observe(caller + "-create-key", "kms", "create_key", {"Description": self.data["prefix"] + "-" + caller,
            "Tags": [{"TagKey": "suite", "TagValue": self.data["prefix"]}]}, caller=caller, required=True)
        return result["KeyMetadata"]["Arn"]

    def defaults(self, phase):
        for caller, region in (("owner", self.args.region), ("owner", self.args.cross_region), ("member", self.args.region)):
            for method in ("get_ebs_encryption_by_default", "get_ebs_default_kms_key_id"):
                self.observe(phase + "-" + caller + "-" + region + "-" + method, "ec2", method, caller=caller, region=region, required=True)

    def run(self):
        self.defaults("before")
        owner_key, member_key = self.create_key("owner"), self.create_key("member")
        shared_policy = policy([
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.account}:root"}, "Action": "kms:*", "Resource": "*"},
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.member_account}:root"}, "Action": [
                "kms:DescribeKey", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:CreateGrant"], "Resource": "*"}])
        self.observe("source-key-share-policy", "kms", "put_key_policy", {"KeyId": owner_key, "PolicyName": "default", "Policy": json.dumps(shared_policy)}, required=True)
        plain, encrypted = self.source("plain-source"), self.source("encrypted-source", owner_key)
        self.data["sources"] = {"plain": plain, "encrypted": encrypted}
        states = self.wait_all("source", self.data["sources"])
        if any(states.get(name, {}).get("State") != "completed" for name in self.data["sources"]):
            raise RuntimeError("Synthetic sources did not complete")
        for label, sid in self.data["sources"].items():
            self.read_data(label + "-source", sid, wait=True)
            self.observe(label + "-share", "ec2", "modify_snapshot_attribute", {"SnapshotId": sid,
                "Attribute": "createVolumePermission", "OperationType": "add", "UserIds": [self.args.member_account]}, required=True)
        time.sleep(self.args.share_wait)
        copies = {}
        definitions = [
            ("plain-same-omitted", plain, {}), ("plain-same-false", plain, {"Encrypted": False}),
            ("plain-same-tagged", plain, {"tagged": True}), ("plain-cross", plain, {"region": self.args.cross_region}),
            ("plain-explicit-cmk", plain, {"Encrypted": True, "KmsKeyId": owner_key}),
            ("encrypted-omitted", encrypted, {}), ("encrypted-false", encrypted, {"Encrypted": False}),
            ("encrypted-same-key", encrypted, {"Encrypted": True, "KmsKeyId": owner_key}),
            ("encrypted-default", encrypted, {"Encrypted": True}),
            ("encrypted-cross-default", encrypted, {"region": self.args.cross_region}),
            ("member-plain", plain, {"caller": "member", "tagged": True}),
            ("member-encrypted-default", encrypted, {"caller": "member"}),
            ("member-encrypted-cmk", encrypted, {"caller": "member", "Encrypted": True, "KmsKeyId": member_key}),
            ("invalid-key", plain, {"Encrypted": True, "KmsKeyId": f"arn:aws:kms:{self.args.region}:{self.args.account}:key/{uuid.uuid4()}"}),
            ("improper-presigned", encrypted, {"region": self.args.cross_region,
                "PresignedUrl": f"https://ec2.{self.args.region}.amazonaws.com/?Action=CopySnapshot&SourceRegion={self.args.region}&SourceSnapshotId={encrypted}&DestinationRegion={self.args.cross_region}"}),
        ]
        for label, sid, parameters in definitions:
            copied = self.copy(label, sid, **parameters)
            if copied:
                copies[label] = copied
                context = self.data["owned"]["snapshot_contexts"][copied]
                self.observe(label + "-initial-state", "ec2", "describe_snapshots", {"SnapshotIds": [copied]}, **context)
        states = self.wait_all("copy", copies)
        for name, state in states.items():
            if state["State"] == "completed":
                self.read_data(name + "-bytes", copies[name], wait=True)
        self.lineage(plain, copies, states)
        self.authority(encrypted, member_key)
        for name, sid in self.data["sources"].items():
            self.delete_snapshot(name + "-source-delete", sid)
        for name in ("plain-same-omitted", "plain-cross", "member-plain", "member-encrypted-cmk"):
            if states.get(name, {}).get("State") == "completed":
                self.read_data(name + "-after-source-delete", copies[name], wait=True)
        self.defaults("after")
        self.data["capture_complete_at"] = now()
        self.save()

    def lineage(self, source, copies, states):
        for name in ("plain-same-omitted", "member-plain"):
            if states.get(name, {}).get("State") != "completed":
                continue
            copied = copies[name]
            caller = "member" if name == "member-plain" else "owner"
            for suffix, first, second in (("forward", source, copied), ("reverse", copied, source)):
                self.observe(name + "-source-pair-" + suffix, "ebs", "list_changed_blocks",
                    {"FirstSnapshotId": first, "SecondSnapshotId": second}, caller=caller)
            self.put(name + "-post-copy-put", copied, 9, caller=caller, required=False)
            self.observe(name + "-post-copy-complete", "ebs", "complete_snapshot", {"SnapshotId": copied, "ChangedBlocksCount": 0}, caller=caller)
            child = self.start(name + "-child", caller=caller, ParentSnapshotId=copied)
            if not child:
                continue
            child_id = child["SnapshotId"]
            self.put(name + "-child-put", child_id, 9, caller=caller)
            self.observe(name + "-child-complete", "ebs", "complete_snapshot", {"SnapshotId": child_id, "ChangedBlocksCount": 1}, caller=caller, required=True)
            child_states = self.wait_all("child", {name + "-child": child_id})
            if child_states.get(name + "-child", {}).get("State") == "completed":
                self.read_data(name + "-child-bytes", child_id, wait=True)
                self.observe(name + "-child-vs-copy", "ebs", "list_changed_blocks", {"FirstSnapshotId": copied, "SecondSnapshotId": child_id}, caller=caller)
                self.observe(name + "-child-vs-source", "ebs", "list_changed_blocks", {"FirstSnapshotId": source, "SecondSnapshotId": child_id}, caller=caller)
            self.observe(name + "-copy-permissions", "ec2", "describe_snapshot_attribute", {"SnapshotId": copied, "Attribute": "createVolumePermission"}, caller=caller)
        self.observe("source-tags-after-copy", "ec2", "describe_snapshots", {"SnapshotIds": [source]}, required=True)

    def authority(self, source, key):
        copies = {}
        for label, action in (("describe", "kms:DescribeKey"), ("decrypt", "kms:Decrypt"),
                ("reencrypt", "kms:ReEncrypt*"), ("generate-without-plaintext", "kms:GenerateDataKeyWithoutPlaintext"),
                ("grant", "kms:CreateGrant"), ("generate", "kms:GenerateDataKey")):
            caller = "deny-" + label
            self.assume(caller, [allow("*", "*"), {"Effect": "Deny", "Action": action, "Resource": "*"}])
            copied = self.copy("authority-" + caller, source, caller=caller, Encrypted=True, KmsKeyId=key)
            if copied:
                copies[caller] = copied
        states = self.wait_all("authority", copies)
        for label, state in states.items():
            if state["State"] == "completed":
                self.read_data("authority-" + label + "-bytes", copies[label], wait=True)

    def fresh_authority(self, source_only=False):
        self.defaults("before")
        cases = {}
        actions = [("baseline", None), ("describe", "kms:DescribeKey"), ("decrypt", "kms:Decrypt"),
            ("reencrypt", "kms:ReEncrypt*"), ("generate-without-plaintext", "kms:GenerateDataKeyWithoutPlaintext"),
            ("grant", "kms:CreateGrant"), ("generate", "kms:GenerateDataKey")]
        if source_only:
            actions = [("baseline", None), ("source-grant", "kms:CreateGrant"), ("source-describe", "kms:DescribeKey")]
        for label, action in actions:
            source_key, target_key = self.create_key("owner"), self.create_key("member")
            document = policy([
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.account}:root"}, "Action": "kms:*", "Resource": "*"},
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.member_account}:root"},
                    "Action": ["kms:DescribeKey", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:CreateGrant"], "Resource": "*"}])
            self.observe(label + "-key-share", "kms", "put_key_policy",
                {"KeyId": source_key, "PolicyName": "default", "Policy": json.dumps(document)}, required=True)
            sid = self.source("fresh-" + label + "-source", source_key)
            cases[label] = {"source": sid, "source_key": source_key, "target_key": target_key,
                "denied_action": action, "denied_resource": source_key if source_only else "*"}
        self.data["authority_isolation"] = {
            "scope": "Each copy uses a distinct source CMK, source snapshot and destination CMK. No recipient copy/grant was made previously for these keys.",
            "cases": cases}
        self.save()
        states = self.wait_all("fresh-source", {name: case["source"] for name, case in cases.items()})
        if any(states.get(name, {}).get("State") != "completed" for name in cases):
            raise RuntimeError("Fresh authority sources did not complete")
        for name, case in cases.items():
            self.observe(name + "-snapshot-share", "ec2", "modify_snapshot_attribute",
                {"SnapshotId": case["source"], "Attribute": "createVolumePermission", "OperationType": "add", "UserIds": [self.args.member_account]}, required=True)
        time.sleep(self.args.share_wait)
        copies = {}
        for name, case in cases.items():
            caller = "fresh-" + name
            statements = [allow("*", "*")]
            if case["denied_action"]:
                statements.append({"Effect": "Deny", "Action": case["denied_action"], "Resource": case["denied_resource"]})
            self.assume(caller, statements)
            sid = self.copy(caller, case["source"], caller=caller, Encrypted=True, KmsKeyId=case["target_key"])
            if sid:
                copies[caller] = sid
        states = self.wait_all("fresh-copy", copies)
        for name, state in states.items():
            if state["State"] == "completed":
                self.read_data(name + "-bytes", copies[name], wait=True)
        self.defaults("after")
        self.data["capture_complete_at"] = now()
        self.save()

    def failures(self):
        self.defaults("before")
        source_key, disabled_key = self.create_key("owner"), self.create_key("owner")
        source = self.source("failure-source", source_key)
        self.data["sources"] = {"encrypted": source}
        states = self.wait_all("failure-source", {"encrypted": source})
        if states.get("encrypted", {}).get("State") != "completed":
            raise RuntimeError("Failure-case source did not complete")
        self.read_data("failure-source-control", source, wait=True)
        self.observe("disable-owned-target-key", "kms", "disable_key", {"KeyId": disabled_key}, required=True)
        self.observe("disabled-key-state", "kms", "describe_key", {"KeyId": disabled_key}, required=True)
        signed = self.client("ec2").generate_presigned_url("copy_snapshot", Params={
            "SourceRegion": self.args.region, "SourceSnapshotId": source,
            "DestinationRegion": self.args.cross_region}, ExpiresIn=3600, HttpMethod="GET")
        parsed = urlsplit(signed)
        query = parse_qs(parsed.query)
        if "X-Amz-Signature" not in query:
            raise RuntimeError("SDK did not generate expected signature")
        query["X-Amz-Signature"] = ["0" * 64]
        tampered = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True), parsed.fragment))
        self.data["failure_inputs"] = {
            "invalid-signature": "SDK-generated valid source-region CopySnapshot presign; only X-Amz-Signature replaced with 64 zeroes.",
            "malformed-presigned": "Literal not-a-url string, not a bearer URL.",
            "source-mismatch": "Unsigned URL references syntactically valid nonexistent snapshot while outer request references owned source.",
            "destination-mismatch": "Unsigned URL DestinationRegion is source Region while outer request endpoint is cross Region.",
            "disabled-target-key": disabled_key}
        copies = {}
        for label, parameters in [
            ("disabled-target-key", {"Encrypted": True, "KmsKeyId": disabled_key}),
            ("missing-key-alias", {"Encrypted": True, "KmsKeyId": "alias/" + self.data["prefix"] + "-missing"}),
            ("invalid-signature", {"region": self.args.cross_region, "PresignedUrl": tampered}),
            ("source-mismatch", {"region": self.args.cross_region, "PresignedUrl":
                f"https://ec2.{self.args.region}.amazonaws.com/?Action=CopySnapshot&SourceRegion={self.args.region}&SourceSnapshotId=snap-00000000000000000&DestinationRegion={self.args.cross_region}"}),
            ("destination-mismatch", {"region": self.args.cross_region, "PresignedUrl":
                f"https://ec2.{self.args.region}.amazonaws.com/?Action=CopySnapshot&SourceRegion={self.args.region}&SourceSnapshotId={source}&DestinationRegion={self.args.region}"}),
            ("malformed-presigned", {"region": self.args.cross_region, "PresignedUrl": "not-a-url"})]:
            sid = self.copy(label, source, **parameters)
            if sid:
                copies[label] = sid
        states = self.wait_all("failure-copy", copies)
        for label, state in states.items():
            if state["State"] == "completed":
                self.read_data(label + "-bytes", copies[label], wait=True)
        self.defaults("after")
        self.data["capture_complete_at"] = now()
        self.save()

    def public_data(self):
        self.defaults("before")
        self.observe("public-block-setting-before", "ec2", "get_snapshot_block_public_access_state", required=True)
        source = self.source("public-byte-source")
        self.data["sources"] = {"plain": source}
        states = self.wait_all("public-source", {"plain": source})
        if states.get("plain", {}).get("State") != "completed":
            raise RuntimeError("Public synthetic source did not complete")
        self.read_data("public-source-control", source, wait=True)
        self.observe("public-source-share", "ec2", "modify_snapshot_attribute", {"SnapshotId": source,
            "Attribute": "createVolumePermission", "OperationType": "add", "GroupNames": ["all"]}, required=True)
        self.observe("public-source-permissions", "ec2", "describe_snapshot_attribute",
            {"SnapshotId": source, "Attribute": "createVolumePermission"}, required=True)
        time.sleep(self.args.share_wait)
        self.observe("member-public-source-list", "ebs", "list_snapshot_blocks", {"SnapshotId": source}, caller="member")
        copied = self.copy("member-public-copy", source, caller="member", tagged=True)
        if not copied:
            raise RuntimeError("Public synthetic copy was not admitted")
        states = self.wait_all("public-copy", {"member-public-copy": copied})
        if states.get("member-public-copy", {}).get("State") != "completed":
            raise RuntimeError("Public synthetic copy did not complete")
        self.read_data("public-copy-before-reset", copied, wait=True)
        self.observe("public-source-reset", "ec2", "reset_snapshot_attribute",
            {"SnapshotId": source, "Attribute": "createVolumePermission"}, required=True)
        self.observe("public-source-permissions-after-reset", "ec2", "describe_snapshot_attribute",
            {"SnapshotId": source, "Attribute": "createVolumePermission"}, required=True)
        deadline = time.monotonic() + self.args.read_wait
        attempt = 0
        while True:
            self.observe("member-source-after-reset-" + str(attempt), "ec2", "describe_snapshots",
                {"SnapshotIds": [source]}, caller="member")
            if self.data["calls"][-1]["code"] == "InvalidSnapshot.NotFound":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Public source visibility did not settle after reset")
            attempt += 1
            time.sleep(10)
        self.read_data("public-copy-after-source-reset", copied, wait=True)
        self.delete_snapshot("public-source-delete", source)
        self.read_data("public-copy-after-source-delete", copied, wait=True)
        self.observe("public-block-setting-after", "ec2", "get_snapshot_block_public_access_state", required=True)
        self.defaults("after")
        self.data["capture_complete_at"] = now()
        self.save()

    def delete_snapshot(self, label, sid):
        deleted = self.data["cleanup"].setdefault("deleted_snapshots", [])
        if sid in deleted:
            return
        self.observe(label, "ec2", "delete_snapshot", {"SnapshotId": sid}, **self.data["owned"]["snapshot_contexts"][sid])
        if self.data["calls"][-1]["code"] in ("Success", "InvalidSnapshot.NotFound"):
            deleted.append(sid)
        self.save()

    def cleanup(self):
        for sid in reversed(self.data["owned"]["snapshots"]):
            self.delete_snapshot("cleanup-delete-" + sid, sid)
        scheduled = self.data["cleanup"].setdefault("keys_scheduled", [])
        for key in self.data["owned"]["keys"]:
            if key["arn"] in scheduled:
                continue
            self.observe("cleanup-key-" + key["caller"], "kms", "schedule_key_deletion",
                {"KeyId": key["arn"], "PendingWindowInDays": 7}, caller=key["caller"], region=key["region"], required=True)
            scheduled.append(key["arn"])
        remaining = []
        for caller, region in (("owner", self.args.region), ("owner", self.args.cross_region), ("member", self.args.region)):
            result = self.observe("cleanup-inventory-" + caller + "-" + region, "ec2", "describe_snapshots",
                {"OwnerIds": ["self"], "Filters": [{"Name": "description", "Values": [self.data["prefix"] + "-*"]}]}, caller=caller, region=region, required=True)
            remaining += result.get("Snapshots", [])
        self.data["cleanup"].update(remaining_snapshots=remaining, observed_at=now())
        self.save()
        if remaining:
            raise RuntimeError("Owned snapshot cleanup incomplete")

    def audit(self):
        audit = self.data.setdefault("cloudtrail", {"events": [], "observations": [],
            "boundary": "Positive matching management-event lookup records only. Missing eventual records do not establish absence. No additional trail created."})
        fields = ("events", "pages", "observations", "objects", "errors")
        collections = {}
        for caller, region in (("owner", self.args.region), ("owner", self.args.cross_region), ("member", self.args.region)):
            previous = dict(audit.get("scopes", {}).get(caller + ":" + region, {}))
            for field in fields:
                previous[field] = [row for row in audit.get(field, [])
                    if row.get("caller") == caller and row.get("region") == region]
            collections[caller, region] = previous
        markers = self.data["owned"]["snapshots"] + [self.data["prefix"]]
        for key in self.data["owned"]["keys"]:
            markers += [key["arn"], key["arn"].rsplit("/", 1)[-1]]
        for row in self.data["calls"]:
            identity = row.get("output", {})
            if row["operation"] == "GetCallerIdentity" and ":assumed-role/" in identity.get("Arn", ""):
                markers += [identity["Arn"], identity["UserId"]]
        requests = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("request_id")}
        start = datetime.datetime.fromisoformat(self.data["captured_at"])

        def owned_event(event):
            text = json.dumps(event)
            return any(marker in text for marker in markers)

        for (caller, region), previous in collections.items():
            collected = None
            try:
                client = self.client("cloudtrail", caller, region)
                collected = collect_history(
                    lambda parameters: client.lookup_events(**parameters),
                    requests, start_time=start, event_sources=("ec2.amazonaws.com", "kms.amazonaws.com"),
                    max_pages=20, related=owned_event, previous=previous)
            except CollectionError as error:
                collected = error.result
                raise
            finally:
                if collected is not None:
                    new_pages = collected["pages"][len(previous["pages"]):]
                    for observation in collected["observations"][len(previous["observations"]):]:
                        observation["event_source"] = observation["source"]
                        observation["looked_up"] = sum(page["returned"] for page in new_pages
                            if page["source"] == observation["source"] and page["round"] == observation["round"])
                    collections[caller, region] = collected
                    for field in fields:
                        audit[field] = [
                            {**row, "caller": scope_caller, "region": scope_region}
                            for (scope_caller, scope_region), result in collections.items()
                            for row in result[field]]
                    audit["scopes"] = {
                        scope_caller + ":" + scope_region: {
                            key: value for key, value in result.items() if key not in fields}
                        for (scope_caller, scope_region), result in collections.items()}
                    audit["page_cap_reached"] = any(result.get("page_cap_reached", False) for result in collections.values())
                    audit["partial"] = any(result.get("partial", False) or result.get("errors") for result in collections.values())
                    found = {row["event"].get("requestID") for row in audit["events"] if row["call_label"] is not None}
                    audit["missing_request_ids"] = [request_id for request_id in requests if request_id not in found]
                    audit["missing_calls"] = [requests[request_id] for request_id in audit["missing_request_ids"]]
                    audit["captured_at"] = now()
                    self.save()


def summarize(path):
    data = json.loads(path.read_text())
    states = {row["SnapshotId"]: row for row in data.get("terminal_states", {}).values()}
    copies = {}
    for name, case in data["cases"].items():
        calls = [row for row in data["calls"] if row["label"] == name]
        copies[name] = dict(case, terminal=states.get(case.get("snapshot")),
            response=calls[-1] if calls else None)
    byte_reads = [
        {"label": row["label"], "snapshot": row["input"]["SnapshotId"],
            "block_index": row["input"]["BlockIndex"], "caller": row["caller"],
            "region": row["region"], "data": row["output"]["BlockData"],
            "checksum": row["output"].get("Checksum")}
        for row in data["calls"] if row["operation"] == "GetSnapshotBlock" and row["code"] == "Success"]
    contract = {
        "schema_version": 1, "source_script": "scripts/aws/ebs_copy_data_probe.py",
        "fixture": str(path), "owner_account": data["account"], "recipient_account": data["member"],
        "documentation": DOCS, "captured_through": data.get("capture_complete_at"),
        "scope": "Finite native observations on owned synthetic resources, not a general parity claim.",
        "copies": copies,
        "source_keys": data["owned"]["keys"],
        "lineage": [row for row in data["calls"] if row["operation"] == "ListChangedBlocks"],
        "post_copy_writes": [row for row in data["calls"] if "-post-copy-" in row["label"]],
        "ownership_and_permissions": [row for row in data["calls"] if row["label"].endswith("-copy-permissions")],
        "byte_reads": byte_reads,
        "sparse_lists": [row for row in data["calls"] if row["operation"] == "ListSnapshotBlocks" and row["code"] == "Success"],
        "session_authority": data["sessions"],
        "authority_isolation": data.get("authority_isolation"),
        "failure_inputs": data.get("failure_inputs"),
        "sdk_request_semantics": data["wire_requests"],
        "kms_events": [row for row in data.get("cloudtrail", {}).get("events", [])
            if row["event"].get("eventSource") == "kms.amazonaws.com"],
        "copy_events": [row for row in data.get("cloudtrail", {}).get("events", [])
            if row["event"].get("eventName") == "CopySnapshot"],
        "defaults_before_after": [row for row in data["calls"]
            if row["operation"] in ("GetEbsEncryptionByDefault", "GetEbsDefaultKmsKeyId")],
        "cleanup": data["cleanup"], "gaps": data["gaps"],
        "boundaries": [
            "Only positive delivered CloudTrail records are evidence; missing eventual events do not establish absence.",
            data.get("authority_isolation", {}).get("scope",
                "KMS session denies are applied to all keys and measured after a successful shared-source copy; grants may already exist. They are not a minimal-permission proof for every encryption route."),
            "Observed source/copy readiness and async completion times are not latency guarantees.",
            "Snapshots contain only synthetic data; all plaintext returned by EBS is represented by length and SHA-256, not stored block bytes.",
            "No account encryption defaults, standing IAM roles or AWS-managed keys were mutated or deleted."
        ],
        "verification": {"successful_block_reads": len(byte_reads),
            "all_block_digests_match": bool(byte_reads) and all(row["data"] == {key: data["payload"][key] for key in ("length", "sha256")} for row in byte_reads),
            "project_builds_tests_formatters_run": False}
    }
    destination = path.with_name(path.stem + "_contract.json")
    destination.write_text(json.dumps(contract, indent=2) + "\n")
    print("CONTRACT " + str(destination), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", help="Required for native capture, cleanup and audit")
    parser.add_argument("--member-account", help="Required for native capture, cleanup and audit")
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--cross-region", default="us-west-2", choices=["us-west-2"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/copy_data.json"))
    parser.add_argument("--completion-wait", type=int, default=900)
    parser.add_argument("--read-wait", type=int, default=600)
    parser.add_argument("--share-wait", type=int, default=90)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--audit-only", action="store_true")
    mode.add_argument("--summarize-only", action="store_true")
    mode.add_argument("--fresh-authority-only", action="store_true")
    mode.add_argument("--source-authority-only", action="store_true")
    mode.add_argument("--failures-only", action="store_true")
    mode.add_argument("--public-data-only", action="store_true")
    args = parser.parse_args()
    if args.summarize_only:
        summarize(args.output)
        return
    if not args.account or not args.member_account:
        parser.error("--account and --member-account are required for native AWS operations")
    capture = CopyDataCapture(args)
    if args.cleanup_only:
        capture.cleanup()
    elif args.audit_only:
        capture.audit()
    else:
        try:
            if args.fresh_authority_only:
                capture.fresh_authority()
            elif args.source_authority_only:
                capture.fresh_authority(source_only=True)
            elif args.failures_only:
                capture.failures()
            elif args.public_data_only:
                capture.public_data()
            else:
                capture.run()
        finally:
            capture.cleanup()
        capture.audit()
    summarize(args.output)


if __name__ == "__main__":
    main()
