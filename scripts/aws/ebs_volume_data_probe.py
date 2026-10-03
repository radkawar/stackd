#!/usr/bin/env python3
"""Capture native snapshot -> volume -> snapshot bytes and caller authority.

Only owned synthetic 1-GiB resources, CMKs, queues/rules and trails/buckets are
mutated. Existing member-role sessions are restricted in memory. Account defaults
and standing roles remain unchanged. Block bodies/tokens and credentials are not
persisted. --cleanup-only resumes cleanup; --audit-only harvests owned trails.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from botocore.exceptions import ClientError

from ebs_encryption_probe import BLOCK, CHECKSUM, CONFIG, allow, now, policy, safe
from ebs_copy_data_probe import sanitized
from ebs_sharing_data_probe import SharingCapture

DOCS = [
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshot.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-cloud-watch-events.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/encryption-examples.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/security_iam_id-based-policy-examples.html",
]


class VolumeDataCapture(SharingCapture):
    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(prefix="stackd-ebs-volume-data-" + uuid.uuid4().hex[:12], documentation=DOCS,
                scope="Owned synthetic 1-GiB sources/volumes/snapshots, own CMKs and trails/queues only; no instances or account-default changes",
                payload={"length": len(BLOCK), "sha256": hashlib.sha256(BLOCK).hexdigest(),
                    "checksum": CHECKSUM, "block_index": 7,
                    "recipe": "ASCII 'stackd synthetic EBS encryption evidence\\n' repeated 14000 times, truncated to 524288 bytes"})
        self.data["owned"].setdefault("volumes", {})
        self.data["owned"].setdefault("keys", [])
        self.data.setdefault("cases", {})
        self.data.setdefault("terminal_volumes", {})
        self.data.setdefault("terminal_snapshots", {})
        for actor in ("owner", "member"):
            credentials = self.actors[actor]["ec2"]._request_signer._credentials.get_frozen_credentials()
            import boto3
            session = boto3.Session(region_name=args.region, aws_access_key_id=credentials.access_key,
                aws_secret_access_key=credentials.secret_key, aws_session_token=credentials.token)
            for service in ("events", "sqs"):
                self.actors[actor][service] = session.client(service, config=CONFIG)
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(sanitized(safe(self.data)), indent=2) + "\n")

    def observe(self, label, service, method, parameters=None, *, client=None, caller="owner", required=False):
        result = super().observe(label, service, method, parameters, client=client, caller=caller, required=required)
        owned = self.data["owned"]
        owner = "owner" if caller == "owner" else "member"
        if result and method == "create_volume":
            owned.setdefault("volumes", {})[result["VolumeId"]] = {"caller": owner, "label": label}
        if result and method == "create_snapshot":
            owned["snapshots"].append(result["SnapshotId"])
            owned["snapshot_accounts"][result["SnapshotId"]] = self.args.account if owner == "owner" else self.args.member_account
        if result and method == "create_key":
            owned.setdefault("keys", []).append({"arn": result["KeyMetadata"]["Arn"], "caller": owner})
        row = self.data["calls"][-1]
        encoded = re.search(r"Encoded authorization failure message: (\S+)", row.get("error", {}).get("Message", ""))
        if encoded:
            try:
                response = self.actors[owner]["sts"].decode_authorization_message(EncodedMessage=encoded[1])
                row["decoded_authorization"] = sanitized(json.loads(response["DecodedMessage"]))
            except ClientError as error:
                row["authorization_decode_error"] = error.response["Error"]
        self.save()
        return result

    def setup_events(self):
        for actor, account in (("owner", self.args.account), ("member", self.args.member_account)):
            name = self.data["prefix"] + "-" + actor
            result = self.observe(actor + "-event-queue", "sqs", "create_queue", {"QueueName": name}, caller=actor, required=True)
            arn = f"arn:aws:sqs:{self.args.region}:{account}:{name}"
            rule_arn = f"arn:aws:events:{self.args.region}:{account}:rule/{name}"
            self.data["owned"].setdefault("events", {})[actor] = {"queue": result["QueueUrl"], "rule": name}
            self.save()
            document = policy([{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}])
            self.observe(actor + "-queue-policy", "sqs", "set_queue_attributes",
                {"QueueUrl": result["QueueUrl"], "Attributes": {"Policy": json.dumps(document)}}, caller=actor, required=True)
            self.observe(actor + "-event-rule", "events", "put_rule", {"Name": name, "State": "ENABLED",
                "EventPattern": json.dumps({"source": ["aws.ec2"], "detail-type": ["EBS Volume Notification", "EBS Snapshot Notification"]})}, caller=actor, required=True)
            result = self.observe(actor + "-event-target", "events", "put_targets",
                {"Rule": name, "Targets": [{"Id": "owned-volume-capture", "Arn": arn}]}, caller=actor, required=True)
            if result.get("FailedEntryCount"):
                raise RuntimeError("Owned event target setup failed")

    def capture_events(self):
        evidence = self.data.setdefault("eventbridge", {"events": [], "boundary": "Positive delivered notifications only; missing eventual records do not establish absence"})
        seen = {row["event"]["id"] for row in evidence["events"]}
        markers = self.data["owned"]["snapshots"] + list(self.data["owned"]["volumes"])
        for actor, resource in self.data["owned"].get("events", {}).items():
            if self.data["cleanup"].get(actor + "_events_deleted"):
                continue
            client = self.actors[actor]["sqs"]
            while True:
                messages = client.receive_message(QueueUrl=resource["queue"], MaxNumberOfMessages=10, WaitTimeSeconds=1).get("Messages", [])
                for message in messages:
                    event = json.loads(message["Body"])
                    if event.get("id") not in seen and any(marker in message["Body"] for marker in markers):
                        evidence["events"].append({"account": actor, "event": sanitized(event)})
                        seen.add(event["id"])
                    client.delete_message(QueueUrl=resource["queue"], ReceiptHandle=message["ReceiptHandle"])
                if not messages:
                    break
        evidence["captured_at"] = now()
        self.save()

    def defaults(self, phase):
        for actor in ("owner", "member"):
            for method in ("get_ebs_encryption_by_default", "get_ebs_default_kms_key_id"):
                self.observe(phase + "-" + actor + "-" + method, "ec2", method, caller=actor, required=True)

    def key(self, label, caller="owner", shared=False):
        result = self.observe(label + "-key", "kms", "create_key", {"Description": self.data["prefix"] + "-" + label,
            "Tags": [{"TagKey": "suite", "TagValue": self.data["prefix"]}]}, caller=caller, required=True)
        arn = result["KeyMetadata"]["Arn"]
        if shared:
            document = policy([
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.account}:root"}, "Action": "kms:*", "Resource": "*"},
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.member_account}:root"}, "Action": [
                    "kms:DescribeKey", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:CreateGrant"], "Resource": "*"}])
            self.observe(label + "-key-share", "kms", "put_key_policy", {"KeyId": arn, "PolicyName": "default", "Policy": json.dumps(document)}, required=True)
        return arn

    def source(self, label, key=None, complete=True, size=1):
        extra = {"Encrypted": True, "KmsKeyArn": key} if key else {}
        result = self.start(label, VolumeSize=size, **extra)
        sid = result["SnapshotId"]
        self.observe(label + "-put", "ebs", "put_snapshot_block", {"SnapshotId": sid, "BlockIndex": 7,
            "BlockData": BLOCK, "DataLength": len(BLOCK), "Checksum": CHECKSUM, "ChecksumAlgorithm": "SHA256"}, required=True)
        if complete:
            self.observe(label + "-complete", "ebs", "complete_snapshot", {"SnapshotId": sid, "ChangedBlocksCount": 1}, required=True)
        return sid

    def wait_snapshots(self, snapshots):
        remaining = {label: sid for label, sid in snapshots.items() if sid}
        deadline = time.monotonic() + self.args.completion_wait
        attempt = 0
        while remaining:
            for label, sid in list(remaining.items()):
                caller = "owner" if self.data["owned"]["snapshot_accounts"][sid] == self.args.account else "member"
                result = self.observe(label + "-snapshot-state-" + str(attempt), "ec2", "describe_snapshots", {"SnapshotIds": [sid]}, caller=caller)
                if result.get("Snapshots") and result["Snapshots"][0]["State"] in ("completed", "error"):
                    self.data["terminal_snapshots"][sid] = result["Snapshots"][0]
                    del remaining[label]
            if not remaining or time.monotonic() >= deadline:
                break
            attempt += 1
            time.sleep(10)
        for label, sid in remaining.items():
            self.data["gaps"].append({"case": label, "snapshot": sid, "reason": "bounded snapshot completion observation expired"})
        self.save()

    def volume(self, label, sid, caller="owner", **extra):
        parameters = {"SnapshotId": sid, "AvailabilityZone": self.data["zones"]["owner" if caller == "owner" else "member"], "VolumeType": "gp3"}
        parameters.update(extra)
        result = self.observe(label, "ec2", "create_volume", parameters, caller=caller)
        self.data["cases"][label] = {"source": sid, "caller": caller, "volume": result.get("VolumeId"), "request_code": self.data["calls"][-1]["code"]}
        self.save()
        return result.get("VolumeId")

    def wait_volumes(self, volumes):
        remaining = {label: vid for label, vid in volumes.items() if vid}
        deadline = time.monotonic() + self.args.completion_wait
        attempt = 0
        while remaining:
            for label, vid in list(remaining.items()):
                caller = self.data["owned"]["volumes"][vid]["caller"]
                result = self.observe(label + "-volume-state-" + str(attempt), "ec2", "describe_volumes", {"VolumeIds": [vid]}, caller=caller)
                code = self.data["calls"][-1]["code"]
                if code == "InvalidVolume.NotFound" or (result.get("Volumes") and result["Volumes"][0]["State"] in ("available", "error", "deleted")):
                    self.data["terminal_volumes"][vid] = result.get("Volumes", [{"State": "not-found", "code": code}])[0]
                    del remaining[label]
            self.capture_events()
            if not remaining or time.monotonic() >= deadline:
                break
            attempt += 1
            time.sleep(10)
        for label, vid in remaining.items():
            self.data["gaps"].append({"case": label, "volume": vid, "reason": "bounded volume completion observation expired"})
        self.save()

    def snapshot(self, label, vid, caller=None, **extra):
        caller = caller or self.data["owned"]["volumes"][vid]["caller"]
        result = self.observe(label, "ec2", "create_snapshot", dict(VolumeId=vid, **extra), caller=caller)
        self.data["cases"][label] = {"source_volume": vid, "caller": caller, "snapshot": result.get("SnapshotId"), "request_code": self.data["calls"][-1]["code"]}
        self.save()
        return result.get("SnapshotId")

    def read_bytes(self, label, sid):
        caller = "owner" if self.data["owned"]["snapshot_accounts"][sid] == self.args.account else "member"
        deadline = time.monotonic() + self.args.read_wait
        attempt = 0
        while True:
            result = self.observe(label + "-list-" + str(attempt), "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, caller=caller)
            if self.data["calls"][-1]["code"] == "Success":
                for block in result.get("Blocks", []):
                    data = self.observe(label + "-get-" + str(block["BlockIndex"]), "ebs", "get_snapshot_block", {"SnapshotId": sid,
                        "BlockIndex": block["BlockIndex"], "BlockToken": block["BlockToken"]}, caller=caller, required=True)
                    if block["BlockIndex"] == 7 and (len(data["BlockData"]) != len(BLOCK) or hashlib.sha256(data["BlockData"]).hexdigest() != hashlib.sha256(BLOCK).hexdigest()):
                        raise RuntimeError("Native round-trip payload differs from synthetic source")
                if not any(block["BlockIndex"] == 7 for block in result.get("Blocks", [])):
                    raise RuntimeError("Native round-trip omitted known block")
                return
            if time.monotonic() >= deadline:
                self.data["gaps"].append({"case": label, "snapshot": sid, "reason": "EBS readability observation expired"})
                self.save()
                return
            attempt += 1
            time.sleep(10)

    def source_iam(self, sid):
        source = f"arn:aws:ec2:{self.args.region}::snapshot/{sid}"
        destination = f"arn:aws:ec2:{self.args.region}:{self.args.member_account}:volume/*"
        conditions = [
            ("source-and-destination", [allow("ec2:CreateVolume", [source, destination])]),
            ("destination-only", [allow("ec2:CreateVolume", destination)]),
            ("source-only", [allow("ec2:CreateVolume", source)]),
            ("source-account-filled", [allow("ec2:CreateVolume", [source.replace("::snapshot/", ":" + self.args.account + ":snapshot/"), destination])]),
            ("source-owner", [allow("ec2:CreateVolume", destination), allow("ec2:CreateVolume", source, {"StringEquals": {"ec2:Owner": self.args.account}})]),
            ("source-resource-account", [allow("ec2:CreateVolume", destination), allow("ec2:CreateVolume", source, {"StringEquals": {"aws:ResourceAccount": self.args.account}})]),
            ("source-tag", [allow("ec2:CreateVolume", destination), allow("ec2:CreateVolume", source, {"StringEquals": {"ec2:ResourceTag/suite": self.data["prefix"]}})]),
            ("source-snapshot-id", [allow("ec2:CreateVolume", destination), allow("ec2:CreateVolume", source, {"ArnEquals": {"ec2:SnapshotID": source}})]),
        ]
        for label, statements in conditions:
            actor = "source-iam-" + label
            self.assume(actor, statements)
            self.volume(actor, sid, caller=actor, DryRun=True)
        blocks = self.observe("source-iam-token", "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, caller="member")
        for label, denied in (("deny-describe", "ec2:DescribeSnapshots"), ("deny-ebs-read", ["ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock"]), ("deny-source-create-volume", "ec2:CreateVolume")):
            actor = "source-iam-" + label
            resource = source if denied == "ec2:CreateVolume" else "*"
            self.assume(actor, [allow("*", "*"), {"Effect": "Deny", "Action": denied, "Resource": resource}])
            self.observe(actor + "-describe", "ec2", "describe_snapshots", {"SnapshotIds": [sid]}, caller=actor)
            self.observe(actor + "-list", "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, caller=actor)
            for block in blocks.get("Blocks", []):
                self.observe(actor + "-get", "ebs", "get_snapshot_block", {"SnapshotId": sid,
                    "BlockIndex": block["BlockIndex"], "BlockToken": block["BlockToken"]}, caller=actor)
            self.volume(actor, sid, caller=actor)

    def snapshot_iam(self, vid):
        source = f"arn:aws:ec2:{self.args.region}:{self.args.member_account}:volume/{vid}"
        destination = f"arn:aws:ec2:{self.args.region}::snapshot/*"
        definitions = [
            ("both", [allow("ec2:CreateSnapshot", [source, destination])], {}),
            ("volume-only", [allow("ec2:CreateSnapshot", source)], {}),
            ("snapshot-only", [allow("ec2:CreateSnapshot", destination)], {}),
            ("source-resource-tag", [allow("ec2:CreateSnapshot", destination), allow("ec2:CreateSnapshot", source, {"StringEquals": {"ec2:ResourceTag/volume-only": "member-plain"}})], {}),
            ("destination-request-tag", [allow("ec2:CreateSnapshot", source), allow("ec2:CreateSnapshot", destination, {"StringEquals": {"aws:RequestTag/snapshot-only": "native"}}),
                allow("ec2:CreateTags", destination, {"StringEquals": {"ec2:CreateAction": "CreateSnapshot"}})],
                {"TagSpecifications": [{"ResourceType": "snapshot", "Tags": [{"Key": "snapshot-only", "Value": "native"}]}]}),
            ("tag-no-create-tags", [allow("ec2:CreateSnapshot", [source, destination])],
                {"TagSpecifications": [{"ResourceType": "snapshot", "Tags": [{"Key": "snapshot-only", "Value": "native"}]}]}),
        ]
        for label, statements, extra in definitions:
            actor = "snapshot-iam-" + label
            self.assume(actor, statements)
            self.snapshot(actor, vid, caller=actor, DryRun=True, **extra)
        actor = "snapshot-deny-dependencies"
        self.assume(actor, [allow("*", "*"), {"Effect": "Deny", "Action": ["ec2:DescribeVolumes", "ebs:*"], "Resource": "*"}])
        self.snapshot(actor, vid, caller=actor)

    def run(self):
        self.setup_audit()
        self.setup_events()
        self.defaults("before")
        self.data["zones"] = {}
        for actor in ("owner", "member"):
            result = self.observe(actor + "-zones", "ec2", "describe_availability_zones", {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}, {"Name": "state", "Values": ["available"]}]}, caller=actor, required=True)
            self.data["zones"][actor] = result["AvailabilityZones"][0]["ZoneName"]
        source_key = self.key("source", shared=True)
        owner_target = self.key("owner-target")
        member_target = self.key("member-target", caller="member")
        disabled = self.key("disabled-target")
        self.observe("disable-target-key", "kms", "disable_key", {"KeyId": disabled}, required=True)
        plain, encrypted = self.source("plain-source"), self.source("encrypted-source", source_key)
        pending = self.source("pending-source", complete=False)
        self.data["sources"] = {"plain": plain, "encrypted": encrypted, "pending": pending}
        self.volume("pending-source", pending)
        self.volume("missing-source", "snap-0123456789abcdef0")
        self.wait_snapshots({"plain-source": plain, "encrypted-source": encrypted})
        self.volume("unshared-member-source", plain, caller="member")
        for label, sid in (("plain", plain), ("encrypted", encrypted)):
            self.share(label + "-share", sid)
        time.sleep(self.args.share_wait)
        volumes = {}
        definitions = [
            ("plain-default", plain, "owner", {}),
            ("plain-tagged", plain, "owner", {"TagSpecifications": [{"ResourceType": "volume", "Tags": [{"Key": "volume-only", "Value": "native"}]}]}),
            ("plain-default-encrypted", plain, "owner", {"Encrypted": True}),
            ("plain-custom-encrypted", plain, "owner", {"Encrypted": True, "KmsKeyId": owner_target}),
            ("encrypted-inherited", encrypted, "owner", {}),
            ("encrypted-false", encrypted, "owner", {"Encrypted": False}),
            ("encrypted-rekey", encrypted, "owner", {"Encrypted": True, "KmsKeyId": owner_target}),
            ("member-plain", plain, "member", {"TagSpecifications": [{"ResourceType": "volume", "Tags": [{"Key": "volume-only", "Value": "member-plain"}]}]}),
            ("member-encrypted-inherited", encrypted, "member", {}),
            ("member-encrypted-custom", encrypted, "member", {"Encrypted": True, "KmsKeyId": member_target}),
            ("invalid-key", plain, "owner", {"Encrypted": True, "KmsKeyId": "arn:aws:kms:us-east-1:" + self.args.account + ":key/00000000-0000-0000-0000-000000000000"}),
            ("disabled-key", plain, "owner", {"Encrypted": True, "KmsKeyId": disabled}),
            ("key-without-encrypted", plain, "owner", {"KmsKeyId": owner_target}),
        ]
        for label, sid, caller, extra in definitions:
            volumes[label] = self.volume(label, sid, caller=caller, **extra)
        self.source_iam(plain)
        self.wait_volumes({row["label"]: vid for vid, row in self.data["owned"]["volumes"].items()})
        snapshots = {}
        for label, vid in volumes.items():
            if vid and self.data["terminal_volumes"].get(vid, {}).get("State") == "available":
                snapshots[label + "-snapshot"] = self.snapshot(label + "-snapshot", vid)
        if volumes.get("plain-tagged"):
            snapshots["snapshot-description-tags"] = self.snapshot("snapshot-description-tags", volumes["plain-tagged"],
                Description="native snapshot description Ω", TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "snapshot-only", "Value": "native"}]}])
        if volumes.get("plain-default"):
            snapshots["same-request-repeat"] = self.snapshot("same-request-repeat", volumes["plain-default"])
        if volumes.get("member-plain"):
            self.snapshot_iam(volumes["member-plain"])
        self.wait_snapshots({"output-" + sid: sid for sid in self.data["owned"]["snapshots"] if sid not in self.data["sources"].values()})
        for label in ("plain-default-snapshot", "encrypted-inherited-snapshot", "member-encrypted-custom-snapshot"):
            if snapshots.get(label):
                self.read_bytes(label + "-before-source-delete", snapshots[label])
        for label, sid in (("plain", plain), ("encrypted", encrypted)):
            self.delete_snapshot(label + "-original-delete", sid)
            self.observe(label + "-original-gone", "ec2", "describe_snapshots", {"SnapshotIds": [sid]})
        for label, sid in snapshots.items():
            if sid and self.data["terminal_snapshots"].get(sid, {}).get("State") == "completed":
                self.read_bytes(label + "-after-source-delete", sid)
        self.volume("deleted-source", plain)
        self.capture_events()
        self.defaults("after")
        self.data["capture_complete_at"] = now()
        self.save()

    def source_authority(self):
        self.data["zones"] = {}
        for actor in ("owner", "member"):
            result = self.observe(actor + "-zones", "ec2", "describe_availability_zones",
                {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}, {"Name": "state", "Values": ["available"]}]},
                caller=actor, required=True)
            self.data["zones"][actor] = result["AvailabilityZones"][0]["ZoneName"]
        sid = self.source("source-authority")
        self.wait_snapshots({"source-authority": sid})
        self.read_bytes("source-authority-ready", sid)
        self.share("source-authority-share", sid)
        time.sleep(self.args.share_wait)
        self.source_iam(sid)
        self.wait_volumes({row["label"]: vid for vid, row in self.data["owned"]["volumes"].items()})
        self.data["capture_complete_at"] = now()
        self.save()

    def snapshot_controls(self):
        self.data["scope"] = "Owned 2-GiB synthetic source, one restored member volume and two snapshots; no account-default or standing-role changes"
        self.data["zones"] = {}
        for actor in ("owner", "member"):
            result = self.observe(actor + "-zones", "ec2", "describe_availability_zones",
                {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}, {"Name": "state", "Values": ["available"]}]},
                caller=actor, required=True)
            self.data["zones"][actor] = result["AvailabilityZones"][0]["ZoneName"]
        sid = self.source("snapshot-control-source", size=2)
        self.wait_snapshots({"snapshot-control-source": sid})
        self.volume("size-smaller-than-source", sid, Size=1)
        self.share("snapshot-control-share", sid)
        time.sleep(self.args.share_wait)
        vid = self.volume("snapshot-control-volume", sid, caller="member",
            TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "volume-only", "Value": "not-inherited"}]}])
        if not vid:
            raise RuntimeError("Snapshot control volume was not admitted")
        self.wait_volumes({"snapshot-control-volume": vid})
        actor = "snapshot-without-read-authority"
        self.assume(actor, [allow("*", "*"), {"Effect": "Deny",
            "Action": ["ec2:DescribeVolumes", "ebs:*"], "Resource": "*"}])
        parameters = {"Description": "native snapshot description",
            "TagSpecifications": [{"ResourceType": "snapshot", "Tags": [{"Key": "snapshot-only", "Value": "native"}]}]}
        started = time.monotonic()
        first = self.snapshot("snapshot-tagged-description", vid, caller=actor, **parameters)
        self.wait_snapshots({"snapshot-tagged-description": first})
        time.sleep(max(0, 60 - (time.monotonic() - started)))
        second = self.snapshot("snapshot-identical-request-after-complete", vid, caller=actor, **parameters)
        self.wait_snapshots({"snapshot-identical-request-after-complete": second})
        self.delete_snapshot("snapshot-control-original-delete", sid)
        for label, snapshot in (("snapshot-tagged-description", first), ("snapshot-identical-request-after-complete", second)):
            if snapshot:
                self.read_bytes(label, snapshot)
        self.data["capture_complete_at"] = now()
        self.save()

    def fresh_authority(self):
        if self.args.skip_trail:
            self.data["gaps"].append("Supplementary run explicitly omits an owned trail after observed regional trail quota; main and authority fixtures retain delivered audit.")
        else:
            self.setup_audit()
        self.setup_events()
        self.defaults("before")
        self.data["zones"] = {}
        for actor in ("owner", "member"):
            result = self.observe(actor + "-zones", "ec2", "describe_availability_zones", {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}, {"Name": "state", "Values": ["available"]}]}, caller=actor, required=True)
            self.data["zones"][actor] = result["AvailabilityZones"][0]["ZoneName"]
        cases = {}
        for label, action, target in (("control", None, False), ("source-create-grant", "kms:CreateGrant", False),
                ("source-decrypt", "kms:Decrypt", False), ("source-describe", "kms:DescribeKey", False),
                ("source-reencrypt", "kms:ReEncryptFrom", False), ("target-reencrypt", "kms:ReEncryptTo", True),
                ("target-create-grant", "kms:CreateGrant", True), ("target-generate", "kms:GenerateDataKeyWithoutPlaintext", True),
                ("target-describe", "kms:DescribeKey", True), ("same-key-create-grant", "kms:CreateGrant", "inherit")):
            if self.args.authority_case and label not in self.args.authority_case:
                continue
            key = self.key(label + "-source", shared=True)
            destination = key if target == "inherit" else self.key(label + "-target", caller="member")
            sid = self.source(label + "-source", key)
            cases[label] = {"source": sid, "source_key": key, "target_key": destination,
                "denied_action": action, "denied_resource": destination if target else key}
        self.data["fresh_authority"] = cases
        self.wait_snapshots({label: row["source"] for label, row in cases.items()})
        for label, row in cases.items():
            self.share(label + "-share", row["source"])
        time.sleep(self.args.share_wait)
        volumes = {}
        for label, row in cases.items():
            actor = "fresh-" + label
            statements = [allow("*", "*")]
            if row["denied_action"]:
                statements.append({"Effect": "Deny", "Action": row["denied_action"], "Resource": row["denied_resource"]})
            self.assume(actor, statements)
            volumes[label] = self.volume(actor, row["source"], caller=actor, Encrypted=True, KmsKeyId=row["target_key"])
        self.wait_volumes(volumes)
        snapshots = {}
        control = volumes.get("control")
        if control and self.data["terminal_volumes"].get(control, {}).get("State") == "available":
            self.assume("snapshot-deny-all-kms", [allow("*", "*"), {"Effect": "Deny", "Action": "kms:*", "Resource": "*"}])
            snapshots["snapshot-deny-all-kms"] = self.snapshot("snapshot-deny-all-kms", control, caller="snapshot-deny-all-kms")
        for label, vid in volumes.items():
            if vid and self.data["terminal_volumes"].get(vid, {}).get("State") == "available":
                snapshots[label] = self.snapshot(label + "-snapshot", vid)
        self.wait_snapshots(snapshots)
        for label, sid in snapshots.items():
            if sid:
                self.read_bytes(label + "-bytes", sid)
        self.capture_events()
        self.defaults("after")
        self.data["capture_complete_at"] = now()
        self.save()

    def audit_markers(self):
        markers = super().audit_markers() + list(self.data["owned"]["volumes"])
        markers += [row["arn"] for row in self.data["owned"]["keys"]]
        markers += [row["arn"].rsplit("/", 1)[-1] for row in self.data["owned"]["keys"]]
        return markers

    def delete_snapshot(self, label, sid):
        deleted = self.data["cleanup"].setdefault("deleted_snapshots", [])
        if sid in deleted:
            return
        caller = "owner" if self.data["owned"]["snapshot_accounts"][sid] == self.args.account else "member"
        self.observe(label, "ec2", "delete_snapshot", {"SnapshotId": sid}, caller=caller)
        if self.data["calls"][-1]["code"] in ("Success", "InvalidSnapshot.NotFound"):
            deleted.append(sid)
        self.save()

    def cleanup_resources(self):
        deleted = self.data["cleanup"].setdefault("deleted_volumes", [])
        for vid, context in self.data["owned"]["volumes"].items():
            if vid not in deleted:
                self.observe("cleanup-delete-" + vid, "ec2", "delete_volume", {"VolumeId": vid}, caller=context["caller"])
                if self.data["calls"][-1]["code"] in ("Success", "InvalidVolume.NotFound"):
                    deleted.append(vid)
                self.save()
        for sid in reversed(self.data["owned"]["snapshots"]):
            self.delete_snapshot("cleanup-delete-" + sid, sid)
        scheduled = self.data["cleanup"].setdefault("keys_scheduled", [])
        for row in self.data["owned"]["keys"]:
            if row["arn"] not in scheduled:
                result = self.observe("cleanup-key-" + row["arn"].rsplit("/", 1)[-1], "kms", "schedule_key_deletion",
                    {"KeyId": row["arn"], "PendingWindowInDays": 7}, caller=row["caller"])
                if result.get("KeyState") == "PendingDeletion":
                    scheduled.append(row["arn"])
                self.save()
        remaining = {"volumes": [], "snapshots": []}
        for actor in ("owner", "member"):
            volumes = self.observe("cleanup-volume-inventory-" + actor, "ec2", "describe_volumes", caller=actor, required=True)
            remaining["volumes"] += [row for row in volumes["Volumes"] if row["VolumeId"] in self.data["owned"]["volumes"] and row["State"] != "deleting"]
            snapshots = self.observe("cleanup-snapshot-inventory-" + actor, "ec2", "describe_snapshots", {"OwnerIds": ["self"]}, caller=actor, required=True)
            remaining["snapshots"] += [row for row in snapshots["Snapshots"] if row["SnapshotId"] in self.data["owned"]["snapshots"]]
        self.data["cleanup"]["remaining"] = remaining
        self.save()
        if any(remaining.values()) or len(scheduled) != len(self.data["owned"]["keys"]):
            raise RuntimeError("Owned volume/snapshot/key cleanup incomplete")

    def cleanup_events(self):
        for actor, resource in self.data["owned"].get("events", {}).items():
            if self.data["cleanup"].get(actor + "_events_deleted"):
                continue
            self.observe(actor + "-remove-target", "events", "remove_targets", {"Rule": resource["rule"], "Ids": ["owned-volume-capture"]}, caller=actor)
            self.observe(actor + "-delete-rule", "events", "delete_rule", {"Name": resource["rule"]}, caller=actor)
            if self.data["calls"][-1]["code"] not in ("Success", "ResourceNotFoundException"):
                raise RuntimeError("Owned event rule cleanup failed")
            self.observe(actor + "-delete-queue", "sqs", "delete_queue", {"QueueUrl": resource["queue"]}, caller=actor)
            if self.data["calls"][-1]["code"] not in ("Success", "AWS.SimpleQueueService.NonExistentQueue"):
                raise RuntimeError("Owned event queue cleanup failed")
            self.data["cleanup"][actor + "_events_deleted"] = True
            self.save()

def summarize(path):
    data = json.loads(path.read_text())
    by_label = {row["label"]: row for row in data["calls"]}
    cases = {}
    for label, case in data["cases"].items():
        record = dict(case, response=by_label.get(label))
        if case.get("volume"):
            record["terminal"] = data["terminal_volumes"].get(case["volume"])
        if case.get("snapshot"):
            record["terminal"] = data["terminal_snapshots"].get(case["snapshot"])
        cases[label] = record
    contract = {
        "schema_version": 1, "source_script": "scripts/aws/ebs_volume_data_probe.py",
        "fixture": str(path), "documentation": data["documentation"],
        "account": data["account"], "member": data["member"], "region": data["region"],
        "captured_at": data["captured_at"], "capture_complete_at": data.get("capture_complete_at"),
        "scope": data["scope"], "payload": data["payload"],
        "cases": cases,
        "byte_reads": [{"label": row["label"], "snapshot": row["input"]["SnapshotId"],
            "block_index": row["input"]["BlockIndex"], "caller": row["caller"], "output": row["output"]}
            for row in data["calls"] if row["operation"] == "GetSnapshotBlock" and row["code"] == "Success"],
        "fresh_authority": data.get("fresh_authority"),
        "sessions": data["sessions"],
        "service_notifications": data.get("eventbridge"),
        "kms_audit": [row for row in data.get("cloudtrail", {}).get("events", []) if row["event"]["eventSource"] == "kms.amazonaws.com"],
        "ec2_audit": [row for row in data.get("cloudtrail", {}).get("events", []) if row["event"].get("eventName") in ("CreateVolume", "CreateSnapshot", "DeleteVolume")],
        "delivered_audit_objects": data.get("cloudtrail", {}).get("objects"),
        "defaults": [row for row in data["calls"] if row["operation"] in ("GetEbsEncryptionByDefault", "GetEbsDefaultKmsKeyId")],
        "owned": data["owned"], "cleanup": data["cleanup"], "gaps": data["gaps"],
        "boundary": "Finite native observations on owned synthetic resources; missing eventual records do not establish absence. No EC2 guest instances were created.",
    }
    destination = path.with_name(path.stem + "_contract.json")
    destination.write_text(json.dumps(sanitized(safe(contract)), indent=2) + "\n")
    print(json.dumps({"contract": str(destination), "cases": len(cases), "byte_reads": len(contract["byte_reads"]),
        "service_notifications": len((contract["service_notifications"] or {}).get("events", [])),
        "kms_audit": len(contract["kms_audit"]), "gaps": contract["gaps"]}), flush=True)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--member-account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/volume_data.json"))
    parser.add_argument("--completion-wait", type=int, default=600)
    parser.add_argument("--read-wait", type=int, default=600)
    parser.add_argument("--share-wait", type=int, default=90)
    parser.add_argument("--audit-wait", type=int, default=600)
    parser.add_argument("--audit-related", type=Path, action="append", default=[])
    parser.add_argument("--authority-case", action="append", default=[])
    parser.add_argument("--skip-trail", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--audit-only", action="store_true")
    mode.add_argument("--fresh-authority-only", action="store_true")
    mode.add_argument("--source-authority-only", action="store_true")
    mode.add_argument("--snapshot-controls-only", action="store_true")
    mode.add_argument("--summarize-only", action="store_true")
    args = parser.parse_args()
    if args.summarize_only:
        summarize(args.output)
        return
    capture = VolumeDataCapture(args)
    try:
        if args.audit_only:
            capture.audit()
        elif not args.cleanup_only:
            if args.fresh_authority_only:
                capture.fresh_authority()
            elif args.source_authority_only:
                capture.source_authority()
            elif args.snapshot_controls_only:
                capture.snapshot_controls()
            else:
                capture.run()
    finally:
        try:
            capture.cleanup_resources()
            if not args.cleanup_only and not args.audit_only:
                capture.audit()
            capture.capture_events()
        finally:
            capture.cleanup_events()
            capture.cleanup_audit()


if __name__ == "__main__":
    main()
