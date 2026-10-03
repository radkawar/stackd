#!/usr/bin/env python3
"""Observe cross-account EBS sharing using only owned synthetic snapshots.

The capture deletes snapshots and schedules its CMK for deletion before waiting
for trail delivery and deleting its trails/buckets. --defer-audit leaves only
the trails/buckets for a later --audit-only run; --cleanup-only removes every
remaining owned resource. No standing IAM role or account setting is changed.
STS credentials and block tokens stay in memory.
"""
import argparse
import json
from pathlib import Path
import time
import uuid

import boto3

from cloudtrail_events import CollectionError, collect_s3
from ebs_encryption_probe import BLOCK, CHECKSUM, CONFIG, Capture, allow, now, policy, safe

SERVICES = ("sts", "ebs", "ec2", "kms", "iam", "cloudtrail", "s3")
DOCS = [
    "https://docs.aws.amazon.com/ebs/latest/APIReference/API_StartSnapshot.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebsapi-permissions.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/logging-ebs-apis-using-cloudtrail.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebsapi-faq.html",
]


class SharingCapture(Capture):
    def __init__(self, args):
        self.args = args
        self.session = boto3.Session(region_name=args.region)
        self.clients = {name: self.session.client(name, config=CONFIG) for name in SERVICES}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != self.args.account:
            raise RuntimeError("Refusing writes outside authorized owner account")
        self.actors = {"owner": self.clients}
        self.tokens = {}
        if args.audit_only or args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.args.account or self.data["member"] != self.args.member_account or self.data["region"] != args.region:
                raise RuntimeError("Evidence ownership mismatch")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite live evidence")
            self.data = {"account": self.args.account, "member": self.args.member_account, "region": args.region,
                "prefix": "stackd-ebs-share-data-" + uuid.uuid4().hex[:12], "captured_at": now(),
                "identity": safe(identity), "documentation": DOCS, "sdk": {"boto3": boto3.__version__},
                "scope": "Owned 1-GiB logical snapshots with synthetic blocks; own CMK and account-local trails/buckets; no existing resource or default mutations",
                "owned": {"snapshots": [], "snapshot_accounts": {}, "audit": {}}, "sessions": {}, "calls": [], "cleanup": {}, "gaps": []}
        self.assume("member")
        self.save()

    def assume(self, label, statements=None, role_arn=None):
        parameters = {"RoleArn": role_arn or f"arn:aws:iam::{self.args.member_account}:role/OrganizationAccountAccessRole",
            "RoleSessionName": self.data["prefix"][-12:] + "-" + label, "DurationSeconds": 3600}
        if statements is not None:
            document = policy(statements)
            self.data["sessions"][label] = document
            parameters["Policy"] = json.dumps(document, separators=(",", ":"))
        response = self.clients["sts"].assume_role(**parameters)
        credentials = response["Credentials"]
        session = boto3.Session(region_name=self.args.region, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        self.actors[label] = {name: session.client(name, config=CONFIG) for name in SERVICES}
        identity = self.observe(label + "-identity", "sts", "get_caller_identity", caller=label, required=True)
        if identity["Account"] != self.args.member_account:
            raise RuntimeError("Recipient identity mismatch")
        return self.actors[label]["ebs"]

    def observe(self, label, service, method, parameters=None, *, client=None, caller="owner", required=False):
        output = super().observe(label, service, method, parameters, client=client or self.actors[caller][service], caller=caller, required=required)
        if service == "ebs" and method == "start_snapshot" and output:
            self.data["owned"]["snapshot_accounts"][output["SnapshotId"]] = output["OwnerId"]
            self.save()
        return output

    def finish(self, label, snapshot, *, block=False, caller="owner"):
        if not snapshot:
            return
        sid = snapshot["SnapshotId"]
        if block:
            self.observe(label + "-put", "ebs", "put_snapshot_block", {"SnapshotId": sid, "BlockIndex": 0,
                "BlockData": BLOCK, "DataLength": len(BLOCK), "Checksum": CHECKSUM, "ChecksumAlgorithm": "SHA256"}, caller=caller, required=True)
        self.observe(label + "-complete", "ebs", "complete_snapshot", {"SnapshotId": sid, "ChangedBlocksCount": int(block)}, caller=caller, required=True)

    def ready(self, label, sid, caller="owner"):
        for attempt in range(180):
            result = self.observe(label + "-readiness-" + str(attempt), "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, caller=caller)
            if self.data["calls"][-1]["code"] == "Success":
                return result
            time.sleep(5)
        raise RuntimeError(label + " did not become readable")

    def read_data(self, label, sid, caller="member", token=None):
        if token:
            self.observe(label + "-old-token-get", "ebs", "get_snapshot_block", {"SnapshotId": sid, "BlockIndex": 0, "BlockToken": token}, caller=caller)
        result = self.observe(label + "-list", "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, caller=caller)
        if result.get("Blocks"):
            token = result["Blocks"][0]["BlockToken"]
        if token:
            self.observe(label + "-get", "ebs", "get_snapshot_block", {"SnapshotId": sid, "BlockIndex": 0, "BlockToken": token}, caller=caller)
        return token

    def share(self, label, sid, operation="add"):
        self.observe(label, "ec2", "modify_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission",
            "OperationType": operation, "UserIds": [self.args.member_account]}, required=True)

    def describe(self, phase, sid):
        filters = [{"Name": "snapshot-id", "Values": [sid]}]
        cases = [("ids", {"SnapshotIds": [sid]}), ("owner", {"OwnerIds": [self.args.account], "Filters": filters}),
            ("self-owned", {"OwnerIds": ["self"], "Filters": filters}),
            ("restorable-self", {"RestorableByUserIds": ["self"], "Filters": filters}),
            ("restorable-member", {"RestorableByUserIds": [self.args.member_account], "Filters": filters}),
            ("restorable-owner", {"RestorableByUserIds": [self.args.account], "Filters": filters})]
        for suffix, parameters in cases:
            self.observe(phase + "-describe-" + suffix, "ec2", "describe_snapshots", parameters, caller="member")
        self.observe(phase + "-owner-describe", "ec2", "describe_snapshots", {"SnapshotIds": [sid]})

    def setup_audit(self):
        for actor, account in (("owner", self.args.account), ("member", self.args.member_account)):
            name = self.data["prefix"] + "-" + actor
            arn = f"arn:aws:cloudtrail:{self.args.region}:{account}:trail/{name}"
            self.observe(actor + "-create-bucket", "s3", "create_bucket", {"Bucket": name}, caller=actor, required=True)
            self.data["owned"]["audit"][actor] = {"bucket": name, "trail": name, "arn": arn}
            self.save()
            document = policy([
                {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::" + name, "Condition": {"StringEquals": {"aws:SourceArn": arn}}},
                {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{name}/AWSLogs/{account}/*", "Condition": {"StringEquals": {"aws:SourceArn": arn, "s3:x-amz-acl": "bucket-owner-full-control"}}}])
            self.observe(actor + "-bucket-policy", "s3", "put_bucket_policy", {"Bucket": name, "Policy": json.dumps(document)}, caller=actor, required=True)
            self.observe(actor + "-create-trail", "cloudtrail", "create_trail", {"Name": name, "S3BucketName": name, "IsMultiRegionTrail": False, "IncludeGlobalServiceEvents": False}, caller=actor, required=True)
            selectors = [{"Name": "snapshot-data", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::EC2::Snapshot"]}]},
                {"Name": "management", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]
            self.observe(actor + "-trail-selectors", "cloudtrail", "put_event_selectors", {"TrailName": name, "AdvancedEventSelectors": selectors}, caller=actor, required=True)
            self.observe(actor + "-start-logging", "cloudtrail", "start_logging", {"Name": name}, caller=actor, required=True)
        time.sleep(15)

    def run(self):
        self.setup_audit()
        for actor in ("owner", "member"):
            self.observe(actor + "-encryption-default", "ec2", "get_ebs_encryption_by_default", caller=actor, required=True)
        self.observe("create-owned-key", "kms", "create_key", {"Description": self.data["prefix"], "Tags": [{"TagKey": "suite", "TagValue": self.data["prefix"]}]}, required=True)
        key = self.data["owned"]["key"]
        plain = self.start("plain-source")
        encrypted = self.start("encrypted-source", Encrypted=True, KmsKeyArn=key)
        for label, snapshot in (("plain", plain), ("encrypted", encrypted)):
            self.finish(label, snapshot, block=True)
        for label, snapshot in (("plain", plain), ("encrypted", encrypted)):
            sid = snapshot["SnapshotId"]
            self.ready(label, sid)
            self.tokens[label + "-owner"] = self.read_data(label + "-owner", sid, "owner")
            self.describe(label + "-private", sid)
            self.read_data(label + "-private", sid, token=self.tokens[label + "-owner"])
            child = self.start(label + "-private-parent", caller="member", ParentSnapshotId=sid)
            self.finish(label + "-private-parent", child, caller="member")
            self.share(label + "-share", sid)
            self.describe(label + "-shared", sid)
            # EC2 metadata propagation and EBS data visibility are separate gates.
            # Keep owner-readable proof before allowing this bounded share window.
            self.observe(label + "-owner-after-share", "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, required=True)
            time.sleep(self.args.share_wait)
            self.tokens[label + "-shared"] = self.read_data(label + "-shared", sid, token=self.tokens[label + "-owner"])
            child = self.start(label + "-shared-parent", caller="member", ParentSnapshotId=sid)
            self.finish(label + "-shared-parent", child, caller="member")
            if child:
                self.data.setdefault("children", {})[label] = child["SnapshotId"]
        self.data["early_contract_ready_at"] = now()
        self.save()
        print("EARLY_CONTRACT_READY " + str(self.args.output), flush=True)
        self.authority(plain["SnapshotId"], encrypted["SnapshotId"], key)
        for label, snapshot in (("plain", plain), ("encrypted", encrypted)):
            sid = snapshot["SnapshotId"]
            self.mutation_checks(label, sid)
            self.share(label + "-revoke", sid, "remove")
            time.sleep(self.args.revoke_wait)
            self.describe(label + "-revoked", sid)
            self.read_data(label + "-revoked", sid, token=self.tokens[label + "-shared"])
            self.share(label + "-reshare", sid)
            time.sleep(self.args.share_wait)
            self.read_data(label + "-reshared-old-token", sid, token=self.tokens[label + "-shared"])
            self.observe(label + "-reset", "ec2", "reset_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission"}, required=True)
            time.sleep(self.args.revoke_wait)
            self.describe(label + "-reset", sid)
            self.read_data(label + "-reset", sid, token=self.tokens[label + "-shared"])
        self.lineage(plain["SnapshotId"], encrypted["SnapshotId"])
        self.data["capture_complete_at"] = now()
        self.save()

    def mutation_checks(self, label, sid):
        for suffix, method, parameters in [
            ("permission-read", "describe_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission"}),
            ("permission-add", "modify_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission", "OperationType": "add", "UserIds": [self.args.member_account]}),
            ("permission-reset", "reset_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission"}),
            ("source-delete", "delete_snapshot", {"SnapshotId": sid}),
            ("tag-write", "create_tags", {"Resources": [sid], "Tags": [{"Key": "recipient", "Value": "synthetic"}]})]:
            self.observe(label + "-member-" + suffix, "ec2", method, parameters, caller="member")
        self.observe(label + "-member-source-complete", "ebs", "complete_snapshot", {"SnapshotId": sid, "ChangedBlocksCount": 0}, caller="member")
        self.observe(label + "-member-source-put", "ebs", "put_snapshot_block", {"SnapshotId": sid, "BlockIndex": 0, "BlockData": BLOCK, "DataLength": len(BLOCK), "Checksum": CHECKSUM, "ChecksumAlgorithm": "SHA256"}, caller="member")
        self.describe(label + "-after-recipient-mutations", sid)

    def authority(self, plain, encrypted, key):
        reads = ["ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock", "ebs:ListChangedBlocks"]
        source_arn = f"arn:aws:ec2:{self.args.region}::snapshot/{plain}"
        self.no_identity_authority(plain)
        for label, statements in [
            ("implicit-session-deny", [allow("ec2:DescribeSnapshots", "*")]),
            ("resource-account-owner", [allow(reads, source_arn, {"StringEquals": {"aws:ResourceAccount": self.args.account}})]),
            ("resource-account-member", [allow(reads, source_arn, {"StringEquals": {"aws:ResourceAccount": self.args.member_account}})]),
            ("deny-list", [allow("*", "*"), {"Effect": "Deny", "Action": "ebs:ListSnapshotBlocks", "Resource": "*"}]),
            ("deny-get", [allow("*", "*"), {"Effect": "Deny", "Action": "ebs:GetSnapshotBlock", "Resource": "*"}]),
            ("deny-describe", [allow("*", "*"), {"Effect": "Deny", "Action": "ec2:DescribeSnapshots", "Resource": "*"}])]:
            self.assume(label, statements)
            self.read_data(label, plain, label, self.tokens["plain-shared"])
        key_policy = policy([
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.account}:root"}, "Action": "kms:*", "Resource": "*"},
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{self.args.member_account}:root"}, "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKey", "kms:ReEncrypt*"], "Resource": "*"}])
        self.observe("allow-member-owned-key", "kms", "put_key_policy", {"KeyId": key, "PolicyName": "default", "Policy": json.dumps(key_policy)}, required=True)
        time.sleep(10)
        self.tokens["encrypted-shared"] = self.read_data("encrypted-key-shared", encrypted, token=self.tokens["encrypted-owner"])
        child = self.start("encrypted-key-shared-parent", caller="member", ParentSnapshotId=encrypted)
        self.finish("encrypted-key-shared-parent", child, caller="member")
        if child:
            self.data.setdefault("children", {})["encrypted"] = child["SnapshotId"]
        for label, action in (("deny-kms-decrypt", "kms:Decrypt"), ("deny-kms-generate", "kms:GenerateDataKeyWithoutPlaintext"), ("deny-kms-grant", "kms:CreateGrant")):
            self.assume(label, [allow("*", "*"), {"Effect": "Deny", "Action": action, "Resource": key}])
            self.read_data(label, encrypted, label, self.tokens["encrypted-shared"])
            child = self.start(label + "-parent", caller=label, ParentSnapshotId=encrypted)
            self.finish(label + "-parent", child, caller="member")
        self.parent_authority(plain)

    def no_identity_authority(self, sid):
        name = self.data["prefix"] + "-unprivileged"
        response = self.observe("create-unprivileged-member-role", "iam", "create_role", {"RoleName": name,
            "AssumeRolePolicyDocument": json.dumps(policy([{"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}]))},
            caller="member", required=True)
        self.data["owned"]["member_role"] = name
        self.save()
        time.sleep(15)
        self.assume("no-identity-allow", role_arn=response["Role"]["Arn"])
        self.read_data("no-identity-allow", sid, "no-identity-allow", self.tokens["plain-shared"])

    def parent_authority(self, sid):
        source = f"arn:aws:ec2:{self.args.region}::snapshot/{sid}"
        snapshots = f"arn:aws:ec2:{self.args.region}::snapshot/*"
        for label, statements in [
            ("parent-start-only", [allow("ebs:StartSnapshot", snapshots)]),
            ("parent-deny-source-start", [allow("ebs:StartSnapshot", snapshots), {"Effect": "Deny", "Action": "ebs:StartSnapshot", "Resource": source}]),
            ("parent-deny-source-reads", [allow("ebs:StartSnapshot", snapshots), {"Effect": "Deny", "Action": ["ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock", "ec2:DescribeSnapshots"], "Resource": "*"}]),
            ("parent-owner-resource-account", [allow("ebs:StartSnapshot", snapshots, {"StringEquals": {"aws:ResourceAccount": self.args.account}})]),
            ("parent-member-resource-account", [allow("ebs:StartSnapshot", snapshots, {"StringEquals": {"aws:ResourceAccount": self.args.member_account}})])]:
            self.assume(label, statements)
            child = self.start(label, caller=label, tagged=False, ParentSnapshotId=sid)
            self.finish(label, child, caller="member")

    def tag_views(self, label, sid):
        for actor in ("owner", "member"):
            self.observe(label + "-" + actor + "-tags", "ec2", "describe_tags", {"Filters": [{"Name": "resource-id", "Values": [sid]}]}, caller=actor)
            self.observe(label + "-" + actor + "-snapshots", "ec2", "describe_snapshots", {"SnapshotIds": [sid]}, caller=actor)
            for value in (self.data["prefix"], "recipient"):
                self.observe(label + "-" + actor + "-tag-filter-" + value, "ec2", "describe_snapshots",
                    {"Filters": [{"Name": "snapshot-id", "Values": [sid]}, {"Name": "tag:suite", "Values": [value]}]}, caller=actor)

    def tag_probe(self):
        snapshot = self.start("tag-source")
        sid = snapshot["SnapshotId"]
        self.finish("tag-source", snapshot)
        time.sleep(15)
        tag = {"Resources": [sid], "Tags": [{"Key": "suite", "Value": "recipient"}]}
        self.observe("private-recipient-create-tags", "ec2", "create_tags", tag, caller="member")
        self.share("tag-source-share", sid)
        self.observe("shared-recipient-create-tags", "ec2", "create_tags", tag, caller="member", required=True)
        self.tag_views("shared", sid)
        arn = f"arn:aws:ec2:{self.args.region}::snapshot/{sid}"
        for condition in ("ec2:Owner", "aws:ResourceAccount"):
            for suffix, account in (("owner", self.args.account), ("member", self.args.member_account)):
                label = condition.replace(":", "-") + "-" + suffix
                self.assume(label, [allow("ec2:CreateTags", arn, {"StringEquals": {condition: account}})])
                self.observe(label, "ec2", "create_tags", {"Resources": [sid], "Tags": [{"Key": label, "Value": "synthetic"}]}, caller=label)
        self.share("tag-source-revoke", sid, "remove")
        self.observe("revoked-owner-permissions", "ec2", "describe_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission"}, required=True)
        time.sleep(self.args.revoke_wait)
        self.tag_views("revoked", sid)
        self.observe("revoked-recipient-create-tags", "ec2", "create_tags", {"Resources": [sid], "Tags": [{"Key": "after-revoke", "Value": "synthetic"}]}, caller="member")
        self.observe("revoked-recipient-delete-tags", "ec2", "delete_tags", {"Resources": [sid], "Tags": [{"Key": "suite"}]}, caller="member")
        self.tag_views("revoked-after-delete-tag", sid)
        self.data["capture_complete_at"] = now()
        self.save()

    def pair_probe(self):
        source = self.start("pair-source")
        self.finish("pair-source", source, block=True)
        self.ready("pair-source", source["SnapshotId"])
        child = self.start("pair-owner-child", ParentSnapshotId=source["SnapshotId"])
        self.finish("pair-owner-child", child)
        member = self.start("pair-member-root", caller="member")
        self.finish("pair-member-root", member, block=True, caller="member")
        for label, snapshot, actor in (("child", child, "owner"), ("member", member, "member")):
            self.ready("pair-" + label, snapshot["SnapshotId"], actor)
        source_id, child_id, member_id = source["SnapshotId"], child["SnapshotId"], member["SnapshotId"]
        for label, sid in (("source", source_id), ("child", child_id)):
            self.share("pair-share-" + label, sid)
        time.sleep(self.args.share_wait)
        self.read_data("pair-shared-source", source_id)
        self.read_data("pair-shared-child", child_id)
        for label, first, second, actor in (
            ("shared-lineage", source_id, child_id, "member"),
            ("owner-lineage", source_id, child_id, "owner"),
            ("cross-owner-forward", source_id, member_id, "member"),
            ("cross-owner-reverse", member_id, source_id, "member")):
            self.observe(label, "ebs", "list_changed_blocks", {"FirstSnapshotId": first, "SecondSnapshotId": second}, caller=actor)
        self.share("pair-revoke-child", child_id, "remove")
        time.sleep(self.args.revoke_wait)
        self.observe("shared-first-private-second", "ebs", "list_changed_blocks", {"FirstSnapshotId": source_id, "SecondSnapshotId": child_id}, caller="member")
        self.observe("private-first-shared-second", "ebs", "list_changed_blocks", {"FirstSnapshotId": child_id, "SecondSnapshotId": source_id}, caller="member")
        self.observe("public-setting-observation", "ec2", "get_snapshot_block_public_access_state")
        self.observe("public-and-private-share", "ec2", "modify_snapshot_attribute", {"SnapshotId": source_id,
            "Attribute": "createVolumePermission", "OperationType": "add", "GroupNames": ["all"]})
        if self.data["calls"][-1]["code"] == "Success":
            time.sleep(self.args.share_wait)
            self.read_data("owner-public-and-private", source_id, "owner")
            self.read_data("member-public-and-private", source_id)
            self.share("remove-private-keep-public", source_id, "remove")
            time.sleep(self.args.share_wait)
            self.read_data("owner-public-only", source_id, "owner")
            self.read_data("member-public-only", source_id)
            self.observe("revoke-owned-public-share", "ec2", "reset_snapshot_attribute", {"SnapshotId": source_id, "Attribute": "createVolumePermission"}, required=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def self_permission_limits(self, sid):
        self.observe("self-limits-before", "ec2", "describe_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission"}, required=True)
        for count in (500, 501):
            self.observe("canonical-self-add-" + str(count), "ec2", "modify_snapshot_attribute", {"SnapshotId": sid,
                "CreateVolumePermission": {"Add": [{"UserId": self.args.account}] * count}})
            self.observe("legacy-self-add-" + str(count), "ec2", "modify_snapshot_attribute", {"SnapshotId": sid,
                "Attribute": "createVolumePermission", "OperationType": "add", "UserIds": [self.args.account] * count})
        self.observe("self-limits-after", "ec2", "describe_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission"}, required=True)

    def public_token_probe(self):
        snapshot = self.start("public-token-source")
        sid = snapshot["SnapshotId"]
        self.finish("public-token-source", snapshot, block=True)
        self.ready("public-token-source", sid)
        self.self_permission_limits(sid)
        self.share("public-token-private-share", sid)
        time.sleep(self.args.share_wait)
        token = self.read_data("public-token-private", sid)
        self.observe("public-token-setting", "ec2", "get_snapshot_block_public_access_state")
        self.observe("public-token-add-public", "ec2", "modify_snapshot_attribute", {"SnapshotId": sid,
            "Attribute": "createVolumePermission", "OperationType": "add", "GroupNames": ["all"]})
        if self.data["calls"][-1]["code"] == "Success":
            time.sleep(self.args.share_wait)
            self.read_data("public-token-both", sid, token=token)
            self.share("public-token-remove-private", sid, "remove")
            time.sleep(self.args.share_wait)
            self.read_data("public-token-public-only", sid, token=token)
            self.observe("public-token-reset", "ec2", "reset_snapshot_attribute", {"SnapshotId": sid, "Attribute": "createVolumePermission"}, required=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def lineage(self, plain, encrypted):
        children = self.data.get("children", {})
        for label, sid in (("plain", plain), ("encrypted", encrypted)):
            child = children.get(label)
            if not child:
                continue
            self.ready(label + "-child", child, "member")
            self.read_data(label + "-child-after-source-reset", child)
            self.share(label + "-share-for-pair", sid)
            for suffix, first, second, actor in (("forward-member", sid, child, "member"), ("reverse-member", child, sid, "member"), ("forward-owner", sid, child, "owner")):
                self.observe(label + "-pair-" + suffix, "ebs", "list_changed_blocks", {"FirstSnapshotId": first, "SecondSnapshotId": second}, caller=actor)
            self.observe(label + "-source-delete-owner", "ec2", "delete_snapshot", {"SnapshotId": sid}, required=True)
            self.data["cleanup"].setdefault("deleted_snapshots", []).append(sid)
            self.read_data(label + "-child-after-source-delete", child)
            self.observe(label + "-child-describe", "ec2", "describe_snapshots", {"SnapshotIds": [child]}, caller="member")
        self.observe("post-reset-unrelated-pair", "ebs", "list_changed_blocks", {"FirstSnapshotId": plain, "SecondSnapshotId": encrypted}, caller="member")

    def cleanup_snapshots(self):
        deleted = self.data["cleanup"].setdefault("deleted_snapshots", [])
        untagged = self.data["cleanup"].setdefault("recipient_tags_removed", [])
        for sid in reversed(self.data["owned"]["snapshots"]):
            if sid not in untagged:
                self.observe("cleanup-recipient-tags-" + sid, "ec2", "delete_tags", {"Resources": [sid]}, caller="member")
                result = self.observe("cleanup-recipient-tags-verify-" + sid, "ec2", "describe_tags",
                    {"Filters": [{"Name": "resource-id", "Values": [sid]}]}, caller="member", required=True)
                if result["Tags"]:
                    raise RuntimeError("Owned recipient tag cleanup incomplete")
                untagged.append(sid)
            if sid in deleted:
                continue
            actor = "owner" if self.data["owned"]["snapshot_accounts"].get(sid, self.args.account) == self.args.account else "member"
            self.observe("cleanup-delete-" + sid, "ec2", "delete_snapshot", {"SnapshotId": sid}, caller=actor)
            if self.data["calls"][-1]["code"] in ("Success", "InvalidSnapshot.NotFound"):
                deleted.append(sid)
        remaining = []
        for actor in ("owner", "member"):
            result = self.observe(actor + "-cleanup-inventory", "ec2", "describe_snapshots", {"OwnerIds": ["self"], "Filters": [{"Name": "description", "Values": [self.data["prefix"] + "-*"]}]}, caller=actor, required=True)
            remaining += [item["SnapshotId"] for item in result["Snapshots"]]
        self.data["cleanup"]["remaining_snapshots"] = remaining
        role = self.data["owned"].get("member_role")
        if role and not self.data["cleanup"].get("member_role_deleted"):
            self.observe("cleanup-member-role", "iam", "delete_role", {"RoleName": role}, caller="member")
            if self.data["calls"][-1]["code"] not in ("Success", "NoSuchEntity"):
                raise RuntimeError("Owned member role cleanup failed")
            self.data["cleanup"]["member_role_deleted"] = True
        key = self.data["owned"].get("key")
        if key and not self.data["cleanup"].get("key_deletion_scheduled"):
            result = self.observe("cleanup-key", "kms", "schedule_key_deletion", {"KeyId": key, "PendingWindowInDays": 7}, required=True)
            self.data["cleanup"]["key_deletion_scheduled"] = safe(result)
        self.save()
        if remaining:
            raise RuntimeError("Owned snapshot cleanup incomplete")

    def audit_markers(self):
        owned = self.data["owned"]
        return owned["snapshots"] + [self.data["prefix"]] + ([owned["key"]] if owned.get("key") else [])

    def audit(self):
        audit = self.data.setdefault("cloudtrail", {"events": [], "objects": [], "observations": []})
        fields = ("events", "objects", "pages", "observations", "errors")
        collections = {
            actor: {field: [{key: value for key, value in row.items() if key != "account"}
                            for row in audit.get(field, []) if row["account"] == actor]
                    for field in fields}
            for actor in self.data["owned"]["audit"]
        }
        for field in fields:
            audit.setdefault(field, [])
        requests = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("request_id")}
        markers = self.audit_markers()
        audit["related_fixtures"] = [str(path) for path in self.args.audit_related]
        for path in self.args.audit_related:
            related = json.loads(path.read_text())
            if related["account"] != self.args.account or related["member"] != self.args.member_account or related["region"] != self.args.region:
                raise RuntimeError("Related evidence ownership mismatch")
            markers += related["owned"]["snapshots"] + [related["prefix"]]
            requests.update({row["request_id"]: path.name + ":" + row["label"] for row in related["calls"] if row.get("request_id")})

        def owned_event(event):
            text = json.dumps(event)
            return any(marker in text for marker in markers)

        deadline = time.monotonic() + self.args.audit_wait
        while True:
            for actor, resource in self.data["owned"]["audit"].items():
                if self.data["cleanup"].get(actor + "_audit_deleted"):
                    continue
                client = self.actors[actor]["s3"]
                previous = collections[actor]
                collected = None
                try:
                    collected = collect_s3(
                        lambda parameters: client.list_objects_v2(**parameters),
                        lambda parameters: client.get_object(**parameters),
                        requests, bucket=resource["bucket"], related=owned_event,
                        previous=previous)
                except CollectionError as error:
                    collected = error.result
                    raise
                finally:
                    if collected is not None:
                        collections[actor] = collected
                        for field in fields:
                            audit[field] = [{"account": account, **safe(row)}
                                            for account, result in collections.items()
                                            for row in result[field]]
                        audit.setdefault("bounds", {})[actor] = collected["bounds"]
                        audit["page_cap_reached"] = audit.get("page_cap_reached", False) or any(value.get("page_cap_reached", False) for value in collections.values())
                        audit["partial"] = audit.get("partial", False) or any(value.get("partial", False) for value in collections.values())
                        found = {row["event"].get("requestID") for row in audit["events"] if row["call_label"] is not None}
                        audit["missing_request_ids"] = [request_id for request_id in requests if request_id not in found]
                        audit["missing_calls"] = [requests[request_id] for request_id in audit["missing_request_ids"]]
                        audit["captured_at"] = now()
                        audit["boundary"] = collected["boundary"]
                        self.save()
            if time.monotonic() >= deadline:
                break
            time.sleep(min(30, max(0, deadline - time.monotonic())))
        audit["captured_at"] = now()
        audit.setdefault("boundary", "Positive delivered records only; missing eventual records do not establish absence.")
        self.save()
        print(json.dumps({"audit_events": len(audit["events"]), "objects": len(audit["objects"])}), flush=True)

    def cleanup_audit(self):
        for actor, resource in self.data["owned"]["audit"].items():
            if self.data["cleanup"].get(actor + "_audit_deleted"):
                continue
            self.observe(actor + "-stop-trail", "cloudtrail", "stop_logging", {"Name": resource["trail"]}, caller=actor)
            self.observe(actor + "-delete-trail", "cloudtrail", "delete_trail", {"Name": resource["trail"]}, caller=actor)
            if self.data["calls"][-1]["code"] not in ("Success", "TrailNotFoundException"):
                raise RuntimeError("Owned trail cleanup failed")
            client = self.actors[actor]["s3"]
            for page in client.get_paginator("list_objects_v2").paginate(Bucket=resource["bucket"]):
                if page.get("Contents"):
                    self.observe(actor + "-delete-log-objects", "s3", "delete_objects", {"Bucket": resource["bucket"], "Delete": {"Objects": [{"Key": item["Key"]} for item in page["Contents"]]}}, caller=actor, required=True)
            self.observe(actor + "-delete-bucket", "s3", "delete_bucket", {"Bucket": resource["bucket"]}, caller=actor, required=True)
            self.data["cleanup"][actor + "_audit_deleted"] = True
            self.save()
        self.data["cleanup"]["finished_at"] = now()
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--member-account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/sharing_data.json"))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--audit-only", action="store_true")
    group.add_argument("--cleanup-only", action="store_true")
    group.add_argument("--tags-only", action="store_true")
    group.add_argument("--pairs-only", action="store_true")
    group.add_argument("--public-token-only", action="store_true")
    parser.add_argument("--audit-wait", type=int, default=600)
    parser.add_argument("--audit-related", type=Path, action="append", default=[])
    parser.add_argument("--defer-audit", action="store_true")
    parser.add_argument("--share-wait", type=int, default=120)
    parser.add_argument("--revoke-wait", type=int, default=65)
    args = parser.parse_args()
    capture = SharingCapture(args)
    if args.cleanup_only:
        capture.cleanup_snapshots()
        capture.cleanup_audit()
    elif args.audit_only:
        try:
            capture.audit()
        finally:
            capture.cleanup_audit()
    else:
        try:
            if args.tags_only:
                capture.tag_probe()
            elif args.pairs_only:
                capture.pair_probe()
            elif args.public_token_only:
                capture.public_token_probe()
            else:
                capture.run()
        except BaseException:
            capture.cleanup_audit()
            raise
        finally:
            capture.cleanup_snapshots()
        if capture.data["owned"]["audit"] and not args.defer_audit:
            try:
                capture.audit()
            finally:
                capture.cleanup_audit()


if __name__ == "__main__":
    main()
