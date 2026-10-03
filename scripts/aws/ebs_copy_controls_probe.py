#!/usr/bin/env python3
"""Capture owned, unencrypted CopySnapshot controls and management events.

Only empty 1-GiB direct snapshots are used. Each invocation accepts at most ten
copy target IDs. The default run owns two management trails and EventBridge/SQS
completion capture targets; focused IAM/public modes avoid extra audit resources.
Account settings and standing roles are never changed. Session secrets and
presigned URLs remain in memory. --cleanup-only resumes owned cleanup;
--audit-only harvests still-owned trails after an interrupted run, then removes
them. --context-source only makes read and DryRun calls on an existing owned source.
"""
import argparse
import json
from pathlib import Path
import re
import time
import urllib.request
import uuid

import boto3
from botocore.exceptions import ClientError
from botocore.handlers import inject_presigned_url_ec2

from ebs_encryption_probe import CONFIG, Capture, allow, now, policy, safe
from ebs_sharing_data_probe import SERVICES, SharingCapture

SAR = "https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json"
DOCS = [
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CopySnapshot.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-copy-snapshot.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/security_iam_id-based-policy-examples.html#iam-copy-snapshot",
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-cloud-watch-events.html#copy-snapshot-complete",
    SAR,
]


def sanitized(value):
    value = safe(value)
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower() in ("presignedurl", "x-amz-security-token", "x-amz-signature", "x-amz-credential") else sanitized(child)
                for key, child in value.items()}
    if isinstance(value, list):
        return [sanitized(child) for child in value]
    if isinstance(value, str):
        return re.sub(r"https?://[^\s\"<>]*[?&]X-Amz-[^\s\"<>]*", "<redacted-presigned-url>", value, flags=re.I)
    return value


class CopyCapture(SharingCapture):
    def __init__(self, args):
        super().__init__(args)
        if not args.audit_only and not args.cleanup_only:
            self.data.update(prefix="stackd-ebs-copy-controls-" + uuid.uuid4().hex[:12], documentation=DOCS,
                scope="Owned empty 1-GiB source, at most ten copies, temporary bounded owner role and owner/member trails; no standing resource/default changes",
                source_region=args.region, target_region=args.region,
                sdk_signing="botocore automatic CopySnapshot presigning disabled: plain source requires no PresignedUrl; preserves explicit DestinationRegion and missing-field wire cases",
                payload={"recipe": "Empty 1-GiB logical snapshot; ChangedBlocksCount=0"})
            with urllib.request.urlopen(SAR, timeout=30) as response:
                reference = json.load(response)
            self.data["service_authorization_reference"] = {"url": SAR, "retrieved_at": now(),
                "actions": [row for row in reference["Actions"] if row["Name"] in ("CopySnapshot", "CreateTags")],
                "resource": [row for row in reference["Resources"] if row["Name"] == "snapshot"]}
        self.data["owned"].setdefault("copies", {})
        for clients in self.actors.values():
            self.raw_copy(clients["ec2"])
            credentials = clients["ec2"]._request_signer._credentials.get_frozen_credentials()
            session = boto3.Session(region_name=args.region, aws_access_key_id=credentials.access_key,
                aws_secret_access_key=credentials.secret_key, aws_session_token=credentials.token)
            for service in ("sqs", "events"):
                clients[service] = session.client(service, config=CONFIG)
        self.save()

    @staticmethod
    def raw_copy(client):
        client.meta.events.unregister("before-call.ec2.CopySnapshot", inject_presigned_url_ec2)

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(sanitized(self.data), indent=2) + "\n")

    def observe(self, label, service, method, parameters=None, *, client=None, caller="owner", required=False):
        output = super().observe(label, service, method, parameters, client=client, caller=caller, required=required)
        row = self.data["calls"][-1]
        row["target_region"] = (client or self.actors[caller][service]).meta.region_name
        if service == "ec2" and method == "copy_snapshot":
            row["source_region"] = (parameters or {}).get("SourceRegion")
            if output.get("SnapshotId"):
                sid = output["SnapshotId"]
                self.data["owned"]["snapshots"].append(sid)
                self.data["owned"]["copies"][sid] = {"label": label, "caller": caller,
                    "account": self.args.member_account if caller.startswith("member") else self.args.account}
                self.data["owned"]["snapshot_accounts"][sid] = self.data["owned"]["copies"][sid]["account"]
        encoded = re.search(r"Encoded authorization failure message: (\S+)", row.get("error", {}).get("Message", ""))
        if encoded:
            try:
                decoded = self.clients["sts"].decode_authorization_message(EncodedMessage=encoded[1])
                row["decoded_authorization"] = sanitized(json.loads(decoded["DecodedMessage"]))
            except ClientError as error:
                row["authorization_decode_error"] = error.response["Error"]
        self.save()
        return output

    def setup_events(self):
        for actor, account in (("owner", self.args.account), ("member", self.args.member_account)):
            name = self.data["prefix"] + "-" + actor
            result = self.observe(actor + "-event-queue", "sqs", "create_queue", {"QueueName": name}, caller=actor, required=True)
            queue = result["QueueUrl"]
            arn = f"arn:aws:sqs:{self.args.region}:{account}:{name}"
            rule_arn = f"arn:aws:events:{self.args.region}:{account}:rule/{name}"
            self.data["owned"].setdefault("events", {})[actor] = {"queue": queue, "rule": name}
            self.save()
            document = policy([{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}])
            self.observe(actor + "-event-queue-policy", "sqs", "set_queue_attributes",
                {"QueueUrl": queue, "Attributes": {"Policy": json.dumps(document)}}, caller=actor, required=True)
            self.observe(actor + "-event-rule", "events", "put_rule", {"Name": name, "State": "ENABLED",
                "EventPattern": json.dumps({"source": ["aws.ec2"], "detail-type": ["EBS Snapshot Notification"],
                    "detail": {"event": ["copySnapshot"]}})}, caller=actor, required=True)
            result = self.observe(actor + "-event-target", "events", "put_targets",
                {"Rule": name, "Targets": [{"Id": "owned-copy-capture", "Arn": arn}]}, caller=actor, required=True)
            if result.get("FailedEntryCount"):
                raise RuntimeError("Owned event target setup failed")

    def capture_events(self):
        evidence = self.data.setdefault("eventbridge", {"events": [], "boundary": "Positive received records only; missing events do not establish absence"})
        seen = {row["event"]["id"] for row in evidence["events"]}
        markers = list(self.data["owned"]["snapshots"])
        for path in self.args.audit_related:
            if path.exists():
                related = json.loads(path.read_text())
                markers += related.get("owned", {}).get("snapshots", [])
        for actor, resource in self.data["owned"].get("events", {}).items():
            client = self.actors[actor]["sqs"]
            if self.data["cleanup"].get(actor + "_events_deleted"):
                continue
            while True:
                result = client.receive_message(QueueUrl=resource["queue"], MaxNumberOfMessages=10, WaitTimeSeconds=1)
                messages = result.get("Messages", [])
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

    def cleanup_events(self):
        for actor, resource in self.data["owned"].get("events", {}).items():
            if self.data["cleanup"].get(actor + "_events_deleted"):
                continue
            self.observe(actor + "-remove-event-target", "events", "remove_targets",
                {"Rule": resource["rule"], "Ids": ["owned-copy-capture"]}, caller=actor)
            self.observe(actor + "-delete-event-rule", "events", "delete_rule", {"Name": resource["rule"]}, caller=actor)
            if self.data["calls"][-1]["code"] not in ("Success", "ResourceNotFoundException"):
                raise RuntimeError("Owned event rule cleanup failed")
            self.observe(actor + "-delete-event-queue", "sqs", "delete_queue", {"QueueUrl": resource["queue"]}, caller=actor)
            if self.data["calls"][-1]["code"] not in ("Success", "AWS.SimpleQueueService.NonExistentQueue"):
                raise RuntimeError("Owned event queue cleanup failed")
            self.data["cleanup"][actor + "_events_deleted"] = True
            self.save()

    def actor(self, label, statements, *, member=False):
        role = f"arn:aws:iam::{self.args.member_account}:role/OrganizationAccountAccessRole" if member else self.data["owned"]["role_arn"]
        document = policy(statements)
        self.data["sessions"][label] = document
        self.save()
        for attempt in range(15):
            try:
                response = self.clients["sts"].assume_role(RoleArn=role, RoleSessionName=label, DurationSeconds=3600,
                    Policy=json.dumps(document, separators=(",", ":")))
                break
            except ClientError as error:
                if error.response["Error"]["Code"] != "AccessDenied" or attempt == 14:
                    raise
                time.sleep(3)
        credentials = response["Credentials"]
        session = boto3.Session(region_name=self.args.region, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        self.actors[label] = {name: session.client(name, config=CONFIG) for name in SERVICES}
        self.raw_copy(self.actors[label]["ec2"])
        identity = self.observe(label + "-identity", "sts", "get_caller_identity", caller=label, required=True)
        if identity["Account"] != (self.args.member_account if member else self.args.account):
            raise RuntimeError("Assumed actor ownership mismatch")
        return label

    def copy(self, label, parameters=None, *, caller="owner", dry=False, base=True):
        request = {"SourceRegion": self.args.region, "SourceSnapshotId": self.data["source"]} if base else {}
        request.update(parameters or {})
        if dry:
            request["DryRun"] = True
        if not dry and len(self.data["owned"]["copies"]) >= 10:
            raise RuntimeError("Successful copy budget exhausted")
        return self.observe(label, "ec2", "copy_snapshot", request, caller=caller)

    def describe_copies(self, phase):
        for sid, metadata in self.data["owned"]["copies"].items():
            actor = "member" if metadata["account"] == self.args.member_account else "owner"
            self.observe(phase + "-" + metadata["label"], "ec2", "describe_snapshots", {"SnapshotIds": [sid]}, caller=actor)
            self.observe(phase + "-permissions-" + metadata["label"], "ec2", "describe_snapshot_attribute",
                {"SnapshotId": sid, "Attribute": "createVolumePermission"}, caller=actor)

    def wait_copies(self):
        pending = dict(self.data["owned"]["copies"])
        deadline = time.monotonic() + self.args.completion_wait
        attempt = 0
        while pending:
            for sid, metadata in list(pending.items()):
                actor = "member" if metadata["account"] == self.args.member_account else "owner"
                result = self.observe("lifecycle-" + metadata["label"] + "-" + str(attempt), "ec2", "describe_snapshots",
                    {"SnapshotIds": [sid]}, caller=actor)
                if result.get("Snapshots") and result["Snapshots"][0]["State"] in ("completed", "error"):
                    self.data.setdefault("terminal_snapshots", {})[sid] = result["Snapshots"][0]
                    del pending[sid]
            self.save()
            if not pending or time.monotonic() >= deadline:
                break
            attempt += 1
            time.sleep(min(15, max(0, deadline - time.monotonic())))
        if pending:
            self.data["gaps"].append({"bounded_completion_wait_seconds": self.args.completion_wait, "pending": list(pending)})
        self.save()

    def admission(self):
        source = self.data["source"]
        cases = [
            ("missing-both", {}), ("missing-source-region", {"SourceSnapshotId": source}),
            ("missing-source-id", {"SourceRegion": self.args.region}),
            ("empty-source-id", {"SourceRegion": self.args.region, "SourceSnapshotId": ""}),
            ("malformed-source-id", {"SourceRegion": self.args.region, "SourceSnapshotId": "bad"}),
            ("missing-source-id-valid-form", {"SourceRegion": self.args.region, "SourceSnapshotId": "snap-00000000000000000"}),
            ("malformed-source-region", {"SourceRegion": "not-a-region", "SourceSnapshotId": source}),
            ("empty-source-region", {"SourceRegion": "", "SourceSnapshotId": source}),
            ("wrong-source-region", {"SourceRegion": "us-west-2", "SourceSnapshotId": source}),
        ]
        for label, parameters in cases:
            for dry in (False, True):
                self.copy("admission-" + label + "-dry-" + str(dry), parameters, dry=dry, base=False)
        for duration in (-1, 0, 1, 14, 15, 16, 2880, 2881):
            self.copy("duration-" + str(duration) + "-dry", {"CompletionDurationMinutes": duration}, dry=True)
        for duration in (0, 1, 16, 2881):
            self.copy("duration-" + str(duration) + "-actual", {"CompletionDurationMinutes": duration})
        for label, parameters in (
            ("destination-mismatch", {"DestinationRegion": "us-west-2"}),
            ("destination-invalid", {"DestinationRegion": "not-a-region"}),
            ("url-malformed", {"PresignedUrl": "not-a-url"}),
            ("url-empty", {"PresignedUrl": ""}),
            ("tag-wrong-resource", {"TagSpecifications": [{"ResourceType": "volume", "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]}]}),
            ("tag-duplicate-key", {"TagSpecifications": [{"ResourceType": "snapshot", "Tags": [{"Key": "suite", "Value": "a"}, {"Key": "suite", "Value": "b"}]}]}),
        ):
            self.copy(label + "-dry", parameters, dry=True)
        self.copy("destination-mismatch-actual", {"DestinationRegion": "us-west-2"})

    def iam(self):
        p = self.data["prefix"]
        arn = f"arn:aws:ec2:{self.args.region}::snapshot/"
        source = arn + self.data["source"]
        wildcard = arn + "*"
        self.observe("create-owned-role", "iam", "create_role", {"RoleName": p,
            "AssumeRolePolicyDocument": json.dumps(policy([{"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}])),
            "Tags": [{"Key": "suite", "Value": p}]}, required=True)
        self.observe("bound-owned-role", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-snapshots-only",
            "PolicyDocument": json.dumps(policy([
                allow("ec2:CopySnapshot", wildcard, {"StringEquals": {"ec2:Region": self.args.region}}),
                allow("ec2:CreateTags", wildcard, {"StringEquals": {"aws:RequestTag/suite": p}}),
            ]))}, required=True)
        time.sleep(15)
        denied = self.actor("owner-explicit-deny", [allow("ec2:CopySnapshot", "*"), {"Effect": "Deny", "Action": "ec2:CopySnapshot", "Resource": "*"}])
        for label, parameters, base in (
            ("valid", {}, True), ("missing-both", {}, False),
            ("malformed-id", {"SourceSnapshotId": "bad"}, True),
            ("missing-id", {"SourceSnapshotId": "snap-00000000000000000"}, True),
            ("invalid-region", {"SourceRegion": "not-a-region"}, True),
            ("invalid-duration", {"CompletionDurationMinutes": 1}, True),
        ):
            for dry in (False, True):
                self.copy("denied-" + label + "-dry-" + str(dry), parameters, caller=denied, dry=dry, base=base)
        for member in (False, True):
            prefix = "member" if member else "owner"
            for label, resource, condition in (
                ("source-only", source, None), ("wildcard", wildcard, None),
                ("account-filled", wildcard.replace("::snapshot/", ":" + (self.args.member_account if member else self.args.account) + ":snapshot/"), None),
                ("resource-account-source", wildcard, {"StringEquals": {"aws:ResourceAccount": self.args.account}}),
                ("resource-account-caller", wildcard, {"StringEquals": {"aws:ResourceAccount": self.args.member_account if member else self.args.account}}),
                ("resource-account-wrong", wildcard, {"StringEquals": {"aws:ResourceAccount": "000000000000"}}),
                ("source-region-match", wildcard, {"StringEquals": {"ec2:SourceRegion": self.args.region}}),
                ("source-region-wrong", wildcard, {"StringEquals": {"ec2:SourceRegion": "us-west-2"}}),
                ("owner-source", wildcard, {"StringEquals": {"ec2:Owner": self.args.account}}),
                ("owner-caller", wildcard, {"StringEquals": {"ec2:Owner": self.args.member_account if member else self.args.account}}),
                ("owner-wrong", wildcard, {"StringEquals": {"ec2:Owner": "000000000000"}}),
                ("deny-source", wildcard, None),
            ):
                statements = [allow("ec2:CopySnapshot", resource, condition)]
                if label == "deny-source":
                    statements.append({"Effect": "Deny", "Action": "ec2:CopySnapshot", "Resource": source})
                actor = self.actor(prefix + "-" + label, statements, member=member)
                self.copy(actor + "-dry", caller=actor, dry=True)
            actor = self.actor(prefix + "-destination-only", [
                {"Effect": "Allow", "Action": "ec2:CopySnapshot", "NotResource": source}], member=member)
            self.copy(actor + "-dry", caller=actor, dry=True)
        tags = [{"ResourceType": "snapshot", "Tags": [{"Key": "suite", "Value": p}, {"Key": "new-tag", "Value": "new-value"}]}]
        for label, create_action in (("tag-absent", None), ("tag-action-match", "CopySnapshot"), ("tag-action-wrong", "CreateSnapshot")):
            statements = [allow("ec2:CopySnapshot", wildcard)]
            if create_action:
                statements.append(allow("ec2:CreateTags", wildcard, {"StringEquals": {"ec2:CreateAction": create_action}}))
            actor = self.actor("owner-" + label, statements)
            self.copy(label + "-dry", {"TagSpecifications": tags}, caller=actor, dry=True)
        actor = self.actor("owner-deny-unneeded-reads", [allow("ec2:CopySnapshot", wildcard),
            {"Effect": "Deny", "Action": ["ec2:DescribeSnapshots", "ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock", "ebs:ListChangedBlocks"], "Resource": "*"}])
        self.copy("no-read-permissions-actual", caller=actor)
        self.copy("tag-action-match-actual", {"Description": p + "-tagged", "TagSpecifications": tags}, caller="owner-tag-action-match")

    def iam_only(self):
        source = self.start("iam-source", Encrypted=False)
        self.data["source"] = source["SnapshotId"]
        self.save()
        Capture.finish(self, "iam-source", source, readable=True)
        self.share("iam-share-source", self.data["source"])
        try:
            time.sleep(self.args.share_wait)
            if self.args.source_authority_only:
                source_arn = f"arn:aws:ec2:{self.args.region}::snapshot/{self.data['source']}"
                actor = self.actor("member-explicit-source-deny", [allow("ec2:CopySnapshot", "*"),
                    {"Effect": "Deny", "Action": "ec2:CopySnapshot", "Resource": source_arn}], member=True)
                self.copy("member-explicit-source-deny-dry", caller=actor, dry=True)
                self.copy("member-explicit-source-deny-actual", caller=actor)
            else:
                self.iam()
            self.wait_copies()
            self.describe_copies("iam-final")
        finally:
            self.share("iam-revoke-source", self.data["source"], "remove")
        self.data["capture_complete_at"] = now()
        self.save()

    def contexts_only(self):
        result = self.observe("verify-owned-context-source", "ec2", "describe_snapshots",
            {"SnapshotIds": [self.args.context_source]}, required=True)
        source = result["Snapshots"][0]
        if source["OwnerId"] != self.args.account or source["Encrypted"] or not source["Description"].startswith("stackd-ebs-copy-controls-"):
            raise RuntimeError("Context source is not an owned plaintext controls snapshot")
        self.data["source"] = source["SnapshotId"]
        self.data["scope"] = "Read-only split IAM contexts against an existing owned controls source; no resources created or source mutations"
        arn = f"arn:aws:ec2:{self.args.region}::snapshot/{self.data['source']}"
        destination = {"Effect": "Allow", "Action": "ec2:CopySnapshot", "NotResource": arn}
        for label, condition in (
            ("source-owner-match", {"StringEquals": {"ec2:Owner": self.args.account}}),
            ("source-owner-wrong", {"StringEquals": {"ec2:Owner": self.args.member_account}}),
            ("source-region-match", {"StringEquals": {"ec2:SourceRegion": self.args.region}}),
            ("source-resource-account", {"StringEquals": {"aws:ResourceAccount": self.args.account}}),
        ):
            actor = self.actor("member-split-" + label, [destination, allow("ec2:CopySnapshot", arn, condition)], member=True)
            self.copy(actor + "-dry", caller=actor, dry=True)
        destination = dict(destination, Condition={"StringEquals": {"aws:ResourceAccount": self.args.member_account}})
        actor = self.actor("member-split-both-accounts", [destination,
            allow("ec2:CopySnapshot", arn, {"StringEquals": {"aws:ResourceAccount": self.args.account}})], member=True)
        self.copy(actor + "-dry", caller=actor, dry=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def public_only(self):
        public = self.observe("public-setting-before", "ec2", "get_snapshot_block_public_access_state", required=True)
        if public.get("State") != "unblocked":
            self.data["gaps"].append("Public-copy skipped: existing setting was not unblocked")
            self.save()
            return
        source = self.start("public-source", Encrypted=False)
        self.data["source"] = source["SnapshotId"]
        self.save()
        Capture.finish(self, "public-source", source, readable=True)
        self.observe("public-source-add", "ec2", "modify_snapshot_attribute", {"SnapshotId": self.data["source"],
            "CreateVolumePermission": {"Add": [{"Group": "all"}]}}, required=True)
        try:
            time.sleep(self.args.share_wait)
            self.copy("member-public-source-dry", caller="member", dry=True)
            self.copy("member-public-source-actual", caller="member")
            self.describe_copies("public-initial")
            self.wait_copies()
        finally:
            self.observe("public-source-remove", "ec2", "reset_snapshot_attribute",
                {"SnapshotId": self.data["source"], "Attribute": "createVolumePermission"}, required=True)
        time.sleep(self.args.revoke_wait)
        self.observe("owner-source-after-public-reset", "ebs", "list_snapshot_blocks", {"SnapshotId": self.data["source"]})
        for sid in self.data["owned"]["copies"]:
            self.observe("member-copy-after-public-reset", "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, caller="member")
        self.observe("public-setting-after", "ec2", "get_snapshot_block_public_access_state", required=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def run(self):
        self.setup_audit()
        self.setup_events()
        for actor in ("owner", "member"):
            self.observe(actor + "-encryption-default-before", "ec2", "get_ebs_encryption_by_default", caller=actor, required=True)
        public = self.observe("public-setting-before", "ec2", "get_snapshot_block_public_access_state", required=True)
        source = self.start("source", Encrypted=False)
        self.data["source"] = source["SnapshotId"]
        self.save()
        self.observe("pending-source-state", "ec2", "describe_snapshots", {"SnapshotIds": [self.data["source"]]}, required=True)
        self.copy("pending-source-actual")
        self.copy("pending-source-dry", dry=True)
        Capture.finish(self, "source", source, readable=True)
        self.copy("completed-default-description")
        self.copy("completed-default-description-duplicate")
        self.copy("completion-duration-normal", {"CompletionDurationMinutes": 15})
        self.copy("member-private-source-actual", caller="member")
        self.copy("member-private-source-dry", caller="member", dry=True)
        self.share("share-source", self.data["source"])
        time.sleep(self.args.share_wait)
        self.copy("member-shared-source-actual", caller="member")
        self.iam()
        self.admission()
        self.describe_copies("initial")
        self.wait_copies()
        self.share("revoke-source", self.data["source"], "remove")
        time.sleep(self.args.revoke_wait)
        self.copy("member-revoked-source-actual", caller="member")
        self.copy("member-revoked-source-dry", caller="member", dry=True)
        self.observe("owner-source-after-revoke", "ebs", "list_snapshot_blocks", {"SnapshotId": self.data["source"]})
        for sid, metadata in self.data["owned"]["copies"].items():
            if metadata["account"] == self.args.member_account:
                self.observe("member-copy-after-revoke", "ebs", "list_snapshot_blocks", {"SnapshotId": sid}, caller="member")
        if public.get("State") == "unblocked":
            self.observe("public-source-add", "ec2", "modify_snapshot_attribute", {"SnapshotId": self.data["source"],
                "CreateVolumePermission": {"Add": [{"Group": "all"}]}}, required=True)
            try:
                time.sleep(self.args.share_wait)
                self.copy("member-public-source-dry", caller="member", dry=True)
                self.copy("member-public-source-actual", caller="member")
                self.wait_copies()
            finally:
                self.observe("public-source-remove", "ec2", "reset_snapshot_attribute", {"SnapshotId": self.data["source"], "Attribute": "createVolumePermission"}, required=True)
        else:
            self.data["gaps"].append("Public-copy case skipped: existing source-account public-block setting was not unblocked")
        self.describe_copies("final")
        for actor in ("owner", "member"):
            self.observe(actor + "-encryption-default-after", "ec2", "get_ebs_encryption_by_default", caller=actor, required=True)
        self.observe("public-setting-after", "ec2", "get_snapshot_block_public_access_state", required=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def cleanup_snapshots(self):
        deleted = self.data["cleanup"].setdefault("deleted_snapshots", [])
        for sid in reversed(self.data["owned"]["snapshots"]):
            if sid in deleted:
                continue
            actor = "member" if self.data["owned"]["snapshot_accounts"].get(sid) == self.args.member_account else "owner"
            self.observe("cleanup-delete-" + sid, "ec2", "delete_snapshot", {"SnapshotId": sid}, caller=actor)
            if self.data["calls"][-1]["code"] in ("Success", "InvalidSnapshot.NotFound"):
                deleted.append(sid)
        self.data["cleanup"]["remaining_snapshots"] = [sid for sid in self.data["owned"]["snapshots"] if sid not in deleted]
        role = self.data["owned"].get("role")
        if role and not self.data["cleanup"].get("role_deleted"):
            self.observe("cleanup-role-policy", "iam", "delete_role_policy", {"RoleName": role, "PolicyName": "owned-snapshots-only"})
            self.observe("cleanup-role", "iam", "delete_role", {"RoleName": role})
            if self.data["calls"][-1]["code"] in ("Success", "NoSuchEntity"):
                self.data["cleanup"]["role_deleted"] = True
        self.save()
        if self.data["cleanup"]["remaining_snapshots"] or role and not self.data["cleanup"].get("role_deleted"):
            raise RuntimeError("Owned resource cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--member-account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/copy_controls.json"))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--audit-only", action="store_true")
    group.add_argument("--cleanup-only", action="store_true")
    group.add_argument("--iam-only", action="store_true", help="Fresh owned source/role, focused IAM supplemental evidence")
    group.add_argument("--source-authority-only", action="store_true", help="One real recipient copy with explicit source CopySnapshot deny")
    group.add_argument("--public-only", action="store_true", help="One owned public-source copy without changing public-block settings")
    group.add_argument("--context-source", help="Read-only split IAM conditions on an existing owned controls snapshot")
    parser.add_argument("--audit-wait", type=int, default=300)
    parser.add_argument("--audit-related", type=Path, action="append", default=[])
    parser.add_argument("--completion-wait", type=int, default=900)
    parser.add_argument("--share-wait", type=int, default=90)
    parser.add_argument("--revoke-wait", type=int, default=65)
    args = parser.parse_args()
    capture = CopyCapture(args)
    try:
        if args.cleanup_only:
            capture.cleanup_snapshots()
        elif args.audit_only:
            capture.audit()
        else:
            try:
                if args.iam_only or args.source_authority_only:
                    capture.iam_only()
                elif args.public_only:
                    capture.public_only()
                elif args.context_source:
                    capture.contexts_only()
                else:
                    capture.run()
            finally:
                capture.cleanup_snapshots()
            if not args.iam_only and not args.source_authority_only and not args.public_only and not args.context_source:
                capture.audit()
    finally:
        try:
            if not args.cleanup_only:
                capture.capture_events()
        finally:
            try:
                capture.cleanup_events()
            finally:
                capture.cleanup_audit()


if __name__ == "__main__":
    main()
