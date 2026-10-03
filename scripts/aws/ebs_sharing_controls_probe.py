#!/usr/bin/env python3
"""Capture owned snapshot sharing controls without changing account settings.

Reuses the encryption probe's capture, cleanup and CloudTrail helpers. Snapshot
contents are synthetic zeroes: no volumes, instances, customer data or block reads.
Only a unique-prefix IAM role and snapshots and one customer KMS key are created.
"""
import argparse
import json
from pathlib import Path
import re
import time
import urllib.request
import uuid
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ebs_encryption_probe import CONFIG, Capture, allow, now, policy, safe
from cloudtrail_events import CollectionError, collect_history

ATTRIBUTE = "createVolumePermission"
ACTIONS = ["ec2:" + action + "SnapshotAttribute" for action in ("Describe", "Modify", "Reset")]
SAR = "https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json"
SOURCES = [SAR] + ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + action + "SnapshotAttribute.html"
                   for action in ("Describe", "Modify", "Reset")] + [
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html"] + [
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + action + ".html" for action in
    ("GetSnapshotBlockPublicAccessState", "EnableSnapshotBlockPublicAccess", "DisableSnapshotBlockPublicAccess")]


class SharingCapture(Capture):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        if args.audit_only or args.cleanup_only:
            if self.data.get("member", args.member_account) != args.member_account:
                raise RuntimeError("Evidence member ownership mismatch")
        else:
            self.data["member"] = args.member_account
        if not args.audit_only and not args.cleanup_only:
            self.data.update(prefix="stackd-ebs-share-" + uuid.uuid4().hex[:12], documentation=SOURCES,
                scope="Owned empty 1-GiB snapshots, one bounded owner role and one customer KMS key; readonly account settings; no data-plane reads or standing-resource changes",
                payload={"recipe": "Empty direct snapshots: zero changed blocks, synthetic logical zeroes only"})
            with urllib.request.urlopen(SAR, timeout=30) as response:
                reference = json.load(response)
            self.data["service_authorization_reference"] = {"url": SAR, "retrieved_at": now(),
                "actions": [row for row in reference["Actions"] if "ec2:" + row["Name"] in ACTIONS],
                "resource": [row for row in reference["Resources"] if row["Name"] == "snapshot"]}
        self.member = self.session_clients("member-owner", "arn:aws:iam::" + self.args.member_account + ":role/OrganizationAccountAccessRole", None, self.args.member_account)
        self.save()

    def session_clients(self, label: str, role: str, statements: list[dict[str, Any]] | None,
                        account: str | None = None) -> dict[str, Any]:
        if account is None:
            account = self.args.account
        parameters: dict[str, Any] = {"RoleArn": role, "RoleSessionName": label, "DurationSeconds": 3600}
        if statements is not None:
            document = policy(statements)
            parameters["Policy"] = json.dumps(document, separators=(",", ":"))
            self.data["sessions"][label] = document
            self.save()
        for attempt in range(15):
            try:
                credentials = self.clients["sts"].assume_role(**parameters)["Credentials"]
                break
            except ClientError as error:
                if error.response["Error"]["Code"] != "AccessDenied" or attempt == 14:
                    raise
                time.sleep(3)
        session = boto3.Session(region_name=self.args.region, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        clients = {name: session.client(name, config=CONFIG) for name in ("ec2", "sts", "cloudtrail")}
        identity = self.observe(label + "-identity", "sts", "get_caller_identity", client=clients["sts"], caller=label, required=True)
        if identity["Account"] != account:
            raise RuntimeError("Assumed session account mismatch")
        return clients

    def permissions(self, label: str, snapshot: str) -> dict[str, Any]:
        return self.observe(label, "ec2", "describe_snapshot_attribute", {"SnapshotId": snapshot, "Attribute": ATTRIBUTE}, required=True)

    def change(self, label: str, snapshot: str, parameters: dict[str, Any] | None = None,
               *, method: str = "modify_snapshot_attribute", client: Any = None, caller: str = "owner") -> None:
        self.permissions(label + "-before", snapshot)
        self.observe(label, "ec2", method, dict(SnapshotId=snapshot, **(parameters or {})), client=client, caller=caller)
        row = self.data["calls"][-1]
        encoded = re.search(r"Encoded authorization failure message: (\S+)", row.get("error", {}).get("Message", ""))
        if encoded:
            try:
                decoded = self.clients["sts"].decode_authorization_message(EncodedMessage=encoded[1])
                row["decoded_authorization"] = safe(json.loads(decoded["DecodedMessage"]))
            except ClientError as error:
                row["authorization_decode_error"] = safe(error.response["Error"])
        self.permissions(label + "-after", snapshot)

    def condition(self, label: str, snapshot: str, actions: list[str], condition: dict[str, Any] | None,
                  *, resource: str | None = None) -> Any:
        arn = "arn:aws:ec2:" + self.args.region + "::snapshot/" + snapshot
        return self.session_clients(label, self.data["owned"]["role_arn"], [allow(actions, resource or arn, condition)])["ec2"]

    def run(self) -> None:
        p = self.data["prefix"]
        self.observe("encryption-default-before", "ec2", "get_ebs_encryption_by_default", required=True)
        self.observe("default-key-before", "ec2", "get_ebs_default_kms_key_id", required=True)
        public = self.observe("block-public-access-before", "ec2", "get_snapshot_block_public_access_state", required=True)
        self.data["public_sharing_setting"] = public
        self.public_access_dry_runs()
        self.observe("create-owned-key", "kms", "create_key", {"Description": p,
            "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT", "Tags": [{"TagKey": "suite", "TagValue": p}]}, required=True)
        plain = self.start("plain", Encrypted=False)
        snapshot = plain["SnapshotId"]
        self.data["primary_snapshot"] = snapshot
        self.observe("pending-state", "ec2", "describe_snapshots", {"SnapshotIds": [snapshot]}, required=True)
        self.permissions("pending-permissions", snapshot)
        self.change("pending-add", snapshot, {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}})
        self.change("pending-remove", snapshot, {"CreateVolumePermission": {"Remove": [{"UserId": self.args.member_account}]}})
        self.change("pending-reset", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")
        self.finish("plain", plain)
        self.permissions("completed-permissions", snapshot)
        self.observe("completed-products", "ec2", "describe_snapshot_attribute", {"SnapshotId": snapshot, "Attribute": "productCodes"})
        cases = [
            ("empty", {}), ("empty-canonical", {"CreateVolumePermission": {}}),
            ("empty-add", {"CreateVolumePermission": {"Add": []}}),
            ("attribute-only", {"Attribute": ATTRIBUTE}),
            ("canonical-add", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}),
            ("canonical-add-repeat", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}),
            ("canonical-duplicate", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}, {"UserId": self.args.member_account}]}}),
            ("self-add", {"CreateVolumePermission": {"Add": [{"UserId": self.args.account}]}}),
            ("mixed-same-account", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}], "Remove": [{"UserId": self.args.member_account}]}}),
            ("mixed-accounts", {"CreateVolumePermission": {"Add": [{"UserId": self.args.account}], "Remove": [{"UserId": self.args.member_account}]}}),
            ("canonical-remove", {"CreateVolumePermission": {"Remove": [{"UserId": self.args.member_account}]}}),
            ("canonical-remove-absent", {"CreateVolumePermission": {"Remove": [{"UserId": self.args.member_account}]}}),
            ("self-remove", {"CreateVolumePermission": {"Remove": [{"UserId": self.args.account}]}}),
            ("legacy-add", {"Attribute": ATTRIBUTE, "OperationType": "add", "UserIds": [self.args.member_account]}),
            ("legacy-duplicate", {"Attribute": ATTRIBUTE, "OperationType": "add", "UserIds": [self.args.member_account, self.args.member_account]}),
            ("legacy-remove", {"Attribute": ATTRIBUTE, "OperationType": "remove", "UserIds": [self.args.member_account]}),
            ("legacy-no-attribute", {"OperationType": "add", "UserIds": [self.args.member_account]}),
            ("legacy-no-operation", {"Attribute": ATTRIBUTE, "UserIds": [self.args.member_account]}),
            ("legacy-invalid-operation", {"Attribute": ATTRIBUTE, "OperationType": "replace", "UserIds": [self.args.member_account]}),
            ("canonical-with-attribute", {"Attribute": ATTRIBUTE, "CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}),
            ("canonical-legacy-same", {"Attribute": ATTRIBUTE, "OperationType": "add", "UserIds": [self.args.member_account], "CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}),
            ("canonical-legacy-conflict", {"Attribute": ATTRIBUTE, "OperationType": "remove", "UserIds": [self.args.member_account], "CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}),
            ("invalid-account-short", {"CreateVolumePermission": {"Add": [{"UserId": "123"}]}}),
            ("invalid-account-text", {"CreateVolumePermission": {"Add": [{"UserId": "not-an-account"}]}}),
            ("invalid-account-hyphens", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account[:4] + "-" + self.args.member_account[4:8] + "-" + self.args.member_account[8:]}]}}),
            ("invalid-account-empty", {"CreateVolumePermission": {"Add": [{"UserId": ""}]}}),
            ("valid-invalid-atomicity", {"CreateVolumePermission": {"Add": [{"UserId": self.args.account}, {"UserId": "123"}]}}),
            ("invalid-group", {"CreateVolumePermission": {"Add": [{"Group": "everyone"}]}}),
            ("invalid-group-remove", {"CreateVolumePermission": {"Remove": [{"Group": "everyone"}]}}),
            ("empty-item", {"CreateVolumePermission": {"Add": [{}]}}),
            ("modify-products", {"Attribute": "productCodes", "OperationType": "add", "UserIds": [self.args.member_account]}),
            ("modify-invalid-attribute", {"Attribute": "invalid", "CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}),
            ("public-add", {"CreateVolumePermission": {"Add": [{"Group": "all"}]}}),
            ("public-remove", {"CreateVolumePermission": {"Remove": [{"Group": "all"}]}}),
            ("legacy-public-add", {"Attribute": ATTRIBUTE, "OperationType": "add", "GroupNames": ["all"]}),
            ("legacy-public-remove", {"Attribute": ATTRIBUTE, "OperationType": "remove", "GroupNames": ["all"]}),
            ("combined-user-group-item", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account, "Group": "all"}]}}),
        ]
        for label, parameters in cases:
            self.change(label, snapshot, parameters)
        self.change("reset-permissions", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")
        self.change("reset-empty-permissions", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")
        for method in ("describe_snapshot_attribute", "reset_snapshot_attribute"):
            for attribute in ("productCodes", "invalid", "", None):
                parameters = {} if attribute is None else {"Attribute": attribute}
                self.change(method + "-attribute-" + str(attribute), snapshot, parameters, method=method)
        self.permission_edge_cases(snapshot)
        self.encrypted_cases()
        self.ownership_cases(snapshot)
        self.iam_cases(snapshot)
        self.observe("block-public-access-after", "ec2", "get_snapshot_block_public_access_state", required=True)
        self.data["capture_complete"] = True
        self.save()

    def permission_edge_cases(self, snapshot: str) -> None:
        cases = [
            ("atomic-canonical", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}, {"UserId": "123"}]}}),
            ("atomic-legacy", {"Attribute": ATTRIBUTE, "OperationType": "add", "UserIds": [self.args.member_account, "123"]}),
            ("twelve-digit-zero-account", {"CreateVolumePermission": {"Add": [{"UserId": "000000000000"}]}}),
            ("legacy-empty-add", {"Attribute": ATTRIBUTE, "OperationType": "add", "UserIds": []}),
            ("legacy-invalid-attribute", {"Attribute": "invalid", "OperationType": "add", "UserIds": [self.args.member_account]}),
            ("combined-item-empty-state", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account, "Group": "all"}]}}),
            ("canonical-invalid-operation", {"OperationType": "invalid", "CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}),
            ("dryrun-mixed", {"DryRun": True, "CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}], "Remove": [{"UserId": self.args.member_account}]}}),
            ("dryrun-empty", {"DryRun": True}),
            ("dryrun-invalid-group", {"DryRun": True, "CreateVolumePermission": {"Add": [{"Group": "invalid"}]}}),
        ]
        for label, parameters in cases:
            self.change(label + "-reset", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")
            self.change(label, snapshot, parameters)
        self.change("edge-cases-final-reset", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")

    def encrypted_cases(self) -> None:
        managed = self.observe("aws-managed-key", "kms", "describe_key", {"KeyId": "alias/aws/ebs"}, required=True)
        self.data["aws_managed_key"] = managed["KeyMetadata"]["Arn"]
        for name, key in (("aws-managed", self.data["aws_managed_key"]), ("customer-key", self.data["owned"]["key"])):
            started = self.start(name, Encrypted=True, KmsKeyArn=key)
            snapshot = started["SnapshotId"]
            self.change(name + "-pending-add", snapshot, {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}})
            self.finish(name, started)
            self.change(name + "-completed-add", snapshot, {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}})
            self.change(name + "-self-add", snapshot, {"CreateVolumePermission": {"Add": [{"UserId": self.args.account}]}})
            self.change(name + "-public-add", snapshot, {"CreateVolumePermission": {"Add": [{"Group": "all"}]}})
            self.change(name + "-remove", snapshot, {"CreateVolumePermission": {"Remove": [{"UserId": self.args.member_account}]}})
            self.change(name + "-reset", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")

    def ownership_cases(self, snapshot: str) -> None:
        for shared in (False, True):
            if shared:
                self.change("share-for-unowned-probes", snapshot, {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}})
            for method in ("describe_snapshot_attribute", "modify_snapshot_attribute", "reset_snapshot_attribute"):
                parameters = {"Attribute": ATTRIBUTE}
                if method == "modify_snapshot_attribute":
                    parameters["CreateVolumePermission"] = {"Add": [{"UserId": self.args.member_account}]}
                for dry in (False, True):
                    self.change("member-" + str(shared) + "-" + method + "-dry-" + str(dry), snapshot,
                        dict(parameters, DryRun=dry), method=method, client=self.member["ec2"], caller="member-owner")
        self.change("reset-after-unowned-probes", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")

    def iam_cases(self, snapshot: str) -> None:
        p = self.data["prefix"]
        arn = "arn:aws:ec2:" + self.args.region + "::snapshot/" + snapshot
        self.observe("create-owned-role", "iam", "create_role", {"RoleName": p,
            "AssumeRolePolicyDocument": json.dumps(policy([{"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}])),
            "Tags": [{"Key": "suite", "Value": p}]}, required=True)
        self.observe("bound-owned-role", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-snapshots-only",
            "PolicyDocument": json.dumps(policy([allow(ACTIONS, arn)]))}, required=True)
        time.sleep(15)
        denied = self.session_clients("explicit-deny", self.data["owned"]["role_arn"], [allow(ACTIONS, "*"),
            {"Effect": "Deny", "Action": ACTIONS, "Resource": "*"}])["ec2"]
        for method in ("describe_snapshot_attribute", "modify_snapshot_attribute", "reset_snapshot_attribute"):
            base: dict[str, Any] = {"SnapshotId": snapshot, "Attribute": ATTRIBUTE}
            if method == "modify_snapshot_attribute":
                base["CreateVolumePermission"] = {"Add": [{"UserId": self.args.member_account}]}
            variants = [("valid", {}), ("missing", {"SnapshotId": "snap-00000000000000000"}),
                ("malformed", {"SnapshotId": "bad"}), ("invalid-attribute", {"Attribute": "invalid"})]
            if method == "modify_snapshot_attribute":
                variants.append(("invalid-account", {"CreateVolumePermission": {"Add": [{"UserId": "bad"}]}}))
            for label, overrides in variants:
                for caller, client in (("owner", None), ("explicit-deny", denied)):
                    for dry in (False, True):
                        parameters = dict(base, **overrides, DryRun=dry)
                        self.observe(method + "-" + label + "-" + caller + "-dry-" + str(dry), "ec2", method,
                            parameters, client=client, caller=caller)
            self.permissions(method + "-precedence-final-state", snapshot)
        for key, value in (("ec2:Owner", self.args.account), ("aws:ResourceAccount", self.args.account),
                           ("aws:ResourceTag/suite", p), ("ec2:ResourceTag/suite", p)):
            for match in (True, False):
                label = key.replace(":", "-").replace("/", "-") + "-" + str(match)
                condition = {"StringEquals": {key: value if match else "mismatch"}}
                client = self.condition(label, snapshot, ACTIONS, condition)
                for method in ("describe_snapshot_attribute", "modify_snapshot_attribute", "reset_snapshot_attribute"):
                    parameters = {"Attribute": ATTRIBUTE}
                    if method == "modify_snapshot_attribute":
                        parameters["CreateVolumePermission"] = {"Add": [{"UserId": self.args.member_account}]}
                    self.change(label + "-" + method, snapshot, parameters, method=method, client=client, caller=label)
        for resource_name, resource in (("empty-account", arn), ("filled-account", arn.replace("::snapshot/", ":" + self.args.account + ":snapshot/"))):
            client = self.condition(resource_name, snapshot, ACTIONS, None, resource=resource)
            self.change(resource_name + "-arn", snapshot, {"Attribute": ATTRIBUTE}, method="describe_snapshot_attribute", client=client, caller=resource_name)
        requests = [
            ("canonical-add", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}, "ec2:Add/userId", self.args.member_account),
            ("legacy-add", {"Attribute": ATTRIBUTE, "OperationType": "add", "UserIds": [self.args.member_account]}, "ec2:Add/userId", self.args.member_account),
            ("canonical-remove", {"CreateVolumePermission": {"Remove": [{"UserId": self.args.member_account}]}}, "ec2:Remove/userId", self.args.member_account),
            ("legacy-remove", {"Attribute": ATTRIBUTE, "OperationType": "remove", "UserIds": [self.args.member_account]}, "ec2:Remove/userId", self.args.member_account),
            ("public-add", {"CreateVolumePermission": {"Add": [{"Group": "all"}]}}, "ec2:Add/group", "all"),
            ("public-remove", {"CreateVolumePermission": {"Remove": [{"Group": "all"}]}}, "ec2:Remove/group", "all"),
            ("attribute-canonical", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}, "ec2:Attribute", ATTRIBUTE),
            ("attribute-legacy", {"Attribute": ATTRIBUTE, "OperationType": "add", "UserIds": [self.args.member_account]}, "ec2:Attribute", ATTRIBUTE),
            ("attribute-value", {"CreateVolumePermission": {"Add": [{"UserId": self.args.member_account}]}}, "ec2:Attribute/createVolumePermission", self.args.member_account),
        ]
        for name, parameters, key, value in requests:
            for match in (True, False):
                label = "condition-" + name + "-" + str(match)
                condition = {"ForAnyValue:StringEquals": {key: value if match else "mismatch"}}
                client = self.condition(label, snapshot, ["ec2:ModifySnapshotAttribute"], condition)
                self.change(label, snapshot, parameters, client=client, caller=label)
        for match in (True, False):
            label = "condition-reset-attribute-" + str(match)
            client = self.condition(label, snapshot, ["ec2:ResetSnapshotAttribute"],
                {"StringEquals": {"ec2:Attribute": ATTRIBUTE if match else "invalid"}})
            self.change(label, snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute", client=client, caller=label)
        self.change("reset-after-iam-probes", snapshot, {"Attribute": ATTRIBUTE}, method="reset_snapshot_attribute")

    def public_access_dry_runs(self) -> None:
        """Never issue Enable/Disable without an explicit true DryRun."""
        actions = ["ec2:" + name for name in ("GetSnapshotBlockPublicAccessState",
            "EnableSnapshotBlockPublicAccess", "DisableSnapshotBlockPublicAccess")]
        denied = self.session_clients("public-settings-denied", "arn:aws:iam::" + self.args.member_account + ":role/OrganizationAccountAccessRole",
            [allow(actions, "*"), {"Effect": "Deny", "Action": actions, "Resource": "*"}], self.args.member_account)["ec2"]
        owner_before = self.observe("settings-owner-before", "ec2", "get_snapshot_block_public_access_state", required=True)
        member_before = self.observe("settings-member-before", "ec2", "get_snapshot_block_public_access_state",
            client=self.member["ec2"], caller="member-owner", required=True)
        for caller, client in (("owner", None), ("public-settings-denied", denied)):
            for state in ("block-all-sharing", "block-new-sharing", "unblocked", "invalid", "", None):
                # EC2 publishes a one-token bucket refilling at 0.1/second.
                time.sleep(10.2)
                parameters: dict[str, Any] = {"DryRun": True}
                if state is not None:
                    parameters["State"] = state
                self.observe("settings-enable-" + str(state) + "-" + caller, "ec2", "enable_snapshot_block_public_access",
                    parameters, client=client, caller=caller)
            for method in ("disable_snapshot_block_public_access", "get_snapshot_block_public_access_state"):
                self.observe("settings-" + method + "-" + caller, "ec2", method, {"DryRun": True}, client=client, caller=caller)
        owner_after = self.observe("settings-owner-after", "ec2", "get_snapshot_block_public_access_state", required=True)
        member_after = self.observe("settings-member-after", "ec2", "get_snapshot_block_public_access_state",
            client=self.member["ec2"], caller="member-owner", required=True)
        self.data["public_settings_unchanged"] = {"owner": owner_before == owner_after, "member": member_before == member_after}
        self.data["documentation"] = SOURCES
        self.save()
        if owner_before != owner_after or member_before != member_after:
            raise RuntimeError("Observed account setting changed during DryRun-only capture")

    def deleted_snapshot_cases(self) -> None:
        """Use a real, deleted ID: all-zero IDs have a separate malformed error."""
        snapshot = self.data["primary_snapshot"]
        if snapshot not in self.data["cleanup"]["deleted_snapshots"]:
            raise RuntimeError("Missing-resource probe requires confirmed owned snapshot deletion")
        denied = self.session_clients("deleted-snapshot-denied", "arn:aws:iam::" + self.args.member_account + ":role/OrganizationAccountAccessRole",
            [allow(ACTIONS, "*"), {"Effect": "Deny", "Action": ACTIONS, "Resource": "*"}], self.args.member_account)["ec2"]
        for method in ("describe_snapshot_attribute", "modify_snapshot_attribute", "reset_snapshot_attribute"):
            parameters: dict[str, Any] = {"SnapshotId": snapshot, "Attribute": ATTRIBUTE}
            if method == "modify_snapshot_attribute":
                parameters["CreateVolumePermission"] = {"Add": [{"UserId": self.args.member_account}]}
            for caller, client in (("owner", None), ("deleted-snapshot-denied", denied)):
                for dry in (False, True):
                    self.observe("deleted-" + method + "-" + caller + "-dry-" + str(dry), "ec2", method,
                        dict(parameters, DryRun=dry), client=client, caller=caller)

    def audit(self) -> None:
        audit = self.data.get("cloudtrail", {})
        fields = ("events", "pages", "observations", "objects", "errors")
        collections = {}
        for account in (self.args.account, self.args.member_account):
            previous = dict(audit.get("accounts", {}).get(account, {}))
            if account == self.args.account and "accounts" not in audit:
                previous.update({key: audit[key] for key in ("bounds", "page_cap_reached", "partial") if key in audit})
            for field in fields:
                previous[field] = [row for row in audit.get(field, [])
                    if row.get("lookup_account", self.args.account) == account]
            collections[account] = previous
        request_ids = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("request_id")}
        for account, previous in collections.items():
            collected = None
            try:
                if account == self.args.account:
                    super().audit(previous=previous)
                    collected = self.data["cloudtrail"]
                else:
                    collected = collect_history(
                        lambda parameters: self.member["cloudtrail"].lookup_events(**parameters),
                        request_ids, start_time=self.data["captured_at"],
                        event_sources=("ec2.amazonaws.com",), max_pages=20, previous=previous)
            except CollectionError as error:
                collected = error.result
                raise
            finally:
                if collected is not None:
                    collections[account] = safe(collected)
                    if account == self.args.account:
                        audit.update({key: value for key, value in collections[account].items() if key not in fields})
                    for field in fields:
                        audit[field] = [
                            {**row, "lookup_account": lookup_account}
                            for lookup_account, result in collections.items()
                            for row in result[field]]
                    audit["accounts"] = {
                        lookup_account: {key: value for key, value in result.items() if key not in fields}
                        for lookup_account, result in collections.items()}
                    audit["page_cap_reached"] = any(result.get("page_cap_reached", False) for result in collections.values())
                    audit["partial"] = any(result.get("partial", False) or result.get("errors") for result in collections.values())
                    found = {row["event"].get("requestID") for row in audit["events"] if row["call_label"] is not None}
                    audit["missing_request_ids"] = [request_id for request_id in request_ids if request_id not in found]
                    audit["missing_calls"] = [request_ids[request_id] for request_id in audit["missing_request_ids"]]
                    audit["missing_management_calls"] = [row["label"] for row in self.data["calls"]
                        if row["service"] in ("ec2", "kms") or (row["service"] == "ebs" and row["operation"] in ("StartSnapshot", "CompleteSnapshot"))
                        if row.get("request_id") not in found]
                    audit["captured_at"] = now()
                    audit["interpretation"] = "Positive delivered management events only; missing LookupEvents records are not evidence of non-emission. No trail or Lake resources were created."
                    self.data["cloudtrail"] = audit
                    self.save()
        print(json.dumps({"both_accounts_audit_events": len(audit["events"]),
            "missing_management_calls": len(audit["missing_management_calls"])}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--member-account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/sharing_controls.json"))
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    capture = SharingCapture(args)
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
    capture.deleted_snapshot_cases()
    capture.audit()


if __name__ == "__main__":
    main()
