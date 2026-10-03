#!/usr/bin/env python3
"""Capture AMI controls from owned empty snapshots; no instances or default changes.

The persisted Capture ledger owns every snapshot, image and bounded IAM role.
--cleanup-only resumes cleanup after interruption. No credentials enter evidence.
"""
import argparse
import json
from pathlib import Path
import signal
import time
import uuid

import boto3
from botocore.exceptions import ClientError

from ebs_encryption_probe import CONFIG, Capture, allow, now, policy

ACTIONS = ("RegisterImage", "DescribeImages", "DescribeImageAttribute", "ModifyImageAttribute", "ResetImageAttribute", "DeregisterImage")


class ImageCapture(Capture):
    def __init__(self, args):
        super().__init__(args)
        if args.cleanup_only:
            if self.data.get("member", args.member_account) != args.member_account:
                raise RuntimeError("Evidence member ownership mismatch")
        else:
            self.data["member"] = args.member_account
        if not args.cleanup_only:
            self.data.update(prefix="stackd-ec2-images-" + uuid.uuid4().hex[:12],
                documentation=["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + action + ".html" for action in ACTIONS],
                scope="Owned empty 1-GiB snapshot, derived AMIs and one bounded IAM role; no instances, public sharing, standing-role or account-setting changes",
                payload={"recipe": "Zero changed blocks: synthetic logical zeroes only"})
        self.data["owned"].setdefault("images", [])
        self.save()

    def observe(self, label, service, method, parameters=None, **kwargs):
        out = super().observe(label, service, method, parameters, **kwargs)
        if method == "register_image" and "ImageId" in out:
            self.data["owned"]["images"].append(out["ImageId"])
            self.save()
        return out

    def assumed_image(self, label, statements):
        document = policy(statements)
        self.data["sessions"][label] = document
        self.save()
        for attempt in range(15):
            try:
                credentials = self.clients["sts"].assume_role(RoleArn=self.data["owned"]["role_arn"],
                    RoleSessionName=label, DurationSeconds=900, Policy=json.dumps(document))["Credentials"]
                return boto3.client("ec2", region_name=self.args.region, config=CONFIG,
                    aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
            except ClientError as error:
                if error.response["Error"]["Code"] != "AccessDenied" or attempt == 14:
                    raise
                time.sleep(2)

    def run(self):
        p = self.data["prefix"]
        snapshot = self.start("empty", Encrypted=False)
        self.finish("empty", snapshot)
        sid = snapshot["SnapshotId"]
        base = {"Name": p + "-base", "Architecture": "x86_64", "VirtualizationType": "hvm", "RootDeviceName": "/dev/sda1",
            "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": sid}}],
            "TagSpecifications": [{"ResourceType": "image", "Tags": [{"Key": "suite", "Value": p}]}]}
        image = self.observe("register-minimal", "ec2", "register_image", base, required=True)["ImageId"]
        self.observe("describe-minimal", "ec2", "describe_images", {"ImageIds": [image]}, required=True)
        for attr in ("description", "launchPermission", "bootMode", "imdsSupport", "kernel", "ramdisk", "sriovNetSupport", "tpmSupport", "uefiData", "productCodes", "deregistrationProtection", "lastLaunchedTime", "blockDeviceMapping"):
            self.observe("attribute-" + attr, "ec2", "describe_image_attribute", {"ImageId": image, "Attribute": attr})
        for label, extra in (("description", {"Description": {"Value": "owned description"}}),
                ("description-empty", {"Attribute": "description", "Value": ""}),
                ("imds", {"ImdsSupport": {"Value": "v2.0"}}),
                ("imds-reset", {"ImdsSupport": {"Value": ""}}),
                ("empty", {}), ("empty-permissions", {"LaunchPermission": {}}),
                ("self-add", {"LaunchPermission": {"Add": [{"UserId": self.args.account}]}}),
                ("self-remove", {"LaunchPermission": {"Remove": [{"UserId": self.args.account}]}}),
                ("bad-account", {"LaunchPermission": {"Add": [{"UserId": "123"}]}}),
                ("mixed-attributes", {"Description": {"Value": "must not apply"}, "ImdsSupport": {"Value": "v2.0"}})):
            self.observe("modify-" + label, "ec2", "modify_image_attribute", dict(ImageId=image, **extra))
        self.observe("reset-launch", "ec2", "reset_image_attribute", {"ImageId": image, "Attribute": "launchPermission"})
        self.observe("reset-description", "ec2", "reset_image_attribute", {"ImageId": image, "Attribute": "description"})
        self.observe("describe-after-modify", "ec2", "describe_images", {"ImageIds": [image]})
        for label, params in (("duplicate", base), ("missing-root", dict(base, Name=p + "-missing-root", RootDeviceName="/dev/missing")),
                ("invalid-name", dict(base, Name="x")), ("missing-snapshot", dict(base, Name=p + "-missing-snapshot", BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": "snap-00000000000000000"}}])),
                ("encrypted-field", dict(base, Name=p + "-encrypted-field", BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": sid, "Encrypted": False}}]))):
            self.observe("register-" + label, "ec2", "register_image", params)
        for label, params in (("max-one", {"Owners": ["self"], "Filters": [{"Name": "tag:suite", "Values": [p]}], "MaxResults": 1}),
                ("ids-page", {"ImageIds": [image], "MaxResults": 5}), ("missing", {"ImageIds": ["ami-00000000000000000"]})):
            self.observe("describe-" + label, "ec2", "describe_images", params)
        image_arn = "arn:aws:ec2:" + self.args.region + "::image/"
        snap_arn = "arn:aws:ec2:" + self.args.region + "::snapshot/" + sid
        self.observe("create-owned-role", "iam", "create_role", {"RoleName": p, "AssumeRolePolicyDocument": json.dumps(policy([
            {"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}])), "Tags": [{"Key": "suite", "Value": p}]}, required=True)
        self.observe("bind-owned-role", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-images-only", "PolicyDocument": json.dumps(policy([
            allow("ec2:RegisterImage", [image_arn + "*", snap_arn]),
            allow("ec2:CreateTags", image_arn + "*", {"StringEquals": {"aws:RequestTag/suite": p}})]))}, required=True)
        time.sleep(15)
        for label, statements, tagged in (("no-snapshot", [allow("ec2:RegisterImage", image_arn + "*")], False),
                ("no-image", [allow("ec2:RegisterImage", snap_arn)], False),
                ("no-tag-permission", [allow("ec2:RegisterImage", [image_arn + "*", snap_arn])], True),
                ("no-describe-permission", [allow("ec2:RegisterImage", [image_arn + "*", snap_arn]), {"Effect": "Deny", "Action": "ec2:DescribeSnapshots", "Resource": "*"}], False)):
            client = self.assumed_image(label, statements)
            params = dict(base, Name=p + "-" + label)
            if not tagged:
                params.pop("TagSpecifications")
            self.observe("iam-" + label, "ec2", "register_image", params, client=client, caller=label)
        self.observe("snapshot-in-use", "ec2", "delete_snapshot", {"SnapshotId": sid})
        self.observe("deregister-primary", "ec2", "deregister_image", {"ImageId": image}, required=True)
        self.observe("describe-deregistered", "ec2", "describe_images", {"ImageIds": [image]})
        self.observe("deregister-repeated", "ec2", "deregister_image", {"ImageId": image})

    def sharing(self):
        member = self.args.member_account
        credentials = self.clients["sts"].assume_role(RoleArn="arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole",
            RoleSessionName="stackd-image-readonly", DurationSeconds=900,
            Policy=json.dumps(policy([allow(["ec2:DescribeImages", "ec2:DescribeImageAttribute"], "*")])) )["Credentials"]
        session = boto3.Session(region_name=self.args.region, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        reader = session.client("ec2", config=CONFIG)
        identity = self.observe("member-identity", "sts", "get_caller_identity", client=session.client("sts", config=CONFIG), caller="member", required=True)
        if identity["Account"] != member:
            raise RuntimeError("Read-only member identity mismatch")
        self.data["scope"] = "Owned empty snapshot and one AMI shared temporarily with verified existing organization member; only read-only STS session on existing role, no role/default/public-access modifications"
        self.save()
        snapshot = self.start("empty-sharing", Encrypted=False)
        self.finish("empty-sharing", snapshot)
        image = self.observe("register-sharing", "ec2", "register_image", {"Name": self.data["prefix"],
            "Description": "owned sharing evidence", "Architecture": "x86_64", "VirtualizationType": "hvm", "RootDeviceName": "/dev/sda1",
            "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": snapshot["SnapshotId"]}}],
            "TagSpecifications": [{"ResourceType": "image", "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]}]}, required=True)["ImageId"]
        self.observe("member-before-share", "ec2", "describe_images", {"ImageIds": [image]}, client=reader, caller="member")
        for suffix, permissions in (("self", [{"UserId": self.args.account}]), ("member", [{"UserId": member}])):
            self.observe("share-" + suffix, "ec2", "modify_image_attribute", {"ImageId": image, "LaunchPermission": {"Add": permissions}}, required=True)
            self.observe("permissions-after-" + suffix, "ec2", "describe_image_attribute", {"ImageId": image, "Attribute": "launchPermission"}, required=True)
        for attempt in range(30):
            self.observe("member-shared-" + str(attempt), "ec2", "describe_images", {"ImageIds": [image]}, client=reader, caller="member")
            if self.data["calls"][-1]["code"] == "Success":
                break
            time.sleep(2)
        for attribute in ("description", "launchPermission", "bootMode", "imdsSupport", "productCodes"):
            self.observe("member-attribute-" + attribute, "ec2", "describe_image_attribute", {"ImageId": image, "Attribute": attribute}, client=reader, caller="member")
        for user in ("self", self.args.account, member, "all"):
            self.observe("executable-" + user, "ec2", "describe_images", {"ImageIds": [image], "ExecutableUsers": [user]})
        self.observe("reset-sharing", "ec2", "reset_image_attribute", {"ImageId": image, "Attribute": "launchPermission"}, required=True)
        self.observe("permissions-after-reset", "ec2", "describe_image_attribute", {"ImageId": image, "Attribute": "launchPermission"}, required=True)
        self.observe("member-after-reset", "ec2", "describe_images", {"ImageIds": [image]}, client=reader, caller="member")

    def cleanup(self):
        result = self.data["cleanup"] = {"started_at": now(), "failures": [], "absent": {"images": [], "snapshots": [], "roles": []}}
        for image in reversed(self.data["owned"]["images"]):
            self.observe("cleanup-image-" + image, "ec2", "deregister_image", {"ImageId": image})
            if self.data["calls"][-1]["code"] not in ("Success", "InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
                result["failures"].append(image)
            self.observe("cleanup-check-" + image, "ec2", "describe_images", {"ImageIds": [image]})
            row = self.data["calls"][-1]
            if row["code"] == "InvalidAMIID.NotFound" or row.get("output", {}).get("Images") == []:
                result["absent"]["images"].append(image)
            else:
                result["failures"].append(image + " remains visible")
        for sid in reversed(self.data["owned"]["snapshots"]):
            for attempt in range(30):
                self.observe("cleanup-snapshot-" + sid, "ec2", "delete_snapshot", {"SnapshotId": sid})
                if self.data["calls"][-1]["code"] in ("Success", "InvalidSnapshot.NotFound"):
                    break
                time.sleep(2)
            self.observe("cleanup-check-" + sid, "ec2", "describe_snapshots", {"SnapshotIds": [sid]})
            if self.data["calls"][-1]["code"] == "InvalidSnapshot.NotFound":
                result["absent"]["snapshots"].append(sid)
            else:
                result["failures"].append(sid)
        role = self.data["owned"].get("role")
        if role:
            self.observe("cleanup-role-policy", "iam", "delete_role_policy", {"RoleName": role, "PolicyName": "owned-images-only"})
            self.observe("cleanup-role", "iam", "delete_role", {"RoleName": role})
            self.observe("cleanup-check-role", "iam", "get_role", {"RoleName": role})
            if self.data["calls"][-1]["code"] == "NoSuchEntity":
                result["absent"]["roles"].append(role)
            else:
                result["failures"].append(role)
        result.update(finished_at=now(), complete=not result["failures"])
        self.save()
        if result["failures"]:
            raise RuntimeError("Owned cleanup incomplete")


class SnapshotReferenceCapture(ImageCapture):
    def __init__(self, args):
        super().__init__(args)
        self.member_session = None
        self.member_snapshot_ids = None
        self.data["owned"].setdefault("image_accounts", {})
        self.data["owned"].setdefault("snapshot_shares", [])
        if not args.cleanup_only:
            self.data.update(mode="snapshot-references",
                scope="Owned empty snapshots and disposable owner/member images; private snapshot share only, no instances, standing-role/default/public-access changes",
                bounds={"maximum_owned_snapshots": args.max_reference_snapshots, "logical_gib_each": 1})
            self.data["documentation"].append("https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteSnapshot.html")
        self.save()

    def observe(self, label, service, method, parameters=None, **kwargs):
        out = super().observe(label, service, method, parameters, **kwargs)
        if method == "register_image" and "ImageId" in out:
            self.data["owned"]["image_accounts"][out["ImageId"]] = self.args.member_account if kwargs.get("caller") == "member" else self.args.account
            self.save()
        return out

    def member(self):
        ids = tuple(self.data["owned"]["snapshots"])
        if self.member_session is not None and self.member_snapshot_ids == ids:
            return self.member_session
        image_arn = "arn:aws:ec2:" + self.args.region + "::image/*"
        document = policy([
            allow("ec2:RegisterImage", image_arn),
            allow("ec2:RegisterImage", ["arn:aws:ec2:" + self.args.region + "::snapshot/" + sid for sid in ids]),
            allow("ec2:CreateTags", image_arn, {"StringEquals": {"aws:RequestTag/suite": self.data["prefix"]}}),
            allow("ec2:DeregisterImage", image_arn),
            allow(["ec2:DescribeImages", "ec2:DescribeImageAttribute", "ec2:DescribeSnapshots"], "*")])
        self.data["sessions"]["member-snapshot-references-" + str(len(ids))] = document
        self.save()
        credentials = self.clients["sts"].assume_role(RoleArn="arn:aws:iam::" + self.args.member_account + ":role/OrganizationAccountAccessRole",
            RoleSessionName="stackd-image-references", DurationSeconds=900, Policy=json.dumps(document))["Credentials"]
        session = boto3.Session(region_name=self.args.region, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        identity = self.observe("member-identity-" + str(len(ids)), "sts", "get_caller_identity",
            client=session.client("sts", config=CONFIG), caller="member", required=True)
        if identity["Account"] != self.args.member_account:
            raise RuntimeError("Snapshot-reference member identity mismatch")
        self.member_session = session.client("ec2", config=CONFIG)
        self.member_snapshot_ids = ids
        return self.member_session

    def empty_snapshot(self, label):
        if len(self.data["owned"]["snapshots"]) >= self.args.max_reference_snapshots:
            return None
        snapshot = self.start(label, Encrypted=False)
        self.finish(label, snapshot)
        return snapshot["SnapshotId"]

    def register_reference(self, label, sid, *, member=False, data_only=False, root_snapshot=None):
        mappings = [{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": sid}}]
        if data_only:
            root = {"SnapshotId": root_snapshot} if root_snapshot else {"VolumeSize": 1}
            mappings = [{"DeviceName": "/dev/sda1", "Ebs": root}, {"DeviceName": "/dev/sdf", "Ebs": {"SnapshotId": sid}}]
        out = self.observe(label, "ec2", "register_image", {"Name": self.data["prefix"] + "-" + label,
            "Architecture": "x86_64", "VirtualizationType": "hvm", "RootDeviceName": "/dev/sda1", "BlockDeviceMappings": mappings,
            "TagSpecifications": [{"ResourceType": "image", "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]}]},
            client=self.member() if member else None, caller="member" if member else "owner")
        if "ImageId" in out:
            self.observe(label + "-describe", "ec2", "describe_images", {"ImageIds": [out["ImageId"]]},
                client=self.member() if member else None, caller="member" if member else "owner", required=True)
        return out.get("ImageId")

    def delete_probe(self, label, sid):
        self.observe(label + "-dry", "ec2", "delete_snapshot", {"SnapshotId": sid, "DryRun": True})
        self.observe(label + "-actual", "ec2", "delete_snapshot", {"SnapshotId": sid})
        return self.data["calls"][-1]["code"] == "Success"

    def share_snapshot(self, label, sid, grant):
        if sid not in self.data["owned"]["snapshot_shares"]:
            self.data["owned"]["snapshot_shares"].append(sid)
            self.save()
        self.observe(label, "ec2", "modify_snapshot_attribute", {"SnapshotId": sid,
            "CreateVolumePermission": {"Add" if grant else "Remove": [{"UserId": self.args.member_account}]}}, required=True)
        self.observe(label + "-permissions", "ec2", "describe_snapshot_attribute",
            {"SnapshotId": sid, "Attribute": "createVolumePermission"}, required=True)

    def run(self):
        sid = self.empty_snapshot("root-reference")
        owner_image = self.register_reference("owner-root", sid)
        if owner_image is None:
            raise RuntimeError("Owned root registration prerequisite failed")
        if self.delete_probe("owner-root-registered", sid):
            raise RuntimeError("Root snapshot unexpectedly deleted; retained actual outcome")
        self.share_snapshot("share-owned-snapshot", sid, True)
        self.observe("member-visible-snapshot", "ec2", "describe_snapshots", {"SnapshotIds": [sid]}, client=self.member(), caller="member", required=True)
        member_image = self.register_reference("member-root", sid, member=True)
        self.observe("deregister-owner-root", "ec2", "deregister_image", {"ImageId": owner_image}, required=True)
        sid_deleted = False
        if member_image:
            sid_deleted = self.delete_probe("recipient-root-shared", sid)
            if not sid_deleted:
                self.share_snapshot("revoke-owned-snapshot", sid, False)
                sid_deleted = self.delete_probe("recipient-root-revoked", sid)
            else:
                self.data["gaps"].append("Shared recipient-root reference allowed deletion, so revocation on the same deleted snapshot cannot be exercised.")
            self.observe("member-image-after-owner-delete", "ec2", "describe_images", {"ImageIds": [member_image]},
                client=self.member(), caller="member", required=True)
            self.observe("deregister-member-root", "ec2", "deregister_image", {"ImageId": member_image},
                client=self.member(), caller="member", required=True)
        else:
            self.share_snapshot("revoke-owned-snapshot", sid, False)
        if sid_deleted:
            sid = self.empty_snapshot("data-reference")
        if sid:
            data_image = self.register_reference("owner-data-blank-root", sid, data_only=True)
            if data_image is None:
                root = self.empty_snapshot("isolated-root-source")
                if root:
                    data_image = self.register_reference("owner-data-isolated-root", sid, data_only=True, root_snapshot=root)
                else:
                    self.data["gaps"].append("AWS rejected the blank root. Isolating a data-only reference requires another owned root snapshot beyond this capture's bound.")
            if data_image:
                self.delete_probe("owner-data-only-registered", sid)
                self.observe("owner-data-image-after-delete", "ec2", "describe_images", {"ImageIds": [data_image]}, required=True)
        else:
            self.data["gaps"].append("Initial snapshot was deleted; data-only capture requires another owned snapshot beyond this capture's bound.")
        self.save()

    def cleanup(self):
        result = self.data["cleanup"] = {"started_at": now(), "failures": [], "absent": {"images": [], "snapshots": []}, "shares_removed": []}
        for image in reversed(self.data["owned"]["images"]):
            member = self.data["owned"]["image_accounts"].get(image, self.args.account) == self.args.member_account
            client = self.member() if member else None
            caller = "member" if member else "owner"
            self.observe("cleanup-image-" + image, "ec2", "deregister_image", {"ImageId": image}, client=client, caller=caller)
            if self.data["calls"][-1]["code"] not in ("Success", "InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
                result["failures"].append(image)
            out = self.observe("cleanup-check-" + image, "ec2", "describe_images", {"ImageIds": [image]}, client=client, caller=caller)
            if self.data["calls"][-1]["code"] == "InvalidAMIID.NotFound" or out.get("Images") == []:
                result["absent"]["images"].append(image)
            else:
                result["failures"].append(image + " remains visible")
        for sid in self.data["owned"]["snapshot_shares"]:
            self.observe("cleanup-revoke-" + sid, "ec2", "modify_snapshot_attribute", {"SnapshotId": sid,
                "CreateVolumePermission": {"Remove": [{"UserId": self.args.member_account}]}})
            if self.data["calls"][-1]["code"] not in ("Success", "InvalidSnapshot.NotFound"):
                result["failures"].append(sid + " share removal")
            out = self.observe("cleanup-share-check-" + sid, "ec2", "describe_snapshot_attribute",
                {"SnapshotId": sid, "Attribute": "createVolumePermission"})
            if self.data["calls"][-1]["code"] == "InvalidSnapshot.NotFound" or out.get("CreateVolumePermissions") == []:
                result["shares_removed"].append(sid)
            else:
                result["failures"].append(sid + " share remains")
        for sid in reversed(self.data["owned"]["snapshots"]):
            self.observe("cleanup-snapshot-" + sid, "ec2", "delete_snapshot", {"SnapshotId": sid})
            if self.data["calls"][-1]["code"] not in ("Success", "InvalidSnapshot.NotFound"):
                result["failures"].append(sid)
            self.observe("cleanup-check-" + sid, "ec2", "describe_snapshots", {"SnapshotIds": [sid]})
            if self.data["calls"][-1]["code"] == "InvalidSnapshot.NotFound":
                result["absent"]["snapshots"].append(sid)
            else:
                result["failures"].append(sid + " remains")
        result.update(finished_at=now(), complete=not result["failures"])
        self.save()
        if result["failures"]:
            raise RuntimeError("Snapshot-reference cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--member-account", help="Required for sharing and snapshot-reference modes")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--sharing-only", action="store_true")
    parser.add_argument("--snapshot-references", action="store_true")
    parser.add_argument("--max-reference-snapshots", type=int, default=1)
    args = parser.parse_args()
    args.audit_only = False
    if (args.sharing_only or args.snapshot_references) and not args.member_account:
        parser.error("--member-account is required for sharing and snapshot-reference modes")
    capture = SnapshotReferenceCapture(args) if args.snapshot_references else ImageCapture(args)
    def interrupt(*_):
        raise KeyboardInterrupt("capture interrupted")
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGALRM, interrupt)
    signal.alarm(600)
    try:
        if not args.cleanup_only:
            if args.sharing_only:
                capture.sharing()
            else:
                capture.run()
    finally:
        signal.alarm(0)
        capture.cleanup()


if __name__ == "__main__":
    main()
