#!/usr/bin/env python3
"""Capture native EC2 empty-volume controls without changing account defaults.

Owns at most 30 volumes: normally 1-GiB gp2/gp3/standard and at most two
4-GiB io1/io2 volumes with 100 IOPS. HDD requests are below their minimum size.
No instances are created. Initialization mode owns one empty 1-GiB direct snapshot;
events mode owns one EventBridge rule and SQS queue. Credentials, pagination tokens
and queue receipt handles remain in memory. Cleanup verifies volumes absent and
removes snapshots, roles and event resources; --cleanup-only resumes interrupted
cleanup. Observation is bounded, not an assumption of immediate initialization.
Snapshot identifier mode makes read-only and DryRun requests only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

import boto3
from botocore.exceptions import ClientError

from ebs_encryption_probe import CONFIG, Capture, allow, now, policy, safe

OPERATIONS = ("CreateVolume", "DescribeVolumes", "DeleteVolume", "DescribeVolumeAttribute",
              "ModifyVolumeAttribute", "DescribeVolumeStatus", "ModifyVolume", "DescribeVolumesModifications", "EnableVolumeIO")
DOCS = ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + name + ".html" for name in OPERATIONS] + [
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modify-volume.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/monitoring-volume-modifications.html",
    "https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/supported-iam-actions-tagging.html",
]
MISSING = "vol-00000000000000000"


def sanitized(value):
    value = safe(value)
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower() in ("nexttoken", "authorization", "x-amz-security-token", "x-amz-signature", "x-amz-credential")
                else sanitized(child) for key, child in value.items()}
    if isinstance(value, list):
        return [sanitized(child) for child in value]
    if isinstance(value, str):
        return re.sub(r"Encoded authorization failure message: \S+", "Encoded authorization failure message: <redacted>", value)
    return value


class VolumeCapture(Capture):
    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only:
            self.data.update(prefix="stackd-ebs-volume-controls-" + uuid.uuid4().hex[:12], documentation=DOCS,
                scope="Owned small EBS volumes, optional empty initialization snapshot, bounded IAM role or event resources; no instance/default mutations")
            self.data.pop("payload", None)
        self.data["owned"].setdefault("volumes", {})
        self.actors = {"owner": self.clients["ec2"]}
        if args.events_only or self.data["owned"].get("events"):
            self.clients.update({service: self.session.client(service, config=CONFIG) for service in ("events", "sqs")})
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(sanitized(self.data), indent=2) + "\n")

    def observe(self, label, service, method, parameters=None, *, client=None, caller="owner", required=False):
        if service == "ec2":
            client = client or self.actors[caller]
        result = super().observe(label, service, method, parameters, client=client, caller=caller, required=required)
        row = self.data["calls"][-1]
        if method == "create_volume" and result.get("VolumeId"):
            self.data["owned"]["volumes"].setdefault(result["VolumeId"], {"label": label, "caller": caller})
        match = re.search(r"Encoded authorization failure message: (\S+)", row.get("error", {}).get("Message", ""))
        if match:
            try:
                decoded = self.clients["sts"].decode_authorization_message(EncodedMessage=match[1])
                row["decoded_authorization"] = safe(json.loads(decoded["DecodedMessage"]))
            except ClientError as error:
                row["decode_error"] = error.response["Error"]["Code"]
        for direction, values in (("request", parameters or {}), ("response", result)):
            if values.get("NextToken"):
                row[direction + "_pagination_token_sha256"] = hashlib.sha256(values["NextToken"].encode()).hexdigest()
        self.save()
        return result

    def ec2(self, label, method, parameters=None, **kwargs):
        return self.observe(label, "ec2", method, parameters, **kwargs)

    def tags(self, *extra):
        return [{"ResourceType": "volume", "Tags": [{"Key": "suite", "Value": self.data["prefix"]}, *extra]}]

    def create(self, label, parameters=None, *, base=True, dry=False, caller="owner", required=False):
        request = {"AvailabilityZone": self.data["zone"]["ZoneName"], "Size": 1, "VolumeType": "gp3"} if base else {}
        request.update(parameters or {})
        if dry:
            request["DryRun"] = True
        if not request.get("DryRun"):
            if request.get("Size", 0) > 4 or request.get("Iops", 0) > 3001 or request.get("Throughput", 0) > 2001:
                raise RuntimeError("Refusing potentially costly actual allocation")
            if len(self.data["owned"]["volumes"]) >= 30:
                raise RuntimeError("Owned volume count limit reached")
        return self.ec2(label, "create_volume", request, caller=caller, required=required)

    def available(self, vid):
        for attempt in range(60):
            result = self.ec2("available-" + vid + "-" + str(attempt), "describe_volumes", {"VolumeIds": [vid]}, required=True)
            state = result["Volumes"][0]["State"]
            if state == "available":
                return
            if state == "error":
                raise RuntimeError("Owned empty volume entered error")
            time.sleep(2)
        raise RuntimeError("Owned volume did not become available within 120 seconds")

    def admission(self):
        zone = self.data["zone"]
        for label, request in (
            ("missing-all", {}), ("missing-zone", {"Size": 1}),
            ("missing-size-snapshot", {"AvailabilityZone": zone["ZoneName"]}),
            ("empty-zone", {"Size": 1, "AvailabilityZone": ""}),
            ("bad-zone", {"Size": 1, "AvailabilityZone": "not-a-zone"}),
            ("empty-zone-id", {"Size": 1, "AvailabilityZoneId": ""}),
            ("bad-zone-id", {"Size": 1, "AvailabilityZoneId": "use1-az999"}),
            ("both-zone-selectors", {"Size": 1, "AvailabilityZone": zone["ZoneName"], "AvailabilityZoneId": zone["ZoneId"]}),
        ):
            for dry in (False, True):
                self.create("admission-" + label + "-dry-" + str(dry), request, base=False, dry=dry)
        cases = [
            ("size-zero", {"Size": 0}), ("size-negative", {"Size": -1}),
            ("type-empty", {"VolumeType": ""}), ("type-bad", {"VolumeType": "bad"}),
            ("type-case", {"VolumeType": "GP3"}), ("gp3-iops-low", {"Iops": 2999}),
            ("gp3-iops-per-gib", {"Iops": 3001}), ("gp3-throughput-low", {"Throughput": 124}),
            ("gp3-throughput-high", {"Throughput": 2001}), ("gp3-throughput-ratio", {"Throughput": 751}),
            ("gp2-iops", {"VolumeType": "gp2", "Iops": 100}),
            ("gp2-throughput", {"VolumeType": "gp2", "Throughput": 125}),
            ("standard-iops", {"VolumeType": "standard", "Iops": 100}),
            ("standard-throughput", {"VolumeType": "standard", "Throughput": 125}),
            ("io1-missing-iops", {"VolumeType": "io1"}), ("io2-missing-iops", {"VolumeType": "io2"}),
            ("io1-size-small", {"VolumeType": "io1", "Iops": 100}),
            ("io2-size-small", {"VolumeType": "io2", "Iops": 100}),
            ("io1-iops-low", {"VolumeType": "io1", "Size": 4, "Iops": 99}),
            ("io2-iops-low", {"VolumeType": "io2", "Size": 4, "Iops": 99}),
            ("io1-iops-ratio", {"VolumeType": "io1", "Size": 4, "Iops": 201}),
            ("st1-small", {"VolumeType": "st1"}), ("sc1-small", {"VolumeType": "sc1"}),
            ("gp3-multiattach", {"MultiAttachEnabled": True}),
            ("initialization-without-snapshot", {"VolumeInitializationRate": 100}),
            ("tags-wrong-resource", {"TagSpecifications": [{"ResourceType": "snapshot", "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]}]}),
            ("tags-duplicate", {"TagSpecifications": self.tags({"Key": "suite", "Value": "duplicate"})}),
            ("tags-reserved", {"TagSpecifications": self.tags({"Key": "aws:reserved", "Value": "x"})}),
            ("tags-empty-key", {"TagSpecifications": self.tags({"Key": "", "Value": "x"})}),
            ("token-too-long", {"ClientToken": "x" * 65}),
        ]
        for label, request in cases:
            for dry in (False, True):
                self.create("create-" + label + "-dry-" + str(dry), request, dry=dry)
        for label, request in (
            ("gp2-size-max-plus", {"VolumeType": "gp2", "Size": 16385}),
            ("gp3-size-max-plus", {"Size": 65537}), ("standard-size-max-plus", {"VolumeType": "standard", "Size": 1025}),
            ("gp3-iops-max-plus", {"Iops": 80001}), ("io1-iops-max-plus", {"VolumeType": "io1", "Iops": 64001}),
            ("io2-iops-max-plus", {"VolumeType": "io2", "Iops": 256001}),
        ):
            self.create("bounded-dry-only-" + label, request, dry=True)
        self.data["gaps"].append("Potentially large allocation upper bounds are DryRun-only; DryRun success is authority evidence, not actual allocation/validation proof")

    def bad_ids(self):
        for method, base in (("delete_volume", {}), ("describe_volume_attribute", {"Attribute": "autoEnableIO"}),
                             ("modify_volume_attribute", {"AutoEnableIO": {"Value": True}}), ("modify_volume", {"Size": 1})):
            for label, extra in (("absent", {}), ("empty", {"VolumeId": ""}), ("malformed", {"VolumeId": "bad"}),
                                 ("missing", {"VolumeId": MISSING})):
                for dry in (False, True):
                    self.ec2(method + "-" + label + "-dry-" + str(dry), method, dict(base, **extra, DryRun=dry))
        for method in ("describe_volumes", "describe_volume_status", "describe_volumes_modifications"):
            for label, ids in (("empty-list", []), ("empty-id", [""]), ("malformed", ["bad"]), ("missing", [MISSING])):
                for dry in (False, True):
                    parameters = {"VolumeIds": ids, "DryRun": dry}
                    if not ids:
                        parameters["Filters"] = [{"Name": "availability-zone" if method == "describe_volume_status" else "volume-id", "Values": ["not-a-zone" if method == "describe_volume_status" else MISSING]}]
                    self.ec2(method + "-" + label + "-dry-" + str(dry), method, parameters)

    def attributes(self, vid):
        for label, request in (("missing", {}), ("empty", {"Attribute": ""}), ("bad", {"Attribute": "bad"}),
                               ("auto", {"Attribute": "autoEnableIO"}), ("products", {"Attribute": "productCodes"})):
            for dry in (False, True):
                self.ec2("attribute-describe-" + label + "-dry-" + str(dry), "describe_volume_attribute", dict(request, VolumeId=vid, DryRun=dry))
        for label, request in (("absent", {}), ("empty", {"AutoEnableIO": {}}),
                               ("true", {"AutoEnableIO": {"Value": True}}), ("false", {"AutoEnableIO": {"Value": False}})):
            self.ec2("attribute-modify-" + label, "modify_volume_attribute", dict(request, VolumeId=vid))
            self.ec2("attribute-after-" + label, "describe_volume_attribute", {"VolumeId": vid, "Attribute": "autoEnableIO"})

    def discovery(self, vid):
        p = self.data["prefix"]
        for name, values in (("tag:suite", [p]), ("tag-key", ["suite"]), ("tag-value", [p]),
                             ("availability-zone", [self.data["zone"]["ZoneName"]]),
                             ("availability-zone-id", [self.data["zone"]["ZoneId"]]),
                             ("size", ["1"]), ("volume-type", ["gp3"]), ("status", ["available"]),
                             ("encrypted", ["false"]), ("multi-attach-enabled", ["false"]),
                             ("tag:suite", ["no-match"]), ("bad-filter", ["x"]), ("status", [])):
            self.ec2("volumes-filter-" + name + "-" + "-".join(values), "describe_volumes",
                {"VolumeIds": [vid], "Filters": [{"Name": name, "Values": values}]})
        self.ec2("volumes-duplicate-ids", "describe_volumes", {"VolumeIds": [vid, vid]})
        self.ec2("volumes-mixed-missing", "describe_volumes", {"VolumeIds": [vid, MISSING]})
        for method in ("describe_volumes", "describe_volume_status", "describe_volumes_modifications"):
            self.ec2(method + "-owned", method, {"VolumeIds": [vid]})
            for limit in (0, 1, 4, 5, 500, 501, 1000, 1001):
                self.ec2(method + "-page-ids-" + str(limit), method, {"VolumeIds": [vid], "MaxResults": limit})
            self.ec2(method + "-bad-token", method, {"VolumeIds": [vid], "NextToken": "invalid"})
            self.ec2(method + "-bad-filter", method, {"VolumeIds": [vid], "Filters": [{"Name": "bad-filter", "Values": ["x"]}]})
        for name, values in (("volume-status.status", ["ok"]), ("volume-status.status", ["insufficient-data"]),
                             ("volume-status.details-name", ["io-enabled"]), ("volume-status.details-status", ["passed"]),
                             ("availability-zone", [self.data["zone"]["ZoneName"]])):
            self.ec2("status-filter-" + name + "-" + values[0], "describe_volume_status",
                {"VolumeIds": [vid], "Filters": [{"Name": name, "Values": values}]})
        filters = [{"Name": "tag:suite", "Values": [p]}]
        for limit in (1, 5):
            result = self.ec2("volumes-filter-page-" + str(limit), "describe_volumes", {"Filters": filters, "MaxResults": limit})
            if result.get("NextToken"):
                token = result["NextToken"]
                parameters = {"Filters": filters, "MaxResults": limit, "NextToken": token}
                self.ec2("volumes-next-page-" + str(limit), "describe_volumes", parameters)
                self.ec2("volumes-next-page-replay-" + str(limit), "describe_volumes", parameters)
                self.ec2("volumes-next-page-changed-filter-" + str(limit), "describe_volumes",
                    dict(parameters, Filters=[{"Name": "tag:suite", "Values": ["no-match"]}]))

    def tokens(self):
        token = self.data["prefix"] + "-token"
        tags = self.tags({"Key": "name", "Value": "token"})
        request = {"ClientToken": token, "TagSpecifications": tags}
        first = self.create("token-create", request, required=True)
        self.create("token-identical-replay", request)
        self.create("token-explicit-defaults", dict(request, Iops=3000, Throughput=125, Encrypted=False, MultiAttachEnabled=False))
        reordered = [{"ResourceType": "volume", "Tags": list(reversed(tags[0]["Tags"]))}]
        self.create("token-reordered-tags", dict(request, TagSpecifications=reordered))
        self.create("token-changed-size", dict(request, Size=2))
        self.create("token-changed-tags", dict(request, TagSpecifications=self.tags({"Key": "name", "Value": "changed"})))
        self.create("token-zone-id-equivalent", {"AvailabilityZoneId": self.data["zone"]["ZoneId"], "Size": 1,
            "VolumeType": "gp3", **request}, base=False)
        self.available(first["VolumeId"])
        self.create("token-available-replay", request)
        self.delete(first["VolumeId"], "token-delete")
        self.create("token-deleted-replay", request)
        self.create("token-deleted-changed-size", dict(request, Size=2))

    def modification(self, vid, gp2):
        for label, request in (("absent-change", {}), ("same-size", {"Size": 1}), ("zero-size", {"Size": 0}),
                               ("bad-type", {"VolumeType": "bad"}), ("iops-low", {"Iops": 2999}),
                               ("throughput-low", {"Throughput": 124}), ("multiattach", {"MultiAttachEnabled": True})):
            for dry in (False, True):
                self.ec2("modify-" + label + "-dry-" + str(dry), "modify_volume", dict(request, VolumeId=vid, DryRun=dry))
        self.ec2("modify-grow", "modify_volume", {"VolumeId": vid, "Size": 2})
        self.ec2("modify-grow-repeat", "modify_volume", {"VolumeId": vid, "Size": 2})
        self.ec2("modify-grow-overlap", "modify_volume", {"VolumeId": vid, "Throughput": 126})
        self.ec2("modify-gp2-to-gp3", "modify_volume", {"VolumeId": gp2, "VolumeType": "gp3"})
        deadline = time.monotonic() + self.args.modification_wait
        pending = {vid, gp2}
        attempt = 0
        while pending:
            for current in list(pending):
                result = self.ec2("modification-state-" + current + "-" + str(attempt), "describe_volumes_modifications", {"VolumeIds": [current]})
                self.ec2("modification-volume-" + current + "-" + str(attempt), "describe_volumes", {"VolumeIds": [current]})
                rows = result.get("VolumesModifications", [])
                if rows and rows[0]["ModificationState"] in ("completed", "failed"):
                    pending.remove(current)
            if not pending or time.monotonic() >= deadline:
                break
            time.sleep(min(10, max(0, deadline - time.monotonic())))
            attempt += 1
        if pending:
            self.data["gaps"].append({"bounded_modification_wait_seconds": self.args.modification_wait, "not_terminal": sorted(pending)})
        for name, values in (("volume-id", [vid]), ("modification-state", ["completed", "optimizing", "modifying"]),
                             ("original-size", ["1"]), ("target-size", ["2"]), ("target-volume-type", ["gp3"]),
                             ("targetMultiAttachEnabled", ["false"])):
            self.ec2("modifications-filter-" + name, "describe_volumes_modifications",
                {"VolumeIds": [vid, gp2], "Filters": [{"Name": name, "Values": values}]})
        self.ec2("modify-shrink-after-grow", "modify_volume", {"VolumeId": vid, "Size": 1})
        self.ec2("modify-repeat-after-observation", "modify_volume", {"VolumeId": vid, "Size": 2})

    def authority(self, vid):
        p = self.data["prefix"]
        arn = f"arn:aws:ec2:{self.args.region}:{self.args.account}:volume/"
        actions = ["ec2:" + operation for operation in OPERATIONS] + ["ec2:CreateTags"]
        self.observe("create-owned-role", "iam", "create_role", {"RoleName": p,
            "AssumeRolePolicyDocument": json.dumps(policy([{"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}])),
            "Tags": [{"Key": "suite", "Value": p}]}, required=True)
        bound = policy([allow("ec2:CreateVolume", arn + "*", {"NumericLessThanEquals": {"ec2:VolumeSize": "4"}}),
            allow("ec2:CreateTags", arn + "*", {"StringEquals": {"aws:RequestTag/suite": p}}),
            allow([action for action in actions if action not in ("ec2:CreateVolume", "ec2:CreateTags")], arn + vid),
            allow(["ec2:DescribeVolumes", "ec2:DescribeVolumeStatus", "ec2:DescribeVolumesModifications"], "*")])
        self.observe("bound-owned-role", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "owned-volumes-only", "PolicyDocument": json.dumps(bound)}, required=True)
        time.sleep(15)
        create = allow("ec2:CreateVolume", arn + "*")
        tag = allow("ec2:CreateTags", arn + "*", {"StringEquals": {"ec2:CreateAction": "CreateVolume"}})
        cases = [
            ("create-volume-resource", [create, tag], True),
            ("create-empty-account-resource", [allow("ec2:CreateVolume", arn.replace(self.args.account, "") + "*"), tag], True),
            ("create-wrong-resource", [allow("ec2:CreateVolume", f"arn:aws:ec2:{self.args.region}::snapshot/*"), tag], True),
            ("create-no-tag-authority", [create], True), ("create-untagged-no-tag-authority", [create], False),
            ("create-tag-denied", [create, tag, {"Effect": "Deny", "Action": "ec2:CreateTags", "Resource": "*"}], True),
            ("create-request-tag-match", [allow("ec2:CreateVolume", arn + "*", {"StringEquals": {"aws:RequestTag/suite": p}}), tag], True),
            ("create-request-tag-mismatch", [allow("ec2:CreateVolume", arn + "*", {"StringEquals": {"aws:RequestTag/suite": "wrong"}}), tag], True),
            ("create-resource-tag-unavailable", [allow("ec2:CreateVolume", arn + "*", {"StringEquals": {"ec2:ResourceTag/suite": p}}), tag], True),
            ("create-type-condition", [allow("ec2:CreateVolume", arn + "*", {"StringEquals": {"ec2:VolumeType": "gp3", "ec2:AvailabilityZone": self.data["zone"]["ZoneName"]}, "NumericEquals": {"ec2:VolumeSize": "1"}}), tag], True),
            ("create-denied", [{"Effect": "Deny", "Action": "ec2:*", "Resource": "*"}], True),
        ]
        for label, statements, tagged in cases:
            ebs = self.assumed(label, statements)
            credentials = ebs._request_signer._credentials.get_frozen_credentials()
            self.actors[label] = boto3.client("ec2", region_name=self.args.region, config=CONFIG,
                aws_access_key_id=credentials.access_key, aws_secret_access_key=credentials.secret_key, aws_session_token=credentials.token)
            request = {"TagSpecifications": self.tags()} if tagged else {}
            for dry in (False, True):
                self.create("iam-" + label + "-dry-" + str(dry), request, dry=dry, caller=label)
            if label == "create-denied":
                for suffix, malformed in (("missing-all", {}), ("bad-zone", {"AvailabilityZone": "bad", "Size": 1}),
                                          ("zero-size", {"AvailabilityZone": self.data["zone"]["ZoneName"], "Size": 0})):
                    for dry in (False, True):
                        self.create("iam-denied-" + suffix + "-dry-" + str(dry), malformed, base=False, dry=dry, caller=label)
                for method, request in (("delete_volume", {"VolumeId": "bad"}), ("describe_volumes", {"VolumeIds": ["bad"]}),
                                         ("describe_volume_attribute", {"VolumeId": "bad", "Attribute": "bad"}),
                                         ("modify_volume_attribute", {"VolumeId": "bad"}), ("modify_volume", {"VolumeId": "bad"}),
                                         ("describe_volume_status", {"VolumeIds": ["bad"]}), ("describe_volumes_modifications", {"VolumeIds": ["bad"]})):
                    self.ec2("iam-denied-" + method + "-dry", method, dict(request, DryRun=True), caller=label)

    def delete(self, vid, label):
        self.ec2(label, "delete_volume", {"VolumeId": vid})
        for method in ("describe_volumes", "describe_volume_status", "describe_volumes_modifications"):
            self.ec2(label + "-immediate-" + method, method, {"VolumeIds": [vid]})
        self.ec2(label + "-repeat", "delete_volume", {"VolumeId": vid})
        for attempt in range(60):
            self.ec2(label + "-absence-" + str(attempt), "describe_volumes", {"VolumeIds": [vid]})
            if self.data["calls"][-1]["code"] == "InvalidVolume.NotFound":
                self.data["cleanup"].setdefault("absent_volumes", []).append(vid)
                self.save()
                return
            time.sleep(2)
        raise RuntimeError("Owned volume deletion not confirmed")

    def run(self):
        self.ec2("default-encryption-before", "get_ebs_encryption_by_default", required=True)
        zones = self.ec2("availability-zones", "describe_availability_zones", {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(row for row in zones["AvailabilityZones"] if row["State"] == "available")
        self.save()
        defaults = self.create("default-gp2", {"AvailabilityZone": self.data["zone"]["ZoneName"], "Size": 1, "TagSpecifications": self.tags()}, base=False, required=True)
        gp3 = self.create("gp3-defaults", {"TagSpecifications": self.tags()}, required=True)
        self.create("standard-defaults", {"VolumeType": "standard", "TagSpecifications": self.tags()}, required=True)
        self.create("zone-id-only", {"AvailabilityZoneId": self.data["zone"]["ZoneId"], "Size": 1, "TagSpecifications": self.tags()}, base=False, required=True)
        for kind in ("io1", "io2"):
            self.create(kind + "-minimum", {"Size": 4, "VolumeType": kind, "Iops": 100, "TagSpecifications": self.tags()})
        self.admission()
        self.bad_ids()
        self.available(gp3["VolumeId"])
        self.available(defaults["VolumeId"])
        self.attributes(gp3["VolumeId"])
        self.discovery(gp3["VolumeId"])
        self.tokens()
        self.modification(gp3["VolumeId"], defaults["VolumeId"])
        self.authority(gp3["VolumeId"])
        self.ec2("default-encryption-after", "get_ebs_encryption_by_default", required=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def bounds(self):
        zones = self.ec2("bounds-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(row for row in zones["AvailabilityZones"] if row["State"] == "available")
        self.save()
        for field, values in (("Iops", (-1, 0, 1, 500, 501)), ("Throughput", (-1, 0, 1))):
            for value in values:
                for dry in (False, True):
                    self.create("bounds-" + field + "-" + str(value) + "-dry-" + str(dry),
                        {field: value}, dry=dry)
        for kind in ("gp2", "standard"):
            for field in ("Iops", "Throughput"):
                self.create("bounds-" + kind + "-" + field + "-zero",
                    {"VolumeType": kind, field: 0})
        token_request = {"TagSpecifications": self.tags(), "ClientToken": self.data["prefix"] + "-grow"}
        fresh = self.create("bounds-pristine-grow-source", token_request, required=True)
        vid = fresh["VolumeId"]
        self.ec2("bounds-status-immediately-after-create", "describe_volume_status", {"VolumeIds": [vid]})
        self.ec2("bounds-volume-immediately-after-create", "describe_volumes", {"VolumeIds": [vid]})
        self.available(vid)
        self.ec2("bounds-enable-available", "enable_volume_io", {"VolumeId": vid})
        self.ec2("bounds-enable-available-dry", "enable_volume_io", {"VolumeId": vid, "DryRun": True})
        self.ec2("bounds-status-after-enable", "describe_volume_status", {"VolumeIds": [vid]})
        for field, value in (("Iops", 3000), ("Throughput", 125), ("Encrypted", False), ("MultiAttachEnabled", False)):
            self.create("bounds-token-explicit-" + field, dict(token_request, **{field: value}))
        self.ec2("bounds-pristine-grow", "modify_volume", {"VolumeId": vid, "Size": 2})
        self.ec2("bounds-pristine-grow-immediate", "describe_volumes", {"VolumeIds": [vid]})
        self.ec2("bounds-pristine-grow-overlap", "modify_volume", {"VolumeId": vid, "Size": 3})
        self.ec2("bounds-pristine-grow-shrink", "modify_volume", {"VolumeId": vid, "Size": 1})
        for attempt in range(7):
            result = self.ec2("bounds-grow-state-" + str(attempt), "describe_volumes_modifications", {"VolumeIds": [vid]})
            self.ec2("bounds-grow-volume-" + str(attempt), "describe_volumes", {"VolumeIds": [vid]})
            rows = result.get("VolumesModifications", [])
            if rows and rows[0]["ModificationState"] in ("completed", "failed"):
                break
            if attempt < 6:
                time.sleep(10)
        self.ec2("bounds-grow-noop-after-observation", "modify_volume", {"VolumeId": vid, "Size": 2})
        self.ec2("bounds-grow-shrink-after-observation", "modify_volume", {"VolumeId": vid, "Size": 1})
        self.create("bounds-token-replay-after-modify", token_request)
        self.create("bounds-token-current-size-after-modify", dict(token_request, Size=2))
        for iteration in range(3):
            for attempt in range(10):
                result = self.ec2("bounds-repeat-state-" + str(iteration) + "-" + str(attempt),
                    "describe_volumes_modifications", {"VolumeIds": [vid]})
                rows = result.get("VolumesModifications", [])
                if rows and rows[0]["ModificationState"] in ("completed", "failed"):
                    break
                time.sleep(2)
            self.ec2("bounds-repeat-modification-" + str(iteration), "modify_volume", {"VolumeId": vid, "Size": 2})
        for method in ("describe_volumes", "describe_volume_status", "describe_volumes_modifications"):
            filters = [{"Name": "availability-zone", "Values": ["not-a-zone"]}] if method == "describe_volume_status" else [{"Name": "volume-id", "Values": [vid]}]
            for limit in (-1, 0, 1, 4, 5, 500, 501, 1000, 1001):
                self.ec2("bounds-page-" + method + "-" + str(limit), method, {"Filters": filters, "MaxResults": limit})
            self.ec2("bounds-page-" + method + "-bad-token", method, {"Filters": filters, "NextToken": "invalid"})
        for name in ("target-multi-attach-enabled", "original-multi-attach-enabled", "originalMultiAttachEnabled", "bad-filter"):
            self.ec2("bounds-modification-filter-" + name, "describe_volumes_modifications",
                {"VolumeIds": [vid], "Filters": [{"Name": name, "Values": ["false"]}]})
        self.delete(vid, "bounds-delete-modified")
        self.create("bounds-token-deleted-after-modify", token_request)
        self.create("bounds-token-deleted-current-size", dict(token_request, Size=2))
        for method, parameters in (("delete_volume", {"VolumeId": vid}),
                                   ("describe_volumes", {"VolumeIds": [vid]}),
                                   ("describe_volume_attribute", {"VolumeId": vid, "Attribute": "autoEnableIO"}),
                                   ("modify_volume_attribute", {"VolumeId": vid, "AutoEnableIO": {"Value": True}}),
                                   ("modify_volume", {"VolumeId": vid, "Size": 2}),
                                   ("enable_volume_io", {"VolumeId": vid}),
                                   ("describe_volume_status", {"VolumeIds": [vid]}),
                                   ("describe_volumes_modifications", {"VolumeIds": [vid]})):
            for dry in (False, True):
                self.ec2("bounds-deleted-" + method + "-dry-" + str(dry), method, dict(parameters, DryRun=dry))
        self.data["capture_complete_at"] = now()
        self.save()

    def configuration(self):
        zones = self.ec2("configuration-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(row for row in zones["AvailabilityZones"] if row["State"] == "available")
        self.save()
        for label, parameters in (
            ("gp3-iops-100", {"Iops": 100}), ("gp3-iops-100-throughput-125", {"Iops": 100, "Throughput": 125}),
            ("gp3-iops-100-throughput-750", {"Iops": 100, "Throughput": 750}),
            ("gp3-iops-500-throughput-751", {"Iops": 500, "Throughput": 751}),
            ("io1-high", {"VolumeType": "io1", "Size": 4, "Iops": 64001}),
            ("io2-high", {"VolumeType": "io2", "Size": 4, "Iops": 256001}),
            ("io2-ratio", {"VolumeType": "io2", "Size": 4, "Iops": 4001}),
            ("gp3-blank-type-iops", {"VolumeType": "", "Iops": 3000}),
        ):
            self.create("configuration-" + label, parameters, dry=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def io_modifications(self):
        zones = self.ec2("io-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(row for row in zones["AvailabilityZones"] if row["State"] == "available")
        self.save()
        for kind in ("io1", "io2"):
            source = self.create(kind + "-multi-source",
                {"VolumeType": kind, "Size": 4, "Iops": 100, "MultiAttachEnabled": True, "TagSpecifications": self.tags()},
                required=True)
            vid = source["VolumeId"]
            self.available(vid)
            cases = [("same-size", {"Size": 4}), ("change-type", {"VolumeType": "gp3", "MultiAttachEnabled": False}),
                     ("disable-multi", {"MultiAttachEnabled": False})]
            for label, request in cases:
                self.ec2(kind + "-multi-" + label, "modify_volume", dict(request, VolumeId=vid))
                for attempt in range(10):
                    result = self.ec2(kind + "-multi-" + label + "-state-" + str(attempt),
                        "describe_volumes_modifications", {"VolumeIds": [vid]})
                    rows = result.get("VolumesModifications", [])
                    if not rows or rows[0]["ModificationState"] in ("completed", "failed"):
                        break
                    time.sleep(2)
            self.ec2(kind + "-final-volume", "describe_volumes", {"VolumeIds": [vid]})
        self.data["capture_complete_at"] = now()
        self.save()

    def deletion(self):
        zones = self.ec2("delete-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(row for row in zones["AvailabilityZones"] if row["State"] == "available")
        self.save()
        source = self.create("delete-creating-source", {"TagSpecifications": self.tags()}, required=True)
        self.ec2("delete-creating-immediate", "delete_volume", {"VolumeId": source["VolumeId"]})
        self.ec2("delete-creating-after", "describe_volumes", {"VolumeIds": [source["VolumeId"]]})
        for label, parameters in (("absent", {}), ("empty", {"VolumeId": ""}),
                                  ("bad", {"VolumeId": "bad"}), ("zero", {"VolumeId": MISSING})):
            for dry in (False, True):
                self.ec2("enable-" + label + "-dry-" + str(dry), "enable_volume_io", dict(parameters, DryRun=dry))
        self.data["capture_complete_at"] = now()
        self.save()

    def events(self):
        self.data["documentation"].append("https://docs.aws.amazon.com/ebs/latest/userguide/ebs-cloud-watch-events.html")
        p = self.data["prefix"]
        region = self.args.region
        queue_arn = f"arn:aws:sqs:{region}:{self.args.account}:{p}"
        rule_arn = f"arn:aws:events:{region}:{self.args.account}:rule/{p}"
        queue = self.observe("events-create-queue", "sqs", "create_queue", {"QueueName": p}, required=True)["QueueUrl"]
        self.data["owned"]["events"] = {"queue": queue, "rule": p}
        self.save()
        document = policy([{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}])
        self.observe("events-queue-policy", "sqs", "set_queue_attributes",
            {"QueueUrl": queue, "Attributes": {"Policy": json.dumps(document)}}, required=True)
        self.observe("events-create-rule", "events", "put_rule", {"Name": p, "State": "ENABLED",
            "EventPattern": json.dumps({"source": ["aws.ec2"], "detail-type": ["EBS Volume Notification"],
                "detail": {"event": ["modifyVolume"]}})}, required=True)
        targets = self.observe("events-create-target", "events", "put_targets",
            {"Rule": p, "Targets": [{"Id": "owned-modification", "Arn": queue_arn}]}, required=True)
        if targets.get("FailedEntryCount"):
            raise RuntimeError("Owned modification target setup failed")
        time.sleep(10)
        zones = self.ec2("events-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(row for row in zones["AvailabilityZones"] if row["State"] == "available")
        self.save()
        vid = self.create("events-source", {"TagSpecifications": self.tags()}, required=True)["VolumeId"]
        self.available(vid)
        self.ec2("events-modify-grow", "modify_volume", {"VolumeId": vid, "Size": 2}, required=True)
        self.ec2("events-modify-initial-state", "describe_volumes_modifications", {"VolumeIds": [vid]})
        evidence = self.data["eventbridge"] = {"events": [], "boundary": "Positive delivered notifications only; missing records do not prove no notification"}
        seen = set()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = self.clients["sqs"].receive_message(QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for message in result.get("Messages", []):
                event = json.loads(message["Body"])
                if vid in message["Body"] and event.get("id") not in seen:
                    seen.add(event["id"])
                    evidence["events"].append({"received_at": now(), "event": safe(event)})
                    self.save()
                    print("MODIFICATION_EVENT " + json.dumps(safe(event)), flush=True)
                self.clients["sqs"].delete_message(QueueUrl=queue, ReceiptHandle=message["ReceiptHandle"])
        self.ec2("events-modify-final-state", "describe_volumes_modifications", {"VolumeIds": [vid]})
        evidence["captured_at"] = now()
        self.data["capture_complete_at"] = now()
        self.save()

    def cleanup_events(self):
        resource = self.data["owned"].get("events")
        if not resource or self.data["cleanup"].get("events_deleted"):
            return
        self.observe("events-cleanup-target", "events", "remove_targets",
            {"Rule": resource["rule"], "Ids": ["owned-modification"]})
        self.observe("events-cleanup-rule", "events", "delete_rule", {"Name": resource["rule"]})
        rule_deleted = self.data["calls"][-1]["code"] in ("Success", "ResourceNotFoundException")
        self.observe("events-cleanup-queue", "sqs", "delete_queue", {"QueueUrl": resource["queue"]})
        queue_deleted = self.data["calls"][-1]["code"] in ("Success", "AWS.SimpleQueueService.NonExistentQueue")
        self.data["cleanup"]["events_deleted"] = rule_deleted and queue_deleted
        self.save()
        if not self.data["cleanup"]["events_deleted"]:
            raise RuntimeError("Owned modification event resources not removed")

    def initialization(self):
        self.data["documentation"].extend([
            "https://docs.aws.amazon.com/ebs/latest/userguide/initalize-volume.html",
            "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-initialize-monitor.html",
            "https://docs.aws.amazon.com/ebs/latest/APIReference/API_StartSnapshot.html",
            "https://docs.aws.amazon.com/ebs/latest/APIReference/API_CompleteSnapshot.html",
        ])
        self.data["payload"] = {"recipe": "Empty direct snapshot; CompleteSnapshot ChangedBlocksCount=0",
            "logical_size_gib": 1, "written_blocks": 0}
        self.save()
        self.ec2("initialization-default-before", "get_ebs_encryption_by_default", required=True)
        zones = self.ec2("initialization-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(row for row in zones["AvailabilityZones"] if row["State"] == "available")
        self.save()
        source = self.start("initialization-empty-source")
        if not source:
            raise RuntimeError("Owned initialization snapshot was not created")
        self.finish("initialization-empty-source", source, readable=True)
        sid = source["SnapshotId"]
        self.data["source_snapshot"] = sid
        for rate in (None, 0, 99, 100, 300, 301):
            label = "omitted" if rate is None else str(rate)
            request = {"SnapshotId": sid, "TagSpecifications": self.tags({"Key": "rate", "Value": label})}
            if rate is not None:
                request["VolumeInitializationRate"] = rate
            for dry in (False, True):
                result = self.create("initialization-rate-" + label + "-dry-" + str(dry), request, dry=dry)
                if result.get("VolumeId"):
                    vid = result["VolumeId"]
                    self.ec2("initialization-immediate-status-" + label, "describe_volume_status", {"VolumeIds": [vid]})
                    self.ec2("initialization-immediate-volume-" + label, "describe_volumes", {"VolumeIds": [vid]})
        self.data["initialization_admission_captured_at"] = now()
        self.save()
        print("INITIALIZATION_ADMISSION_CAPTURED", flush=True)
        volumes = list(self.data["owned"]["volumes"])
        for vid in volumes:
            self.available(vid)
        deadline = time.monotonic() + self.args.initialization_wait
        attempt = 0
        pending = set(volumes)
        while volumes:
            result = self.ec2("initialization-settled-status-" + str(attempt), "describe_volume_status", {"VolumeIds": volumes})
            self.ec2("initialization-settled-volumes-" + str(attempt), "describe_volumes", {"VolumeIds": volumes})
            for row in result.get("VolumeStatuses", []):
                details = row.get("VolumeStatus", {}).get("Details", [])
                if any(detail.get("Name") == "initialization-state" and detail.get("Status") == "completed" for detail in details):
                    pending.discard(row["VolumeId"])
            if not pending or time.monotonic() >= deadline:
                break
            time.sleep(min(15, max(0, deadline - time.monotonic())))
            attempt += 1
        self.data["initialization_observation"] = {
            "bounded_wait_seconds": self.args.initialization_wait, "without_observed_completed_details": sorted(pending),
            "boundary": "Zero written snapshot blocks: this capture cannot establish data-bearing hydration duration or bandwidth"}
        self.ec2("initialization-default-after", "get_ebs_encryption_by_default", required=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def snapshot_ids(self):
        source = json.loads(self.args.snapshot_id_source_fixture.read_text())
        previous = json.loads(self.args.snapshot_id_previous_fixture.read_text())
        if source["account"] != self.args.account or previous["account"] != self.args.account:
            raise RuntimeError("Snapshot identifier baselines must belong to the guarded owner")
        sid = source["source_snapshot"]
        if sid not in source["owned"]["snapshots"] or not re.fullmatch(r"snap-[0-9a-f]{17}", sid):
            raise RuntimeError("Expected a captured owned long-form source snapshot")
        body = sid[5:]
        cases = [
            ("formerly-owned-initialization", sid),
            ("previously-owned-data", previous["owned"]["snapshots"][0]),
            ("reported-missing", "snap-0123456789abcdef0"),
            ("reversed-sequence", "snap-0fedcba9876543210"),
            ("source-first-eight", "snap-" + body[:8]),
            ("source-last-eight", "snap-" + body[-8:]),
            ("source-uppercase-hex", "snap-" + body.upper()),
        ]
        for length in (8, 17):
            for digit in ("0", "1", "f"):
                cases.append(("repeated-" + digit + "-length-" + str(length), "snap-" + digit * length))
        for leading in ("0", "1", "f"):
            cases.extend([
                ("source-leading-" + leading, "snap-" + leading + body[1:]),
                ("sequence-leading-" + leading, "snap-" + leading + "123456789abcdef0"),
                ("ones-leading-" + leading, "snap-" + leading + "1" * 16),
                ("fs-leading-" + leading, "snap-" + leading + "f" * 16),
            ])
        for position, digit in enumerate(body):
            changed = format((int(digit, 16) + 1) % 16, "x")
            cases.append(("source-mutated-nibble-" + str(position), "snap-" + body[:position] + changed + body[position + 1:]))
        cases = list({snapshot_id: (label, snapshot_id) for label, snapshot_id in reversed(cases)}.values())[::-1]
        self.data["documentation"].extend([
            "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html",
            "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshotAttribute.html",
        ])
        self.data["identifier_cases"] = [{"label": label, "snapshot_id": snapshot_id, "hex_digits": len(snapshot_id) - 5}
            for label, snapshot_id in cases]
        self.data["identifier_baselines"] = {"source_fixture": str(self.args.snapshot_id_source_fixture),
            "previous_fixture": str(self.args.snapshot_id_previous_fixture),
            "boundary": "Source was already deleted before this supplement; its prior live success and deletion are retained in the source fixture. No arbitrary actual CreateVolume is issued."}
        self.save()
        zones = self.ec2("snapshot-id-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        zone = next(row["ZoneName"] for row in zones["AvailabilityZones"] if row["State"] == "available")
        for label, snapshot_id in cases:
            self.ec2("snapshot-id-describe-" + label, "describe_snapshots", {"SnapshotIds": [snapshot_id]})
            self.ec2("snapshot-id-attribute-" + label, "describe_snapshot_attribute",
                {"SnapshotId": snapshot_id, "Attribute": "createVolumePermission"})
            self.create("snapshot-id-create-dry-" + label,
                {"AvailabilityZone": zone, "SnapshotId": snapshot_id, "VolumeType": "gp3"}, base=False, dry=True)
        self.data["capture_complete_at"] = now()
        self.save()

    def snapshot_id_bits(self):
        source = json.loads(self.args.snapshot_id_source_fixture.read_text())
        previous = json.loads(self.args.snapshot_id_previous_fixture.read_text())
        cross = json.loads(self.args.snapshot_id_cross_fixture.read_text())
        if any(fixture["account"] != self.args.account for fixture in (source, previous, cross)):
            raise RuntimeError("Identifier baselines must belong to the guarded owner")
        originals = [source["source_snapshot"], previous["owned"]["snapshots"][0]]
        west = next(sid for sid, context in cross["owned"]["snapshot_contexts"].items()
            if context == {"caller": "owner", "region": "us-west-2"})
        cases = {}
        for index, sid in enumerate(originals):
            body = sid[5:]
            for position in (3, 4, 13, 14, 15, 16):
                for digit in "0123456789abcdef":
                    variant = "snap-" + body[:position] + digit + body[position + 1:]
                    cases.setdefault(("us-east-1", variant), {"label": "east-" + str(index) + "-nibble-" + str(position) + "-" + digit,
                        "snapshot_id": variant, "origin_id": sid, "origin_region": "us-east-1",
                        "request_region": "us-east-1", "position": position, "digit": digit})
        for region, sid, origin in (("us-east-1", west, "us-west-2"), ("us-west-2", west, "us-west-2"),
                ("us-west-2", originals[0], "us-east-1"), ("us-west-2", originals[1], "us-east-1")):
            cases.setdefault((region, sid), {"label": "region-control-" + region + "-" + sid,
                "snapshot_id": sid, "origin_id": sid, "origin_region": origin, "request_region": region})
        for position in (3, 4, 13, 14, 15, 16):
            body = west[5:]
            digit = format((int(body[position], 16) + 1) % 16, "x")
            variant = "snap-" + body[:position] + digit + body[position + 1:]
            for region in ("us-east-1", "us-west-2"):
                cases.setdefault((region, variant), {"label": "west-nibble-" + str(position) + "-" + region,
                    "snapshot_id": variant, "origin_id": west, "origin_region": "us-west-2",
                    "request_region": region, "position": position, "digit": digit})
        if len(cases) > 200:
            raise RuntimeError("Read-only identifier matrix exceeded its explicit call bound")
        self.data["scope"] = "Bounded read-only identifier routing/bit constraints; no resources or account mutations"
        self.data["identifier_cases"] = list(cases.values())
        self.data["identifier_baselines"] = {"source_fixture": str(self.args.snapshot_id_source_fixture),
            "previous_fixture": str(self.args.snapshot_id_previous_fixture), "cross_fixture": str(self.args.snapshot_id_cross_fixture),
            "boundary": "Finite observations do not establish a universal checksum/type/version decoder or stable backend topology."}
        self.data["documentation"].append("https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html")
        self.save()
        clients = {"us-east-1": self.clients["ec2"], "us-west-2": self.session.client("ec2", region_name="us-west-2", config=CONFIG)}
        for case in cases.values():
            self.ec2("snapshot-id-bits-" + case["label"], "describe_snapshots", {"SnapshotIds": [case["snapshot_id"]]},
                client=clients[case["request_region"]])
            self.data["calls"][-1]["region"] = case["request_region"]
            self.save()
        self.data["capture_complete_at"] = now()
        self.save()

    def cleanup(self):
        failures = []
        for vid in self.data["owned"]["volumes"]:
            if vid in self.data["cleanup"].get("absent_volumes", []):
                continue
            try:
                self.delete(vid, "cleanup-" + vid)
            except Exception as error:
                failures.append({"volume": vid, "error_type": type(error).__name__})
        role = self.data["owned"].get("role")
        if role and not self.data["cleanup"].get("role_deleted"):
            self.observe("cleanup-role-policy", "iam", "delete_role_policy", {"RoleName": role, "PolicyName": "owned-volumes-only"})
            self.observe("cleanup-role", "iam", "delete_role", {"RoleName": role})
            self.data["cleanup"]["role_deleted"] = self.data["calls"][-1]["code"] in ("Success", "NoSuchEntity")
            if not self.data["cleanup"]["role_deleted"]:
                failures.append({"role": role})
        deleted_snapshots = self.data["cleanup"].setdefault("deleted_snapshots", [])
        for sid in self.data["owned"].get("snapshots", []):
            if sid in deleted_snapshots:
                continue
            self.ec2("cleanup-snapshot-" + sid, "delete_snapshot", {"SnapshotId": sid})
            if self.data["calls"][-1]["code"] in ("Success", "InvalidSnapshot.NotFound"):
                deleted_snapshots.append(sid)
                self.ec2("cleanup-snapshot-absence-" + sid, "describe_snapshots", {"SnapshotIds": [sid]})
            else:
                failures.append({"snapshot": sid})
        self.data["cleanup"]["failures"] = failures
        self.data["cleanup"]["finished_at"] = now()
        self.save()
        if failures:
            raise RuntimeError("Owned resource cleanup incomplete; use --cleanup-only")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ebs/volume_controls.json"))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cleanup-only", action="store_true")
    group.add_argument("--bounds-only", action="store_true", help="Fresh small-volume numeric boundaries and pristine growth")
    group.add_argument("--configuration-only", action="store_true", help="DryRun-only cross-field normalization precedence")
    group.add_argument("--io-modifications-only", action="store_true", help="Two owned 4-GiB/100-IOPS Multi-Attach modification cases")
    group.add_argument("--deletion-only", action="store_true", help="One owned immediate create/delete and EnableVolumeIO admission")
    group.add_argument("--events-only", action="store_true", help="One owned volume/rule/queue for native modification notifications")
    group.add_argument("--initialization-only", action="store_true", help="One empty snapshot and small volume initialization-rate controls")
    group.add_argument("--snapshot-ids-only", action="store_true", help="Read-only and DryRun controlled snapshot identifier variants")
    group.add_argument("--snapshot-id-bits-only", action="store_true", help="At most200 read-only snapshot ID nibble/routing probes")
    parser.add_argument("--snapshot-id-source-fixture", type=Path, default=Path(".stackd/probes/ebs/volume_controls_initialization.json"))
    parser.add_argument("--snapshot-id-previous-fixture", type=Path, default=Path(".stackd/probes/ebs/volume_data.json"))
    parser.add_argument("--snapshot-id-cross-fixture", type=Path, default=Path(".stackd/probes/ebs/copy_data.json"))
    parser.add_argument("--modification-wait", type=int, default=120)
    parser.add_argument("--initialization-wait", type=int, default=330)
    args = parser.parse_args()
    args.audit_only = False
    capture = VolumeCapture(args)
    try:
        if not args.cleanup_only:
            if args.bounds_only:
                capture.bounds()
            elif args.configuration_only:
                capture.configuration()
            elif args.io_modifications_only:
                capture.io_modifications()
            elif args.deletion_only:
                capture.deletion()
            elif args.events_only:
                capture.events()
            elif args.initialization_only:
                capture.initialization()
            elif args.snapshot_ids_only:
                capture.snapshot_ids()
            elif args.snapshot_id_bits_only:
                capture.snapshot_id_bits()
            else:
                capture.run()
    finally:
        try:
            capture.cleanup()
        finally:
            capture.cleanup_events()


if __name__ == "__main__":
    main()
