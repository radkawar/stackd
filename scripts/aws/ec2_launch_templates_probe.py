#!/usr/bin/env python3
"""Owned free EC2 launch-template controls and dry-run launch contrasts."""
import argparse
import base64
import json
from pathlib import Path
import uuid

from aws_cli import call
from cloudtrail_events import collect_history
from ebs_encryption_probe import Capture, now, safe


class LaunchTemplatesCapture(Capture):
    def __init__(self, args):
        super().__init__(args)
        if not args.audit_only and not args.cleanup_only:
            self.data.update(schema_version=1, prefix="stackd-lt-" + uuid.uuid4().hex[:12],
                             scope="Owned free launch templates only; RunInstances always DryRun; no instance/network/account mutation",
                             documentation=["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + op + ".html" for op in (
                                 "CreateLaunchTemplate", "CreateLaunchTemplateVersion", "DescribeLaunchTemplates", "DescribeLaunchTemplateVersions",
                                 "ModifyLaunchTemplate", "DeleteLaunchTemplate", "DeleteLaunchTemplateVersions", "GetLaunchTemplateData", "RunInstances")],
                             owned={"templates": []}, complete=False)
            self.data.pop("payload", None)
            self.data.pop("sessions", None)
            self.save()

    def ec2(self, label, method, **parameters):
        out = self.observe(label, "ec2", method, parameters)
        if method == "create_launch_template" and out.get("LaunchTemplate"):
            tid = out["LaunchTemplate"]["LaunchTemplateId"]
            if tid not in self.data["owned"]["templates"]:
                self.data["owned"]["templates"].append(tid)
                self.save()
        return out

    def run(self):
        p = self.data["prefix"]
        self.ec2("missing-selector", "describe_launch_template_versions")
        self.ec2("invalid-name", "create_launch_template", LaunchTemplateName="a", LaunchTemplateData={"InstanceType": "t3.nano"})
        self.ec2("empty-data", "create_launch_template", LaunchTemplateName=p + "-empty", LaunchTemplateData={})
        self.ec2("empty-data-dry", "create_launch_template", LaunchTemplateName=p + "-dry", LaunchTemplateData={}, DryRun=True)
        data = {"ImageId": "ami-00000000000000001", "InstanceType": "t3.nano", "KeyName": "missing-key", "UserData": base64.b64encode(b"template-evidence-not-secret").decode(),
                "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 2},
                "Placement": {"Tenancy": "default", "AvailabilityZone": "us-east-1a"},
                "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": "snap-00000000000000001", "VolumeSize": 8, "DeleteOnTermination": True}}],
                "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "original", "Value": "yes"}]}]}
        params = {"LaunchTemplateName": p, "ClientToken": p + "-create", "VersionDescription": "first", "LaunchTemplateData": data,
                  "TagSpecifications": [{"ResourceType": "launch-template", "Tags": [{"Key": "suite", "Value": p}]}]}
        created = self.ec2("create", "create_launch_template", **params)
        tid = created["LaunchTemplate"]["LaunchTemplateId"]
        self.ec2("create-replay", "create_launch_template", **params)
        self.ec2("create-token-mismatch", "create_launch_template", **dict(params, VersionDescription="changed"))
        self.ec2("duplicate-name", "create_launch_template", LaunchTemplateName=p, LaunchTemplateData={"InstanceType": "t3.nano"})
        self.ec2("both-selectors", "describe_launch_template_versions", LaunchTemplateId=tid, LaunchTemplateName=p)
        self.ec2("describe", "describe_launch_templates", LaunchTemplateIds=[tid])
        self.ec2("describe-name", "describe_launch_templates", LaunchTemplateNames=[p])
        self.ec2("describe-filter", "describe_launch_templates", Filters=[{"Name": "tag:suite", "Values": [p]}], MaxResults=1)
        self.ec2("describe-bad-filter", "describe_launch_templates", LaunchTemplateIds=[tid], Filters=[{"Name": "garbage", "Values": ["x"]}])
        self.ec2("describe-bad-id", "describe_launch_templates", LaunchTemplateIds=["oops"])
        self.ec2("describe-missing-id", "describe_launch_templates", LaunchTemplateIds=["lt-00000000000000001"])
        self.ec2("describe-missing-name", "describe_launch_templates", LaunchTemplateNames=[p + "-missing"])
        for label, version in (("default", "$Default"), ("latest", "$Latest"), ("bad", "x"), ("zero", "0"), ("missing", "999")):
            self.ec2("version-" + label, "describe_launch_template_versions", LaunchTemplateId=tid, Versions=[version])
        version = {"LaunchTemplateId": tid, "SourceVersion": "1", "ClientToken": p + "-version", "VersionDescription": "second",
                   "LaunchTemplateData": {"MetadataOptions": {"HttpEndpoint": "enabled"}, "Placement": {"AvailabilityZone": "us-east-1b"}, "TagSpecifications": [{"ResourceType": "volume", "Tags": [{"Key": "new", "Value": "yes"}]}]}}
        self.ec2("inherit", "create_launch_template_version", **version)
        self.ec2("inherit-replay", "create_launch_template_version", **version)
        self.ec2("inherit-token-mismatch", "create_launch_template_version", **dict(version, VersionDescription="mismatch"))
        self.ec2("without-source", "create_launch_template_version", LaunchTemplateId=tid, LaunchTemplateData={"InstanceType": "t3.micro"})
        self.ec2("empty-inherit", "create_launch_template_version", LaunchTemplateId=tid, SourceVersion="$Latest", LaunchTemplateData={})
        self.ec2("versions", "describe_launch_template_versions", LaunchTemplateId=tid)
        self.ec2("versions-page", "describe_launch_template_versions", LaunchTemplateId=tid, MaxResults=1)
        self.ec2("versions-range", "describe_launch_template_versions", LaunchTemplateId=tid, MinVersion="2", MaxVersion="3")
        self.ec2("versions-mixed-range", "describe_launch_template_versions", LaunchTemplateId=tid, Versions=["1"], MinVersion="2")
        self.ec2("versions-duplicate", "describe_launch_template_versions", LaunchTemplateId=tid, Versions=["1", "1", "$Default"])
        self.ec2("modify-no-version", "modify_launch_template", LaunchTemplateId=tid)
        self.ec2("modify-default", "modify_launch_template", LaunchTemplateId=tid, DefaultVersion="2", ClientToken=p + "-modify")
        self.ec2("modify-token-mismatch", "modify_launch_template", LaunchTemplateId=tid, DefaultVersion="3", ClientToken=p + "-modify")
        self.ec2("modify-symbolic", "modify_launch_template", LaunchTemplateId=tid, DefaultVersion="$Latest")
        self.ec2("delete-versions", "delete_launch_template_versions", LaunchTemplateId=tid, Versions=["2", "3", "999", "$Latest", "x", "0", "1"])
        self.ec2("after-delete-versions", "describe_launch_template_versions", LaunchTemplateId=tid)
        self.ec2("after-delete-summary", "describe_launch_templates", LaunchTemplateIds=[tid])
        self.ec2("after-delete-create", "create_launch_template_version", LaunchTemplateId=tid, LaunchTemplateData={"InstanceType": "t3.nano"})
        for label, launch in (("missing-template", {"LaunchTemplateId": "lt-00000000000000001"}), ("present", {"LaunchTemplateId": tid}), ("missing-version", {"LaunchTemplateId": tid, "Version": "999"})):
            self.ec2("launch-dry-" + label, "run_instances", LaunchTemplate=launch, MinCount=1, MaxCount=1, DryRun=True)
        self.ec2("get-data-missing", "get_launch_template_data", InstanceId="i-00000000000000001")
        for label, stored in (("unsupported", {"HibernationOptions": {"Configured": True}, "InstanceMarketOptions": {"MarketType": "spot"}, "EnclaveOptions": {"Enabled": True}}),
                              ("invalid-values", {"ImageId": "nonsense", "InstanceType": "not-real", "UserData": "not base64", "MetadataOptions": {"HttpPutResponseHopLimit": 999}}),
                              ("network-conflict", {"SecurityGroupIds": ["sg-00000000000000001"], "NetworkInterfaces": [{"DeviceIndex": 0, "Groups": ["sg-00000000000000002"]}]})):
            self.ec2("store-" + label, "create_launch_template", LaunchTemplateName=p + "-" + label, LaunchTemplateData=stored)
        self.data.update(complete=True, capture_complete_at=now())
        self.save()

    def edges(self):
        p = self.data["prefix"]
        params = {"LaunchTemplateName": p, "ClientToken": p, "LaunchTemplateData": {"InstanceType": "t3.nano"}}
        tid = self.ec2("create", "create_launch_template", **params)["LaunchTemplate"]["LaunchTemplateId"]
        for number in (2, 3):
            self.ec2("create-v" + str(number), "create_launch_template_version", LaunchTemplateId=tid, LaunchTemplateData={"InstanceType": "t3.micro"})
        self.ec2("replay-after-versions", "create_launch_template", **params)
        self.ec2("delete-default-latest-missing", "delete_launch_template_versions", LaunchTemplateId=tid, Versions=["1", "3", "999"])
        self.ec2("after-delete", "describe_launch_templates", LaunchTemplateIds=[tid])
        self.ec2("after-delete-version", "describe_launch_template_versions", LaunchTemplateId=tid, Versions=["$Latest"])
        self.ec2("version-after-delete", "create_launch_template_version", LaunchTemplateId=tid, LaunchTemplateData={"InstanceType": "t3.nano"})
        self.ec2("delete-symbolic", "delete_launch_template_versions", LaunchTemplateId=tid, Versions=["$Latest", "$Default"])
        self.ec2("delete-zero", "delete_launch_template_versions", LaunchTemplateId=tid, Versions=["0"])
        self.ec2("delete-negative", "delete_launch_template_versions", LaunchTemplateId=tid, Versions=["-1"])
        self.ec2("delete-missing", "delete_launch_template_versions", LaunchTemplateId="lt-00000000000000001", Versions=["1"])
        self.ec2("version-by-name-missing", "describe_launch_template_versions", LaunchTemplateName=p, Versions=["999"])
        self.ec2("all-defaults", "describe_launch_template_versions", Versions=["$Default"], Filters=[{"Name": "launch-template-id", "Values": [tid]}])
        self.ec2("create-dry-duplicate", "create_launch_template", LaunchTemplateName=p, LaunchTemplateData={}, DryRun=True)
        for label, data in (("bad-type", {"InstanceType": "not-real"}), ("bad-userdata", {"UserData": "not base64"}),
                            ("bad-metadata", {"MetadataOptions": {"HttpPutResponseHopLimit": 999}}),
                            ("bad-key", {"KeyName": "missing-key"}), ("empty-object", {"Monitoring": {}})):
            self.ec2("store-" + label, "create_launch_template", LaunchTemplateName=p + "-" + label, LaunchTemplateData=data)
        self.ec2("delete-original", "delete_launch_template", LaunchTemplateId=tid)
        self.ec2("replay-after-delete", "create_launch_template", **params)
        self.data.update(complete=True, capture_complete_at=now())
        self.save()

    def deletion_edges(self):
        tid = self.ec2("create", "create_launch_template", LaunchTemplateName=self.data["prefix"], LaunchTemplateData={"InstanceType": "t3.nano"})["LaunchTemplate"]["LaunchTemplateId"]
        for version in (2, 3):
            self.ec2("version-" + str(version), "create_launch_template_version", LaunchTemplateId=tid, LaunchTemplateData={"InstanceType": "t3.micro"})
        self.ec2("delete-latest-and-missing", "delete_launch_template_versions", LaunchTemplateId=tid, Versions=["3", "999"])
        self.ec2("after-delete", "describe_launch_templates", LaunchTemplateIds=[tid])
        self.ec2("latest-after-delete", "describe_launch_template_versions", LaunchTemplateId=tid, Versions=["$Latest"])
        self.ec2("new-version-after-delete", "create_launch_template_version", LaunchTemplateId=tid, LaunchTemplateData={"InstanceType": "t3.nano"})
        self.ec2("delete-symbolic-latest", "delete_launch_template_versions", LaunchTemplateId=tid, Versions=["$Latest"])
        self.ec2("all-defaults", "describe_launch_template_versions", Versions=["$Default"])
        self.data.update(complete=True, capture_complete_at=now())
        self.save()

    def cleanup(self):
        for tid in self.data["owned"]["templates"]:
            self.ec2("cleanup-" + tid, "delete_launch_template", LaunchTemplateId=tid)
            self.ec2("cleanup-confirm-" + tid, "describe_launch_templates", LaunchTemplateIds=[tid])
        self.data["cleanup"]["finished_at"] = now()
        self.save()

    def audit(self):
        ids = {r["request_id"]: r["label"] for r in self.data["calls"] if r.get("request_id")}
        self.data["cloudtrail"] = safe(collect_history(lambda parameters: call("cloudtrail", "lookup-events", parameters, env=self.env, paginate=False, error_format="json"),
                                                        ids, start_time=self.data["captured_at"], event_sources=("ec2.amazonaws.com",), previous=self.data.get("cloudtrail")))
        self.save()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--account", required=True)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/launch_templates.json"))
    p.add_argument("--audit-only", action="store_true")
    p.add_argument("--cleanup-only", action="store_true")
    p.add_argument("--edges-only", action="store_true")
    p.add_argument("--deletion-only", action="store_true")
    a = p.parse_args()
    if a.region != "us-east-1":
        p.error("Only the authorized us-east-1 region is allowed")
    c = LaunchTemplatesCapture(a)
    if a.audit_only:
        c.audit()
    elif a.cleanup_only:
        c.cleanup()
    else:
        try:
            if a.deletion_only:
                c.deletion_edges()
            elif a.edges_only:
                c.edges()
            else:
                c.run()
        finally:
            c.cleanup()
        c.audit()
