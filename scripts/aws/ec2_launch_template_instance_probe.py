#!/usr/bin/env python3
"""One bounded owned t3.nano, no public IP; always terminate and remove dependencies."""
import argparse
import base64
import json
from pathlib import Path
import time

from ec2_launch_templates_probe import LaunchTemplatesCapture
from ebs_encryption_probe import now


class InstanceCapture(LaunchTemplatesCapture):
    def launch(self):
        p = self.data["prefix"]
        o = self.data["owned"]
        self.data["scope"] = "One owned t3.nano, no public IPv4, 8-GiB delete-on-terminate root, finite cleanup; template and explicit overrides, API and console IMDS evidence"
        self.save()
        image = self.session.client("ssm").get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
        o["vpc"] = self.ec2("create-vpc", "create_vpc", CidrBlock="10.194.20.0/24")["Vpc"]["VpcId"]; self.save()
        o["subnet"] = self.ec2("create-subnet", "create_subnet", VpcId=o["vpc"], CidrBlock="10.194.20.0/24")["Subnet"]["SubnetId"]; self.save()
        o["group"] = self.ec2("create-group", "create_security_group", VpcId=o["vpc"], GroupName=p, Description=p)["GroupId"]; self.save()
        script = '''#!/bin/bash
exec >/dev/console 2>&1
echo STACKD_LT_IMDS_BEGIN
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
for path in meta-data/instance-id meta-data/tags/instance meta-data/tags/instance/aws:ec2launchtemplate:id meta-data/tags/instance/aws:ec2launchtemplate:version meta-data/placement/availability-zone user-data; do
echo "PATH:$path"
curl -sS -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/$path"
echo
done
echo STACKD_LT_IMDS_END
'''
        data = {"ImageId": image, "InstanceType": "t3.nano", "MetadataOptions": {"HttpTokens": "required", "InstanceMetadataTags": "enabled", "HttpPutResponseHopLimit": 2},
                "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": o["subnet"], "Groups": [o["group"]], "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
                "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}],
                "UserData": base64.b64encode(script.encode()).decode(),
                "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "suite", "Value": p}, {"Key": "original", "Value": "template"}]}]}
        tid = self.ec2("create-template", "create_launch_template", LaunchTemplateName=p, LaunchTemplateData=data)["LaunchTemplate"]["LaunchTemplateId"]
        for label, params in (("default", {}), ("explicit-image", {"ImageId": image}), ("explicit-metadata", {"MetadataOptions": {"HttpEndpoint": "enabled"}})):
            self.ec2("dry-" + label, "run_instances", LaunchTemplate={"LaunchTemplateId": tid}, MinCount=1, MaxCount=1, DryRun=True, **params)
        launched = self.ec2("run-instance", "run_instances", LaunchTemplate={"LaunchTemplateId": tid}, MinCount=1, MaxCount=1,
                            ClientToken=p, MetadataOptions={"HttpEndpoint": "enabled"},
                            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "original", "Value": "override"}, {"Key": "explicit", "Value": "yes"}]}])
        o["instance"] = launched["Instances"][0]["InstanceId"]; self.save()
        print("COST_IDS " + json.dumps({"instance": o["instance"], "template": tid}), flush=True)
        for _ in range(90):
            desc = self.ec2("describe-instance", "describe_instances", InstanceIds=[o["instance"]])["Reservations"][0]["Instances"][0]
            o["volumes"] = [m["Ebs"]["VolumeId"] for m in desc.get("BlockDeviceMappings", [])]; self.save()
            if desc["State"]["Name"] == "running":
                break
            time.sleep(3)
        self.ec2("get-template-data", "get_launch_template_data", InstanceId=o["instance"])
        self.ec2("describe-template-tags", "describe_tags", Filters=[{"Name": "resource-id", "Values": [o["instance"]]}])
        for _ in range(48):
            console = self.ec2("console-imds", "get_console_output", InstanceId=o["instance"], Latest=True)
            text = console.get("Output", "")
            try:
                text = base64.b64decode(text).decode(errors="replace")
            except Exception:
                pass
            if "STACKD_LT_IMDS_END" in text:
                self.data["console_imds"] = text[text.index("STACKD_LT_IMDS_BEGIN"):]; self.save(); break
            time.sleep(5)
        self.ec2("delete-template-while-instance-running", "delete_launch_template", LaunchTemplateId=tid)
        self.ec2("get-data-after-template-delete", "get_launch_template_data", InstanceId=o["instance"])
        self.ec2("describe-after-template-delete", "describe_instances", InstanceIds=[o["instance"]])
        self.data.update(complete=True, capture_complete_at=now()); self.save()

    def cleanup(self):
        o = self.data["owned"]
        if o.get("instance"):
            self.ec2("cleanup-terminate", "terminate_instances", InstanceIds=[o["instance"]])
            for _ in range(90):
                out = self.ec2("cleanup-instance-state", "describe_instances", InstanceIds=[o["instance"]])
                if out["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated":
                    self.data["cleanup"]["instance_terminated"] = True; self.save(); break
                time.sleep(3)
            for volume in o.get("volumes", []):
                self.ec2("cleanup-volume-absence", "describe_volumes", VolumeIds=[volume])
        super().cleanup()
        for name, method, arg in (("group", "delete_security_group", "GroupId"), ("subnet", "delete_subnet", "SubnetId"), ("vpc", "delete_vpc", "VpcId")):
            if name in o:
                self.ec2("cleanup-" + name, method, **{arg: o[name]})
        self.data["cleanup"]["finished_at"] = now(); self.save()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--account", required=True)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/launch_template_instance.json"))
    p.add_argument("--audit-only", action="store_true")
    p.add_argument("--cleanup-only", action="store_true")
    a = p.parse_args()
    if a.region != "us-east-1": p.error("Only authorized us-east-1 region")
    c = InstanceCapture(a)
    if a.audit_only: c.audit()
    elif a.cleanup_only: c.cleanup()
    else:
        try: c.launch()
        finally: c.cleanup()
        c.audit()
