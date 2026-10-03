#!/usr/bin/env python3
"""Actual retained CLI + signed SDK + firmware QEMU launch-template workflow."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import time
import uuid

from ssm_managed_guest_smoke import Smoke as GuestSmoke, REGION


class Smoke(GuestSmoke):
    # Reuse the existing signed SDK, native-controller and sparse EBS image
    # importer. This workflow does not install or substitute an SSM agent.
    def __init__(self, args):
        self.args, self.account = args, "815602947201"
        self.state = args.state_directory.resolve()
        self.state.mkdir(parents=True, exist_ok=False)
        self.prefix = "stackd-lt-guest-" + uuid.uuid4().hex[:10]
        self.endpoint = f"https://127.0.0.1:{args.port}"
        self.guest_endpoint = f"https://{args.gateway}:{args.port}"
        self.process = self.artifacts = self.log = None
        self.clients, self.owned = {}, {}
        self.data = {"source": "local actual CLI, signed SDK and firmware QEMU guest", "account": self.account,
                     "prefix": self.prefix, "calls": [], "observations": {}, "owned": self.owned, "cleanup": {},
                     "raw_image": str(args.raw_image), "bios": str(args.bios)}
        self.save()

    def prepare(self):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=stackd-lt-guest",
                        "-addext", f"subjectAltName=IP:127.0.0.1,IP:{self.args.gateway},DNS:localhost",
                        "-keyout", str(self.state / "server.key"), "-out", str(self.state / "server.crt")], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.start()

    def run(self):
        self.prepare()
        self.import_image()
        o = self.owned
        o["vpc"] = self.call("owned-vpc", "ec2", "create_vpc", CidrBlock="10.194.20.0/24")["Vpc"]["VpcId"]
        o["subnet"] = self.call("owned-subnet", "ec2", "create_subnet", VpcId=o["vpc"], CidrBlock="10.194.20.0/24", AvailabilityZone=REGION + "a")["Subnet"]["SubnetId"]
        o["sg"] = self.call("owned-sg", "ec2", "create_security_group", VpcId=o["vpc"], GroupName=self.prefix, Description=self.prefix)["GroupId"]
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        o["role"] = self.prefix
        role = self.call("owned-role", "iam", "create_role", RoleName=o["role"], AssumeRolePolicyDocument=json.dumps(trust))["Role"]
        o["profile"] = self.prefix
        self.call("owned-profile", "iam", "create_instance_profile", InstanceProfileName=o["profile"])
        self.call("bind-profile", "iam", "add_role_to_instance_profile", InstanceProfileName=o["profile"], RoleName=o["role"])
        tags = lambda kind: [{"ResourceType": kind, "Tags": [{"Key": "suite", "Value": self.prefix}]}]
        data = {"ImageId": o["image"], "InstanceType": "t3.nano", "IamInstanceProfile": {"Name": o["profile"]},
                "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 2, "InstanceMetadataTags": "enabled"},
                "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": o["subnet"], "Groups": [o["sg"]], "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
                "UserData": base64.b64encode(b"#!/bin/bash\necho WRONG_TEMPLATE_USERDATA >/dev/console\n").decode(),
                "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "suite", "Value": self.prefix}, {"Key": "override", "Value": "template"}]}]}
        create = {"LaunchTemplateName": self.prefix, "ClientToken": self.prefix, "LaunchTemplateData": data, "TagSpecifications": tags("launch-template")}
        o["template"] = self.call("create-template", "ec2", "create_launch_template", **create)["LaunchTemplate"]["LaunchTemplateId"]
        replay = self.call("replay-create", "ec2", "create_launch_template", **create)["LaunchTemplate"]
        assert replay["LaunchTemplateId"] == o["template"]
        self.call("inherit-version", "ec2", "create_launch_template_version", LaunchTemplateId=o["template"], SourceVersion="1", LaunchTemplateData={"InstanceType": "t3.micro"}, VersionDescription="inherited")
        self.call("default-version-two", "ec2", "modify_launch_template", LaunchTemplateId=o["template"], DefaultVersion="2")
        self.expect("cannot-delete-default", "InvalidParameterValue", "ec2", "delete_launch_template_versions", LaunchTemplateId=o["template"], Versions=["2"])
        self.authority(role["Arn"])
        admission = {"LaunchTemplate": {"LaunchTemplateId": o["template"], "Version": "2"}, "MinCount": 1, "MaxCount": 1, "DryRun": True}
        self.expect("template-interface-top-level-subnet-conflict", "InvalidParameterCombination", "ec2", "run_instances", SubnetId=o["subnet"], **admission)
        self.expect("template-primary-network-subnet-override", "DryRunOperation", "ec2", "run_instances", NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": o["subnet"]}], **admission)
        script = '''#!/bin/bash
set -eu
exec > >(tee /dev/console) 2>&1
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
for key in aws:ec2launchtemplate:id aws:ec2launchtemplate:version override suite; do
printf 'LT_META_%s=' "$key"
curl -fsS -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/meta-data/tags/instance/$key"
printf '\n'
done
printf 'STACKD_LT_FIRMWARE_BOOT_OK\n'
for attempt in $(seq 1 120); do
  if token=$(curl -fsS --max-time 3 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token); then
    if value=$(curl -fsS --max-time 3 -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/tags/instance/suite); then
      printf 'LT_LIVE_SUITE=%s\n' "$value"
    fi
  fi
  sleep 2
done
'''
        params = {"LaunchTemplate": {"LaunchTemplateName": self.prefix}, "MinCount": 1, "MaxCount": 1, "ClientToken": self.prefix + "-launch",
                  "InstanceType": "t3.nano", "MetadataOptions": {"HttpEndpoint": "enabled"}, "UserData": script,
                  "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "override", "Value": "explicit"}]}]}
        result = self.call("launch-template-real-guest", "ec2", "run_instances", **params)
        o["instance"] = result["Instances"][0]["InstanceId"]
        self.save()
        self.wait("firmware guest running", lambda: self.client("ec2").describe_instances(InstanceIds=[o["instance"]]), lambda r: r["Reservations"][0]["Instances"][0]["State"]["Name"] == "running", 240)
        desc = self.call("describe-launched-instance", "ec2", "describe_instances", InstanceIds=[o["instance"]])["Reservations"][0]["Instances"][0]
        assert desc["InstanceType"] == "t3.nano"
        assert desc["MetadataOptions"]["HttpTokens"] == "required" and desc["MetadataOptions"]["HttpPutResponseHopLimit"] == 2
        actual_tags = {t["Key"]: t["Value"] for t in desc["Tags"]}
        assert actual_tags["suite"] == self.prefix and actual_tags["override"] == "explicit"
        assert actual_tags["aws:ec2launchtemplate:id"] == o["template"] and actual_tags["aws:ec2launchtemplate:version"] == "2"
        o["volumes"] = [m["Ebs"]["VolumeId"] for m in desc["BlockDeviceMappings"]]
        console = self.wait("actual guest IMDS", lambda: self.client("ec2").get_console_output(InstanceId=o["instance"], Latest=True), lambda r: "STACKD_LT_FIRMWARE_BOOT_OK" in r.get("Output", ""), 300, 2)
        text = console["Output"]
        assert "LT_META_aws:ec2launchtemplate:version=2" in text and "LT_META_override=explicit" in text
        self.data["observations"]["guest_console"] = text
        replay = self.call("replay-launch", "ec2", "run_instances", **params)
        assert replay["Instances"][0]["InstanceId"] == o["instance"]
        self.data_authority()
        before = self.call("current-instance-template-data", "ec2", "get_launch_template_data", InstanceId=o["instance"])["LaunchTemplateData"]
        assert before["ImageId"] == o["image"] and before["InstanceType"] == "t3.nano"
        assert {x["Key"]: x["Value"] for x in before["TagSpecifications"][0]["Tags"]} == {"suite": self.prefix, "override": "explicit"}
        self.stop()
        self.start()
        after = self.call("retained-template-data", "ec2", "get_launch_template_data", InstanceId=o["instance"])["LaunchTemplateData"]
        assert after == before
        self.call("tag-through-restarted-controller", "ec2", "create_tags", Resources=[o["instance"]], Tags=[{"Key": "suite", "Value": self.prefix + "-restarted"}])
        live_marker = "LT_LIVE_SUITE=" + self.prefix + "-restarted"
        resumed = self.wait("guest IMDS after retained restart", lambda: self.client("ec2").get_console_output(InstanceId=o["instance"], Latest=True), lambda r: live_marker in r.get("Output", ""), 90, 2)
        self.data["observations"]["guest_after_restart"] = resumed["Output"]
        self.call("default-after-restart", "ec2", "modify_launch_template", LaunchTemplateId=o["template"], DefaultVersion="1")
        current = self.call("retained-versions", "ec2", "describe_launch_template_versions", LaunchTemplateId=o["template"], Versions=["$Default", "$Latest"])["LaunchTemplateVersions"]
        assert {v["VersionNumber"] for v in current} == {1, 2}
        first = self.call("page-first", "ec2", "describe_launch_template_versions", LaunchTemplateId=o["template"], MaxResults=1)
        second = self.call("page-second", "ec2", "describe_launch_template_versions", LaunchTemplateId=o["template"], MaxResults=1, NextToken=first["NextToken"])
        assert first["LaunchTemplateVersions"][0]["VersionNumber"] == 2 and second["LaunchTemplateVersions"][0]["VersionNumber"] == 1
        self.call("delete-template-while-running", "ec2", "delete_launch_template", LaunchTemplateId=o["template"])
        self.expect("template-exact-absence", "InvalidLaunchTemplateId.NotFound", "ec2", "describe_launch_templates", LaunchTemplateIds=[o["template"]])
        retained = self.call("instance-retains-template-origin", "ec2", "describe_instances", InstanceIds=[o["instance"]])["Reservations"][0]["Instances"][0]
        assert {x["Key"]: x["Value"] for x in retained["Tags"]}["aws:ec2launchtemplate:version"] == "2"
        self.call("delete-customer-tags-only", "ec2", "delete_tags", Resources=[o["instance"]])
        retained = self.call("system-tags-survive-delete-all", "ec2", "describe_instances", InstanceIds=[o["instance"]])["Reservations"][0]["Instances"][0]
        assert {x["Key"]: x["Value"] for x in retained["Tags"]} == {"aws:ec2launchtemplate:id": o["template"], "aws:ec2launchtemplate:version": "2"}
        self.data["observations"].update(firmware_boot=True, template_overrides=True, retained_restart=True, native_system_tags=True)
        self.save()

    def authority(self, role):
        o = self.owned
        user = self.prefix + "-launcher"
        self.call("create-launcher", "iam", "create_user", UserName=user)
        o["user"] = user
        access = self.client("iam").create_access_key(UserName=user)["AccessKey"]
        o["access_key"] = access["AccessKeyId"]
        launcher = self.client("ec2", {"AccessKeyId": access["AccessKeyId"], "SecretAccessKey": access["SecretAccessKey"]})
        self.launcher = launcher
        arn = f"arn:aws:ec2:{REGION}:{self.account}:launch-template/{o['template']}"
        base = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}
        self.call("launcher-without-passrole", "iam", "put_user_policy", UserName=user, PolicyName="launch", PolicyDocument=json.dumps(base))
        params = {"LaunchTemplate": {"LaunchTemplateId": o["template"], "Version": "2"}, "MinCount": 1, "MaxCount": 1, "DryRun": True}
        self.expect("current-passrole-denied", "UnauthorizedOperation", "ec2", "run_instances", client=launcher, **params)
        base["Statement"].append({"Effect": "Allow", "Action": "iam:PassRole", "Resource": role, "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}})
        self.call("allow-current-passrole", "iam", "put_user_policy", UserName=user, PolicyName="launch", PolicyDocument=json.dumps(base))
        self.expect("authorized-template-dry-run", "DryRunOperation", "ec2", "run_instances", client=launcher, **params)
        base["Statement"].append({"Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "*", "Condition": {"ArnEquals": {"ec2:LaunchTemplate": arn}}})
        self.call("deny-template-current-policy", "iam", "put_user_policy", UserName=user, PolicyName="launch", PolicyDocument=json.dumps(base))
        self.expect("current-template-deny", "UnauthorizedOperation", "ec2", "run_instances", client=launcher, **params)
        base["Statement"][-1] = {"Effect": "Deny", "Action": "ec2:RunInstances", "Resource": f"arn:aws:ec2:{REGION}::image/*", "Condition": {"Bool": {"ec2:IsLaunchTemplateResource": "false"}}}
        self.call("protect-template-image", "iam", "put_user_policy", UserName=user, PolicyName="launch", PolicyDocument=json.dumps(base))
        self.expect("inherited-image-allowed", "DryRunOperation", "ec2", "run_instances", client=launcher, **params)
        self.expect("explicit-image-override-denied", "UnauthorizedOperation", "ec2", "run_instances", client=launcher, ImageId=o["image"], **params)
        self.data["observations"]["current_authority"] = ["PassRole", "ec2:LaunchTemplate", "ec2:IsLaunchTemplateResource"]
        self.save()

    def data_authority(self):
        dependencies = ["DescribeInstanceAttribute", "DescribeInstanceCreditSpecifications", "DescribeVolumes"]
        for denied in dependencies:
            actions = ["ec2:GetLaunchTemplateData"] + ["ec2:" + action for action in dependencies if action != denied]
            policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
            self.call("deny-data-dependency-" + denied, "iam", "put_user_policy", UserName=self.owned["user"], PolicyName="launch", PolicyDocument=json.dumps(policy))
            self.expect("current-data-dependency-" + denied, "UnauthorizedOperation", "ec2", "get_launch_template_data", client=self.launcher, InstanceId=self.owned["instance"])
        policy["Statement"][0]["Action"] = ["ec2:GetLaunchTemplateData"] + ["ec2:" + action for action in dependencies]
        self.call("allow-data-dependencies", "iam", "put_user_policy", UserName=self.owned["user"], PolicyName="launch", PolicyDocument=json.dumps(policy))
        data = self.call("current-data-dependencies-allowed", "ec2", "get_launch_template_data", client=self.launcher, InstanceId=self.owned["instance"])["LaunchTemplateData"]
        assert data["ImageId"] == self.owned["image"]
        self.data["observations"]["get_data_dependencies"] = dependencies
        self.save()

    def cleanup(self):
        o = self.owned
        if "instance" in o:
            self.call("cleanup-terminate", "ec2", "terminate_instances", InstanceIds=[o["instance"]])
            self.wait("exact termination", lambda: self.client("ec2").describe_instances(InstanceIds=[o["instance"]]), lambda r: r["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated", 180)
            for volume in o.get("volumes", []):
                self.expect("cleanup-volume-absence", "InvalidVolume.NotFound", "ec2", "describe_volumes", VolumeIds=[volume])
        if "template" in o:
            try:
                self.client("ec2").delete_launch_template(LaunchTemplateId=o["template"])
            except self.client("ec2").exceptions.ClientError as err:
                if err.response["Error"]["Code"] != "InvalidLaunchTemplateId.NotFound": raise
        if "profile" in o:
            self.call("cleanup-unbind-profile", "iam", "remove_role_from_instance_profile", InstanceProfileName=o["profile"], RoleName=o["role"])
            self.call("cleanup-profile", "iam", "delete_instance_profile", InstanceProfileName=o["profile"])
        if "role" in o: self.call("cleanup-role", "iam", "delete_role", RoleName=o["role"])
        if "user" in o:
            if "access_key" in o: self.client("iam").delete_access_key(UserName=o["user"], AccessKeyId=o["access_key"])
            self.call("cleanup-user-policy", "iam", "delete_user_policy", UserName=o["user"], PolicyName="launch")
            self.call("cleanup-user", "iam", "delete_user", UserName=o["user"])
        for key, method, argument in (("sg", "delete_security_group", "GroupId"), ("subnet", "delete_subnet", "SubnetId"), ("vpc", "delete_vpc", "VpcId"), ("image", "deregister_image", "ImageId"), ("snapshot", "delete_snapshot", "SnapshotId")):
            if key in o: self.call("cleanup-" + key, "ec2", method, **{argument: o[key]})
        self.data["cleanup"]["complete"] = True
        self.save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--raw-image", type=Path, default=Path("/tmp/stackd-ubuntu-24.04-server.raw"))
    parser.add_argument("--bios", type=Path, default=Path("/usr/share/seabios/bios-256k.bin"))
    parser.add_argument("--state-directory", type=Path, default=Path("/tmp/lt229"))
    parser.add_argument("--port", type=int, default=15949)
    parser.add_argument("--gateway", default="10.194.20.1")
    parser.add_argument("--output", type=Path, default=Path("testdata/integration/ec2_launch_template_guest.json"))
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    smoke = Smoke(args)
    try:
        smoke.run()
    except BaseException as error:
        smoke.data["failure"] = {"type": type(error).__name__, "message": str(error)}
        smoke.save()
        raise
    finally:
        try:
            smoke.cleanup()
        except BaseException as error:
            smoke.data["cleanup"]["failure"] = {"type": type(error).__name__, "message": str(error)}
            smoke.save()
            raise
        finally:
            smoke.stop()
    print(json.dumps({"observations": smoke.data["observations"], "cleanup": smoke.data["cleanup"]}, default=str))
