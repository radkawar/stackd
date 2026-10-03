#!/usr/bin/env python3
"""Capture EC2 monitoring with one bounded private t3.nano and exact-owned cleanup."""
import argparse
import json
import signal
import time
import uuid
from pathlib import Path

from ebs_encryption_probe import Capture, CONFIG, now


class MonitoringCapture(Capture):
    def __init__(self, args):
        super().__init__(args)
        if args.cleanup_only:
            return
        self.data.update(
            schema_version=1,
            prefix="stackd-ec2-monitoring-" + uuid.uuid4().hex[:12],
            scope="One private t3.nano, owned VPC/subnet/security group, delete-on-terminate root; detailed launch, duplicate/mixed/state/DryRun monitoring admission; no public network",
            documentation=[
                "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_MonitorInstances.html",
                "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_UnmonitorInstances.html",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html",
            ],
            owned={}, cleanup={}, gaps=[], complete=False,
        )
        self.data.pop("payload", None)
        self.data.pop("sessions", None)
        self.save()

    def ec2(self, label, method, **parameters):
        return self.observe(label, "ec2", method, parameters)

    def wait_state(self, label, state):
        for attempt in range(90):
            result = self.ec2(label + "-" + str(attempt), "describe_instances", InstanceIds=[self.data["owned"]["instance"]])
            instance = result["Reservations"][0]["Instances"][0]
            if instance["State"]["Name"] == state:
                return instance
            time.sleep(2)
        raise RuntimeError("Instance did not reach " + state)

    def run(self):
        # Native short IDs have lexical validation, unlike opaque long IDs.
        absent = "i-12345678"
        self.ec2("confirm-absent-target", "describe_instances", InstanceIds=[absent])
        if self.data["calls"][-1]["code"] != "InvalidInstanceID.NotFound":
            raise RuntimeError("Refusing to probe a target not confirmed absent")
        for method in ("monitor_instances", "unmonitor_instances"):
            for label, parameters in (
                ("missing", {}), ("empty", {"InstanceIds": []}),
                ("empty-id", {"InstanceIds": [""]}),
                ("malformed", {"InstanceIds": ["invalid"]}),
                ("malformed-prefix", {"InstanceIds": ["i-zzzzzzzz"]}),
                ("short-prefix", {"InstanceIds": ["i-"]}),
                ("absent", {"InstanceIds": [absent]}),
                ("duplicate-absent", {"InstanceIds": [absent, absent]}),
                ("dry-missing", {"DryRun": True}),
                ("dry-empty-id", {"InstanceIds": [""], "DryRun": True}),
                ("dry-malformed", {"InstanceIds": ["invalid"], "DryRun": True}),
                ("dry-absent", {"InstanceIds": [absent], "DryRun": True}),
            ):
                self.ec2(method + "-" + label, method, **parameters)
        p, owned = self.data["prefix"], self.data["owned"]
        tags = [{"Key": "suite", "Value": p}]
        image = self.session.client("ssm").get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
        owned["vpc"] = self.ec2("create-vpc", "create_vpc", CidrBlock="10.193.40.0/24", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]; self.save()
        owned["subnet"] = self.ec2("create-subnet", "create_subnet", VpcId=owned["vpc"], CidrBlock="10.193.40.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}])["Subnet"]["SubnetId"]; self.save()
        owned["group"] = self.ec2("create-group", "create_security_group", VpcId=owned["vpc"], GroupName=p, Description=p, TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}])["GroupId"]; self.save()
        launched = self.ec2("launch-detailed", "run_instances", ImageId=image, InstanceType="t3.nano", MinCount=1, MaxCount=1, ClientToken=p,
            Monitoring={"Enabled": True},
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": owned["subnet"], "Groups": [owned["group"]], "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
            BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}],
            TagSpecifications=[{"ResourceType": "instance", "Tags": tags}, {"ResourceType": "volume", "Tags": tags}])
        owned["instance"] = launched["Instances"][0]["InstanceId"]; self.save()
        instance = owned["instance"]
        for method in ("monitor_instances", "unmonitor_instances"):
            self.ec2("pending-" + method, method, InstanceIds=[instance])
        running = self.wait_state("running", "running")
        owned["volumes"] = [mapping["Ebs"]["VolumeId"] for mapping in running.get("BlockDeviceMappings", [])]; self.save()
        self.ec2("running-monitor-duplicates", "monitor_instances", InstanceIds=[instance, instance])
        self.ec2("running-monitor-repeat", "monitor_instances", InstanceIds=[instance])
        self.ec2("before-mixed-unmonitor", "describe_instances", InstanceIds=[instance])
        self.ec2("mixed-unmonitor", "unmonitor_instances", InstanceIds=[instance, absent])
        self.ec2("after-mixed-unmonitor", "describe_instances", InstanceIds=[instance])
        self.ec2("dry-unmonitor", "unmonitor_instances", InstanceIds=[instance], DryRun=True)
        self.ec2("after-dry-unmonitor", "describe_instances", InstanceIds=[instance])
        self.ec2("running-unmonitor-duplicates", "unmonitor_instances", InstanceIds=[instance, instance])
        self.ec2("mixed-monitor", "monitor_instances", InstanceIds=[absent, instance])
        self.ec2("after-mixed-monitor", "describe_instances", InstanceIds=[instance])
        self.ec2("dry-monitor", "monitor_instances", InstanceIds=[instance], DryRun=True)
        self.ec2("after-dry-monitor", "describe_instances", InstanceIds=[instance])
        self.ec2("stop-instance", "stop_instances", InstanceIds=[instance])
        for method in ("monitor_instances", "unmonitor_instances"):
            self.ec2("stopping-" + method, method, InstanceIds=[instance])
        self.wait_state("stopped", "stopped")
        for method in ("monitor_instances", "unmonitor_instances"):
            self.ec2("stopped-" + method, method, InstanceIds=[instance, instance])
            self.ec2("after-stopped-" + method, "describe_instances", InstanceIds=[instance])
        self.ec2("terminate-instance", "terminate_instances", InstanceIds=[instance])
        for method in ("monitor_instances", "unmonitor_instances"):
            self.ec2("shutting-down-" + method, method, InstanceIds=[instance])
        self.wait_state("terminated", "terminated")
        for method in ("monitor_instances", "unmonitor_instances"):
            self.ec2("terminated-" + method, method, InstanceIds=[instance])
            self.ec2("dry-terminated-" + method, method, InstanceIds=[instance], DryRun=True)
            self.ec2(method + "-empty-mixed", method, InstanceIds=[instance, ""])
            self.ec2(method + "-dry-empty-mixed", method, InstanceIds=[instance, ""], DryRun=True)
        document = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}}
        session = self.observe("read-only-federation", "sts", "get_federation_token", {"Name": "stackd-monitor-readonly", "DurationSeconds": 900, "Policy": json.dumps(document)}, required=True)
        credentials = session["Credentials"]
        client = self.session.client("ec2", config=CONFIG, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        self.data["sessions"] = {"read-only": document}; self.save()
        for method in ("monitor_instances", "unmonitor_instances"):
            for label, parameters in (
                ("denied-terminal", {"InstanceIds": [instance]}),
                ("denied-dry-terminal", {"InstanceIds": [instance], "DryRun": True}),
                ("denied-absent", {"InstanceIds": [absent]}),
                ("denied-dry-absent", {"InstanceIds": [absent], "DryRun": True}),
                ("denied-malformed", {"InstanceIds": ["invalid"]}),
                ("denied-dry-malformed", {"InstanceIds": ["invalid"], "DryRun": True}),
                ("denied-empty", {"InstanceIds": []}),
            ):
                self.observe(method + "-" + label, "ec2", method, parameters, client=client, caller="read-only")
        self.data.update(complete=True, capture_complete_at=now()); self.save()

    def cleanup(self):
        owned = self.data["owned"]
        if "instance" in owned:
            self.ec2("cleanup-terminate", "terminate_instances", InstanceIds=[owned["instance"]])
            self.wait_state("cleanup-terminated", "terminated")
            self.data["cleanup"]["instance_terminated"] = True; self.save()
            for volume in owned.get("volumes", []):
                self.ec2("cleanup-volume-absence", "describe_volumes", VolumeIds=[volume])
                if self.data["calls"][-1]["code"] != "InvalidVolume.NotFound":
                    raise RuntimeError("Owned root volume still exists")
        for kind, method, parameter in (("group", "delete_security_group", "GroupId"), ("subnet", "delete_subnet", "SubnetId"), ("vpc", "delete_vpc", "VpcId")):
            if kind in owned:
                self.ec2("cleanup-" + kind, method, **{parameter: owned[kind]})
                if self.data["calls"][-1]["code"] != "Success":
                    raise RuntimeError("Could not delete owned " + kind)
        for kind, method, parameter, code in (("group", "describe_security_groups", "GroupIds", "InvalidGroup.NotFound"), ("subnet", "describe_subnets", "SubnetIds", "InvalidSubnetID.NotFound"), ("vpc", "describe_vpcs", "VpcIds", "InvalidVpcID.NotFound")):
            if kind in owned:
                self.ec2("cleanup-absence-" + kind, method, **{parameter: [owned[kind]]})
                if self.data["calls"][-1]["code"] != code:
                    raise RuntimeError("Owned " + kind + " still exists")
        self.data["cleanup"].update(exact_network_absence=True, finished_at=now()); self.save()


def interrupt(signum, frame):
    raise RuntimeError("Bounded monitoring probe interrupted")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/instance_monitoring_owned.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    args.audit_only = False
    if args.region != "us-east-1":
        parser.error("This probe is scoped to us-east-1")
    capture = MonitoringCapture(args)
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only:
            signal.alarm(480)
            capture.run()
    except Exception as error:
        capture.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}; capture.save()
        raise
    finally:
        signal.alarm(0)
        capture.cleanup()
