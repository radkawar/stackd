#!/usr/bin/env python3
"""Signed rolling refresh and rollback through real QEMU guests and ALB packets."""
import argparse
import base64
import json
from pathlib import Path

from autoscaling_guest_smoke import Smoke as GuestSmoke


class Smoke(GuestSmoke):
    def after_load_balancer(self, lb):
        self.prepare_targets(lb)
        self.prepare_events()
        o = self.owned
        script = '''#!/bin/bash
set -eu
exec > >(tee /dev/console) 2>&1
instance=$(cat /var/lib/cloud/data/instance-id)
boot=$(cat /proc/sys/kernel/random/boot_id)
mkdir -p /opt/refresh-http
printf '{"version":"VERSION","instance":"%s","boot":"%s"}\\n' "$instance" "$boot" >/opt/refresh-http/index.html
cd /opt/refresh-http
exec python3 -u -m http.server 8080 --bind 0.0.0.0
'''
        data = {"ImageId": o["image"], "InstanceType": "t3.nano",
            "NetworkInterfaces": [{"DeviceIndex": 0, "Groups": [o["sg"]], "DeleteOnTermination": True, "AssociatePublicIpAddress": False}],
            "UserData": base64.b64encode(script.replace("VERSION", "one").encode()).decode()}
        o["template"] = self.call("refresh-template-one", "ec2", "create_launch_template", LaunchTemplateName=self.prefix,
            LaunchTemplateData=data)["LaunchTemplate"]["LaunchTemplateId"]
        self.call("refresh-template-two", "ec2", "create_launch_template_version", LaunchTemplateId=o["template"], SourceVersion="1",
            LaunchTemplateData={"UserData": base64.b64encode(script.replace("VERSION", "two").encode()).decode()})
        self.asg("refresh-group", "create_auto_scaling_group", AutoScalingGroupName=self.prefix,
            LaunchTemplate={"LaunchTemplateId": o["template"], "Version": "1"}, MinSize=0, MaxSize=2, DesiredCapacity=0,
            VPCZoneIdentifier=o["subnet"], TargetGroupARNs=[o["tg"]], HealthCheckType="ELB", HealthCheckGracePeriod=180,
            DefaultInstanceWarmup=0)
        o["group"] = self.prefix
        empty = self.asg("long-warmup-admission", "start_instance_refresh", AutoScalingGroupName=self.prefix,
            Preferences={"InstanceWarmup": 172801})["InstanceRefreshId"]
        self.wait("empty long-warmup refresh", lambda: self.client("autoscaling").describe_instance_refreshes(
            AutoScalingGroupName=self.prefix, InstanceRefreshIds=[empty])["InstanceRefreshes"][0],
            lambda row: row["Status"] == "Successful", 60)
        self.asg("launch-original-guest", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=1)
        before = self.wait("original version-one guest packet", lambda: self.http(o["dns"]), lambda x: x and x["version"] == "one", 360)
        self.wait("original InService", self.group, lambda g: g and len(g["Instances"]) == 1 and g["Instances"][0]["LifecycleState"] == "InService", 180)
        refresh = self.asg("rolling-refresh", "start_instance_refresh", AutoScalingGroupName=self.prefix,
            DesiredConfiguration={"LaunchTemplate": {"LaunchTemplateId": o["template"], "Version": "2"}},
            Preferences={"MinHealthyPercentage": 90, "MaxHealthyPercentage": 100, "InstanceWarmup": 10, "BakeTime": 600})["InstanceRefreshId"]
        def status():
            if "replacement_overlap" not in self.data["observations"]:
                group = self.group()
                live = [member for member in group["Instances"] if member["LifecycleState"] == "InService"]
                if len(live) == 2 and any(member["InstanceId"] == before["instance"] for member in live):
                    self.data["observations"]["replacement_overlap"] = group
                    self.save()
            return self.client("autoscaling").describe_instance_refreshes(AutoScalingGroupName=self.prefix,
                InstanceRefreshIds=[refresh])["InstanceRefreshes"][0]
        self.wait("refresh reaches Baking", status, lambda r: r["Status"] == "Baking", 600)
        assert "replacement_overlap" in self.data["observations"], "explicit rounded bounds retired the original before replacement"
        after = self.wait("version-two replacement packet", lambda: self.http(o["dns"]), lambda x: x and x["version"] == "two", 240)
        assert after["instance"] != before["instance"] and after["boot"] != before["boot"], (before, after)
        group = self.group()
        assert group["LaunchTemplate"]["Version"] == "1", group
        self.wait("original physically terminated", lambda: self.instance(before["instance"]), lambda i: i["State"]["Name"] == "terminated", 180)
        self.stop()
        self.start()
        reopened = self.wait("retained version-two boot after restart", lambda: self.http(o["dns"]), lambda x: x == after, 240)
        assert status()["Status"] == "Baking", status()
        self.asg("manual-refresh-rollback", "rollback_instance_refresh", AutoScalingGroupName=self.prefix)
        rolled = self.wait("rollback successful", status, lambda r: r["Status"] in ("RollbackSuccessful", "RollbackFailed"), 600)
        assert rolled["Status"] == "RollbackSuccessful", rolled
        rollback = self.wait("rollback version-one guest packet", lambda: self.http(o["dns"]), lambda x: x and x["version"] == "one", 240)
        assert rollback["boot"] != before["boot"] and rollback["instance"] not in (before["instance"], after["instance"]), rollback
        self.wait("version-two physically terminated", lambda: self.instance(after["instance"]), lambda i: i["State"]["Name"] == "terminated", 180)
        self.asg("commit-refresh", "start_instance_refresh", AutoScalingGroupName=self.prefix,
            DesiredConfiguration={"LaunchTemplate": {"LaunchTemplateId": o["template"], "Version": "2"}},
            Preferences={"MinHealthyPercentage": 0, "MaxHealthyPercentage": 100, "InstanceWarmup": 0})
        completed = self.wait("public desired config committed", self.group,
            lambda g: g and g["LaunchTemplate"]["Version"] == "2" and len(g["Instances"]) == 1, 600)
        final = self.wait("committed version-two packet", lambda: self.http(o["dns"]), lambda x: x and x["version"] == "two", 240)
        self.data["observations"].update(before=before, replacement=after, reopened=reopened, rollback=rollback,
            rollback_status=rolled, committed_group=completed, final=final)
        self.save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elbv2-node-executable", type=Path, default=Path("bin/stackd-elbv2-node-integration"))
    parser.add_argument("--raw-image", type=Path, default=Path("/tmp/stackd-ubuntu-24.04-server.raw"))
    parser.add_argument("--bios", type=Path, default=Path("/usr/share/seabios/bios-256k.bin"))
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--port", type=int, default=15971)
    parser.add_argument("--gateway", default="10.194.20.1")
    parser.add_argument("--output", type=Path, default=Path("testdata/integration/autoscaling_refresh.json"))
    args = parser.parse_args()
    args.upgrade_from_binary = None
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
        finally:
            smoke.stop()
    print(json.dumps({"observations": smoke.data["observations"], "cleanup": smoke.data["cleanup"]}, default=str))
