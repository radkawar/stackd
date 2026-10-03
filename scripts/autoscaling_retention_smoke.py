#!/usr/bin/env python3
"""Retain a real Ubuntu ASG guest, replace it, reopen SQLite, then release it.

Reuses the ASG guest harness's signed clients, sparse EBS import, controller,
EventBridge/SQS lifecycle delivery, direct HTTP and exact resource cleanup.
No packages are downloaded or installed in the firmware-booted guests.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from botocore.exceptions import ClientError

from autoscaling_guest_smoke import Smoke as GroupSmoke, REGION


class Smoke(GroupSmoke):
    def after_load_balancer(self, lb):
        o = self.owned
        self.prepare_targets(lb, drain_seconds=5)
        self.prepare_events()
        script = '''#!/bin/bash
set -eu
exec > >(tee /dev/console) 2>&1
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
instance=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/instance-id)
group=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/tags/instance/aws:autoscaling:groupName)
boot=$(cat /proc/sys/kernel/random/boot_id)
mkdir -p /opt/retained-http
printf '{"instance":"%s","group":"%s","boot":"%s"}\\n' "$instance" "$group" "$boot" >/opt/retained-http/index.html
cd /opt/retained-http
exec python3 -u -m http.server 8080 --bind 0.0.0.0
'''
        o["template"] = self.call("retention-template", "ec2", "create_launch_template", LaunchTemplateName=self.prefix, LaunchTemplateData={
            "ImageId": o["image"], "InstanceType": "t3.nano", "UserData": base64.b64encode(script.encode()).decode(),
            "MetadataOptions": {"HttpTokens": "required", "InstanceMetadataTags": "enabled"},
            "NetworkInterfaces": [{"DeviceIndex": 0, "Groups": [o["sg"]], "DeleteOnTermination": True, "AssociatePublicIpAddress": False}],
        })["LaunchTemplate"]["LaunchTemplateId"]
        self.asg("create-retaining-group", "create_auto_scaling_group", AutoScalingGroupName=self.prefix,
                 LaunchTemplate={"LaunchTemplateId": o["template"], "Version": "1"}, MinSize=0, MaxSize=1, DesiredCapacity=1,
                 VPCZoneIdentifier=o["subnet"], TargetGroupARNs=[o["tg"]], HealthCheckGracePeriod=0, DefaultInstanceWarmup=0,
                 InstanceLifecyclePolicy={"RetentionTriggers": {"TerminateHookAbandon": "retain"}},
                 LifecycleHookSpecificationList=[{"LifecycleHookName": "terminate", "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
                                                   "HeartbeatTimeout": 600, "DefaultResult": "ABANDON"}])
        o["group"] = self.prefix
        self.save()
        self.asg("enable-retention-gauges", "enable_metrics_collection", AutoScalingGroupName=self.prefix, Granularity="1Minute",
                 Metrics=["GroupDesiredCapacity", "GroupInServiceInstances", "GroupTerminatingRetainedInstances", "GroupTotalInstances"])
        initial = self.wait("initial member in service", self.group,
                            lambda g: g and len(g["Instances"]) == 1 and g["Instances"][0]["LifecycleState"] == "InService", 300)
        original = initial["Instances"][0]["InstanceId"]
        original_ec2 = self.instance(original)
        address = original_ec2["PrivateIpAddress"] + ":8080"
        before = self.wait("original firmware HTTP", lambda: self.http(address), lambda r: r and r["instance"] == original, 300, 2)
        assert before["group"] == self.prefix, before
        self.wait("original ALB HTTP", lambda: self.http(o["dns"]), lambda r: r and r["instance"] == original, 180)
        first_activity = self.asg("request-replacement", "terminate_instance_in_auto_scaling_group", InstanceId=original, ShouldDecrementDesiredCapacity=False)["Activity"]
        action = self.action("autoscaling:EC2_INSTANCE_TERMINATING", original)
        targets = self.call("targets-before-hook-abandon", "elbv2", "describe_target_health", TargetGroupArn=o["tg"])["TargetHealthDescriptions"]
        assert not any(row["Target"]["Id"] == original for row in targets), targets
        during_hook = self.http(address)
        assert during_hook == before, (before, during_hook)
        self.data["observations"]["drained_before_termination_hook"] = {"targets": targets, "original_http": during_hook}
        self.complete(action, "ABANDON")
        retained = self.wait("retained member and replacement", self.group,
                             lambda g: g and g["DesiredCapacity"] == 1 and any(i["InstanceId"] == original and i["LifecycleState"] == "Terminating:Retained" for i in g["Instances"])
                             and any(i["InstanceId"] != original and i["LifecycleState"] == "InService" for i in g["Instances"]), 300)
        replacement = next(i["InstanceId"] for i in retained["Instances"] if i["InstanceId"] != original)
        replacement_address = self.instance(replacement)["PrivateIpAddress"] + ":8080"
        replacement_http = self.wait("replacement firmware HTTP", lambda: self.http(replacement_address),
                                     lambda r: r and r["instance"] == replacement, 300, 2)
        self.wait("replacement ALB HTTP", lambda: self.http(o["dns"]), lambda r: r and r["instance"] == replacement, 180)
        activities = self.call("retained-terminal-activities", "autoscaling", "describe_scaling_activities", AutoScalingGroupName=self.prefix)["Activities"]
        cancelled = [a for a in activities if a["StatusCode"] == "Cancelled" and a["ActivityId"] == first_activity["ActivityId"]]
        assert len(cancelled) == 1 and cancelled[0].get("EndTime"), cancelled
        self.data["observations"].update(original_http=before, replacement_http=replacement_http, retained_group=retained, cancelled_activity=cancelled[0])
        self.stop()
        self.start()
        after = self.wait("unchanged retained boot after restart", lambda: self.http(address), bool, 120)
        assert after == before, (before, after)
        reopened = self.group()
        assert reopened["DesiredCapacity"] == 1 and len(reopened["Instances"]) == 2, reopened
        assert {i["InstanceId"]: i["LifecycleState"] for i in reopened["Instances"]} == {original: "Terminating:Retained", replacement: "InService"}, reopened
        now_ec2 = self.instance(original)
        assert now_ec2["State"]["Name"] == "running" and now_ec2["BlockDeviceMappings"] == original_ec2["BlockDeviceMappings"], now_ec2
        assert {t["Key"]: t["Value"] for t in now_ec2["Tags"]}["aws:autoscaling:groupName"] == self.prefix, now_ec2
        self.wait("replacement still serves after restart", lambda: self.http(o["dns"]), lambda r: r and r == replacement_http, 180)
        self.data["observations"]["restart"] = {"original_http": after, "original_ec2": now_ec2, "group": reopened}
        try:
            self.client("autoscaling").set_instance_protection(
                AutoScalingGroupName=self.prefix, InstanceIds=[original], ProtectedFromScaleIn=True)
        except ClientError as rejection:
            assert rejection.response["Error"]["Code"] == "ValidationError", rejection.response
            rejected_id = rejection.response["ResponseMetadata"]["RequestId"]
        else:
            raise AssertionError("retained instance accepted scale-in protection")

        def protection_audit():
            rows = self.client("cloudtrail").lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "SetInstanceProtection"}])["Events"]
            for row in rows:
                event = json.loads(row["CloudTrailEvent"])
                if event["requestID"] == rejected_id:
                    return event

        rejected_event = self.wait("native-shaped retained protection audit", protection_audit, bool, 30)
        assert rejected_event["errorCode"] == "InvalidParameterValueException", rejected_event
        self.data["observations"]["retained_protection_cloudtrail"] = rejected_event
        start = datetime.now(timezone.utc)
        self.wait("retained gauge publication", lambda: self.client("cloudwatch").get_metric_statistics(
            Namespace="AWS/AutoScaling", MetricName="GroupTerminatingRetainedInstances", Dimensions=[{"Name": "AutoScalingGroupName", "Value": self.prefix}],
            StartTime=start, EndTime=datetime.now(timezone.utc) + timedelta(minutes=1), Period=60, Statistics=["Average"])["Datapoints"],
            lambda rows: any(p["Average"] == 1 and p["Unit"] == "None" for p in rows), 150)
        self.asg("release-retained-original", "terminate_instance_in_auto_scaling_group", InstanceId=original, ShouldDecrementDesiredCapacity=False)
        release_action = self.action("autoscaling:EC2_INSTANCE_TERMINATING", original)
        assert release_action["LifecycleActionToken"] != action["LifecycleActionToken"], (action, release_action)
        release_wait = self.group()
        assert release_wait["DesiredCapacity"] == 1 and any(i["InstanceId"] == original and i["LifecycleState"] == "Terminating:Wait" for i in release_wait["Instances"]), release_wait
        assert self.http(address) == before, "original stopped before new release hook completed"
        self.complete(release_action, "CONTINUE")
        released = self.wait("release removes only retained membership", self.group,
                             lambda g: g and g["DesiredCapacity"] == 1 and len(g["Instances"]) == 1 and g["Instances"][0]["InstanceId"] == replacement, 240)
        self.wait("original actual native retirement", lambda: self.instance(original), lambda row: row["State"]["Name"] == "terminated", 180)
        assert self.http(address) is None, "released original still serves HTTP"
        self.wait("replacement survives manual release", lambda: self.http(o["dns"]), lambda r: r == replacement_http, 120)
        self.expect("release-hook-completed", "ValidationError", "autoscaling", "record_lifecycle_action_heartbeat",
                    AutoScalingGroupName=self.prefix, LifecycleHookName="terminate", LifecycleActionToken=release_action["LifecycleActionToken"])
        self.data["observations"]["manual_release"] = {"new_hook": release_action, "waiting_group": release_wait, "group": released,
                                                      "original_http_absent": True, "replacement_http": replacement_http}
        self.save()

    def cleanup(self):
        if "group" in self.owned and self.group():
            # Failed runs may still own retained guests. Release them explicitly;
            # neither deleting a hook nor waiting can abandon retained ownership.
            self.asg("cleanup-disable-retention", "update_auto_scaling_group", AutoScalingGroupName=self.prefix,
                     InstanceLifecyclePolicy={"RetentionTriggers": {"TerminateHookAbandon": "terminate"}})
            self.asg("cleanup-continue-hook", "put_lifecycle_hook", AutoScalingGroupName=self.prefix, LifecycleHookName="terminate",
                     LifecycleTransition="autoscaling:EC2_INSTANCE_TERMINATING", HeartbeatTimeout=30, DefaultResult="CONTINUE")
            for member in self.group()["Instances"]:
                if member["LifecycleState"] == "Terminating:Retained":
                    self.asg("cleanup-release-" + member["InstanceId"], "terminate_instance_in_auto_scaling_group",
                             InstanceId=member["InstanceId"], ShouldDecrementDesiredCapacity=False)
            self.asg("cleanup-force-group", "delete_auto_scaling_group", AutoScalingGroupName=self.prefix, ForceDelete=True)
            hooks = self.client("autoscaling").describe_lifecycle_hooks(AutoScalingGroupName=self.prefix)["LifecycleHooks"]
            for hook in hooks:
                self.asg("cleanup-delete-" + hook["LifecycleHookName"], "delete_lifecycle_hook",
                         AutoScalingGroupName=self.prefix, LifecycleHookName=hook["LifecycleHookName"])
            self.wait("cleanup retained group absence", self.group, lambda g: g is None, 240)
            del self.owned["group"]
        super().cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elbv2-node-executable", type=Path, default=Path("bin/stackd-elbv2-node-integration"))
    parser.add_argument("--raw-image", type=Path, default=Path("/tmp/stackd-ubuntu-24.04-server.raw"))
    parser.add_argument("--bios", type=Path, default=Path("/usr/share/seabios/bios-256k.bin"))
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--port", type=int, default=15953)
    parser.add_argument("--gateway", default="10.194.20.1")
    parser.add_argument("--output", type=Path, default=Path("testdata/integration/autoscaling_retention_guest.json"))
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    args.upgrade_from_binary = None
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
