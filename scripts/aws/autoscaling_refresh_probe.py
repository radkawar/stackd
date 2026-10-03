#!/usr/bin/env python3
"""Bounded native rolling refresh evidence using LifecycleCapture ownership/cleanup.

At most two private t3.nano guests with encrypted 8GiB disposable roots. A failed
capture is preserved and cleanup is always attempted; audit collection is separate.
"""
import argparse
import base64
from pathlib import Path
import signal
import time

from autoscaling_lifecycle_probe import LifecycleCapture
from ec2_instances_probe import interrupt
from ebs_encryption_probe import now


def run(c):
    signal.alarm(c.args.live_seconds)
    c.deadline = time.monotonic() + c.args.live_seconds
    c.setup()
    p = c.data["prefix"]
    c.data["group_name"] = p + "-refresh"
    c.data["documentation"] = [
        "https://docs.aws.amazon.com/autoscaling/ec2/userguide/instance-refresh-overview.html",
        "https://docs.aws.amazon.com/autoscaling/ec2/userguide/understand-instance-refresh-default-values.html",
        "https://docs.aws.amazon.com/autoscaling/ec2/userguide/instance-refresh-rollback.html"]
    image = c.data["source_image"]
    launch = {"ImageId": image["ImageId"], "InstanceType": "t3.nano",
        "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": False,
            "DeleteOnTermination": True, "Groups": [c.data["owned"]["group"]]}],
        "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"], "Ebs": {
            "VolumeSize": 8, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}}],
        "CreditSpecification": {"CpuCredits": "standard"},
        "UserData": base64.b64encode(b"#!/bin/sh\necho refresh-version-one > /etc/stackd-refresh\n").decode(),
        "TagSpecifications": [{"ResourceType": k, "Tags": [{"Key": "suite", "Value": p}]} for k in ("instance", "volume", "network-interface")]}
    tid = c.ec2("refresh-template-one", "create_launch_template", {"LaunchTemplateName": p,
        "LaunchTemplateData": launch, "TagSpecifications": c.tags("launch-template")}, required=True)["LaunchTemplate"]["LaunchTemplateId"]
    c.data["template_id"] = tid
    c.ec2("refresh-template-two", "create_launch_template_version", {"LaunchTemplateId": tid,
        "SourceVersion": "1", "LaunchTemplateData": {"UserData": base64.b64encode(
            b"#!/bin/sh\necho refresh-version-two > /etc/stackd-refresh\n").decode()}}, required=True)
    g = {"AutoScalingGroupName": c.data["group_name"]}
    c.asg("refresh-group-zero", "create_auto_scaling_group", dict(g, MinSize=0, MaxSize=2, DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": tid, "Version": "1"}, VPCZoneIdentifier=c.data["owned"]["subnet"],
        HealthCheckGracePeriod=0, DefaultInstanceWarmup=0, Tags=[{"Key": "suite", "Value": p, "PropagateAtLaunch": True}]), required=True)
    c.events_setup(c.group("refresh-initial")["AutoScalingGroupARN"])
    for method in ("cancel_instance_refresh", "rollback_instance_refresh", "describe_instance_refreshes"):
        c.asg("refresh-empty-" + method, method, g)
    for label, extra in (("bad-strategy", {"Strategy": "ReplaceRootVolume"}),
            ("rollback-without-desired", {"Preferences": {"AutoRollback": True}}),
            ("bad-checkpoints", {"Preferences": {"CheckpointPercentages": [40, 20]}}),
            ("bad-range", {"Preferences": {"MinHealthyPercentage": 0, "MaxHealthyPercentage": 200}})):
        c.asg("refresh-" + label, "start_instance_refresh", dict(g, **extra))
    c.asg("refresh-default-start", "start_instance_refresh", g, required=True)
    c.asg("refresh-default-immediate", "describe_instance_refreshes", g, required=True)
    wait(c, "refresh-default-done", lambda r: r["Status"] in ("Successful", "Failed"))
    c.asg("refresh-scale-one", "set_desired_capacity", dict(g, DesiredCapacity=1), required=True)
    old = c.wait_group("refresh-old-ready", lambda x: len(x["Instances"]) == 1 and x["Instances"][0]["LifecycleState"] == "InService", 240)["Instances"][0]["InstanceId"]
    desired = {"LaunchTemplate": {"LaunchTemplateId": tid, "Version": "2"}}
    c.asg("refresh-rolling-start", "start_instance_refresh", dict(g, DesiredConfiguration=desired,
        Preferences={"MinHealthyPercentage": 100, "MaxHealthyPercentage": 100, "InstanceWarmup": 0,
            "BakeTime": 60, "CheckpointPercentages": [100], "CheckpointDelay": 0}), required=True)
    c.asg("refresh-concurrent-start", "start_instance_refresh", g)
    c.asg("refresh-update-rejected", "update_auto_scaling_group", dict(g, LaunchTemplate={"LaunchTemplateId": tid, "Version": "1"}))
    wait(c, "refresh-baking", lambda r: r["Status"] in ("Baking", "Successful", "Failed"), 330)
    c.snapshot("refresh-replaced-before-commit")
    c.asg("refresh-manual-rollback", "rollback_instance_refresh", g, required=True)
    wait(c, "refresh-rollback-done", lambda r: r["Status"] in ("RollbackSuccessful", "RollbackFailed"), 300)
    c.snapshot("refresh-rollback-membership")
    c.asg("refresh-protect", "set_instance_protection", dict(g,
        InstanceIds=[i["InstanceId"] for i in c.group("refresh-protect-source")["Instances"]], ProtectedFromScaleIn=True), required=True)
    c.asg("refresh-wait-start", "start_instance_refresh", g, required=True)
    time.sleep(10)
    c.asg("refresh-wait-describe", "describe_instance_refreshes", g, required=True)
    c.asg("refresh-cancel", "cancel_instance_refresh", dict(g, WaitForTransitioningInstances=False), required=True)
    wait(c, "refresh-cancel-done", lambda r: r["Status"] == "Cancelled")
    c.asg("refresh-history-page", "describe_instance_refreshes", dict(g, MaxRecords=1), required=True)
    c.note("refresh-complete", original_instance=old)


def wait(c, label, predicate, seconds=100):
    end = time.monotonic() + seconds
    attempt = 0
    while True:
        rows = c.asg(label + "-" + str(attempt), "describe_instance_refreshes",
            {"AutoScalingGroupName": c.data["group_name"]}, required=True)["InstanceRefreshes"]
        c.drain_events(label + "-" + str(attempt))
        if rows and predicate(rows[0]):
            return rows[0]
        if time.monotonic() >= end:
            raise TimeoutError(label + " not observed in bounded window")
        time.sleep(5)
        attempt += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/autoscaling/refresh_native.json"))
    parser.add_argument("--live-seconds", type=int, default=1000, choices=range(300, 1001))
    parser.add_argument("--audit-rounds", type=int, default=1)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    c = LifecycleCapture(args)
    if args.audit_only:
        if not c.data["cleanup"].get("complete"):
            raise RuntimeError("Cleanup required before audit")
        c.audit()
        return
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only:
            run(c)
    except Exception as error:
        c.data.setdefault("failures", []).append({"type": type(error).__name__, "message": str(error), "at": now()})
        c.save()
        raise
    finally:
        c.cleanup()


if __name__ == "__main__":
    main()
