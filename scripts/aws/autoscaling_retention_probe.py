#!/usr/bin/env python3
"""Capture owned ASG retention, real EC2 survival and manual release in AWS.

LifecycleCapture supplies account verification, AWS recording, isolated networking,
IAM, EventBridge/SQS delivery, exact-owned cleanup and request-ID CloudTrail joins.
No standing resources are mutated. At most two private t3.nano guests exist at once;
each root is delete-on-termination 8-GiB gp3. Experiment expiry enters cleanup, never
leaves stopped guests. Request acceptance and later observations remain separate.
Run --audit-only after observed cleanup to collect bounded late management events.

Manual release invokes a new termination hook; complete that new action with
CONTINUE before expecting the real guest to terminate. Force deletion rejects
retention policy retain, so cleanup explicitly changes only the owned group's
policy before delegation. Contrast modes isolate newly reachable admissions
without repeating a failed observation window from another output.
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import signal
import time

from autoscaling_lifecycle_probe import LifecycleCapture, DOCS
from ec2_instances_probe import interrupt
from ebs_encryption_probe import now

RETENTION_DOCS = DOCS + [
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/manage-retained-instances.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/instance-lifecycle-policy.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_TerminateInstanceInAutoScalingGroup.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DetachInstances.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_EnterStandby.html",
]
METRICS = ["GroupTerminatingRetainedInstances", "GroupTerminatingRetainedCapacity",
    "GroupDesiredCapacity", "GroupInServiceInstances", "GroupTotalInstances", "GroupTerminatingInstances"]


class RetentionCapture(LifecycleCapture):
    def policy(self, label, value):
        return self.asg(label, "update_auto_scaling_group", {
            "AutoScalingGroupName": self.data["group_name"],
            "InstanceLifecyclePolicy": {"RetentionTriggers": {"TerminateHookAbandon": value}}}, required=True)

    def complete(self, label, iid, result="ABANDON"):
        return self.asg(label, "complete_lifecycle_action", {
            "AutoScalingGroupName": self.data["group_name"], "LifecycleHookName": "terminate",
            "InstanceId": iid, "LifecycleActionResult": result}, required=True)

    def retained(self, label, iid, seconds=150):
        group = self.wait_group(label, lambda g: g and any(i["InstanceId"] == iid and
            i["LifecycleState"] == "Terminating:Retained" for i in g["Instances"]), seconds=seconds)
        self.state(iid, "running", label + "-real-guest", seconds=20)
        self.note(label, instance_id=iid, desired_capacity=group["DesiredCapacity"],
            instances=group["Instances"], observation_boundary="Polling observation, not a service latency guarantee")
        return group

    def terminate_to_wait(self, label, iid, decrement):
        self.asg(label + "-request", "terminate_instance_in_auto_scaling_group", {
            "InstanceId": iid, "ShouldDecrementDesiredCapacity": decrement}, required=True)
        return self.wait_group(label + "-waiting", lambda g: g and any(i["InstanceId"] == iid and
            i["LifecycleState"] == "Terminating:Wait" for i in g["Instances"]), seconds=120)

    def active(self, label, excluded=()):
        group = self.wait_group(label, lambda g: g and any(i["LifecycleState"] == "InService" and
            i["InstanceId"] not in excluded for i in g["Instances"]), seconds=150)
        return next(i["InstanceId"] for i in group["Instances"] if i["LifecycleState"] == "InService"
            and i["InstanceId"] not in excluded)

    def release(self, label, iid, decrement):
        self.asg(label, "terminate_instance_in_auto_scaling_group", {
            "InstanceId": iid, "ShouldDecrementDesiredCapacity": decrement})
        accepted = self.data["calls"][-1]["code"] == "Success"
        self.snapshot(label + "-immediate")
        if accepted:
            group = self.wait_group(label + "-hook-wait", lambda g: not g or not any(
                i["InstanceId"] == iid for i in g["Instances"]) or any(
                i["InstanceId"] == iid and i["LifecycleState"] == "Terminating:Wait"
                for i in g["Instances"]), seconds=90)
            if group and any(i["InstanceId"] == iid for i in group["Instances"]):
                self.complete(label + "-new-hook-continue", iid, "CONTINUE")
            self.wait_group(label + "-removed", lambda g: not g or all(
                i["InstanceId"] != iid for i in g["Instances"]), seconds=120)
            self.state(iid, "terminated", label + "-ec2-terminal", seconds=90)
        return accepted

    def metric_observations(self, label):
        for metric in METRICS:
            self.observe(label + "-" + metric, "cloudwatch", "get_metric_statistics", {
                "Namespace": "AWS/AutoScaling", "MetricName": metric,
                "Dimensions": [{"Name": "AutoScalingGroupName", "Value": self.data["group_name"]}],
                "StartTime": datetime.fromisoformat(self.data["captured_at"]),
                "EndTime": datetime.now(timezone.utc), "Period": 60, "Statistics": ["Minimum", "Maximum", "Average", "SampleCount"]})

    def prepare(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.data.update(scope=__doc__, documentation=RETENTION_DOCS,
            group_name=self.data["prefix"] + "-retention",
            uncovered_boundaries=["Warm pools", "Multiple termination hooks", "Unhealthy retained health mutation",
                "Policy update while an action is waiting"])
        self.data["bounds"]["cleanup_reserve_seconds"] = 1200 - self.args.live_seconds
        if self.args.membership_contrast_only:
            self.data["bounds"]["max_simultaneous_instances"] = 1
        else:
            self.data["uncovered_boundaries"].append("Detach retained membership")
        self.save()
        self.setup()
        # Reuse the bounded launch request; strip direct-RunInstances fields and
        # guest/data-disk instrumentation unrelated to this lifecycle observation.
        launch = self.request()
        for key in ("MinCount", "MaxCount", "ClientToken", "UserData"):
            launch.pop(key)
        launch["NetworkInterfaces"][0].pop("SubnetId")
        launch["BlockDeviceMappings"] = launch["BlockDeviceMappings"][:1]
        launch["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] = True
        template = self.ec2("retention-owned-template", "create_launch_template", {
            "LaunchTemplateName": self.data["prefix"], "LaunchTemplateData": launch,
            "TagSpecifications": self.tags("launch-template")}, required=True)["LaunchTemplate"]["LaunchTemplateId"]
        self.data["template_id"] = template
        self.save()
        self.asg("retention-create-zero", "create_auto_scaling_group", {
            "AutoScalingGroupName": self.data["group_name"], "MinSize": 0, "MaxSize": 1, "DesiredCapacity": 0,
            "VPCZoneIdentifier": self.data["owned"]["subnet"],
            "LaunchTemplate": {"LaunchTemplateId": template, "Version": "1"},
            "HealthCheckGracePeriod": 0, "DefaultCooldown": 0, "DefaultInstanceWarmup": 0,
            "InstanceLifecyclePolicy": {"RetentionTriggers": {"TerminateHookAbandon": "retain"}},
            "Tags": [{"Key": "suite", "Value": self.data["prefix"], "PropagateAtLaunch": True}],
            "LifecycleHookSpecificationList": [{"LifecycleHookName": "terminate",
                "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING", "HeartbeatTimeout": 60,
                "DefaultResult": "ABANDON"}]}, required=True)
        group = self.group("retention-created")
        self.events_setup(group["AutoScalingGroupARN"])
        self.asg("retention-enable-metrics", "enable_metrics_collection", {
            "AutoScalingGroupName": self.data["group_name"], "Granularity": "1Minute", "Metrics": METRICS}, required=True)
        self.asg("retention-launch-one", "set_desired_capacity", {
            "AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 1}, required=True)

    def run(self):
        self.prepare()
        if self.args.decrement_contrast_only:
            self.decrement_contrast()
            return
        if self.args.membership_contrast_only:
            self.membership_contrast()
            return
        original = self.active("explicit-original-inservice")
        self.data["explicit_instance"] = original
        self.save()
        self.terminate_to_wait("explicit-terminate-no-decrement", original, False)
        self.complete("explicit-abandon", original)
        self.retained("explicit-retention-observed", original)
        replacement = self.active("explicit-replacement-inservice", (original,))
        self.data["explicit_replacement"] = replacement
        self.save()
        self.snapshot("explicit-retained-and-replacement")
        self.asg("retained-delete-nonforce", "delete_auto_scaling_group", {
            "AutoScalingGroupName": self.data["group_name"]})
        self.policy("retained-policy-change-terminate", "terminate")
        self.snapshot("retained-after-policy-change")
        self.policy("retained-policy-restore-retain", "retain")
        if not self.release("retained-manual-release-false", original, False):
            raise RuntimeError("Retained manual release false was rejected; preserve native failure")
        self.note("explicit-manual-release-complete", instance_id=original, replacement_id=replacement)

        # Expiry is a distinct trigger, with no heartbeat or explicit completion.
        self.terminate_to_wait("expiry-terminate-no-decrement", replacement, False)
        self.retained("expiry-default-abandon-retained", replacement, seconds=180)
        active = self.active("expiry-replacement-inservice", (replacement,))
        self.data["expiry_instance"] = replacement
        self.data["expiry_replacement"] = active
        self.save()
        self.asg("retained-enter-standby", "enter_standby", {
            "AutoScalingGroupName": self.data["group_name"], "InstanceIds": [replacement],
            "ShouldDecrementDesiredCapacity": False})
        self.asg("retained-set-health-healthy", "set_instance_health", {
            "InstanceId": replacement, "HealthStatus": "Healthy", "ShouldRespectGracePeriod": False})
        self.snapshot("expiry-after-membership-requests")
        released = self.release("retained-manual-release-true", replacement, True)
        if not released and not self.release("retained-manual-release-false-after-true-rejection", replacement, False):
            raise RuntimeError("Retained manual release false was rejected after true rejection")
        self.note("expiry-manual-release-complete", instance_id=replacement, decrement_true_accepted=released)

        # Make the force-delete case independent of any desired-capacity side
        # effect observed from decrement=true. Never launch above one active plus
        # one retained guest; prior retained EC2 termination was observed first.
        group = self.snapshot("force-case-initial")
        member = next((i for i in group["Instances"] if i["InstanceId"] == active), None)
        if member and member["LifecycleState"] == "InService":
            self.terminate_to_wait("force-prepare-terminate-decrement", active, True)
            self.complete("force-prepare-abandon", active)
        elif member and member["LifecycleState"] == "Terminating:Wait":
            self.complete("force-existing-wait-abandon", active)
        elif not member or member["LifecycleState"] != "Terminating:Retained":
            raise RuntimeError("Force case has no coherent surviving active/waiting/retained member")
        self.retained("force-retained-observed", active)
        self.asg("retained-only-delete-nonforce", "delete_auto_scaling_group", {
            "AutoScalingGroupName": self.data["group_name"]})
        self.asg("retained-force-delete", "delete_auto_scaling_group", {
            "AutoScalingGroupName": self.data["group_name"], "ForceDelete": True})
        if self.data["calls"][-1]["code"] != "Success":
            self.policy("force-policy-terminate", "terminate")
            self.asg("force-after-policy-terminate", "delete_auto_scaling_group", {
                "AutoScalingGroupName": self.data["group_name"], "ForceDelete": True}, required=True)
        self.wait_group("retained-force-group-absent", lambda g: g is None, seconds=150)
        self.state(active, "terminated", "retained-force-real-guest-terminal", seconds=90)
        self.note("force-retention-complete", instance_id=active)
        self.metric_observations("retention-metrics-final")

    def decrement_contrast(self):
        original = self.active("contrast-original-inservice")
        self.data["contrast_instance"] = original
        self.save()
        self.terminate_to_wait("contrast-prepare-terminate", original, False)
        self.complete("contrast-prepare-abandon", original)
        self.retained("contrast-retained", original)
        replacement = self.active("contrast-positive-desired-replacement", (original,))
        self.data["contrast_replacement"] = replacement
        self.save()
        self.snapshot("contrast-before-decrement-true")
        self.asg("contrast-retained-enter-standby", "enter_standby", {
            "AutoScalingGroupName": self.data["group_name"], "InstanceIds": [original],
            "ShouldDecrementDesiredCapacity": False})
        self.asg("contrast-retained-health-healthy", "set_instance_health", {
            "InstanceId": original, "HealthStatus": "Healthy", "ShouldRespectGracePeriod": False})
        self.snapshot("contrast-after-membership-requests")
        accepted = self.release("contrast-retained-manual-release-true", original, True)
        self.note("contrast-decrement-admission", accepted=accepted, instance_id=original)
        self.policy("contrast-remedial-policy-terminate", "terminate")
        self.snapshot("contrast-retained-after-policy-update")
        self.asg("contrast-remedial-force-delete", "delete_auto_scaling_group", {
            "AutoScalingGroupName": self.data["group_name"], "ForceDelete": True}, required=True)
        self.snapshot("contrast-force-request-immediate")
        self.wait_group("contrast-force-group-absent", lambda g: g is None, seconds=150)
        for iid in (original, replacement):
            self.state(iid, "terminated", "contrast-force-ec2-terminal-" + iid, seconds=90)
        self.note("contrast-force-complete", instance_ids=[original, replacement])

    def membership_contrast(self):
        iid = self.active("membership-original-inservice")
        self.data["membership_instance"] = iid
        self.save()
        self.terminate_to_wait("membership-prepare-scale-in", iid, True)
        self.complete("membership-prepare-abandon", iid)
        self.retained("membership-retained-desired-zero", iid)
        self.asg("membership-retained-protection-true", "set_instance_protection", {
            "AutoScalingGroupName": self.data["group_name"], "InstanceIds": [iid],
            "ProtectedFromScaleIn": True})
        self.snapshot("membership-after-protection")
        self.asg("membership-retained-detach-false", "detach_instances", {
            "AutoScalingGroupName": self.data["group_name"], "InstanceIds": [iid],
            "ShouldDecrementDesiredCapacity": False})
        detached = self.data["calls"][-1]["code"] == "Success"
        self.snapshot("membership-after-detach-request")
        if detached:
            self.wait_group("membership-detached", lambda g: g and not g["Instances"], seconds=90)
            self.state(iid, "running", "membership-detached-real-guest", seconds=20)
            self.ec2("membership-cleanup-detached-guest", "terminate_instances", {"InstanceIds": [iid]}, required=True)
            self.state(iid, "terminated", "membership-detached-guest-terminal", seconds=120)
        elif not self.release("membership-cleanup-retained-manual-release", iid, False):
            raise RuntimeError("Manual cleanup release was rejected after detach rejection")
        self.wait_group("membership-empty-retain-group", lambda g: g and not g["Instances"], seconds=90)
        self.asg("membership-empty-force-retain", "delete_auto_scaling_group", {
            "AutoScalingGroupName": self.data["group_name"], "ForceDelete": True})
        if self.data["calls"][-1]["code"] != "Success":
            self.asg("membership-empty-ordinary-delete", "delete_auto_scaling_group", {
                "AutoScalingGroupName": self.data["group_name"]}, required=True)
        self.wait_group("membership-empty-group-absent", lambda g: g is None, seconds=90)
        self.note("membership-controls-complete", instance_id=iid, detach_accepted=detached)

    def cleanup(self):
        self.cleaning = True
        signal.alarm(0)
        # Native force deletion rejects retain policy. This is remedial cleanup,
        # not a retry of that semantic assertion. Delegate all resource removal.
        for name in self.data["owned"]["asgs"]:
            result = self.asg("cleanup-retention-policy-read", "describe_auto_scaling_groups",
                {"AutoScalingGroupNames": [name]})
            for group in result.get("AutoScalingGroups", []):
                if group.get("InstanceLifecyclePolicy", {}).get("RetentionTriggers", {}).get("TerminateHookAbandon") == "retain":
                    self.asg("cleanup-retention-policy-terminate", "update_auto_scaling_group", {
                        "AutoScalingGroupName": name,
                        "InstanceLifecyclePolicy": {"RetentionTriggers": {"TerminateHookAbandon": "terminate"}}}, required=True)
        super().cleanup()
        elapsed = (datetime.fromisoformat(self.data["cleanup"]["finished_at"]) -
            datetime.fromisoformat(self.data["captured_at"])).total_seconds()
        self.data["cleanup"]["capture_to_cleanup_wall_seconds"] = elapsed
        self.data["cleanup"]["wall_bound_boundary"] = "Conservative paid-resource bound includes setup and all cleanup; not billing granularity."
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/autoscaling/retention_native.json"))
    parser.add_argument("--live-seconds", type=int, default=780, choices=range(300, 781), metavar="300..780")
    parser.add_argument("--audit-rounds", type=int, default=6, choices=range(1, 7))
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument("--decrement-contrast-only", action="store_true",
        help="Fresh positive-desired retained decrement admission and policy-terminate force contrast only")
    variants.add_argument("--membership-contrast-only", action="store_true",
        help="One guest only: retained protection/detach and empty-group force policy admission")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--cleanup-only", action="store_true")
    modes.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    capture = RetentionCapture(args)
    if args.audit_only:
        if not capture.data["cleanup"].get("complete"):
            raise RuntimeError("Complete paid-resource cleanup before audit collection")
        capture.metric_observations("retention-metrics-after-cleanup")
        capture.audit()
        return
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only:
            capture.run()
    except Exception as error:
        capture.data.setdefault("failures", []).append({"type": type(error).__name__, "message": str(error), "at": now()})
        capture.save()
        raise
    finally:
        capture.cleanup()


if __name__ == "__main__":
    main()
