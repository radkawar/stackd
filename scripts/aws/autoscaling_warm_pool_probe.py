#!/usr/bin/env python3
"""Capture real, owned AWS warm-pool transitions and request-ID audit evidence.

At most two private t3.nano guests, 8-GiB delete-on-termination gp3 roots, no
standing policy/default changes. LifecycleCapture owns recording, isolated
network/profile/launch-template dependencies, EventBridge/SQS and cleanup.
The default run covers controls, Stopped/Running, activation, reuse and deletion.
--retention-only uses a fresh scope to contrast launch/termination ABANDON.
--lifecycle-only skips existing zero-capacity control evidence in a fresh scope.
--reuse-only uses an encrypted-root, configuration-omitted Hibernated warm launch
before the remaining minimum/prepared sizing, Running, reuse and deletion path.
--group-deletion-only isolates ordinary/forced group deletion with a nonempty pool.
--force-retained-only isolates forced re-entry, re-retention and manual release.
--suspended-launch-only contrasts desired-capacity growth while Launch is suspended.
Every live experiment is bounded; --audit-only runs only after paid cleanup.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import time

from autoscaling_lifecycle_probe import LifecycleCapture, DOCS
from ec2_instances_probe import interrupt
from ebs_encryption_probe import allow, now, policy

WARM_DOCS = DOCS + [
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-warm-pools.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pool-instance-lifecycle.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pools-eventbridge-events.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutWarmPool.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DescribeWarmPool.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DeleteWarmPool.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/manage-retained-instances.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/instance-lifecycle-policy.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_autoscaling.html",
]
METRICS = ["WarmPoolDesiredCapacity", "WarmPoolWarmedCapacity", "WarmPoolPendingCapacity",
    "WarmPoolTerminatingCapacity", "WarmPoolTotalCapacity", "GroupAndWarmPoolDesiredCapacity",
    "GroupAndWarmPoolTotalCapacity", "GroupDesiredCapacity", "GroupInServiceInstances",
    "GroupTotalInstances", "GroupTerminatingRetainedInstances",
    "WarmPoolPendingRetainedCapacity", "WarmPoolTerminatingRetainedCapacity"]


class WarmPoolCapture(LifecycleCapture):
    def put(self, label, *, required=False, **values):
        return self.asg(label, "put_warm_pool", {"AutoScalingGroupName": self.data["group_name"], **values}, required=required)

    def pool(self, label, **values):
        return self.asg(label, "describe_warm_pool", {"AutoScalingGroupName": self.data["group_name"], **values})

    def desired(self, label, value):
        self.asg(label, "set_desired_capacity", {
            "AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": value}, required=True)

    def snapshot(self, label):
        group = super().snapshot(label)
        pool = self.pool(label + "-pool")
        ids = [i["InstanceId"] for i in pool.get("Instances", [])]
        if ids:
            self.ec2(label + "-warm-ec2", "describe_instances", {"InstanceIds": ids})
            self.asg(label + "-warm-membership", "describe_auto_scaling_instances", {"InstanceIds": ids})
        return group

    def wait_pool(self, label, predicate, seconds=150):
        end = time.monotonic() + seconds
        attempt = 0
        while True:
            pool = self.pool(label + "-" + str(attempt))
            code = self.data["calls"][-1]["code"]
            ids = [i["InstanceId"] for i in pool.get("Instances", [])]
            if ids:
                self.ec2(label + "-ec2-" + str(attempt), "describe_instances", {"InstanceIds": ids})
            self.drain_events(label + "-" + str(attempt))
            if code == "Success" and predicate(pool):
                self.snapshot(label + "-observed")
                return pool
            if time.monotonic() >= end:
                self.data["gaps"].append(label + ": not observed within " + str(seconds) + " seconds")
                self.save()
                raise TimeoutError(label + " observation window expired")
            time.sleep(5)
            attempt += 1

    def warm_member(self, label, state, excluded=()):
        pool = self.wait_pool(label, lambda p: any(i["LifecycleState"] == state and
            i["InstanceId"] not in excluded for i in p.get("Instances", [])))
        return next(i["InstanceId"] for i in pool["Instances"] if i["LifecycleState"] == state
            and i["InstanceId"] not in excluded)

    def complete(self, label, iid, hook, result="CONTINUE", origin=None, destination=None):
        # One instance can encounter the same launch hook repeatedly. Never reuse
        # LifecycleCapture's first historical token for a later warm transition.
        used = set(self.data.setdefault("used_hook_tokens", []))
        completed = max((datetime.fromisoformat(call["finished_at"]) for call in self.data["calls"]
            if call["operation"] == "CompleteLifecycleAction" and call["code"] == "Success" and
            call["input"].get("InstanceId") == iid and call["input"].get("LifecycleHookName") == hook),
            default=datetime.min.replace(tzinfo=timezone.utc))
        token = None
        for attempt in range(9):
            self.drain_events(label + "-token-" + str(attempt))
            for row in reversed(self.data["eventbridge_events"]):
                detail = row["event"].get("detail", {})
                candidate = detail.get("LifecycleActionToken")
                if (candidate and candidate not in used and detail.get("EC2InstanceId") == iid and
                        detail.get("LifecycleHookName") == hook and
                        datetime.fromisoformat(row["event"]["time"].replace("Z", "+00:00")) > completed and
                        (origin is None or detail.get("Origin") == origin) and
                        (destination is None or detail.get("Destination") == destination)):
                    token = candidate
                    self.note(label + "-notification", detail=detail)
                    break
            if token:
                break
            time.sleep(5)
        params = {"AutoScalingGroupName": self.data["group_name"], "LifecycleHookName": hook}
        params.update({"LifecycleActionToken": token} if token else {"InstanceId": iid})
        if token:
            self.data["used_hook_tokens"].append(token)
        else:
            self.data["gaps"].append(label + ": matching EventBridge token not delivered within 45 seconds; completing by instance ID")
        self.save()
        self.asg(label + "-heartbeat", "record_lifecycle_action_heartbeat", params)
        self.asg(label + "-complete", "complete_lifecycle_action", dict(params, LifecycleActionResult=result), required=True)
        return params

    def metric_observations(self, label):
        for metric in METRICS:
            self.observe(label + "-" + metric, "cloudwatch", "get_metric_statistics", {
                "Namespace": "AWS/AutoScaling", "MetricName": metric,
                "Dimensions": [{"Name": "AutoScalingGroupName", "Value": self.data["group_name"]}],
                "StartTime": datetime.fromisoformat(self.data["captured_at"]),
                "EndTime": datetime.now(timezone.utc), "Period": 60,
                "Statistics": ["Minimum", "Maximum", "Average", "SampleCount"]})
        window = self.data.get("ec2_group_metric_window")
        if window:
            dimensions = [("AutoScalingGroupName", self.data["group_name"])] + [
                ("InstanceId", iid) for iid in window["instance_ids"]]
            for dimension, value in dimensions:
                self.observe(label + "-EC2-CPU-" + value, "cloudwatch", "get_metric_statistics", {
                    "Namespace": "AWS/EC2", "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": dimension, "Value": value}],
                    "StartTime": datetime.fromisoformat(window["start_time"]),
                    "EndTime": datetime.fromisoformat(window["end_time"]),
                    "Period": 60, "Statistics": ["Average", "SampleCount"]})

    def stable_metric_window(self, active, warmed):
        end = (int(time.time()) // 60 + 2) * 60
        wait = end - time.time()
        if self.deadline - time.monotonic() < wait + 300:
            self.note("ec2-group-metrics-uncaptured", reason="Insufficient existing live bound for stable minute and remaining lifecycle")
            return
        self.ec2("ec2-group-metrics-enable-detailed", "monitor_instances", {"InstanceIds": [active, warmed]})
        if self.data["calls"][-1]["code"] != "Success":
            return
        self.data["ec2_group_metric_window"] = {
            "instance_ids": [active, warmed], "in_service_instance": active, "warmed_running_instance": warmed,
            "start_time": datetime.fromtimestamp(end - 60, timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(end, timezone.utc).isoformat(),
            "boundary": "One full aligned minute with no probe capacity mutations; metric availability and SampleCount are native observations."}
        self.save()
        self.snapshot("ec2-group-metrics-before-stable-minute")
        time.sleep(max(0, end - time.time()))
        self.snapshot("ec2-group-metrics-after-stable-minute")
        self.metric_observations("ec2-group-metrics-immediate")

    def prepare(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.data.update(scope=__doc__, documentation=WARM_DOCS,
            force_retained_only=self.args.force_retained_only,
            suspended_launch_only=self.args.suspended_launch_only,
            group_name=self.data["prefix"] + "-warm",
            uncovered_boundaries=["Guest-memory preservation through hibernation is a separate EC2 dependency capture",
                "Mixed instances, Spot, refresh, weighted capacity and multi-AZ placement",
                "Polling observations are not latency guarantees or an exhaustive transition trace"])
        self.data["bounds"]["cleanup_reserve_seconds"] = 1200 - self.args.live_seconds
        if self.args.suspended_launch_only:
            self.data["bounds"]["max_simultaneous_instances"] = 1
        self.save()
        self.setup()
        launch = self.request()
        for key in ("MinCount", "MaxCount", "ClientToken", "UserData"):
            launch.pop(key)
        launch["NetworkInterfaces"][0].pop("SubnetId")
        launch["BlockDeviceMappings"] = launch["BlockDeviceMappings"][:1]
        launch["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] = True
        if (self.args.initial_pool_state or ("Hibernated" if self.args.reuse_only else "Stopped")) == "Hibernated":
            launch["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] = True
        template = self.ec2("warm-owned-template", "create_launch_template", {
            "LaunchTemplateName": self.data["prefix"], "LaunchTemplateData": launch,
            "TagSpecifications": self.tags("launch-template")}, required=True)["LaunchTemplate"]["LaunchTemplateId"]
        self.data["template_id"] = template
        self.save()
        params = {"AutoScalingGroupName": self.data["group_name"], "MinSize": 0, "MaxSize": 0, "DesiredCapacity": 0,
            "VPCZoneIdentifier": self.data["owned"]["subnet"],
            "LaunchTemplate": {"LaunchTemplateId": template, "Version": "1"},
            "HealthCheckGracePeriod": 0, "DefaultCooldown": 0, "DefaultInstanceWarmup": 0,
            "Tags": [{"Key": "suite", "Value": self.data["prefix"], "PropagateAtLaunch": True}],
            "LifecycleHookSpecificationList": [
                {"LifecycleHookName": "launch", "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
                    "HeartbeatTimeout": 120, "DefaultResult": "ABANDON"},
                {"LifecycleHookName": "terminate", "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
                    "HeartbeatTimeout": 120, "DefaultResult": "CONTINUE"}]}
        if self.args.retention_only or self.args.pending_retention_only or self.args.force_retained_only:
            params["InstanceLifecyclePolicy"] = {"RetentionTriggers": {"TerminateHookAbandon": "retain"}}
            params["LifecycleHookSpecificationList"][1]["DefaultResult"] = "ABANDON"
        self.asg("warm-create-zero", "create_auto_scaling_group", params, required=True)
        group = self.group("warm-created")
        self.events_setup(group["AutoScalingGroupARN"])
        if not self.args.force_retained_only and not self.args.suspended_launch_only:
            self.asg("warm-enable-metrics", "enable_metrics_collection", {
                "AutoScalingGroupName": self.data["group_name"], "Granularity": "1Minute", "Metrics": METRICS}, required=True)

    def controls(self):
        name = {"AutoScalingGroupName": self.data["group_name"]}
        self.pool("warm-absent-describe")
        self.asg("warm-absent-delete", "delete_warm_pool", name)
        self.put("warm-zero-defaults")
        self.pool("warm-zero-defaults-described")
        self.put("warm-zero-explicit", MinSize=0, MaxGroupPreparedCapacity=0,
            PoolState="Running", InstanceReusePolicy={"ReuseOnScaleIn": True})
        self.pool("warm-zero-explicit-described")
        self.put("warm-zero-omitted-update")
        self.pool("warm-zero-omitted-update-described")
        self.put("warm-zero-clear-prepared", MaxGroupPreparedCapacity=-1)
        self.pool("warm-zero-clear-prepared-described")
        self.put("warm-hibernated-unconfigured-template", PoolState="Hibernated")
        self.pool("warm-after-hibernated-request")
        self.put("warm-zero-restore-stopped", PoolState="Stopped", MinSize=0,
            MaxGroupPreparedCapacity=0, InstanceReusePolicy={"ReuseOnScaleIn": False})
        for label, values in (("negative-min", {"MinSize": -1}),
                ("invalid-state", {"PoolState": "invalid"}),
                ("invalid-prepared", {"MaxGroupPreparedCapacity": -2})):
            self.put("warm-invalid-" + label, **values)
        self.pool("warm-invalid-pagination", NextToken="not-a-real-token")
        self.pool("warm-maxrecords-one", MaxRecords=1)
        root = "arn:aws:autoscaling:" + self.args.region + ":" + self.args.account + ":autoScalingGroup:*:autoScalingGroupName/" + self.data["group_name"]
        statements = self.launch_statements + [
            allow("ec2:RunInstances", "arn:aws:ec2:" + self.args.region + ":" + self.args.account + ":launch-template/" + self.data["template_id"]),
            allow(["autoscaling:PutWarmPool", "autoscaling:DescribeWarmPool", "autoscaling:DeleteWarmPool"], root)]
        self.observe("warm-bounded-launcher-policy", "iam", "put_role_policy", {
            "RoleName": self.data["launcher_role"], "PolicyName": "owned-launches",
            "PolicyDocument": json.dumps(policy(statements))}, required=True)
        time.sleep(15)
        for label, action in (("allowed", None), ("deny-put", "autoscaling:PutWarmPool"),
                ("deny-describe", "autoscaling:DescribeWarmPool"), ("deny-delete", "autoscaling:DeleteWarmPool"),
                ("deny-run", "ec2:RunInstances"), ("deny-pass", "iam:PassRole")):
            current = self.assumed_clients("warm-" + label, statements + ([{
                "Effect": "Deny", "Action": action, "Resource": "*"}] if action else []))
            method = {"deny-describe": "describe_warm_pool", "deny-delete": "delete_warm_pool"}.get(label, "put_warm_pool")
            self.asg("warm-iam-" + label, method, name, client=current["autoscaling"], caller="warm-" + label)
        self.asg("warm-empty-delete", "delete_warm_pool", name)
        self.pool("warm-empty-deleted-describe")
        self.wait_pool("warm-empty-delete-finished", lambda p: not p.get("WarmPoolConfiguration"))
        self.note("warm-control-calibration-complete")

    def run(self):
        self.prepare()
        if self.args.suspended_launch_only:
            self.suspended_launch()
            return
        if self.args.retention_only:
            self.retention()
            return
        if self.args.pending_retention_only or self.args.force_retained_only:
            if self.args.pending_retention_only:
                self.empty_group_deletion()
            self.asg("retention-pending-max-one", "update_auto_scaling_group", {
                "AutoScalingGroupName": self.data["group_name"], "MaxSize": 1}, required=True)
            self.put("retention-pending-running", PoolState="Running", MaxGroupPreparedCapacity=1,
                InstanceReusePolicy={"ReuseOnScaleIn": True}, required=True)
            self.pending_retention()
            return
        if self.args.group_deletion_only:
            self.group_deletion()
            return
        if not self.args.lifecycle_only and not self.args.reuse_only:
            self.controls()
        name = {"AutoScalingGroupName": self.data["group_name"]}
        initial_state = self.args.initial_pool_state or ("Hibernated" if self.args.reuse_only else "Stopped")
        if self.args.reuse_only:
            self.put("warm-empty-reuse-policy-create", PoolState=initial_state,
                MaxGroupPreparedCapacity=0, InstanceReusePolicy={}, required=True)
            self.pool("warm-empty-reuse-policy-created-described")
            self.put("warm-reuse-policy-true-before-empty", InstanceReusePolicy={"ReuseOnScaleIn": True}, required=True)
            self.put("warm-empty-reuse-policy-update", InstanceReusePolicy={}, required=True)
            self.pool("warm-empty-reuse-policy-updated-described")
            self.put("warm-empty-reuse-policy-restore", MaxGroupPreparedCapacity=-1,
                InstanceReusePolicy={"ReuseOnScaleIn": False}, required=True)
        self.asg("warm-max-one", "update_auto_scaling_group", dict(name, MaxSize=1), required=True)
        if self.args.reuse_only or self.args.initial_pool_state:
            self.put("warm-explicit-initial-state", PoolState=initial_state, required=True)
        else:
            self.put("warm-default-one", required=True)
        first = self.warm_member("warm-initial-launch-wait", "Warmed:Pending:Wait")
        self.complete("warm-initial-launch", first, "launch", origin="EC2", destination="WarmPool")
        self.warm_member("warm-initial-settled", "Warmed:" + initial_state)
        ec2_state = "running" if initial_state == "Running" else "stopped"
        instance = self.state(first, ec2_state, "warm-initial-ec2-state", seconds=60)
        self.note("warm-initial-ec2-state-observation", instance_id=first, pool_state=initial_state,
            hibernation_options=instance.get("HibernationOptions"), state_reason=instance.get("StateReason"))
        self.desired("warm-activate-one", 1)
        self.wait_group("warm-activation-wait", lambda g: any(i["InstanceId"] == first and
            i["LifecycleState"] == "Pending:Wait" for i in g["Instances"]))
        self.complete("warm-activation-launch", first, "launch", origin="WarmPool", destination="AutoScalingGroup")
        self.wait_group("warm-activation-inservice", lambda g: any(i["InstanceId"] == first and
            i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.state(first, "running", "warm-activation-ec2-running", seconds=30)
        self.wait_pool("warm-activation-pool-empty", lambda p: not p.get("Instances"))
        self.note("same-instance-" + initial_state.lower() + "-activation",
            instance_id=first)

        # Prepared=desired=1 gives zero dynamic pool size; MinSize=1 adds a guest.
        self.put("warm-minimum-overrides-prepared", MinSize=1, MaxGroupPreparedCapacity=1,
            PoolState="Running", InstanceReusePolicy={"ReuseOnScaleIn": True}, required=True)
        second = self.warm_member("warm-minimum-launch-wait", "Warmed:Pending:Wait", (first,))
        self.complete("warm-minimum-launch", second, "launch", origin="EC2", destination="WarmPool")
        self.warm_member("warm-minimum-running", "Warmed:Running")
        self.state(second, "running", "warm-minimum-ec2-running", seconds=30)
        self.note("minimum-prepared-sizing", active_instance=first, warm_instance=second)
        if self.args.ec2_group_metrics:
            self.stable_metric_window(first, second)
        self.put("warm-shrink-minimum", MinSize=0, required=True)
        self.warm_member("warm-shrink-termination-wait", "Warmed:Terminating:Wait")
        self.asg("warm-force-delete-outstanding-termination", "delete_warm_pool", dict(name, ForceDelete=True), required=True)
        self.wait_pool("warm-shrunk-pool-deleted", lambda p: not p.get("WarmPoolConfiguration") and not p.get("Instances"))
        self.asg("warm-deleted-action-completion", "complete_lifecycle_action", dict(name,
            LifecycleHookName="terminate", InstanceId=second, LifecycleActionResult="CONTINUE"))
        self.state(second, "terminated", "warm-shrunk-ec2-terminal", seconds=90)
        self.put("warm-reuse-configure", MaxGroupPreparedCapacity=1, PoolState="Stopped",
            InstanceReusePolicy={"ReuseOnScaleIn": True}, required=True)
        self.desired("warm-reuse-scale-in", 0)
        self.warm_member("warm-reuse-termination-wait", "Warmed:Pending:Wait")
        self.complete("warm-reuse-termination", first, "terminate", origin="AutoScalingGroup", destination="WarmPool")
        self.warm_member("warm-reused-stopped", "Warmed:Stopped")
        self.state(first, "stopped", "warm-reused-ec2-stopped", seconds=60)
        self.note("same-instance-scale-in-reuse", instance_id=first)
        self.metric_observations("warm-metrics-before-delete")
        self.asg("warm-nonempty-normal-delete", "delete_warm_pool", name)
        self.snapshot("warm-after-normal-delete")
        self.asg("warm-nonempty-force-delete", "delete_warm_pool", dict(name, ForceDelete=True), required=True)
        self.wait_pool("warm-force-deleted", lambda p: not p.get("WarmPoolConfiguration") and not p.get("Instances"))
        self.state(first, "terminated", "warm-force-ec2-terminal", seconds=90)
        self.group_deletion()
        self.note("warm-main-capture-complete")

    def suspended_launch(self):
        name = {"AutoScalingGroupName": self.data["group_name"]}
        self.asg("suspended-launch-max-one", "update_auto_scaling_group", dict(name, MaxSize=1), required=True)
        self.put("suspended-launch-running-pool", PoolState="Running", MinSize=0,
            MaxGroupPreparedCapacity=1, InstanceReusePolicy={"ReuseOnScaleIn": False}, required=True)
        first = self.warm_member("suspended-launch-initial-wait", "Warmed:Pending:Wait")
        self.complete("suspended-launch-initial", first, "launch", origin="EC2", destination="WarmPool")
        self.warm_member("suspended-launch-initial-ready", "Warmed:Running")
        self.state(first, "running", "suspended-launch-initial-running", seconds=60)
        self.snapshot("suspended-launch-before-suspend")
        self.asg("suspended-launch-suspend", "suspend_processes", dict(name, ScalingProcesses=["Launch"]), required=True)
        self.desired("suspended-launch-desired-one", 1)

        # Do not release any hook until the unchanged-capacity observation window
        # has captured whether native AWS reserves or retires the prepared guest.
        def sample(label):
            group = self.group(label + "-group")
            pool = self.pool(label + "-pool")
            self.asg(label + "-activities", "describe_scaling_activities",
                dict(name, IncludeDeletedGroups=True, MaxRecords=100), required=True)
            response = self.ec2(label + "-owned-ec2", "describe_instances",
                {"Filters": [{"Name": "tag:suite", "Values": [self.data["prefix"]]}]}, required=True)
            instances = [i for r in response["Reservations"] for i in r["Instances"]]
            self.drain_events(label)
            self.note(label, desired_capacity=group["DesiredCapacity"],
                suspended_processes=group.get("SuspendedProcesses", []),
                group_instances=group["Instances"], warm_instances=pool.get("Instances", []),
                ec2_instances=[{"InstanceId": i["InstanceId"], "State": i["State"]} for i in instances])
            if sum(i["State"]["Name"] != "terminated" for i in instances) > 1:
                raise RuntimeError("Suspended-launch capture exceeded one nonterminal guest")
            return group, pool, instances

        started_at = now()
        start = time.monotonic()
        attempt = 0
        while True:
            group, pool, instances = sample("suspended-launch-window-" + str(attempt))
            if time.monotonic() - start >= 60:
                break
            time.sleep(5)
            attempt += 1
        self.note("suspended-launch-stable-window-complete", original_instance=first,
            started_at=started_at, observed_seconds=time.monotonic() - start,
            boundary="60-second polling window with Launch suspended and desired=prepared=1; no hook completion or capacity mutation during the window.",
            group_instances=group["Instances"], warm_instances=pool.get("Instances", []))

        member = next((i for i in pool.get("Instances", []) if i["InstanceId"] == first), None)
        if member and member["LifecycleState"] == "Warmed:Terminating:Wait":
            self.complete("suspended-launch-retirement", first, "terminate", origin="WarmPool", destination="EC2")
        physical = next((i["State"]["Name"] for i in instances if i["InstanceId"] == first), None)
        retired = (member is not None and member["LifecycleState"].startswith("Warmed:Terminating")) or physical in ("shutting-down", "terminated")
        if retired:
            self.state(first, "terminated", "suspended-launch-retired-terminal", seconds=90)
            self.wait_pool("suspended-launch-retired-pool-empty", lambda p: not p.get("Instances"))
        sample("suspended-launch-before-resume")
        self.asg("suspended-launch-resume", "resume_processes", dict(name, ScalingProcesses=["Launch"]), required=True)
        group = self.wait_group("suspended-launch-activation-wait",
            lambda g: any(i["LifecycleState"] == "Pending:Wait" for i in g["Instances"]))
        activated = next(i["InstanceId"] for i in group["Instances"] if i["LifecycleState"] == "Pending:Wait")
        sample("suspended-launch-activation-before-complete")
        self.complete("suspended-launch-activation", activated, "launch",
            origin="WarmPool" if activated == first else "EC2", destination="AutoScalingGroup")
        self.wait_group("suspended-launch-inservice",
            lambda g: any(i["InstanceId"] == activated and i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.state(activated, "running", "suspended-launch-active-running", seconds=30)
        self.wait_pool("suspended-launch-active-pool-empty", lambda p: not p.get("Instances"))
        sample("suspended-launch-after-activation")
        self.note("suspended-launch-activation-outcome", original_instance=first,
            active_instance=activated, same_instance=activated == first, retired_before_resume=retired)

        self.asg("suspended-launch-cleanup-suspend", "suspend_processes", dict(name, ScalingProcesses=["Launch"]), required=True)
        self.desired("suspended-launch-cleanup-desired-zero", 0)
        self.wait_group("suspended-launch-cleanup-termination-wait",
            lambda g: any(i["InstanceId"] == activated and i["LifecycleState"] == "Terminating:Wait" for i in g["Instances"]))
        self.complete("suspended-launch-cleanup-termination", activated, "terminate", origin="AutoScalingGroup", destination="EC2")
        self.state(activated, "terminated", "suspended-launch-cleanup-terminal", seconds=90)
        self.note("suspended-launch-capture-complete")

    def group_deletion(self):
        name = {"AutoScalingGroupName": self.data["group_name"]}
        self.asg("warm-group-delete-max-one", "update_auto_scaling_group", dict(name, MaxSize=1), required=True)
        self.put("warm-group-delete-pool", PoolState="Running", MaxGroupPreparedCapacity=1, required=True)
        iid = self.warm_member("warm-group-delete-launch-wait", "Warmed:Pending:Wait")
        self.complete("warm-group-delete-launch", iid, "launch", origin="EC2", destination="WarmPool")
        self.warm_member("warm-group-delete-running", "Warmed:Running")
        self.asg("warm-nonempty-group-normal-delete", "delete_auto_scaling_group", name)
        self.snapshot("warm-after-group-normal-delete")
        self.asg("warm-nonempty-group-force-delete", "delete_auto_scaling_group", dict(name, ForceDelete=True), required=True)
        self.warm_member("warm-group-delete-termination-wait", "Warmed:Terminating:Wait")
        self.complete("warm-group-delete-termination", iid, "terminate", origin="WarmPool", destination="EC2")
        self.wait_group("warm-group-force-absent", lambda g: g is None, seconds=150)
        self.state(iid, "terminated", "warm-group-force-ec2-terminal", seconds=90)
        self.pool("warm-group-absent-describe")
        self.put("warm-group-absent-put")
        self.asg("warm-group-absent-delete", "delete_warm_pool", name)
        self.note("warm-group-delete-capture-complete")

    def retention(self):
        name = {"AutoScalingGroupName": self.data["group_name"]}
        root = self.request()["BlockDeviceMappings"][:1]
        root[0]["Ebs"].update(Encrypted=True, DeleteOnTermination=True)
        version = self.ec2("hibernated-encrypted-template-no-configured", "create_launch_template_version", {
            "LaunchTemplateId": self.data["template_id"], "SourceVersion": "1",
            "LaunchTemplateData": {"BlockDeviceMappings": root}}, required=True)["LaunchTemplateVersion"]["VersionNumber"]
        self.asg("hibernated-encrypted-template-select", "update_auto_scaling_group", dict(name,
            LaunchTemplate={"LaunchTemplateId": self.data["template_id"], "Version": str(version)}), required=True)
        self.put("hibernated-encrypted-configured-omitted", PoolState="Hibernated",
            MinSize=0, MaxGroupPreparedCapacity=0)
        self.pool("hibernated-encrypted-configured-omitted-described")
        self.put("hibernated-admission-restore-running", PoolState="Running", required=True)
        self.asg("hibernated-admission-template-restore", "update_auto_scaling_group", dict(name,
            LaunchTemplate={"LaunchTemplateId": self.data["template_id"], "Version": "1"}), required=True)
        self.asg("retention-warm-max-one", "update_auto_scaling_group", dict(name, MaxSize=1), required=True)
        self.put("retention-warm-running", PoolState="Running", MaxGroupPreparedCapacity=1,
            InstanceReusePolicy={"ReuseOnScaleIn": True}, required=True)
        first = self.warm_member("retention-warm-launch-wait", "Warmed:Pending:Wait")
        self.asg("retention-suspend-replacement", "suspend_processes", dict(name, ScalingProcesses=["Launch"]), required=True)
        self.complete("retention-warm-launch-abandon", first, "launch", "ABANDON", origin="EC2", destination="WarmPool")
        self.snapshot("retention-after-pending-abandon")
        self.warm_member("retention-warm-termination-wait", "Warmed:Terminating:Wait")
        self.complete("retention-warm-termination-abandon", first, "terminate", "ABANDON", destination="EC2")
        pool = self.wait_pool("retention-warm-abandon-settled", lambda p: not p.get("Instances") or any(
            "Retained" in i["LifecycleState"] for i in p.get("Instances", [])))
        self.snapshot("retention-warm-abandon-boundary")
        retained = [i for i in pool.get("Instances", []) if i["InstanceId"] == first and "Retained" in i["LifecycleState"]]
        if retained:
            self.state(first, "running", "retention-warm-retained-ec2-running", seconds=30)
            self.note("warm-pending-and-termination-abandon", instance_id=first, retained=retained)
            self.asg("retention-warm-manual-release", "terminate_instance_in_auto_scaling_group", {
                "InstanceId": first, "ShouldDecrementDesiredCapacity": False}, required=True)
            self.warm_member("retention-warm-release-hook", "Warmed:Terminating:Wait")
            self.complete("retention-warm-release", first, "terminate", destination="EC2")
            self.wait_pool("retention-warm-release-empty", lambda p: not p.get("Instances"))
        self.state(first, "terminated", "retention-warm-abandon-ec2-terminal", seconds=90)
        self.asg("retention-resume-launch", "resume_processes", dict(name, ScalingProcesses=["Launch"]), required=True)
        self.pending_retention((first,))

    def empty_group_deletion(self):
        name = self.data["prefix"] + "-empty-warm"
        self.asg("empty-warm-group-create", "create_auto_scaling_group", {
            "AutoScalingGroupName": name, "MinSize": 0, "MaxSize": 0, "DesiredCapacity": 0,
            "VPCZoneIdentifier": self.data["owned"]["subnet"],
            "LaunchTemplate": {"LaunchTemplateId": self.data["template_id"], "Version": "1"},
            "Tags": [{"Key": "suite", "Value": self.data["prefix"], "PropagateAtLaunch": True}]}, required=True)
        self.asg("empty-warm-group-configure", "put_warm_pool", {
            "AutoScalingGroupName": name, "MinSize": 0, "MaxGroupPreparedCapacity": 0}, required=True)
        self.asg("empty-warm-group-normal-delete", "delete_auto_scaling_group", {"AutoScalingGroupName": name})
        accepted = self.data["calls"][-1]["code"] == "Success"
        for attempt in range(13):
            groups = self.asg("empty-warm-group-deleted-" + str(attempt), "describe_auto_scaling_groups",
                {"AutoScalingGroupNames": [name]}, required=True)["AutoScalingGroups"]
            if not groups or not accepted:
                self.note("empty-configured-warm-group-deletion", accepted=accepted, groups=groups)
                return
            time.sleep(5)
        self.data["gaps"].append("Empty configured group deletion accepted but absence not observed within 65 seconds")
        self.save()

    def pending_retention(self, excluded=()):
        name = {"AutoScalingGroupName": self.data["group_name"]}
        second = self.warm_member("retention-reuse-initial-wait", "Warmed:Pending:Wait", excluded)
        self.complete("retention-reuse-initial-launch", second, "launch", origin="EC2", destination="WarmPool")
        self.warm_member("retention-reuse-initial-running", "Warmed:Running")
        if not self.args.force_retained_only:
            self.put("retention-existing-running-change-stopped", PoolState="Stopped")
            for sample in range(3):
                time.sleep(10)
                self.snapshot("retention-existing-state-update-" + str(sample))
            self.wait_pool("retention-existing-state-update-stable", lambda p: any(
                i["InstanceId"] == second and i["LifecycleState"] in ("Warmed:Running", "Warmed:Stopped")
                for i in p.get("Instances", [])))
            self.put("retention-reuse-restore-running", PoolState="Running")
        self.asg("return-abandon-current-policy", "update_auto_scaling_group", dict(name,
            InstanceLifecyclePolicy={"RetentionTriggers": {"TerminateHookAbandon": self.args.return_policy}}), required=True)
        self.desired("retention-activate-one", 1)
        self.wait_group("retention-activation-wait", lambda g: any(i["InstanceId"] == second and
            i["LifecycleState"] == "Pending:Wait" for i in g["Instances"]))
        self.complete("retention-activation-launch", second, "launch", origin="WarmPool", destination="AutoScalingGroup")
        self.wait_group("retention-activation-inservice", lambda g: any(i["InstanceId"] == second and
            i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.asg("retention-suspend-reuse-replacement", "suspend_processes", dict(name, ScalingProcesses=["Launch"]), required=True)
        self.desired("retention-reuse-scale-in", 0)
        self.warm_member("retention-reuse-wait", "Warmed:Pending:Wait")
        self.complete("retention-reuse-abandon", second, "terminate", "ABANDON", origin="AutoScalingGroup", destination="WarmPool")
        pool = self.wait_pool("retention-reuse-abandon-settled", lambda p: not p.get("Instances") or any(
            i["InstanceId"] == second and (i["LifecycleState"].endswith(":Retained") or
                i["LifecycleState"] in ("Warmed:Running", "Warmed:Stopped"))
            for i in p.get("Instances", [])))
        self.snapshot("retention-reuse-abandon-boundary")
        member = next((i for i in pool.get("Instances", []) if i["InstanceId"] == second), None)
        expected = "terminated" if member is None else (
            "stopped" if member["LifecycleState"] == "Warmed:Stopped" else "running")
        self.state(second, expected, "retention-reuse-real-guest-outcome", seconds=90)
        self.note("reuse-termination-abandon-observed", instance_id=second,
            retention_policy=self.args.return_policy, member=member, ec2_state=expected)
        if not self.args.force_retained_only:
            self.asg("retention-pending-normal-delete-pool", "delete_warm_pool", name)
        self.asg("retention-pending-force-delete-pool", "delete_warm_pool", dict(name, ForceDelete=True))
        self.snapshot("retention-pending-after-delete")
        if self.args.force_retained_only:
            self.force_retained(second)
        else:
            self.metric_observations("retention-warm-metrics")

    def force_retained(self, iid):
        end = time.monotonic() + 120
        abandoned = False
        previous_state = None
        attempt = 0
        while True:
            pool = self.pool("force-retained-unchanged-policy-" + str(attempt))
            member = next((i for i in pool.get("Instances", []) if i["InstanceId"] == iid), None)
            state = member["LifecycleState"] if member else None
            self.drain_events("force-retained-unchanged-policy-" + str(attempt))
            if state != previous_state:
                self.snapshot("force-retained-transition-" + str(attempt))
                self.note("force-retained-transition", instance_id=iid, member=member)
                previous_state = state
            if state == "Warmed:Terminating:Wait" and not abandoned:
                self.complete("force-retained-new-termination", iid, "terminate", "ABANDON",
                    origin="WarmPool", destination="EC2")
                abandoned = True
                end = time.monotonic() + 120
            if time.monotonic() >= end or not member:
                break
            time.sleep(5)
            attempt += 1
        self.snapshot("force-retained-before-manual-release")
        self.note("force-retained-unchanged-policy-window-complete", instance_id=iid,
            member=member, abandoned_new_hook=abandoned)
        if state and state.endswith(":Retained"):
            self.asg("force-retained-manual-release", "terminate_instance_in_auto_scaling_group", {
                "InstanceId": iid, "ShouldDecrementDesiredCapacity": False}, required=True)
            self.warm_member("force-retained-manual-release-wait", "Warmed:Terminating:Wait")
            self.complete("force-retained-manual-release", iid, "terminate",
                origin="WarmPool", destination="EC2")
        elif state == "Warmed:Terminating:Wait":
            self.complete("force-retained-current-termination", iid, "terminate",
                origin="WarmPool", destination="EC2")
        self.wait_pool("force-retained-deletion-complete",
            lambda p: not p.get("WarmPoolConfiguration") and not p.get("Instances"))
        self.state(iid, "terminated", "force-retained-real-guest-terminal", seconds=90)
        self.note("force-retained-capture-complete", instance_id=iid)

    def cleanup(self):
        self.cleaning = True
        signal.alarm(0)
        for name in self.data["owned"]["asgs"]:
            response = self.asg("cleanup-warm-retention-policy-read", "describe_auto_scaling_groups", {"AutoScalingGroupNames": [name]})
            for group in response.get("AutoScalingGroups", []):
                if group.get("InstanceLifecyclePolicy", {}).get("RetentionTriggers", {}).get("TerminateHookAbandon") == "retain":
                    self.asg("cleanup-warm-retention-policy-terminate", "update_auto_scaling_group", {
                        "AutoScalingGroupName": name,
                        "InstanceLifecyclePolicy": {"RetentionTriggers": {"TerminateHookAbandon": "terminate"}}})
        super().cleanup()
        self.data["cleanup"]["capture_to_cleanup_wall_seconds"] = (
            datetime.fromisoformat(self.data["cleanup"]["finished_at"]) -
            datetime.fromisoformat(self.data["captured_at"])).total_seconds()
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/autoscaling/warm_pool_native.json"))
    parser.add_argument("--live-seconds", type=int, default=780, choices=range(300, 781), metavar="300..780")
    parser.add_argument("--audit-rounds", type=int, default=6, choices=range(1, 7))
    parser.add_argument("--return-policy", default="retain", choices=["retain", "terminate"],
        help="Policy used by the pending-return ABANDON contrast")
    parser.add_argument("--initial-pool-state", choices=["Stopped", "Running", "Hibernated"],
        help="Fresh lifecycle initial state; defaults Stopped, or Hibernated for --reuse-only")
    parser.add_argument("--ec2-group-metrics", action="store_true",
        help="If remaining live bound permits, detail-monitor active and Running-warm instances for a full aligned minute")
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument("--retention-only", action="store_true")
    variants.add_argument("--pending-retention-only", action="store_true",
        help="Fresh Running pool state update, reuse ABANDON and Warmed:Pending:Retained")
    variants.add_argument("--lifecycle-only", action="store_true",
        help="Fresh lifecycle scope, skipping already captured zero-capacity control/IAM contrasts")
    variants.add_argument("--reuse-only", action="store_true",
        help="Encrypted-root Hibernated launch with configured omitted, then sizing/Running/reuse/deletion")
    variants.add_argument("--group-deletion-only", action="store_true",
        help="Fresh one-guest nonempty warm pool ordinary/forced group deletion contrast")
    variants.add_argument("--force-retained-only", action="store_true",
        help="Unchanged-policy force deletion, one ABANDON, bounded re-retention and manual release")
    variants.add_argument("--suspended-launch-only", action="store_true",
        help="One-guest Running pool: suspend Launch, increase desired, observe 60 seconds, resume and identify activation")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--cleanup-only", action="store_true")
    modes.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    capture = WarmPoolCapture(args)
    if args.audit_only:
        if not capture.data["cleanup"].get("complete"):
            raise RuntimeError("Complete paid-resource cleanup before audit collection")
        if not capture.data.get("force_retained_only") and not capture.data.get("suspended_launch_only"):
            capture.metric_observations("warm-metrics-after-cleanup")
        capture.audit()
        if capture.data.get("ec2_group_metric_window"):
            first_late_metric = len(capture.data["calls"])
            capture.metric_observations("warm-metrics-after-audit")
            capture.data["cloudtrail"]["other_services_outside_selected_sources"].extend(
                call["label"] for call in capture.data["calls"][first_late_metric:])
            capture.save()
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
