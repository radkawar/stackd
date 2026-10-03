#!/usr/bin/env python3
"""Owned, bounded native ASG lifecycle and caller-authority evidence.

Reuse InstanceCapture's recorder, IAM/network setup, ownership discovery and EC2
cleanup, and collect_history's exact-request-ID CloudTrail collector. Never alter
standing roles/defaults. The output is also the resumable ownership ledger.

Fresh captures refuse an existing output. --final-phase-only captures only the
default-version/min-max/protected-force-delete branch with fresh owned resources;
it does not resume or claim completion of a failed earlier observation window.
--direct-force-only isolates force deletion without earlier scale-in intent.
--metrics-only keeps MinSize, MaxSize and DesiredCapacity zero and borrows an
authorized subnet read-only; it never creates networking or EC2 instances.
--cleanup-only resumes exact-owned cleanup, and --audit-only harvests read-only
CloudTrail history after paid-resource cleanup. Keep failed calls and late/missing
event windows: observed polling timestamps are not service latency guarantees.
"""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import signal
import time
import uuid

import boto3
from botocore.exceptions import BotoCoreError

from cloudtrail_events import CollectionError, collect_history
from ec2_instances_probe import InstanceCapture, interrupt
from ebs_encryption_probe import CONFIG, allow, now, policy, safe

DOCS = [
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-launch-template-permissions.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-instance-protection.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_UpdateAutoScalingGroup.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DeleteAutoScalingGroup.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_SetInstanceHealth.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-event-reference.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html",
]


class LifecycleCapture(InstanceCapture):
    def __init__(self, args):
        super().__init__(args)
        for service in ("autoscaling", "events", "sqs", "cloudwatch"):
            self.clients[service] = self.session.client(service, config=CONFIG)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(prefix="stackd-asg-life-" + uuid.uuid4().hex[:12], documentation=DOCS,
                scope=__doc__, bounds={"max_simultaneous_instances": 2,
                    "experiment_seconds": args.live_seconds, "paid_resource_wall_bound_seconds": 1200,
                    "instance_type": "t3.nano", "root_gib": 8, "root_type": "gp3",
                    "delete_on_termination": True, "public_network": False},
                eventbridge_events=[], phases=[])
            self.data.pop("guest_program", None)
            self.data.pop("guest_observations", None)
        for kind in ("asgs", "templates"):
            self.data["owned"].setdefault(kind, [])
        self.save()

    def asg(self, label, method, parameters=None, **kwargs):
        return self.observe(label, "autoscaling", method, parameters, **kwargs)

    def observe(self, label, service, method, parameters=None, **kwargs):
        started_at = now()
        try:
            result = super().observe(label, service, method, parameters, **kwargs)
        except BotoCoreError as error:
            self.data.setdefault("transport_failures", []).append({
                "label": label, "service": service, "method": method, "input": safe(parameters or {}),
                "started_at": started_at, "finished_at": now(),
                "type": type(error).__name__, "message": str(error),
                "boundary": "No valid native response/request ID was received; mutation outcome may be unknown."})
            self.save()
            raise
        if self.data["calls"][-1]["code"] == "Success":
            if method == "create_auto_scaling_group":
                self.own("asgs", parameters["AutoScalingGroupName"])
            elif method == "create_launch_template":
                self.own("templates", result["LaunchTemplate"]["LaunchTemplateId"])
            elif method == "create_queue":
                self.data["owned"]["queue_url"] = result["QueueUrl"]
            elif method == "put_rule":
                self.data["owned"].update(rule=parameters["Name"], rule_arn=result["RuleArn"])
        self.save()
        return result

    def note(self, name, **details):
        self.data["phases"].append({"name": name, "at": now(), **safe(details)})
        self.save()
        print("PHASE " + name, flush=True)

    def group(self, label):
        groups = self.asg(label, "describe_auto_scaling_groups",
            {"AutoScalingGroupNames": [self.data["group_name"]]}, required=True)["AutoScalingGroups"]
        return groups[0] if groups else None

    def snapshot(self, label):
        group = self.group(label + "-group")
        self.asg(label + "-activities", "describe_scaling_activities",
            {"AutoScalingGroupName": self.data["group_name"], "IncludeDeletedGroups": True, "MaxRecords": 100})
        ids = [row["InstanceId"] for row in (group or {}).get("Instances", [])]
        if ids:
            self.asg(label + "-membership", "describe_auto_scaling_instances", {"InstanceIds": ids})
            self.ec2(label + "-ec2", "describe_instances", {"InstanceIds": ids}, required=True)
            self.ec2(label + "-volumes", "describe_volumes",
                {"Filters": [{"Name": "attachment.instance-id", "Values": ids}]}, required=True)
        self.drain_events(label)
        return group

    def wait_group(self, label, predicate, seconds=150):
        end = time.monotonic() + seconds
        attempt = 0
        while True:
            group = self.group(label + "-" + str(attempt))
            ids = [row["InstanceId"] for row in (group or {}).get("Instances", [])]
            if ids:
                self.ec2(label + "-ec2-" + str(attempt), "describe_instances", {"InstanceIds": ids})
            self.drain_events(label + "-" + str(attempt))
            if predicate(group):
                return self.snapshot(label + "-observed")
            if time.monotonic() >= end:
                self.data["gaps"].append(label + ": not observed within " + str(seconds) + " seconds")
                self.save()
                raise TimeoutError(label + " observation window expired")
            time.sleep(5)
            attempt += 1

    def drain_events(self, label):
        queue = self.data["owned"].get("queue_url")
        if not queue or self.data.get("notification_queue_deleted"):
            return
        for batch in range(3):
            response = self.observe(label + "-events-" + str(batch), "sqs", "receive_message",
                {"QueueUrl": queue, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 0})
            messages = response.get("Messages", [])
            for message in messages:
                event = json.loads(message["Body"])
                if event.get("id") not in {row["event"].get("id") for row in self.data["eventbridge_events"]}:
                    self.data["eventbridge_events"].append({"observed_at": now(), "event": event,
                        "sqs_message_id": message["MessageId"]})
                self.observe(label + "-ack-" + message["MessageId"], "sqs", "delete_message",
                    {"QueueUrl": queue, "ReceiptHandle": message["ReceiptHandle"]})
            self.save()
            if len(messages) < 10:
                break

    def hook_token(self, iid, transition, label):
        for attempt in range(13):
            self.drain_events(label + "-" + str(attempt))
            for row in self.data["eventbridge_events"]:
                detail = row["event"].get("detail", {})
                if detail.get("EC2InstanceId") == iid and detail.get("LifecycleTransition") == transition:
                    return detail["LifecycleActionToken"]
            time.sleep(5)
        self.data["gaps"].append(label + ": lifecycle EventBridge token absent within 65-second observation window; instance-ID action remains available")
        self.save()
        return None

    def action(self, label, iid, hook, result=None):
        transition = "autoscaling:EC2_INSTANCE_" + ("LAUNCHING" if hook == "launch" else "TERMINATING")
        token = self.hook_token(iid, transition, label)
        parameters = {"AutoScalingGroupName": self.data["group_name"], "LifecycleHookName": hook}
        parameters.update({"LifecycleActionToken": token} if token else {"InstanceId": iid})
        self.asg(label + "-heartbeat", "record_lifecycle_action_heartbeat", parameters)
        if result:
            self.asg(label + "-complete", "complete_lifecycle_action",
                dict(parameters, LifecycleActionResult=result), required=True)
        return parameters

    def events_setup(self, arn):
        p = self.data["prefix"]
        queue = self.observe("owned-event-queue", "sqs", "create_queue",
            {"QueueName": p, "Attributes": {"MessageRetentionPeriod": "3600"},
             "tags": {"suite": p}}, required=True)["QueueUrl"]
        queue_arn = self.observe("owned-event-queue-arn", "sqs", "get_queue_attributes",
            {"QueueUrl": queue, "AttributeNames": ["QueueArn"]}, required=True)["Attributes"]["QueueArn"]
        rule = self.observe("owned-exact-group-rule", "events", "put_rule", {"Name": p,
            "EventPattern": json.dumps({"source": ["aws.autoscaling"], "resources": [arn]}),
            "State": "ENABLED", "Tags": [{"Key": "suite", "Value": p}]}, required=True)["RuleArn"]
        self.observe("owned-event-queue-policy", "sqs", "set_queue_attributes", {"QueueUrl": queue,
            "Attributes": {"Policy": json.dumps(policy([{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule}}}]))}}, required=True)
        response = self.observe("owned-event-target", "events", "put_targets",
            {"Rule": p, "Targets": [{"Id": "owned", "Arn": queue_arn}]}, required=True)
        if response.get("FailedEntryCount"):
            raise RuntimeError("EventBridge target failed")
        self.data["event_selector"] = {"group_arn": arn, "rule_arn": rule, "queue_arn": queue_arn}
        self.save()
        time.sleep(10)

    def assumed_clients(self, label, statements):
        document = policy(statements)
        self.data["sessions"][label] = document
        self.save()
        response = self.observe(label + "-assume", "sts", "assume_role",
            {"RoleArn": "arn:aws:iam::" + self.args.account + ":role/" + self.data["launcher_role"],
             "RoleSessionName": label, "DurationSeconds": 900, "Policy": json.dumps(document)}, required=True)
        credentials = response["Credentials"]
        session = boto3.Session(region_name=self.args.region, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        return {name: session.client(name, config=CONFIG) for name in ("ec2", "autoscaling")}

    def calibrate(self, template, base):
        p = self.data["prefix"]
        root = "arn:aws:autoscaling:" + self.args.region + ":" + self.args.account + ":autoScalingGroup:*:autoScalingGroupName/" + p + "*"
        statements = self.launch_statements + [allow("ec2:RunInstances", "arn:aws:ec2:" + self.args.region + ":" + self.args.account + ":launch-template/" + template),
            allow(["autoscaling:CreateAutoScalingGroup", "autoscaling:UpdateAutoScalingGroup", "autoscaling:DeleteAutoScalingGroup", "autoscaling:SetDesiredCapacity"], root)]
        self.observe("bounded-asg-launcher-policy", "iam", "put_role_policy", {"RoleName": self.data["launcher_role"],
            "PolicyName": "owned-launches", "PolicyDocument": json.dumps(policy(statements))}, required=True)
        time.sleep(15)
        clients = {}
        for name, deny in (("allowed", None), ("denied-run", {"Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "*"}),
                ("denied-pass", {"Effect": "Deny", "Action": "iam:PassRole", "Resource": self.pass_statement["Resource"]})):
            current = self.assumed_clients(name, statements + ([deny] if deny else []))
            clients[name] = current
            self.ec2(name + "-direct-dryrun", "run_instances", {"LaunchTemplate": {"LaunchTemplateId": template, "Version": "1"},
                "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": self.data["owned"]["subnet"],
                    "Groups": [self.data["owned"]["group"]], "AssociatePublicIpAddress": False,
                    "DeleteOnTermination": True}], "MinCount": 1, "MaxCount": 1, "DryRun": True},
                client=current["ec2"], caller=name)
            request = dict(base, AutoScalingGroupName=p + "-" + name)
            self.asg(name + "-create-zero", "create_auto_scaling_group", request, client=current["autoscaling"], caller=name)
            if self.data["calls"][-1]["code"] == "Success":
                self.asg(name + "-delete-zero", "delete_auto_scaling_group", {"AutoScalingGroupName": request["AutoScalingGroupName"]}, required=True)
        for name in ("denied-run", "denied-pass"):
            self.asg(name + "-update-capacity-only", "update_auto_scaling_group",
                {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 0}, client=clients[name]["autoscaling"], caller=name)
            self.asg(name + "-update-template", "update_auto_scaling_group",
                {"AutoScalingGroupName": self.data["group_name"], "LaunchTemplate": base["LaunchTemplate"]}, client=clients[name]["autoscaling"], caller=name)
        name = p + "-retired-time"
        schedule = {"AutoScalingGroupName": self.data["group_name"], "ScheduledActionName": name}
        try:
            self.asg("schedule-retired-time-only", "put_scheduled_update_group_action",
                dict(schedule, Time=datetime.now(timezone.utc) + timedelta(days=1), DesiredCapacity=0))
            self.asg("schedule-retired-time-described", "describe_scheduled_actions",
                {"AutoScalingGroupName": self.data["group_name"], "ScheduledActionNames": [name]})
        finally:
            self.asg("schedule-retired-time-delete", "delete_scheduled_action", schedule)
        self.asg("delete-nonexistent-policy", "delete_policy",
            {"AutoScalingGroupName": self.data["group_name"], "PolicyName": p + "-never-created"})
        self.note("authority-calibration-complete")
        return clients

    def run_metrics(self):
        p = self.data["prefix"]
        self.data["bounds"].update(max_simultaneous_instances=0, metric_observation_seconds=180,
            resource_boundary="One owned launch template and zero-capacity group; borrowed subnet is read-only.")
        self.data["group_name"] = p + "-metrics"
        placement = ({"SubnetIds": [self.args.metrics_subnet]} if self.args.metrics_subnet else
            {"Filters": [{"Name": "default-for-az", "Values": ["true"]}]})
        subnets = self.ec2("borrow-subnet-read-only" if self.args.metrics_subnet else "borrow-default-subnet-read-only",
            "describe_subnets", placement, required=True)["Subnets"]
        candidates = [row for row in subnets if row["State"] == "available" and row["OwnerId"] == self.args.account]
        if not candidates:
            raise RuntimeError("No available same-account borrowed subnet; no metrics controls created")
        subnet = candidates[0]
        self.data["borrowed_subnet"] = subnet["SubnetId"]
        image_id = self.observe("official-amazon-linux-parameter", "ssm", "get_parameter",
            {"Name": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}, required=True)["Parameter"]["Value"]
        image = self.ec2("official-amazon-linux-image", "describe_images",
            {"ImageIds": [image_id], "Owners": ["amazon"]}, required=True)["Images"][0]
        template = self.ec2("owned-zero-capacity-template", "create_launch_template",
            {"LaunchTemplateName": p, "TagSpecifications": self.tags("launch-template"),
             "LaunchTemplateData": {"ImageId": image_id, "InstanceType": "t3.nano",
                "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
                "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"],
                    "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}]}}, required=True)["LaunchTemplate"]["LaunchTemplateId"]
        self.data["template_id"] = template
        self.asg("create-metrics-zero", "create_auto_scaling_group",
            {"AutoScalingGroupName": self.data["group_name"], "MinSize": 0, "MaxSize": 0, "DesiredCapacity": 0,
             "VPCZoneIdentifier": subnet["SubnetId"], "LaunchTemplate": {"LaunchTemplateId": template, "Version": "1"},
             "Tags": [{"Key": "suite", "Value": p, "PropagateAtLaunch": True}]}, required=True)
        self.asg("enable-all-one-minute-metrics", "enable_metrics_collection",
            {"AutoScalingGroupName": self.data["group_name"], "Granularity": "1Minute"}, required=True)
        self.group("metrics-enabled-group")
        start = datetime.now(timezone.utc) - timedelta(minutes=1)
        deadline = time.monotonic() + 180
        metrics = ("GroupDesiredCapacity", "GroupInServiceInstances", "GroupAndWarmPoolDesiredCapacity")
        found = set()
        attempt = 0
        while True:
            for metric in metrics:
                result = self.observe("native-metric-" + metric + "-" + str(attempt), "cloudwatch", "get_metric_statistics",
                    {"Namespace": "AWS/AutoScaling", "MetricName": metric,
                     "Dimensions": [{"Name": "AutoScalingGroupName", "Value": self.data["group_name"]}],
                     "StartTime": start, "EndTime": datetime.now(timezone.utc),
                     "Period": 60, "Statistics": ["Average", "Minimum", "Maximum", "SampleCount"]}, required=True)
                if result.get("Datapoints"):
                    found.add(metric)
            if time.monotonic() >= deadline:
                break
            time.sleep(min(30, max(0, deadline - time.monotonic())))
            attempt += 1
        for metric in metrics:
            if metric not in found:
                self.data["gaps"].append(metric + ": no native datapoints inside bounded180-second observation; not evidence of non-emission.")
        for metric in ("WarmPoolDesiredCapacity", "WarmPoolTotalCapacity"):
            result = self.observe("native-no-pool-" + metric, "cloudwatch", "get_metric_statistics",
                {"Namespace": "AWS/AutoScaling", "MetricName": metric,
                 "Dimensions": [{"Name": "AutoScalingGroupName", "Value": self.data["group_name"]}],
                 "StartTime": start, "EndTime": datetime.now(timezone.utc),
                 "Period": 60, "Statistics": ["Average", "Minimum", "Maximum", "SampleCount"]}, required=True)
            if result.get("Datapoints"):
                found.add(metric)
            else:
                self.data["gaps"].append(metric + ": no native datapoints in final bounded query; not evidence of non-emission.")
        self.group("metrics-final-zero-group")
        self.note("zero-capacity-metrics-complete", metrics_with_observed_datapoints=sorted(found))

    def run_failure_boundaries(self):
        self.data["bounds"].update(max_simultaneous_instances=1,
            resource_boundary="One owned private t3.nano; failed lifecycle delivery, suspended membership and protected retirement.")
        self.setup()
        p, owned = self.data["prefix"], self.data["owned"]
        self.data["group_name"] = p + "-failures"
        image = self.data["source_image"]
        launch = {"ImageId": image["ImageId"], "InstanceType": "t3.nano",
            "IamInstanceProfile": {"Name": self.data["guest_role"]},
            "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": False,
                "DeleteOnTermination": True, "Groups": [owned["group"]]}],
            "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"],
                "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}],
            "CreditSpecification": {"CpuCredits": "standard"},
            "TagSpecifications": self.tags("instance", "volume", "network-interface")}
        template = self.ec2("failure-template", "create_launch_template",
            {"LaunchTemplateName": p, "LaunchTemplateData": launch,
             "TagSpecifications": self.tags("launch-template")}, required=True)["LaunchTemplate"]["LaunchTemplateId"]
        group_input = {"AutoScalingGroupName": self.data["group_name"]}
        self.asg("failure-group-zero", "create_auto_scaling_group", dict(group_input,
            MinSize=0, MaxSize=1, DesiredCapacity=0, VPCZoneIdentifier=owned["subnet"],
            LaunchTemplate={"LaunchTemplateId": template, "Version": "1"},
            HealthCheckGracePeriod=0, DefaultCooldown=0), required=True)
        queue = self.observe("failure-notification-queue", "sqs", "create_queue",
            {"QueueName": p, "tags": {"suite": p}}, required=True)["QueueUrl"]
        queue_arn = self.observe("failure-notification-queue-arn", "sqs", "get_queue_attributes",
            {"QueueUrl": queue, "AttributeNames": ["QueueArn"]}, required=True)["Attributes"]["QueueArn"]
        role = self.data["guest_role"]
        self.data["notification_role"] = role
        self.save()
        self.observe("notification-role-trust", "iam", "update_assume_role_policy",
            {"RoleName": role, "PolicyDocument": json.dumps(policy([{"Effect": "Allow",
             "Principal": {"Service": ["ec2.amazonaws.com", "autoscaling.amazonaws.com"]},
             "Action": "sts:AssumeRole"}]))}, required=True)
        self.observe("notification-role-send", "iam", "put_role_policy",
            {"RoleName": role, "PolicyName": "notify-lifecycle",
             "PolicyDocument": json.dumps(policy([allow(["sqs:SendMessage", "sqs:GetQueueUrl"], queue_arn)]))}, required=True)
        time.sleep(15)
        for hook, transition in (("launch", "LAUNCHING"), ("terminate", "TERMINATING")):
            self.asg("valid-notification-hook-" + hook, "put_lifecycle_hook", dict(group_input,
                LifecycleHookName=hook, LifecycleTransition="autoscaling:EC2_INSTANCE_" + transition,
                HeartbeatTimeout=30, DefaultResult="CONTINUE", NotificationTargetARN=queue_arn,
                RoleARN="arn:aws:iam::" + self.args.account + ":role/" + role), required=True)
        self.drain_events("initial-test-notifications")
        self.observe("delete-notification-destination", "sqs", "delete_queue", {"QueueUrl": queue}, required=True)
        self.observe("notification-destination-absent", "sqs", "get_queue_attributes",
            {"QueueUrl": queue, "AttributeNames": ["QueueArn"]})
        if self.data["calls"][-1]["code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise RuntimeError("Notification destination absence was not observed")
        self.data["notification_queue_deleted"] = True
        self.note("notification-destination-absent-before-launch")
        self.asg("launch-with-unavailable-notification", "set_desired_capacity", dict(group_input, DesiredCapacity=1), required=True)
        group = self.wait_group("failed-notification-launch", lambda g: any(
            i["LifecycleState"] == "InService" for i in g["Instances"]), seconds=240)
        iid = group["Instances"][0]["InstanceId"]
        self.note("failed-notification-launch-inservice", instance=iid)
        self.asg("detach-for-suspended-attach", "detach_instances",
            dict(group_input, InstanceIds=[iid], ShouldDecrementDesiredCapacity=True), required=True)
        self.wait_group("detached-before-suspended-attach", lambda g: not g["Instances"])
        self.asg("suspend-launch-for-attach", "suspend_processes", dict(group_input, ScalingProcesses=["Launch"]), required=True)
        self.asg("attach-while-launch-suspended", "attach_instances", dict(group_input, InstanceIds=[iid]))
        self.asg("resume-launch-for-attach", "resume_processes", dict(group_input, ScalingProcesses=["Launch"]), required=True)
        self.asg("attach-after-launch-resumed", "attach_instances", dict(group_input, InstanceIds=[iid]), required=True)
        self.wait_group("reattached-inservice", lambda g: any(i["InstanceId"] == iid and i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.asg("enter-standby-before-suspension", "enter_standby", dict(group_input, InstanceIds=[iid], ShouldDecrementDesiredCapacity=True), required=True)
        self.wait_group("entered-standby", lambda g: any(i["LifecycleState"] == "Standby" for i in g["Instances"]))
        self.asg("suspend-launch-for-exit", "suspend_processes", dict(group_input, ScalingProcesses=["Launch"]), required=True)
        self.asg("exit-standby-while-launch-suspended", "exit_standby", dict(group_input, InstanceIds=[iid]))
        self.asg("resume-launch-for-exit", "resume_processes", dict(group_input, ScalingProcesses=["Launch"]), required=True)
        self.asg("exit-standby-after-launch-resumed", "exit_standby", dict(group_input, InstanceIds=[iid]), required=True)
        self.wait_group("returned-inservice", lambda g: any(i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.data["protected_instance"] = iid
        self.save()
        self.ec2("enable-api-termination-protection", "modify_instance_attribute",
            {"InstanceId": iid, "DisableApiTermination": {"Value": True}}, required=True)
        self.ec2("public-protected-termination", "terminate_instances", {"InstanceIds": [iid]})
        self.asg("suspend-automatic-termination", "suspend_processes", dict(group_input, ScalingProcesses=["Terminate"]), required=True)
        self.asg("unhealthy-with-terminate-suspended", "set_instance_health",
            {"InstanceId": iid, "HealthStatus": "Unhealthy", "ShouldRespectGracePeriod": False}, required=True)
        self.asg("zero-before-resuming-termination", "set_desired_capacity", dict(group_input, DesiredCapacity=0), required=True)
        for attempt in range(3):
            self.snapshot("terminate-suspended-" + str(attempt))
            time.sleep(15)
        self.asg("resume-protected-retirement", "resume_processes", dict(group_input, ScalingProcesses=["Terminate"]), required=True)
        self.wait_group("failed-notification-termination", lambda g: not g["Instances"], seconds=240)
        self.state(iid, "terminated", "protected-native-retirement", seconds=180)
        self.data["protected_instance_terminated"] = True
        self.note("failure-boundaries-complete", instance=iid)

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        if self.args.metrics_only:
            self.run_metrics()
            return
        if self.args.failure_boundaries_only:
            self.run_failure_boundaries()
            return
        for method in ("describe_metric_collection_types", "describe_termination_policy_types", "describe_scaling_process_types"):
            self.asg("catalog-" + method, method)
        self.setup()
        p = self.data["prefix"]
        self.data["group_name"] = p + "-main"
        image = self.data["source_image"]
        launch = {"ImageId": image["ImageId"], "InstanceType": "t3.nano",
            "IamInstanceProfile": {"Name": self.data["guest_role"]},
            "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": False, "DeleteOnTermination": True,
                "Groups": [self.data["owned"]["group"]]}],
            "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"], "Ebs": {"VolumeSize": 8,
                "VolumeType": "gp3", "DeleteOnTermination": True}}],
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "CreditSpecification": {"CpuCredits": "standard"},
            "TagSpecifications": [{"ResourceType": kind, "Tags": [{"Key": "suite", "Value": p},
                {"Key": "template-version", "Value": "1"}, {"Key": "shared", "Value": "template"}]} for kind in ("instance", "volume", "network-interface")]}
        template = self.ec2("owned-launch-template-v1", "create_launch_template", {"LaunchTemplateName": p,
            "LaunchTemplateData": launch, "TagSpecifications": self.tags("launch-template")}, required=True)["LaunchTemplate"]["LaunchTemplateId"]
        self.data["template_id"] = template
        self.save()
        base = {"AutoScalingGroupName": self.data["group_name"], "MinSize": 0, "MaxSize": 2, "DesiredCapacity": 0,
            "VPCZoneIdentifier": self.data["owned"]["subnet"], "LaunchTemplate": {"LaunchTemplateId": template, "Version": "1"},
            "HealthCheckGracePeriod": 0, "DefaultCooldown": 0, "DefaultInstanceWarmup": 0,
            "Tags": [{"Key": "suite", "Value": p, "PropagateAtLaunch": True},
                {"Key": "shared", "Value": "group", "PropagateAtLaunch": True},
                {"Key": "group-only", "Value": "not-on-instance", "PropagateAtLaunch": False}],
            "LifecycleHookSpecificationList": [{"LifecycleHookName": "launch", "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING", "HeartbeatTimeout": 120, "DefaultResult": "ABANDON"},
                {"LifecycleHookName": "terminate", "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING", "HeartbeatTimeout": 120, "DefaultResult": "CONTINUE"}]}
        if self.args.direct_force_only:
            base.update(MaxSize=1, DesiredCapacity=1, NewInstancesProtectedFromScaleIn=True,
                LifecycleHookSpecificationList=[{"LifecycleHookName": "terminate",
                    "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
                    "HeartbeatTimeout": 30, "DefaultResult": "CONTINUE"}])
        self.asg("create-main-one" if self.args.direct_force_only else "create-main-zero",
            "create_auto_scaling_group", base, required=True)
        group = self.group("main-initial")
        self.asg("delete-nonexistent-hook", "delete_lifecycle_hook",
            {"AutoScalingGroupName": self.data["group_name"], "LifecycleHookName": p + "-never-created"})
        self.asg("delete-nonexistent-schedule", "delete_scheduled_action",
            {"AutoScalingGroupName": self.data["group_name"], "ScheduledActionName": p + "-never-created"})
        self.events_setup(group["AutoScalingGroupARN"])
        if self.args.direct_force_only:
            group = self.wait_group("direct-force-inservice", lambda g: any(
                i["LifecycleState"] == "InService" and i["ProtectedFromScaleIn"] for i in g["Instances"]))
            instance = group["Instances"][0]["InstanceId"]
            self.asg("direct-force-delete-protected", "delete_auto_scaling_group",
                {"AutoScalingGroupName": self.data["group_name"], "ForceDelete": True}, required=True)
            self.wait_group("direct-force-deleted-group", lambda g: g is None, seconds=150)
            self.state(instance, "terminated", "direct-force-ec2-terminal", seconds=60)
            self.note("direct-force-control-complete", instance_id=instance)
            return
        version2 = copy.deepcopy(launch["TagSpecifications"])
        for spec in version2:
            next(tag for tag in spec["Tags"] if tag["Key"] == "template-version")["Value"] = "2"
        self.ec2("owned-launch-template-v2", "create_launch_template_version", {"LaunchTemplateId": template, "SourceVersion": "1",
            "LaunchTemplateData": {"TagSpecifications": version2}}, required=True)
        self.ec2("owned-default-v2", "modify_launch_template", {"LaunchTemplateId": template, "DefaultVersion": "2"}, required=True)
        if self.args.final_phase_only:
            self.final_phase(template)
            return
        clients = self.calibrate(template, base)
        for label, values in (("min-over-max", {"MinSize": 2, "MaxSize": 1}),
                ("desired-over-max", {"DesiredCapacity": 3}), ("negative-min", {"MinSize": -1}),
                ("missing-template-version", {"LaunchTemplate": {"LaunchTemplateId": template, "Version": "999999"}})):
            self.asg("invalid-create-" + label, "create_auto_scaling_group", dict(base, AutoScalingGroupName=p + "-invalid-" + label, **values))
        self.asg("invalid-desired-negative", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": -1})
        self.asg("invalid-desired-over-max", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 3})
        self.asg("invalid-update-min-over-max", "update_auto_scaling_group", {"AutoScalingGroupName": self.data["group_name"], "MinSize": 2, "MaxSize": 1})
        self.asg("denied-run-set-desired-one", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 1},
            client=clients["denied-run"]["autoscaling"], caller="denied-run", required=True)
        group = self.wait_group("numeric-launch-wait", lambda g: any(i["LifecycleState"] == "Pending:Wait" for i in g["Instances"]))
        first = next(i["InstanceId"] for i in group["Instances"] if i["LifecycleState"] == "Pending:Wait")
        action = self.action("numeric-launch", first, "launch", "CONTINUE")
        self.wait_group("numeric-inservice", lambda g: any(i["InstanceId"] == first and i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.asg("duplicate-complete-launch", "complete_lifecycle_action", dict(action, LifecycleActionResult="CONTINUE"))
        self.note("numeric-launch-complete", instance_id=first)
        self.asg("protect-first", "set_instance_protection", {"AutoScalingGroupName": self.data["group_name"], "InstanceIds": [first], "ProtectedFromScaleIn": True}, required=True)
        self.asg("nonforce-delete-populated", "delete_auto_scaling_group", {"AutoScalingGroupName": self.data["group_name"]})
        self.asg("protected-desired-zero", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 0}, required=True)
        time.sleep(20)
        self.snapshot("protected-scale-in")
        self.asg("restore-desired-one", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 1}, required=True)
        self.asg("mark-protected-unhealthy", "set_instance_health", {"InstanceId": first, "HealthStatus": "Unhealthy", "ShouldRespectGracePeriod": False}, required=True)
        self.wait_group("unhealthy-termination-hook", lambda g: any(i["InstanceId"] == first and i["LifecycleState"] == "Terminating:Wait" for i in g["Instances"]))
        self.action("health-termination", first, "terminate", "CONTINUE")
        group = self.wait_group("replacement-launch-hook", lambda g: any(i["InstanceId"] != first and i["LifecycleState"] == "Pending:Wait" for i in g["Instances"]))
        second = next(i["InstanceId"] for i in group["Instances"] if i["InstanceId"] != first and i["LifecycleState"] == "Pending:Wait")
        self.action("replacement-launch", second, "launch", "CONTINUE")
        self.wait_group("replacement-inservice", lambda g: any(i["InstanceId"] == second and i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.state(first, "terminated", "health-replaced-ec2-terminal", seconds=90)
        self.note("health-replacement-complete", old_instance=first, replacement_instance=second)
        self.asg("scale-zero-for-alias", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 0}, required=True)
        self.wait_group("ordinary-termination-hook", lambda g: any(i["InstanceId"] == second and i["LifecycleState"] == "Terminating:Wait" for i in g["Instances"]))
        self.action("ordinary-termination", second, "terminate", "ABANDON")
        self.wait_group("numeric-empty", lambda g: not g["Instances"])
        self.state(second, "terminated", "numeric-second-terminal", seconds=90)
        self.asg("update-latest-alias", "update_auto_scaling_group", {"AutoScalingGroupName": self.data["group_name"],
            "LaunchTemplate": {"LaunchTemplateId": template, "Version": "$Latest"}}, required=True)
        version3 = copy.deepcopy(version2)
        for spec in version3:
            next(tag for tag in spec["Tags"] if tag["Key"] == "template-version")["Value"] = "3"
        self.ec2("owned-launch-template-v3-after-admission", "create_launch_template_version", {"LaunchTemplateId": template,
            "SourceVersion": "2", "LaunchTemplateData": {"TagSpecifications": version3}}, required=True)
        self.asg("alias-desired-one", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 1}, required=True)
        group = self.wait_group("alias-launch-hook", lambda g: any(i["LifecycleState"] == "Pending:Wait" for i in g["Instances"]))
        third = next(i["InstanceId"] for i in group["Instances"] if i["LifecycleState"] == "Pending:Wait")
        self.asg("suspend-before-launch-abandon", "suspend_processes", {"AutoScalingGroupName": self.data["group_name"], "ScalingProcesses": ["Launch"]}, required=True)
        self.action("alias-launch-abandon", third, "launch", "ABANDON")
        self.asg("abandon-desired-zero", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 0}, required=True)
        self.wait_group("abandoned-termination-hook", lambda g: any(i["InstanceId"] == third and i["LifecycleState"] == "Terminating:Wait" for i in g["Instances"]))
        self.action("abandoned-termination", third, "terminate", "CONTINUE")
        self.wait_group("abandon-empty", lambda g: not g["Instances"])
        self.state(third, "terminated", "abandoned-ec2-terminal", seconds=90)
        self.note("alias-and-abandon-complete", instance_id=third)
        self.asg("resume-launch", "resume_processes", {"AutoScalingGroupName": self.data["group_name"], "ScalingProcesses": ["Launch"]}, required=True)
        self.final_phase(template)

    def final_phase(self, template):
        self.asg("default-alias-min-raises-desired", "update_auto_scaling_group", {"AutoScalingGroupName": self.data["group_name"],
            "MinSize": 1, "NewInstancesProtectedFromScaleIn": True,
            "LaunchTemplate": {"LaunchTemplateId": template, "Version": "$Default"}}, required=True)
        group = self.wait_group("default-launch-hook", lambda g: any(i["LifecycleState"] == "Pending:Wait" for i in g["Instances"]))
        fourth = next(i["InstanceId"] for i in group["Instances"] if i["LifecycleState"] == "Pending:Wait")
        self.action("default-launch", fourth, "launch", "CONTINUE")
        self.wait_group("default-inservice", lambda g: any(i["InstanceId"] == fourth and i["LifecycleState"] == "InService" for i in g["Instances"]))
        self.asg("invalid-desired-below-min", "set_desired_capacity", {"AutoScalingGroupName": self.data["group_name"], "DesiredCapacity": 0})
        self.asg("max-lowers-desired-protected", "update_auto_scaling_group",
            {"AutoScalingGroupName": self.data["group_name"], "MinSize": 0, "MaxSize": 0}, required=True)
        for sample in range(3):
            time.sleep(15)
            self.snapshot("protected-idle-" + str(sample))
        self.asg("force-delete-protected", "delete_auto_scaling_group", {"AutoScalingGroupName": self.data["group_name"], "ForceDelete": True}, required=True)
        self.wait_group("force-deleted-group", lambda g: g is None, seconds=240)
        self.state(fourth, "terminated", "force-deleted-ec2-terminal", seconds=90)
        self.note("lifecycle-capture-complete")

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        self.data.setdefault("cleanup_attempts", []).append({"started_at": now(), "prior": copy.deepcopy(self.data["cleanup"])})
        owned = self.data["owned"]
        # Recover names from successful recorder rows if interrupted between ledger writes.
        for row in self.data["calls"]:
            if row["code"] != "Success":
                continue
            if row["operation"] == "CreateAutoScalingGroup":
                self.own("asgs", row["input"]["AutoScalingGroupName"])
            if row["operation"] == "CreateLaunchTemplate":
                self.own("templates", row["output"]["LaunchTemplate"]["LaunchTemplateId"])
            if row["operation"] == "CreateQueue":
                owned["queue_url"] = row["output"]["QueueUrl"]
            if row["operation"] == "PutRule":
                owned["rule"] = row["input"]["Name"]
        if self.data.get("protected_instance") and not self.data.get("protected_instance_terminated"):
            self.ec2("cleanup-disable-owned-api-protection", "modify_instance_attribute",
                {"InstanceId": self.data["protected_instance"], "DisableApiTermination": {"Value": False}})
        for group in owned["asgs"]:
            self.asg("cleanup-force-delete-" + group, "delete_auto_scaling_group", {"AutoScalingGroupName": group, "ForceDelete": True})
        failures = []
        for attempt in range(37):
            response = self.asg("cleanup-group-absence-" + str(attempt), "describe_auto_scaling_groups", {"AutoScalingGroupNames": owned["asgs"]}) if owned["asgs"] else {"AutoScalingGroups": []}
            if not response.get("AutoScalingGroups") and (not owned["asgs"] or self.data["calls"][-1]["code"] == "Success"):
                break
            if attempt == 36:
                failures.append({"groups": "absence unverified"})
            time.sleep(5)
        self.drain_events("cleanup-final")
        for template in owned["templates"]:
            self.ec2("cleanup-delete-template", "delete_launch_template", {"LaunchTemplateId": template})
            self.ec2("cleanup-template-absence", "describe_launch_templates", {"LaunchTemplateIds": [template]})
            if self.data["calls"][-1]["code"] != "InvalidLaunchTemplateId.NotFound":
                failures.append({"template": template})
        if owned.get("rule"):
            self.observe("cleanup-rule-target", "events", "remove_targets", {"Rule": owned["rule"], "Ids": ["owned"]})
            self.observe("cleanup-rule-delete", "events", "delete_rule", {"Name": owned["rule"]})
            self.observe("cleanup-rule-absence", "events", "describe_rule", {"Name": owned["rule"]})
            if self.data["calls"][-1]["code"] != "ResourceNotFoundException":
                failures.append({"rule": owned["rule"]})
        if owned.get("queue_url"):
            self.observe("cleanup-queue-delete", "sqs", "delete_queue", {"QueueUrl": owned["queue_url"]})
            self.observe("cleanup-queue-absence", "sqs", "get_queue_attributes", {"QueueUrl": owned["queue_url"], "AttributeNames": ["QueueArn"]})
            if self.data["calls"][-1]["code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
                failures.append({"queue": owned["queue_url"]})
        if self.data.get("notification_role"):
            self.observe("cleanup-notification-policy", "iam", "delete_role_policy",
                {"RoleName": self.data["notification_role"], "PolicyName": "notify-lifecycle"})
        try:
            super().cleanup()
        finally:
            self.data["cleanup"]["failures"] = self.data["cleanup"].get("failures", []) + failures
            self.data["cleanup"]["complete"] = not self.data["cleanup"]["failures"]
            self.data["cleanup"]["asg_control_resources_absent"] = not failures
            self.data["cleanup"]["standing_service_linked_role_unchanged"] = True
            self.data["cleanup_attempts"][-1]["result"] = copy.deepcopy(self.data["cleanup"])
            self.save()
        if failures:
            raise RuntimeError("ASG control cleanup incomplete; resume --cleanup-only")

    def audit(self):
        services = {"autoscaling", "ec2", "iam", "events", "sqs", "sts"}
        excluded = [row for row in self.data["calls"] if row["service"] == "sqs" and
            row["operation"] in ("ReceiveMessage", "DeleteMessage", "GetQueueAttributes")]
        excluded_ids = {row.get("request_id") for row in excluded}
        requests = {row["request_id"]: row["label"] for row in self.data["calls"]
            if row["service"] in services and row.get("request_id") and row["request_id"] not in excluded_ids}
        markers = [self.data["prefix"]] + self.data["owned"]["instances"] + self.data["owned"]["templates"]
        for capture in self.data.get("additional_captures", []):
            markers += [capture["prefix"]] + capture["owned"]["instances"] + capture["owned"]["templates"]
        result = None
        try:
            result = collect_history(lambda params: self.clients["cloudtrail"].lookup_events(**params), requests,
                start_time=self.data["captured_at"], event_sources=tuple(name + ".amazonaws.com" for name in sorted(services)),
                max_pages=20, rounds=self.args.audit_rounds, wait_seconds=30,
                related=lambda event: any(marker in json.dumps(event) for marker in markers),
                previous=self.data.get("cloudtrail"))
        except CollectionError as error:
            result = error.result
            raise
        finally:
            if result is not None:
                self.data["cloudtrail"] = safe(result)
                self.data["cloudtrail"]["captured_at"] = now()
                self.data["cloudtrail"]["data_event_boundary"] = {
                    "documentation": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html",
                    "meaning": "SQS data events are not in LookupEvents history; no paid trail was created.",
                    "calls_outside_history_scope": [row["label"] for row in excluded]}
                self.data["cloudtrail"]["other_services_outside_selected_sources"] = [
                    row["label"] for row in self.data["calls"] if row["service"] not in services]
                self.data["cloudtrail"]["eventbridge_request_id_boundary"] = (
                    "EventBridge detail.RequestId is retained verbatim, not assumed to be an SDK or "
                    "CloudTrail request ID. Captured scaling-success events used ActivityId here.")
                self.save()
        print(json.dumps({"events": len(result["events"]), "missing_calls": len(result["missing_calls"]),
            "boundary": result["boundary"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/autoscaling/lifecycle_native.json"))
    parser.add_argument("--live-seconds", type=int, default=1000, choices=range(300, 1001), metavar="300..1000")
    parser.add_argument("--audit-rounds", type=int, default=1, choices=range(1, 7))
    parser.add_argument("--final-phase-only", action="store_true",
        help="Fresh owned capture of default-version/min-max/protected-force-delete recovery only")
    parser.add_argument("--direct-force-only", action="store_true",
        help="Fresh desired-one protected group, only30-second termination hook, then direct ForceDelete")
    parser.add_argument("--failure-boundaries-only", action="store_true",
        help="One private guest: missing notification destination, suspended membership and protected retirement")
    parser.add_argument("--metrics-only", action="store_true",
        help="Free zero-capacity metrics calibration using a borrowed existing subnet")
    parser.add_argument("--metrics-subnet", help="Explicit authorized read-only subnet; otherwise look for an AWS-default subnet")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--cleanup-only", action="store_true")
    modes.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    if sum((args.final_phase_only, args.direct_force_only, args.metrics_only, args.failure_boundaries_only)) > 1:
        parser.error("Select at most one capture variant")
    capture = LifecycleCapture(args)
    if args.audit_only:
        if not capture.data["cleanup"].get("complete"):
            raise RuntimeError("Complete paid-resource cleanup before audit collection")
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
