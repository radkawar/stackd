#!/usr/bin/env python3
"""Signed Auto Scaling, retained firmware guests, lifecycle events and ALB packets."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import urllib.error

from botocore.exceptions import ClientError

from ec2_launch_template_smoke import Smoke as TemplateSmoke, REGION
from dns_http_client import opener as dns_opener


class Smoke(TemplateSmoke):
    def __init__(self, args):
        super().__init__(args)
        self.dns_endpoint = f"127.0.0.1:{args.port + 1}"
        self.opener = dns_opener(self.dns_endpoint)
        self.data["source"] = "local signed APIs, real firmware QEMU guests, retained SQLite and ALB sockets"
        self.actions = []
        self.owned["instances"] = []
        self.target_binary = args.binary
        if args.upgrade_from_binary:
            args.binary = args.upgrade_from_binary.resolve()

    def start(self):
        self.controller_args = ["-elbv2-node-executable", str(self.args.elbv2_node_executable.resolve())]
        if self.args.binary == self.target_binary:
            self.controller_args.extend(["-dns-listen", self.dns_endpoint])
        super().start()
        if self.args.binary == self.target_binary and "lb" in self.owned:
            retained = self.call("retained-load-balancer-endpoint", "elbv2", "describe_load_balancers",
                                 LoadBalancerArns=[self.owned["lb"]])["LoadBalancers"][0]
            self.owned["dns"] = retained["DNSName"]
            self.save()

    def asg(self, label, method, **kwargs):
        return self.call(label, "autoscaling", method, **kwargs)

    def group(self):
        rows = self.client("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[self.prefix])["AutoScalingGroups"]
        if rows:
            for member in rows[0].get("Instances", []):
                if member["InstanceId"] not in self.owned["instances"]:
                    self.owned["instances"].append(member["InstanceId"])
                    self.instance(member["InstanceId"])
            return rows[0]
        return None

    def action(self, transition, instance=None):
        def receive():
            rows = self.client("sqs").receive_message(QueueUrl=self.owned["queue"], MaxNumberOfMessages=10, WaitTimeSeconds=1).get("Messages", [])
            for row in rows:
                event = json.loads(row["Body"])
                self.data.setdefault("events", []).append(event)
                detail = event.get("detail", {})
                if detail.get("LifecycleActionToken"):
                    self.actions.append(detail)
                self.client("sqs").delete_message(QueueUrl=self.owned["queue"], ReceiptHandle=row["ReceiptHandle"])
            self.save()
            return next((a for a in self.actions if a.get("LifecycleTransition") == transition and (instance is None or a.get("EC2InstanceId") == instance)), None)
        # The race-enabled SQLite run materialized the replacement root volume
        # beyond 180 seconds. Keep observing the real transition, not acceptance.
        return self.wait("lifecycle event " + transition, receive, bool, 300)

    def complete(self, action, result="CONTINUE"):
        self.asg("complete-" + action["EC2InstanceId"] + "-" + result, "complete_lifecycle_action", AutoScalingGroupName=self.prefix,
                 LifecycleHookName=action["LifecycleHookName"], LifecycleActionToken=action["LifecycleActionToken"], LifecycleActionResult=result)
        self.actions.remove(action)

    def http(self, host):
        try:
            with self.opener.open("http://" + host, timeout=5) as response:
                return json.load(response)
        except (OSError, ValueError):
            return None

    def instance(self, instance):
        record = self.client("ec2").describe_instances(InstanceIds=[instance])["Reservations"][0]["Instances"][0]
        for mapping in record.get("BlockDeviceMappings", []):
            volume = mapping.get("Ebs", {}).get("VolumeId")
            if volume and volume not in self.owned.setdefault("volumes", []):
                self.owned["volumes"].append(volume)
                self.save()
        return record

    def run(self):
        self.prepare()
        self.import_image()
        o = self.owned
        o["vpc"] = self.call("vpc", "ec2", "create_vpc", CidrBlock="10.194.20.0/24")["Vpc"]["VpcId"]
        o["subnet"] = self.call("subnet-a", "ec2", "create_subnet", VpcId=o["vpc"], CidrBlock="10.194.20.0/25", AvailabilityZone=REGION + "a")["Subnet"]["SubnetId"]
        o["subnet_b"] = self.call("subnet-b", "ec2", "create_subnet", VpcId=o["vpc"], CidrBlock="10.194.20.128/25", AvailabilityZone=REGION + "b")["Subnet"]["SubnetId"]
        o["sg"] = self.call("sg", "ec2", "create_security_group", VpcId=o["vpc"], GroupName=self.prefix, Description=self.prefix)["GroupId"]
        self.call("http-ingress", "ec2", "authorize_security_group_ingress", GroupId=o["sg"], IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 8080, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        lb = self.call("actual-alb", "elbv2", "create_load_balancer", Name=self.prefix[:32], Scheme="internal", Type="application", Subnets=[o["subnet"], o["subnet_b"]], SecurityGroups=[o["sg"]])["LoadBalancers"][0]
        self.after_load_balancer(lb)

    def prepare_targets(self, lb, drain_seconds=1):
        o = self.owned
        o["lb"] = lb["LoadBalancerArn"]
        self.save()
        ready = self.wait("native ALB address ready", lambda: self.client("elbv2").describe_load_balancers(LoadBalancerArns=[o["lb"]])["LoadBalancers"][0],
                          lambda row: row["State"]["Code"] == "active" and row.get("DNSName"), 180)
        o["dns"] = ready["DNSName"]
        o["tg"] = self.call("actual-instance-targets", "elbv2", "create_target_group", Name=self.prefix[:32], Protocol="HTTP", Port=8080,
                            VpcId=o["vpc"], TargetType="instance", HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2,
                            HealthyThresholdCount=2, UnhealthyThresholdCount=2)["TargetGroups"][0]["TargetGroupArn"]
        self.call("short-drain", "elbv2", "modify_target_group_attributes", TargetGroupArn=o["tg"],
                  Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(drain_seconds)}])
        o["listener"] = self.call("forward-to-guests", "elbv2", "create_listener", LoadBalancerArn=o["lb"], Protocol="HTTP", Port=80,
                                  DefaultActions=[{"Type": "forward", "TargetGroupArn": o["tg"]}])["Listeners"][0]["ListenerArn"]

    def prepare_events(self):
        o = self.owned
        o["queue"] = self.call("events-queue", "sqs", "create_queue", QueueName=self.prefix)["QueueUrl"]
        queue_arn = self.call("queue-arn", "sqs", "get_queue_attributes", QueueUrl=o["queue"], AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        self.call("events-permission", "sqs", "set_queue_attributes", QueueUrl=o["queue"], Attributes={"Policy": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                                                 "Action": "sqs:SendMessage", "Resource": queue_arn}]})})
        self.call("asg-events-rule", "events", "put_rule", Name=self.prefix,
                  EventPattern=json.dumps({"source": ["aws.autoscaling"], "detail": {"AutoScalingGroupName": [self.prefix]}}))
        o["rule"] = self.prefix
        targets = self.call("asg-events-target", "events", "put_targets", Rule=self.prefix, Targets=[{"Id": "queue", "Arn": queue_arn}])
        assert targets["FailedEntryCount"] == 0, targets

    def after_load_balancer(self, lb):
        o = self.owned
        if not self.args.upgrade_from_binary:
            assert lb.get("DNSName"), lb
        self.prepare_targets(lb)
        if lb.get("DNSName"):
            assert o["dns"] == lb["DNSName"], (lb, o["dns"])
        if self.args.upgrade_from_binary:
            def empty_target_status():
                try:
                    with self.opener.open("http://" + o["dns"], timeout=5) as response:
                        return response.status
                except urllib.error.HTTPError as error:
                    return error.code
                except OSError:
                    return None
            self.wait("baseline native ALB socket", empty_target_status, lambda code: code == 503, 180)
            self.stop()
            self.args.binary = self.target_binary
            self.start()
            self.wait("upgraded retained ALB socket", empty_target_status, lambda code: code == 503, 180)
            self.data["observations"]["schema_upgrade"] = {"from_binary": str(self.args.upgrade_from_binary), "to_binary": str(self.target_binary), "retained_alb": o["lb"], "retained_image": o["image"], "native_http_before_after": 503}
        self.prepare_events()
        script = '''#!/bin/bash
set -eu
exec > >(tee /dev/console) 2>&1
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
group=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/tags/instance/aws:autoscaling:groupName)
instance=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/instance-id)
override=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/tags/instance/override)
boot=$(cat /proc/sys/kernel/random/boot_id)
mkdir -p /opt/asg-http
printf '{"group":"%s","instance":"%s","override":"%s","boot":"%s"}\\n' "$group" "$instance" "$override" "$boot" >/opt/asg-http/index.html
echo STACKD_ASG_INITIAL_IMDS_OK
cd /opt/asg-http
exec python3 -u -m http.server 8080 --bind 0.0.0.0
'''
        data = {"ImageId": o["image"], "InstanceType": "t3.nano", "MetadataOptions": {"HttpTokens": "required", "InstanceMetadataTags": "enabled"},
                "NetworkInterfaces": [{"DeviceIndex": 0, "Groups": [o["sg"]], "DeleteOnTermination": True, "AssociatePublicIpAddress": False}],
                "UserData": base64.b64encode(script.encode()).decode(), "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "override", "Value": "template"}]}]}
        o["template"] = self.call("guest-template", "ec2", "create_launch_template", LaunchTemplateName=self.prefix, LaunchTemplateData=data)["LaunchTemplate"]["LaunchTemplateId"]
        hooks = [{"LifecycleHookName": "launch", "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING", "HeartbeatTimeout": 600, "DefaultResult": "ABANDON"},
                 {"LifecycleHookName": "terminate", "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING", "HeartbeatTimeout": 600, "DefaultResult": "CONTINUE"}]
        self.asg("create-actual-group", "create_auto_scaling_group", AutoScalingGroupName=self.prefix, LaunchTemplate={"LaunchTemplateId": o["template"], "Version": "1"}, MinSize=0, MaxSize=2, DesiredCapacity=1,
                 VPCZoneIdentifier=o["subnet"], TargetGroupARNs=[o["tg"]], HealthCheckType="ELB", HealthCheckGracePeriod=60, DefaultInstanceWarmup=0, NewInstancesProtectedFromScaleIn=True,
                 LifecycleHookSpecificationList=hooks, Tags=[{"Key": "override", "Value": "group", "PropagateAtLaunch": True}])
        o["group"] = self.prefix
        self.asg("enable-real-gauges", "enable_metrics_collection", AutoScalingGroupName=self.prefix, Granularity="1Minute")
        launch = self.action("autoscaling:EC2_INSTANCE_LAUNCHING")
        first = launch["EC2InstanceId"]
        pending = self.group()
        assert pending["Instances"][0]["LifecycleState"] == "Pending:Wait", pending
        assert pending["Instances"][0]["ProtectedFromScaleIn"] is False, pending
        self.asg("heartbeat-before-restart", "record_lifecycle_action_heartbeat", AutoScalingGroupName=self.prefix, LifecycleHookName="launch", LifecycleActionToken=launch["LifecycleActionToken"])
        direct = self.instance(first)["PrivateIpAddress"] + ":8080"
        before = self.wait("guest initial system tags and HTTP", lambda: self.http(direct), bool, 300, 2)
        assert before["group"] == self.prefix and before["override"] == "group" and before["instance"] == first, before
        self.stop()
        self.start()
        retained = self.group()
        assert retained["Instances"][0]["InstanceId"] == first and retained["Instances"][0]["LifecycleState"] == "Pending:Wait", retained
        after = self.wait("retained native boot", lambda: self.http(direct), bool, 120)
        assert before == after, (before, after)
        self.complete(launch)
        active = self.wait("protected in-service member", self.group, lambda g: g and any(i["InstanceId"] == first and i["LifecycleState"] == "InService" and i["ProtectedFromScaleIn"] for i in g["Instances"]), 120)
        packet = self.wait("real ASG to ALB packet", lambda: self.http(o["dns"]), lambda r: r and r["instance"] == first, 180)
        self.data["observations"].update(initial_imds=before, retained_boot=after, alb_packet=packet, in_service=active)
        self.asg("protected-scale-in", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=0)
        cancelled = self.wait("protected cancellation", lambda: self.client("autoscaling").describe_scaling_activities(AutoScalingGroupName=self.prefix)["Activities"], lambda rows: any(a["StatusCode"] == "Cancelled" for a in rows), 60)
        self.data["observations"]["protected_scale_in"] = cancelled
        policy = self.asg("actual-simple-policy", "put_scaling_policy", AutoScalingGroupName=self.prefix, PolicyName="restore", PolicyType="SimpleScaling", AdjustmentType="ExactCapacity", ScalingAdjustment=1, Cooldown=0)
        o["alarm"] = self.prefix + "-restore"
        self.call("real-scaling-alarm", "cloudwatch", "put_metric_alarm", AlarmName=o["alarm"], Namespace="Stackd/ASGSmoke", MetricName="Restore", Period=10, EvaluationPeriods=1, Threshold=0.5, ComparisonOperator="GreaterThanThreshold", Statistic="Average", TreatMissingData="notBreaching", AlarmActions=[policy["PolicyARN"]])
        self.call("trigger-scaling-alarm", "cloudwatch", "put_metric_data", Namespace="Stackd/ASGSmoke", MetricData=[{"MetricName": "Restore", "Value": 1, "StorageResolution": 1}])
        restored = self.wait("CloudWatch action restores desired capacity", self.group, lambda g: g["DesiredCapacity"] == 1, 60)
        self.data["observations"]["cloudwatch_policy_capacity"] = restored
        self.call("disable-observed-alarm", "cloudwatch", "disable_alarm_actions", AlarmNames=[o["alarm"]])
        self.asg("schedule-scale-in", "put_scheduled_update_group_action", AutoScalingGroupName=self.prefix, ScheduledActionName="scheduled-zero", StartTime=datetime.now(timezone.utc) + timedelta(seconds=5), DesiredCapacity=0)
        self.wait("scheduled desired capacity", self.group, lambda g: g["DesiredCapacity"] == 0, 30)
        self.asg("restore-before-health-replacement", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=1)
        self.asg("actual-health-replacement", "set_instance_health", InstanceId=first, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False)
        termination = self.action("autoscaling:EC2_INSTANCE_TERMINATING", first)
        replacement = self.action("autoscaling:EC2_INSTANCE_LAUNCHING")
        second = replacement["EC2InstanceId"]
        assert second != first
        overlap = self.group()
        assert {i["InstanceId"] for i in overlap["Instances"]} == {first, second}, overlap
        self.data["observations"]["replacement_during_termination_hook"] = overlap
        self.complete(termination)
        self.wait("first native guest terminated", lambda: self.instance(first), lambda i: i["State"]["Name"] == "terminated", 180)
        direct_second = self.instance(second)["PrivateIpAddress"] + ":8080"
        second_packet = self.wait("replacement actual firmware HTTP", lambda: self.http(direct_second), bool, 300, 2)
        self.complete(replacement)
        self.wait("replacement packet", lambda: self.http(o["dns"]), lambda r: r and r["instance"] == second, 180)
        self.data["observations"]["replacement_guest"] = second_packet
        now = datetime.now(timezone.utc)
        metric = self.call("observed-group-gauge", "cloudwatch", "get_metric_statistics", Namespace="AWS/AutoScaling", MetricName="GroupDesiredCapacity", Dimensions=[{"Name": "AutoScalingGroupName", "Value": self.prefix}], StartTime=now-timedelta(minutes=15), EndTime=now+timedelta(minutes=1), Period=60, Statistics=["Average"])
        assert any(p["Average"] == 1 and p["Unit"] == "None" for p in metric["Datapoints"]), metric
        self.asg("detach-running-nondefault-subnet-member", "detach_instances", AutoScalingGroupName=self.prefix, InstanceIds=[second], ShouldDecrementDesiredCapacity=True)
        self.wait("detached membership", self.group, lambda g: not g["Instances"], 120)
        detached = self.instance(second)
        assert detached["State"]["Name"] == "running" and "aws:autoscaling:groupName" not in {t["Key"] for t in detached["Tags"]}, detached
        self.asg("reattach-explicit-subnet-member", "attach_instances", AutoScalingGroupName=self.prefix, InstanceIds=[second])
        self.wait("reattached service", self.group, lambda g: any(i["InstanceId"] == second and i["LifecycleState"] == "InService" for i in g["Instances"]), 120)
        reattached = self.wait("reattached ALB packet", lambda: self.http(o["dns"]), lambda r: r and r["instance"] == second, 180)
        assert reattached["boot"] == second_packet["boot"], reattached
        self.data["observations"]["detach_attach_retained_guest"] = reattached
        self.asg("force-delete-populated-group", "delete_auto_scaling_group", AutoScalingGroupName=self.prefix, ForceDelete=True)
        final_action = self.action("autoscaling:EC2_INSTANCE_TERMINATING", second)
        deleting = self.group()
        assert deleting["Status"] == "Delete in progress" and deleting["Instances"][0]["LifecycleState"] == "Terminating:Wait", deleting
        self.data["observations"]["force_delete_waits_hook"] = deleting
        self.complete(final_action)
        self.wait("group exact absence", self.group, lambda g: g is None, 240)
        self.wait("replacement native termination", lambda: self.instance(second), lambda i: i["State"]["Name"] == "terminated", 180)
        self.save()

    def cleanup(self):
        o = self.owned
        if "group" in o:
            group = self.group()
            if group:
                self.asg("cleanup-force-group", "delete_auto_scaling_group", AutoScalingGroupName=self.prefix, ForceDelete=True)
                try:
                    hooks = self.asg("cleanup-hook-inventory", "describe_lifecycle_hooks", AutoScalingGroupName=self.prefix)["LifecycleHooks"]
                    for hook in hooks:
                        name = hook["LifecycleHookName"]
                        self.asg("cleanup-delete-hook-" + name, "delete_lifecycle_hook", AutoScalingGroupName=self.prefix, LifecycleHookName=name)
                except ClientError as error:
                    if error.response["Error"]["Code"] != "ValidationError" or self.group() is not None:
                        raise
                    # Asynchronous deletion already removed the group and its hooks.
                self.wait("cleanup group absence", self.group, lambda g: g is None, 240)
        for instance in o["instances"]:
            self.wait("cleanup instance " + instance, lambda: self.instance(instance), lambda i: i["State"]["Name"] == "terminated", 180)
        for volume in o.get("volumes", []):
            self.expect("cleanup-root-volume-absence", "InvalidVolume.NotFound", "ec2", "describe_volumes", VolumeIds=[volume])
        if "alarm" in o: self.call("cleanup-alarm", "cloudwatch", "delete_alarms", AlarmNames=[o["alarm"]])
        if "listener" in o: self.call("cleanup-listener", "elbv2", "delete_listener", ListenerArn=o["listener"])
        if "lb" in o: self.call("cleanup-alb", "elbv2", "delete_load_balancer", LoadBalancerArn=o["lb"])
        if "tg" in o: self.call("cleanup-targets", "elbv2", "delete_target_group", TargetGroupArn=o["tg"])
        if "rule" in o:
            self.call("cleanup-event-target", "events", "remove_targets", Rule=o["rule"], Ids=["queue"])
            self.call("cleanup-event-rule", "events", "delete_rule", Name=o["rule"])
        if "queue" in o: self.call("cleanup-event-queue", "sqs", "delete_queue", QueueUrl=o["queue"])
        if "vpc" in o:
            self.wait("actual ENI retirement", lambda: self.client("ec2").describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [o["vpc"]]}])["NetworkInterfaces"], lambda rows: not rows, 180)
        if "subnet_b" in o: self.call("cleanup-subnet-b", "ec2", "delete_subnet", SubnetId=o["subnet_b"])
        super().cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--upgrade-from-binary", type=Path)
    parser.add_argument("--elbv2-node-executable", type=Path, default=Path("bin/stackd-elbv2-node-integration"))
    parser.add_argument("--raw-image", type=Path, default=Path("/tmp/stackd-ubuntu-24.04-server.raw"))
    parser.add_argument("--bios", type=Path, default=Path("/usr/share/seabios/bios-256k.bin"))
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--port", type=int, default=15951)
    parser.add_argument("--gateway", default="10.194.20.1")
    parser.add_argument("--output", type=Path, default=Path("testdata/integration/autoscaling_guest.json"))
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
