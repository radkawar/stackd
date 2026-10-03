#!/usr/bin/env python3
"""Signed SQLite/QEMU/ALB/OCI-Lambda custom termination scenario.

Uses the same guest image importer, process launcher, event tokens and cleanup as
autoscaling_guest_smoke.py. The customer handler runs only in Lambda's real OCI
runtime. It does not emulate a Lambda handler in the test driver.
"""
import argparse
import base64
import io
import json
from pathlib import Path
import time
import zipfile

from autoscaling_guest_smoke import Smoke as GuestSmoke
from ssm_managed_guest_smoke import safe

HANDLER = '''import json, os, time
def handler(event, context):
    mode = os.environ["MODE"]
    print("TERMINATION " + json.dumps({"event": event, "mode": mode, "request_id": context.aws_request_id}), flush=True)
    if mode == "error": raise RuntimeError("customer workload still busy")
    if mode == "slow": time.sleep(2.5)
    result = {"InstanceIDs": os.environ.get("IDS", "").split(",") if os.environ.get("IDS") else []}
    print("DECISION " + json.dumps(result), flush=True)
    return result
'''


class Smoke(GuestSmoke):
    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(self.data, indent=2,
            default=lambda value: base64.b64encode(value).decode() if isinstance(value, bytes) else safe(value)) + "\n")

    def mode(self, mode, ids=""):
        self.call("lambda-mode-" + mode, "lambda", "update_function_configuration", FunctionName=self.owned["function"],
                  Environment={"Variables": {"MODE": mode, "IDS": ids}})
        self.wait("Lambda update " + mode, lambda: self.client("lambda").get_function_configuration(FunctionName=self.owned["function"]),
                  lambda result: result.get("LastUpdateStatus") == "Successful" and result.get("State") == "Active", 120)

    def invocations(self):
        rows = []
        for page in self.client("logs").get_paginator("filter_log_events").paginate(logGroupName="/aws/lambda/" + self.owned["function"]):
            for event in page.get("events", []):
                message = event["message"]
                if "TERMINATION " in message:
                    rows.append(json.loads(message.split("TERMINATION ", 1)[1]))
        self.data["observations"]["lambda_invocations"] = rows
        self.save()
        return rows

    def held(self, mode, ids=""):
        self.mode(mode, ids)
        self.wait("actual Lambda retries " + mode, self.invocations,
                  lambda rows: sum(row["mode"] == mode for row in rows) >= 2, 100, 1)
        group = self.group()
        assert len(group["Instances"]) == 2 and all(i["LifecycleState"] == "InService" for i in group["Instances"]), group
        self.data["observations"][mode + "_held"] = group
        self.save()

    def after_load_balancer(self, lb):
        self.prepare_targets(lb, drain_seconds=10)
        self.prepare_events()
        o = self.owned
        role_name = self.prefix + "-lambda"
        o["lambda_role"] = role_name
        role = self.call("lambda-execution-role", "iam", "create_role", RoleName=role_name,
                         AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}]}))["Role"]["Arn"]
        o["function"] = self.prefix
        log_group = "/aws/lambda/" + o["function"]
        self.call("lambda-log-group", "logs", "create_log_group", logGroupName=log_group)
        self.call("lambda-log-authority", "iam", "put_role_policy", RoleName=role_name, PolicyName="logs",
                  PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                  "Resource": "arn:aws:logs:us-east-1:" + self.account + ":log-group:" + log_group + ":*"}]}))
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("index.py", HANDLER)
        function = self.call("actual-oci-lambda", "lambda", "create_function", FunctionName=o["function"], Runtime="python3.12", Handler="index.handler", Role=role,
                             Timeout=5, MemorySize=128, Code={"ZipFile": archive.getvalue()}, Environment={"Variables": {"MODE": "empty", "IDS": ""}})["FunctionArn"]
        self.wait("real Lambda OCI deployment", lambda: self.client("lambda").get_function_configuration(FunctionName=o["function"]), lambda r: r.get("State") == "Active", 180)
        script = '''#!/bin/bash
set -eu
mkdir -p /opt/asg-http
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
instance=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/instance-id)
printf '{"instance":"%s"}\\n' "$instance" >/opt/asg-http/index.html
cd /opt/asg-http
exec python3 -u -m http.server 8080 --bind 0.0.0.0
'''
        template = {"ImageId": o["image"], "InstanceType": "t3.nano", "MetadataOptions": {"HttpTokens": "required"},
                    "NetworkInterfaces": [{"DeviceIndex": 0, "Groups": [o["sg"]], "DeleteOnTermination": True, "AssociatePublicIpAddress": False}],
                    "UserData": base64.b64encode(script.encode()).decode()}
        o["template"] = self.call("termination-guest-template", "ec2", "create_launch_template", LaunchTemplateName=self.prefix, LaunchTemplateData=template)["LaunchTemplate"]["LaunchTemplateId"]
        self.call("autoscaling-linked-role", "iam", "create_service_linked_role", AWSServiceName="autoscaling.amazonaws.com")
        slr = "arn:aws:iam::" + self.account + ":role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        self.call("current-function-authority", "lambda", "add_permission", FunctionName=o["function"], StatementId="AutoScaling", Action="lambda:InvokeFunction", Principal=slr)
        self.asg("create-group-zero", "create_auto_scaling_group", AutoScalingGroupName=self.prefix, MinSize=0, MaxSize=2, DesiredCapacity=0,
                 LaunchTemplate={"LaunchTemplateId": o["template"], "Version": "1"}, VPCZoneIdentifier=o["subnet"], TargetGroupARNs=[o["tg"]], HealthCheckType="EC2",
                 TerminationPolicies=[function, "OldestInstance"], LifecycleHookSpecificationList=[{"LifecycleHookName": "terminate", "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING", "HeartbeatTimeout": 600, "DefaultResult": "CONTINUE"}])
        o["group"] = self.prefix
        self.asg("first-native-guest", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=1)
        first_group = self.wait("first in-service guest", self.group, lambda g: len(g["Instances"]) == 1 and g["Instances"][0]["LifecycleState"] == "InService", 300)
        first = first_group["Instances"][0]["InstanceId"]
        self.wait("first native ALB packet", lambda: self.http(o["dns"]), lambda packet: packet and packet["instance"] == first, 180)
        self.asg("second-native-guest", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=2)
        group = self.wait("two in-service guests", self.group, lambda g: len(g["Instances"]) == 2 and all(i["LifecycleState"] == "InService" for i in g["Instances"]), 300)
        second = next(i["InstanceId"] for i in group["Instances"] if i["InstanceId"] != first)
        self.asg("lambda-scale-in", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=1)
        self.held("empty")
        self.held("error")
        self.held("slow", first)
        self.asg("protect-lambda-override", "set_instance_protection", AutoScalingGroupName=self.prefix, InstanceIds=[first], ProtectedFromScaleIn=True)
        self.held("protected", first)
        self.held("foreign", "i-0123456789abcdef0")
        self.asg("cancel-scale-in", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=2)
        self.mode("cancelled", second)
        time.sleep(7)
        assert all(i["LifecycleState"] == "InService" for i in self.group()["Instances"])
        self.call("revoke-current-function-authority", "lambda", "remove_permission", FunctionName=o["function"], StatementId="AutoScaling")
        self.asg("scale-in-without-authority", "set_desired_capacity", AutoScalingGroupName=self.prefix, DesiredCapacity=1)
        self.stop()
        self.start()
        time.sleep(7)
        denied = self.group()
        assert len(denied["Instances"]) == 2 and all(i["LifecycleState"] == "InService" for i in denied["Instances"]), denied
        self.data["observations"]["reopened_current_authority_denial"] = denied
        self.asg("unprotect-before-choice", "set_instance_protection", AutoScalingGroupName=self.prefix, InstanceIds=[first], ProtectedFromScaleIn=False)
        self.mode("choice", second + "," + first)
        self.call("restore-current-function-authority", "lambda", "add_permission", FunctionName=o["function"], StatementId="AutoScaling", Action="lambda:InvokeFunction", Principal=slr)
        action = self.action("autoscaling:EC2_INSTANCE_TERMINATING")
        assert action["EC2InstanceId"] == first, action
        self.data["observations"]["oldest_policy_not_lambda_order"] = action
        self.complete(action)
        self.wait("real selected guest retirement", lambda: self.instance(first), lambda i: i["State"]["Name"] == "terminated", 180)
        packet = self.wait("ALB survives selected retirement", lambda: self.http(o["dns"]), lambda packet: packet and packet["instance"] == second, 180)
        self.data["observations"]["surviving_guest_packet"] = packet
        self.mode("health-empty")
        self.asg("suspend-replacement", "suspend_processes", AutoScalingGroupName=self.prefix, ScalingProcesses=["Launch"])
        self.asg("unhealthy-bypasses-lambda", "set_instance_health", InstanceId=second, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False)
        unhealthy = self.action("autoscaling:EC2_INSTANCE_TERMINATING", second)
        self.data["observations"]["unhealthy_bypass"] = unhealthy
        self.complete(unhealthy)
        self.wait("unhealthy real retirement", lambda: self.instance(second), lambda i: i["State"]["Name"] == "terminated", 180)
        self.invocations()
        self.save()

    def cleanup(self):
        super().cleanup()
        o = self.owned
        if "function" in o:
            self.call("cleanup-lambda", "lambda", "delete_function", FunctionName=o["function"])
            self.expect("cleanup-lambda-absence", "ResourceNotFoundException", "lambda", "get_function", FunctionName=o["function"])
            self.call("cleanup-lambda-logs", "logs", "delete_log_group", logGroupName="/aws/lambda/" + o["function"])
        if "lambda_role" in o:
            self.call("cleanup-lambda-role-policy", "iam", "delete_role_policy", RoleName=o["lambda_role"], PolicyName="logs")
            self.call("cleanup-lambda-role", "iam", "delete_role", RoleName=o["lambda_role"])
        self.data["cleanup"]["lambda_deleted"] = True
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
    parser.add_argument("--output", type=Path, default=Path("testdata/integration/autoscaling_termination.json"))
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
        except BaseException as error:
            smoke.data["cleanup"]["failure"] = {"type": type(error).__name__, "message": str(error)}
            smoke.save()
            raise
        finally:
            smoke.stop()
    print(json.dumps({"observations": smoke.data["observations"], "cleanup": smoke.data["cleanup"]}, default=str))
