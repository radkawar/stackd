#!/usr/bin/env python3
"""Bounded exact-owned Lambda termination evidence; never alter a standing SLR.

Two isolated t3.nano at most, encrypted 8GiB roots, one Lambda, scoped execution
role/log group and one data-only CloudTrail. Failed observations remain in output.
--cleanup-only resumes owned cleanup; --audit-only collects management history.
"""
import argparse
import gzip
import io
import json
from pathlib import Path
import signal
import time
import uuid
import zipfile

from autoscaling_lifecycle_probe import LifecycleCapture
from cloudtrail_events import collect_history
from ec2_instances_probe import interrupt
from ebs_encryption_probe import CONFIG, allow, now, policy, safe

DOCS = [
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/lambda-custom-termination-policy.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-termination-policies.html",
    "https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-service-linked-role.html",
    "https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
]
HANDLER = '''import json, os, time
def handler(event, context):
    mode = os.environ.get("MODE", "empty")
    print("TERMINATION_INPUT " + json.dumps({"event": event, "request_id": context.aws_request_id, "mode": mode}), flush=True)
    if mode == "error": raise RuntimeError("owned termination rejection")
    if mode == "slow": time.sleep(2.5)
    ids = [] if mode in ("empty", "slow") else [i["InstanceId"] for i in reversed(event["Instances"])]
    if mode == "explicit": ids = os.environ["IDS"].split(",")
    result = {"InstanceIDs": ids}
    print("TERMINATION_OUTPUT " + json.dumps({"result": result, "request_id": context.aws_request_id}), flush=True)
    return result
'''


class TerminationCapture(LifecycleCapture):
    def __init__(self, args):
        super().__init__(args)
        for service in ("lambda", "logs", "s3"):
            self.clients[service] = self.session.client(service, config=CONFIG)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(prefix="stackd-asg-term-" + uuid.uuid4().hex[:12], documentation=DOCS,
                scope=__doc__, handler=HANDLER, invocation_logs=[], invocation_audit=[])
        self.save()

    def logs(self, label):
        if not self.data["owned"].get("log_group"):
            return
        parameters = {"logGroupName": self.data["owned"]["log_group"]}
        known = {row["eventId"] for row in self.data["invocation_logs"]}
        for page in range(100):
            result = self.observe(label + "-" + str(page), "logs", "filter_log_events", parameters)
            for row in result.get("events", []):
                if row["eventId"] not in known:
                    self.data["invocation_logs"].append(row)
                    known.add(row["eventId"])
            self.save()
            token = result.get("nextToken")
            if not token or token == parameters.get("nextToken"):
                return
            parameters["nextToken"] = token
        raise RuntimeError("Lambda log pagination bound exceeded")

    def mode(self, mode, ids=""):
        self.observe("mode-" + mode, "lambda", "update_function_configuration", {
            "FunctionName": self.data["owned"]["function"], "Environment": {"Variables": {"MODE": mode, "IDS": ids}}}, required=True)
        for attempt in range(20):
            result = self.observe("mode-ready-" + mode + "-" + str(attempt), "lambda", "get_function_configuration",
                {"FunctionName": self.data["owned"]["function"]}, required=True)
            if result.get("LastUpdateStatus") == "Successful":
                return
            time.sleep(2)
        raise TimeoutError("Lambda configuration update not ready")

    def trail(self, function):
        p = self.data["prefix"]
        self.data["owned"]["trail_bucket"] = p + "-audit"
        self.save()
        bucket = self.data["owned"]["trail_bucket"]
        self.observe("owned-trail-bucket", "s3", "create_bucket", {"Bucket": bucket}, required=True)
        trail_arn = "arn:aws:cloudtrail:" + self.args.region + ":" + self.args.account + ":trail/" + p
        self.observe("owned-trail-bucket-policy", "s3", "put_bucket_policy", {"Bucket": bucket, "Policy": json.dumps(policy([
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::" + bucket, "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + bucket + "/AWSLogs/" + self.args.account + "/*", "Condition": {"StringEquals": {"aws:SourceArn": trail_arn, "s3:x-amz-acl": "bucket-owner-full-control"}}}]))}, required=True)
        self.data["owned"]["trail"] = p
        self.save()
        self.observe("owned-data-trail", "cloudtrail", "create_trail", {"Name": p, "S3BucketName": bucket, "IsMultiRegionTrail": False, "IncludeGlobalServiceEvents": False}, required=True)
        self.observe("exact-function-selector", "cloudtrail", "put_event_selectors", {"TrailName": p, "AdvancedEventSelectors": [{"Name": "owned-function-only", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}, {"Field": "resources.ARN", "StartsWith": [function]}]}]}, required=True)
        self.observe("owned-trail-start", "cloudtrail", "start_logging", {"Name": p}, required=True)

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds + 30)
        self.setup()
        p, owned = self.data["prefix"], self.data["owned"]
        self.data["group_name"] = p
        role = p + "-lambda"
        role_arn = self.observe("owned-lambda-role", "iam", "create_role", {"RoleName": role,
            "AssumeRolePolicyDocument": json.dumps(policy([{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]))}, required=True)["Role"]["Arn"]
        owned["log_group"] = "/aws/lambda/" + p
        owned["function"] = p
        self.save()
        self.observe("owned-lambda-logs", "logs", "create_log_group", {"logGroupName": owned["log_group"]}, required=True)
        self.observe("owned-lambda-log-policy", "iam", "put_role_policy", {"RoleName": role, "PolicyName": "owned-log", "PolicyDocument": json.dumps(policy([allow(["logs:CreateLogStream", "logs:PutLogEvents"], "arn:aws:logs:" + self.args.region + ":" + self.args.account + ":log-group:" + owned["log_group"] + ":*")]))}, required=True)
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("index.py", HANDLER)
        time.sleep(15)
        function = self.observe("owned-lambda", "lambda", "create_function", {"FunctionName": p, "Runtime": "python3.12", "Handler": "index.handler", "Role": role_arn,
            "Timeout": 5, "MemorySize": 128, "Code": {"ZipFile": package.getvalue()}, "Environment": {"Variables": {"MODE": "empty"}}, "Tags": {"suite": p}}, required=True)["FunctionArn"]
        self.data["function_arn"] = function
        for attempt in range(30):
            result = self.observe("function-ready-" + str(attempt), "lambda", "get_function_configuration", {"FunctionName": p}, required=True)
            if result.get("State") == "Active": break
            time.sleep(2)
        self.trail(function)
        slr = "arn:aws:iam::" + self.args.account + ":role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        self.observe("standing-slr-read-only", "iam", "get_role", {"RoleName": "AWSServiceRoleForAutoScaling"}, required=True)
        self.observe("owned-function-permission", "lambda", "add_permission", {"FunctionName": p, "StatementId": "AutoScaling", "Action": "lambda:InvokeFunction", "Principal": slr}, required=True)
        self.observe("owned-function-policy", "lambda", "get_policy", {"FunctionName": p}, required=True)
        version = self.observe("owned-function-version", "lambda", "publish_version", {"FunctionName": p}, required=True)["Version"]
        self.observe("owned-function-alias", "lambda", "create_alias", {"FunctionName": p, "Name": "live", "FunctionVersion": version}, required=True)
        image = self.data["source_image"]
        template = self.ec2("owned-termination-template", "create_launch_template", {"LaunchTemplateName": p, "TagSpecifications": self.tags("launch-template"), "LaunchTemplateData": {
            "ImageId": image["ImageId"], "InstanceType": "t3.nano", "NetworkInterfaces": [{"DeviceIndex": 0, "Groups": [owned["group"]], "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
            "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"], "Ebs": {"Encrypted": True, "VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}]}}, required=True)["LaunchTemplate"]["LaunchTemplateId"]
        base = {"AutoScalingGroupName": p, "MinSize": 0, "MaxSize": 2, "DesiredCapacity": 0, "VPCZoneIdentifier": owned["subnet"], "LaunchTemplate": {"LaunchTemplateId": template, "Version": "1"}, "TerminationPolicies": [function, "OldestInstance"], "Tags": [{"Key": "suite", "Value": p, "PropagateAtLaunch": True}]}
        self.asg("termination-create-zero", "create_auto_scaling_group", base, required=True)
        for label, policies in (("latest", [function + ":$LATEST"]), ("second", ["OldestInstance", function]), ("two", [function, function + ":live"]), ("account", [function.replace(self.args.account, "123456789012")]), ("region", [function.replace(self.args.region, "us-west-2")]), ("name", [p]), ("missing", [function + "-absent"]), ("alias", [function + ":live"]), ("version", [function + ":" + version]), ("unqualified", [function, "OldestInstance"])):
            self.asg("termination-policy-" + label, "update_auto_scaling_group", {"AutoScalingGroupName": p, "TerminationPolicies": policies})
        for qualifier in ("live", version):
            self.observe("owned-qualified-permission-" + qualifier, "lambda", "add_permission", {"FunctionName": p, "Qualifier": qualifier, "StatementId": "AutoScaling", "Action": "lambda:InvokeFunction", "Principal": slr}, required=True)
            self.asg("termination-policy-authorized-" + qualifier, "update_auto_scaling_group", {"AutoScalingGroupName": p, "TerminationPolicies": [function + ":" + qualifier]}, required=True)
        self.asg("termination-policy-restore", "update_auto_scaling_group", {"AutoScalingGroupName": p, "TerminationPolicies": [function, "OldestInstance"]}, required=True)
        self.asg("termination-launch-one", "set_desired_capacity", {"AutoScalingGroupName": p, "DesiredCapacity": 1}, required=True)
        group = self.wait_group("termination-first-ready", lambda g: len(g["Instances"]) == 1 and g["Instances"][0]["LifecycleState"] == "InService")
        oldest = group["Instances"][0]["InstanceId"]
        self.asg("termination-launch-two", "set_desired_capacity", {"AutoScalingGroupName": p, "DesiredCapacity": 2}, required=True)
        group = self.wait_group("termination-second-ready", lambda g: len(g["Instances"]) == 2 and all(i["LifecycleState"] == "InService" for i in g["Instances"]))
        newest = next(i["InstanceId"] for i in group["Instances"] if i["InstanceId"] != oldest)
        self.data.update(oldest=oldest, newest=newest)
        self.save()
        self.asg("termination-hook", "put_lifecycle_hook", {"AutoScalingGroupName": p, "LifecycleHookName": "observe-termination", "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING", "HeartbeatTimeout": 60, "DefaultResult": "CONTINUE"}, required=True)
        self.asg("termination-scale-in", "set_desired_capacity", {"AutoScalingGroupName": p, "DesiredCapacity": 1}, required=True)
        for mode in ("empty", "error", "slow"):
            if mode != "empty": self.mode(mode)
            time.sleep(22)
            self.snapshot("termination-" + mode)
            self.logs("termination-" + mode + "-logs")
        self.asg("termination-cancel-scale-in", "set_desired_capacity", {"AutoScalingGroupName": p, "DesiredCapacity": 2}, required=True)
        self.mode("explicit", oldest)
        time.sleep(12)
        self.snapshot("termination-cancelled")
        self.asg("termination-protect-oldest", "set_instance_protection", {"AutoScalingGroupName": p, "InstanceIds": [oldest], "ProtectedFromScaleIn": True}, required=True)
        self.asg("termination-protected-scale-in", "set_desired_capacity", {"AutoScalingGroupName": p, "DesiredCapacity": 1}, required=True)
        time.sleep(22)
        self.snapshot("termination-protected-override")
        self.mode("explicit", "i-0123456789abcdef0")
        time.sleep(22)
        self.snapshot("termination-foreign-override")
        self.asg("termination-unprotect-oldest", "set_instance_protection", {"AutoScalingGroupName": p, "InstanceIds": [oldest], "ProtectedFromScaleIn": False}, required=True)
        self.mode("explicit", newest + "," + oldest)
        group = self.wait_group("termination-choice", lambda g: any(i["LifecycleState"] == "Terminating:Wait" for i in g["Instances"]))
        selected = next(i["InstanceId"] for i in group["Instances"] if i["LifecycleState"] == "Terminating:Wait")
        self.note("termination-selected", selected=selected, oldest=oldest, response_order=[newest, oldest])
        self.asg("termination-complete", "complete_lifecycle_action", {"AutoScalingGroupName": p, "LifecycleHookName": "observe-termination", "InstanceId": selected, "LifecycleActionResult": "CONTINUE"}, required=True)
        self.wait_group("termination-finished", lambda g: len(g["Instances"]) == 1)
        self.mode("empty")
        self.asg("termination-unhealthy", "set_instance_health", {"InstanceId": newest if selected == oldest else oldest, "HealthStatus": "Unhealthy", "ShouldRespectGracePeriod": False}, required=True)
        self.asg("termination-prevent-replacement", "suspend_processes", {"AutoScalingGroupName": p, "ScalingProcesses": ["Launch"]}, required=True)
        self.wait_group("termination-unhealthy-bypass", lambda g: any(i["LifecycleState"] == "Terminating:Wait" for i in g["Instances"]))
        self.logs("termination-final-logs")

    def collect_invokes(self):
        bucket = self.data["owned"].get("trail_bucket")
        if not bucket: return
        seen = {row["eventID"] for row in self.data["invocation_audit"]}
        for attempt in range(13):
            result = self.observe("trail-objects-" + str(attempt), "s3", "list_objects_v2", {"Bucket": bucket})
            for item in result.get("Contents", []):
                if not item["Key"].endswith(".json.gz"): continue
                response = self.clients["s3"].get_object(Bucket=bucket, Key=item["Key"])
                with response["Body"] as body:
                    records = json.loads(gzip.decompress(body.read()))["Records"]
                for event in records:
                    if event["eventID"] not in seen:
                        self.data["invocation_audit"].append(safe(event)); seen.add(event["eventID"])
            self.save()
            if any(row.get("eventName") == "Invoke" for row in self.data["invocation_audit"]): return
            if attempt != 12: time.sleep(20)
        self.data["gaps"].append("Lambda data trail delivery absent inside bounded240-second post-compute-cleanup observation")
        self.save()

    def cleanup(self):
        self.cleaning = True
        signal.alarm(0)
        role = self.data["prefix"] + "-lambda"
        if role in self.data["owned"]["roles"]:
            self.observe("cleanup-owned-lambda-log-policy", "iam", "delete_role_policy", {"RoleName": role, "PolicyName": "owned-log"})
        super().cleanup()
        failures = []
        owned = self.data["owned"]
        self.data["cleanup"]["complete"] = False
        self.save()
        self.logs("cleanup-lambda-logs")
        self.collect_invokes()
        for kind, service, delete, get, key in (("function", "lambda", "delete_function", "get_function_configuration", "FunctionName"), ("trail", "cloudtrail", "delete_trail", "get_trail", "Name")):
            if owned.get(kind):
                self.observe("cleanup-" + kind, service, delete, {key: owned[kind]})
                self.observe("cleanup-" + kind + "-absence", service, get, {key: owned[kind]})
                if self.data["calls"][-1]["code"] not in ("ResourceNotFoundException", "TrailNotFoundException"): failures.append(kind)
        if owned.get("log_group"):
            self.observe("cleanup-lambda-log-group", "logs", "delete_log_group", {"logGroupName": owned["log_group"]})
            response = self.observe("cleanup-lambda-log-absence", "logs", "describe_log_groups", {"logGroupNamePrefix": owned["log_group"]})
            if response.get("logGroups"): failures.append("log_group")
        bucket = owned.get("trail_bucket")
        if bucket:
            for attempt in range(4):
                result = self.observe("cleanup-trail-objects", "s3", "list_objects_v2", {"Bucket": bucket})
                for item in result.get("Contents", []):
                    self.observe("cleanup-trail-object", "s3", "delete_object", {"Bucket": bucket, "Key": item["Key"]})
                self.observe("cleanup-trail-bucket", "s3", "delete_bucket", {"Bucket": bucket})
                if self.data["calls"][-1]["code"] in ("Success", "NoSuchBucket"): break
                time.sleep(3)
            self.observe("cleanup-trail-bucket-absence", "s3", "head_bucket", {"Bucket": bucket})
            if self.data["calls"][-1]["code"] not in ("404", "NoSuchBucket"): failures.append("trail_bucket")
        self.data["cleanup"].update(complete=not failures, termination_failures=failures)
        self.save()
        if failures: raise RuntimeError("Termination resource cleanup incomplete: " + str(failures))

    def audit(self):
        requests = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("request_id") and row["service"] in ("autoscaling", "lambda", "iam", "ec2", "sts")}
        result = collect_history(lambda params: self.clients["cloudtrail"].lookup_events(**params), requests,
            start_time=self.data["captured_at"], event_sources=tuple(s + ".amazonaws.com" for s in ("autoscaling", "lambda", "iam", "ec2", "sts")), max_pages=20, rounds=self.args.audit_rounds, wait_seconds=30,
            related=lambda event: self.data["prefix"] in json.dumps(event), previous=self.data.get("cloudtrail"))
        self.data["cloudtrail"] = safe(result)
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/autoscaling/termination_native.json"))
    parser.add_argument("--live-seconds", type=int, default=800, choices=range(300, 901))
    parser.add_argument("--audit-rounds", type=int, default=2, choices=range(1, 7))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--cleanup-only", action="store_true")
    modes.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    capture = TerminationCapture(args)
    if args.audit_only:
        if not capture.data["cleanup"].get("complete"): raise RuntimeError("Finish cleanup before audit")
        capture.audit(); return
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM): signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only: capture.run()
    except Exception as error:
        capture.data.setdefault("failures", []).append({"type": type(error).__name__, "message": str(error), "at": now()})
        capture.save()
        raise
    finally:
        capture.cleanup()


if __name__ == "__main__":
    main()
