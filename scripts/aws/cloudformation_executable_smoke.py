#!/usr/bin/env python3
"""Local-only signed CloudFormation deploy proof; requires a built CLI and real Lambda Docker runtime.

Run with --binary bin/stackd --state-directory /absolute/fresh/owned-directory.
Requires boto3, AWS CLI, Docker, the pinned python3.13 x86_64 image and the
Lambda telemetry helpers built alongside stackd. Never uses host AWS credentials.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from scheduler_pipes_executable_smoke import require
from stackd_process import StackdProcess


HANDLER = '''import json, os, platform
from urllib.parse import urlsplit
import boto3
from botocore.config import Config

def handler(event, context):
    detail = event.get("detail", event)
    body = boto3.client("s3", config=Config(s3={"addressing_style": "path"})).get_object(
        Bucket=os.environ["BUCKET"], Key=detail["key"])["Body"].read().decode()
    sqs = boto3.client("sqs")
    queue = sqs.get_queue_url(QueueName=os.environ["QUEUE_NAME"])["QueueUrl"]
    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    if endpoint:
        queue = endpoint.rstrip("/") + urlsplit(queue).path
    result = {"marker": detail["marker"], "body": body, "stage": os.environ["STAGE"],
        "invocation": context.aws_request_id, "runtime": platform.python_version(),
        "function": context.invoked_function_arn}
    sqs.send_message(QueueUrl=queue, MessageBody=json.dumps(result, sort_keys=True))
    print(json.dumps(result, sort_keys=True), flush=True)
    return result
'''


class Application:
    def __init__(self, args):
        self.args = args
        fixture = json.loads((Path(__file__).resolve().parents[2] / "testdata/aws/cloudformation/lifecycle.json").read_text())
        require(fixture.get("workflow_complete") and fixture.get("export_update_complete") and fixture["cleanup"]["complete"],
            "requires completed native lifecycle/export-constraint fixture with verified cleanup")
        self.native = {row["label"]: row for row in fixture["calls"]}
        self.native_constraints = fixture["constraint_observations"]
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        require(not any(self.state.iterdir()), "requires an empty owned state directory")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.prefix = "cfn-" + uuid.uuid4().hex[:12]
        self.controller = StackdProcess(self.state)
        self.stacks = []
        self.functions = set()
        self.object_keys = set()
        self.report = {"prefix": self.prefix, "endpoint": self.endpoint, "observations": {},
                       "controllers": self.controller.runs, "cleanup": {}}
        self.clients = {name: self.client(name) for name in ("cloudformation", "s3", "sqs", "sns", "iam", "lambda", "events", "logs")}

    def client(self, service, account="test", region="us-east-1", key=None):
        credentials = {"aws_access_key_id": account, "aws_secret_access_key": "test"}
        if key:
            credentials = {"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]}
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region,
            config=Config(retries={"max_attempts": 0}, connect_timeout=3, read_timeout=90,
                s3={"addressing_style": "path"}), **credentials)

    def save(self):
        (self.state / "report.json").write_text(json.dumps(self.report, indent=2, default=str) + "\n")

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"0.0.0.0:{self.port}",
            "-public-endpoint", self.endpoint, "-database", str(self.state / "state.sqlite"),
            "-docker-host", self.args.docker_host, "-lambda-runtime", "-compute-endpoint", f"http://host.docker.internal:{self.port}"]
        if self.args.telemetry_directory:
            command += ["-lambda-telemetry-directory", str(Path(self.args.telemetry_directory).resolve())]
        environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        self.controller.start(command, self.endpoint, environment=environment)

    def wait(self, callback, label, seconds=90):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = callback()
            if result:
                return result
            time.sleep(0.2)
        raise TimeoutError(label)

    def error(self, operation, codes, **parameters):
        codes = {codes} if isinstance(codes, str) else set(codes)
        try:
            operation(**parameters)
        except ClientError as error:
            code = error.response["Error"]["Code"]
            require(code in codes, f"expected {sorted(codes)}, got {error}")
            return {"code": code, "status": error.response["ResponseMetadata"]["HTTPStatusCode"]}
        raise AssertionError("expected modeled error " + str(sorted(codes)))

    def stack(self, name):
        return self.clients["cloudformation"].describe_stacks(StackName=name)["Stacks"][0]

    def wait_stack(self, name, status):
        def settled():
            stack = self.stack(name)
            current = stack["StackStatus"]
            if current == status:
                return stack
            require(current.endswith("_IN_PROGRESS"), f"{name}: expected {status}, got {stack}")
            return None
        return self.wait(settled, name + " " + status, 180)

    def export_constraint(self, label, name, operation, **parameters):
        # Admission versus asynchronous failure is an observed AWS contract,
        # never inferred from a waiter timeout or accepted as either outcome.
        expected = self.native[label]
        if expected["code"] == "Success":
            previous = self.stack(name)["StackStatus"]
            operation(**parameters)
            if label == "delete-export-in-use":
                evidence = self.native_constraints[label]
                status = evidence["final_status"]
                if status == evidence["previous_status"]:
                    status = previous  # Native cancellation restores its previous stable state.
            else:
                status = self.native[label + "-describe"]["output"]["Stacks"][0]["StackStatus"]
            self.wait_stack(name, status)
            observed = {"code": "Success", "terminal": status}
        else:
            observed = self.error(operation, expected["code"], **parameters)
            require(observed["status"] == expected["http_status"], "constraint error HTTP status differs from native")
        self.report["observations"][label] = observed

    def outputs(self, name):
        return {item["OutputKey"]: item["OutputValue"] for item in self.stack(name).get("Outputs", [])}

    def resources(self, name):
        rows = self.clients["cloudformation"].list_stack_resources(StackName=name)["StackResourceSummaries"]
        return {row["LogicalResourceId"]: row for row in rows}

    def deploy(self, name, template):
        path = self.state / (name + ".json")
        path.write_text(json.dumps(template, indent=2) + "\n")
        environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1",
            AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="", AWS_CONFIG_FILE=os.devnull,
            AWS_SHARED_CREDENTIALS_FILE=os.devnull, AWS_MAX_ATTEMPTS="1")
        self.stacks.append(name)
        result = subprocess.run([self.args.aws_cli, "--endpoint-url", self.endpoint, "--region", "us-east-1",
            "cloudformation", "deploy", "--stack-name", name, "--template-file", str(path),
            "--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset"],
            capture_output=True, text=True, env=environment, timeout=240)
        self.report["observations"]["aws-cli-deploy"] = {"status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        require(result.returncode == 0, "AWS CLI deploy failed: " + result.stderr + result.stdout)
        return self.wait_stack(name, "CREATE_COMPLETE")

    def change(self, name, template, label, expected):
        cfn = self.clients["cloudformation"]
        change = cfn.create_change_set(StackName=name, ChangeSetName=self.prefix + "-" + label,
            ChangeSetType="UPDATE", TemplateBody=json.dumps(template), Capabilities=["CAPABILITY_NAMED_IAM"])["Id"]
        def ready():
            result = cfn.describe_change_set(ChangeSetName=change)
            require(result["Status"] != "FAILED", str(result))
            return result if result["Status"] == "CREATE_COMPLETE" else None
        description = self.wait(ready, "change set " + label)
        changes = {row["ResourceChange"]["LogicalResourceId"]: row["ResourceChange"] for row in description["Changes"]}
        for logical, (action, replacement) in expected.items():
            require(logical in changes and changes[logical]["Action"] == action and
                changes[logical].get("Replacement") == replacement, f"{label}: unexpected plan {changes}")
        self.report["observations"][label + "-plan"] = changes
        cfn.execute_change_set(ChangeSetName=change)
        result = self.wait_stack(name, "UPDATE_COMPLETE")
        executed = cfn.describe_change_set(ChangeSetName=change)
        require(executed["ExecutionStatus"] == "EXECUTE_COMPLETE", "change set execution did not finish")
        return result

    def receive(self, queue, expected):
        sqs = self.clients["sqs"]
        def poll():
            for message in sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10).get("Messages", []):
                value = json.loads(message["Body"])
                sqs.delete_message(QueueUrl=queue, ReceiptHandle=message["ReceiptHandle"])
                if expected(value):
                    return value
            return None
        result = self.wait(poll, "actual SQS message", 120)
        self.report["observations"].setdefault("messages", []).append(result)
        return result


def template(app):
    prefix = app.prefix
    ref = lambda name: {"Ref": name}
    arn = lambda name: {"Fn::GetAtt": [name, "Arn"]}
    policy = lambda statements: {"Version": "2012-10-17", "Statement": statements}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Owned real CloudFormation data path",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": prefix + "-data"}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": prefix + "-input", "VisibilityTimeout": 20}},
            "Result": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": prefix + "-result"}},
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": prefix}},
            "Subscription": {"Type": "AWS::SNS::Subscription", "Properties": {
                "TopicArn": ref("Topic"), "Protocol": "sqs", "Endpoint": arn("Queue"), "RawMessageDelivery": True}},
            "QueuePolicy": {"Type": "AWS::SQS::QueuePolicy", "Properties": {"Queues": [ref("Queue")],
                "PolicyDocument": policy([
                    {"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
                        "Resource": arn("Queue"), "Condition": {"ArnEquals": {"aws:SourceArn": ref("Topic")}}},
                    {"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
                        "Resource": arn("Queue"), "Condition": {"ArnEquals": {"aws:SourceArn": arn("Rule")}}}])}},
            "Role": {"Type": "AWS::IAM::Role", "Properties": {"RoleName": prefix + "-lambda",
                "AssumeRolePolicyDocument": policy([{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]),
                "Policies": [{"PolicyName": "customer", "PolicyDocument": policy([
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": {"Fn::Sub": "${Bucket.Arn}/*"}},
                    {"Effect": "Allow", "Action": ["sqs:GetQueueUrl", "sqs:SendMessage"], "Resource": arn("Result")},
                    {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/" + prefix + ":*"}}])}]}},
            "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": "/aws/lambda/" + prefix}},
            "Function": {"Type": "AWS::Lambda::Function", "DependsOn": "LogGroup", "Properties": {
                "FunctionName": prefix, "Runtime": "python3.13", "Handler": "index.handler", "Timeout": 20,
                "Role": arn("Role"), "Code": {"ZipFile": HANDLER}, "Environment": {"Variables": {
                    "BUCKET": ref("Bucket"), "QUEUE_NAME": prefix + "-result", "STAGE": "v1"}}}},
            "Rule": {"Type": "AWS::Events::Rule", "Properties": {"Name": prefix, "State": "ENABLED",
                "EventPattern": {"source": [prefix]}, "Targets": [
                    {"Id": "queue", "Arn": arn("Queue")}, {"Id": "customer", "Arn": arn("Function") }]}},
            "Permission": {"Type": "AWS::Lambda::Permission", "Properties": {"FunctionName": ref("Function"),
                "Action": "lambda:InvokeFunction", "Principal": "events.amazonaws.com", "SourceArn": arn("Rule")}}},
        "Outputs": {"Bucket": {"Value": ref("Bucket")}, "Queue": {"Value": ref("Queue")},
            "QueueArn": {"Value": arn("Queue")}, "Result": {"Value": ref("Result")},
            "Topic": {"Value": ref("Topic"), "Export": {"Name": prefix + "-topic"}},
            "Function": {"Value": arn("Function")}, "Role": {"Value": ref("Role")},
            "Rule": {"Value": arn("Rule")}}}


def data_path(app, name, stage, label=None):
    out = app.outputs(name)
    marker = app.prefix + "-" + (label or stage)
    key = marker + ".txt"
    body = "actual customer object " + marker
    app.object_keys.add((out["Bucket"], key))
    app.clients["s3"].put_object(Bucket=out["Bucket"], Key=key, Body=body.encode())
    topic_payload = {"marker": marker, "via": "sns"}
    app.clients["sns"].publish(TopicArn=out["Topic"], Message=json.dumps(topic_payload))
    require(app.receive(out["Queue"], lambda value: value == topic_payload) == topic_payload, "SNS payload altered")
    result = app.clients["events"].put_events(Entries=[{"Source": app.prefix,
        "DetailType": "cloudformation-smoke", "Detail": json.dumps({"marker": marker, "key": key})}])
    require(result["FailedEntryCount"] == 0 and "EventId" in result["Entries"][0], "EventBridge rejected customer event")
    event = app.receive(out["Queue"], lambda value: value.get("detail", {}).get("marker") == marker)
    require(event["source"] == app.prefix and event["detail"] == {"marker": marker, "key": key}, "EventBridge envelope altered")
    customer = app.receive(out["Result"], lambda value: value.get("marker") == marker)
    require(customer["body"] == body and customer["stage"] == stage and customer["function"] == out["Function"],
        "real customer Lambda did not read deployed object or use current environment")
    uuid.UUID(customer["invocation"])
    require(customer["runtime"].startswith("3.13."), "customer handler did not execute selected Python runtime")
    return out


def rollback(app):
    sqs, cfn = app.clients["sqs"], app.clients["cloudformation"]
    name = app.prefix + "-rollback"
    app.stacks.append(name)
    resources = {
        "First": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": app.prefix + "-rb-first"}},
        "Fail": {"Type": "AWS::SQS::Queue", "DependsOn": "First", "Properties": {
            "QueueName": app.prefix + "-rb-fail", "RedrivePolicy": {
                "deadLetterTargetArn": "arn:aws:sqs:us-east-1:000000000000:" + app.prefix + "-missing-dlq",
                "maxReceiveCount": 3}}},
        "After": {"Type": "AWS::SQS::Queue", "DependsOn": "Fail", "Properties": {"QueueName": app.prefix + "-rb-after"}}}
    ident = cfn.create_stack(StackName=name, TemplateBody=json.dumps({"Resources": resources}))["StackId"]
    app.wait_stack(ident, "ROLLBACK_COMPLETE")
    events = cfn.describe_stack_events(StackName=ident)["StackEvents"]
    transitions = {(event["LogicalResourceId"], event["ResourceStatus"]) for event in events}
    require({("First", "CREATE_COMPLETE"), ("Fail", "CREATE_FAILED"), ("First", "DELETE_COMPLETE")}.issubset(transitions),
        "dependency failure did not roll back previously created resource")
    require(("After", "CREATE_COMPLETE") not in transitions, "dependent resource executed after failed dependency")
    for suffix in ("rb-first", "rb-fail", "rb-after", "missing-dlq"):
        app.error(sqs.get_queue_url, "AWS.SimpleQueueService.NonExistentQueue", QueueName=app.prefix + "-" + suffix)
    app.report["observations"]["rollback"] = sorted(transitions)


def current_authority(app, name):
    iam = app.clients["iam"]
    user = app.prefix + "-reader"
    app.report["reader_user"] = user
    iam.create_user(UserName=user)
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "cloudformation:DescribeStacks", "Resource": "*"}]}
    iam.put_user_policy(UserName=user, PolicyName="current", PolicyDocument=json.dumps(policy))
    key = iam.create_access_key(UserName=user)["AccessKey"]
    app.reader_key = key["AccessKeyId"]
    client = app.client("cloudformation", key=key)
    expected = app.stack(name)["StackId"]
    require(client.describe_stacks(StackName=name)["Stacks"][0]["StackId"] == expected, "reader allow policy failed")
    policy["Statement"].append({"Effect": "Deny", "Action": "cloudformation:DescribeStacks", "Resource": "*"})
    iam.put_user_policy(UserName=user, PolicyName="current", PolicyDocument=json.dumps(policy))
    app.report["observations"]["current-iam-denial"] = app.error(client.describe_stacks, "AccessDenied", StackName=name)
    require(app.stack(name)["StackId"] == expected, "denied read changed stack")


def exact_absence(app, resources):
    c = app.clients
    checks = {}
    for logical, row in resources.items():
        if not row.get("PhysicalResourceId") or row.get("ResourceStatus") == "CREATE_FAILED":
            continue  # A failed create never transfers ownership of the conflicting resource.
        ident, kind = row["PhysicalResourceId"], row["ResourceType"]
        if kind == "AWS::S3::Bucket":
            result = app.error(c["s3"].head_bucket, "404", Bucket=ident)
        elif kind == "AWS::SQS::Queue":
            result = app.error(c["sqs"].get_queue_attributes, "AWS.SimpleQueueService.NonExistentQueue", QueueUrl=ident, AttributeNames=["QueueArn"])
        elif kind == "AWS::SNS::Topic":
            result = app.error(c["sns"].get_topic_attributes, "NotFound", TopicArn=ident)
        elif kind == "AWS::SNS::Subscription":
            result = app.error(c["sns"].get_subscription_attributes, "NotFound", SubscriptionArn=ident)
        elif kind == "AWS::IAM::Role":
            result = app.error(c["iam"].get_role, "NoSuchEntity", RoleName=ident)
        elif kind == "AWS::Lambda::Function":
            result = app.error(c["lambda"].get_function, "ResourceNotFoundException", FunctionName=ident)
        elif kind == "AWS::Events::Rule":
            result = app.error(c["events"].describe_rule, "ResourceNotFoundException", Name=ident.rsplit("/", 1)[-1])
        elif kind == "AWS::Logs::LogGroup":
            result = app.error(c["logs"].describe_log_streams, "ResourceNotFoundException", logGroupName=ident)
        elif kind in ("AWS::SQS::QueuePolicy", "AWS::Lambda::Permission"):
            continue  # Parent queue/function absence proves these attached policies no longer exist.
        else:
            raise AssertionError("missing exact absence proof for " + kind)
        checks[logical] = result
    return checks


def cleanup(app):
    failures = []
    def attempt(label, callback):
        try:
            return callback()
        except Exception as error:
            failures.append(label + ": " + str(error))
            return None
    cfn = app.clients["cloudformation"]
    for bucket, key in sorted(app.object_keys):
        attempt("delete owned object " + key, lambda b=bucket, k=key: app.clients["s3"].delete_object(Bucket=b, Key=k))
    for name in reversed(app.stacks):
        def remove(name=name):
            try:
                stack = app.stack(name)
            except ClientError as error:
                if error.response["Error"]["Code"] == "ValidationError":
                    return
                raise
            ident = stack["StackId"]
            resources = app.resources(ident)
            changes = [cfn.describe_change_set(ChangeSetName=row["ChangeSetId"])
                for page in cfn.get_paginator("list_change_sets").paginate(StackName=ident)
                for row in page.get("Summaries", [])]
            cfn.delete_stack(StackName=ident)
            app.wait_stack(ident, "DELETE_COMPLETE")
            app.report["cleanup"][name] = exact_absence(app, resources)
            app.error(cfn.describe_stacks, "ValidationError", StackName=name)
            require(app.stack(ident)["StackStatus"] == "DELETE_COMPLETE", "deleted stack ID lost retained history")
            for change in changes:
                change_id = change["ChangeSetId"]
                if change["ExecutionStatus"] in ("EXECUTE_COMPLETE", "EXECUTE_FAILED"):
                    app.error(cfn.delete_change_set, "InvalidChangeSetStatus", ChangeSetName=change_id)
                    retained = cfn.describe_change_set(ChangeSetName=change_id)
                    fields = ("ChangeSetId", "StackId", "Status", "ExecutionStatus")
                    require({key: retained[key] for key in fields} == {key: change[key] for key in fields},
                        "executed change set lost native retained history after stack deletion")
                    app.report.setdefault("retained_execution_history", {})[change_id] = {key: retained[key] for key in fields}
                else:
                    cfn.delete_change_set(ChangeSetName=change_id)
                    app.error(cfn.describe_change_set, "ChangeSetNotFound", ChangeSetName=change_id)
        attempt("delete stack " + name, remove)
    if app.report.get("reader_user"):
        user = app.report["reader_user"]
        if hasattr(app, "reader_key"):
            attempt("delete reader key", lambda: app.clients["iam"].delete_access_key(UserName=user, AccessKeyId=app.reader_key))
        attempt("delete reader policy", lambda: app.clients["iam"].delete_user_policy(UserName=user, PolicyName="current"))
        attempt("delete reader user", lambda: app.clients["iam"].delete_user(UserName=user))
        attempt("reader absence", lambda: app.error(app.clients["iam"].get_user, "NoSuchEntity", UserName=user))
    attempt("stop controller", lambda: app.controller.stop(kill_on_timeout=True))
    for function in sorted(app.functions):
        def runtime_absence(function=function):
            docker = ["docker", "--host", app.args.docker_host]
            selector = "label=io.stackd.function=" + function
            for listing in (["ps", "--all", "--quiet"], ["volume", "ls", "--quiet"]):
                result = subprocess.check_output(docker + listing + ["--filter", selector], text=True).strip()
                require(not result, "owned Lambda runtime remained: " + function + " " + result)
            app.report["cleanup"][function] = "exact labeled containers and volumes absent"
        attempt("Lambda runtime absence", runtime_absence)
    app.report["cleanup_complete"] = not failures
    app.report["cleanup_errors"] = failures
    app.save()
    require(not failures, "owned cleanup failed: " + "; ".join(failures))


def run(app):
    app.start()
    name = app.prefix + "-application"
    document = template(app)
    app.functions.add("arn:aws:lambda:us-east-1:000000000000:function:" + app.prefix)
    created = app.deploy(name, document)
    app.functions.add(app.outputs(name)["Function"])
    initial = app.resources(name)
    out = data_path(app, name, "v1")
    cfn = app.clients["cloudformation"]
    for label, client in (("region", app.client("cloudformation", region="us-west-2")),
                          ("account", app.client("cloudformation", account="111111111111"))):
        app.report["observations"]["cross-" + label] = app.error(client.describe_stacks, "ValidationError", StackName=created["StackId"])
    current_authority(app, name)
    updated = copy.deepcopy(document)
    updated["Resources"]["Function"]["Properties"]["Environment"]["Variables"]["STAGE"] = "v2"
    updated["Resources"]["Queue"]["Properties"]["VisibilityTimeout"] = 31
    app.change(name, updated, "mutable-update", {"Queue": ("Modify", "False"), "Function": ("Modify", "False")})
    require(app.resources(name)["Queue"]["PhysicalResourceId"] == initial["Queue"]["PhysicalResourceId"], "mutable queue update replaced physical resource")
    require(app.clients["sqs"].get_queue_attributes(QueueUrl=out["Queue"], AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"] == "31", "owner queue attribute did not update")
    data_path(app, name, "v2")
    replacement = copy.deepcopy(updated)
    replacement["Resources"]["Queue"]["Properties"]["QueueName"] = app.prefix + "-replaced"
    replacement["Resources"]["Function"]["Properties"]["Environment"]["Variables"]["STAGE"] = "v3"
    app.change(name, replacement, "create-only-replacement", {"Queue": ("Modify", "True")})
    replaced = app.resources(name)
    require(replaced["Queue"]["PhysicalResourceId"] != initial["Queue"]["PhysicalResourceId"], "create-only change retained old physical queue")
    app.error(app.clients["sqs"].get_queue_attributes, "AWS.SimpleQueueService.NonExistentQueue", QueueUrl=out["Queue"], AttributeNames=["QueueArn"])
    data_path(app, name, "v3")
    importer = app.prefix + "-importer"
    imported = {"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": app.prefix + "-import"}}},
        "Outputs": {"Imported": {"Value": {"Fn::ImportValue": app.prefix + "-topic"}}}}
    app.stacks.append(importer)
    cfn.create_stack(StackName=importer, TemplateBody=json.dumps(imported))
    app.wait_stack(importer, "CREATE_COMPLETE")
    require(app.outputs(importer)["Imported"] == out["Topic"], "import did not resolve actual exported topic")
    require(cfn.list_imports(ExportName=app.prefix + "-topic")["Imports"] == [importer], "export dependency missing")
    changed_export = copy.deepcopy(replacement)
    changed_export["Outputs"]["Topic"]["Value"] = "changed"
    app.export_constraint("update-export-in-use", name, cfn.update_stack,
        StackName=name, TemplateBody=json.dumps(changed_export), Capabilities=["CAPABILITY_NAMED_IAM"])
    require(app.outputs(name)["Topic"] == out["Topic"], "rejected export mutation changed producer")
    app.export_constraint("delete-export-in-use", name, cfn.delete_stack, StackName=name)
    require(app.outputs(name)["Topic"] == out["Topic"], "blocked deletion removed exported output")
    rollback(app)
    snapshot = {key: row["PhysicalResourceId"] for key, row in app.resources(name).items()}
    before = app.outputs(name)
    before_status = app.stack(name)["StackStatus"]
    app.controller.stop(kill_on_timeout=True)
    app.start()
    require(app.stack(name)["StackId"] == created["StackId"] and app.stack(name)["StackStatus"] == before_status,
        "stack identity/status lost across SQLite restart")
    require({key: row["PhysicalResourceId"] for key, row in app.resources(name).items()} == snapshot and app.outputs(name) == before,
        "resource/output identity changed across restart")
    require(cfn.list_imports(ExportName=app.prefix + "-topic")["Imports"] == [importer], "import protection lost across restart")
    data_path(app, name, "v3", "after-restart")
    app.report["observations"]["restart"] = {"stack": created["StackId"], "resources": snapshot, "outputs": before}
    app.report["complete"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--telemetry-directory", default="")
    parser.add_argument("--aws-cli", default="aws")
    args = parser.parse_args()
    app = Application(args)
    try:
        run(app)
    except BaseException as error:
        app.report["failure"] = repr(error)
        raise
    finally:
        if app.controller.process is not None:
            cleanup(app)
        else:
            app.save()
    print(json.dumps({"complete": app.report.get("complete", False), "cleanup_complete": app.report.get("cleanup_complete", False),
        "report": str(app.state / "report.json")}, indent=2))


if __name__ == "__main__":
    main()
