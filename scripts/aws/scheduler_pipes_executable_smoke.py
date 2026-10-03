#!/usr/bin/env python3
"""Local-only official SDK proof against the actual SQLite-backed stackd binary."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess


def require(value, message):
    if not value:
        raise AssertionError(message)


class Application:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        require(not (self.state / "state.sqlite").exists(), "requires fresh owned state directory")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.prefix = "sp-" + uuid.uuid4().hex[:10]
        self.controller = StackdProcess(self.state)
        self.receipts = {}
        self.report = {"endpoint": self.endpoint, "prefix": self.prefix, "observations": {}, "controllers": self.controller.runs}
        self.clients = {name: self.client(name) for name in
                        ("iam", "sqs", "scheduler", "pipes", "lambda", "events", "kinesis", "dynamodb", "cloudwatch", "cloudtrail", "logs", "kms")}

    def client(self, service, account="test", region="us-east-1"):
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region,
            aws_access_key_id=account, aws_secret_access_key="test",
            config=Config(retries={"max_attempts": 0}, connect_timeout=3, read_timeout=60))

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"0.0.0.0:{self.port}",
            "-public-endpoint", self.endpoint, "-database", str(self.state / "state.sqlite"),
            "-clock-start", "2026-09-26T12:00:00Z", "-docker-host", self.args.docker_host,
            "-compute-endpoint", f"http://host.docker.internal:{self.port}"]
        if self.args.telemetry_directory:
            command += ["-lambda-telemetry-directory", self.args.telemetry_directory]
        environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        self.controller.start(command, self.endpoint, environment=environment)

    def control(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else b""
        request = urllib.request.Request(self.endpoint + path, data=data,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    def now(self):
        with urllib.request.urlopen(self.endpoint + "/_stackd/clock", timeout=5) as response:
            return datetime.fromisoformat(json.load(response)["time"].replace("Z", "+00:00"))

    def advance(self, seconds):
        self.control("/_stackd/clock", {"advance": f"{seconds}s"})
        return self.control("/_stackd/jobs/drain?limit=1024")

    def wait(self, fn, label, seconds=60, advance=1):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = fn()
            if result:
                return result
            self.advance(advance)
            time.sleep(0.1)
        raise TimeoutError(label)

    def queue(self, suffix):
        sqs = self.clients["sqs"]
        name = self.prefix + "-" + suffix
        url = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "5"})["QueueUrl"]
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        return {"name": name, "url": url, "arn": arn}

    def receive(self, queue, marker, seconds=60):
        messages = self.receipts.setdefault(queue["url"], [])
        def check():
            output = self.clients["sqs"].receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10,
                MessageAttributeNames=["All"], MessageSystemAttributeNames=["All"])
            for message in output.get("Messages", []):
                messages.append(message)
                self.clients["sqs"].delete_message(QueueUrl=queue["url"], ReceiptHandle=message["ReceiptHandle"])
            return [message for message in messages if marker in message["Body"]]
        result = self.wait(check, "target delivery " + marker, seconds)
        self.report["observations"][marker] = result
        return result

    def error(self, operation, code, **params):
        try:
            operation(**params)
        except ClientError as error:
            observed = error.response["Error"]["Code"]
            require(observed == code, f"expected {code}, got {observed}: {error}")
            return observed
        raise AssertionError("expected " + code)


def owned_engine_specs(app):
    database = app.state / "state.sqlite"
    if not database.exists():
        return []
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        result = []
        for service, table, identifier in (
                ("dynamodb", "dynamodb_databases", "id"), ("kinesis", "kinesis_streams", "engine_id")):
            for row in connection.execute(f"select {identifier}, partition, account_id, region from {table}"):
                result.append({"service": service, **dict(zip(("id", "partition", "account", "region"), row))})
        return result


def remove_owned_engine(app, specification):
    # A fresh owned SQLite store is the authority for physical engine IDs. Never
    # prune by account, service, image, or a before/after list of Docker resources.
    command = ["docker", "--host", app.args.docker_host]
    prefix = "stackd." + specification["service"] + "."
    selector = prefix + "id=" + specification["id"]
    expected = {prefix + key: specification[key] for key in ("id", "partition", "account", "region")}
    containers = subprocess.check_output(command + ["ps", "--all", "--quiet", "--filter", "label=" + selector], text=True).split()
    removed = {"specification": specification, "containers": [], "volumes": []}
    for identifier in containers:
        inspection = json.loads(subprocess.check_output(command + ["inspect", "--type", "container", identifier], text=True))[0]
        labels = inspection["Config"].get("Labels", {})
        roles = {"database", "init"} if specification["service"] == "dynamodb" else {"broker", "init"}
        require(all(labels.get(key) == value for key, value in expected.items()) and labels.get(prefix + "role") in roles,
                "refusing foreign Docker container: " + identifier)
        subprocess.run(command + ["rm", "--force", identifier], check=True, capture_output=True, text=True)
        removed["containers"].append(identifier)
    volumes = subprocess.check_output(command + ["volume", "ls", "--quiet", "--filter", "label=" + selector], text=True).split()
    for name in volumes:
        inspection = json.loads(subprocess.check_output(command + ["volume", "inspect", name], text=True))[0]
        labels = inspection.get("Labels", {})
        require(all(labels.get(key) == value for key, value in expected.items()) and labels.get(prefix + "role") == "data",
                "refusing foreign Docker volume: " + name)
        subprocess.run(command + ["volume", "rm", name], check=True, capture_output=True, text=True)
        removed["volumes"].append(name)
    for listing in (["ps", "--all", "--quiet"], ["volume", "ls", "--quiet"]):
        require(not subprocess.check_output(command + listing + ["--filter", "label=" + selector], text=True).strip(),
                "owned physical engine remained: " + specification["id"])
    return removed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--telemetry-directory", default="")
    args = parser.parse_args()
    app = Application(args)
    queues = []
    functions = []
    streams = []
    tables = []
    pipes = []
    schedules = []
    try:
        app.start()
        iam, sqs, scheduler, pipesapi = (app.clients[name] for name in ("iam", "sqs", "scheduler", "pipes"))
        target, source, dlq = (app.queue(name) for name in ("target", "source", "dlq"))
        queues += [target, source, dlq]
        roles = {}
        for service in ("scheduler", "pipes", "lambda"):
            name = app.prefix + "-" + service
            roles[service] = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
                    "Service": service + ".amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
            iam.put_role_policy(RoleName=name, PolicyName="owned", PolicyDocument=json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
        group = scheduler.create_schedule_group(Name=app.prefix, Tags=[{"Key": "smoke", "Value": "owned"}])["ScheduleGroupArn"]
        require(scheduler.get_schedule_group(Name=app.prefix)["State"] == "ACTIVE", "group active")
        scheduler.tag_resource(ResourceArn=group, Tags=[{"Key": "second", "Value": "tag"}])
        require({v["Key"] for v in scheduler.list_tags_for_resource(ResourceArn=group)["Tags"]} == {"smoke", "second"}, "group tags")
        app.error(scheduler.get_schedule, "ResourceNotFoundException", Name="absent", GroupName=app.prefix)
        app.error(app.client("scheduler", region="us-west-2").get_schedule_group, "ResourceNotFoundException", Name=app.prefix)
        app.error(app.client("scheduler", account="111111111111").get_schedule_group, "ResourceNotFoundException", Name=app.prefix)

        def make_schedule(name, arn, payload, **options):
            role = options.pop("role", roles["scheduler"])
            retry = options.pop("retry", 0)
            target_parameters = options.pop("target_parameters", {})
            at = app.now() + timedelta(seconds=60)
            params = {"Name": name, "GroupName": app.prefix, "ScheduleExpression": "at(" + at.strftime("%Y-%m-%dT%H:%M:%S") + ")",
                "FlexibleTimeWindow": {"Mode": "OFF"}, "Target": {"Arn": arn, "RoleArn": role,
                    "RetryPolicy": {"MaximumRetryAttempts": retry,
                    "MaximumEventAgeInSeconds": 600}, "DeadLetterConfig": {"Arn": dlq["arn"]}}}
            if payload is not None:
                params["Target"]["Input"] = json.dumps(payload)
            params.update(options)
            params["Target"].update(target_parameters)
            scheduler.create_schedule(**params)
            schedules.append(name)
            return params

        make_schedule("direct", target["arn"], {"marker": "scheduled-direct"}, ActionAfterCompletion="DELETE")
        app.advance(60)
        app.receive(target, "scheduled-direct")
        app.error(scheduler.get_schedule, "ResourceNotFoundException", Name="direct", GroupName=app.prefix)
        default_schedule = make_schedule("default", target["arn"], None)
        app.advance(60)
        notification = json.loads(app.receive(target, "aws.scheduler")[0]["Body"])
        uuid.UUID(notification["id"])
        require({key: value for key, value in notification.items() if key != "id"} == {
            "version": "0", "detail-type": "Scheduled Event", "source": "aws.scheduler",
            "account": target["arn"].split(":")[4], "region": "us-east-1",
            "time": default_schedule["ScheduleExpression"][3:-1] + "Z",
            "resources": [group.replace(":schedule-group/", ":schedule/") + "/default"], "detail": "{}"},
            "omitted Input notification differs from fresh native SQS delivery")
        app.report["observations"]["scheduler-default-notification"] = notification
        disabled = make_schedule("disabled", target["arn"], {"marker": "must-not-deliver"}, State="DISABLED")
        app.advance(120)
        require(not sqs.receive_message(QueueUrl=target["url"]).get("Messages"), "disabled schedule delivered")
        app.error(scheduler.create_schedule, "ConflictException", **disabled)
        invalid = dict(disabled, Name="invalid", ScheduleExpression="cron(* * * * * *)")
        app.error(scheduler.create_schedule, "ValidationException", **invalid)
        make_schedule("universal", "arn:aws:scheduler:::aws-sdk:sqs:sendMessage", {
            "QueueUrl": target["url"], "MessageBody": "scheduled-universal"})
        app.advance(60)
        app.receive(target, "scheduled-universal")
        make_schedule("sdk-name", "arn:aws:scheduler:::aws-sdk:cloudwatchlogs:createLogGroup", {"LogGroupName": app.prefix})
        app.advance(60)
        require(any(group["logGroupName"] == app.prefix for group in
                    app.clients["logs"].describe_log_groups(logGroupNamePrefix=app.prefix)["logGroups"]),
                "universal SDK service identifier did not reach the actual Logs command")
        log_group_arn = f"arn:aws:logs:us-east-1:{target['arn'].split(':')[4]}:log-group:{app.prefix}"
        app.clients["logs"].put_resource_policy(policyName=app.prefix, policyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": log_group_arn + ":*",
                "Condition": {"StringEquals": {"aws:SourceAccount": target["arn"].split(":")[4]}}}]}))
        key = app.clients["kms"].create_key(Description=app.prefix)["KeyMetadata"]["Arn"]
        make_schedule("encrypted", target["arn"], {"marker": "scheduled-encrypted"}, KmsKeyArn=key)
        encrypted = scheduler.get_schedule(Name="encrypted", GroupName=app.prefix)
        require(encrypted["KmsKeyArn"] == key and json.loads(encrypted["Target"]["Input"])["marker"] == "scheduled-encrypted",
                "encrypted schedule did not decrypt through the current caller")
        app.advance(60)
        app.receive(target, "scheduled-encrypted")

        events = app.clients["events"]
        bus = events.create_event_bus(Name=app.prefix)["EventBusArn"]
        rule = events.put_rule(Name=app.prefix, EventBusName=app.prefix,
            EventPattern=json.dumps({"source": ["smoke.scheduler"]}))["RuleArn"]
        sqs.set_queue_attributes(QueueUrl=target["url"], Attributes={"Policy": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": target["arn"], "Condition": {"ArnEquals": {"aws:SourceArn": rule}}}]})})
        events.put_targets(Rule=app.prefix, EventBusName=app.prefix, Targets=[{"Id": "queue", "Arn": target["arn"]}])
        event_schedule = make_schedule("eventbridge", bus, {"marker": "scheduled-eventbridge"}, State="DISABLED",
            target_parameters={"EventBridgeParameters": {"Source": "smoke.scheduler", "DetailType": "scheduled"}})
        event_schedule["State"] = "ENABLED"
        scheduler.update_schedule(**event_schedule)
        app.advance(60)
        app.receive(target, "scheduled-eventbridge")

        code = '''import json, os, boto3\ndef handler(event, context):\n    if isinstance(event, list):\n        return [dict(json.loads(row["body"]), enriched=True) for row in event]\n    boto3.client("sqs").send_message(QueueUrl=os.environ["QUEUE"],MessageBody=json.dumps(event))\n    return {"delivered": True}\n'''
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("handler.py", code)
        function = app.clients["lambda"].create_function(FunctionName=app.prefix, Runtime="python3.13",
            Role=roles["lambda"], Handler="handler.handler", Code={"ZipFile": package.getvalue()}, Timeout=15,
            Environment={"Variables": {"QUEUE": target["url"].replace("127.0.0.1", "host.docker.internal"),
                "AWS_ENDPOINT_URL": app.endpoint.replace("127.0.0.1", "host.docker.internal")}})["FunctionArn"]
        functions.append(function)
        app.wait(lambda: app.clients["lambda"].get_function_configuration(FunctionName=function).get("State") == "Active", "Lambda active")
        make_schedule("lambda", function, {"marker": "scheduled-lambda"})
        app.advance(60)
        app.receive(target, "scheduled-lambda", 90)

        deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "sqs:SendMessage", "Resource": target["arn"]}]}
        iam.put_role_policy(RoleName=app.prefix+"-scheduler", PolicyName="deny", PolicyDocument=json.dumps(deny))
        make_schedule("dlq", target["arn"], {"marker": "scheduled-denied"})
        app.advance(60)
        app.receive(dlq, "scheduled-denied")
        app.clients["lambda"].put_function_concurrency(FunctionName=function, ReservedConcurrentExecutions=0)
        make_schedule("retry", "arn:aws:scheduler:::aws-sdk:lambda:invoke", {
            "FunctionName": function, "InvocationType": "RequestResponse",
            "Payload": {"marker": "scheduled-restart-retry"}}, retry=3)
        app.advance(60)
        require(not sqs.receive_message(QueueUrl=target["url"]).get("Messages"), "throttled Scheduler target delivered")
        saved = app.now()
        app.controller.stop(kill_on_timeout=True)
        app.start()
        require(app.now() == saved, "manual clock not retained")
        iam.delete_role_policy(RoleName=app.prefix+"-scheduler", PolicyName="deny")
        app.clients["lambda"].delete_function_concurrency(FunctionName=function)
        app.advance(60)
        app.receive(target, "scheduled-restart-retry")

        params = {"Name": app.prefix, "RoleArn": roles["pipes"], "Source": source["arn"], "Target": target["arn"],
            "DesiredState": "STOPPED", "KmsKeyIdentifier": key,
            "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1},
                "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"body": {"keep": [True]}})}]}},
            "TargetParameters": {"InputTemplate": '{"marker":<$.body.marker>,"value":<$.body.value>}'},
            "LogConfiguration": {"Level": "TRACE", "IncludeExecutionData": ["ALL"],
                "CloudwatchLogsLogDestination": {"LogGroupArn": log_group_arn}}}
        pipearn = pipesapi.create_pipe(**params)["Arn"]
        pipes.append(app.prefix)
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "pipe stopped")
        description = pipesapi.describe_pipe(Name=app.prefix)
        require(description["KmsKeyIdentifier"] == key and
                description["SourceParameters"]["FilterCriteria"] == params["SourceParameters"]["FilterCriteria"],
                "encrypted Pipes filter did not decrypt through the current caller")
        app.error(pipesapi.create_pipe, "ConflictException", **params)
        app.error(app.client("pipes", region="us-west-2").describe_pipe, "NotFoundException", Name=app.prefix)
        app.error(app.client("pipes", account="111111111111").describe_pipe, "NotFoundException", Name=app.prefix)
        for marker, keep in (("filtered-drop", False), ("pipe-delivery", True)):
            sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": marker, "keep": keep, "value": 7}))
        app.advance(30)
        counts = sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]
        require(counts["ApproximateNumberOfMessages"] == "2", "STOPPED pipe consumed source")
        pipesapi.start_pipe(Name=app.prefix)
        delivered = app.receive(target, "pipe-delivery")
        require(json.loads(delivered[0]["Body"]) == {"marker": "pipe-delivery", "value": 7}, "input transformation")
        app.report["observations"]["pipe-logs"] = app.wait(lambda:
            app.clients["logs"].filter_log_events(logGroupName=app.prefix, filterPattern='"pipe-delivery"').get("events"),
            "actual Pipes execution payload in CloudWatch Logs")
        app.wait(lambda: sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=["ApproximateNumberOfMessagesNotVisible"])["Attributes"]["ApproximateNumberOfMessagesNotVisible"] == "0", "source acknowledgement")
        require(not sqs.receive_message(QueueUrl=source["url"]).get("Messages"), "filtered/success source not acknowledged")
        pipesapi.stop_pipe(Name=app.prefix)
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "pipe stop")
        pipesapi.update_pipe(Name=app.prefix, RoleArn=roles["pipes"], Enrichment=function,
            TargetParameters={"InputTemplate": '{"marker":<$.marker>,"enriched":<$.enriched>}'})
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "pipe enrichment update")
        sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": "pipe-enriched", "keep": True}))
        pipesapi.start_pipe(Name=app.prefix)
        delivered = app.receive(target, "pipe-enriched", 90)
        require(json.loads(delivered[0]["Body"]) == {"marker": "pipe-enriched", "enriched": True}, "real Lambda enrichment output")
        pipesapi.stop_pipe(Name=app.prefix)
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "pipe stop before retry")
        pipesapi.update_pipe(Name=app.prefix, RoleArn=roles["pipes"], Enrichment="",
            TargetParameters={"InputTemplate": '{"marker":<$.body.marker>}'})
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "pipe retry update")
        iam.put_role_policy(RoleName=app.prefix+"-pipes", PolicyName="deny", PolicyDocument=json.dumps(deny))
        sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": "pipe-restart-retry", "keep": True}))
        pipesapi.start_pipe(Name=app.prefix)
        app.advance(2)
        time.sleep(0.3)
        app.control("/_stackd/jobs/drain?limit=1024")
        require(not sqs.receive_message(QueueUrl=target["url"]).get("Messages"), "denied Pipes target delivered")
        app.controller.stop(kill_on_timeout=True)
        app.start()
        iam.delete_role_policy(RoleName=app.prefix+"-pipes", PolicyName="deny")
        app.advance(30)
        app.receive(target, "pipe-restart-retry", 90)
        pipesapi.stop_pipe(Name=app.prefix)
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "pipe stopped after restart")
        app.report["observations"]["pipe-tags"] = pipesapi.list_tags_for_resource(resourceArn=pipearn)
        partial_code = '''import json, os, boto3\nfailed_once=set()\ndef handler(records, context):\n    failures=[]\n    for record in records:\n        body=json.loads(record["body"])\n        identifier=record["messageId"]\n        if body.get("failOnce") and identifier not in failed_once:\n            failed_once.add(identifier)\n            failures.append({"itemIdentifier":identifier})\n            continue\n        boto3.client("sqs").send_message(QueueUrl=os.environ["QUEUE"],MessageBody=json.dumps(body))\n    return {"batchItemFailures":failures}\n'''
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("handler.py", partial_code)
        partial_function = app.clients["lambda"].create_function(FunctionName=app.prefix+"-partial", Runtime="python3.13",
            Role=roles["lambda"], Handler="handler.handler", Code={"ZipFile": package.getvalue()}, Timeout=15,
            Environment={"Variables": {"QUEUE": target["url"].replace("127.0.0.1", "host.docker.internal"),
                "AWS_ENDPOINT_URL": app.endpoint.replace("127.0.0.1", "host.docker.internal")}})["FunctionArn"]
        functions.append(partial_function)
        app.wait(lambda: app.clients["lambda"].get_function_configuration(FunctionName=partial_function).get("State") == "Active",
                 "partial-failure Lambda active")
        pipesapi.update_pipe(Name=app.prefix, RoleArn=roles["pipes"], Target=partial_function,
            SourceParameters={"SqsQueueParameters": {"BatchSize": 2}},
            TargetParameters={"LambdaFunctionParameters": {"InvocationType": "REQUEST_RESPONSE"}})
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "pipe partial-batch update")
        for marker, fail in (("partial-good", False), ("partial-retry", True)):
            sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": marker, "keep": True, "failOnce": fail}))
        pipesapi.start_pipe(Name=app.prefix)
        app.receive(target, "partial-good", 90)
        app.receive(target, "partial-retry", 90)
        pipesapi.stop_pipe(Name=app.prefix)
        app.wait(lambda: pipesapi.describe_pipe(Name=app.prefix)["CurrentState"] == "STOPPED", "partial pipe stop")
        require(sum("partial-good" in row["Body"] for row in app.receipts[target["url"]]) == 1,
                "successful partial-batch item was re-executed")
        app.advance(10)
        require(not sqs.receive_message(QueueUrl=source["url"]).get("Messages"), "partial batch source was not acknowledged")

        stream = app.prefix + "-stream"
        app.clients["kinesis"].create_stream(StreamName=stream, ShardCount=1)
        streams.append(stream)
        description = app.wait(lambda: (lambda result: result if result["StreamStatus"] == "ACTIVE" else None)(
            app.clients["kinesis"].describe_stream_summary(StreamName=stream)["StreamDescriptionSummary"]), "Kinesis active", 90)
        name = app.prefix + "-kinesis"
        pipesapi.create_pipe(Name=name, RoleArn=roles["pipes"], Source=description["StreamARN"], Target=target["arn"],
            SourceParameters={"KinesisStreamParameters": {"StartingPosition": "TRIM_HORIZON", "BatchSize": 1}})
        pipes.append(name)
        app.clients["kinesis"].put_record(StreamName=stream, PartitionKey="owned", Data=b"kinesis-actual-record")
        messages = app.receive(target, base64.b64encode(b"kinesis-actual-record").decode(), 90)
        require("kinesis" in messages[0]["Body"].lower(), "real Kinesis source envelope missing")
        table = app.prefix + "-table"
        app.clients["dynamodb"].create_table(TableName=table, AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST",
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"})
        tables.append(table)
        description = app.wait(lambda: (lambda result: result if result["TableStatus"] == "ACTIVE" else None)(
            app.clients["dynamodb"].describe_table(TableName=table)["Table"]), "DynamoDB active", 90)
        name = app.prefix + "-dynamodb"
        pipesapi.create_pipe(Name=name, RoleArn=roles["pipes"], Source=description["LatestStreamArn"], Target=target["arn"],
            SourceParameters={"DynamoDBStreamParameters": {"StartingPosition": "TRIM_HORIZON", "BatchSize": 1}})
        pipes.append(name)
        app.clients["dynamodb"].put_item(TableName=table, Item={"pk": {"S": "dynamodb-actual-record"}, "n": {"N": "7"}})
        app.receive(target, "dynamodb-actual-record", 90)
        app.controller.stop(kill_on_timeout=True)
        app.start()
        app.clients["kinesis"].put_record(StreamName=stream, PartitionKey="owned", Data=b"kinesis-resumed-record")
        app.clients["dynamodb"].put_item(TableName=table, Item={"pk": {"S": "dynamodb-resumed-record"}, "n": {"N": "8"}})
        app.receive(target, base64.b64encode(b"kinesis-resumed-record").decode(), 90)
        app.receive(target, "dynamodb-resumed-record", 90)
        for marker in (base64.b64encode(b"kinesis-actual-record").decode(), "dynamodb-actual-record"):
            require(sum(marker in row["Body"] for row in app.receipts[target["url"]]) == 1,
                    "acknowledged stream record replayed after restart: " + marker)
        app.advance(60)
        for event_name, event_source in (("CreateSchedule", "scheduler.amazonaws.com"), ("CreatePipe", "pipes.amazonaws.com")):
            records = app.clients["cloudtrail"].lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}])["Events"]
            projected = [json.loads(record["CloudTrailEvent"]) for record in records]
            require(projected and all(record["eventSource"] == event_source for record in projected),
                    "CloudTrail management projection source: " + event_name)
            app.report["observations"]["cloudtrail-" + event_name] = projected
        for namespace, metric, dimension, minimum in (
                ("AWS/Scheduler", "InvocationAttemptCount", "ScheduleGroup", 8),
                ("AWS/EventBridge/Pipes", "EventCount", "PipeName", 4)):
            result = app.clients["cloudwatch"].get_metric_statistics(
                Namespace=namespace, MetricName=metric,
                Dimensions=[{"Name": dimension, "Value": app.prefix}],
                StartTime=datetime(2026, 9, 26, 12, tzinfo=timezone.utc), EndTime=app.now() + timedelta(minutes=1),
                Period=60, Statistics=["Sum"])
            app.report["observations"][namespace + "/" + metric] = result
            require(sum(point["Sum"] for point in result["Datapoints"]) >= minimum,
                    "missing execution metric observations: " + namespace + "/" + metric)
        app.report["complete"] = True
    except Exception as error:
        app.report["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cleanup = []
        try:
            engines = owned_engine_specs(app)
        except Exception as error:
            engines = []
            cleanup.append("engine ownership snapshot: " + str(error))
        if app.controller.process and app.controller.process.poll() is None:
            for name in pipes:
                try:
                    app.clients["pipes"].delete_pipe(Name=name)
                except Exception as error:
                    cleanup.append(str(error))
            for name in functions:
                try:
                    app.clients["lambda"].delete_function(FunctionName=name)
                except Exception as error:
                    cleanup.append(str(error))
            for name in streams:
                try:
                    app.clients["kinesis"].delete_stream(StreamName=name, EnforceConsumerDeletion=True)
                except Exception as error:
                    cleanup.append(str(error))
            for name in tables:
                try:
                    app.clients["dynamodb"].delete_table(TableName=name)
                except Exception as error:
                    cleanup.append(str(error))
            try:
                app.advance(30)
            except Exception as error:
                cleanup.append(str(error))
        try:
            app.controller.stop(kill_on_timeout=True)
        finally:
            app.report["engine_cleanup"] = []
            for specification in engines:
                try:
                    app.report["engine_cleanup"].append(remove_owned_engine(app, specification))
                except Exception as error:
                    cleanup.append("physical engine cleanup: " + str(error))
            app.report["cleanup_errors"] = cleanup
            (app.state / "report.json").write_text(json.dumps(app.report, indent=2, default=str) + "\n")
            print(json.dumps({"report": str(app.state / "report.json"), "complete": app.report.get("complete", False),
                "failure": app.report.get("failure"), "cleanup_errors": cleanup}))
            require(not cleanup, "owned runtime cleanup failed: " + "; ".join(cleanup))


if __name__ == "__main__":
    main()
