#!/usr/bin/env python3
"""Signed SDK workflow against one actual isolated stackd executable and SQLite."""
import argparse
import gzip
import io
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--telemetry-directory", default="")
    args = parser.parse_args()
    state = Path(args.state_directory).resolve()
    state.mkdir(parents=True, exist_ok=True)
    require(not any(state.iterdir()), "fresh owned state directory required")
    with socket.socket() as listener:
        listener.bind(("0.0.0.0", 0))
        port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true")
    controller = StackdProcess(state)
    report = {"observations": {}, "controllers": controller.runs, "cleanup": []}
    name = "stackd-next-config-local-" + uuid.uuid4().hex[:8]
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1")
    clients = {s: session.client(s, endpoint_url=endpoint, config=Config(retries={"max_attempts": 0}, read_timeout=120, s3={"addressing_style": "path"})) for s in ("config", "iam", "s3", "sqs", "sns", "lambda", "sts")}
    config, iam, s3, sqs, sns, functions = [clients[s] for s in ("config", "iam", "s3", "sqs", "sns", "lambda")]
    bucket = queue_url = notices_url = topic_arn = function_arn = actor_key = None
    role_names = []
    rules = []
    def save():
        (state / "report.json").write_text(json.dumps(report, default=str, indent=2) + "\n")
    def start():
        command = [str(Path(args.binary).resolve()), "-listen", f"0.0.0.0:{port}", "-public-endpoint", endpoint, "-database", str(state / "state.sqlite"), "-clock-start", "2026-09-28T12:00:00Z", "-docker-host", args.docker_host, "-compute-endpoint", f"http://host.docker.internal:{port}"]
        if args.telemetry_directory:
            command += ["-lambda-telemetry-directory", args.telemetry_directory]
        controller.start(command, endpoint, environment=environment)
    def stop():
        controller.stop(timeout=45)
        save()
    def control(path, payload=None):
        req = urllib.request.Request(endpoint + path, data=json.dumps(payload or {}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as response:
            return json.load(response)
    def drain():
        return control("/_stackd/jobs/drain?limit=1024")
    def advance(seconds):
        control("/_stackd/clock", {"advance": f"{seconds}s"})
        return drain()
    def wait(fn, description, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = fn()
            if value:
                return value
            advance(1)
            time.sleep(.1)
        raise TimeoutError(description)
    def error(fn, code):
        try:
            fn()
        except ClientError as exc:
            require(exc.response["Error"]["Code"] == code, str(exc))
            return exc.response["Error"]
        raise AssertionError("expected " + code)
    def role(suffix, principal, statements):
        role_name = name + suffix
        arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        role_names.append(role_name)
        iam.put_role_policy(RoleName=role_name, PolicyName="owned", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
        return arn
    def history():
        return config.get_resource_config_history(resourceType="AWS::SQS::Queue", resourceId=resource_id, chronologicalOrder="Forward")["configurationItems"]
    def all_notifications():
        out = []
        while True:
            batch = sqs.receive_message(QueueUrl=notices_url, MaxNumberOfMessages=10).get("Messages", [])
            if not batch:
                return out
            for message in batch:
                body = json.loads(message["Body"])
                out.append(json.loads(body["Message"]))
                sqs.delete_message(QueueUrl=notices_url, ReceiptHandle=message["ReceiptHandle"])
    try:
        start()
        account = clients["sts"].get_caller_identity()["Account"]
        report["observations"]["missing_recorder"] = error(lambda: config.start_configuration_recorder(ConfigurationRecorderName=name), "NoSuchConfigurationRecorderException")
        role_arn = role("-recorder", "config.amazonaws.com", [{"Effect": "Allow", "Action": ["sqs:GetQueueAttributes", "sqs:ListQueueTags", "sqs:ListQueues", "s3:*", "sns:Publish"], "Resource": "*"}])
        bucket = name + "-delivery"
        s3.create_bucket(Bucket=bucket)
        topic_arn = sns.create_topic(Name=name)["TopicArn"]
        notices_url = sqs.create_queue(QueueName=name + "-notices")["QueueUrl"]
        notices_arn = sqs.get_queue_attributes(QueueUrl=notices_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sqs.set_queue_attributes(QueueUrl=notices_url, Attributes={"Policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": notices_arn, "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
        sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=notices_arn)
        config.put_configuration_recorder(ConfigurationRecorder={"name": name, "roleARN": role_arn, "recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::SQS::Queue", "AWS::S3::Bucket"]}})
        config.put_delivery_channel(DeliveryChannel={"name": name, "s3BucketName": bucket, "s3KeyPrefix": "evidence", "snsTopicARN": topic_arn})
        report["observations"]["stopped_snapshot"] = error(lambda: config.deliver_config_snapshot(deliveryChannelName=name), "NoRunningConfigurationRecorderException")
        config.start_configuration_recorder(ConfigurationRecorderName=name)
        queue_url = sqs.create_queue(QueueName=name, tags={"environment": "dev"})["QueueUrl"]
        resource_id = f"https://sqs.us-east-1.amazonaws.com/{account}/{name}"
        initial = history()
        require(initial[-1]["configurationItemStatus"] == "ResourceDiscovered", "initial owner observation")
        sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"VisibilityTimeout": "45"})
        sqs.tag_queue(QueueUrl=queue_url, Tags={"environment": "prod"})
        changes = history()
        require(len(changes) == 3 and json.loads(changes[1]["configuration"])["VisibilityTimeout"] == "45" and changes[2]["tags"]["environment"] == "prod", "real owner changes not retained")
        report["observations"]["owner_history"] = changes
        first = config.get_resource_config_history(resourceType="AWS::SQS::Queue", resourceId=resource_id, chronologicalOrder="Forward", limit=1)
        second = config.get_resource_config_history(resourceType="AWS::SQS::Queue", resourceId=resource_id, chronologicalOrder="Forward", limit=1, nextToken=first["nextToken"])
        require(second["configurationItems"][0]["configurationStateId"] == changes[1]["configurationStateId"], "history page drift")
        managed = name + "-tags"
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "environment", "Value": "prod"}]})
        config.put_config_rule(ConfigRule={"ConfigRuleName": managed, "Source": {"Owner": "AWS", "SourceIdentifier": "REQUIRED_TAGS"}, "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]}, "InputParameters": json.dumps({"tag1Key": "environment", "tag1Value": "prod"})})
        rules.append(managed)
        drain()
        managed_results = config.get_compliance_details_by_config_rule(ConfigRuleName=managed)["EvaluationResults"]
        require(any(r["ComplianceType"] == "COMPLIANT" and r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] == bucket for r in managed_results), "managed required-tags evaluation")
        report["observations"]["managed_results"] = managed_results
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "environment", "Value": "dev"}]})
        drain()
        require(config.get_compliance_details_by_config_rule(ConfigRuleName=managed)["EvaluationResults"][0]["ComplianceType"] == "NON_COMPLIANT", "managed rule ignored owner tag transition")
        config.start_config_rules_evaluation(ConfigRuleNames=[managed])
        drain()
        report["observations"]["managed_reevaluation"] = config.describe_config_rule_evaluation_status(ConfigRuleNames=[managed])["ConfigRulesEvaluationStatus"]
        config.put_configuration_aggregator(ConfigurationAggregatorName=name, AccountAggregationSources=[{"AccountIds": [account], "AwsRegions": ["us-east-1"]}])
        aggregated = config.list_aggregate_discovered_resources(ConfigurationAggregatorName=name, ResourceType="AWS::SQS::Queue")
        require(any(i["ResourceId"] == resource_id for i in aggregated["ResourceIdentifiers"]), "aggregate did not read source Config history")
        report["observations"]["aggregate_resource"] = config.get_aggregate_resource_config(ConfigurationAggregatorName=name, ResourceIdentifier={"SourceAccountId": account, "SourceRegion": "us-east-1", "ResourceId": resource_id, "ResourceType": "AWS::SQS::Queue"})["ConfigurationItem"]
        # Actual runtime executes a signed PutEvaluations callback; no in-process handler.
        function_role = role("-lambda", "lambda.amazonaws.com", [{"Effect": "Allow", "Action": ["config:PutEvaluations", "logs:*"], "Resource": "*"}])
        code = "import boto3,json,os\nfrom datetime import datetime\ndef handler(event,context):\n i=json.loads(event['invokingEvent'])['configurationItem']\n c=boto3.client('config',endpoint_url=os.environ['AWS_ENDPOINT_URL'])\n return c.put_evaluations(Evaluations=[{'ComplianceResourceType':i['resourceType'],'ComplianceResourceId':i['resourceId'],'ComplianceType':'COMPLIANT' if i.get('tags',{}).get('environment')=='prod' else 'NON_COMPLIANT','OrderingTimestamp':datetime.fromisoformat(i['configurationItemCaptureTime'].replace('Z','+00:00'))}],ResultToken=event['resultToken'])\n"
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("handler.py", code)
        function_arn = functions.create_function(FunctionName=name, Runtime="python3.13", Handler="handler.handler", Role=function_role, Code={"ZipFile": package.getvalue()}, Timeout=30, Environment={"Variables": {"AWS_ENDPOINT_URL": f"http://host.docker.internal:{port}"}})["FunctionArn"]
        def active():
            configuration = functions.get_function_configuration(FunctionName=function_arn)
            report["observations"]["lambda_state"] = {k: configuration.get(k) for k in ("State", "StateReason", "StateReasonCode")}
            return configuration.get("State") == "Active"
        wait(active, "Lambda active")
        functions.add_permission(FunctionName=function_arn, StatementId="config", Action="lambda:InvokeFunction", Principal="config.amazonaws.com", SourceAccount=account)
        custom = name + "-custom"
        config.put_config_rule(ConfigRule={"ConfigRuleName": custom, "Source": {"Owner": "CUSTOM_LAMBDA", "SourceIdentifier": function_arn, "SourceDetails": [{"EventSource": "aws.config", "MessageType": "ConfigurationItemChangeNotification"}]}, "Scope": {"ComplianceResourceTypes": ["AWS::SQS::Queue"]}})
        rules.append(custom)
        drain()
        custom_results = wait(lambda: config.get_compliance_details_by_config_rule(ConfigRuleName=custom).get("EvaluationResults"), "actual Lambda results")
        require(any(r["ComplianceType"] == "COMPLIANT" and r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] == resource_id for r in custom_results), "custom runtime did not publish compliance")
        report["observations"]["custom_lambda_results"] = custom_results
        snapshot = config.deliver_config_snapshot(deliveryChannelName=name)["configSnapshotId"]
        stop()
        start()
        drain()
        retained = history()
        require(retained == changes, "history differs across executable restart")
        report["observations"]["retained_after_restart"] = retained
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        snapshot_key = next(o["Key"] for o in objects if snapshot in o["Key"])
        data = json.loads(gzip.decompress(s3.get_object(Bucket=bucket, Key=snapshot_key)["Body"].read()))
        require(any(i["resourceId"] == resource_id and i["configuration"]["VisibilityTimeout"] == "45" for i in data["configurationItems"]), "snapshot does not contain actual owner configuration")
        report["observations"]["snapshot"] = data
        notifications = all_notifications()
        require(any(n["messageType"] == "ConfigurationItemChangeNotification" and n["configurationItem"]["resourceId"] == resource_id for n in notifications), "actual SNS-to-SQS notification missing")
        report["observations"]["sns_notifications"] = notifications
        west = session.client("config", endpoint_url=endpoint, region_name="us-west-2", config=Config(retries={"max_attempts": 0}))
        require(west.describe_configuration_recorders()["ConfigurationRecorders"] == [], "regional isolation")
        report["observations"]["regional_history_error"] = error(lambda: west.get_resource_config_history(resourceType="AWS::SQS::Queue", resourceId=resource_id), "ResourceNotDiscoveredException")
        iam.create_user(UserName=name)
        actor_key = iam.create_access_key(UserName=name)["AccessKey"]
        actor = boto3.client("config", endpoint_url=endpoint, region_name="us-east-1", aws_access_key_id=actor_key["AccessKeyId"], aws_secret_access_key=actor_key["SecretAccessKey"], config=Config(retries={"max_attempts": 0}))
        report["observations"]["caller_iam_denial"] = error(lambda: actor.describe_configuration_recorders(), "AccessDeniedException")
        before_denial = history()
        iam.put_role_policy(RoleName=name + "-recorder", PolicyName="deny", PolicyDocument=json.dumps({"Statement": [{"Effect": "Deny", "Action": "sqs:GetQueueAttributes", "Resource": "*"}]}))
        sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"VisibilityTimeout": "60"})
        require(history() == before_denial, "denied collection recorded unauthorized owner state")
        require(sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"] == "60", "Config denial rolled back source owner")
        report["observations"]["recorder_role_denial"] = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        iam.delete_role_policy(RoleName=name + "-recorder", PolicyName="deny")
        sqs.tag_queue(QueueUrl=queue_url, Tags={"capture": "restored"})
        require(json.loads(history()[-1]["configuration"])["VisibilityTimeout"] == "60", "current authority restore failed")
        sqs.delete_queue(QueueUrl=queue_url)
        queue_url = None
        deleted = history()
        require(deleted[-1]["configurationItemStatus"] == "ResourceDeleted", "owner deletion was not recorded")
        report["observations"]["deleted_history"] = deleted
        config.stop_configuration_recorder(ConfigurationRecorderName=name)
        config.delete_delivery_channel(DeliveryChannelName=name)
        config.delete_configuration_recorder(ConfigurationRecorderName=name)
        require(history() == deleted, "deleting recorder erased history")
        report["observations"]["deleted_recorder_history_retained"] = True
        save()
    except Exception as exc:
        report["failure"] = str(exc)
        raise
    finally:
        if controller.process is not None and controller.process.poll() is None:
            def cleanup(label, fn):
                try:
                    fn()
                    report["cleanup"].append({"resource": label, "deleted": True})
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code not in ("NoSuchConfigurationRecorderException", "NoSuchDeliveryChannelException", "NoSuchEntity"):
                        report["cleanup"].append({"resource": label, "error": code})
            cleanup("recorder-stop", lambda: config.stop_configuration_recorder(ConfigurationRecorderName=name))
            cleanup("delivery-channel", lambda: config.delete_delivery_channel(DeliveryChannelName=name))
            cleanup("recorder", lambda: config.delete_configuration_recorder(ConfigurationRecorderName=name))
            for rule_name in rules:
                cleanup(rule_name, lambda n=rule_name: config.delete_config_rule(ConfigRuleName=n))
            if function_arn:
                cleanup(function_arn, lambda: functions.delete_function(FunctionName=function_arn))
            for url in (queue_url, notices_url):
                if url:
                    cleanup(url, lambda u=url: sqs.delete_queue(QueueUrl=u))
            if topic_arn:
                cleanup(topic_arn, lambda: sns.delete_topic(TopicArn=topic_arn))
            if bucket:
                for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                    cleanup(obj["Key"], lambda k=obj["Key"]: s3.delete_object(Bucket=bucket, Key=k))
                cleanup(bucket, lambda: s3.delete_bucket(Bucket=bucket))
            cleanup("aggregator", lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=name))
            if actor_key:
                cleanup("actor-key", lambda: iam.delete_access_key(UserName=name, AccessKeyId=actor_key["AccessKeyId"]))
                cleanup("actor", lambda: iam.delete_user(UserName=name))
            for role_name in role_names:
                for policy in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                    cleanup(role_name + "/" + policy, lambda r=role_name, p=policy: iam.delete_role_policy(RoleName=r, PolicyName=p))
                cleanup(role_name, lambda r=role_name: iam.delete_role(RoleName=r))
        stop()
        save()
    require(not any("error" in c for c in report["cleanup"]), "owned cleanup failed")
    print(json.dumps({"report": str(state / "report.json"), "controllers": report["controllers"], "configuration_history": True, "s3_snapshot": True, "sns_delivery": True, "real_lambda_rule": True, "restart": True}))


if __name__ == "__main__":
    main()
