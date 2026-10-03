#!/usr/bin/env python3
"""Capture native Config behavior without modifying an existing regional singleton.

Read-only by default. --mutate requires explicit coordinator clearance and an
empty region; cleanup addresses only resources created by this invocation.
"""
import argparse
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

SOURCES = [
    "https://docs.aws.amazon.com/config/latest/APIReference/API_PutConfigurationRecorder.html",
    "https://docs.aws.amazon.com/config/latest/APIReference/API_PutDeliveryChannel.html",
    "https://docs.aws.amazon.com/config/latest/APIReference/API_GetResourceConfigHistory.html",
    "https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html",
    "https://docs.aws.amazon.com/config/latest/developerguide/sns-topic-policy.html",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--out", "--output", dest="out", default=".stackd/probes/configservice/baseline.json")
    parser.add_argument("--mutate", action="store_true")
    parser.add_argument("--clearance", default="", help="Coordinator authorization reference")
    parser.add_argument("--wait-seconds", type=int, default=900)
    args = parser.parse_args()
    session = boto3.Session(region_name=args.region)
    clients = {name: session.client(name, config=Config(
        retries={"max_attempts": 0}, connect_timeout=10, read_timeout=40,
        parameter_validation=False)) for name in ("sts", "config", "iam", "s3", "sns", "sqs")}
    capture = {"started_at": datetime.now(timezone.utc).isoformat(), "region": args.region,
               "sdk": {"boto3": boto3.__version__}, "sources": SOURCES,
               "calls": [], "ownership": {}, "observations": {}, "cleanup": []}
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    credentials = session.get_credentials().get_frozen_credentials()
    secrets = [v for v in (credentials.access_key, credentials.secret_key, credentials.token) if v]

    def save():
        text = json.dumps(capture, indent=2, default=str)
        for secret in secrets:
            text = text.replace(secret, "<redacted-credential>")
        path.write_text(text + "\n")

    def call(label, service, operation, *, optional=False, **parameters):
        row = {"label": label, "service": service, "operation": operation,
               "parameters": parameters, "at": datetime.now(timezone.utc).isoformat()}
        capture["calls"].append(row)
        try:
            result = getattr(clients[service], operation)(**parameters)
            if "Body" in result and hasattr(result["Body"], "read"):
                body = result.pop("Body").read()
                result["Body"] = json.loads(gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body)
            for message in result.get("Messages", []):
                message.pop("ReceiptHandle", None)
            row.update(code="Success", output=result)
            return result
        except ClientError as error:
            row.update(code=error.response["Error"]["Code"], error=error.response)
            if not optional:
                raise
            return error.response
        finally:
            save()

    def baseline(region):
        client = session.client("config", region_name=region)
        return {"recorders": client.describe_configuration_recorders(),
                "channels": client.describe_delivery_channels(),
                "status": client.describe_configuration_recorder_status()}

    identity = call("identity", "sts", "get_caller_identity")
    if identity["Account"] != args.account:
        raise RuntimeError("Probe authorized only for account " + args.account)
    capture["identity"] = identity
    capture["baseline"] = {"us-east-1": baseline("us-east-1"), args.region: baseline(args.region)}
    save()
    if not args.mutate:
        print(json.dumps({"capture": str(path), "read_only": True}))
        return
    if not args.clearance or args.region == "us-east-1":
        raise RuntimeError("Mutation requires explicit clearance and a non-baseline region")
    selected = capture["baseline"][args.region]
    if selected["recorders"].get("ConfigurationRecorders") or selected["channels"].get("DeliveryChannels"):
        raise RuntimeError("Refusing to mutate an existing regional Config singleton")
    capture["clearance"] = args.clearance
    prefix = "stackd-next-config-" + uuid.uuid4().hex[:10]
    capture["prefix"] = prefix
    owned = capture["ownership"]
    recorder_name = prefix
    channel_name = prefix
    role_arn = f"arn:aws:iam::{args.account}:role/{prefix}"
    bucket = prefix + "-delivery"
    resource_bucket = prefix + "-resource"
    topic_arn = f"arn:aws:sns:{args.region}:{args.account}:{prefix}"
    recorder = {"name": recorder_name, "roleARN": role_arn,
                "recordingGroup": {"allSupported": False, "includeGlobalResourceTypes": False,
                                   "resourceTypes": ["AWS::SQS::Queue", "AWS::S3::Bucket"]}}
    channel = {"name": channel_name, "s3BucketName": bucket, "s3KeyPrefix": "evidence",
               "snsTopicARN": topic_arn, "configSnapshotDeliveryProperties": {"deliveryFrequency": "One_Hour"}}

    def create_bucket(name):
        parameters = {"Bucket": name}
        if args.region != "us-east-1":
            parameters["CreateBucketConfiguration"] = {"LocationConstraint": args.region}
        call("create-" + name, "s3", "create_bucket", **parameters)
        owned.setdefault("buckets", []).append(name)
        save()
        call("tag-" + name, "s3", "put_bucket_tagging", Bucket=name,
             Tagging={"TagSet": [{"Key": "stackd-probe", "Value": prefix}]})

    def history(resource_type, resource_id, label):
        return call(label, "config", "get_resource_config_history", optional=True,
                    resourceType=resource_type, resourceId=resource_id, chronologicalOrder="Forward",
                    earlierTime=datetime.fromisoformat(capture["started_at"]),
                    laterTime=datetime.now(timezone.utc))

    def wait_history(resource_type, resource_id, label, predicate):
        deadline = time.monotonic() + args.wait_seconds
        while True:
            result = history(resource_type, resource_id, label)
            items = result.get("configurationItems", [])
            if predicate(items):
                capture["observations"][label] = result
                save()
                return items
            if time.monotonic() >= deadline:
                capture["observations"][label] = {"not_observed_seconds": args.wait_seconds}
                save()
                return []
            time.sleep(20)

    try:
        call("start-missing-recorder", "config", "start_configuration_recorder", optional=True,
             ConfigurationRecorderName=recorder_name)
        call("delete-missing-recorder", "config", "delete_configuration_recorder", optional=True,
             ConfigurationRecorderName=recorder_name)
        call("snapshot-missing-channel", "config", "deliver_config_snapshot", optional=True,
             deliveryChannelName=channel_name)
        call("channel-before-recorder", "config", "put_delivery_channel", optional=True,
             DeliveryChannel=channel)
        call("recorder-missing-role", "config", "put_configuration_recorder", optional=True,
             ConfigurationRecorder={"name": recorder_name})
        call("create-role", "iam", "create_role", RoleName=prefix,
             AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                 "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"},
                 "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"AWS:SourceAccount": args.account}}}]}),
             Tags=[{"Key": "stackd-probe", "Value": prefix}])
        owned["role"] = prefix
        save()
        role_policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["sqs:ListQueues", "sqs:GetQueueAttributes", "sqs:ListQueueTags",
                "s3:ListAllMyBuckets", "s3:GetBucket*", "s3:ListBucket",
                "s3:GetAccelerateConfiguration", "s3:GetEncryptionConfiguration",
                "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration",
                "config:BatchGet*", "config:Describe*", "config:Get*", "config:List*",
                "config:Put*", "config:Select*", "tag:GetResources"], "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn}]}
        call("role-policy", "iam", "put_role_policy", RoleName=prefix, PolicyName="capture",
             PolicyDocument=json.dumps(role_policy))
        time.sleep(12)
        call("put-recorder", "config", "put_configuration_recorder", ConfigurationRecorder=recorder)
        owned["recorder"] = recorder_name
        save()
        call("describe-recorder", "config", "describe_configuration_recorders")
        call("start-without-channel", "config", "start_configuration_recorder", optional=True,
             ConfigurationRecorderName=recorder_name)
        call("channel-missing-bucket", "config", "put_delivery_channel", optional=True,
             DeliveryChannel=channel)
        create_bucket(bucket)
        create_bucket(resource_bucket)
        call("create-topic", "sns", "create_topic", Name=prefix,
             Tags=[{"Key": "stackd-probe", "Value": prefix}])
        owned["topic"] = topic_arn
        save()
        queue = call("create-notification-queue", "sqs", "create_queue", QueueName=prefix + "-notifications",
                     tags={"stackd-probe": prefix})["QueueUrl"]
        owned["notification_queue"] = queue
        save()
        queue_arn = call("notification-queue-arn", "sqs", "get_queue_attributes", QueueUrl=queue,
                         AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        call("notification-queue-policy", "sqs", "set_queue_attributes", QueueUrl=queue,
             Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{
                 "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                 "Action": "sqs:SendMessage", "Resource": queue_arn,
                 "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
        subscription = call("subscribe-notifications", "sns", "subscribe", TopicArn=topic_arn,
                            Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
        owned["subscription"] = subscription
        save()
        call("put-channel", "config", "put_delivery_channel", DeliveryChannel=channel)
        owned["channel"] = channel_name
        save()
        call("describe-channel", "config", "describe_delivery_channels")
        call("snapshot-stopped-recorder", "config", "deliver_config_snapshot", optional=True,
             deliveryChannelName=channel_name)
        call("start-recorder", "config", "start_configuration_recorder", ConfigurationRecorderName=recorder_name)
        call("delete-channel-recording", "config", "delete_delivery_channel", optional=True,
             DeliveryChannelName=channel_name)
        observed = call("create-observed-queue", "sqs", "create_queue", QueueName=prefix + "-resource",
                        Attributes={"VisibilityTimeout": "37"}, tags={"stackd-probe": prefix})["QueueUrl"]
        owned["resource_queue"] = observed
        save()
        call("observed-queue-arn", "sqs", "get_queue_attributes", QueueUrl=observed,
             AttributeNames=["QueueArn"])
        wait_history("AWS::SQS::Queue", observed, "queue-created", lambda items: bool(items))
        wait_history("AWS::S3::Bucket", resource_bucket, "bucket-created", lambda items: bool(items))
        call("change-observed-queue", "sqs", "set_queue_attributes", QueueUrl=observed,
             Attributes={"VisibilityTimeout": "43"})
        call("tag-observed-queue", "sqs", "tag_queue", QueueUrl=observed,
             Tags={"capture-stage": "changed"})
        call("change-observed-bucket", "s3", "put_bucket_versioning", Bucket=resource_bucket,
             VersioningConfiguration={"Status": "Enabled"})
        wait_history("AWS::SQS::Queue", observed, "queue-changed",
                     lambda items: any(json.loads(item.get("configuration") or "null").get("VisibilityTimeout") == "43"
                                       and item.get("tags", {}).get("capture-stage") == "changed"
                                       for item in items if item.get("configuration") not in (None, "", "null")))
        wait_history("AWS::S3::Bucket", resource_bucket, "bucket-changed",
                     lambda items: any("Enabled" in json.dumps(item) for item in items))
        call("delete-observed-queue", "sqs", "delete_queue", QueueUrl=observed)
        call("delete-observed-bucket", "s3", "delete_bucket", Bucket=resource_bucket)
        wait_history("AWS::SQS::Queue", observed, "queue-deleted",
                     lambda items: any(item["configurationItemStatus"] == "ResourceDeleted" for item in items))
        wait_history("AWS::S3::Bucket", resource_bucket, "bucket-deleted",
                     lambda items: any(item["configurationItemStatus"] == "ResourceDeleted" for item in items))
        call("deliver-snapshot", "config", "deliver_config_snapshot", deliveryChannelName=channel_name)
        deadline = time.monotonic() + args.wait_seconds
        while True:
            objects = call("list-delivered-objects", "s3", "list_objects_v2", Bucket=bucket).get("Contents", [])
            if any("ConfigSnapshot" in obj["Key"] and obj["Size"] for obj in objects):
                break
            if time.monotonic() >= deadline:
                capture["observations"]["snapshot_not_observed_seconds"] = args.wait_seconds
                break
            time.sleep(20)
        for obj in objects:
            call("delivered-object-head", "s3", "head_object", Bucket=bucket, Key=obj["Key"])
            call("delivered-object-acl", "s3", "get_object_acl", Bucket=bucket, Key=obj["Key"])
            if obj["Size"]:
                call("delivered-object", "s3", "get_object", Bucket=bucket, Key=obj["Key"])
        call("delivered-notifications", "sqs", "receive_message", QueueUrl=queue, MaxNumberOfMessages=10,
             WaitTimeSeconds=20, MessageAttributeNames=["All"])
        call("recorder-status", "config", "describe_configuration_recorder_status")
        call("channel-status", "config", "describe_delivery_channel_status")
        call("stop-recorder", "config", "stop_configuration_recorder", ConfigurationRecorderName=recorder_name)
    except BaseException as error:
        capture["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        def cleanup(label, service, operation, **parameters):
            result = call("cleanup-" + label, service, operation, optional=True, **parameters)
            # Native Config throttled recorder deletion immediately after
            # Stop/DeleteChannel; retain each failure and finish owned cleanup.
            for delay in (2, 4, 8):
                if result.get("Error", {}).get("Code") != "ThrottlingException":
                    break
                time.sleep(delay)
                result = call("cleanup-" + label, service, operation, optional=True, **parameters)
            capture["cleanup"].append({"resource": label, "operation": operation,
                                        "code": result.get("Error", {}).get("Code", "Success")})
            save()
        if owned.get("recorder"):
            cleanup("stop", "config", "stop_configuration_recorder", ConfigurationRecorderName=owned["recorder"])
        if owned.get("channel"):
            cleanup("channel", "config", "delete_delivery_channel", DeliveryChannelName=owned["channel"])
        if owned.get("recorder"):
            cleanup("recorder", "config", "delete_configuration_recorder", ConfigurationRecorderName=owned["recorder"])
        if owned.get("subscription"):
            cleanup("subscription", "sns", "unsubscribe", SubscriptionArn=owned["subscription"])
        if owned.get("topic"):
            cleanup("topic", "sns", "delete_topic", TopicArn=owned["topic"])
        for key in ("resource_queue", "notification_queue"):
            if owned.get(key):
                cleanup(key, "sqs", "delete_queue", QueueUrl=owned[key])
        for name in owned.get("buckets", []):
            objects = call("cleanup-list-" + name, "s3", "list_objects_v2", optional=True, Bucket=name)
            for obj in objects.get("Contents", []):
                cleanup("object", "s3", "delete_object", Bucket=name, Key=obj["Key"])
            cleanup(name, "s3", "delete_bucket", Bucket=name)
        if owned.get("role"):
            cleanup("role-policy", "iam", "delete_role_policy", RoleName=owned["role"], PolicyName="capture")
            cleanup("role", "iam", "delete_role", RoleName=owned["role"])
        capture["final_config_state"] = baseline(args.region)
        checks = []
        for name in owned.get("buckets", []):
            checks.append(("bucket", "s3", "head_bucket", {"Bucket": name}, {"404", "NoSuchBucket"}))
        for key in ("resource_queue", "notification_queue"):
            if owned.get(key):
                checks.append((key, "sqs", "get_queue_url",
                               {"QueueName": owned[key].rsplit("/", 1)[-1]},
                               {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}))
        if owned.get("role"):
            checks.append(("role", "iam", "get_role", {"RoleName": owned["role"]}, {"NoSuchEntity"}))
        if owned.get("topic"):
            checks.append(("topic", "sns", "get_topic_attributes",
                           {"TopicArn": owned["topic"]}, {"NotFound"}))
        capture["absence_checks"] = []
        for label, service, operation, parameters, absent in checks:
            result = call("absence-" + label, service, operation, optional=True, **parameters)
            capture["absence_checks"].append({"resource": label, "parameters": parameters,
                                             "absent": result.get("Error", {}).get("Code") in absent})
        capture["cleanup_complete"] = (
            not capture["final_config_state"]["recorders"].get("ConfigurationRecorders")
            and not capture["final_config_state"]["channels"].get("DeliveryChannels")
            and all(check["absent"] for check in capture["absence_checks"]))
        capture["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
        print(json.dumps({"capture": str(path), "prefix": prefix, "failure": capture.get("failure"),
                          "final_recorders": capture["final_config_state"]["recorders"].get("ConfigurationRecorders"),
                          "final_channels": capture["final_config_state"]["channels"].get("DeliveryChannels")}))


if __name__ == "__main__":
    main()
