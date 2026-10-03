#!/usr/bin/env python3
"""Calibrate Scheduler/Pipes only through uniquely owned queues, roles and trail.

Run with PYTHONPATH including scripts/aws for the shared CloudTrail collector.
The capture retains native API outputs, errors and exact request IDs. Missing
CloudTrail/metrics observations are bounded non-observations, not native absence.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cloudtrail_events import CollectionError, collect_s3
from cloudtrail_service_probe import document

REGION = "us-east-1"


def verify_absence(clients, owned):
    """Read only exact owned identifiers; preserve native cleanup evidence."""
    checks = []
    if owned.get("group"):
        checks.append(("group", "scheduler", "get_schedule_group", {"Name": owned["group"]}, {"ResourceNotFoundException"}))
    if owned.get("pipe"):
        checks.append(("pipe", "pipes", "describe_pipe", {"Name": owned["pipe"]}, {"NotFoundException"}))
    if owned.get("trail"):
        checks.append(("trail", "cloudtrail", "get_trail", {"Name": owned["trail"]}, {"TrailNotFoundException"}))
    if owned.get("bucket"):
        checks.append(("bucket", "s3", "head_bucket", {"Bucket": owned["bucket"]}, {"404", "NoSuchBucket"}))
    for service, role in owned.get("roles", {}).items():
        checks.append(("role-" + service, "iam", "get_role", {"RoleName": role["RoleName"]}, {"NoSuchEntity"}))
    for kind, queue in owned.get("queues", {}).items():
        checks.append(("queue-" + kind, "sqs", "get_queue_url", {"QueueName": queue["name"]},
                       {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}))
    observations = []
    for label, service, operation, parameters, absent in checks:
        for attempt in range(30):
            try:
                response = getattr(clients[service], operation)(**parameters)
                observation = {"resource": label, "service": service, "operation": operation,
                    "parameters": parameters, "absent": False, "output": response}
            except ClientError as error:
                observation = {"resource": label, "service": service, "operation": operation,
                    "parameters": parameters, "absent": error.response["Error"]["Code"] in absent,
                    "error": error.response}
            observations.append(observation)
            if observation["absent"] or label not in ("group", "pipe"):
                break
            time.sleep(1)
    return observations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=".stackd/probes/scheduler_pipes/lifecycle.json")
    parser.add_argument("--trail-rounds", type=int, default=25)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    session = boto3.Session(region_name=REGION)
    clients = {name: session.client(name, config=Config(retries={"max_attempts": 0},
        connect_timeout=10, read_timeout=30, parameter_validation=False))
        for name in ("sts", "iam", "sqs", "scheduler", "pipes", "s3", "cloudtrail", "cloudwatch")}
    identity = clients["sts"].get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Probe is authorized only for account " + args.account)
    prefix = "stackd-sp-" + uuid.uuid4().hex[:12]
    start = datetime.now(timezone.utc)
    capture = {"started_at": start.isoformat(), "identity": identity, "region": REGION,
        "prefix": prefix, "ownership": {}, "calls": [], "observations": {}, "cleanup": [],
        "sources": ["https://docs.aws.amazon.com/scheduler/latest/UserGuide/logging-using-cloudtrail.html",
                    "https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_CreatePipe.html"],
        "boundary": "Only owned queues consumed. Missing observations are not absence evidence."}
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    secrets = session.get_credentials().get_frozen_credentials()
    secret_values = [value for value in (secrets.secret_key, secrets.token) if value]
    requests = {}
    owned = capture["ownership"]

    def save():
        text = json.dumps(document(capture), indent=2, default=str)
        for value in secret_values:
            text = text.replace(value, "<redacted-credential>")
        path.write_text(text + "\n")

    def call(label, service, operation, parameters=None, *, optional=False):
        parameters = parameters or {}
        row = {"label": label, "service": service, "operation": operation,
               "parameters": parameters, "at": datetime.now(timezone.utc).isoformat()}
        capture["calls"].append(row)
        try:
            response = getattr(clients[service], operation)(**parameters)
            row.update(code="Success", output=response)
        except ClientError as error:
            response = error.response
            row.update(code=response["Error"]["Code"], error=response)
            if not optional:
                save()
                raise
        finally:
            save()
        request_id = response.get("ResponseMetadata", {}).get("RequestId")
        if request_id:
            row["request_id"] = request_id
            requests[request_id] = label
        save()
        return response

    def wait_pipe(state, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = call("pipe-wait-" + state, "pipes", "describe_pipe", {"Name": prefix})
            if value["CurrentState"] == state:
                return value
            if value["CurrentState"].endswith("FAILED"):
                raise RuntimeError("Pipe entered " + value["CurrentState"] + ": " + value.get("StateReason", ""))
            time.sleep(3)
        raise RuntimeError("Pipe did not reach " + state + " within owned observation window")

    def receive(kind, marker, seconds=120):
        deadline = time.monotonic() + seconds
        for previous in capture["observations"].values():
            if isinstance(previous, list) and any(marker in row["Body"] for row in previous):
                capture["observations"][marker] = previous
                save()
                return previous
        found = []
        while time.monotonic() < deadline:
            result = call("receive-" + marker, "sqs", "receive_message", {
                "QueueUrl": owned["queues"][kind]["url"], "WaitTimeSeconds": 2,
                "MaxNumberOfMessages": 10, "MessageAttributeNames": ["All"],
                "MessageSystemAttributeNames": ["All"]})
            for message in result.get("Messages", []):
                found.append(message)
                call("ack-" + marker, "sqs", "delete_message", {
                    "QueueUrl": owned["queues"][kind]["url"], "ReceiptHandle": message["ReceiptHandle"]})
            if any(marker in message["Body"] for message in found):
                capture["observations"][marker] = found
                save()
                return found
        capture["observations"][marker] = {"not_observed_seconds": seconds, "received": found}
        save()
        raise RuntimeError("Owned target marker not observed: " + marker)

    def schedule(name, **overrides):
        value = {"Name": name, "GroupName": prefix, "ScheduleExpression": "rate(1 day)",
            "FlexibleTimeWindow": {"Mode": "OFF"}, "State": "DISABLED",
            "Target": {"Arn": owned["queues"]["target"]["arn"], "RoleArn": owned["roles"]["scheduler"]["Arn"],
                "Input": json.dumps({"marker": name}), "RetryPolicy": {"MaximumRetryAttempts": 0,
                "MaximumEventAgeInSeconds": 60}, "DeadLetterConfig": {"Arn": owned["queues"]["dlq"]["arn"]}}}
        value.update(overrides)
        return value

    save()
    try:
        owned["queues"] = {}
        for kind in ("source", "target", "dlq"):
            name = prefix + "-" + kind
            result = call("create-queue-" + kind, "sqs", "create_queue", {
                "QueueName": name, "Attributes": {"VisibilityTimeout": "5"}, "tags": {"stackd-probe": prefix}})
            owned["queues"][kind] = {"name": name, "url": result["QueueUrl"]}
            save()
            result = call("queue-arn-" + kind, "sqs", "get_queue_attributes", {
                "QueueUrl": result["QueueUrl"], "AttributeNames": ["QueueArn"]})
            owned["queues"][kind]["arn"] = result["Attributes"]["QueueArn"]
            save()
        bucket = prefix + "-audit"
        call("create-audit-bucket", "s3", "create_bucket", {"Bucket": bucket})
        owned["bucket"] = bucket
        save()
        trail_arn = f"arn:aws:cloudtrail:{REGION}:{args.account}:trail/{prefix}"
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::" + bucket,
             "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{args.account}/*",
             "Condition": {"StringEquals": {"aws:SourceArn": trail_arn, "s3:x-amz-acl": "bucket-owner-full-control"}}}]}
        call("audit-bucket-policy", "s3", "put_bucket_policy", {"Bucket": bucket, "Policy": json.dumps(policy)})
        call("create-owned-trail", "cloudtrail", "create_trail", {"Name": prefix,
             "S3BucketName": bucket, "IsMultiRegionTrail": False, "IncludeGlobalServiceEvents": False})
        owned["trail"] = prefix
        save()
        call("owned-trail-selectors", "cloudtrail", "put_event_selectors", {"TrailName": prefix,
            "AdvancedEventSelectors": [
                {"Name": "Management", "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management"]}]},
                {"Name": "OwnedQueueData", "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": ["AWS::SQS::Queue"]},
                    {"Field": "resources.ARN", "Equals": [q["arn"] for q in owned["queues"].values()]}]}]})
        call("start-owned-trail", "cloudtrail", "start_logging", {"Name": prefix})
        print(json.dumps({"owned_trail_started": prefix, "bucket": bucket}), flush=True)
        sentinels = {}
        sentinel_collection = None
        for attempt in range(25):
            label = "trail-readiness-sentinel-" + str(attempt)
            response = call(label, "sqs", "send_message", {
                "QueueUrl": owned["queues"]["dlq"]["url"], "MessageBody": prefix + "-readiness"})
            sentinels[response["ResponseMetadata"]["RequestId"]] = label
            time.sleep(30)
            try:
                sentinel_collection = collect_s3(lambda p: clients["s3"].list_objects_v2(**p),
                    lambda p: clients["s3"].get_object(**p), sentinels, bucket=bucket,
                    prefix=f"AWSLogs/{args.account}/CloudTrail/{REGION}/", rounds=1,
                    max_pages=10, previous=sentinel_collection)
            except CollectionError as error:
                capture["trail_readiness"] = error.result
                save()
                raise
            capture["trail_readiness"] = sentinel_collection
            save()
            if any(row["call_label"] and row["event"].get("eventCategory") == "Data"
                   for row in sentinel_collection["events"]):
                break
        else:
            raise RuntimeError("Owned exact-ID SQS data sentinel not observed within 25 x 30-second readiness bounds")
        owned["roles"] = {}
        for service in ("scheduler", "pipes"):
            source = f"arn:aws:scheduler:{REGION}:{args.account}:schedule-group/{prefix}" if service == "scheduler" else f"arn:aws:pipes:{REGION}:{args.account}:pipe/{prefix}"
            trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Principal": {"Service": service + ".amazonaws.com"}, "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": args.account}, "ArnEquals": {"aws:SourceArn": source}}}]}
            result = call("create-role-" + service, "iam", "create_role", {"RoleName": prefix + "-" + service,
                "AssumeRolePolicyDocument": json.dumps(trust), "Tags": [{"Key": "stackd-probe", "Value": prefix}]})
            owned["roles"][service] = result["Role"]
            save()
            permissions = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": [q["arn"] for q in owned["queues"].values()]}]}
            call("role-policy-" + service, "iam", "put_role_policy", {"RoleName": prefix + "-" + service,
                "PolicyName": "owned", "PolicyDocument": json.dumps(permissions)})
        time.sleep(12)
        call("create-group", "scheduler", "create_schedule_group", {"Name": prefix,
            "Tags": [{"Key": "stage", "Value": "probe"}]})
        owned["group"] = prefix
        owned["schedules"] = []
        save()
        group_arn = f"arn:aws:scheduler:{REGION}:{args.account}:schedule-group/{prefix}"
        call("get-group", "scheduler", "get_schedule_group", {"Name": prefix})
        call("group-tags", "scheduler", "list_tags_for_resource", {"ResourceArn": group_arn})
        call("tag-group", "scheduler", "tag_resource", {"ResourceArn": group_arn,
            "Tags": [{"Key": "probe", "Value": prefix}]})
        call("untag-group", "scheduler", "untag_resource", {"ResourceArn": group_arn, "TagKeys": ["stage"]})
        call("duplicate-group", "scheduler", "create_schedule_group", {"Name": prefix}, optional=True)
        basic = schedule("control")
        call("create-schedule", "scheduler", "create_schedule", basic)
        owned["schedules"].append("control")
        save()
        call("get-schedule", "scheduler", "get_schedule", {"Name": "control", "GroupName": prefix})
        call("duplicate-schedule", "scheduler", "create_schedule", basic, optional=True)
        for label, overrides in [
            ("invalid-cron", {"ScheduleExpression": "cron(* * * * * *)"}),
            ("invalid-zone", {"ScheduleExpressionTimezone": "Not/AZone"}),
            ("window-missing-size", {"FlexibleTimeWindow": {"Mode": "FLEXIBLE"}}),
            ("date-order", {"StartDate": start + timedelta(days=2), "EndDate": start + timedelta(days=1)}),
            ("missing-group", {"GroupName": prefix + "-absent"}),
            ("empty-input", {"Target": dict(basic["Target"], Input="")}),
            ("absent-input", {"Target": {k: v for k, v in basic["Target"].items() if k != "Input"}}),
            ("rate-plural", {"ScheduleExpression": "rate(1 minutes)"}),
            ("at-past", {"ScheduleExpression": "at(2020-01-01T00:00:00)"}),
            ("dst-gap", {"ScheduleExpression": "at(2027-03-14T02:30:00)", "ScheduleExpressionTimezone": "America/New_York"}),
            ("at-bounds", {"ScheduleExpression": "at(2027-01-01T00:00:00)", "StartDate": start + timedelta(days=1), "EndDate": start + timedelta(days=2)}),
        ]:
            name = "negative-" + label
            result = call(label, "scheduler", "create_schedule", schedule(name, **overrides), optional=True)
            if "ScheduleArn" in result:
                owned["schedules"].append(name)
                save()
        call("update-schedule", "scheduler", "update_schedule", schedule("control",
            ScheduleExpression="cron(30 1 * * ? *)", ScheduleExpressionTimezone="America/New_York",
            FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 5}))
        call("get-updated-schedule", "scheduler", "get_schedule", {"Name": "control", "GroupName": prefix})
        call("list-owned-schedules", "scheduler", "list_schedules", {"GroupName": prefix})
        call("get-missing-schedule", "scheduler", "get_schedule", {"Name": "missing", "GroupName": prefix}, optional=True)
        when = datetime.now(timezone.utc) + timedelta(seconds=90)
        call("create-at-delivery", "scheduler", "create_schedule", schedule("scheduled-delivery", State="ENABLED",
            ScheduleExpression="at(" + when.strftime("%Y-%m-%dT%H:%M:%S") + ")", ActionAfterCompletion="DELETE"))
        owned["schedules"].append("scheduled-delivery")
        save()
        pipe = {"Name": prefix, "RoleArn": owned["roles"]["pipes"]["Arn"],
            "Source": owned["queues"]["source"]["arn"], "Target": owned["queues"]["target"]["arn"],
            "DesiredState": "STOPPED", "Tags": {"stackd-probe": prefix},
            "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1},
                "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"body": {"keep": [True]}})}]}},
            "TargetParameters": {"InputTemplate": '{"marker":<$.body.marker>,"value":<$.body.value>}'}}
        call("create-pipe-stopped", "pipes", "create_pipe", pipe)
        owned["pipe"] = prefix
        save()
        wait_pipe("STOPPED")
        call("duplicate-pipe", "pipes", "create_pipe", pipe, optional=True)
        call("pipe-tags", "pipes", "list_tags_for_resource", {"resourceArn": f"arn:aws:pipes:{REGION}:{args.account}:pipe/{prefix}"})
        call("update-pipe", "pipes", "update_pipe", {"Name": prefix, "RoleArn": pipe["RoleArn"],
            "Description": "owned lifecycle capture", "DesiredState": "STOPPED"})
        wait_pipe("STOPPED")
        for marker, keep in (("filtered-drop", False), ("pipe-delivery", True)):
            call("send-" + marker, "sqs", "send_message", {"QueueUrl": owned["queues"]["source"]["url"],
                "MessageBody": json.dumps({"marker": marker, "keep": keep, "value": 7})})
        time.sleep(3)
        call("stopped-source-count", "sqs", "get_queue_attributes", {"QueueUrl": owned["queues"]["source"]["url"],
            "AttributeNames": ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]})
        call("start-pipe", "pipes", "start_pipe", {"Name": prefix})
        wait_pipe("RUNNING")
        receive("target", "pipe-delivery")
        call("stop-pipe", "pipes", "stop_pipe", {"Name": prefix})
        wait_pipe("STOPPED")
        call("post-filter-source-count", "sqs", "get_queue_attributes", {"QueueUrl": owned["queues"]["source"]["url"],
            "AttributeNames": ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]})
        receive("target", "scheduled-delivery", 180)
        call("completed-schedule", "scheduler", "get_schedule", {"Name": "scheduled-delivery", "GroupName": prefix}, optional=True)
        call("pipe-missing", "pipes", "describe_pipe", {"Name": prefix + "-missing"}, optional=True)
        call("delete-pipe", "pipes", "delete_pipe", {"Name": prefix})
        for _ in range(40):
            result = call("wait-pipe-deleted", "pipes", "describe_pipe", {"Name": prefix}, optional=True)
            if result.get("Error", {}).get("Code") == "NotFoundException":
                owned["pipe_deleted"] = True
                break
            time.sleep(3)
        capture["workflow_complete"] = True
        save()
        wanted = {rid: label for rid, label in requests.items() if any(
            row.get("request_id") == rid and row["service"] in ("scheduler", "pipes") for row in capture["calls"])}
        try:
            capture["cloudtrail"] = collect_s3(lambda p: clients["s3"].list_objects_v2(**p),
                lambda p: clients["s3"].get_object(**p), wanted, bucket=bucket,
                prefix=f"AWSLogs/{args.account}/CloudTrail/{REGION}/", rounds=args.trail_rounds,
                wait_seconds=30, max_pages=10, related=lambda event: any(q["arn"] in json.dumps(event)
                    for q in owned["queues"].values()) or prefix in json.dumps(event))
        except CollectionError as error:
            capture["cloudtrail"] = error.result
            save()
            raise
        for namespace, dimension, value, names in [
            ("AWS/Scheduler", "ScheduleGroup", prefix, ["InvocationAttemptCount", "TargetErrorCount", "InvocationDroppedCount"]),
            ("AWS/EventBridge/Pipes", "PipeName", prefix, ["EventCount", "Invocations", "Duration", "ExecutionFailed"])]:
            for metric in names:
                call("metric-" + metric, "cloudwatch", "get_metric_statistics", {"Namespace": namespace,
                    "MetricName": metric, "Dimensions": [{"Name": dimension, "Value": value}],
                    "StartTime": start - timedelta(minutes=1), "EndTime": datetime.now(timezone.utc) + timedelta(minutes=1),
                    "Period": 60, "Statistics": ["Sum"]})
        save()
    except Exception as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        save()
        raise
    finally:
        def cleanup(label, service, operation, params, absent=()):
            try:
                result = call("cleanup-" + label, service, operation, params, optional=True)
                code = result.get("Error", {}).get("Code")
                capture["cleanup"].append({"label": label, "ok": code is None or code in absent, "code": code})
            except Exception as error:
                capture["cleanup"].append({"label": label, "ok": False, "error": str(error)})
            save()
        if owned.get("pipe") and not owned.get("pipe_deleted"):
            cleanup("pipe", "pipes", "delete_pipe", {"Name": prefix}, ("NotFoundException",))
            for _ in range(40):
                result = call("cleanup-pipe-absence", "pipes", "describe_pipe", {"Name": prefix}, optional=True)
                if result.get("Error", {}).get("Code") == "NotFoundException":
                    owned["pipe_deleted"] = True
                    break
                time.sleep(3)
        for name in owned.get("schedules", []):
            cleanup("schedule-" + name, "scheduler", "delete_schedule", {"Name": name, "GroupName": prefix}, ("ResourceNotFoundException",))
        if owned.get("group"):
            cleanup("group", "scheduler", "delete_schedule_group", {"Name": prefix}, ("ResourceNotFoundException",))
        if owned.get("trail"):
            cleanup("stop-trail", "cloudtrail", "stop_logging", {"Name": prefix})
            cleanup("trail", "cloudtrail", "delete_trail", {"Name": prefix})
        for service, role in owned.get("roles", {}).items():
            cleanup("role-policy-" + service, "iam", "delete_role_policy", {"RoleName": role["RoleName"], "PolicyName": "owned"}, ("NoSuchEntity",))
            cleanup("role-" + service, "iam", "delete_role", {"RoleName": role["RoleName"]}, ("NoSuchEntity",))
        for kind, queue in owned.get("queues", {}).items():
            cleanup("queue-" + kind, "sqs", "delete_queue", {"QueueUrl": queue["url"]}, ("AWS.SimpleQueueService.NonExistentQueue",))
            result = call("verify-queue-absent-" + kind, "sqs", "get_queue_url", {"QueueName": queue["name"]}, optional=True)
            capture["cleanup"].append({"label": "verify-queue-" + kind,
                "ok": result.get("Error", {}).get("Code") == "AWS.SimpleQueueService.NonExistentQueue"})
        if owned.get("bucket"):
            try:
                for page in clients["s3"].get_paginator("list_objects_v2").paginate(Bucket=owned["bucket"]):
                    objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
                    if objects:
                        cleanup("audit-objects", "s3", "delete_objects", {"Bucket": owned["bucket"], "Delete": {"Objects": objects}})
                cleanup("audit-bucket", "s3", "delete_bucket", {"Bucket": owned["bucket"]})
            except Exception as error:
                capture["cleanup"].append({"label": "audit-bucket", "ok": False, "error": str(error)})
        capture["absence_verification"] = verify_absence(clients, owned)
        capture["finished_at"] = datetime.now(timezone.utc).isoformat()
        absent = {row["resource"]: row["absent"] for row in capture["absence_verification"]}
        capture["cleanup_complete"] = bool(absent) and all(absent.values())
        save()
        print(json.dumps({"capture": str(path), "prefix": prefix, "workflow_complete": capture.get("workflow_complete", False),
                          "cleanup_complete": capture["cleanup_complete"], "failure": capture.get("failure")}))


if __name__ == "__main__":
    main()
