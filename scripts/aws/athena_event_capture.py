"""Owned EventBridge-to-SQS observer for the analytics application native probe."""
import json
import time

from glue_native_common import require


def install(cap, job, database, workgroup):
    queue_name = cap.prefix + "-events"
    queue_url = require(cap.request("create-event-queue", "sqs", "create-queue", {"QueueName": queue_name, "Attributes": {"MessageRetentionPeriod": "3600"}}))["QueueUrl"]
    state = {"queue_name": queue_name, "queue_url": queue_url, "rules": []}
    cap.capture["event_resources"] = state
    queue_arn = require(cap.request("event-queue-arn", "sqs", "get-queue-attributes", {"QueueUrl": queue_url, "AttributeNames": ["QueueArn"]}))["Attributes"]["QueueArn"]
    patterns = [
        ("glue-job", {"source": ["aws.glue"], "detail": {"jobName": [job]}}),
        ("glue-catalog", {"source": ["aws.glue"], "detail": {"databaseName": [database]}}),
        ("athena", {"source": ["aws.athena"], "detail": {"workgroupName": [workgroup]}}),
    ]
    for suffix, pattern in patterns:
        name = cap.prefix + "-" + suffix
        state["rules"].append(name)
        require(cap.request("create-event-rule-" + suffix, "events", "put-rule", {"Name": name, "EventPattern": json.dumps(pattern), "State": "ENABLED"}))
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": [f"arn:aws:events:us-east-1:{cap.account}:rule/{name}" for name in state["rules"]]}}}]}
    require(cap.request("event-queue-policy", "sqs", "set-queue-attributes", {"QueueUrl": queue_url, "Attributes": {"Policy": json.dumps(policy)}}))
    for name in state["rules"]:
        require(cap.request("attach-event-target", "events", "put-targets", {"Rule": name, "Targets": [{"Id": "owned", "Arn": queue_arn}]}))
    cap.capture["event_capture_bounds"] = {"max_rules": 3, "max_queues": 1, "receive_seconds": 35, "max_receive_calls": 8, "delivery": "Best effort; bounded missing events are not asserted absent forever."}
    cap.save()
    return state


def receive(cap, state):
    deadline = time.monotonic() + 35
    events = []
    for attempt in range(8):
        if time.monotonic() > deadline:
            break
        response = cap.request("receive-owned-events-" + str(attempt), "sqs", "receive-message", {"QueueUrl": state["queue_url"], "MaxNumberOfMessages": 10, "WaitTimeSeconds": 5, "VisibilityTimeout": 120}, options=["--query", "{Messages:Messages[].{Body:Body,MessageId:MessageId}}"])
        if response["code"] == "Success":
            for message in response["output"].get("Messages") or []:
                events.append(json.loads(message["Body"]))
    cap.capture["native_events"] = events
    cap.capture["event_projection"] = "SQS ReceiptHandle omitted by CLI JMESPath before recording; native event Body parsed without changing fields/order."
    cap.save()


def cleanup(cap, state):
    remaining = []
    for name in state["rules"]:
        cap.request("cleanup-remove-event-target", "events", "remove-targets", {"Rule": name, "Ids": ["owned"]})
        cap.request("cleanup-delete-event-rule", "events", "delete-rule", {"Name": name})
        if cap.request("verify-event-rule-absent", "events", "describe-rule", {"Name": name})["code"] != "ResourceNotFoundException":
            remaining.append(name)
    cap.request("cleanup-delete-event-queue", "sqs", "delete-queue", {"QueueUrl": state["queue_url"]})
    response = cap.request("verify-event-queue-absent", "sqs", "get-queue-url", {"QueueName": state["queue_name"]})
    if response["code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
        remaining.append(state["queue_name"])
    return remaining
