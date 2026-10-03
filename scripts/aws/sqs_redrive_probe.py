#!/usr/bin/env python3
"""Capture native redrive counters, completion and cancellation on owned queues."""

import argparse
import datetime
import json
import pathlib
import time
import uuid

from aws_cli import AWSCLIError, call, require_account


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID authorized for this probe")
    args = parser.parse_args()
    require_account(args.account)
    path = pathlib.Path(__file__).resolve().parents[2] / ".stackd/probes/sqs/redrive.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "region": "us-east-1", "source": "Native AWS SQS through AWS CLI; three owned standard queues",
               "comparison": "Starting count versus moved count, task states, cancellation and moved message contents",
               "limitations": "Small custom-destination run; not exact timing, optimized rate, IAM/KMS, FIFO or 36-hour conformance",
               "observations": [], "owned_queues": {}, "cleanup": {}}
    prefix = "stackd-redrive-" + uuid.uuid4().hex[:12]
    active = None

    def save():
        path.write_text(json.dumps(fixture, indent=2) + "\n")

    def observe(case, operation, parameters):
        out = call("sqs", operation, parameters, error_format="json")
        normalized = json.dumps(out)
        for label, url in fixture["owned_queues"].items():
            normalized = normalized.replace(url, f"<queue:{label}>")
            normalized = normalized.replace(arns[label], f"<arn:{label}>")
        data = json.loads(normalized)
        if "TaskHandle" in data:
            data["TaskHandle"] = "<task>"
        for result in data.get("Results", []):
            if "TaskHandle" in result:
                result["TaskHandle"] = "<task>"
        for message in data.get("Messages", []):
            message.pop("ReceiptHandle", None)
            message.pop("MessageId", None)
        fixture["observations"].append({"case": case, "operation": operation, "output": data})
        save()
        return out

    arns = {}
    try:
        for label in ("dead", "source", "destination"):
            attrs = {}
            if label == "source":
                attrs["RedrivePolicy"] = json.dumps({"deadLetterTargetArn": arns["dead"], "maxReceiveCount": 1})
            out = call("sqs", "create-queue", {"QueueName": prefix + "-" + label, "Attributes": attrs})
            url = out["QueueUrl"]
            fixture["owned_queues"][label] = url
            save()
            arns[label] = call("sqs", "get-queue-attributes", {"QueueUrl": url, "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        time.sleep(1)
        dead = fixture["owned_queues"]["dead"]
        # Direct DLQ messages are valid with a custom redrive destination.
        for offset in (0, 10):
            observe("populate", "send-message-batch", {"QueueUrl": dead, "Entries": [
                {"Id": str(i), "MessageBody": f"work-{i}"} for i in range(offset, min(offset + 10, 12))]})
        started = observe("start", "start-message-move-task", {"SourceArn": arns["dead"],
            "DestinationArn": arns["destination"], "MaxNumberOfMessagesPerSecond": 1})
        active = started["TaskHandle"]
        for _ in range(60):
            status = observe("progress", "list-message-move-tasks", {"SourceArn": arns["dead"]})["Results"][0]["Status"]
            if status not in ("RUNNING", "CANCELLING"):
                active = None
                break
            time.sleep(2)
        if status != "COMPLETED":
            raise RuntimeError(f"Redrive did not complete: {status}")
        received = 0
        for _ in range(12):
            out = observe("destination", "receive-message", {"QueueUrl": fixture["owned_queues"]["destination"],
                "MaxNumberOfMessages": 10, "WaitTimeSeconds": 1})
            received += len(out.get("Messages", []))
            if received == 12:
                break
        observe("populate_cancel", "send-message-batch", {"QueueUrl": dead, "Entries": [
            {"Id": str(i), "MessageBody": f"cancel-{i}"} for i in range(5)]})
        active = observe("start_cancel", "start-message-move-task", {"SourceArn": arns["dead"],
            "DestinationArn": arns["destination"], "MaxNumberOfMessagesPerSecond": 1})["TaskHandle"]
        observe("cancel", "cancel-message-move-task", {"TaskHandle": active})
        for _ in range(30):
            status = observe("cancel_progress", "list-message-move-tasks", {"SourceArn": arns["dead"]})["Results"][0]["Status"]
            if status not in ("RUNNING", "CANCELLING"):
                active = None
                break
            time.sleep(2)
        fixture["completed"] = received == 12 and status == "CANCELLED"
    finally:
        if active is not None:
            try:
                call("sqs", "cancel-message-move-task", {"TaskHandle": active})
            except RuntimeError as error:
                fixture["cancel_cleanup_error"] = str(error)
        for label, url in list(fixture["owned_queues"].items()):
            call("sqs", "delete-queue", {"QueueUrl": url})
            try:
                call("sqs", "get-queue-url", {"QueueName": url.rsplit("/", 1)[1]}, error_format="json")
            except AWSCLIError as error:
                code = error.details["Code"]
                if code != "AWS.SimpleQueueService.NonExistentQueue":
                    raise
                fixture["cleanup"][label] = code
                del fixture["owned_queues"][label]
            else:
                raise RuntimeError("Deleted queue still resolves")
            save()
        save()
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
