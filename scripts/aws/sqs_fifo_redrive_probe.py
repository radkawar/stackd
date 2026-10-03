#!/usr/bin/env python3
"""Observe FIFO group locks and destination deduplication during native redrive."""

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
    path = pathlib.Path(__file__).resolve().parents[2] / ".stackd/probes/sqs/fifo_redrive.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "region": "us-east-1", "source": "Native AWS SQS; isolated owned FIFO queue families",
               "comparison": "Group blocking, redriven identifiers and destination deduplication; generated IDs retained for relationships",
               "limitations": "Finite group-lock, deduplication and original-source cases; not throughput or distributed timing guarantees",
               "observations": [], "owned_queues": {}, "cleanup": {}}
    prefix = "stackd-fifo-redrive-" + uuid.uuid4().hex[:10]
    arns = {}
    active = None
    started = time.monotonic()

    def save():
        path.write_text(json.dumps(fixture, indent=2) + "\n")

    def observe(case, operation, parameters):
        try:
            out = call("sqs", operation, parameters, error_format="json")
        except AWSCLIError as error:
            fixture["observations"].append({"case": case, "operation": operation,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "error": error.details})
            save()
            raise
        data = json.loads(json.dumps(out))
        data.pop("TaskHandle", None)
        for result in data.get("Results", []):
            if "TaskHandle" in result:
                result["TaskHandle"] = "<task>"
        for message in data.get("Messages", []):
            message.pop("ReceiptHandle", None)
        encoded = json.dumps(data)
        for label, url in fixture["owned_queues"].items():
            encoded = encoded.replace(url, f"<queue:{label}>").replace(arns[label], f"<arn:{label}>")
        account = next(iter(fixture["owned_queues"].values())).split("/")[-2]
        encoded = encoded.replace(account, "111111111111")
        fixture["observations"].append({"case": case, "operation": operation,
            "elapsed_seconds": round(time.monotonic() - started, 3), "output": json.loads(encoded)})
        save()
        return out

    def receive(case, url, visibility=600):
        return observe(case, "receive-message", {"QueueUrl": url, "MaxNumberOfMessages": 10,
            "WaitTimeSeconds": 1, "VisibilityTimeout": visibility, "MessageSystemAttributeNames": ["All"]}).get("Messages", [])

    delivered = {}

    def collect(case):
        for m in receive(case, destination):
            delivered[m["Body"]] = m
            call("sqs", "delete-message", {"QueueUrl": destination, "ReceiptHandle": m["ReceiptHandle"]})

    def wait_task(case):
        nonlocal active
        for _ in range(40):
            status = observe(case, "list-message-move-tasks", {"SourceArn": dead_arn})["Results"][0]["Status"]
            if status not in ("RUNNING", "CANCELLING"):
                active = None
                return status
            time.sleep(2)
        raise RuntimeError(f"Task did not finish: {case}")

    def dead_letter(body):
        source = source_url
        observe("source_send_" + body, "send-message", {"QueueUrl": source, "MessageBody": body,
            "MessageGroupId": "source-group", "MessageDeduplicationId": "source-" + body})
        for attempt in range(60):
            receive("source_attempt_" + body, source, visibility=0)
            for m in receive("dead_arrival_" + body, dead):
                if m["Body"] == body:
                    return m
            if attempt % 10 == 9:
                for label, url in fixture["owned_queues"].items():
                    observe("waiting_" + body + "_" + label, "get-queue-attributes", {"QueueUrl": url,
                        "AttributeNames": ["All"]})
        raise RuntimeError(f"Message did not reach DLQ: {body}")

    def create_group(group, roles):
        result = {}
        for role in roles:
            label = group + "-" + role
            attrs = {"FifoQueue": "true"}
            if role == "source":
                attrs["RedrivePolicy"] = json.dumps({"deadLetterTargetArn": result["dead"][1], "maxReceiveCount": 1})
            url = call("sqs", "create-queue", {"QueueName": prefix + "-" + label + ".fifo", "Attributes": attrs})["QueueUrl"]
            fixture["owned_queues"][label] = url
            save()
            arn = call("sqs", "get-queue-attributes", {"QueueUrl": url, "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
            arns[label] = arn
            result[role] = (url, arn)
        return result

    try:
        queues = create_group("locks", ("dead", "source", "destination"))
        dead, dead_arn = queues["dead"]
        destination, destination_arn = queues["destination"]
        time.sleep(1)
        observe("send_a0", "send-message", {"QueueUrl": dead, "MessageBody": "a0", "MessageGroupId": "a", "MessageDeduplicationId": "manual-a0"})
        held = receive("hold_a0", dead)
        if len(held) != 1 or held[0]["Body"] != "a0":
            raise RuntimeError("Could not establish the held FIFO message")
        for body, group in (("a1", "a"), ("b0", "b")):
            observe("send_" + body, "send-message", {"QueueUrl": dead, "MessageBody": body, "MessageGroupId": group, "MessageDeduplicationId": "manual-" + body})
        active = observe("start", "start-message-move-task", {"SourceArn": dead_arn, "DestinationArn": destination_arn, "MaxNumberOfMessagesPerSecond": 10})["TaskHandle"]
        for _ in range(20):
            observe("held_progress", "list-message-move-tasks", {"SourceArn": dead_arn})
            collect("held_destination")
            if "b0" in delivered:
                break
            time.sleep(2)
        # Leave the held group blocked after unrelated work has made progress.
        for _ in range(3):
            time.sleep(2)
            collect("still_held_destination")
        observe("before_release", "list-message-move-tasks", {"SourceArn": dead_arn})
        observe("release_a0", "change-message-visibility", {"QueueUrl": dead, "ReceiptHandle": held[0]["ReceiptHandle"], "VisibilityTimeout": 0})
        for _ in range(40):
            collect("released_destination")
            status = observe("released_progress", "list-message-move-tasks", {"SourceArn": dead_arn})["Results"][0]["Status"]
            if status not in ("RUNNING", "CANCELLING"):
                active = None
                break
            time.sleep(2)
        if set(delivered) != {"a0", "a1", "b0"}:
            raise RuntimeError(f"Unexpected delivered bodies: {sorted(delivered)}")
        for body in ("a0", "a1", "b0"):
            m = delivered[body]
            observe("duplicate_" + body, "send-message", {"QueueUrl": destination, "MessageBody": "duplicate-" + body,
                "MessageGroupId": m["Attributes"]["MessageGroupId"], "MessageDeduplicationId": m["Attributes"]["MessageDeduplicationId"]})
        receive("after_duplicate_sends", destination)

        # A task that reports COMPLETED can still claim late arrivals in AWS.
        # Isolate this case so an earlier task cannot move before the seed exists.
        queues = create_group("collision", ("dead", "source", "destination"))
        dead, dead_arn = queues["dead"]
        destination, destination_arn = queues["destination"]
        time.sleep(1)
        collision = observe("send_collision", "send-message", {"QueueUrl": dead, "MessageBody": "collision",
            "MessageGroupId": "collision-group", "MessageDeduplicationId": "collision-input"})
        observe("seed_collision", "send-message", {"QueueUrl": destination, "MessageBody": "existing",
            "MessageGroupId": "collision-group", "MessageDeduplicationId": collision["MessageId"]})
        collect("seed_destination")
        active = observe("collision_start", "start-message-move-task", {"SourceArn": dead_arn,
            "DestinationArn": destination_arn, "MaxNumberOfMessagesPerSecond": 10})["TaskHandle"]
        if wait_task("collision_progress") != "COMPLETED":
            raise RuntimeError("Collision redrive failed")
        collect("collision_destination")

        queues = create_group("automatic", ("dead", "source"))
        dead, dead_arn = queues["dead"]
        source_url, _ = queues["source"]
        time.sleep(1)
        poison = dead_letter("poison")
        call("sqs", "delete-message", {"QueueUrl": dead, "ReceiptHandle": poison["ReceiptHandle"]})
        observe("duplicate_dead_arrival", "send-message", {"QueueUrl": dead, "MessageBody": "duplicate-poison",
            "MessageGroupId": "source-group", "MessageDeduplicationId": poison["Attributes"]["MessageDeduplicationId"]})
        for m in receive("after_dead_duplicate", dead):
            call("sqs", "delete-message", {"QueueUrl": dead, "ReceiptHandle": m["ReceiptHandle"]})

        returned = dead_letter("return")
        observe("release_return", "change-message-visibility", {"QueueUrl": dead,
            "ReceiptHandle": returned["ReceiptHandle"], "VisibilityTimeout": 0})
        active = observe("return_start", "start-message-move-task", {"SourceArn": dead_arn,
            "MaxNumberOfMessagesPerSecond": 10})["TaskHandle"]
        if wait_task("return_progress") != "COMPLETED":
            raise RuntimeError("Original-source redrive failed")
        received_return = receive("returned_source", source_url)
        fixture["completed"] = status == "COMPLETED" and any(m["Body"] == "return" for m in received_return)
    except BaseException as error:
        fixture["incomplete_reason"] = str(error)
        raise
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
                raise RuntimeError("Deleted FIFO queue still resolves")
            save()
        save()
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
