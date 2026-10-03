#!/usr/bin/env python3
"""Observe standard-queue tenant delivery using one owned, short-lived AWS queue.

At most 150 synthetic messages and 80 receive requests. This captures delivery
order, not a guarantee of exact distributed scheduling or detection thresholds.
"""

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
    destination = pathlib.Path(__file__).resolve().parents[2] / ".stackd/probes/sqs/fairness.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    name = "stackd-fairness-" + uuid.uuid4().hex[:16]
    started = time.monotonic()
    fixture = {
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": "us-east-1",
        "source": "Native AWS SQS API through AWS CLI; one owned standard queue",
        "comparison": "Group attribute round trips, delivery while same-group messages are in flight, and quiet/ungrouped delivery amid noisy backlog. Body order is observed, not guaranteed.",
        "limitations": "One finite run; does not establish exact detection thresholds, processing-time accounting, five-minute recovery or CloudWatch metrics.",
        "observations": [],
    }
    url = None

    def save():
        destination.write_text(json.dumps(fixture, indent=2) + "\n")

    def record(case, operation, output):
        fixture["observations"].append({"case": case, "operation": operation,
                                        "elapsed_seconds": round(time.monotonic() - started, 3),
                                        **output})
        save()

    def send(case, group, count):
        for offset in range(0, count, 10):
            entries = [{"Id": str(i), "MessageBody": f"{case}-{i}"}
                       for i in range(offset, min(offset + 10, count))]
            if group is not None:
                for entry in entries:
                    entry["MessageGroupId"] = group
            out = call("sqs", "send-message-batch", {"QueueUrl": url, "Entries": entries})
            record(case, "SendMessageBatch", {"entries": entries, "successful": len(out.get("Successful", [])),
                                               "failed": out.get("Failed", [])})
            if out.get("Failed"):
                raise RuntimeError("Native send batch failed; see fixture")

    def receive(case, maximum):
        out = call("sqs", "receive-message", {"QueueUrl": url, "MaxNumberOfMessages": maximum,
                   "WaitTimeSeconds": 1, "MessageSystemAttributeNames": ["All"]})
        # Receipts and generated identifiers stay out of the fixture. Synthetic
        # bodies identify messages across requests; semantic attributes survive.
        messages = [{"body": m["Body"], "attributes": {k: v for k, v in m.get("Attributes", {}).items()
                     if k in ("MessageGroupId", "ApproximateReceiveCount", "MessageDeduplicationId", "SequenceNumber")}}
                    for m in out.get("Messages", [])]
        record(case, "ReceiveMessage", {"maximum": maximum, "messages": messages})
        return messages

    try:
        out = call("sqs", "create-queue", {"QueueName": name, "Attributes": {"VisibilityTimeout": "600"},
                                            "tags": {"project": "stackd", "purpose": "fairness-conformance"}})
        url = out["QueueUrl"]
        # Preserve the owned resource until deletion is confirmed, for recovery.
        fixture["owned_queue"] = url
        save()
        time.sleep(1)
        send("noisy", "noisy", 120)
        held = []
        for _ in range(40):
            held.extend(receive("hold_noisy", min(10, 60 - len(held))))
            if len(held) == 60:
                break
        if len(held) != 60:
            raise RuntimeError("Could not establish 60 concurrent noisy messages")
        send("quiet", "quiet", 20)
        send("ungrouped", None, 10)
        time.sleep(10)
        delivered = []
        for _ in range(40):
            delivered.extend(receive("contended", 10))
            if len(delivered) >= 90:
                break
        fixture["completed"] = len(delivered) == 90
        save()
    finally:
        if url is not None:
            call("sqs", "delete-queue", {"QueueUrl": url})
            # Native lookup owns the deletion result; no separate cleanup ledger.
            try:
                call("sqs", "get-queue-url", {"QueueName": name}, error_format="json")
            except AWSCLIError as error:
                details = error.details
                code = details["Code"]
                if code not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
                    raise
                fixture["cleanup"] = {"DeleteQueue": "succeeded", "GetQueueUrl": code}
                del fixture["owned_queue"]
            else:
                raise RuntimeError("Deleted queue still resolves; ownership retained in fixture")
        save()
    print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
