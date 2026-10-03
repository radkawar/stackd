#!/usr/bin/env python3
"""Capture SQS redrive and KMS forwarding context using owned resource policies."""

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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--redrive-details", action="store_true", help="isolate each queue condition and dependent attribute checks")
    mode.add_argument("--accepted-task", action="store_true", help="apply restrictions after accepting a task with a held message")
    args = parser.parse_args()
    details, accepted = args.redrive_details, args.accepted_task
    filename = "forwarding_execution.json" if accepted else "forwarding_redrive.json" if details else "forwarding.json"
    path = pathlib.Path(__file__).resolve().parents[2] / ".stackd/probes/sqs" / filename
    caller = require_account(args.account)
    path.parent.mkdir(parents=True, exist_ok=True)
    account = caller["Account"]
    prefix = "stackd-forward-" + uuid.uuid4().hex[:10]
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": "us-east-1", "source": "Native AWS SQS/KMS; owned queue and key policies, existing authenticated IAM caller",
        "comparison": "Direct versus forwarded authorization, redrive acceptance/completion and encrypted delivery",
        "limitations": "Commercial public endpoints; finite policy cases, no VPC endpoint or policy-propagation timing guarantees",
        "observations": [], "owned_queues": {}, "cleanup": {}}
    arns = {}
    active = None
    key_id = None

    def save():
        path.write_text(json.dumps(fixture, indent=2) + "\n")

    def observe(case, service, operation, parameters):
        row = {"case": case, "service": service, "operation": operation}
        try:
            out = call(service, operation, parameters, error_format="json")
        except AWSCLIError as error:
            row["error"] = error.details
            out = None
        else:
            data = json.loads(json.dumps(out))
            for field in ("Plaintext", "CiphertextBlob", "TaskHandle"):
                data.pop(field, None)
            for result in data.get("Results", []):
                result.pop("TaskHandle", None)
            for message in data.get("Messages", []):
                message.pop("ReceiptHandle", None)
            row["output"] = data
        normalized = json.dumps(row)
        for label, url in fixture["owned_queues"].items():
            normalized = normalized.replace(url, f"<queue:{label}>").replace(arns[label], f"<arn:{label}>")
        normalized = normalized.replace(account, "111111111111")
        fixture["observations"].append(json.loads(normalized))
        save()
        return out

    def queue(label, attrs):
        url = call("sqs", "create-queue", {"QueueName": prefix + "-" + label, "Attributes": attrs})["QueueUrl"]
        fixture["owned_queues"][label] = url
        save()
        arn = call("sqs", "get-queue-attributes", {"QueueUrl": url, "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        arns[label] = arn
        return url, arn

    conditions = {
        "last": {"StringNotEqualsIfExists": {"aws:CalledViaLast": "sqs.amazonaws.com"}},
        "first": {"StringNotEqualsIfExists": {"aws:CalledViaFirst": "sqs.amazonaws.com"}},
        "chain": {"ForAllValues:StringNotEquals": {"aws:CalledVia": "sqs.amazonaws.com"}},
        "via": {"Bool": {"aws:ViaAWSService": "false"}},
        "principal": {"Bool": {"aws:PrincipalIsAWSService": "false"}},
    }
    fixture["deny_conditions"] = conditions
    cases = [("forwarded", ("last", "first", "chain", "via")), ("principal", ("principal",)), ("control", ("via",))]
    if accepted:
        cases = [(name, (name,)) for name in ("last", "first", "chain", "via", "principal")]
    elif details:
        cases = [(name, (name,)) for name in ("last", "first", "chain", "via")] + [("attributes", ("last",))]
    try:
        for case, names in cases:
            dead, dead_arn = queue(case + "-dead", {})
            queue(case + "-source", {"RedrivePolicy": json.dumps({"deadLetterTargetArn": dead_arn, "maxReceiveCount": 1})})
            destination, destination_arn = queue(case + "-destination", {})
            call("sqs", "send-message", {"QueueUrl": dead, "MessageBody": "redriven"})
            started = None
            if accepted:
                held = call("sqs", "receive-message", {"QueueUrl": dead, "VisibilityTimeout": 600, "WaitTimeSeconds": 2})["Messages"][0]
                started = observe(case + "_start", "sqs", "start-message-move-task", {"SourceArn": dead_arn,
                    "DestinationArn": destination_arn, "MaxNumberOfMessagesPerSecond": 10})
                if started is None:
                    raise RuntimeError("Could not accept the unrestricted task")
                active = started["TaskHandle"]
            for url, arn, actions in ((dead, dead_arn, ["sqs:ReceiveMessage", "sqs:DeleteMessage"]),
                                      (destination, destination_arn, ["sqs:SendMessage"])):
                if case == "control":
                    actions = ["sqs:StartMessageMoveTask"]
                elif case == "attributes":
                    actions = ["sqs:GetQueueAttributes"]
                policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*",
                    "Action": actions, "Resource": arn, "Condition": conditions[name]} for name in names]}
                call("sqs", "set-queue-attributes", {"QueueUrl": url, "Attributes": {"Policy": json.dumps(policy)}})
            time.sleep(5)
            if case == "attributes":
                observe(case + "_direct_attributes", "sqs", "get-queue-attributes", {"QueueUrl": dead, "AttributeNames": ["QueueArn"]})
            elif case != "control":
                observe(case + "_direct_receive", "sqs", "receive-message", {"QueueUrl": dead, "VisibilityTimeout": 0})
                observe(case + "_direct_send", "sqs", "send-message", {"QueueUrl": destination, "MessageBody": "direct"})
            if accepted:
                observe(case + "_before_release", "sqs", "list-message-move-tasks", {"SourceArn": dead_arn})
                call("sqs", "change-message-visibility", {"QueueUrl": dead, "ReceiptHandle": held["ReceiptHandle"], "VisibilityTimeout": 0})
            else:
                started = observe(case + "_start", "sqs", "start-message-move-task", {"SourceArn": dead_arn,
                    "DestinationArn": destination_arn, "MaxNumberOfMessagesPerSecond": 10})
            if started is not None:
                active = started["TaskHandle"]
                for _ in range(30):
                    result = observe(case + "_progress", "sqs", "list-message-move-tasks", {"SourceArn": dead_arn})
                    if result["Results"][0]["Status"] not in ("RUNNING", "CANCELLING"):
                        active = None
                        break
                    time.sleep(2)
                if active is not None:
                    raise RuntimeError("Redrive task did not finish: " + case)
            observe(case + "_destination", "sqs", "receive-message", {"QueueUrl": destination,
                "WaitTimeSeconds": 1, "MaxNumberOfMessages": 10, "MessageSystemAttributeNames": ["All"]})

        if not details and not accepted:
            key = call("kms", "create-key", {"Description": prefix, "Tags": [{"TagKey": "stackd-probe", "TagValue": prefix}]})["KeyMetadata"]
            key_id = key["KeyId"]
            fixture["owned_key"] = {"KeyId": key_id, "Arn": key["Arn"]}
            save()
            for case in ("last", "via", "principal"):
                policy = {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "kms:*", "Resource": "*"},
                    {"Effect": "Deny", "Principal": "*", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "*", "Condition": conditions[case]}]}
                call("kms", "put-key-policy", {"KeyId": key_id, "PolicyName": "default", "Policy": json.dumps(policy)})
                encrypted, _ = queue("kms-" + case, {"KmsMasterKeyId": key["Arn"], "KmsDataKeyReusePeriodSeconds": "60"})
                time.sleep(3)
                observe("kms_" + case + "_direct", "kms", "generate-data-key", {"KeyId": key_id, "KeySpec": "AES_256"})
                sent = observe("kms_" + case + "_send", "sqs", "send-message", {"QueueUrl": encrypted, "MessageBody": "encrypted"})
                if sent is not None:
                    observe("kms_" + case + "_receive", "sqs", "receive-message", {"QueueUrl": encrypted, "WaitTimeSeconds": 1})
        fixture["completed"] = True
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
        if key_id is not None:
            deletion = call("kms", "schedule-key-deletion", {"KeyId": key_id, "PendingWindowInDays": 7})
            fixture["cleanup"]["kms"] = deletion
        save()
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
