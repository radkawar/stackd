#!/usr/bin/env python3
"""Observe omitted Scheduler input/defaults using one owned SQS queue and role.

No existing queues, roles, groups or trails are mutated or consumed. This records
API and delivery observations, not CloudTrail data-event evidence.
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

from scheduler_pipes_probe import REGION, document, verify_absence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=".stackd/probes/scheduler_pipes/default_input.json")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    session = boto3.Session(region_name=REGION)
    clients = {name: session.client(name, config=Config(retries={"max_attempts": 0}))
               for name in ("sts", "iam", "scheduler", "sqs")}
    identity = clients["sts"].get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Probe authorized only for account " + args.account)
    prefix = "stackd-spdefault-" + uuid.uuid4().hex[:12]
    capture = {"started_at": datetime.now(timezone.utc).isoformat(), "identity": identity,
               "region": REGION, "prefix": prefix, "ownership": {}, "calls": [], "cleanup": [],
               "observations": {}, "boundary": "API and SQS delivery observations; no CloudTrail data-event claim"}
    owned = capture["ownership"]
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    credentials = session.get_credentials().get_frozen_credentials()
    secrets = [value for value in (credentials.secret_key, credentials.token) if value]

    def save():
        text = json.dumps(document(capture), indent=2, default=str)
        for secret in secrets:
            text = text.replace(secret, "<redacted-credential>")
        path.write_text(text + "\n")

    def call(label, service, operation, parameters, optional=False):
        row = {"label": label, "service": service, "operation": operation,
               "parameters": parameters, "at": datetime.now(timezone.utc).isoformat()}
        capture["calls"].append(row)
        try:
            result = getattr(clients[service], operation)(**parameters)
            row.update(code="Success", output=result)
        except ClientError as error:
            result = error.response
            row.update(code=result["Error"]["Code"], error=result)
            if not optional:
                raise
        finally:
            result_metadata = row.get("output", row.get("error", {})).get("ResponseMetadata", {})
            row["request_id"] = result_metadata.get("RequestId")
            save()
        return result

    save()
    try:
        result = call("queue", "sqs", "create_queue", {"QueueName": prefix, "tags": {"stackd-probe": prefix}})
        owned["queues"] = {"target": {"name": prefix, "url": result["QueueUrl"]}}
        save()
        queue = owned["queues"]["target"]
        queue["arn"] = call("queue-arn", "sqs", "get_queue_attributes", {
            "QueueUrl": queue["url"], "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        group_arn = f"arn:aws:scheduler:{REGION}:{args.account}:schedule-group/{prefix}"
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": args.account}, "ArnEquals": {"aws:SourceArn": group_arn}}}]}
        role = call("role", "iam", "create_role", {"RoleName": prefix,
            "AssumeRolePolicyDocument": json.dumps(trust), "Tags": [{"Key": "stackd-probe", "Value": prefix}]})["Role"]
        owned["roles"] = {"scheduler": role}
        save()
        call("role-policy", "iam", "put_role_policy", {"RoleName": prefix, "PolicyName": "owned",
            "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Action": "sqs:SendMessage", "Resource": queue["arn"]}]})})
        call("group", "scheduler", "create_schedule_group", {"Name": prefix})
        owned["group"] = prefix
        owned["schedules"] = []
        save()
        time.sleep(12)
        target = {"Arn": queue["arn"], "RoleArn": role["Arn"]}
        for name, expression, state in (("defaults", "rate(1 day)", "DISABLED"),
                ("omitted-input", "at(" + (datetime.now(timezone.utc) + timedelta(seconds=75)).strftime("%Y-%m-%dT%H:%M:%S") + ")", "ENABLED")):
            call("create-" + name, "scheduler", "create_schedule", {"Name": name, "GroupName": prefix,
                "ScheduleExpression": expression, "FlexibleTimeWindow": {"Mode": "OFF"}, "State": state, "Target": target})
            owned["schedules"].append(name)
            save()
            call("get-" + name, "scheduler", "get_schedule", {"Name": name, "GroupName": prefix})
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            result = call("receive-owned", "sqs", "receive_message", {"QueueUrl": queue["url"],
                "WaitTimeSeconds": 5, "MaxNumberOfMessages": 10, "MessageSystemAttributeNames": ["All"]})
            if result.get("Messages"):
                capture["observations"]["omitted_input_messages"] = result["Messages"]
                for message in result["Messages"]:
                    call("ack-owned", "sqs", "delete_message", {"QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]})
                capture["workflow_complete"] = True
                save()
                break
        else:
            raise RuntimeError("Owned omitted-input delivery not observed within 180 seconds")
    except Exception as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        save()
        raise
    finally:
        cleanup = []
        for name in owned.get("schedules", []):
            cleanup.append(("schedule-" + name, "scheduler", "delete_schedule", {"Name": name, "GroupName": prefix}, {"ResourceNotFoundException"}))
        if owned.get("group"):
            cleanup.append(("group", "scheduler", "delete_schedule_group", {"Name": prefix}, {"ResourceNotFoundException"}))
        if owned.get("roles"):
            cleanup += [("policy", "iam", "delete_role_policy", {"RoleName": prefix, "PolicyName": "owned"}, {"NoSuchEntity"}),
                        ("role", "iam", "delete_role", {"RoleName": prefix}, {"NoSuchEntity"})]
        if owned.get("queues"):
            cleanup.append(("queue", "sqs", "delete_queue", {"QueueUrl": owned["queues"]["target"]["url"]}, {"AWS.SimpleQueueService.NonExistentQueue"}))
        for label, service, operation, parameters, absent in cleanup:
            try:
                result = call("cleanup-" + label, service, operation, parameters, optional=True)
                code = result.get("Error", {}).get("Code")
                capture["cleanup"].append({"resource": label, "ok": code is None or code in absent, "code": code})
            except Exception as error:
                capture["cleanup"].append({"resource": label, "ok": False, "error": str(error)})
            save()
        capture["absence_verification"] = verify_absence(clients, owned)
        capture["cleanup_complete"] = bool(cleanup) and all(row["ok"] for row in capture["cleanup"]) and all(
            {row["resource"]: row["absent"] for row in capture["absence_verification"]}.values())
        capture["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
        print(json.dumps({"capture": str(path), "prefix": prefix, "workflow_complete": capture.get("workflow_complete", False),
                          "cleanup_complete": capture["cleanup_complete"], "failure": capture.get("failure")}))


if __name__ == "__main__":
    main()
