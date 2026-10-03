#!/usr/bin/env python3
"""Capture EventBridge service-principal authorization using owned SQS targets."""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import call


def queue_policy(queue_arn, condition):
    statement = {"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                 "Action": "sqs:SendMessage", "Resource": queue_arn}
    if condition:
        statement["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


def receive_deliveries(queues, case, target_arns, env, record):
    """Consume each correlated target/DLQ outcome once, saving it as it arrives."""
    pending = set(target_arns)
    deadline = time.monotonic() + 90
    while pending and time.monotonic() < deadline:
        for kind, queue in queues.items():
            if kind != "dlq" and queue["arn"] not in pending:
                continue
            response = call("sqs", "receive-message", {"QueueUrl": queue["url"], "WaitTimeSeconds": 2,
                "MaxNumberOfMessages": 10, "MessageAttributeNames": ["All"]}, env)
            for message in response.get("Messages", []):
                envelope = json.loads(message["Body"])
                call("sqs", "delete-message", {"QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]}, env)
                if envelope.get("detail", {}).get("case") != case:
                    continue
                attributes = {k: v.get("StringValue") for k, v in message.get("MessageAttributes", {}).items()}
                target_arn = attributes.get("TARGET_ARN") if kind == "dlq" else queue["arn"]
                if target_arn in pending:
                    record(target_arn, "dlq" if kind == "dlq" else "target", attributes)
                    pending.remove(target_arn)
    if pending:
        raise RuntimeError("Owned event delivery was not observed within the probe window: " + case
                           + "; pending targets: " + ", ".join(sorted(pending)))


def main(account, principal_types=False, kms=False):
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="2")
    if call("sts", "get-caller-identity", env=env)["Account"] != account:
        raise RuntimeError("Caller account differs from --account")
    prefix = "stackd-event-delivery-" + uuid.uuid4().hex[:10]
    queues, rules, targets = {}, {}, {}
    bus, key = False, None
    capture = {"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scope": "Owned EventBridge bus/rules and SQS queues; no existing resources changed",
               "observations": [], "cleanup": False}
    filename = "kms_delivery.json" if kms else "principal_types.json" if principal_types else "delivery.json"
    path = Path(".stackd/probes/eventbridge") / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if kms and path.exists():
        previous = json.loads(path.read_text())
        capture["previous_runs"] = previous.get("previous_runs", []) + [{
            "retrieved_at": previous["retrieved_at"], "key": previous.get("key"),
            "key_cleanup": previous.get("key_cleanup"), "cleanup": previous["cleanup"]}]

    def save():
        path.write_text(json.dumps(capture, indent=2) + "\n")

    def set_queue_policy(kind, condition):
        queue = queues[kind]
        call("sqs", "set-queue-attributes", {"QueueUrl": queue["url"], "Attributes": {
            "Policy": queue_policy(queue["arn"], condition)}}, env)

    try:
        kinds = ["service", "source-rule", "source-queue", "source-absent", "source-account"] if kms else ["target"]
        for kind in kinds + ["dlq"]:
            url = call("sqs", "create-queue", {"QueueName": prefix + "-" + kind}, env)["QueueUrl"]
            queues[kind] = {"url": url}
            attributes = call("sqs", "get-queue-attributes", {"QueueUrl": url,
                "AttributeNames": ["QueueArn", "SqsManagedSseEnabled"]}, env)["Attributes"]
            queues[kind]["arn"] = attributes["QueueArn"]
            queues[kind]["attributes"] = attributes
        call("events", "create-event-bus", {"Name": prefix}, env)
        bus = True
        for name in (["a", "b"] if kms else ["default"]):
            pattern = {"source": [prefix]}
            if kms:
                pattern["detail"] = {"rule": [name]}
            rule_name = prefix + "-" + name if kms else prefix
            rules[name] = {"name": rule_name, "arn": call("events", "put-rule", {
                "Name": rule_name, "EventBusName": prefix, "EventPattern": json.dumps(pattern)}, env)["RuleArn"]}
        source_arns = [rule["arn"] for rule in rules.values()]
        source_condition = {"ArnEquals": {"aws:SourceArn": source_arns if kms else source_arns[0]}}
        set_queue_policy("dlq", source_condition)

        if kms:
            capture["scope"] += "; one customer managed KMS key, scheduled for deletion after seven days"
            conditions = {
                "service": {},
                "source-rule": {"ArnEquals": {"aws:SourceArn": rules["a"]["arn"]}},
                "source-queue": {"ArnEquals": {"aws:SourceArn": queues["source-queue"]["arn"]}},
                "source-absent": {"Null": {"aws:SourceArn": "true"}},
                "source-account": {"StringEquals": {"aws:SourceAccount": account}},
            }
            policy = {"Version": "2012-10-17", "Statement": [{"Sid": "Owner",
                "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*", "Resource": "*"}]}
            for kind in kinds:
                condition = json.loads(json.dumps(conditions[kind]))
                condition.setdefault("StringEquals", {})["kms:EncryptionContext:aws:sqs:arn"] = queues[kind]["arn"]
                policy["Statement"].append({"Sid": kind.replace("-", ""), "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "*", "Condition": condition})
            key = call("kms", "create-key", {"Description": prefix + " EventBridge encrypted SQS probe",
                "Policy": json.dumps(policy), "Tags": [{"TagKey": "stackd-probe", "TagValue": prefix}]}, env)["KeyMetadata"]
            capture.update(key={"id": key["KeyId"], "arn": key["Arn"]}, key_policy=policy,
                           rules=rules, queues=queues, data_key_reuse_seconds=300)
            save()
            print("owned key: " + key["KeyId"], flush=True)
            for kind in kinds:
                set_queue_policy(kind, source_condition)
                call("sqs", "set-queue-attributes", {"QueueUrl": queues[kind]["url"], "Attributes": {
                    "KmsMasterKeyId": key["Arn"], "KmsDataKeyReusePeriodSeconds": "300"}}, env)
                queues[kind]["attributes"] = call("sqs", "get-queue-attributes", {
                    "QueueUrl": queues[kind]["url"], "AttributeNames": ["QueueArn", "KmsMasterKeyId",
                        "KmsDataKeyReusePeriodSeconds", "SqsManagedSseEnabled"]}, env)["Attributes"]
            save()

        for name, rule in rules.items():
            entries = [{"Id": kind, "Arn": queues[kind]["arn"],
                "DeadLetterConfig": {"Arn": queues["dlq"]["arn"]},
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}} for kind in kinds]
            targets[name] = [entry["Id"] for entry in entries]
            response = call("events", "put-targets", {"Rule": rule["name"], "EventBusName": prefix,
                "Targets": entries}, env)
            if response["FailedEntryCount"]:
                raise RuntimeError("Owned target registration failed: " + json.dumps(response))

        if kms:
            cases = [("cold-rule-b", "b"), ("cold-rule-a", "a"),
                     ("warm-rule-b", "b"), ("warm-rule-a", "a")]
            time.sleep(5)
        else:
            rule_arn = rules["default"]["arn"]
            cases = [
                ("service-principal", {}),
                ("source-arn", {"ArnEquals": {"aws:SourceArn": rule_arn}}),
                ("wrong-source-arn", {"ArnEquals": {"aws:SourceArn": rule_arn + "-other"}}),
                ("source-account", {"StringEquals": {"aws:SourceAccount": account}}),
                ("wrong-source-account", {"StringEquals": {"aws:SourceAccount": "000000000000"}}),
                ("principal-service-name", {"StringEquals": {"aws:PrincipalServiceName": "events.amazonaws.com"}}),
                ("principal-is-service", {"Bool": {"aws:PrincipalIsAWSService": "true"}}),
                ("principal-type", {"StringEquals": {"aws:PrincipalType": "AWSService"}}),
            ]
            if principal_types:
                cases = [("principal-type-" + kind, {"StringEquals": {"aws:PrincipalType": kind}})
                         for kind in ["Service", "Account", "AssumedRole", "Role", "User", "Anonymous"]]
                cases += [("principal-type-null-" + value, {"Null": {"aws:PrincipalType": value}})
                          for value in ["true", "false"]]

        for name, settings in cases:
            rule_name = settings if kms else "default"
            if not kms:
                set_queue_policy("target", settings)
                time.sleep(2)
            result = call("events", "put-events", {"Entries": [{"EventBusName": prefix, "Source": prefix,
                "DetailType": "authorization-probe", "Detail": json.dumps({"case": name, "rule": rule_name})}]}, env)
            if result["FailedEntryCount"]:
                raise RuntimeError("Owned event admission failed: " + json.dumps(result))

            def record(target_arn, delivery, attributes):
                kind = next(kind for kind in kinds if queues[kind]["arn"] == target_arn)
                observation = {"case": name + ":" + kind if kms else name,
                    "condition": conditions[kind] if kms else settings,
                    "delivery": delivery, "attributes": attributes}
                if kms:
                    observation.update(phase=name, rule=rule_name, target=kind,
                                       target_arn=target_arn, rule_arn=rules[rule_name]["arn"])
                capture["observations"].append(observation)
                save()
                print(observation["case"] + ": " + delivery, flush=True)

            receive_deliveries(queues, name, [queues[kind]["arn"] for kind in kinds], env, record)
        capture["capture_complete"] = True
    finally:
        cleanup_errors = []

        def cleanup(service, operation, parameters):
            try:
                return call(service, operation, parameters, env)
            except RuntimeError as error:
                cleanup_errors.append(str(error))
                return None

        for name, ids in targets.items():
            response = cleanup("events", "remove-targets", {"Rule": rules[name]["name"],
                "EventBusName": prefix, "Ids": ids})
            if response and response.get("FailedEntryCount"):
                cleanup_errors.append("Owned target cleanup failed: " + json.dumps(response))
        for rule in rules.values():
            cleanup("events", "delete-rule", {"Name": rule["name"], "EventBusName": prefix})
        if bus:
            cleanup("events", "delete-event-bus", {"Name": prefix})
        for queue in queues.values():
            cleanup("sqs", "delete-queue", {"QueueUrl": queue["url"]})
        if key:
            capture["key_cleanup"] = cleanup("kms", "schedule-key-deletion", {
                "KeyId": key["KeyId"], "PendingWindowInDays": 7})
        capture["cleanup"] = not cleanup_errors
        if cleanup_errors:
            capture["cleanup_errors"] = cleanup_errors
        save()
        print("cleanup: " + str(capture["cleanup"]), flush=True)
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--principal-types", action="store_true")
    mode.add_argument("--kms", action="store_true")
    arguments = parser.parse_args()
    main(arguments.account, arguments.principal_types, arguments.kms)
