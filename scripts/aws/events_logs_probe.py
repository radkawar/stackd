#!/usr/bin/env python3
"""Capture owned native EventBridge-to-Logs delivery; pass an output JSON path.

Uses shared AWS CLI capture helpers, no automatic retries, and only uniquely
owned resources. Raw CLI debug (including signing material) never leaves memory.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import ProbeResult, call, result, run


REGION = "us-east-1"
REFERENCES = [
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html",
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html",
    "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutTargets.html",
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html",
    *["https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_" + name + ".html"
      for name in ("PutResourcePolicy", "DescribeResourcePolicies", "DeleteResourcePolicy")],
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--account", required=True)
    parser.add_argument("--policy-precedence", action="store_true",
                        help="Capture only service-principal allow/deny scope composition and recovery")
    args = parser.parse_args()
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard")
    account = call("sts", "get-caller-identity", env=env)["Account"]
    if account != args.account:
        raise RuntimeError("Caller account differs from --account; no resources created")
    prefix = "stackd-events-logs-" + uuid.uuid4().hex[:20]
    group = "/aws/events/" + prefix
    group_arn = f"arn:aws:logs:{REGION}:{account}:log-group:{group}"
    rule = "owned-rule"
    rule_arn = f"arn:aws:events:{REGION}:{account}:rule/{prefix}/{rule}"
    policy_name = prefix + "-resource"
    account_policy = prefix + "-account"
    queue_name = prefix + "-dlq"
    queue_arn = f"arn:aws:sqs:{REGION}:{account}:{queue_name}"
    source = "stackd.native.events-logs"
    rule_input = {"Name": rule, "EventBusName": prefix}
    target_input = {"Rule": rule, "EventBusName": prefix}
    scoped = {"resourceArn": group_arn}
    capture = {
        "source": "Native AWS CLI, actual configured credentials; not emulator output",
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": REGION,
        "primary_references": REFERENCES,
        "scope": "One unique custom bus/rule, Logs group, resource policy, account policy limited to the owned group/source, and standard SQS target DLQ. No existing policies modified or unrelated Logs records read.",
        "identity_relationships": {
            "caller_account": account, "source_rule_and_destination_account_match": True,
            "source_rule_arn": rule_arn, "destination_group_arn": group_arn,
            "substitutions": "Private native capture retains caller account, owned names, timestamps, IDs, revisions, tokens and stream suffixes. Caller ARN/UserId discarded.",
        },
        "request_counts": {"sts": 1, "logs": 0, "events": 0, "sqs": 0, "total": 1,
                           "automatic_retries": False},
        "bounds": {"max_requests_excluding_cleanup": 150, "success_poll_attempts": 18,
                   "success_poll_interval_seconds": 5, "revoked_dlq_polls": 6,
                   "dlq_long_poll_seconds": 10, "target_maximum_retries": 0,
                   "target_maximum_age_seconds": 60},
        "observations": [], "delivery": {}, "cleanup": {"verified": False},
        "limitations": [
            "One account/region/run. EventBridge eventual propagation and batching are observed only within recorded polling bounds.",
            "HTTP status comes from shared result(debug=True); native modeled error text is retained, not the raw debug/signing log.",
            "Revision tests are sequential stale-token concurrency guards, not simultaneous racing writes.",
            "Describe account policies is not called without the owned resourceArn filter; unrelated policy bodies returned despite a filter are discarded.",
            "DLQ messages and Logs events can be duplicates; bounded absence is not proof of permanent loss or authorization denial.",
        ],
    }
    if args.policy_precedence:
        capture["mode"] = "policy-precedence"
        capture["bounds"].update({"permission_poll_attempts": 6,
                                 "policy_propagation_wait_seconds": 20,
                                 "delivered_conflict_recheck_wait_seconds": 60})
        capture["limitations"] = [item for item in capture["limitations"]
                                 if not item.startswith("Revision tests")]
    if args.output.exists():
        previous = json.loads(args.output.read_text())
        if previous:
            if not previous.get("cleanup", {}).get("verified"):
                raise RuntimeError("Prior owned run has unverified cleanup; refusing to overwrite")
            capture["previous_runs"] = previous.pop("previous_runs", []) + [previous]
    owned = {"group": False, "bus": False, "rule": False, "queue": False,
             "resource_policy": False, "account_policy": False}
    queue_url = None
    revision = None
    cleaning = False

    def save():
        text = json.dumps(capture, indent=2, ensure_ascii=False)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")

    def request(label, service, operation, parameters) -> ProbeResult:
        if not cleaning and capture["request_counts"]["total"] >= 150:
            raise RuntimeError("Bounded request allowance exhausted")
        capture["request_counts"][service] += 1
        capture["request_counts"]["total"] += 1
        entry = {"label": label, "service": service, "operation": operation, "input": parameters,
                 "request_started_ms": time.time_ns() // 1_000_000}
        capture["observations"].append(entry)
        try:
            process = run(service, operation, parameters, env, options=[
                "--debug", "--no-paginate", "--cli-connect-timeout", "10", "--cli-read-timeout", "30",
            ], timeout=50)
            response = result(process, debug=True, cli_message=None)
            if operation == "describe-resource-policies" and response["code"] == "Success":
                output = response["output"]
                rows = output.get("resourcePolicies", [])
                kept = [row for row in rows if row.get("policyName", "").startswith(prefix)
                        or row.get("resourceArn") == group_arn]
                if len(kept) != len(rows):
                    entry["unrelated_policy_records_discarded"] = len(rows) - len(kept)
                    output["resourcePolicies"] = kept
            entry["result"] = response
        except Exception as error:
            entry["transport_error"] = type(error).__name__
            raise
        finally:
            entry["request_finished_ms"] = time.time_ns() // 1_000_000
            save()
        print(label + ": " + response["code"], flush=True)
        return response

    def require(response):
        if response["code"] != "Success" or response.get("output", {}).get("FailedEntryCount", 0):
            raise RuntimeError("Required native operation failed: " + response["code"])
        return response["output"]

    def policy(sid="OwnedEventBridgeLogs", action=None, effect="Allow"):
        return json.dumps({"Version": "2012-10-17", "Statement": [{
            "Sid": sid, "Effect": effect,
            "Principal": {"Service": ["events.amazonaws.com", "delivery.logs.amazonaws.com"]},
            "Action": action or ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": group_arn + ":*",
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn},
                          "StringEquals": {"aws:SourceAccount": account}},
        }]}, separators=(",", ":"))

    def put_scoped(label, **extra):
        nonlocal revision
        document = extra.pop("policyDocument", policy())
        response = request(label, "logs", "put-resource-policy", dict(scoped, policyDocument=document, **extra))
        if response["code"] == "Success":
            owned["resource_policy"] = True
            output = response["output"]
            revision = output.get("revisionId") or output.get("resourcePolicy", {}).get("revisionId")
        return response

    def describe_policy(label, **extra):
        return request(label, "logs", "describe-resource-policies", dict(resourceArn=group_arn, **extra))

    def emit(label):
        sent_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)).replace(microsecond=123000)
        parameters = {"Entries": [{"EventBusName": prefix, "Source": source,
            "DetailType": "OwnedLogsDestination", "Time": sent_time.isoformat(),
            "Resources": [rule_arn], "Detail": json.dumps({"probe": label, "text": "owned hello", "n": 7})}]}
        output = require(request("put-event-" + label, "events", "put-events", parameters))
        return output["Entries"][0]["EventId"]

    def poll_logs(label, event_id, attempts=18):
        started = time.monotonic()
        rows = []
        for attempt in range(attempts):
            response = require(request(f"logs-{label}-{attempt}", "logs", "filter-log-events", {
                "logGroupName": group, "limit": 100,
            }))
            rows = response.get("events", [])
            if any(event_id in row["message"] or ("transformed-" + label) in row["message"] for row in rows):
                break
            if attempt + 1 < attempts:
                time.sleep(5)
        matched = [row for row in rows if event_id in row["message"] or ("transformed-" + label) in row["message"]]
        capture["delivery"][label] = {"event_id": event_id, "elapsed_seconds": round(time.monotonic() - started, 3),
                                      "matched_log_events": matched, "poll_attempts": attempt + 1}
        save()
        return matched

    def permission_delivery(label):
        time.sleep(20)
        event_id = emit(label)
        messages = []
        started = time.monotonic()
        for attempt in range(6):
            matched = poll_logs(label, event_id, attempts=1)
            output = require(request(f"dlq-{label}-{attempt}", "sqs", "receive-message", {
                "QueueUrl": queue_url, "MaxNumberOfMessages": 10, "WaitTimeSeconds": 10,
                "VisibilityTimeout": 90, "MessageAttributeNames": ["All"],
                "MessageSystemAttributeNames": ["All"]}))
            messages.extend(output.get("Messages", []))
            matching = [message for message in messages if event_id in message["Body"]]
            if matched or matching:
                break
        # A delivery may arrive during the last DLQ long poll.
        matched = poll_logs(label, event_id, attempts=1)
        capture["delivery"][label].update({
            "messages": messages, "matching_dlq_messages": matching,
            "permission_poll_attempts": attempt + 1,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "outcome": ("delivered-and-dlq" if matched and matching else "delivered" if matched
                        else "dlq" if matching else "unresolved-within-bounds"),
        })
        save()
        return capture["delivery"][label]

    def policy_precedence():
        target = {"Id": "owned-target", "Arn": group_arn,
                  "DeadLetterConfig": {"Arn": queue_arn},
                  "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}
        capture["permission_precedence"] = {
            "policy_conditions": {"aws:SourceArn": rule_arn, "aws:SourceAccount": account},
            "principal_services": ["events.amazonaws.com", "delivery.logs.amazonaws.com"],
            "actions": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "resource": group_arn + ":*",
            "interpretation": "Only event-correlated Logs records or native DLQ diagnostics establish delivery outcomes. Bounded absence is unresolved; successful conflicting-policy delivery does not establish permanent non-enforcement.",
        }
        require(put_scoped("precedence-resource-allow"))
        require(request("target-default", "events", "put-targets", dict(target_input, Targets=[target])))
        require(request("list-target-default", "events", "list-targets-by-rule", target_input))
        baseline = permission_delivery("resource-allow-only")
        if not baseline["matched_log_events"]:
            raise RuntimeError("Resource-only baseline delivery was not observed")
        capture["successful_default_delivery_observed"] = True

        denied = request("precedence-account-deny", "logs", "put-resource-policy", {
            "policyName": account_policy, "policyDocument": policy(effect="Deny")})
        capture["permission_precedence"]["account_deny_admission"] = denied
        if denied["code"] == "Success":
            owned["account_policy"] = True
            describe_policy("precedence-account-deny-described", policyScope="ACCOUNT")
            describe_policy("precedence-resource-allow-described", policyScope="RESOURCE")
            conflict = permission_delivery("resource-allow-account-deny")
            if conflict["matched_log_events"]:
                time.sleep(60)
                permission_delivery("resource-allow-account-deny-recheck")
            require(request("precedence-delete-account-deny", "logs", "delete-resource-policy",
                            {"policyName": account_policy}))
            owned["account_policy"] = False
            permission_delivery("resource-allow-after-account-deny-deleted")

        require(request("precedence-account-allow", "logs", "put-resource-policy", {
            "policyName": account_policy, "policyDocument": policy()}))
        owned["account_policy"] = True
        require(request("precedence-delete-resource-allow", "logs", "delete-resource-policy",
                        dict(scoped, expectedRevisionId=revision)))
        owned["resource_policy"] = False
        describe_policy("precedence-resource-absent", policyScope="RESOURCE")
        permission_delivery("account-allow-only")
        denied = put_scoped("precedence-resource-deny", policyDocument=policy(effect="Deny"))
        capture["permission_precedence"]["resource_deny_admission"] = denied
        if denied["code"] == "Success":
            describe_policy("precedence-resource-deny-described", policyScope="RESOURCE")
            describe_policy("precedence-account-allow-described", policyScope="ACCOUNT")
            conflict = permission_delivery("account-allow-resource-deny")
            if conflict["matched_log_events"]:
                time.sleep(60)
                permission_delivery("account-allow-resource-deny-recheck")
            require(request("precedence-delete-resource-deny", "logs", "delete-resource-policy",
                            dict(scoped, expectedRevisionId=revision)))
            owned["resource_policy"] = False
            describe_policy("precedence-resource-deny-absent", policyScope="RESOURCE")
            permission_delivery("account-allow-after-resource-deny-deleted")
        save()

    try:
        require(request("create-group", "logs", "create-log-group", {"logGroupName": group}))
        owned["group"] = True
        require(request("retention-one-day", "logs", "put-retention-policy", {"logGroupName": group, "retentionInDays": 1}))
        require(request("create-bus", "events", "create-event-bus", {"Name": prefix}))
        owned["bus"] = True
        require(request("create-rule", "events", "put-rule", dict(rule_input, EventPattern=json.dumps({"source": [source]}))))
        owned["rule"] = True
        queue_url = require(request("create-dlq", "sqs", "create-queue", {"QueueName": queue_name,
            "Attributes": {"MessageRetentionPeriod": "300"}}))["QueueUrl"]
        owned["queue"] = True
        queue_policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})
        require(request("authorize-dlq", "sqs", "set-queue-attributes", {"QueueUrl": queue_url, "Attributes": {"Policy": queue_policy}}))
        if args.policy_precedence:
            policy_precedence()
            return
        describe_policy("resource-policy-before-create", policyScope="RESOURCE")
        request("policy-name-and-resource-arn", "logs", "put-resource-policy",
                dict(scoped, policyName=policy_name, policyDocument=policy()))
        request("policy-invalid-json", "logs", "put-resource-policy", dict(scoped, policyDocument="not-json"))
        request("policy-invalid-document", "logs", "put-resource-policy", dict(scoped, policyDocument="{}"))
        request("policy-invalid-resource-stream", "logs", "put-resource-policy", dict(scoped, resourceArn=group_arn + ":log-stream:owned-invalid", policyDocument=policy()))
        require(put_scoped("resource-policy-create-revision-omitted"))
        original_revision = revision
        describe_policy("resource-policy-describe", policyScope="RESOURCE")
        describe_policy("resource-policy-describe-default-scope")
        put_scoped("resource-policy-update-revision-omitted")
        put_scoped("resource-policy-update-bogus-revision", expectedRevisionId="owned-invalid-revision")
        require(put_scoped("resource-policy-update-current-revision", expectedRevisionId=revision))
        put_scoped("resource-policy-update-stale-revision", expectedRevisionId=original_revision)
        request("resource-policy-delete-stale-revision", "logs", "delete-resource-policy", dict(scoped, expectedRevisionId=original_revision))
        describe_policy("resource-policy-after-rejected-revisions", policyScope="RESOURCE")
        request("resource-policy-unsupported-action", "logs", "put-resource-policy", dict(scoped, expectedRevisionId=revision,
            policyDocument=policy(action=["logs:DeleteLogGroup"])))
        refreshed = require(describe_policy("resource-policy-after-action-probe", policyScope="RESOURCE"))
        if refreshed.get("resourcePolicies"):
            revision = refreshed["resourcePolicies"][0].get("revisionId", revision)
        require(put_scoped("restore-resource-policy", expectedRevisionId=revision))
        target = {"Id": "owned-target", "Arn": group_arn,
                  "DeadLetterConfig": {"Arn": queue_arn},
                  "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}
        for label, change in [
            ("role-arn", {"RoleArn": f"arn:aws:iam::{account}:role/{prefix}-uncreated"}),
            ("input-constant", {"Input": '{"message":"owned-constant"}'}),
            ("input-path", {"InputPath": "$.detail"}),
            ("stream-arn", {"Arn": group_arn + ":log-stream:owned-invalid"}),
            ("transformer-missing-timestamp", {"InputTransformer": {"InputTemplate": '{"message":"owned"}'}}),
        ]:
            request("target-" + label, "events", "put-targets", dict(target_input, Targets=[dict(target, **change)]))
        require(request("target-default", "events", "put-targets", dict(target_input, Targets=[target])))
        request("list-target-default", "events", "list-targets-by-rule", target_input)
        time.sleep(15)
        event_id = emit("resource-policy-default")
        delivered = poll_logs("resource-policy-default", event_id)

        account_response = request("account-policy-create", "logs", "put-resource-policy", {
            "policyName": account_policy, "policyDocument": policy()})
        if account_response["code"] == "Success":
            owned["account_policy"] = True
            request("account-policy-update-bogus-revision", "logs", "put-resource-policy", {
                "policyName": account_policy, "policyDocument": policy("OwnedUpdated"), "expectedRevisionId": "owned-invalid-revision"})
            describe_policy("account-policy-describe-filtered", policyScope="ACCOUNT")
            if not delivered:
                time.sleep(15)
                delivered = poll_logs("account-policy-default", emit("account-policy-default"))
        if not delivered:
            capture["limitations"].append("No successful default delivery within both scoped and account policy windows; DLQ inspected before cleanup.")
        else:
            transformed = dict(target, InputTransformer={
                "InputPathsMap": {"timestamp": "$.time", "text": "$.detail.text", "probe": "$.detail.probe"},
                "InputTemplate": '{"timestamp":<timestamp>,"message":"transformed-<probe>: <text>"}',
            })
            transform_response = request("target-transformer-timestamp-message", "events", "put-targets", dict(target_input, Targets=[transformed]))
            if transform_response["code"] == "Success" and not transform_response["output"].get("FailedEntryCount"):
                request("list-target-transformed", "events", "list-targets-by-rule", target_input)
                time.sleep(15)
                poll_logs("transformed", emit("transformed"))
            streams = require(request("describe-delivered-streams", "logs", "describe-log-streams", {"logGroupName": group, "limit": 10}))
            for stream in streams.get("logStreams", [])[:5]:
                request("get-delivered-stream", "logs", "get-log-events", {"logGroupName": group,
                    "logStreamName": stream["logStreamName"], "startFromHead": True, "limit": 100})

        if owned["account_policy"]:
            deleted = request("account-policy-delete-bogus-revision", "logs", "delete-resource-policy", {
                "policyName": account_policy, "expectedRevisionId": "owned-invalid-revision"})
            if deleted["code"] == "Success":
                owned["account_policy"] = False
            else:
                require(request("account-policy-delete", "logs", "delete-resource-policy", {"policyName": account_policy}))
                owned["account_policy"] = False
            request("account-policy-delete-again", "logs", "delete-resource-policy", {"policyName": account_policy})
        deleted = request("resource-policy-delete-revision-omitted", "logs", "delete-resource-policy", scoped)
        if deleted["code"] == "Success":
            owned["resource_policy"] = False
        else:
            require(request("resource-policy-delete-current-revision", "logs", "delete-resource-policy", dict(scoped, expectedRevisionId=revision)))
            owned["resource_policy"] = False
        describe_policy("resource-policy-after-delete", policyScope="RESOURCE")
        request("resource-policy-delete-again", "logs", "delete-resource-policy", dict(scoped, expectedRevisionId=revision))
        require(request("restore-default-target-before-revocation", "events", "put-targets", dict(target_input, Targets=[target])))
        time.sleep(20)
        revoked_id = emit("revoked")
        dlq_messages = []
        started = time.monotonic()
        for attempt in range(6):
            output = require(request(f"dlq-after-revoke-{attempt}", "sqs", "receive-message", {"QueueUrl": queue_url,
                "MaxNumberOfMessages": 10, "WaitTimeSeconds": 10, "VisibilityTimeout": 90,
                "MessageAttributeNames": ["All"], "MessageSystemAttributeNames": ["All"]}))
            dlq_messages.extend(output.get("Messages", []))
            if any(revoked_id in message["Body"] for message in dlq_messages):
                break
        capture["delivery"]["revocation_dlq"] = {"event_id": revoked_id, "messages": dlq_messages,
            "elapsed_seconds": round(time.monotonic() - started, 3), "poll_attempts": attempt + 1,
            "matching_messages": sum(revoked_id in message["Body"] for message in dlq_messages)}
        poll_logs("revoked", revoked_id, attempts=1)
        capture["successful_default_delivery_observed"] = bool(delivered)
    except Exception as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cleaning = True
        failures = []

        def cleanup(label, service, operation, parameters, accepted=("Success",)):
            try:
                response = request("cleanup-" + label, service, operation, parameters)
                if response["code"] not in accepted or response.get("output", {}).get("FailedEntryCount", 0):
                    failures.append(label + ": " + response["code"])
                return response
            except Exception as error:
                failures.append(label + ": " + type(error).__name__)
                return {"code": "CleanupTransportError"}

        if owned["rule"]:
            cleanup("remove-target", "events", "remove-targets", dict(target_input, Ids=["owned-target"]))
            cleanup("delete-rule", "events", "delete-rule", rule_input)
            cleanup("verify-rule-absent", "events", "describe-rule", rule_input, ("ResourceNotFoundException",))
        if owned["bus"]:
            cleanup("delete-bus", "events", "delete-event-bus", {"Name": prefix})
            cleanup("verify-bus-absent", "events", "describe-event-bus", {"Name": prefix}, ("ResourceNotFoundException",))
        if owned["resource_policy"]:
            parameters = dict(scoped)
            if revision:
                parameters["expectedRevisionId"] = revision
            cleanup("delete-resource-policy", "logs", "delete-resource-policy", parameters, ("Success", "ResourceNotFoundException"))
        if owned["account_policy"]:
            cleanup("delete-account-policy", "logs", "delete-resource-policy", {"policyName": account_policy}, ("Success", "ResourceNotFoundException"))
            if args.policy_precedence:
                cleanup("verify-account-policy-absent", "logs", "delete-resource-policy",
                        {"policyName": account_policy}, ("ResourceNotFoundException",))
        if owned["group"]:
            policies = cleanup("verify-resource-policy-absent", "logs", "describe-resource-policies", {"resourceArn": group_arn, "policyScope": "RESOURCE"})
            if policies.get("output", {}).get("resourcePolicies"):
                failures.append("Resource policy remains")
            cleanup("delete-group", "logs", "delete-log-group", {"logGroupName": group})
            cleanup("verify-group-absent", "logs", "describe-log-streams", {"logGroupName": group}, ("ResourceNotFoundException",))
        if owned["queue"]:
            cleanup("delete-dlq", "sqs", "delete-queue", {"QueueUrl": queue_url})
            cleanup("verify-dlq-absent", "sqs", "get-queue-url", {"QueueName": queue_name}, ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
        capture["cleanup"] = {"verified": not failures, "failures": failures,
                              "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        save()
        if failures:
            raise RuntimeError("Owned cleanup not verified")
    if not capture.get("successful_default_delivery_observed"):
        raise RuntimeError("No successful EventBridge-to-Logs record captured")
    print("Capture saved; successful delivery and owned cleanup verified", flush=True)


if __name__ == "__main__":
    main()
