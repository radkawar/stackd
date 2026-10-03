#!/usr/bin/env python3
"""Capture bounded, uniquely owned native Logs-to-Lambda-to-SQS behavior.

Pass --account ACCOUNT and an output JSON path. Uses aws_cli transport and the existing Lambda native
fixture's minimal IAM/ZIP provisioning pattern; only the owned queue is writable
by customer code. Raw signing/debug output never leaves process memory.
"""
import argparse
import ast
import base64
import collections
import datetime
import io
import json
import os
from pathlib import Path
import time
import uuid
import zipfile

from aws_cli import call, result, run
from cloudtrail_events import CollectionError, collect_history


REGION = "us-east-1"
HANDLER = '''import base64, gzip, json, os, time
import boto3
sqs = boto3.client("sqs", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))
def handler(event, context):
    raw = gzip.decompress(base64.b64decode(event["awslogs"]["data"]))
    record = {"envelope": json.loads(raw), "decoded_utf8": raw.decode("utf-8"),
              "handler_request_id": context.aws_request_id,
              "invoked_function_arn": context.invoked_function_arn,
              "received_unix": time.time()}
    sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps(record))
    return {"collected": True}
'''


def capture_audit(source, output, account):
    """Recover exact-ID management evidence without recreating owned resources."""
    capture = json.loads(source.read_text())
    if not capture["cleanup"]["verified"] or output.exists():
        raise RuntimeError("Audit harvest needs a cleaned source and a new output path")
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    identity = call("sts", "get-caller-identity", env=env)
    if identity["Account"] != account:
        raise RuntimeError("Unexpected native account")
    calls = []
    for row in capture["observations"]:
        if row["service"] != "logs" or row["operation"] == "put-log-events":
            continue
        headers = {key.lower(): value for key, value in row["result"].get("headers", {}).items()}
        request_id = headers.get("x-amzn-requestid") or headers.get("x-amz-request-id")
        if request_id:
            calls.append({**row, "request_id": request_id})
    if not calls:
        raise RuntimeError("Source has no retained Logs management request IDs")
    start = datetime.datetime.fromtimestamp(
        min(row["request_started_ms"] for row in calls) / 1000 - 5, datetime.timezone.utc)
    end = datetime.datetime.fromtimestamp(
        max(row["request_finished_ms"] for row in calls) / 1000 + 5, datetime.timezone.utc)
    evidence = {"captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source_capture": str(source), "account": identity["Account"], "region": REGION,
                "scope": "Read-only exact-request management history from an already cleaned Logs subscription workflow",
                "input_substitutions": capture.get("substitutions"),
                "calls": calls, "cleanup_verified": True,
                "limitations": ["Original inputs retain the source capture's substitutions; CloudTrail events retain native identities and names.",
                                "PutLogEvents is excluded following the documented producer set; this is not evidence of native non-emission."]}
    try:
        evidence["cloudtrail"] = collect_history(
            lambda parameters: call("cloudtrail", "lookup-events", parameters, env=env, paginate=False),
            {row["request_id"]: row["label"] for row in calls},
            start_time=start, end_time=end, event_sources=("logs.amazonaws.com",),
            max_pages=20, rounds=1, wait_seconds=0)
    except CollectionError as error:
        evidence["cloudtrail"] = error.result
        raise
    finally:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"events": len(evidence["cloudtrail"]["events"]),
                      "missing_calls": evidence["cloudtrail"]["missing_calls"],
                      "cleanup_verified": True}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("output", type=Path)
    parser.add_argument("--audit-output", type=Path,
                        help="Only harvest native management history for the existing cleaned output capture")
    args = parser.parse_args()
    if args.audit_output:
        capture_audit(args.output, args.audit_output, args.account)
        return
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard")
    prefix = "stackd-logs-sub-" + uuid.uuid4().hex[:16]
    account = None
    group = "/stackd/" + prefix
    role_name = prefix + "-exec"
    queue_url = None
    function_arn = None
    role_arn = None
    group_arn = None
    permissions = set()
    owned = {"group": False, "queue": False, "role": False, "policy": False, "function": False}
    cleaning = False
    started = time.monotonic()
    capture = {
        "source": "Native AWS CLI and real Python3.12 Lambda runtime using boto3 SQS; no mocks",
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "partition": "aws", "region": REGION,
        "scope": "One owned Lambda, inline-policy IAM role, SQS collector, source group/two streams. No existing resources changed. Runtime has only sqs:SendMessage on owned queue; CloudWatch runtime logging is intentionally not granted.",
        "references": [
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeSubscriptionFilters.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/DeveloperGuide/Subscriptions.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/DeveloperGuide/SubscriptionFilters.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/DeveloperGuide/regex-expressions.html"],
        "substitutions": "Account becomes 123456789012; unique prefix becomes stackd-logs-sub-owned. Caller ARN/UserId, Lambda presigned code location, and SQS receipt handles discarded. Replayable ZIP and handler source retained. Native decoded UTF-8 strings, arrays, timestamps, IDs and field presence preserved otherwise.",
        "bounds": {"max_requests_excluding_cleanup": 350, "max_work_seconds": 650,
                   "automatic_retries": False, "iam_propagation_retries": 1,
                   "iam_initial_wait_seconds": 15, "subscription_settle_seconds": 12,
                   "iam_retry_wait_seconds": 10, "collector_poll_wait_seconds": 5},
        "request_counts": {"total": 0}, "observations": [], "deliveries": [], "windows": [],
        "published": [], "cleanup": {"verified": False},
        "limitations": ["One account, region and bounded run; absence during a poll window does not establish permanent loss.",
                        "Ordering, grouping, duplicates and permission revocation/restore timing are observations, not deterministic service guarantees.",
                        "CONTROL_MESSAGE records are actual collector observations; no absence-based synthetic control outcome is generated.",
                        "Lambda invocation and SQS send requests inside the managed service/runtime are not observable CLI requests and are not included in CLI request counts."]}
    if args.output.exists():
        prior = json.loads(args.output.read_text())
        if prior and not prior.get("cleanup", {}).get("verified"):
            raise RuntimeError("Refusing to overwrite capture with unverified owned cleanup")
        if prior:
            capture["previous_runs"] = prior.pop("previous_runs", []) + [prior]

    def save():
        text = json.dumps(capture, indent=2, ensure_ascii=False)
        if account:
            text = text.replace(account, "123456789012")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text.replace(prefix, "stackd-logs-sub-owned") + "\n")

    def request(label, service, operation, parameters):
        if not cleaning and (capture["request_counts"]["total"] >= 350 or time.monotonic() - started > 650):
            raise RuntimeError("Native work bound exhausted; cleaning owned resources")
        counts = capture["request_counts"]
        counts[service] = counts.get(service, 0) + 1
        counts["total"] += 1
        shown = json.loads(json.dumps(parameters))
        if "ReceiptHandle" in shown:
            shown["ReceiptHandle"] = "<owned receipt handle>"
        entry = {"label": label, "service": service, "operation": operation,
                 "input": shown, "request_started_ms": time.time_ns() // 1_000_000}
        capture["observations"].append(entry)
        try:
            process = run(service, operation, parameters, env, options=[
                "--debug", "--no-paginate", "--cli-connect-timeout", "10", "--cli-read-timeout", "15"], timeout=35)
            response = result(process, debug=True, cli_message=None)
            for line in process.stderr.splitlines():
                if "Response headers:" in line:
                    try:
                        headers = ast.literal_eval(line.split("Response headers:", 1)[1].strip())
                        response["headers"] = {key: value for key, value in headers.items()
                                               if key.lower() in ("date", "x-amzn-requestid", "x-amz-request-id")}
                    except (SyntaxError, ValueError):
                        pass
            output = response.get("output", {})
            if service == "sts":
                output.pop("Arn", None)
                output.pop("UserId", None)
            if operation == "get-function":
                output.pop("Code", None)
            stored = json.loads(json.dumps(response))
            for message in stored.get("output", {}).get("Messages", []):
                message.pop("ReceiptHandle", None)
            entry["result"] = stored
        except Exception as error:
            entry["transport_error"] = type(error).__name__
            raise
        finally:
            entry["request_finished_ms"] = time.time_ns() // 1_000_000
            save()
        print(label + ": " + response["code"], flush=True)
        return response

    def require(response):
        if response["code"] != "Success":
            raise RuntimeError("Required native request failed: " + response["code"])
        return response["output"]

    def put(label, name="a-main", pattern='{ $.kind = "accept" }', **extra):
        parameters = dict(logGroupName=group, filterName=name, filterPattern=pattern, destinationArn=function_arn)
        parameters.update(extra)
        return request(label, "logs", "put-subscription-filter", parameters)

    def describe(label, **extra):
        return request(label, "logs", "describe-subscription-filters", dict(logGroupName=group, **extra))

    def remove(name):
        return request("delete-filter-" + name, "logs", "delete-subscription-filter", dict(logGroupName=group, filterName=name))

    def permission(label, principal="logs.amazonaws.com", source=None, source_account=None):
        parameters = dict(FunctionName=prefix, StatementId=label, Action="lambda:InvokeFunction", Principal=principal,
                          SourceArn=source or group_arn + ":*", SourceAccount=source_account or account)
        response = request("permission-" + label, "lambda", "add-permission", parameters)
        if response["code"] == "Success":
            permissions.add(label)
        return response

    def revoke(label):
        response = request("revoke-" + label, "lambda", "remove-permission", dict(FunctionName=prefix, StatementId=label))
        if response["code"] == "Success":
            permissions.discard(label)
        return response

    def publish(stage, stream="one", partial=False, plain=False):
        if stage != "before-subscription":
            time.sleep(12)
        now = time.time_ns() // 1_000_000
        rows = []
        if partial:
            rows.append({"timestamp": now - 15 * 86400000, "message": json.dumps({"stage": stage, "kind": "accept", "case": "expired"})})
        for kind in ("accept", "skip"):
            message = json.dumps({"stage": stage, "kind": kind, "case": stage + "-" + kind, "text": "owned ü", "n": 7})
            rows.append({"timestamp": now, "message": message})
        if plain:
            rows.append({"timestamp": now, "message": stage + " plain accept"})
        if partial:
            rows.append({"timestamp": now + 3 * 3600000, "message": json.dumps({"stage": stage, "kind": "accept", "case": "future"})})
        response = request("publish-" + stage, "logs", "put-log-events", dict(logGroupName=group, logStreamName=stream, logEvents=rows))
        capture["published"].append({"stage": stage, "stream": stream, "events": rows, "result": response})
        save()
        require(response)

    def poll(label, attempts=3, until_stage=None):
        before = len(capture["deliveries"])
        begin = time.monotonic()
        seen = False
        for attempt in range(attempts):
            output = require(request(f"collect-{label}-{attempt}", "sqs", "receive-message", dict(
                QueueUrl=queue_url, WaitTimeSeconds=5, MaxNumberOfMessages=10, VisibilityTimeout=60,
                MessageSystemAttributeNames=["All"])))
            for message in output.get("Messages", []):
                record = json.loads(message["Body"])
                capture["deliveries"].append({"poll_window": label, "sqs_message_id": message["MessageId"],
                                               "sqs_attributes": message.get("Attributes", {}), "record": record})
                require(request("ack-" + message["MessageId"], "sqs", "delete-message", dict(
                    QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])))
                if until_stage and any(until_stage in event.get("message", "")
                                       for event in record["envelope"].get("logEvents", [])):
                    seen = True
            if seen:
                break
        capture["windows"].append({"label": label, "attempts": attempt + 1,
                                   "elapsed_seconds": round(time.monotonic() - begin, 3),
                                   "new_records": len(capture["deliveries"]) - before,
                                   "correlated_stage": until_stage, "stage_observed": seen if until_stage else None})
        save()
        return seen

    try:
        account = require(request("identity", "sts", "get-caller-identity", {}))["Account"]
        if account != args.account:
            raise RuntimeError("Account does not match --account; no resources created")
        group_arn = f"arn:aws:logs:{REGION}:{account}:log-group:{group}"
        function_arn = f"arn:aws:lambda:{REGION}:{account}:function:{prefix}"
        role_arn = f"arn:aws:iam::{account}:role/{role_name}"
        capture["identity_relationships"] = dict(owner=account, source_group_arn=group_arn,
                                                   destination_arn=function_arn, role_arn=role_arn)
        queue_url = require(request("create-collector", "sqs", "create-queue", dict(QueueName=prefix,
                            Attributes={"MessageRetentionPeriod": "3600"})))["QueueUrl"]
        owned["queue"] = True
        queue_arn = require(request("collector-arn", "sqs", "get-queue-attributes", dict(
            QueueUrl=queue_url, AttributeNames=["QueueArn"])))["Attributes"]["QueueArn"]
        require(request("create-group", "logs", "create-log-group", dict(logGroupName=group)))
        owned["group"] = True
        for stream in ("one", "two"):
            require(request("create-stream-" + stream, "logs", "create-log-stream", dict(logGroupName=group, logStreamName=stream)))
        publish("before-subscription")
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        require(request("create-role", "iam", "create-role", dict(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))))
        owned["role"] = True
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        require(request("put-owned-policy", "iam", "put-role-policy", dict(RoleName=role_name, PolicyName="owned-collector", PolicyDocument=json.dumps(policy))))
        owned["policy"] = True
        time.sleep(15)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr("handler.py", HANDLER)
        capture["handler_source"] = HANDLER
        parameters = dict(FunctionName=prefix, Runtime="python3.12", Role=role_arn,
                          Handler="handler.handler", Timeout=10, MemorySize=128,
                          Code={"ZipFile": base64.b64encode(archive.getvalue()).decode()},
                          Environment={"Variables": {"QUEUE_URL": queue_url}})
        created = request("create-function", "lambda", "create-function", parameters)
        if created["code"] == "InvalidParameterValueException" and "cannot be assumed" in created.get("message", ""):
            time.sleep(10)
            created = request("create-function-iam-propagation-retry", "lambda", "create-function", parameters)
        require(created)
        owned["function"] = True
        for attempt in range(10):
            state = require(request("function-state-" + str(attempt), "lambda", "get-function-configuration", dict(FunctionName=prefix)))
            if state.get("State") == "Active":
                break
            time.sleep(2)
        else:
            raise RuntimeError("Owned function did not become active within bounds")
        put("missing-destination", destinationArn=function_arn + "-missing")
        put("missing-permission")
        describe("empty-after-failures")
        require(permission("wrong-source", source=group_arn + "-wrong:*"))
        put("wrong-source-arn")
        require(revoke("wrong-source"))
        require(permission("wrong-account", source_account="000000000000"))
        put("wrong-source-account")
        require(revoke("wrong-account"))
        require(permission("exact-source", source=group_arn))
        put("exact-source-arn")
        require(revoke("exact-source"))
        require(permission("global"))
        require(put("global-principal-create"))
        poll("global-control", attempts=3)
        require(describe("state-created"))
        quota = request("default-service-quotas", "service-quotas", "list-aws-default-service-quotas", dict(ServiceCode="logs", MaxResults=100))
        if quota["code"] == "Success":
            capture["subscription_default_quotas"] = [row for row in quota["output"].get("Quotas", []) if "subscription" in row.get("QuotaName", "").lower()]
        admitted = ["a-main"]
        for index in range(2, 7):
            name = f"quota-{index}"
            response = put("quota-filter-" + str(index), name=name)
            if response["code"] == "Success":
                admitted.append(name)
        capture["admitted_filters_same_group"] = len(admitted)
        require(describe("quota-state"))
        save()
        print("DECISIVE_ADMITTED_FILTERS=" + str(len(admitted)), flush=True)
        page = require(describe("page-first", limit=1))
        if page.get("nextToken"):
            describe("page-second", limit=1, nextToken=page["nextToken"])
            describe("page-prefix-token", filterNamePrefix="quota-", limit=1, nextToken=page["nextToken"])
        describe("prefix-quota", filterNamePrefix="quota-")
        describe("invalid-token", nextToken="invalid")
        describe("invalid-limit", limit=0)
        for name in admitted[1:]:
            require(remove(name))
        require(put("regional-replace-prep"))
        require(revoke("global"))
        require(permission("regional", principal=f"logs.{REGION}.amazonaws.com"))
        regional = put("regional-principal-replace")
        capture["regional_principal_admission"] = regional
        if regional["code"] != "Success":
            require(revoke("regional"))
            require(permission("global-restored"))
        poll("regional-control", attempts=2)
        put("failed-replacement-missing-destination", pattern="changed", destinationArn=function_arn + "-missing")
        require(describe("preserved-after-bad-destination"))
        active_permission = "regional" if regional["code"] == "Success" else "global-restored"
        require(revoke(active_permission))
        put("failed-replacement-no-permission", pattern="changed")
        require(describe("preserved-after-no-permission"))
        require(permission("delivery"))
        require(put("restore-baseline"))
        for label, extra in [
            ("role-arn", {"roleArn": role_arn}),
            ("distribution-random", {"distribution": "Random"}),
            ("distribution-by-stream", {"distribution": "ByLogStream"}),
            ("distribution-invalid", {"distribution": "Other"}),
            ("transformed-true", {"applyOnTransformedLogs": True}),
            ("transformed-false", {"applyOnTransformedLogs": False}),
            ("emit-invalid", {"emitSystemFields": ["@aws.other"]}),
            ("emit-duplicates", {"emitSystemFields": ["@aws.region", "@aws.region"]}),
            ("selector-invalid-field", {"fieldSelectionCriteria": '@aws.other = "x"'}),
            ("selector-invalid-syntax", {"fieldSelectionCriteria": '@aws.region === "us-east-1"'}),
            ("selector-empty", {"fieldSelectionCriteria": ""}),
        ]:
            put(label, **extra)
            describe("state-after-" + label)
            if label == "transformed-true":
                publish("transformed-without-transformer")
                poll("transformed-without-transformer", attempts=4, until_stage="transformed-without-transformer")
        selector_created = False
        for label, selection in [
            ("selector-region-in-only", '@aws.region IN ["us-east-1"]'),
            ("selector-region-or-equality", '@aws.region = "us-east-1" OR @aws.account = "000000000000"'),
            ("selector-region-not-in-only", '@aws.region NOT IN ["eu-west-1"]'),
            ("selector-region-not-equal", '@aws.region != "eu-west-1"'),
            ("selector-parentheses", '(@aws.region = "us-east-1")'),
            ("selector-lowercase-or", '@aws.region = "us-east-1" or @aws.account = "000000000000"'),
            ("selector-account-in-only", f'@aws.account IN ["{account}"]'),
            ("selector-region-in-two", '@aws.region IN ["us-east-1", "eu-west-1"]'),
            ("selector-region-in-parenthesized", '@aws.region IN ("us-east-1")'),
            ("selector-region-not-in-parenthesized", '@aws.region NOT IN ("eu-west-1")'),
            ("selector-region-lower-in", '@aws.region in ["us-east-1"]'),
            ("selector-region-single-quote-in", "@aws.region IN ['us-east-1']"),
            ("selector-single-quoted-equality", "@aws.region = 'us-east-1'"),
            ("selector-single-quoted-in", "@aws.region IN ('us-east-1')"),
            ("selector-source-log-field", f'@source.log = "{group}"'),
        ]:
            response = put(label, name="selector-admission", pattern='"never-match-owned-selector"',
                           fieldSelectionCriteria=selection)
            selector_created |= response["code"] == "Success"
            describe("state-after-" + label, filterNamePrefix="selector-admission")
        if selector_created:
            require(remove("selector-admission"))
        require(put("selector-membership-delivery-create", name="selector-admission",
                    pattern='"owned-selector-membership-positive"', emitSystemFields=["@aws.region"],
                    fieldSelectionCriteria='@aws.region IN ("us-east-1") AND @aws.account NOT IN ("000000000000")'))
        time.sleep(12)
        require(request("publish-selector-membership-positive", "logs", "put-log-events", {
            "logGroupName": group, "logStreamName": "two",
            "logEvents": [{"timestamp": time.time_ns() // 1_000_000, "message": "owned-selector-membership-positive"}]}))
        poll("selector-membership-positive", attempts=4, until_stage="owned-selector-membership-positive")
        require(remove("selector-admission"))
        describe("verify-selector-admission-absent", filterNamePrefix="selector-admission")
        require(put("baseline-data-filter"))
        publish("baseline", partial=True)
        publish("second-stream", stream="two")
        poll("baseline-data", attempts=8, until_stage="baseline-accept")
        require(put("duplicate-filter", name="b-overlap"))
        publish("overlap")
        poll("overlap-data", attempts=5, until_stage="overlap-accept")
        require(remove("b-overlap"))
        require(put("replace-skip", pattern='{ $.kind = "skip" }'))
        publish("replacement")
        poll("replacement-data", attempts=5, until_stage="replacement-skip")
        require(put("system-fields", pattern="", emitSystemFields=["@aws.region", "@aws.account"],
                    fieldSelectionCriteria=f'@aws.account = "{account}" AND @aws.region = "{REGION}"'))
        require(describe("system-fields-state"))
        publish("system-fields", plain=True)
        poll("system-fields-data", attempts=5, until_stage="system-fields")
        source_field = put("source-log-field", pattern="", emitSystemFields=["@source.log", "@aws.account"])
        describe("source-log-field-state")
        if source_field["code"] == "Success":
            publish("source-log-field", plain=True)
            poll("source-log-field-data", attempts=4, until_stage="source-log-field")
        require(put("field-selector-nonmatch", pattern="", emitSystemFields=["@aws.account"],
                    fieldSelectionCriteria='@aws.region = "eu-west-1"'))
        publish("selector-nonmatch")
        poll("selector-nonmatch-window", attempts=2, until_stage="selector-nonmatch")
        selection = put("field-selector-in-or", pattern="", fieldSelectionCriteria=f'@aws.region IN ["{REGION}"] OR @aws.account = "000000000000"')
        if selection["code"] == "Success":
            publish("selector-in-or")
            poll("selector-in-or-data", attempts=4, until_stage="selector-in-or")
        selection = put("field-selector-not-in", pattern="", fieldSelectionCriteria=f'@aws.region NOT IN ["eu-west-1"] AND @aws.account != "000000000000"')
        if selection["code"] == "Success":
            publish("selector-not-in")
            poll("selector-not-in-data", attempts=4, until_stage="selector-not-in")
        for name, pattern in [
            ("regex-three-terms", "{ $.kind = %accept% && $.text = %owned% && $.stage = %baseline% }"),
            ("regex-invalid", "%[broken%"),
            ("regex-two-terms", "{ $.kind = %accept% && $.text = %owned% }"),
        ]:
            put(name, pattern=pattern)
            describe("state-after-" + name)
        regex_names = []
        for index in range(1, 7):
            name = "regex-" + str(index)
            response = put("regex-group-quota-" + str(index), name=name, pattern="%accept%")
            if response["code"] == "Success":
                regex_names.append(name)
        describe("regex-quota-state")
        for name in regex_names:
            require(remove(name))
        require(put("isolated-regex-baseline"))
        isolated_names = []
        for index in range(1, 4):
            name = "isolated-regex-" + str(index)
            response = put("isolated-six-regex-boundary-" + str(index), name=name,
                           pattern="{ $.kind = %accept% && $.text = %owned% }")
            if response["code"] == "Success":
                isolated_names.append(name)
        describe("isolated-regex-quota-state")
        for name in isolated_names:
            require(remove(name))
        describe("verify-isolated-regex-absent", filterNamePrefix="isolated-regex-")
        require(put("revocation-baseline"))
        publish("before-revoke")
        poll("before-revoke", attempts=4, until_stage="before-revoke-accept")
        require(revoke("delivery"))
        publish("revoked")
        poll("revoked-bounded", attempts=2, until_stage="revoked-accept")
        describe("state-while-revoked")
        require(permission("delivery-restored"))
        publish("restored")
        poll("restored-bounded", attempts=5, until_stage="restored-accept")
        describe("state-after-restore")
        require(remove("a-main"))
        remove("a-main")
        describe("state-removed")
        publish("after-removal")
        poll("after-removal-window", attempts=2, until_stage="after-removal")
        capture["capture_complete"] = True
    except Exception as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cleaning = True
        cleanup_errors = []
        def cleanup(label, service, operation, parameters):
            try:
                return request(label, service, operation, parameters)
            except Exception as error:
                cleanup_errors.append(label + ": " + type(error).__name__)
                return {"code": "TransportError"}
        checks = {}
        if owned["group"]:
            cleanup("cleanup-group", "logs", "delete-log-group", dict(logGroupName=group))
            response = cleanup("verify-group", "logs", "describe-log-groups", dict(logGroupNamePrefix=group))
            checks["group_and_streams_and_filters_absent"] = response["code"] == "Success" and not response["output"].get("logGroups")
        if owned["function"]:
            cleanup("cleanup-function", "lambda", "delete-function", dict(FunctionName=prefix))
            response = cleanup("verify-function", "lambda", "get-function", dict(FunctionName=prefix))
            checks["function_and_permissions_absent"] = response["code"] == "ResourceNotFoundException"
            log_group = "/aws/lambda/" + prefix
            response = cleanup("inspect-runtime-log-group", "logs", "describe-log-groups", dict(logGroupNamePrefix=log_group))
            if response["code"] == "Success":
                for row in response["output"].get("logGroups", []):
                    if row["logGroupName"] == log_group:
                        cleanup("cleanup-runtime-log-group", "logs", "delete-log-group", dict(logGroupName=log_group))
                response = cleanup("verify-runtime-log-group", "logs", "describe-log-groups", dict(logGroupNamePrefix=log_group))
                checks["runtime_log_group_absent"] = response["code"] == "Success" and not response["output"].get("logGroups")
        if owned["policy"]:
            cleanup("cleanup-role-policy", "iam", "delete-role-policy", dict(RoleName=role_name, PolicyName="owned-collector"))
            response = cleanup("verify-role-policy", "iam", "get-role-policy", dict(RoleName=role_name, PolicyName="owned-collector"))
            checks["inline_policy_absent"] = response["code"] == "NoSuchEntity"
        if owned["role"]:
            cleanup("cleanup-role", "iam", "delete-role", dict(RoleName=role_name))
            response = cleanup("verify-role", "iam", "get-role", dict(RoleName=role_name))
            checks["role_absent"] = response["code"] == "NoSuchEntity"
        if owned["queue"]:
            cleanup("cleanup-collector", "sqs", "delete-queue", dict(QueueUrl=queue_url))
            response = cleanup("verify-collector", "sqs", "get-queue-url", dict(QueueName=prefix))
            checks["collector_absent"] = response["code"] in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
        types = collections.Counter(row["record"]["envelope"].get("messageType", "<absent>") for row in capture["deliveries"])
        occurrences = collections.Counter(event["id"] for row in capture["deliveries"] for event in row["record"]["envelope"].get("logEvents", []) if "id" in event)
        capture["delivery_summary"] = {"message_types": dict(types), "event_id_occurrences": dict(occurrences),
                                       "interpretation": "Repeated event IDs can reflect overlapping filters, service retries, or collector redelivery; record envelopes retain grouping and SQS IDs to distinguish observations. Permission restore may remain suppressed beyond this short window; not asserted as deterministic loss."}
        capture["cleanup"] = {"verified": bool(checks) and all(checks.values()) and not cleanup_errors,
                               "checks": checks, "transport_errors": cleanup_errors}
        capture["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save()
        print("CLEANUP_VERIFIED=" + str(capture["cleanup"]["verified"]), flush=True)


if __name__ == "__main__":
    main()
