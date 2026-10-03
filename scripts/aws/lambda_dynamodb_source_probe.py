#!/usr/bin/env python3
"""Capture native DynamoDB/Lambda source contracts; delete every owned resource."""
import argparse
import base64
import datetime
import io
import json
import os
import pathlib
import secrets
import tempfile
import time
import zipfile

from aws_cli import observe, result as cli_result, run


HANDLER = '''import json
import time

def invoke(event, context):
    records = event["Records"]
    images = [r["dynamodb"].get("NewImage", r["dynamodb"].get("OldImage", {})) for r in records]
    mode = next((i.get("mode", {}).get("S") for i in images if i.get("mode")), "success")
    bad = [r["dynamodb"]["SequenceNumber"] for r, i in zip(records, images) if i.get("bad", {}).get("BOOL")]
    response = {"batchItemFailures": [{"itemIdentifier": n} for n in bad]} if mode == "partial" else {"batchItemFailures": []}
    if mode == "invalid":
        response = {"batchItemFailures": [{"itemIdentifier": ""}]}
    if "window" in event:
        state = dict(event.get("state", {}))
        state["count"] = state.get("count", 0) + len(records)
        if records:
            state["phase"] = records[0]["dynamodb"]["Keys"]["pk"]["S"]
        response["state"] = state
    print("DDB_PROBE " + json.dumps({"request_id": context.aws_request_id, "invoked_arn": context.invoked_function_arn, "time": time.time(), "mode": mode, "event": event, "response": response, "raises": mode == "raise" and bool(bad)}, separators=(",", ":")), flush=True)
    if mode == "raise" and bad:
        raise RuntimeError("owned deterministic poison record")
    return response
'''


def compact_events(capture):
    """Intern repeated native log events and message bodies losslessly."""
    for previous in capture.get("prior_runs", []):
        compact_events(previous)
    canonical = {event["eventId"]: event for event in capture.get("log_events", [])}
    bodies = {message["MessageId"]: message["Body"] for message in capture.get("destination_messages", [])}
    for row in capture["observations"]:
        if row["service"] == "logs" and row["operation"] == "filter-log-events":
            events = row["result"].get("output", {}).get("events", [])
            for index, event in enumerate(events):
                if event.get("eventId") in canonical and canonical[event["eventId"]] == event:
                    events[index] = {"event_id_ref": event["eventId"]}
        if row["service"] == "sqs" and row["operation"] == "receive-message":
            for message in row["result"].get("output", {}).get("Messages", []):
                if message.get("MessageId") in bodies and message.get("Body") == bodies[message["MessageId"]]:
                    message["Body"] = {"message_body_ref": message["MessageId"]}
    capture["encoding"] = "In log poll output events, event_id_ref expands to the unchanged object in this run's log_events with that eventId. In SQS poll message Body, message_body_ref expands to the original Body string in this run's destination_messages with that MessageId. No other native output fields are omitted, except SQS ReceiptHandle capabilities. CLI ParamValidation errors are client admission, not native service admission."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/lambda/dynamodb_source.json"))
    parser.add_argument("--tumbling-only", action="store_true", help="Capture stateful windows with a separate owned resource lifecycle")
    parser.add_argument("--s3-only", action="store_true", help="Capture S3 failure object bytes with a separate owned resource lifecycle")
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION="us-east-1", AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="2")
    prefix = "stackd-ddblambda-" + secrets.token_hex(6)
    role_name, log_group = prefix + "-role", "/aws/lambda/" + prefix
    capture = {"source": "Native AWS public endpoints through scripts/aws/aws_cli.py", "region": "us-east-1", "prefix": prefix,
               "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "documentation": ["https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html", "https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-params.html", "https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-batchfailurereporting.html", "https://docs.aws.amazon.com/lambda/latest/dg/services-dynamodb-errors.html", "https://docs.aws.amazon.com/lambda/latest/dg/with-ddb-filtering.html"],
               "handler_source": HANDLER, "observations": [], "delivery": {}, "cleanup": [], "limitations": []}
    if args.output.exists():
        previous = json.loads(args.output.read_text())
        capture["prior_runs"] = previous.pop("prior_runs", []) + [previous]
    owned = {"role": False, "logs": False, "table": False, "function": False, "policies": set(), "mappings": [], "queue": None, "bucket": None}
    all_events, all_messages = {}, {}

    def now():
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, service, operation, parameters, cleanup=False):
        started = now()
        result = observe(service, operation, parameters, env)
        # Receipt handles are opaque capabilities, not behavior evidence.
        if service == "sqs" and operation == "receive-message":
            for message in result.get("output", {}).get("Messages", []):
                message.pop("ReceiptHandle", None)
        row = {"label": label, "service": service, "operation": operation, "input": parameters, "started_at": started, "finished_at": now(), "result": result}
        capture["cleanup" if cleanup else "observations"].append(row)
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError(json.dumps(result))
        return result["output"]

    def policy(name, statements):
        result = record("policy_" + name, "iam", "put-role-policy", {"RoleName": role_name, "PolicyName": name, "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})
        require(result)
        owned["policies"].add(name)

    def settle(uuid, state=None, label="settle", timeout=180, cleanup=False):
        deadline = time.monotonic() + timeout
        attempt = 0
        while time.monotonic() < deadline:
            result = record(label + "_" + str(attempt), "lambda", "get-event-source-mapping", {"UUID": uuid}, cleanup)
            if state == "absent" and result["code"] == "ResourceNotFoundException":
                return
            out = require(result)
            if out["State"] == state or state is None and out["State"] in ("Enabled", "Disabled"):
                return out
            time.sleep(3)
            attempt += 1
        raise RuntimeError("Mapping state did not settle: " + label)

    def update(label, **settings):
        out = require(record(label, "lambda", "update-event-source-mapping", {"UUID": mapping, **settings}))
        settle(mapping, "Enabled" if settings.get("Enabled") else "Disabled" if "Enabled" in settings else None, label + "_ready")
        return out

    def scan(label):
        out = require(record(label + "_logs", "logs", "filter-log-events", {"logGroupName": log_group, "filterPattern": '"DDB_PROBE"'}))
        for event in out.get("events", []):
            all_events[event["eventId"]] = event
        out = require(record(label + "_destination", "sqs", "receive-message", {"QueueUrl": owned["queue"], "MaxNumberOfMessages": 10, "VisibilityTimeout": 1, "WaitTimeSeconds": 1, "MessageSystemAttributeNames": ["All"]}))
        for message in out.get("Messages", []):
            all_messages[message["MessageId"]] = message

    def parsed_events():
        # Native retries reuse context.aws_request_id; each distinct log event
        # and handler timestamp is a separate invocation, not a duplicate.
        return [json.loads(event["message"].split("DDB_PROBE ", 1)[1]) for event in all_events.values()]

    def matching(phase):
        return [event for event in parsed_events() if event["invoked_arn"].endswith(":" + phase) and (event["event"].get("state", {}).get("phase") == phase or any(r["dynamodb"]["Keys"]["pk"]["S"] == phase for r in event["event"]["Records"]))]

    def collect(phase, minimum=1, destination=False, timeout=180, quiet=8):
        deadline = time.monotonic() + timeout
        initial_messages = set(all_messages)
        def destination_ids():
            return {identifier for identifier, message in all_messages.items() if json.loads(message["Body"]).get("requestContext", {}).get("functionArn", "").endswith(":" + phase)}
        attempt, satisfied = 0, None
        while time.monotonic() < deadline:
            scan(phase + "_poll_" + str(attempt))
            events = matching(phase)
            if len(events) >= minimum and (not destination or destination_ids() - initial_messages):
                if satisfied is None:
                    satisfied = time.monotonic()
                if time.monotonic() - satisfied >= quiet:
                    break
            time.sleep(3)
            attempt += 1
        events = matching(phase)
        capture["delivery"][phase] = {"invocations": events, "destination_message_ids_seen_during_window": sorted(destination_ids() - initial_messages), "ended_at": now(), "bounded_wait_seconds": timeout, "minimum_invocations_observed": len(events) >= minimum}
        save()
        return events

    def put(phase, ordinal, mode="success", bad=False, **attributes):
        item = {"pk": {"S": phase}, "ordinal": {"N": str(ordinal)}, "mode": {"S": mode}, "bad": {"BOOL": bad}, **attributes}
        require(record(phase + "_put_" + str(ordinal), "dynamodb", "put-item", {"TableName": prefix, "Item": item}))

    def configure(phase, **settings):
        nonlocal mapping
        # Fresh TRIM_HORIZON mappings isolate delivery from AWS's eventually
        # consistent update workers and their already-advanced filter checkpoints.
        require(record(phase + "_delete_previous", "lambda", "delete-event-source-mapping", {"UUID": mapping}))
        settle(mapping, "absent", phase + "_previous_absent")
        owned["mappings"].remove(mapping)
        defaults = {"BatchSize": 4, "MaximumBatchingWindowInSeconds": 3, "ParallelizationFactor": 1, "BisectBatchOnFunctionError": False, "MaximumRetryAttempts": 1, "MaximumRecordAgeInSeconds": 600, "FunctionResponseTypes": [], "TumblingWindowInSeconds": 0,
                    "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"dynamodb": {"Keys": {"pk": {"S": [phase]}}}})}]}, "DestinationConfig": {"OnFailure": {"Destination": queue_arn}}}
        defaults.update(settings)
        if defaults["TumblingWindowInSeconds"]:
            defaults.pop("FilterCriteria")
        require(record(phase + "_alias", "lambda", "create-alias", {"FunctionName": prefix, "Name": phase, "FunctionVersion": version}))
        created = require(record(phase + "_configure", "lambda", "create-event-source-mapping", {**base, **defaults, "FunctionName": prefix + ":" + phase}))
        mapping = created["UUID"]
        owned["mappings"].append(mapping)
        settle(mapping, "Disabled", phase + "_created")

    def tumbling():
        configure("tumbling", BatchSize=1, MaximumBatchingWindowInSeconds=0, TumblingWindowInSeconds=10)
        update("tumbling_enable", Enabled=True)
        for ordinal in range(1, 5):
            put("tumbling", ordinal)
        collect("tumbling", minimum=4, timeout=180, quiet=20)
        put("tumbling", 5)
        collect("tumbling", minimum=5, timeout=60, quiet=20)

    def s3_delivery():
        bucket = prefix + "-failure"
        require(record("create_failure_bucket", "s3api", "create-bucket", {"Bucket": bucket}))
        owned["bucket"] = bucket
        bucket_arn = "arn:aws:s3:::" + bucket
        policy("owned-s3", [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": bucket_arn},
                            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": bucket_arn + "/*"}])
        time.sleep(8)
        configure("s3_failure", MaximumRetryAttempts=0, DestinationConfig={"OnFailure": {"Destination": bucket_arn}})
        for ordinal in range(1, 5):
            put("s3_failure", ordinal, mode="raise", bad=ordinal == 2)
        update("s3_failure_enable", Enabled=True)
        objects = []
        for attempt in range(36):
            logs = require(record("s3_failure_logs_" + str(attempt), "logs", "filter-log-events", {"logGroupName": log_group, "filterPattern": '"DDB_PROBE"'}))
            for event in logs.get("events", []):
                all_events[event["eventId"]] = event
            listing = require(record("s3_failure_objects_" + str(attempt), "s3api", "list-objects-v2", {"Bucket": bucket}))
            objects = listing.get("Contents", [])
            if objects and matching("s3_failure"):
                break
            time.sleep(5)
        if not objects:
            raise RuntimeError("No native S3 failure object observed within bounded polling")
        capture["delivery"]["s3_failure"] = {"invocations": matching("s3_failure"), "ended_at": now()}
        capture["s3_objects"] = []
        with tempfile.TemporaryDirectory(prefix=prefix, dir=args.output.parent) as directory:
            for index, entry in enumerate(objects):
                parameters = {"Bucket": bucket, "Key": entry["Key"]}
                destination = pathlib.Path(directory) / str(index)
                started = now()
                observed = cli_result(run("s3api", "get-object", env=env, options=["--bucket", bucket, "--key", entry["Key"], str(destination)], timeout=40), cli_message=None)
                capture["observations"].append({"label": "s3_get_failure_object_" + str(index), "service": "s3api", "operation": "get-object", "input": parameters, "started_at": started, "finished_at": now(), "result": observed})
                require(observed)
                content = destination.read_bytes()
                capture["s3_objects"].append({"key": entry["Key"], "metadata": observed["output"], "body_base64": base64.b64encode(content).decode(), "body_utf8": content.decode(), "body_json": json.loads(content)})
        save()

    identity = require(record("identity_before_writes", "sts", "get-caller-identity", {}))
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside explicitly authorized account")
    capture["actor"] = identity
    account = identity["Account"]
    mapping = None
    try:
        require(record("create_log_group", "logs", "create-log-group", {"logGroupName": log_group}))
        owned["logs"] = True
        role = require(record("create_role", "iam", "create-role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}))["Role"]["Arn"]
        owned["role"] = True
        policy("owned-logs", [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:aws:logs:us-east-1:{account}:log-group:{log_group}:*"}])
        table = require(record("create_table", "dynamodb", "create-table", {"TableName": prefix, "BillingMode": "PAY_PER_REQUEST", "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}], "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}], "StreamSpecification": {"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"}}))["TableDescription"]
        owned["table"] = True
        stream = table["LatestStreamArn"]
        for attempt in range(40):
            table = require(record("table_ready_" + str(attempt), "dynamodb", "describe-table", {"TableName": prefix}))["Table"]
            if table["TableStatus"] == "ACTIVE":
                break
            time.sleep(2)
        queue_arn = None
        if not args.s3_only:
            owned["queue"] = require(record("create_destination", "sqs", "create-queue", {"QueueName": prefix + "-failure", "Attributes": {"MessageRetentionPeriod": "3600"}}))["QueueUrl"]
            queue_arn = require(record("destination_arn", "sqs", "get-queue-attributes", {"QueueUrl": owned["queue"], "AttributeNames": ["QueueArn"]}))["Attributes"]["QueueArn"]
            policy("owned-destination", [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}])
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr(zipfile.ZipInfo("entry.py", (2026, 1, 1, 0, 0, 0)), HANDLER)
        parameters = {"FunctionName": prefix, "Role": role, "Runtime": "python3.12", "Handler": "entry.invoke", "Code": {"ZipFile": base64.b64encode(archive.getvalue()).decode()}, "Timeout": 5, "MemorySize": 128}
        for attempt in range(25):
            result = record("create_function_" + str(attempt), "lambda", "create-function", parameters)
            if result["code"] == "Success":
                owned["function"] = True
                break
            if "cannot be assumed" not in json.dumps(result):
                require(result)
            time.sleep(3)
        if not owned["function"]:
            raise RuntimeError("Role trust propagation timed out")
        for attempt in range(40):
            function = require(record("function_ready_" + str(attempt), "lambda", "get-function-configuration", {"FunctionName": prefix}))
            if function["State"] == "Active":
                break
            time.sleep(2)
        version = require(record("publish_handler", "lambda", "publish-version", {"FunctionName": prefix}))["Version"]
        base = {"FunctionName": prefix, "EventSourceArn": stream, "StartingPosition": "TRIM_HORIZON", "Enabled": False}
        record("missing_source_permissions", "lambda", "create-event-source-mapping", base)
        source_allow = [{"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator"], "Resource": stream}, {"Effect": "Allow", "Action": "dynamodb:ListStreams", "Resource": "*"}]
        policy("owned-source", source_allow)
        time.sleep(8)
        admission = [("missing_start", {k: v for k, v in base.items() if k != "StartingPosition"}), ("at_timestamp", {**base, "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": time.time() - 60}), ("bad_start", {**base, "StartingPosition": "BOGUS"}), ("timestamp_with_trim", {**base, "StartingPositionTimestamp": time.time() - 60}), ("batch_10001", {**base, "BatchSize": 10001}), ("batch_101_window_zero", {**base, "BatchSize": 101}), ("parallel_11", {**base, "ParallelizationFactor": 11}), ("age_zero", {**base, "MaximumRecordAgeInSeconds": 0}), ("age_59", {**base, "MaximumRecordAgeInSeconds": 59}), ("retry_minus_two", {**base, "MaximumRetryAttempts": -2}), ("window_301", {**base, "MaximumBatchingWindowInSeconds": 301}), ("tumbling_901", {**base, "TumblingWindowInSeconds": 901}), ("response_bad", {**base, "FunctionResponseTypes": ["Bad"]}), ("filter_bad", {**base, "FilterCriteria": {"Filters": [{"Pattern": "not-json"}]}}), ("sqs_scaling_on_stream", {**base, "ScalingConfig": {"MaximumConcurrency": 2}}), ("success_destination", {**base, "DestinationConfig": {"OnSuccess": {"Destination": queue_arn}}})]
        for label, request in ([] if args.s3_only else admission):
            result = record("admission_" + label, "lambda", "create-event-source-mapping", request)
            if result["code"] == "Success":
                temporary = result["output"]["UUID"]
                owned["mappings"].append(temporary)
                settle(temporary, "Disabled", label + "_ready")
                require(record(label + "_delete", "lambda", "delete-event-source-mapping", {"UUID": temporary}))
                settle(temporary, "absent", label + "_absent")
                owned["mappings"].remove(temporary)
        for attempt in range(20):
            result = record("create_defaults_" + str(attempt), "lambda", "create-event-source-mapping", base)
            if result["code"] == "Success":
                break
            if "permissions" not in json.dumps(result).lower():
                require(result)
            time.sleep(3)
        mapping = require(result)["UUID"]
        owned["mappings"].append(mapping)
        settle(mapping, "Disabled", "defaults_ready")
        if args.s3_only:
            s3_delivery()
            capture["workflow_complete"] = True
            return
        record("list_by_function", "lambda", "list-event-source-mappings", {"FunctionName": prefix})
        record("list_by_stream", "lambda", "list-event-source-mappings", {"EventSourceArn": stream})
        record("duplicate_mapping", "lambda", "create-event-source-mapping", base)
        record("parallel_tumbling_conflict", "lambda", "update-event-source-mapping", {"UUID": mapping, "ParallelizationFactor": 10, "TumblingWindowInSeconds": 1})
        update("stream_settings_admission", BatchSize=10000, MaximumBatchingWindowInSeconds=1, ParallelizationFactor=10, MaximumRecordAgeInSeconds=604800, MaximumRetryAttempts=10000, FunctionResponseTypes=["ReportBatchItemFailures"], BisectBatchOnFunctionError=True)
        update("tumbling_admission", ParallelizationFactor=1, TumblingWindowInSeconds=1)
        tumbling()
        if args.tumbling_only:
            capture["workflow_complete"] = True
            return
        configure("images", BatchSize=3, MaximumBatchingWindowInSeconds=2)
        put("images", 1, nested={"M": {"list": {"L": [{"NULL": True}, {"N": "1.25"}, {"B": "AQID"}]}}}, strings={"SS": ["a", "b"]})
        put("images", 2)
        require(record("images_delete", "dynamodb", "delete-item", {"TableName": prefix, "Key": {"pk": {"S": "images"}}}))
        update("images_enable", Enabled=True)
        collect("images")
        configure("filter", FilterCriteria={"Filters": [{"Pattern": json.dumps({"dynamodb": {"NewImage": {"keep": {"BOOL": [True]}}}})}]})
        put("filter", 1, keep={"BOOL": False})
        put("filter", 2, keep={"BOOL": True})
        put("filter", 3, keep={"BOOL": False})
        put("filter", 4, keep={"BOOL": True})
        update("filter_enable", Enabled=True)
        collect("filter")
        configure("batch_size", BatchSize=2, MaximumBatchingWindowInSeconds=5)
        for ordinal in range(1, 6):
            put("batch_size", ordinal)
        update("batch_size_enable", Enabled=True)
        collect("batch_size", minimum=3)
        configure("window", BatchSize=10, MaximumBatchingWindowInSeconds=5)
        update("window_enable", Enabled=True)
        put("window", 1)
        collect("window")
        for phase, mode, settings, expected, destination in [
            ("partial_disabled", "partial", {}, 1, False),
            ("partial_enabled", "partial", {"FunctionResponseTypes": ["ReportBatchItemFailures"]}, 2, True),
            ("partial_bisect", "partial", {"FunctionResponseTypes": ["ReportBatchItemFailures"], "BisectBatchOnFunctionError": True}, 2, True),
            ("raise_retry", "raise", {"MaximumRetryAttempts": 2}, 3, True),
            ("raise_bisect", "raise", {"MaximumRetryAttempts": 1, "BisectBatchOnFunctionError": True}, 4, True),
            ("invalid_partial", "invalid", {"FunctionResponseTypes": ["ReportBatchItemFailures"], "MaximumRetryAttempts": 0}, 1, True),
        ]:
            configure(phase, **settings)
            for ordinal in range(1, 5):
                put(phase, ordinal, mode=mode, bad=ordinal == 2)
            update(phase + "_enable", Enabled=True)
            collect(phase, minimum=expected, destination=destination)
        configure("maximum_age", MaximumRecordAgeInSeconds=60, MaximumRetryAttempts=-1)
        put("maximum_age", 1, mode="raise", bad=True)
        capture["maximum_age_hold"] = {"started_at": now(), "seconds": 70, "mapping_disabled": True}
        save()
        time.sleep(70)
        update("maximum_age_enable", Enabled=True)
        collect("maximum_age", minimum=0, destination=True, timeout=120)
        configure("permission_revoked", BatchSize=1, MaximumBatchingWindowInSeconds=0)
        update("permission_revoked_enable", Enabled=True)
        policy("owned-source", source_allow + [{"Effect": "Deny", "Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream"], "Resource": stream}])
        time.sleep(15)
        record("update_after_source_deny", "lambda", "update-event-source-mapping", {"UUID": mapping, "BatchSize": 2})
        put("permission_revoked", 1)
        revoked = collect("permission_revoked", timeout=45, quiet=15)
        capture["delivery"]["permission_denied_window"] = capture["delivery"]["permission_revoked"]
        record("get_after_source_deny", "lambda", "get-event-source-mapping", {"UUID": mapping})
        policy("owned-source", source_allow)
        for attempt in range(20):
            time.sleep(3)
            restored = record("permission_restored_" + str(attempt), "lambda", "update-event-source-mapping", {"UUID": mapping, "BatchSize": 1})
            if restored["code"] == "Success":
                settle(mapping, "Enabled", "permission_restored_ready")
                break
        require(restored)
        put("permission_revoked", 2)
        collect("permission_revoked", minimum=len(revoked) + 1, timeout=180, quiet=15)
        # A fresh LATEST mapping is an admission and delivery comparison with TRIM_HORIZON.
        require(record("delete_trim_mapping", "lambda", "delete-event-source-mapping", {"UUID": mapping}))
        settle(mapping, "absent", "trim_mapping_absent")
        owned["mappings"].remove(mapping)
        put("latest", 0)
        require(record("latest_alias", "lambda", "create-alias", {"FunctionName": prefix, "Name": "latest", "FunctionVersion": version}))
        latest = require(record("create_latest", "lambda", "create-event-source-mapping", {**base, "FunctionName": prefix + ":latest", "StartingPosition": "LATEST", "Enabled": True, "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"dynamodb": {"Keys": {"pk": {"S": ["latest"]}}}})}]}}))
        mapping = latest["UUID"]
        owned["mappings"].append(mapping)
        settle(mapping, "Enabled", "latest_ready")
        time.sleep(70)
        put("latest", 1)
        if not collect("latest"):
            put("latest", 2)
            collect("latest")
        record("list_final", "lambda", "list-event-source-mappings", {"FunctionName": prefix})
        s3_delivery()
        capture["workflow_complete"] = True
    except Exception as error:
        capture["workflow_error"] = str(error)
        raise
    finally:
        capture["log_events"] = list(all_events.values())
        capture["destination_messages"] = list(all_messages.values())
        errors = []

        def clean(label, service, operation, parameters, allowed=("Success",)):
            try:
                result = record(label, service, operation, parameters, True)
                if result["code"] not in allowed:
                    errors.append({"label": label, "result": result})
                return result
            except Exception as error:
                errors.append({"label": label, "error": str(error)})
                return {}

        for uuid in owned["mappings"]:
            clean("delete_mapping", "lambda", "delete-event-source-mapping", {"UUID": uuid}, ("Success", "ResourceNotFoundException"))
            try:
                settle(uuid, "absent", "mapping_absent", cleanup=True)
            except Exception as error:
                errors.append(str(error))
        if owned["function"]:
            clean("delete_function", "lambda", "delete-function", {"FunctionName": prefix}, ("Success", "ResourceNotFoundException"))
            clean("function_absent", "lambda", "get-function-configuration", {"FunctionName": prefix}, ("ResourceNotFoundException",))
        if owned["table"]:
            clean("delete_table", "dynamodb", "delete-table", {"TableName": prefix}, ("Success", "ResourceNotFoundException"))
            for attempt in range(60):
                result = record("table_absent_" + str(attempt), "dynamodb", "describe-table", {"TableName": prefix}, True)
                if result["code"] == "ResourceNotFoundException":
                    break
                time.sleep(2)
            else:
                errors.append("Table remains after bounded deletion wait")
        if owned["queue"]:
            clean("delete_destination", "sqs", "delete-queue", {"QueueUrl": owned["queue"]})
            clean("destination_absent", "sqs", "get-queue-url", {"QueueName": prefix + "-failure"}, ("AWS.SimpleQueueService.NonExistentQueue",))
        if owned["bucket"]:
            remaining = clean("list_failure_objects_cleanup", "s3api", "list-objects-v2", {"Bucket": owned["bucket"]})
            for entry in remaining.get("output", {}).get("Contents", []):
                clean("delete_failure_object", "s3api", "delete-object", {"Bucket": owned["bucket"], "Key": entry["Key"]})
            empty = clean("failure_bucket_empty", "s3api", "list-objects-v2", {"Bucket": owned["bucket"]})
            if empty.get("output", {}).get("Contents"):
                errors.append("S3 failure objects remain")
            clean("delete_failure_bucket", "s3api", "delete-bucket", {"Bucket": owned["bucket"]})
            clean("failure_bucket_absent", "s3api", "get-bucket-location", {"Bucket": owned["bucket"]}, ("NoSuchBucket",))
        if owned["logs"]:
            clean("delete_logs", "logs", "delete-log-group", {"logGroupName": log_group}, ("Success", "ResourceNotFoundException"))
            result = clean("logs_absent", "logs", "describe-log-groups", {"logGroupNamePrefix": log_group})
            if result.get("output", {}).get("logGroups"):
                errors.append("Log group remains")
        for name in sorted(owned["policies"]):
            clean("delete_policy_" + name, "iam", "delete-role-policy", {"RoleName": role_name, "PolicyName": name})
            clean("policy_absent_" + name, "iam", "get-role-policy", {"RoleName": role_name, "PolicyName": name}, ("NoSuchEntity",))
        if owned["role"]:
            clean("role_policies_empty", "iam", "list-role-policies", {"RoleName": role_name})
            clean("delete_role", "iam", "delete-role", {"RoleName": role_name})
            clean("role_absent", "iam", "get-role", {"RoleName": role_name}, ("NoSuchEntity",))
        capture["cleanup_errors"] = errors
        capture["cleanup_verified"] = not errors
        capture["finished_at"] = now()
        compact_events(capture)
        save()
        if errors:
            raise RuntimeError("Owned resource cleanup failed: " + json.dumps(errors))


if __name__ == "__main__":
    main()
