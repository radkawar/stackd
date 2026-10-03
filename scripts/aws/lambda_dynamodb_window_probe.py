#!/usr/bin/env python3
"""Capture owned native DynamoDB window failure and oversized-state cases."""
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


LARGE_STATE = "X" * (1024 * 1024 + 64)
HANDLER = '''import json
import time

LARGE = "X" * (1024 * 1024 + 64)

def encode(value):
    if isinstance(value, str) and value == LARGE:
        return {"probe_blob_ref": "oversized_state"}
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [encode(v) for v in value]
    return value

def invoke(event, context):
    state = dict(event.get("state", {}))
    state.pop("oversized", None)
    records = event["Records"]
    state["count"] = state.get("count", 0) + len(records)
    for record in records:
        image = record["dynamodb"]["NewImage"]
        state["last_ordinal"] = int(image["ordinal"]["N"])
        state["fail_final"] = image["fail_final"]["BOOL"]
        if image["oversized"]["BOOL"]:
            state["oversized"] = LARGE
    response = {"state": state}
    raises = bool(event.get("isFinalInvokeForWindow") and state.get("fail_final"))
    evidence = {"request_id": context.aws_request_id, "invoked_arn": context.invoked_function_arn,
                "time": time.time(), "event": event, "response": None if raises else response,
                "error": {"errorType": "RuntimeError", "errorMessage": "owned final window failure"} if raises else None}
    print("DDB_WINDOW_PROBE " + json.dumps(encode(evidence), separators=(",", ":")), flush=True)
    if raises:
        raise RuntimeError("owned final window failure")
    return response
'''


def summarize(capture):
    """Index observed transitions without converting bounded waits into claims."""
    for case, details in capture["cases"].items():
        transitions = []
        for reference in details["invocations"]:
            log = capture["log_events"][reference["log_event_ref"]]
            invocation = json.loads(log["message"].split("DDB_WINDOW_PROBE ", 1)[1])
            event = invocation["event"]
            transitions.append({**reference, "handler_time": invocation["time"], "log_timestamp": log["timestamp"],
                    "window": event.get("window"), "record_ordinals": [record["dynamodb"]["NewImage"]["ordinal"]["N"] for record in event["Records"]],
                    "isFinalInvokeForWindow": event.get("isFinalInvokeForWindow"), "isWindowTerminatedEarly": event.get("isWindowTerminatedEarly"),
                    "incoming_state": event.get("state"), "returned_state": (invocation.get("response") or {}).get("state"), "error": invocation["error"]})
        details["transitions"] = transitions
        details["source_write_observation_labels"] = [row["label"] for row in capture["observations"] if row["label"].startswith(case + "_put_")]
        details["s3_object_keys"] = []
        for key, obj in capture["s3_objects"].items():
            envelope = json.loads(obj["body_utf8"])
            if envelope.get("requestContext", {}).get("functionArn") != details["qualified_function_arn"]:
                continue
            details["s3_object_keys"].append(key)
            payload = envelope.get("payload")
            if isinstance(payload, str):
                payload = json.loads(payload)
            obj["decoded_summary"] = {"envelope_fields": list(envelope), "requestContext": envelope.get("requestContext"),
                    "responseContext": envelope.get("responseContext"), "DDBStreamBatchInfo": envelope.get("DDBStreamBatchInfo"),
                    "timeWindowInfo": envelope.get("timeWindowInfo"),
                    "payload_fields": list(payload) if isinstance(payload, dict) else None,
                    "payload_window": payload.get("window") if isinstance(payload, dict) else None,
                    "payload_state": payload.get("state") if isinstance(payload, dict) else None,
                    "payload_record_count": len(payload["Records"]) if isinstance(payload, dict) and "Records" in payload else None}
        details["observed_counts"] = {"invocations": len(transitions),
                "final_invocations": sum(bool(row["isFinalInvokeForWindow"]) for row in transitions),
                "early_termination_invocations": sum(bool(row["isWindowTerminatedEarly"]) for row in transitions),
                "failed_empty_final_invocations": sum(bool(row["isFinalInvokeForWindow"] and row["error"] and not row["record_ordinals"]) for row in transitions),
                "s3_objects": len(details["s3_object_keys"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/lambda/dynamodb_windows.json"))
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION="us-east-1", AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="2")
    prefix = "stackd-ddbwin-" + secrets.token_hex(6)
    role_name, log_group, bucket = prefix + "-role", "/aws/lambda/" + prefix, prefix + "-failure"
    now = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    capture = {"source": "Native AWS public endpoints through scripts/aws/aws_cli.py", "region": "us-east-1",
               "prefix": prefix, "started_at": now(), "documentation": ["https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-windows.html"],
               "handler_source": HANDLER, "observations": [], "cases": {}, "findings": [], "cleanup": [],
               "log_events": {}, "blobs": {"oversized_state": LARGE_STATE}, "s3_objects": {},
               "encoding": "probe_blob_ref expands to the exact string in blobs. The handler uses this lossless encoding only for evidence logging, not its actual event/return value. log_event_ref expands to log_events. Invocation entries reference the native log event; its DDB_WINDOW_PROBE JSON is the complete encoded event/response/error. S3 body_utf8 is the original object byte sequence encoded as UTF-8, not reserialized JSON; decode that string as JSON for the native envelope and payload."}
    if args.output.exists():
        previous = json.loads(args.output.read_text())
        capture["prior_runs"] = previous.pop("prior_runs", []) + [previous]
    owned = {"role": False, "logs": False, "function": False, "bucket": False, "policies": [], "tables": [], "mappings": [], "aliases": [], "versions": []}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, service, operation, parameters, cleanup=False):
        started = now()
        result = observe(service, operation, parameters, env)
        if service == "logs" and operation == "filter-log-events":
            events = result.get("output", {}).get("events", [])
            for event in events:
                capture["log_events"][event["eventId"]] = event
            if "output" in result:
                result["output"]["events"] = [{"log_event_ref": event["eventId"]} for event in events]
        capture["cleanup" if cleanup else "observations"].append({"label": label, "service": service, "operation": operation,
                     "input": parameters, "started_at": started, "finished_at": now(), "result": result})
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError(json.dumps(result))
        return result["output"]

    def settle(uuid, target, cleanup=False):
        for attempt in range(60):
            result = record("mapping_" + target + "_" + str(attempt), "lambda", "get-event-source-mapping", {"UUID": uuid}, cleanup)
            if target == "absent" and result["code"] == "ResourceNotFoundException":
                return
            if require(result)["State"] == target:
                return
            time.sleep(3)
        raise RuntimeError("Mapping did not reach " + target)

    def policy(name, statements):
        require(record("policy_" + name, "iam", "put-role-policy", {"RoleName": role_name, "PolicyName": name,
                       "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})}))
        owned["policies"].append(name)

    def events(case):
        found = []
        for identifier, entry in capture["log_events"].items():
            if "DDB_WINDOW_PROBE " not in entry["message"]:
                continue
            event = json.loads(entry["message"].split("DDB_WINDOW_PROBE ", 1)[1])
            if event["invoked_arn"] == capture["cases"][case]["qualified_function_arn"]:
                found.append((identifier, event))
        return sorted(found, key=lambda row: row[1]["time"])

    def scan(case, label):
        require(record(case + "_" + label + "_logs", "logs", "filter-log-events", {"logGroupName": log_group}))
        listing = require(record(case + "_" + label + "_objects", "s3api", "list-objects-v2", {"Bucket": bucket}))
        for entry in listing.get("Contents", []):
            key = entry["Key"]
            if key in capture["s3_objects"]:
                continue
            with tempfile.TemporaryDirectory(prefix=prefix) as directory:
                destination = pathlib.Path(directory) / "body"
                started = now()
                result = cli_result(run("s3api", "get-object", env=env, options=["--bucket", bucket, "--key", key, str(destination)], timeout=40), cli_message=None)
                capture["observations"].append({"label": case + "_get_object", "service": "s3api", "operation": "get-object",
                       "input": {"Bucket": bucket, "Key": key}, "started_at": started, "finished_at": now(), "result": result})
                metadata = require(result)
                capture["s3_objects"][key] = {"listing": entry, "metadata": metadata, "body_utf8": destination.read_bytes().decode("utf-8")}
        capture["cases"][case]["invocations"] = [{"log_event_ref": identifier} for identifier, _ in events(case)]
        save()

    def poll(case, stage, seconds, predicate=None):
        timeline = {"stage": stage, "started_at": now(), "bounded_wait_seconds": seconds, "new_source_writes_during_poll": False}
        capture["cases"][case]["timeline"].append(timeline)
        deadline = time.monotonic() + seconds
        attempt = 0
        while time.monotonic() < deadline:
            scan(case, stage + "_" + str(attempt))
            if predicate and predicate([event for _, event in events(case)]):
                timeline["predicate_observed"] = True
                break
            time.sleep(4)
            attempt += 1
        timeline["finished_at"] = now()
        timeline["invocations_observed"] = len(events(case))
        save()

    def put(case, ordinal, fail=False, oversized=False):
        require(record(case + "_put_" + str(ordinal), "dynamodb", "put-item", {"TableName": prefix + "-" + case,
                "Item": {"pk": {"S": "same-shard-key"}, "ordinal": {"N": str(ordinal)}, "fail_final": {"BOOL": fail}, "oversized": {"BOOL": oversized}}}))

    identity = require(record("identity_before_writes", "sts", "get-caller-identity", {}))
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside authorized account")
    capture["actor"] = identity
    account = identity["Account"]
    try:
        require(record("create_logs", "logs", "create-log-group", {"logGroupName": log_group}))
        owned["logs"] = True
        role = require(record("create_role", "iam", "create-role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}))["Role"]["Arn"]
        owned["role"] = True
        require(record("create_bucket", "s3api", "create-bucket", {"Bucket": bucket}))
        owned["bucket"] = True
        streams = {}
        for case in ("final_failure", "oversized"):
            name = prefix + "-" + case
            table = require(record(case + "_create_table", "dynamodb", "create-table", {"TableName": name, "BillingMode": "PAY_PER_REQUEST", "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}], "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}], "StreamSpecification": {"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"}}))["TableDescription"]
            owned["tables"].append(name)
            streams[case] = table["LatestStreamArn"]
            for attempt in range(40):
                if require(record(case + "_table_ready_" + str(attempt), "dynamodb", "describe-table", {"TableName": name}))["Table"]["TableStatus"] == "ACTIVE":
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Table not active")
        policy("owned-access", [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:aws:logs:us-east-1:{account}:log-group:{log_group}:*"},
                {"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator"], "Resource": list(streams.values())},
                {"Effect": "Allow", "Action": "dynamodb:ListStreams", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::" + bucket},
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + bucket + "/*"}])
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr(zipfile.ZipInfo("entry.py", (2026, 1, 1, 0, 0, 0)), HANDLER)
        parameters = {"FunctionName": prefix, "Role": role, "Runtime": "python3.12", "Handler": "entry.invoke", "Code": {"ZipFile": base64.b64encode(archive.getvalue()).decode()}, "Timeout": 10, "MemorySize": 128}
        for attempt in range(30):
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
            if require(record("function_ready_" + str(attempt), "lambda", "get-function-configuration", {"FunctionName": prefix}))["State"] == "Active":
                break
            time.sleep(2)
        version = require(record("publish_handler", "lambda", "publish-version", {"FunctionName": prefix}))["Version"]
        owned["versions"].append(version)
        time.sleep(8)
        for case, stream in streams.items():
            alias = require(record(case + "_alias", "lambda", "create-alias", {"FunctionName": prefix, "Name": case, "FunctionVersion": version}))
            owned["aliases"].append(case)
            mapping = require(record(case + "_create_mapping", "lambda", "create-event-source-mapping", {"FunctionName": prefix + ":" + case, "EventSourceArn": stream,
                      "StartingPosition": "TRIM_HORIZON", "Enabled": True, "BatchSize": 1, "MaximumBatchingWindowInSeconds": 0, "ParallelizationFactor": 1,
                      "TumblingWindowInSeconds": 10, "MaximumRetryAttempts": 0, "MaximumRecordAgeInSeconds": 600,
                      "DestinationConfig": {"OnFailure": {"Destination": "arn:aws:s3:::" + bucket}}}))
            owned["mappings"].append(mapping["UUID"])
            capture["cases"][case] = {"mapping_uuid": mapping["UUID"], "qualified_function_arn": alias["AliasArn"], "function_version": version, "stream_arn": stream, "timeline": [], "invocations": []}
            settle(mapping["UUID"], "Enabled")
            put(case, 1, fail=case == "final_failure", oversized=case == "oversized")
            if case == "final_failure":
                put(case, 2, fail=True)
            poll(case, "initial_delivery", 180, lambda seen: any(event["event"]["Records"] for event in seen))
            poll(case, "idle_after_initial_records", 50)
            put(case, 3)
            poll(case, "later_window_record", 120, lambda seen: any(any(record["dynamodb"]["NewImage"]["ordinal"]["N"] == "3" for record in event["event"]["Records"]) for event in seen))
            poll(case, "idle_after_recovery", 35)
            put(case, 4)
            poll(case, "second_recovery_record", 90, lambda seen: any(any(record["dynamodb"]["NewImage"]["ordinal"]["N"] == "4" for record in event["event"]["Records"]) for event in seen))
            poll(case, "final_observation", 20)
            require(record(case + "_delete_mapping", "lambda", "delete-event-source-mapping", {"UUID": mapping["UUID"]}))
            settle(mapping["UUID"], "absent")
            owned["mappings"].remove(mapping["UUID"])
            scan(case, "after_mapping_deleted")
        capture["workflow_complete"] = True
    except Exception as error:
        capture["workflow_error"] = str(error)
        raise
    finally:
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
                settle(uuid, "absent", True)
            except Exception as error:
                errors.append(str(error))
        if owned["function"]:
            clean("delete_function", "lambda", "delete-function", {"FunctionName": prefix})
            clean("function_absent", "lambda", "get-function-configuration", {"FunctionName": prefix}, ("ResourceNotFoundException",))
            for qualifier in owned["aliases"] + owned["versions"]:
                clean("qualifier_absent_" + qualifier, "lambda", "get-function-configuration", {"FunctionName": prefix, "Qualifier": qualifier}, ("ResourceNotFoundException",))
        for name in owned["tables"]:
            clean("delete_table", "dynamodb", "delete-table", {"TableName": name})
            for attempt in range(60):
                result = clean("table_absent_" + str(attempt), "dynamodb", "describe-table", {"TableName": name}, ("Success", "ResourceNotFoundException"))
                if result.get("code") == "ResourceNotFoundException":
                    break
                time.sleep(2)
            else:
                errors.append("Table remains: " + name)
        if owned["bucket"]:
            listing = clean("list_objects_cleanup", "s3api", "list-objects-v2", {"Bucket": bucket})
            for entry in listing.get("output", {}).get("Contents", []):
                clean("delete_object", "s3api", "delete-object", {"Bucket": bucket, "Key": entry["Key"]})
            empty = clean("bucket_empty", "s3api", "list-objects-v2", {"Bucket": bucket})
            if empty.get("output", {}).get("Contents"):
                errors.append("Bucket objects remain")
            clean("delete_bucket", "s3api", "delete-bucket", {"Bucket": bucket})
            clean("bucket_absent", "s3api", "get-bucket-location", {"Bucket": bucket}, ("NoSuchBucket",))
        if owned["logs"]:
            clean("delete_logs", "logs", "delete-log-group", {"logGroupName": log_group})
            result = clean("logs_absent", "logs", "describe-log-groups", {"logGroupNamePrefix": log_group})
            if result.get("output", {}).get("logGroups"):
                errors.append("Log group remains")
        for name in owned["policies"]:
            clean("delete_policy", "iam", "delete-role-policy", {"RoleName": role_name, "PolicyName": name})
            clean("policy_absent", "iam", "get-role-policy", {"RoleName": role_name, "PolicyName": name}, ("NoSuchEntity",))
        if owned["role"]:
            policies = clean("role_policies_empty", "iam", "list-role-policies", {"RoleName": role_name})
            if policies.get("output", {}).get("PolicyNames"):
                errors.append("Role policies remain")
            clean("delete_role", "iam", "delete-role", {"RoleName": role_name})
            clean("role_absent", "iam", "get-role", {"RoleName": role_name}, ("NoSuchEntity",))
        capture["cleanup_errors"] = errors
        capture["cleanup_verified"] = not errors
        capture["finished_at"] = now()
        capture["findings"].append("Idle polls are observer CloudWatch/S3 reads, not visibility into Lambda's internal DynamoDB polling. Bounded lack of a final invocation or destination cannot establish absence or a requirement for new records.")
        summarize(capture)
        save()
        if errors:
            raise RuntimeError("Cleanup failed: " + json.dumps(errors))


if __name__ == "__main__":
    main()
