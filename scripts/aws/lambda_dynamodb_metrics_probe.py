#!/usr/bin/env python3
"""Capture isolated native DynamoDB stream failure metrics and destination recovery."""
import argparse
import base64
import datetime
import io
import json
import os
import pathlib
import secrets
import time
import zipfile

from aws_cli import observe


HANDLER = '''import json
import time

def invoke(event, context):
    print("DDB_METRICS " + json.dumps({"request_id": context.aws_request_id, "invoked_arn": context.invoked_function_arn, "time": time.time(), "event": event}, separators=(",", ":")), flush=True)
    raise RuntimeError("owned deterministic metrics failure")
'''
EVENT_METRICS = ["PolledEventCount", "FilteredOutEventCount", "InvokedEventCount", "FailedInvokeEventCount", "DroppedEventCount", "OnFailureDestinationDeliveredEventCount"]


def findings(capture):
    """Derive navigation summaries without converting absent metrics to zero."""
    result = {}
    for name, case in capture["cases"].items():
        attempts = list(case["handler_attempts"].values())
        records = [record for attempt in attempts for record in attempt["event"]["Records"]]
        documents = list(case["destination_documents"].values())
        result[name] = {
            "mapping_uuid": case["mapping_uuid"],
            "qualified_function_arn": case["qualified_function_arn"],
            "handler_attempt_count": len(attempts),
            "handler_record_count_including_retries": len(records),
            "distinct_handler_sequences": sorted({record["dynamodb"]["SequenceNumber"] for record in records}, key=int),
            "destination_document_count": len(documents),
            "destination_record_count": sum(document["DDBStreamBatchInfo"]["batchSize"] for document in documents),
            "metric_sums": {metric: series["sum"] for metric, series in capture["latest_metric_summary"][name].items()},
            "metrics_with_no_datapoints": [metric for metric, series in capture["latest_metric_summary"][name].items() if not series["has_datapoints"]],
        }
    denied = capture["cases"]["denied"]
    initial = {record["dynamodb"]["SequenceNumber"] for attempt in denied["handler_attempts"].values() for record in attempt["event"]["Records"] if record["dynamodb"]["NewImage"]["phase"]["S"] == "initial"}
    documents = list(denied["destination_documents"].values())
    recovered = sorted({sequence for sequence in initial if any(int(document["DDBStreamBatchInfo"]["startSequenceNumber"]) <= int(sequence) <= int(document["DDBStreamBatchInfo"]["endSequenceNumber"]) for document in documents)}, key=int)
    result["destination_policy_recovery"] = {
        "admission_preceded_explicit_send_message_deny": True,
        "delivery_failure_observed_before_restore": denied["delivery_failure_observed_at"],
        "restoration_finished_at": denied["restoration_finished_at"],
        "last_recovery_poll_at": denied["recovery_last_observation_at"],
        "observed_seconds_after_restore": (datetime.datetime.fromisoformat(denied["recovery_last_observation_at"]) - datetime.datetime.fromisoformat(denied["restoration_finished_at"])).total_seconds(),
        "initial_sequences": sorted(initial, key=int),
        "initial_sequences_observed_in_destination": recovered,
        "scope": "Missing original sequences describe the recorded bounded interval only, not proof that no future delivery retry is possible. The later control record and native DroppedEventCount provide positive evidence independent of empty queue polls.",
    }
    result["function_metric_sums"] = {metric: series["sum"] for metric, series in capture["latest_metric_summary"]["function"].items()}
    result["metric_dimensions"] = {"namespace": "AWS/Lambda", "event_source": "EventSourceMappingUUID", "function": "FunctionName", "period_seconds": 60, "statistic": "Sum", "missing_values": "null denotes no datapoints, never numeric zero"}
    result["pre_invocation_throttle"] = "Unprobed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/lambda/dynamodb_metrics.json"))
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION="us-east-1", AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="2")
    prefix = "stackd-ddbmetrics-" + secrets.token_hex(6)
    role_name, log_group = prefix + "-role", "/aws/lambda/" + prefix
    now = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    capture = {"source": "Native AWS public endpoints through scripts/aws/aws_cli.py", "region": "us-east-1", "prefix": prefix, "started_at": now(),
               "documentation": ["https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html", "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-view.html"],
               "handler_source": HANDLER, "observations": [], "cases": {}, "findings": {}, "cleanup": [], "limitations": ["Pre-invocation throttle distinction is unprobed; this probe isolates handler failures and destination delivery.", "No datapoints is not zero. Bounded nonobservation of a destination document cannot establish permanent absence of retries."],
               "encoding": "Log poll event_id_ref expands to the unmodified event in cases.*.log_events; SQS Body.message_body_ref expands to cases.*.destination_messages[MessageId].Body. ReceiptHandle capabilities are omitted. All metric timestamps, dimensions, and native values are retained."}
    if args.output.exists():
        previous = json.loads(args.output.read_text())
        capture["prior_runs"] = previous.pop("prior_runs", []) + [previous]
    owned = {"role": False, "logs": False, "function": False, "policies": [], "tables": [], "queues": [], "mappings": [], "aliases": [], "versions": []}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, service, operation, parameters, cleanup=False):
        started = now()
        result = observe(service, operation, parameters, env)
        if service == "logs" and operation == "filter-log-events":
            for index, event in enumerate(result.get("output", {}).get("events", [])):
                payload = json.loads(event["message"].split("DDB_METRICS ", 1)[1])
                case = capture["cases"][payload["invoked_arn"].rsplit(":", 1)[1]]
                case["log_events"][event["eventId"]] = event
                case["handler_attempts"][event["eventId"]] = payload
                result["output"]["events"][index] = {"event_id_ref": event["eventId"]}
        if service == "sqs" and operation == "receive-message":
            for message in result.get("output", {}).get("Messages", []):
                message.pop("ReceiptHandle", None)
                payload = json.loads(message["Body"])
                case = capture["cases"][payload["requestContext"]["functionArn"].rsplit(":", 1)[1]]
                case["destination_messages"][message["MessageId"]] = dict(message)
                case["destination_documents"][message["MessageId"]] = payload
                message["Body"] = {"message_body_ref": message["MessageId"]}
        capture["cleanup" if cleanup else "observations"].append({"label": label, "service": service, "operation": operation, "input": parameters, "started_at": started, "finished_at": now(), "result": result})
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError(json.dumps(result))
        return result["output"]

    def policy(name, statements):
        require(record("policy_" + name, "iam", "put-role-policy", {"RoleName": role_name, "PolicyName": name, "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})}))
        owned["policies"].append(name)

    def settle(uuid, state, cleanup=False):
        for attempt in range(80):
            result = record("mapping_" + state + "_" + str(attempt), "lambda", "get-event-source-mapping", {"UUID": uuid}, cleanup)
            if state == "absent" and result["code"] == "ResourceNotFoundException":
                return
            if require(result)["State"] == state:
                return
            time.sleep(3)
        raise RuntimeError("Mapping did not settle: " + uuid + " " + state)

    def scan(label):
        require(record(label + "_logs", "logs", "filter-log-events", {"logGroupName": log_group, "filterPattern": '"DDB_METRICS"'}))
        for name, case in capture["cases"].items():
            if case.get("queue_url"):
                require(record(label + "_" + name + "_messages", "sqs", "receive-message", {"QueueUrl": case["queue_url"], "MaxNumberOfMessages": 10, "VisibilityTimeout": 60, "WaitTimeSeconds": 1, "MessageSystemAttributeNames": ["All"]}))

    def metrics(label):
        queries = []
        query_index = {}
        for name, case in capture["cases"].items():
            for metric in EVENT_METRICS:
                identifier = "m" + str(len(queries))
                query_index[identifier] = {"case": name, "metric": metric}
                queries.append({"Id": identifier, "MetricStat": {"Metric": {"Namespace": "AWS/Lambda", "MetricName": metric, "Dimensions": [{"Name": "EventSourceMappingUUID", "Value": case["mapping_uuid"]}]}, "Period": 60, "Stat": "Sum"}, "ReturnData": True})
        for metric in ["DestinationDeliveryFailures", "Invocations", "Errors", "Throttles"]:
            identifier = "m" + str(len(queries))
            query_index[identifier] = {"case": "function", "metric": metric}
            queries.append({"Id": identifier, "MetricStat": {"Metric": {"Namespace": "AWS/Lambda", "MetricName": metric, "Dimensions": [{"Name": "FunctionName", "Value": prefix}]}, "Period": 60, "Stat": "Sum"}, "ReturnData": True})
        out = require(record(label, "cloudwatch", "get-metric-data", {"MetricDataQueries": queries, "StartTime": capture["started_at"], "EndTime": now(), "ScanBy": "TimestampAscending"}))
        summary = {}
        for row in out["MetricDataResults"]:
            identity = query_index[row["Id"]]
            summary.setdefault(identity["case"], {})[identity["metric"]] = {"has_datapoints": bool(row["Values"]), "sum": sum(row["Values"]) if row["Values"] else None, "timestamps": row["Timestamps"], "values": row["Values"], "status": row["StatusCode"]}
        capture["metric_query_index"] = query_index
        capture["latest_metric_summary"] = summary
        save()
        return summary

    def put(name, ordinal, phase):
        case = capture["cases"][name]
        require(record(name + "_put_" + str(ordinal), "dynamodb", "put-item", {"TableName": case["table_name"], "Item": {"pk": {"S": "owned-single-shard"}, "ordinal": {"N": str(ordinal)}, "phase": {"S": phase}}}))

    identity = require(record("identity_before_writes", "sts", "get-caller-identity", {}))
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside explicitly authorized account")
    capture["actor"] = identity
    account = identity["Account"]
    try:
        require(record("create_logs", "logs", "create-log-group", {"logGroupName": log_group}))
        owned["logs"] = True
        role = require(record("create_role", "iam", "create-role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}))["Role"]["Arn"]
        owned["role"] = True
        policy("owned-logs", [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:aws:logs:us-east-1:{account}:log-group:{log_group}:*"}])
        for name in ["delivered", "no_destination", "denied"]:
            case = capture["cases"][name] = {"table_name": prefix + "-" + name.replace("_", "-"), "qualified_function_name": prefix + ":" + name, "initial_record_count": 3, "restored_control_record_count": 0, "log_events": {}, "handler_attempts": {}, "destination_messages": {}, "destination_documents": {}}
            table = require(record(name + "_create_table", "dynamodb", "create-table", {"TableName": case["table_name"], "BillingMode": "PAY_PER_REQUEST", "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}], "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}], "StreamSpecification": {"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"}}))["TableDescription"]
            owned["tables"].append(case["table_name"])
            case["stream_arn"] = table["LatestStreamArn"]
            if name != "no_destination":
                case["queue_name"] = prefix + "-" + name
                case["queue_url"] = require(record(name + "_create_queue", "sqs", "create-queue", {"QueueName": case["queue_name"], "Attributes": {"MessageRetentionPeriod": "3600"}}))["QueueUrl"]
                owned["queues"].append((case["queue_name"], case["queue_url"]))
                case["queue_arn"] = require(record(name + "_queue_arn", "sqs", "get-queue-attributes", {"QueueUrl": case["queue_url"], "AttributeNames": ["QueueArn"]}))["Attributes"]["QueueArn"]
        policy("owned-source", [{"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator"], "Resource": [c["stream_arn"] for c in capture["cases"].values()]}, {"Effect": "Allow", "Action": "dynamodb:ListStreams", "Resource": "*"}])
        policy("owned-destination", [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": [c["queue_arn"] for c in capture["cases"].values() if "queue_arn" in c]}])
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr(zipfile.ZipInfo("entry.py", (2026, 1, 1, 0, 0, 0)), HANDLER)
        for attempt in range(30):
            result = record("create_function_" + str(attempt), "lambda", "create-function", {"FunctionName": prefix, "Role": role, "Runtime": "python3.12", "Handler": "entry.invoke", "Code": {"ZipFile": base64.b64encode(archive.getvalue()).decode()}, "Timeout": 5, "MemorySize": 128})
            if result["code"] == "Success":
                owned["function"] = True
                break
            if "cannot be assumed" not in json.dumps(result):
                require(result)
            time.sleep(3)
        if not owned["function"]:
            raise RuntimeError("Role propagation timed out")
        for attempt in range(60):
            configuration = require(record("function_ready_" + str(attempt), "lambda", "get-function-configuration", {"FunctionName": prefix}))
            if configuration["State"] == "Active":
                break
            time.sleep(2)
        version = require(record("publish_handler", "lambda", "publish-version", {"FunctionName": prefix}))["Version"]
        owned["versions"].append(version)
        time.sleep(10)
        for name, case in capture["cases"].items():
            case["qualified_function_arn"] = require(record(name + "_create_alias", "lambda", "create-alias", {"FunctionName": prefix, "Name": name, "FunctionVersion": version}))["AliasArn"]
            owned["aliases"].append(name)
            parameters = {"FunctionName": case["qualified_function_name"], "EventSourceArn": case["stream_arn"], "StartingPosition": "TRIM_HORIZON", "Enabled": False, "BatchSize": 3, "MaximumBatchingWindowInSeconds": 3, "MaximumRetryAttempts": 0, "MaximumRecordAgeInSeconds": 900, "MetricsConfig": {"Metrics": ["EventCount"]}}
            if "queue_arn" in case:
                parameters["DestinationConfig"] = {"OnFailure": {"Destination": case["queue_arn"]}}
            case["mapping_uuid"] = require(record(name + "_create_mapping", "lambda", "create-event-source-mapping", parameters))["UUID"]
            owned["mappings"].append(case["mapping_uuid"])
            settle(case["mapping_uuid"], "Disabled")
        denied = capture["cases"]["denied"]
        deny_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sqs:SendMessage", "Resource": denied["queue_arn"]}]}
        require(record("deny_admitted_destination", "sqs", "set-queue-attributes", {"QueueUrl": denied["queue_url"], "Attributes": {"Policy": json.dumps(deny_policy)}}))
        require(record("verify_denied_policy", "sqs", "get-queue-attributes", {"QueueUrl": denied["queue_url"], "AttributeNames": ["Policy"]}))
        time.sleep(20)
        for name, case in capture["cases"].items():
            case["records_started_at"] = now()
            for ordinal in range(1, 4):
                put(name, ordinal, "initial")
            case["records_finished_at"] = now()
            require(record(name + "_enable", "lambda", "update-event-source-mapping", {"UUID": case["mapping_uuid"], "Enabled": True}))
            settle(case["mapping_uuid"], "Enabled")
        denial_deadline = time.monotonic() + 720
        attempt = 0
        while time.monotonic() < denial_deadline:
            scan("denial_poll_" + str(attempt))
            summary = metrics("denial_metrics_" + str(attempt))
            require(record("denied_mapping_status_" + str(attempt), "lambda", "get-event-source-mapping", {"UUID": denied["mapping_uuid"]}))
            if (summary["function"]["DestinationDeliveryFailures"]["sum"] or 0) > 0 and all(c["handler_attempts"] for c in capture["cases"].values()) and capture["cases"]["delivered"]["destination_documents"]:
                denied["delivery_failure_observed_at"] = now()
                denied["metrics_before_restore"] = summary
                break
            time.sleep(20)
            attempt += 1
        else:
            raise RuntimeError("No confirmed denied destination failure within 720 seconds")
        denied["restoration_started_at"] = now()
        require(record("restore_destination_policy", "sqs", "set-queue-attributes", {"QueueUrl": denied["queue_url"], "Attributes": {"Policy": ""}}))
        require(record("verify_restored_policy", "sqs", "get-queue-attributes", {"QueueUrl": denied["queue_url"], "AttributeNames": ["Policy"]}))
        denied["restoration_finished_at"] = now()
        # A new poison record proves that restored delivery is functioning, while
        # original sequence numbers distinguish recovery from unrelated delivery.
        time.sleep(20)
        put("denied", 4, "restored_control")
        denied["restored_control_put_at"] = now()
        denied["restored_control_record_count"] = 1
        recovery_deadline = time.monotonic() + 960
        attempt = 0
        while time.monotonic() < recovery_deadline:
            scan("recovery_poll_" + str(attempt))
            summary = metrics("recovery_metrics_" + str(attempt))
            initial_sequences = {r["dynamodb"]["SequenceNumber"] for a in denied["handler_attempts"].values() for r in a["event"]["Records"] if r["dynamodb"]["NewImage"]["phase"]["S"] == "initial"}
            delivered_ranges = [(d["DDBStreamBatchInfo"]["startSequenceNumber"], d["DDBStreamBatchInfo"]["endSequenceNumber"]) for d in denied["destination_documents"].values()]
            recovered = bool(initial_sequences) and all(any(int(first) <= int(sequence) <= int(last) for first, last in delivered_ranges) for sequence in initial_sequences)
            control_seen = any(r["dynamodb"]["NewImage"]["phase"]["S"] == "restored_control" for a in denied["handler_attempts"].values() for r in a["event"]["Records"])
            denied["original_sequences_observed_in_destination"] = recovered
            denied["recovery_last_observation_at"] = now()
            if recovered and control_seen and (summary["denied"]["OnFailureDestinationDeliveredEventCount"]["sum"] or 0) >= 4:
                break
            time.sleep(30)
            attempt += 1
        denied["recovery_observation_bound_seconds"] = 960
        for name, case in capture["cases"].items():
            require(record(name + "_disable", "lambda", "update-event-source-mapping", {"UUID": case["mapping_uuid"], "Enabled": False}))
            settle(case["mapping_uuid"], "Disabled")
            require(record(name + "_list_native_metrics", "cloudwatch", "list-metrics", {"Namespace": "AWS/Lambda", "Dimensions": [{"Name": "EventSourceMappingUUID", "Value": case["mapping_uuid"]}]}))
        time.sleep(90)
        scan("final")
        metrics("final_metrics")
        capture["findings"] = findings(capture)
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
            clean("delete_function", "lambda", "delete-function", {"FunctionName": prefix}, ("Success", "ResourceNotFoundException"))
            clean("function_absent", "lambda", "get-function", {"FunctionName": prefix}, ("ResourceNotFoundException",))
            for alias in owned["aliases"]:
                clean("alias_absent_" + alias, "lambda", "get-alias", {"FunctionName": prefix, "Name": alias}, ("ResourceNotFoundException",))
            for version in owned["versions"]:
                clean("version_absent_" + version, "lambda", "get-function", {"FunctionName": prefix, "Qualifier": version}, ("ResourceNotFoundException",))
        for table in owned["tables"]:
            clean("delete_table", "dynamodb", "delete-table", {"TableName": table}, ("Success", "ResourceNotFoundException"))
            for attempt in range(60):
                result = clean("table_absent_" + str(attempt), "dynamodb", "describe-table", {"TableName": table}, ("Success", "ResourceNotFoundException"))
                if result.get("code") == "ResourceNotFoundException":
                    break
                time.sleep(2)
            else:
                errors.append("Table remains: " + table)
        for name, url in owned["queues"]:
            clean("delete_queue", "sqs", "delete-queue", {"QueueUrl": url})
            clean("queue_absent", "sqs", "get-queue-url", {"QueueName": name}, ("AWS.SimpleQueueService.NonExistentQueue",))
        if owned["logs"]:
            clean("delete_logs", "logs", "delete-log-group", {"logGroupName": log_group}, ("Success", "ResourceNotFoundException"))
            result = clean("logs_absent", "logs", "describe-log-groups", {"logGroupNamePrefix": log_group})
            if result.get("output", {}).get("logGroups"):
                errors.append("Log group remains")
        for policy_name in owned["policies"]:
            clean("delete_policy", "iam", "delete-role-policy", {"RoleName": role_name, "PolicyName": policy_name})
            clean("policy_absent", "iam", "get-role-policy", {"RoleName": role_name, "PolicyName": policy_name}, ("NoSuchEntity",))
        if owned["role"]:
            clean("delete_role", "iam", "delete-role", {"RoleName": role_name})
            clean("role_absent", "iam", "get-role", {"RoleName": role_name}, ("NoSuchEntity",))
        capture["cleanup_errors"] = errors
        capture["cleanup_verified"] = not errors
        capture["finished_at"] = now()
        save()
        if errors:
            raise RuntimeError("Owned resource cleanup failed: " + json.dumps(errors))


if __name__ == "__main__":
    main()
