#!/usr/bin/env python3
"""Capture owned CloudWatch metric DATA events from a single-region S3 trail.

Run with --account ACCOUNT --output PATH outside testdata. Only
CloudWatch metric data events are selected; no management logging is started.
Two metric series remain until native retention expires; other resources are
removed and their absence verified in finally. CLI debug is never persisted.
"""
import argparse
import ast
from collections import Counter
import datetime
import gzip
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import time
import uuid

from aws_cli import CLITimeout, result, run


REGION = "us-east-1"
EVENTS = ["PutMetricData", "GetMetricStatistics", "ListMetrics", "GetMetricData"]
REFERENCES = [
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/logging_cw_api_calls.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--delivery-seconds", type=int, default=1080,
                        choices=range(120, 1081), metavar="120..1080")
    parser.add_argument("--resume-cleaned", action="store_true",
                        help="Reuse exact resource/metric identities and remaining bounds after verified cleanup")
    args = parser.parse_args()
    previous = None
    if args.output.exists():
        if not args.resume_cleaned:
            parser.error("output already exists; choose a new path or resume a cleaned run")
        previous = json.loads(args.output.read_text())
        if previous.get("cleanup", {}).get("verified") is not True:
            parser.error("resume requires verified cleanup")
        if previous.get("verified_account") != args.account or previous["region"] != REGION:
            parser.error("resume capture account/region does not match --account")
    elif args.resume_cleaned:
        parser.error("resume requires an existing capture")
    previous_logging_seconds = 0
    prior = previous
    while prior:
        starts = [item for item in prior["observations"] if item.get("operation") == "start-logging"]
        stops = [item for item in prior["cleanup"]["observations"] if item.get("operation") == "stop-logging"]
        if starts and stops:
            previous_logging_seconds += (
                datetime.datetime.fromisoformat(stops[0]["request_started"])
                - datetime.datetime.fromisoformat(starts[0]["request_finished"])).total_seconds()
        prior = prior.get("previous_run", prior.get("previous_setup"))
    args.delivery_seconds = min(args.delivery_seconds, 1080 - int(previous_logging_seconds + 1))
    if args.delivery_seconds < 120:
        parser.error("insufficient remaining delivery window")
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="")
    for key in list(env):
        if key.startswith("AWS_ENDPOINT_URL"):
            del env[key]
    env["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
    token = previous["owned_identity"]["namespace"].rsplit("/", 1)[1] if previous else uuid.uuid4().hex[:16]
    env["AWS_SDK_UA_APP_ID"] = "stackd-cwaudit-" + token
    stem = "stackd-cwaudit-" + token
    bucket, trail = stem + "-bucket", stem + "-trail"
    namespace = "Stackd/NativeAudit/" + token
    owned = {"bucket": False, "trail": False}
    counts = Counter(previous["request_counts"]["by_operation"] if previous else {})
    caller_values = []
    request_ids = {}
    capture = {
        "source": "Native AWS CLI via scripts/aws/aws_cli.py; delivered CloudTrail S3 JSON",
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": REGION,
        "primary_references": REFERENCES,
        "documentation_revision": {
            "url": REFERENCES[0], "retrieved_date": "2026-09-14",
            "last_modified": "Sat, 12 Sep 2026 02:53:17 GMT",
            "rule": "All four named APIs are DATA events, AWS::CloudWatch::Metric; not Event history.",
        },
        "bounds": {"delivery_seconds": args.delivery_seconds, "poll_seconds": 20,
                   "previous_logging_seconds": previous_logging_seconds,
                   "max_cli_calls": 200, "cleanup_reserved_calls": 30,
                   "cli_timeout_seconds": 50, "automatic_retries": False},
        "owned_identity": {"bucket": bucket, "trail": trail, "namespace": namespace,
                           "metric_names": ["Scalar", "Distribution"]},
        "redaction": "Credential ID values, caller principal/ARN/name and client IP redacted; keys retained. Owned names/account, event/request IDs, times, projections and response fields unchanged. No debug logs retained.",
        "observations": [], "delivered_records": [], "delivery_objects": [],
        "residual_metrics": {"maximum_series": 2, "publication_succeeded": bool(previous and previous["residual_metrics"]["publication_succeeded"]),
                             "reason": "CloudWatch has no metric/sample deletion API."},
        "cleanup": {"verified": False, "observations": []},
    }
    if previous:
        capture["previous_run"] = previous

    def scrub(value):
        if isinstance(value, dict):
            return {key: "REDACTED" if key in ("accessKeyId", "AccessKeyId", "SecretAccessKey", "SessionToken", "principalId", "userName")
                    else "192.0.2.1" if key == "sourceIPAddress" and isinstance(item, str) and not item.endswith("amazonaws.com")
                    else scrub(item) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, str):
            for native in caller_values:
                value = value.replace(native, "REDACTED_CALLER")
        return value

    def save():
        capture["request_counts"] = {"by_operation": dict(counts), "total": sum(counts.values())}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(scrub(capture), indent=2) + "\n")

    def request(label, service, operation, parameters, *, cleanup=False, options=()):
        limit = 200 if cleanup else 170
        if sum(counts.values()) >= limit:
            raise RuntimeError("CLI call bound reached; remaining calls reserved for cleanup")
        counts[service + ":" + operation] += 1
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cli_options = ["--no-paginate", "--cli-connect-timeout", "10", "--cli-read-timeout", "30", *options]
        wire_parameters = parameters
        if service == "s3api" and operation == "get-object":
            # Streaming S3 commands do not accept --cli-input-json.
            wire_parameters = None
            cli_options[-1:-1] = ["--bucket", parameters["Bucket"], "--key", parameters["Key"]]
        if service == "cloudwatch":
            cli_options.append("--debug")
        ids = []
        try:
            process = run(service, operation, wire_parameters, env, options=cli_options, timeout=50)
            response = result(process, debug=service == "cloudwatch",
                              cli_message=None if operation == "get-object" else "AWS CLI failed; raw diagnostics discarded")
            if service == "cloudwatch":
                for headers in re.findall(r"Response headers: (\{[^\n]+\})", process.stderr):
                    try:
                        headers = ast.literal_eval(headers)
                    except (ValueError, SyntaxError):
                        continue
                    ids.extend(str(value) for key, value in headers.items()
                               if key.lower() in ("x-amzn-requestid", "x-amzn-request-id", "x-amz-request-id"))
                for request_id in ids:
                    request_ids[request_id] = label
        except CLITimeout:
            response = {"code": "CLITimeout", "message": "Bounded timeout; native outcome unknown"}
        recorded = response
        if service == "sts" and response["code"] == "Success":
            caller_values.extend([response["output"]["Arn"], response["output"]["UserId"]])
            recorded = {"code": "Success", "output": {"Account": response["output"]["Account"]}}
        observation = {"label": label, "service": service, "operation": operation,
                       "input": parameters, "request_started": started,
                       "request_finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       "result": recorded}
        if service == "cloudwatch":
            observation["request_ids"] = ids
        destination = capture["cleanup"]["observations"] if cleanup else capture["observations"]
        destination.append(observation)
        save()
        print(label + ": " + response["code"], flush=True)
        return response

    def require(response):
        if response["code"] != "Success":
            raise RuntimeError("Required native call failed: " + response["code"])
        return response["output"]

    def create(kind, service, operation, parameters):
        owned[kind] = True
        response = request("create-" + kind, service, operation, parameters)
        if response["code"] not in ("Success", "CLITimeout"):
            owned[kind] = False
        return require(response)

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt("Interrupted; cleaning owned resources")

    signal.signal(signal.SIGTERM, interrupt)
    save()
    try:
        identity = require(request("identity", "sts", "get-caller-identity", {}))
        if identity["Account"] != args.account:
            raise RuntimeError("Unexpected AWS account; no resources created")
        capture["verified_account"] = identity["Account"]
        arn = f"arn:aws:cloudtrail:{REGION}:{args.account}:trail/{trail}"
        capture["owned_identity"]["trail_arn"] = arn
        create("bucket", "s3api", "create-bucket", {"Bucket": bucket})
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "CloudTrailAclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::" + bucket,
             "Condition": {"StringEquals": {"aws:SourceArn": arn}}},
            {"Sid": "CloudTrailWrite", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/owned/AWSLogs/{args.account}/*",
             "Condition": {"StringEquals": {"aws:SourceArn": arn, "s3:x-amz-acl": "bucket-owner-full-control"}}},
        ]}
        require(request("bucket-policy", "s3api", "put-bucket-policy", {"Bucket": bucket, "Policy": json.dumps(policy)}))
        create("trail", "cloudtrail", "create-trail", {
            "Name": trail, "S3BucketName": bucket, "S3KeyPrefix": "owned",
            "IncludeGlobalServiceEvents": False, "IsMultiRegionTrail": False,
            "EnableLogFileValidation": False, "IsOrganizationTrail": False,
        })
        selectors = [{"Name": "OnlyCloudWatchMetricData", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": ["AWS::CloudWatch::Metric"]},
            {"Field": "eventSource", "Equals": ["monitoring.amazonaws.com"]},
            {"Field": "eventName", "Equals": EVENTS},
        ]}]
        require(request("select-only-metric-data", "cloudtrail", "put-event-selectors",
                        {"TrailName": trail, "AdvancedEventSelectors": selectors}))
        require(request("record-selectors", "cloudtrail", "get-event-selectors", {"TrailName": trail}))
        require(request("start-logging", "cloudtrail", "start-logging", {"Name": trail}))
        began = time.monotonic()
        # Allow selector/start propagation before the first small publication.
        time.sleep(60)
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=123000)
        start = (now - datetime.timedelta(minutes=5)).isoformat()
        end = (now + datetime.timedelta(minutes=5)).isoformat()
        dimensions = [{"Name": "Probe", "Value": token}, {"Name": "Kind", "Value": "audit"}]
        metric = {"Namespace": namespace, "MetricName": "Scalar", "Dimensions": dimensions}
        samples = [
            {"MetricName": "Scalar", "Dimensions": dimensions, "Timestamp": now.isoformat(),
             "Value": 7.5, "Unit": "Count", "StorageResolution": 1},
            {"MetricName": "Distribution", "Timestamp": now.isoformat(), "Values": [2, 4],
             "Counts": [1, 3], "Unit": "Milliseconds", "StorageResolution": 60},
        ]
        stats = dict(metric, StartTime=start, EndTime=end, Period=60,
                     Statistics=["SampleCount", "Average", "Sum", "Minimum", "Maximum"],
                     Unit="Count")
        query = {"MetricDataQueries": [
            {"Id": "m1", "MetricStat": {"Metric": metric, "Period": 60, "Stat": "Sum", "Unit": "Count"},
             "ReturnData": False},
            {"Id": "e1", "Expression": "m1 * 2", "Label": "Owned expression", "ReturnData": True},
        ], "StartTime": start, "EndTime": end, "ScanBy": "TimestampAscending",
            "MaxDatapoints": 10, "LabelOptions": {"Timezone": "+0000"}}

        def exercise(suffix):
            require(request("publish-" + suffix, "cloudwatch", "put-metric-data", {"Namespace": namespace, "MetricData": samples}))
            capture["residual_metrics"]["publication_succeeded"] = True
            require(request("statistics-" + suffix, "cloudwatch", "get-metric-statistics", stats))
            require(request("list-" + suffix, "cloudwatch", "list-metrics", {
                "Namespace": namespace, "MetricName": "Scalar", "Dimensions": dimensions, "RecentlyActive": "PT3H"}))
            require(request("data-" + suffix, "cloudwatch", "get-metric-data", query))
            request("rejected-publication-" + suffix, "cloudwatch", "put-metric-data", {
                "Namespace": namespace, "MetricData": [dict(samples[0], Value=1e200)]})
            request("rejected-query-" + suffix, "cloudwatch", "get-metric-statistics", dict(stats, EndTime=start, StartTime=end))

        exercise("initial")
        seen_objects, seen_events = set(), set()
        repeated = False
        all_observed = False
        with tempfile.TemporaryDirectory(prefix="stackd-cwaudit-") as temporary:
            while time.monotonic() - began < args.delivery_seconds and sum(counts.values()) < 160:
                elapsed = time.monotonic() - began
                if elapsed >= 180 and not repeated:
                    exercise("after-propagation")
                    repeated = True
                listing = require(request("poll-delivery", "s3api", "list-objects-v2", {
                    "Bucket": bucket, "Prefix": f"owned/AWSLogs/{args.account}/CloudTrail/{REGION}/", "MaxKeys": 1000}))
                if listing.get("IsTruncated"):
                    raise RuntimeError("Unexpected large owned delivery; stop instead of unbounded downloads")
                for item in listing.get("Contents", []):
                    key = item["Key"]
                    if key in seen_objects or not key.endswith(".json.gz"):
                        continue
                    if sum(counts.values()) >= 160 or time.monotonic() - began >= args.delivery_seconds:
                        break
                    path = Path(temporary) / "delivery.json.gz"
                    require(request("read-delivery", "s3api", "get-object", {"Bucket": bucket, "Key": key}, options=[str(path)]))
                    with gzip.open(path, "rt") as body:
                        delivered = json.load(body)
                    selected_count = 0
                    for event in delivered.get("Records", []):
                        if event.get("eventSource") != "monitoring.amazonaws.com" or event.get("eventName") not in EVENTS:
                            continue
                        label = request_ids.get(event.get("requestID"))
                        if not label and namespace not in json.dumps(event.get("requestParameters")) and token not in event.get("userAgent", ""):
                            continue
                        selected_count += 1
                        if event.get("eventID") in seen_events:
                            continue
                        seen_events.add(event.get("eventID"))
                        capture["delivered_records"].append({"s3_key": key, "matched_request_label": label,
                                                              "event": scrub(event)})
                    capture["delivery_objects"].append({"key": key, "record_count": len(delivered.get("Records", [])),
                                                        "owned_record_count": selected_count})
                    seen_objects.add(key)
                observed = {(entry["event"]["eventName"], "errorCode" in entry["event"])
                            for entry in capture["delivered_records"]}
                required = {(name, False) for name in EVENTS} | {("PutMetricData", True), ("GetMetricStatistics", True)}
                all_observed = required <= observed
                capture["delivery"] = {"elapsed_seconds": round(time.monotonic() - began, 3),
                                       "all_named_projections_observed": all_observed,
                                       "observed_cases": sorted([list(case) for case in observed]),
                                       "unresolved_cases": sorted([list(case) for case in required - observed])}
                save()
                if all_observed:
                    break
                time.sleep(max(0, min(20, args.delivery_seconds - (time.monotonic() - began))))
        request("final-trail-status", "cloudtrail", "get-trail-status", {"Name": trail})
        capture["completed"] = True
        capture["uncertainty"] = ["One account/region/run; bounded non-observation is not an absence guarantee.",
                                  "Only owned request-correlated or namespace/user-agent-correlated records retained; other records discarded."]
    except BaseException as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        def clean(label, service, operation, parameters):
            try:
                return request(label, service, operation, parameters, cleanup=True)
            except Exception as error:
                capture["cleanup"]["observations"].append({"label": label, "failure_type": type(error).__name__})
                return {"code": "CleanupException"}

        if owned["trail"]:
            clean("stop-trail", "cloudtrail", "stop-logging", {"Name": trail})
            clean("delete-trail", "cloudtrail", "delete-trail", {"Name": trail})
            checked = clean("verify-trail-absent", "cloudtrail", "get-trail", {"Name": trail})
            owned["trail"] = checked["code"] != "TrailNotFoundException"
        if owned["bucket"]:
            clean("revoke-bucket-delivery-policy", "s3api", "delete-bucket-policy", {"Bucket": bucket})
            for attempt in range(5):
                listing = clean("list-owned-cleanup-objects-" + str(attempt), "s3api", "list-objects-v2", {"Bucket": bucket, "MaxKeys": 1000})
                if listing["code"] == "NoSuchBucket":
                    owned["bucket"] = False
                    break
                if listing["code"] != "Success":
                    break
                keys = [{"Key": item["Key"]} for item in listing["output"].get("Contents", [])]
                if keys:
                    clean("delete-owned-objects-" + str(attempt), "s3api", "delete-objects", {"Bucket": bucket, "Delete": {"Objects": keys, "Quiet": True}})
                deleted = clean("delete-bucket-" + str(attempt), "s3api", "delete-bucket", {"Bucket": bucket})
                if deleted["code"] in ("Success", "NoSuchBucket"):
                    checked = clean("verify-bucket-absent", "s3api", "head-bucket", {"Bucket": bucket})
                    owned["bucket"] = checked["code"] not in ("404", "NoSuchBucket", "NotFound")
                    if not owned["bucket"]:
                        break
                time.sleep(2)
        capture["cleanup"]["remaining_owned"] = [kind for kind, present in owned.items() if present]
        capture["cleanup"]["verified"] = not any(owned.values())
        capture["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    if not capture["cleanup"]["verified"]:
        raise SystemExit("Owned cleanup incomplete; inspect capture")
    if "failure" in capture:
        raise SystemExit("Native experiment failed; inspect capture")
    print("Capture complete; cleanup verified", flush=True)


if __name__ == "__main__":
    main()
