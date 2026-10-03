#!/usr/bin/env python3
"""Capture an owned native CloudTrail -> CloudWatch Logs experiment.

Run with --output PATH (outside testdata). Uses configured AWS credentials only,
requires account prefix 05, and removes owned resources in finally. No S3 log
bodies or unrelated CloudTrail events are retained. Delivery wait is bounded.
"""
import argparse
from collections import Counter
import datetime
import json
import os
from pathlib import Path
import signal
import time
import uuid

from aws_cli import CLITimeout, ProbeResult, result, run


REGION = "us-east-1"
REFERENCES = [
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-log-group-log-stream-naming-for-cloudtrail.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--append", action="store_true", help="Retain a previous fully cleaned experiment in previous_runs")
    parser.add_argument("--delivery-seconds", type=int, default=900, choices=range(120, 1201), metavar="120..1200")
    parser.add_argument("--configuration-only", action="store_true",
                        help="Probe empty destination updates from a configured pair without starting logging")
    args = parser.parse_args()
    previous_runs = []
    if args.output.exists():
        if not args.append:
            parser.error("output already exists; choose a new path or --append")
        previous = json.loads(args.output.read_text())
        if previous.get("cleanup", {}).get("verified") is not True:
            parser.error("previous experiment has unverified cleanup; resolve it before rerunning")
        previous_runs = previous.pop("previous_runs", []) + [previous]
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="")
    # Never let a local endpoint override turn this into a purported native capture.
    for key in list(env):
        if key.startswith("AWS_ENDPOINT_URL"):
            del env[key]
    env["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
    token = uuid.uuid4().hex[:16]
    stem = "stackd-ctlogs-" + token
    bucket, trail, role = stem + "-bucket", stem + "-trail", stem + "-role"
    group = "/stackd/native-cloudtrail-logs-" + token
    policy_name = "owned-cloudtrail-logs"
    account = ""
    substitutions = [(bucket, "stackd-ctlogs-owned-bucket"), (trail, "stackd-ctlogs-owned-trail"),
                     (role, "stackd-ctlogs-owned-role"), (group, "/stackd/native-cloudtrail-logs-owned")]
    counts = Counter()
    owned = {"bucket": False, "trail": False, "role": False, "policy": False, "group": False}
    capture = {
        "source": "native AWS CLI using scripts/aws/aws_cli.py run/result typed decoding",
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "region": REGION,
        "scope": "Unique owned S3 bucket, single-region non-organization trail, IAM role/inline policy and Logs group; write management selection; only own PutBucketTagging records retained",
        "primary_references": REFERENCES,
        "bounds": {"delivery_seconds": args.delivery_seconds, "poll_seconds": 20,
                   "removal_poll_seconds": 60, "cli_timeout_seconds": 50, "automatic_retries": False},
        "substitutions": "Account -> 123456789012; unique names -> owned names consistently across policies, ARNs and messages. Credential IDs omitted; caller ARN/principal ID replaced consistently; client IP -> 192.0.2.1. Native timestamps, request/event IDs and opaque page tokens retained. Message JSON reformatted after redaction.",
        "identity_relationships": {}, "resources": [], "observations": [], "delivery": {},
        "previous_runs": previous_runs,
        "uncertainty": [
            "One account/region/run; bounded absence is not permanent loss or a guaranteed delay.",
            "IAM and trail propagation can affect preflight and delivery independently; recorded retry spacing does not establish AWS retry intervals.",
            "No organization, cross-account, KMS, high-volume streams or delivery-time permission revocation experiment.",
            "CLI debug is decoded only for HTTP status; raw debug/signatures never persisted. HTTP status omitted where shared helper cannot observe it.",
            "S3 delivery bodies are not read. FilterLogEvents queries are restricted to the new group and owned bucket tagging records; GetLogEvents projection discards any other records.",
            "Trail management selectors cannot select S3 specifically: eventSource permits only KMS/RDS exclusions. The new destination can transiently receive other write management events, which are never retained in this capture.",
            "Substituted owned names are scoped to each experiment; previous_runs used different unique native resources.",
        ],
        "cleanup": {"verified": False, "observations": []},
    }
    if args.configuration_only:
        capture["scope"] = "Unique owned S3 bucket, single-region non-organization trail, IAM role/inline policy and Logs group; configuration-only empty destination updates; logging never started"
        capture["bounds"] = {"configuration_attempts": 4, "configuration_retry_seconds": 15,
                             "cli_timeout_seconds": 50, "automatic_retries": False}
        capture["delivery"] = {"attempted": False, "reason": "Configuration-only mode never starts logging or reads events"}
        capture["uncertainty"] = [
            "One account/region/run; immediate configuration/status observations do not establish event-delivery behavior.",
            "IAM propagation may require bounded configured-trail creation retries.",
            "CLI debug is decoded only for HTTP status; raw debug/signatures never persisted. HTTP status omitted where shared helper cannot observe it.",
        ]

    def scrub(value):
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            return {key: ("owned-probe-caller" if key == "userName" else
                          "192.0.2.1" if key == "sourceIPAddress" and isinstance(item, str) and not item.endswith("amazonaws.com") else scrub(item))
                    for key, item in value.items() if key not in ("accessKeyId", "AccessKeyId", "SecretAccessKey", "SessionToken")}
        if isinstance(value, str):
            for old, new in substitutions:
                value = value.replace(old, new)
            return value
        return value

    def save():
        capture["request_counts"] = dict(counts, total=sum(counts.values()))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(scrub(capture), indent=2) + "\n")

    def selected(event):
        try:
            message = json.loads(event["message"])
        except (KeyError, ValueError):
            return None
        if (message.get("eventSource") != "s3.amazonaws.com" or message.get("eventName") != "PutBucketTagging"
                or message.get("requestParameters", {}).get("bucketName") != bucket):
            return None
        return dict(event, message=json.dumps(scrub(message), separators=(",", ":")))

    def request(label, service, operation, parameters, *, cleanup=False) -> ProbeResult:
        counts[service] += 1
        started = time.time_ns() // 1_000_000
        try:
            process = run(service, operation, parameters, env, options=["--no-paginate", "--debug",
                          "--cli-connect-timeout", "10", "--cli-read-timeout", "30"], timeout=50)
            response = result(process, debug=True)
        except CLITimeout:
            response = {"code": "CLITimeout", "message": "Bounded CLI timeout; provider outcome unknown"}
        if service == "sts" and response["code"] == "Success":
            output = response["output"]
            caller_arn = output["Arn"]
            arn_prefix, resource_name = caller_arn.rsplit(":", 1)
            if resource_name != "root":
                resource_kind = resource_name.split("/", 1)[0]
                replacement = resource_kind + "/owned-probe-caller"
                if resource_kind == "assumed-role":
                    replacement += "/owned-session"
                substitutions.append((caller_arn, arn_prefix.replace(output["Account"], "123456789012") + ":" + replacement))
                substitutions.append((output["UserId"], "OWNEDCALLERID"))
            substitutions.append((output["Account"], "123456789012"))
            # Do not persist the caller's native identity.
            recorded = {**response, "output": {"Account": "123456789012"}}
        else:
            recorded = response
        if service == "logs" and operation in ("filter-log-events", "get-log-events") and response["code"] == "Success":
            output = response["output"]
            events = [match for event in output.get("events", []) if (match := selected(event)) is not None]
            response = {**response, "output": {**output, "events": events}}
            recorded = response
        observation = {"label": label, "service": service, "operation": operation, "input": parameters,
                       "request_started_ms": started, "request_finished_ms": time.time_ns() // 1_000_000,
                       "result": recorded}
        observations = capture["cleanup"]["observations"] if cleanup else capture["observations"]
        observations.append(observation)
        save()
        print(label + ": " + response["code"], flush=True)
        return response

    def require(response):
        if response["code"] != "Success":
            raise RuntimeError("Required native operation failed: " + response["code"])
        return response["output"]

    def resource(kind, name, service, operation, parameters):
        # Mark before requesting: a timeout can have created a resource.
        owned[kind] = True
        capture["resources"].append({"kind": kind, "name": name, "creation": "attempted"})
        response = request("create-" + kind, service, operation, parameters)
        if response["code"] != "Success" and response["code"] != "CLITimeout":
            owned[kind] = False
        capture["resources"][-1]["creation"] = response["code"]
        return require(response)

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt("Interrupted; cleaning owned resources")

    signal.signal(signal.SIGTERM, interrupt)
    save()
    try:
        identity = require(request("identity", "sts", "get-caller-identity", {}))
        account = identity["Account"]
        substitutions.append((account, "123456789012"))
        if account != args.account:
            raise RuntimeError("Unexpected AWS account; no resources created")
        trail_arn = f"arn:aws:cloudtrail:{REGION}:{account}:trail/{trail}"
        role_arn = f"arn:aws:iam::{account}:role/{role}"
        group_arn = f"arn:aws:logs:{REGION}:{account}:log-group:{group}"
        capture["identity_relationships"] = {"account": account, "trail_arn": trail_arn, "role_arn": role_arn,
                                             "group_arn": group_arn, "bucket": bucket,
                                             "role_trusted_service": "cloudtrail.amazonaws.com"}
        resource("bucket", bucket, "s3api", "create-bucket", {"Bucket": bucket})
        bucket_policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "AWSCloudTrailAclCheck20150319", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::" + bucket,
             "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
            {"Sid": "AWSCloudTrailWrite20150319", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/owned/AWSLogs/{account}/*",
             "Condition": {"StringEquals": {"aws:SourceArn": trail_arn, "s3:x-amz-acl": "bucket-owner-full-control"}}},
        ]}
        require(request("bucket-policy", "s3api", "put-bucket-policy", {"Bucket": bucket, "Policy": json.dumps(bucket_policy)}))
        resource("group", group, "logs", "create-log-group", {"logGroupName": group, "tags": {"owner": "stackd-probe"}})
        require(request("group-retention", "logs", "put-retention-policy", {"logGroupName": group, "retentionInDays": 1}))
        request("describe-owned-group", "logs", "describe-log-groups", {"logGroupNamePrefix": group})
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role_output = resource("role", role, "iam", "create-role", {"RoleName": role, "AssumeRolePolicyDocument": json.dumps(trust)})
        substitutions.append((role_output["Role"]["RoleId"], "OWNEDROLEID"))
        base = {"Name": trail, "S3BucketName": bucket, "S3KeyPrefix": "owned", "IncludeGlobalServiceEvents": False,
                "IsMultiRegionTrail": False, "EnableLogFileValidation": False, "IsOrganizationTrail": False}
        destination = {"CloudWatchLogsLogGroupArn": group_arn + ":*", "CloudWatchLogsRoleArn": role_arn}

        def create_case(label, extra):
            owned["trail"] = True
            response = request(label, "cloudtrail", "create-trail", dict(base, **extra))
            capture["resources"].append({"kind": "trail", "name": trail, "creation": response["code"], "label": label})
            if response["code"] == "Success":
                require(request(label + "-delete", "cloudtrail", "delete-trail", {"Name": trail}))
            elif response["code"] == "CLITimeout":
                raise RuntimeError("CreateTrail timed out; cleanup must resolve ownership")
            owned["trail"] = False
            return response

        if not args.configuration_only:
            create_case("create-group-without-role", {"CloudWatchLogsLogGroupArn": group_arn + ":*"})
            create_case("create-role-without-group", {"CloudWatchLogsRoleArn": role_arn})
            create_case("create-malformed-group", dict(destination, CloudWatchLogsLogGroupArn="not-an-arn"))
            create_case("create-malformed-role", dict(destination, CloudWatchLogsRoleArn="not-an-arn"))
            time.sleep(20)
            create_case("create-role-without-logs-policy", destination)
        stream_resource = group_arn + f":log-stream:{account}_CloudTrail_{REGION}*"

        def put_policy(actions):
            document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": stream_resource}]}
            owned["policy"] = True
            return request("role-policy-" + "-".join(action.split(":")[1] for action in actions), "iam", "put-role-policy",
                           {"RoleName": role, "PolicyName": policy_name, "PolicyDocument": json.dumps(document)})

        if not args.configuration_only:
            require(put_policy(["logs:CreateLogStream"]))
            time.sleep(15)
            create_case("create-role-missing-put-events", destination)
            request("streams-after-failed-create", "logs", "describe-log-streams", {"logGroupName": group})
        require(put_policy(["logs:CreateLogStream", "logs:PutLogEvents"]))
        capture["resources"].append({"kind": "inline-policy", "name": policy_name, "role": role, "creation": "Success"})
        for attempt in range(4):
            time.sleep(15)
            owned["trail"] = True
            response = request("create-configured-trail-" + str(attempt), "cloudtrail", "create-trail", dict(base, **destination))
            capture["resources"].append({"kind": "trail", "name": trail, "creation": response["code"], "attempt": attempt})
            if response["code"] == "Success":
                break
            if response["code"] not in ("InvalidCloudWatchLogsRoleArnException", "InvalidCloudWatchLogsLogGroupArnException"):
                require(response)
        require(response)
        if args.configuration_only:
            capture["configuration_transitions"] = []
            for index, (label, extra) in enumerate([
                ("configured-empty-role-only", {"CloudWatchLogsRoleArn": ""}),
                ("configured-both-empty", {"CloudWatchLogsLogGroupArn": "", "CloudWatchLogsRoleArn": ""}),
                ("configured-empty-group-nonempty-role", {"CloudWatchLogsLogGroupArn": "", "CloudWatchLogsRoleArn": role_arn}),
                ("configured-nonempty-group-empty-role", {"CloudWatchLogsLogGroupArn": group_arn + ":*", "CloudWatchLogsRoleArn": ""}),
            ]):
                if index:
                    require(request(label + "-restore", "cloudtrail", "update-trail", dict(Name=trail, **destination)))
                before = require(request(label + "-before-get", "cloudtrail", "get-trail", {"Name": trail}))["Trail"]
                if any(before.get(key) != value for key, value in destination.items()):
                    raise RuntimeError("Configured destination pair not established before " + label)
                updated = request(label, "cloudtrail", "update-trail", dict(Name=trail, **extra))
                after = require(request(label + "-immediate-get", "cloudtrail", "get-trail", {"Name": trail}))["Trail"]
                require(request(label + "-immediate-status", "cloudtrail", "get-trail-status", {"Name": trail}))
                preserved = all(after.get(key) == value for key, value in destination.items())
                removed = all(key not in after for key in destination)
                capture["configuration_transitions"].append({
                    "label": label,
                    "update_code": updated["code"],
                    "update_http_status": updated.get("http_status"),
                    "before_destination": {key: before[key] for key in destination if key in before},
                    "after_destination": {key: after[key] for key in destination if key in after},
                    "after_destination_field_presence": {key: key in after for key in destination},
                    "observed_state": "preserved" if preserved else "removed" if removed else "changed",
                })
                save()
        else:
            request("get-configured-trail", "cloudtrail", "get-trail", {"Name": trail})
            request("describe-configured-trail", "cloudtrail", "describe-trails", {"trailNameList": [trail], "includeShadowTrails": False})
            request("streams-after-configured-create", "logs", "describe-log-streams", {"logGroupName": group})
            for label, extra in [
                ("update-omitted-destination", {}),
                ("update-group-without-star", {"CloudWatchLogsLogGroupArn": group_arn}),
                ("update-missing-group", {"CloudWatchLogsLogGroupArn": group_arn + "-missing:*"}),
                ("update-wrong-region", {"CloudWatchLogsLogGroupArn": group_arn.replace(REGION, "us-west-2") + ":*"}),
                ("update-missing-role", {"CloudWatchLogsRoleArn": role_arn + "-missing"}),
                ("update-pair-without-star", dict(destination, CloudWatchLogsLogGroupArn=group_arn)),
                ("update-pair-missing-group", dict(destination, CloudWatchLogsLogGroupArn=group_arn + "-missing:*")),
                ("update-pair-wrong-region", dict(destination, CloudWatchLogsLogGroupArn=group_arn.replace(REGION, "us-west-2") + ":*")),
                ("update-pair-missing-role", dict(destination, CloudWatchLogsRoleArn=role_arn + "-missing")),
            ]:
                request(label, "cloudtrail", "update-trail", dict(Name=trail, **extra))
                request(label + "-get", "cloudtrail", "get-trail", {"Name": trail})
            require(request("restore-configured-destination", "cloudtrail", "update-trail", dict(Name=trail, **destination)))
            selectors = [{"Name": "WriteManagement", "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Management"]},
                {"Field": "readOnly", "Equals": ["false"]},
            ]}]
            require(request("select-write-management", "cloudtrail", "put-event-selectors", {"TrailName": trail, "AdvancedEventSelectors": selectors}))
            request("get-selectors", "cloudtrail", "get-event-selectors", {"TrailName": trail})
            require(request("start-logging", "cloudtrail", "start-logging", {"Name": trail}))
            start_ms = time.time_ns() // 1_000_000

            def tag(phase):
                return require(request("management-tag-" + phase, "s3api", "put-bucket-tagging",
                                       {"Bucket": bucket, "Tagging": {"TagSet": [{"Key": "stackd-probe-phase", "Value": phase}]}}))

            tag("delivery-initial")
            filter_input = {"logGroupName": group, "startTime": start_ms - 1000, "limit": 100,
                            "filterPattern": '{ $.eventName = "PutBucketTagging" && $.requestParameters.bucketName = "' + bucket + '" }'}
            began = time.monotonic()
            found = []
            repeated = False
            for attempt in range(args.delivery_seconds // 20 + 1):
                elapsed = time.monotonic() - began
                if elapsed >= 120 and not repeated:
                    tag("delivery-after-propagation")
                    repeated = True
                status = request("delivery-status-" + str(attempt), "cloudtrail", "get-trail-status", {"Name": trail})
                page = require(request("delivery-filter-" + str(attempt), "logs", "filter-log-events", filter_input))
                found = page.get("events", [])
                if found or elapsed >= args.delivery_seconds:
                    break
                time.sleep(min(20, args.delivery_seconds - elapsed))
            capture["delivery"] = {"selected_record_observed": bool(found), "wait_elapsed_seconds": round(time.monotonic() - began, 3),
                                   "filter_events": found, "status_at_observation": status}
            if found:
                streams = sorted({event["logStreamName"] for event in found})
                for stream in streams:
                    request("describe-delivery-stream", "logs", "describe-log-streams", {"logGroupName": group, "logStreamNamePrefix": stream})
                    request("get-delivered-record", "logs", "get-log-events", {"logGroupName": group, "logStreamName": stream,
                            "startTime": min(event["timestamp"] for event in found), "endTime": max(event["timestamp"] for event in found) + 1,
                            "startFromHead": True, "limit": 100})
            for label, extra in [
                ("remove-group-only", {"CloudWatchLogsLogGroupArn": ""}),
                ("remove-role-only", {"CloudWatchLogsRoleArn": ""}),
                ("remove-both", {"CloudWatchLogsLogGroupArn": "", "CloudWatchLogsRoleArn": ""}),
            ]:
                request(label, "cloudtrail", "update-trail", dict(Name=trail, **extra))
                request(label + "-get", "cloudtrail", "get-trail", {"Name": trail})
            tag("after-destination-removal")
            for attempt in range(4):
                if attempt:
                    time.sleep(20)
                request("removed-status-" + str(attempt), "cloudtrail", "get-trail-status", {"Name": trail})
                request("removed-filter-" + str(attempt), "logs", "filter-log-events", filter_input)
        capture["completed"] = True
    except BaseException as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        # Do not let another ordinary termination interrupt cleanup midway.
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
        if owned["role"]:
            if owned["policy"]:
                removed = clean("delete-inline-policy", "iam", "delete-role-policy", {"RoleName": role, "PolicyName": policy_name})
                owned["policy"] = removed["code"] not in ("Success", "NoSuchEntity")
            clean("delete-role", "iam", "delete-role", {"RoleName": role})
            checked = clean("verify-role-absent", "iam", "get-role", {"RoleName": role})
            owned["role"] = checked["code"] != "NoSuchEntity"
        if owned["group"]:
            clean("delete-group", "logs", "delete-log-group", {"logGroupName": group})
            checked = clean("verify-group-absent", "logs", "describe-log-groups", {"logGroupNamePrefix": group})
            owned["group"] = checked["code"] != "Success" or bool(checked.get("output", {}).get("logGroups"))
        if owned["bucket"]:
            # Stop new writes before draining; the unique bucket has no user objects.
            clean("delete-bucket-policy", "s3api", "delete-bucket-policy", {"Bucket": bucket})
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
        raise SystemExit("Native experiment blocked; inspect capture")
    print("Capture complete; cleanup verified", flush=True)


if __name__ == "__main__":
    main()
