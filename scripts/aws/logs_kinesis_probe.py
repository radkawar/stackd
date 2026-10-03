#!/usr/bin/env python3
"""Capture bounded native Logs/Kinesis behavior and delete every owned resource.

Usage: python3 scripts/aws/logs_kinesis_probe.py --account ACCOUNT OUTPUT.json
The STS caller must match --account. No Lambda, users, or persistent credentials
are created. One provisioned shard, one group, two destinations, three roles.
"""
import argparse
import base64
import collections
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import result, run


REGION = "us-east-1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    env = dict(os.environ, AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION,
               AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard",
               AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    for name in list(env):
        if name.startswith("AWS_ENDPOINT_URL"):
            del env[name]
    prefix = "stackd-logs-kin-" + uuid.uuid4().hex[:16]
    group = "/stackd/" + prefix
    stream_arn = f"arn:aws:kinesis:{REGION}:{args.account}:stream/{prefix}"
    group_arn = f"arn:aws:logs:{REGION}:{args.account}:log-group:{group}"
    destination = prefix + "-a"
    destination_arn = f"arn:aws:logs:{REGION}:{args.account}:destination:{destination}"
    roles = {suffix: prefix + "-" + suffix for suffix in ("delivery", "badtrust", "caller")}
    role_arns = {suffix: f"arn:aws:iam::{args.account}:role/{name}" for suffix, name in roles.items()}
    owned = {"stream": False, "group": False, "roles": [], "destinations": []}
    cleaning = False
    identity_verified = False
    caller_arn = None
    started = time.monotonic()
    iterator = None
    capture = {
        "source": "Native AWS CLI through scripts/aws/aws_cli.py; actual Kinesis gzip bytes decoded, no mocks",
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": REGION, "owned_prefix": prefix,
        "references": [
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutDestination.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutDestinationPolicy.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeDestinations.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteDestination.html",
            "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html",
            "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CreateDestination.html",
            "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html"],
        "substitutions": "Account replaced by 123456789012. Original caller ARN, STS identities and temporary credentials removed. Shard iterators removed. Owned unique names retained. Original compressed Data omitted (contains account); original byte length and SHA256 retained alongside sanitized actual decoded UTF-8 and JSON, never recompressed synthetic records. Partition keys are unmodified and their MD5 checks use the real account before sanitization.",
        "bounds": {"work_seconds": 1000, "work_requests": 280, "request_timeout_seconds": 35,
                   "automatic_retries": False, "iam_initial_wait_seconds": 18,
                   "cleanup_stream_poll_attempts": 36},
        "limitations": [
            "Only one account/region. No cross-account identity was available; logical same-account calls do not establish cross-account policy enforcement or delivery.",
            "Bounded observation cannot establish permanent loss, exact retry timing, or the documented 24-hour retry horizon / 10-minute nonretryable-error suspension.",
            "No throttling load is generated on the one-shard stream. Permission denial/restore probes nonretryable errors, not retryable throttling.",
            "IAM/Logs propagation and batching are asynchronous; observations are not deterministic timing guarantees.",
            "No Lambda resources, IAM users, or long-lived access keys are created."],
        "observations": [], "records": [], "windows": [], "cleanup": {"verified": False}}
    if args.output.exists():
        prior = json.loads(args.output.read_text())
        if not prior.get("cleanup", {}).get("verified"):
            raise RuntimeError("Refusing to overwrite capture with unverified cleanup")
        capture["previous_runs"] = prior.pop("previous_runs", []) + [prior]

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(capture, indent=2, ensure_ascii=False)
        if caller_arn:
            text = text.replace(caller_arn, "<original caller ARN>")
            text = text.replace(caller_arn.replace(args.account, "123456789012"), "<original caller ARN>")
        args.output.write_text(text.replace(args.account, "123456789012") + "\n")

    def request(label, service, operation, parameters, credentials=None):
        if service != "sts" and not identity_verified:
            raise RuntimeError("Account identity has not been verified")
        if not cleaning and (len(capture["observations"]) >= 280 or time.monotonic() - started > 1000):
            raise RuntimeError("Native work bound exhausted")
        shown = dict(parameters)
        if "ShardIterator" in shown:
            shown["ShardIterator"] = "<owned shard iterator>"
        entry = {"label": label, "service": service, "operation": operation, "input": shown,
                 "caller": "owned-no-passrole-session" if credentials else "original",
                 "started_ms": time.time_ns() // 1_000_000}
        capture["observations"].append(entry)
        try:
            response = result(run(service, operation, parameters, credentials or env,
                                  options=["--no-paginate", "--cli-connect-timeout", "10", "--cli-read-timeout", "15"], timeout=35))
            stored = json.loads(json.dumps(response))
            output = stored.get("output", {})
            if service == "sts":
                for field in ("Arn", "UserId", "Credentials", "AssumedRoleUser"):
                    output.pop(field, None)
            for field in ("ShardIterator", "NextShardIterator"):
                if field in output:
                    output[field] = "<owned shard iterator>"
            for record in output.get("Records", []):
                raw = base64.b64decode(record.pop("Data"))
                record["compressed_bytes"] = len(raw)
                record["compressed_sha256"] = hashlib.sha256(raw).hexdigest()
                record["gzip_magic"] = raw[:2].hex()
                decoded = gzip.decompress(raw).decode("utf-8")
                record["decoded_utf8"] = decoded
                record["envelope"] = json.loads(decoded)
                capture["records"].append(dict(record, observed_during=label))
            entry["result"] = stored
        except Exception as error:
            entry["transport_error"] = type(error).__name__
            raise
        finally:
            entry["finished_ms"] = time.time_ns() // 1_000_000
            save()
        print(label + ": " + response["code"], flush=True)
        return response

    def require(response):
        if response["code"] != "Success":
            raise RuntimeError("Required native call failed: " + response["code"])
        return response["output"]

    def policy(effect="Allow"):
        return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": effect,
            "Action": "kinesis:PutRecord", "Resource": [stream_arn, stream_arn + "-missing"]}]})

    def role_policy(label, suffix="delivery", effect="Allow"):
        return request(label, "iam", "put-role-policy", dict(RoleName=roles[suffix], PolicyName="owned", PolicyDocument=policy(effect)))

    def put(label, **extra):
        params = dict(logGroupName=group, filterName="direct", filterPattern="", destinationArn=stream_arn,
                      roleArn=role_arns["delivery"])
        params.update(extra)
        return request(label, "logs", "put-subscription-filter", {k: v for k, v in params.items() if v is not None})

    def describe(label):
        return request(label, "logs", "describe-subscription-filters", dict(logGroupName=group))

    def publish(stage, log_stream="alpha"):
        return require(request("publish-" + stage + "-" + log_stream, "logs", "put-log-events",
            dict(logGroupName=group, logStreamName=log_stream,
                 logEvents=[dict(timestamp=time.time_ns() // 1_000_000,
                                 message=json.dumps({"stage": stage, "stream": log_stream, "kind": "keep"})),
                            dict(timestamp=time.time_ns() // 1_000_000,
                                 message=json.dumps({"stage": stage, "stream": log_stream, "kind": "drop"}))])))

    def poll(label, attempts=8, until=None):
        nonlocal iterator
        start = len(capture["records"])
        begun = time.time_ns() // 1_000_000
        for index in range(attempts):
            output = require(request(f"records-{label}-{index}", "kinesis", "get-records",
                                     dict(ShardIterator=iterator, Limit=100)))
            iterator = output["NextShardIterator"]
            if until and any(until in event["message"] for record in capture["records"][start:]
                             for event in record["envelope"].get("logEvents", [])):
                break
            time.sleep(4)
        capture["windows"].append(dict(label=label, started_ms=begun, finished_ms=time.time_ns() // 1_000_000,
                                       records_observed=len(capture["records"]) - start))
        save()

    def destination_put(label, name=destination, **extra):
        params = dict(destinationName=name, targetArn=stream_arn, roleArn=role_arns["delivery"])
        params.update(extra)
        response = request(label, "logs", "put-destination", params)
        if response["code"] == "Success" and name not in owned["destinations"]:
            owned["destinations"].append(name)
        return response

    try:
        identity = require(request("identity", "sts", "get-caller-identity", {}))
        caller_arn = identity["Arn"]
        if identity["Account"] != args.account:
            raise RuntimeError("Refusing native mutations outside allowed account")
        identity_verified = True
        require(request("create-stream", "kinesis", "create-stream", dict(StreamName=prefix, ShardCount=1,
                StreamModeDetails={"StreamMode": "PROVISIONED"})))
        owned["stream"] = True
        require(request("create-group", "logs", "create-log-group", dict(logGroupName=group)))
        owned["group"] = True
        for log_stream in ("alpha", "beta"):
            require(request("create-log-stream-" + log_stream, "logs", "create-log-stream", dict(logGroupName=group, logStreamName=log_stream)))
        for suffix, role_name in roles.items():
            principal = {"AWS": f"arn:aws:iam::{args.account}:root"} if suffix == "caller" else {"Service": "ec2.amazonaws.com" if suffix == "badtrust" else "logs.amazonaws.com"}
            statement = dict(Effect="Allow", Principal=principal, Action="sts:AssumeRole")
            if suffix == "delivery":
                statement["Condition"] = {"ArnLike": {"aws:SourceArn": f"arn:aws:logs:{REGION}:{args.account}:*"}}
            require(request("create-role-" + suffix, "iam", "create-role", dict(RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}))))
            owned["roles"].append(role_name)
        require(role_policy("grant-badtrust-stream", "badtrust"))
        caller_policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["logs:PutSubscriptionFilter"], "Resource": [group_arn, group_arn + ":*", destination_arn]},
            {"Effect": "Allow", "Action": "logs:PutDestination", "Resource": destination_arn},
            {"Effect": "Deny", "Action": "iam:PassRole", "Resource": role_arns["delivery"]}]}
        require(request("grant-caller-no-passrole", "iam", "put-role-policy", dict(RoleName=roles["caller"],
            PolicyName="owned", PolicyDocument=json.dumps(caller_policy))))
        for attempt in range(24):
            summary = require(request("wait-stream-" + str(attempt), "kinesis", "describe-stream-summary", dict(StreamName=prefix)))
            if summary["StreamDescriptionSummary"]["StreamStatus"] == "ACTIVE":
                break
            time.sleep(3)
        else:
            raise RuntimeError("Stream did not become active within bound")
        iterator = require(request("iterator", "kinesis", "get-shard-iterator", dict(StreamName=prefix,
                           ShardId="shardId-000000000000", ShardIteratorType="TRIM_HORIZON")))["ShardIterator"]
        time.sleep(18)
        put("direct-missing-role", roleArn=None)
        put("direct-nonexistent-role", roleArn=role_arns["delivery"] + "-missing")
        put("direct-bad-trust", roleArn=role_arns["badtrust"])
        put("direct-no-stream-permission")
        require(role_policy("grant-delivery-stream"))
        time.sleep(12)
        put("direct-missing-stream", destinationArn=stream_arn + "-missing")
        session = request("assume-no-passrole-caller", "sts", "assume-role", dict(RoleArn=role_arns["caller"], RoleSessionName="owned", DurationSeconds=900))
        if session["code"] == "Success":
            creds = session["output"]["Credentials"]
            restricted_env = dict(env, AWS_ACCESS_KEY_ID=creds["AccessKeyId"], AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"], AWS_SESSION_TOKEN=creds["SessionToken"])
            restricted_env.pop("AWS_PROFILE", None)
            restricted_identity = require(request("restricted-identity", "sts", "get-caller-identity", {}, restricted_env))
            if restricted_identity["Account"] != args.account:
                raise RuntimeError("Restricted identity escaped allowed account")
            request("direct-passrole-denied", "logs", "put-subscription-filter", dict(logGroupName=group,
                filterName="direct", filterPattern="", destinationArn=stream_arn, roleArn=role_arns["delivery"]), restricted_env)
            request("destination-passrole-denied", "logs", "put-destination", dict(destinationName=destination,
                targetArn=stream_arn, roleArn=role_arns["delivery"]), restricted_env)
        response = put("direct-by-log-stream", distribution="ByLogStream")
        if response["code"] != "Success":
            time.sleep(15)
            response = put("direct-by-log-stream-after-propagation", distribution="ByLogStream")
        require(response)
        describe("state-by-log-stream")
        poll("control-direct", attempts=2)
        publish("by-stream-first")
        publish("by-stream-beta", "beta")
        poll("by-stream-first", until="by-stream-first", attempts=12)
        publish("by-stream-second")
        poll("by-stream-second", until="by-stream-second", attempts=12)
        require(put("change-random", distribution="Random"))
        describe("state-random")
        time.sleep(8)
        publish("random-first")
        poll("random-first", until="random-first", attempts=12)
        publish("random-second")
        poll("random-second", until="random-second", attempts=12)
        require(put("change-pattern", distribution="Random", filterPattern='{ $.kind = "keep" }'))
        put("invalid-distribution-preserves-filter", distribution="not-valid")
        describe("state-after-invalid-update")
        time.sleep(8)
        publish("filtered")
        poll("filtered", until="filtered", attempts=12)
        destination_put("destination-missing-role", roleArn=role_arns["delivery"] + "-missing")
        destination_put("destination-bad-trust", roleArn=role_arns["badtrust"])
        destination_put("destination-missing-stream", targetArn=stream_arn + "-missing")
        require(destination_put("destination-create"))
        require(destination_put("destination-second", name=prefix + "-b"))
        second_arn = f"arn:aws:logs:{REGION}:{args.account}:destination:{prefix}-b"
        request("tags-before-update", "logs", "list-tags-for-resource", dict(resourceArn=second_arn))
        destination_put("destination-update-with-tags", name=prefix + "-b", tags={"owned-probe": "update"})
        request("tags-after-update", "logs", "list-tags-for-resource", dict(resourceArn=second_arn))
        destination_put("destination-update-second-tag", name=prefix + "-b", tags={"second": "tag"})
        request("tags-after-second-update", "logs", "list-tags-for-resource", dict(resourceArn=second_arn))
        destination_put("destination-update-no-tags", name=prefix + "-b")
        request("tags-after-omitted-tags", "logs", "list-tags-for-resource", dict(resourceArn=second_arn))
        first = require(request("destinations-page-one", "logs", "describe-destinations", dict(DestinationNamePrefix=prefix, limit=1)))
        if first.get("nextToken"):
            request("destinations-page-two", "logs", "describe-destinations", dict(DestinationNamePrefix=prefix, limit=1, nextToken=first["nextToken"]))
        put("logical-no-policy", filterName="logical", destinationArn=destination_arn, roleArn=None)
        access_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": args.account},
            "Action": "logs:PutSubscriptionFilter", "Resource": destination_arn}]}
        request("destination-invalid-policy", "logs", "put-destination-policy", dict(destinationName=destination, accessPolicy="not-json"))
        require(request("destination-policy", "logs", "put-destination-policy", dict(destinationName=destination, accessPolicy=json.dumps(access_policy))))
        require(destination_put("destination-update-preserves-policy"))
        request("destinations-after-update", "logs", "describe-destinations", dict(DestinationNamePrefix=prefix))
        logical = put("logical-with-policy", filterName="logical", destinationArn=destination_arn, roleArn=None, distribution="Random")
        put("logical-with-role", filterName="logical", destinationArn=destination_arn)
        describe("state-logical")
        if logical["code"] == "Success":
            time.sleep(8)
            publish("logical")
            poll("logical", attempts=12, until="logical")
        access_policy["Statement"][0]["Effect"] = "Deny"
        request("destination-deny-policy", "logs", "put-destination-policy", dict(destinationName=destination, accessPolicy=json.dumps(access_policy)))
        put("logical-explicit-deny", filterName="logical", destinationArn=destination_arn, roleArn=None)
        request("delete-logical-destination", "logs", "delete-destination", dict(destinationName=destination))
        request("delete-logical-destination-again", "logs", "delete-destination", dict(destinationName=destination))
        describe("state-after-destination-delete")
        put("logical-missing-destination", filterName="logical", destinationArn=destination_arn, roleArn=None)
        request("delete-logical-filter", "logs", "delete-subscription-filter", dict(logGroupName=group, filterName="logical"))
        require(role_policy("deny-delivery-stream", effect="Deny"))
        time.sleep(18)
        publish("permission-denied")
        poll("permission-denied", attempts=5)
        put("admission-while-permission-denied", distribution="Random")
        describe("state-permission-denied")
        require(role_policy("restore-delivery-stream"))
        time.sleep(18)
        publish("permission-restored")
        poll("permission-restored", attempts=12)
        describe("state-restored")
        require(request("delete-direct-filter", "logs", "delete-subscription-filter", dict(logGroupName=group, filterName="direct")))
        publish("after-filter-delete")
        poll("after-filter-delete", attempts=3)
        capture["capture_complete"] = True
    except Exception as error:
        capture["failure"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        cleaning = True
        errors = []

        def cleanup(label, service, operation, params):
            try:
                return request(label, service, operation, params)
            except Exception as error:
                errors.append(label + ": " + type(error).__name__)
                return {"code": "TransportError"}

        checks = {}
        if owned["group"]:
            cleanup("cleanup-group", "logs", "delete-log-group", dict(logGroupName=group))
            response = cleanup("verify-group", "logs", "describe-log-groups", dict(logGroupNamePrefix=group))
            checks["group_streams_filters_absent"] = response["code"] == "Success" and not response["output"].get("logGroups")
        for name in owned["destinations"]:
            cleanup("cleanup-destination-" + name, "logs", "delete-destination", dict(destinationName=name))
        if owned["destinations"]:
            response = cleanup("verify-destinations", "logs", "describe-destinations", dict(DestinationNamePrefix=prefix))
            checks["destinations_absent"] = response["code"] == "Success" and not response["output"].get("destinations")
        for name in owned["roles"]:
            cleanup("cleanup-policy-" + name, "iam", "delete-role-policy", dict(RoleName=name, PolicyName="owned"))
            cleanup("cleanup-role-" + name, "iam", "delete-role", dict(RoleName=name))
            response = cleanup("verify-role-" + name, "iam", "get-role", dict(RoleName=name))
            checks[name + "_and_inline_policy_absent"] = response["code"] == "NoSuchEntity"
        if owned["stream"]:
            cleanup("cleanup-stream", "kinesis", "delete-stream", dict(StreamName=prefix, EnforceConsumerDeletion=True))
            for attempt in range(36):
                response = cleanup("verify-stream-" + str(attempt), "kinesis", "describe-stream-summary", dict(StreamName=prefix))
                if response["code"] == "ResourceNotFoundException":
                    break
                time.sleep(3)
            checks["stream_absent"] = response["code"] == "ResourceNotFoundException"
        capture["cleanup"] = {"verified": bool(checks) and all(checks.values()) and not errors,
                              "checks": checks, "transport_errors": errors}
        capture["summary"] = {"message_types": dict(collections.Counter(r["envelope"].get("messageType") for r in capture["records"])),
            "data_partition_keys_by_stream": {name: sorted({r["PartitionKey"] for r in capture["records"]
                if r["envelope"].get("messageType") == "DATA_MESSAGE" and r["envelope"].get("logStream") == name}) for name in ("alpha", "beta")}}
        capture["summary"]["partition_key_checks"] = [
            {"observed_during": row["observed_during"], "message_type": row["envelope"]["messageType"],
             "log_stream": row["envelope"]["logStream"], "partition_key": row["PartitionKey"],
             "equals_md5_owner_colon_group_colon_stream": row["PartitionKey"] == hashlib.md5(
                 ":".join(row["envelope"][key] for key in ("owner", "logGroup", "logStream")).encode()).hexdigest()}
            for row in capture["records"]]
        capture["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save()
        print("CLEANUP_VERIFIED=" + str(capture["cleanup"]["verified"]), flush=True)
    if capture.get("failure") or not capture["cleanup"]["verified"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
