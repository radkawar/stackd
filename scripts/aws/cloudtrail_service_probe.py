#!/usr/bin/env python3
"""Capture owned management/data events through read/write trails and history.

API cases are ordinary SDK inputs in service_probe_cases.json. Resource lifecycle
stays explicit here; CloudTrail pagination/correlation belongs to cloudtrail_events.
No account defaults, organization settings, existing trails or Lake are changed.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import signal
from string import Template
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudtrail_events import CollectionError, collect_history, collect_s3

REGION = "us-east-1"
CONFIG = Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def document(value):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key.lower() in ("secretaccesskey", "sessiontoken") and item is not None:
                out[key] = "<redacted>"
            elif key.lower() == "accesskeyid" and item:
                out[key] = "<access-key-present>"
            elif key.lower() == "sourceipaddress" and isinstance(item, str):
                try:
                    address = ipaddress.ip_address(item)
                except ValueError:
                    out[key] = item
                else:
                    out[key] = "<ipv" + str(address.version) + "-source-address>"
            else:
                out[key] = document(item)
        return out
    if isinstance(value, (list, tuple)):
        return [document(item) for item in value]
    if isinstance(value, dt.datetime):
        return value.isoformat()
    return value


def expand(value, bindings):
    if isinstance(value, str):
        return Template(value).substitute(bindings)
    if isinstance(value, list):
        return [expand(item, bindings) for item in value]
    if isinstance(value, dict):
        return {key: expand(item, bindings) for key, item in value.items()}
    return value


class Probe:
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.session = boto3.Session(region_name=REGION)
        self.clients = {name: self.session.client(name, config=CONFIG) for name in
                        ("sts", "iam", "s3", "sqs", "cloudtrail", "glue", "athena", "logs")}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != self.account:
            raise RuntimeError("Native probe is restricted to the authorized account")
        if args.cleanup_only or args.collect_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.account or self.data["region"] != REGION:
                raise RuntimeError("Capture ownership differs from the authorized target")
            if args.collect_only and not self.data.get("cleanup", {}).get("complete"):
                raise RuntimeError("Complete owned cleanup before read-only recollection")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            prefix = "stackd-audit-" + uuid.uuid4().hex[:12]
            self.data = {"account": self.account, "region": REGION, "prefix": prefix,
                         "captured_at": now(), "identity": document(identity),
                         "scope": "Owned read/write trails, S3/SQS data and Glue/Athena management; no Lake or standing settings",
                         "cases_source": str(args.cases), "calls": [], "owned": {},
                         "selectors": {}, "delivery": {}, "cleanup": {},
                         "redaction": "Credential secrets removed; access-key presence and IP family retained; identity/session structure unchanged",
                         "documentation": [
                             "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html",
                             "https://docs.aws.amazon.com/glue/latest/dg/monitor-cloudtrail.html",
                             "https://docs.aws.amazon.com/athena/latest/ug/monitor-with-cloudtrail.html"]}
            if args.logs_controls:
                self.data["scope"] = "One owned Logs group, streams, metric filters and scoped resource policy; management history only, no trails, Lake, engine capacity or account policies"
                self.data["documentation"] = ["https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/logging_cw_api_calls_cwl.html"]
        self.bindings = self.data.setdefault("bindings", {})
        self.readers = {}
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(document(self.data), indent=2) + "\n")

    def call(self, label, service, operation, parameters=None, *, caller="owner", category=None, code="Success", required=True):
        client = self.clients[service] if caller == "owner" else self.readers[service]
        row = {"label": label, "service": service, "operation": client.meta.method_to_api_mapping[operation],
               "input": document(parameters or {}), "caller": caller, "started_at": now()}
        if category is not None:
            row["expected_category"] = category
        try:
            output = getattr(client, operation)(**(parameters or {}))
            metadata = output.pop("ResponseMetadata", {})
            if "Body" in output and hasattr(output["Body"], "read"):
                stream = output["Body"]
                try:
                    output["Body"] = stream.read().decode("utf-8")
                finally:
                    stream.close()
            row.update(code="Success", output=document(output))
        except ClientError as error:
            output = {}
            metadata = error.response.get("ResponseMetadata", {})
            row.update(code=error.response["Error"]["Code"], error=error.response["Error"])
        row.update(request_id=metadata.get("RequestId"), http_status=metadata.get("HTTPStatusCode"), finished_at=now())
        self.data["calls"].append(row)
        self.save()
        print(label + ": " + row["code"], flush=True)
        if required and row["code"] != code:
            raise RuntimeError(label + ": expected " + code + ", observed " + row["code"])
        return output

    def setup(self):
        if self.args.logs_controls:
            self.setup_logs()
            return
        prefix, owned = self.data["prefix"], self.data["owned"]
        self.bindings.update(prefix=prefix, account=self.account, data_bucket=prefix + "-data",
                             database=prefix.replace("-", "_"), workgroup=prefix + "-wg",
                             query_token=str(uuid.uuid4()), rejected_query_token=str(uuid.uuid4()))
        owned["buckets"] = []
        for suffix in ("logs", "data"):
            bucket = prefix + "-" + suffix
            self.call("create-" + suffix + "-bucket", "s3", "create_bucket", {"Bucket": bucket})
            owned["buckets"].append(bucket)
            self.save()
        queue = self.call("create-queue", "sqs", "create_queue", {"QueueName": prefix + "-queue"})
        owned["queue_url"] = self.bindings["queue_url"] = queue["QueueUrl"]
        self.save()
        attrs = self.call("queue-arn", "sqs", "get_queue_attributes", {"QueueUrl": queue["QueueUrl"], "AttributeNames": ["QueueArn"]})
        self.bindings["queue_arn"] = attrs["Attributes"]["QueueArn"]
        self.call("create-database", "glue", "create_database", {"DatabaseInput": {"Name": self.bindings["database"]}})
        owned["database"] = self.bindings["database"]
        self.save()
        self.call("create-workgroup", "athena", "create_work_group", {"Name": self.bindings["workgroup"]})
        owned["workgroup"] = self.bindings["workgroup"]
        self.save()
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::" + self.account + ":root"}, "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"]}]}
        role = self.call("create-reader", "iam", "create_role", {"RoleName": prefix + "-reader", "AssumeRolePolicyDocument": json.dumps(trust)})["Role"]
        owned["role"] = role["RoleName"]
        self.save()
        permissions = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::" + self.bindings["data_bucket"] + "/public.txt"},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": self.bindings["queue_arn"]},
            {"Effect": "Allow", "Action": "glue:GetDatabase", "Resource": ["arn:aws:glue:" + REGION + ":" + self.account + ":catalog", "arn:aws:glue:" + REGION + ":" + self.account + ":database/" + self.bindings["database"]]},
            {"Effect": "Allow", "Action": "athena:GetWorkGroup", "Resource": "arn:aws:athena:" + REGION + ":" + self.account + ":workgroup/" + self.bindings["workgroup"]}]}
        self.call("reader-policy", "iam", "put_role_policy", {"RoleName": role["RoleName"], "PolicyName": "owned", "PolicyDocument": json.dumps(permissions)})
        for attempt in range(12):
            result = self.call("assume-reader-" + str(attempt), "sts", "assume_role", {"RoleArn": role["Arn"], "RoleSessionName": "audit-reader", "SourceIdentity": prefix, "DurationSeconds": 3600}, required=False)
            if result:
                credentials = result["Credentials"]
                session = boto3.Session(region_name=REGION, aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
                self.readers = {name: session.client(name, config=CONFIG) for name in ("s3", "sqs", "glue", "athena")}
                break
            if self.data["calls"][-1]["code"] != "AccessDenied":
                raise RuntimeError("Unexpected reader assumption failure")
            time.sleep(5)
        else:
            raise RuntimeError("Owned reader trust did not become available")
        for attempt in range(12):
            if self.call("reader-ready-" + str(attempt), "glue", "get_database", {"Name": self.bindings["database"]}, caller="reader", required=False):
                break
            if self.data["calls"][-1]["code"] != "AccessDeniedException":
                raise RuntimeError("Unexpected reader permission failure")
            time.sleep(5)
        else:
            raise RuntimeError("Owned reader permissions did not become available")
        trail_arns = ["arn:aws:cloudtrail:" + REGION + ":" + self.account + ":trail/" + prefix + "-" + mode for mode in ("read", "write")]
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::" + prefix + "-logs", "Condition": {"StringEquals": {"aws:SourceArn": trail_arns}}},
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject", "Resource": ["arn:aws:s3:::" + prefix + "-logs/" + mode + "/AWSLogs/" + self.account + "/*" for mode in ("read", "write")], "Condition": {"StringEquals": {"aws:SourceArn": trail_arns, "s3:x-amz-acl": "bucket-owner-full-control"}}}]}
        self.call("log-bucket-policy", "s3", "put_bucket_policy", {"Bucket": prefix + "-logs", "Policy": json.dumps(policy)})
        owned["trails"] = []
        for mode, read_only in (("read", "true"), ("write", "false")):
            name = prefix + "-" + mode
            self.call("create-" + mode + "-trail", "cloudtrail", "create_trail", {"Name": name, "S3BucketName": prefix + "-logs", "S3KeyPrefix": mode, "IsMultiRegionTrail": False, "IncludeGlobalServiceEvents": False})
            owned["trails"].append(name)
            self.save()
            selectors = [{"Name": "management", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}, {"Field": "readOnly", "Equals": [read_only]}]}]
            for name_type, resource_type, operator, resource in (("objects", "AWS::S3::Object", "StartsWith", "arn:aws:s3:::" + self.bindings["data_bucket"] + "/"), ("queue", "AWS::SQS::Queue", "Equals", self.bindings["queue_arn"])):
                selectors.append({"Name": name_type, "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "readOnly", "Equals": [read_only]}, {"Field": "resources.type", "Equals": [resource_type]}, {"Field": "resources.ARN", operator: [resource]}]})
            self.call("select-" + mode, "cloudtrail", "put_event_selectors", {"TrailName": name, "AdvancedEventSelectors": selectors})
            self.data["selectors"][mode] = self.call("get-" + mode + "-selectors", "cloudtrail", "get_event_selectors", {"TrailName": name})
            self.call("start-" + mode, "cloudtrail", "start_logging", {"Name": name})
        self.await_delivery_readiness()

    def setup_logs(self):
        prefix = self.data["prefix"]
        group = "/stackd/" + prefix
        self.bindings.update(prefix=prefix, account=self.account, region=REGION, group=group,
                             group_arn="arn:aws:logs:" + REGION + ":" + self.account + ":log-group:" + group,
                             namespace="Stackd/Audit/" + prefix)
        self.data["owned"]["log_group"] = group
        self.save()
        credentials = self.call("federated-reader", "sts", "get_federation_token", {
            "Name": prefix, "DurationSeconds": 900,
            "Policy": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Deny", "Action": "logs:*", "Resource": "*"}]})})["Credentials"]
        session = boto3.Session(region_name=REGION, aws_access_key_id=credentials["AccessKeyId"],
                                aws_secret_access_key=credentials["SecretAccessKey"],
                                aws_session_token=credentials["SessionToken"])
        self.readers["logs"] = session.client("logs", config=CONFIG)

    def await_delivery_readiness(self):
        # StartLogging plus a fixed sleep did not capture any workload IDs in
        # the first campaign. Observe owned data delivery before issuing cases.
        deadline = time.monotonic() + self.args.wait_seconds
        requests = {}
        attempt = 0
        while True:
            for mode, operation, extra in (("write", "put_object", {"Body": "synthetic trail readiness\n"}), ("read", "get_object", {})):
                label = "trail-ready-" + mode + "-" + str(attempt)
                self.call(label, "s3", operation, {"Bucket": self.bindings["data_bucket"], "Key": "trail-readiness.txt", **extra})
                requests[self.data["calls"][-1]["request_id"]] = label
            self.collect_delivery(requests)
            ready = {}
            for mode, capture in self.data["delivery"].items():
                ready[mode] = any(row["call_label"] and row["call_label"].startswith("trail-ready-" + mode + "-")
                                  and row["event"].get("eventCategory") == "Data"
                                  and row["event"].get("readOnly") == (mode == "read")
                                  for row in capture["events"])
            if ready.get("read") and ready.get("write"):
                self.data["delivery_ready_at"] = now()
                self.save()
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned read/write data delivery was not observed; workload was not run")
            attempt += 1
            time.sleep(min(30, max(0, deadline - time.monotonic())))

    def collect_delivery(self, requests, related=None):
        s3 = self.clients["s3"]
        for mode in ("read", "write"):
            try:
                self.data["delivery"][mode] = collect_s3(
                    lambda p: s3.list_objects_v2(**p), lambda p: s3.get_object(**p), requests,
                    bucket=self.data["prefix"] + "-logs", prefix=mode + "/", related=related,
                    previous=self.data["delivery"].get(mode))
            except CollectionError as error:
                self.data["delivery"][mode] = error.result
                self.save()
                raise
            self.save()

    def execute(self):
        cases = json.loads(self.args.cases.read_text())["cases"]
        self.data["case_definitions"] = cases
        for case in cases:
            result = self.call(case["label"], case["service"], case["operation"], expand(case["input"], self.bindings), caller=case.get("caller", "owner"), category=case["category"], code=case.get("code", "Success"), required=case.get("required", True))
            for name, path in case.get("bind", {}).items():
                value = result
                for part in path.split("."):
                    value = value[int(part)] if isinstance(value, list) else value[part]
                self.bindings[name] = value
            self.save()
        if self.args.logs_controls:
            self.data["workload_finished_at"] = now()
            self.save()
            return
        for attempt in range(30):
            query = self.call("query-state-" + str(attempt), "athena", "get_query_execution", {"QueryExecutionId": self.bindings["query_id"]}, category="Management")["QueryExecution"]
            state = query["Status"]["State"]
            if state == "SUCCEEDED":
                break
            if state in ("FAILED", "CANCELLED"):
                raise RuntimeError("Owned native query did not succeed: " + json.dumps(query["Status"]))
            time.sleep(2)
        else:
            raise RuntimeError("Owned query readiness bound expired")
        result = self.call("query-results", "athena", "get_query_results", {"QueryExecutionId": self.bindings["query_id"]}, category="Management")
        if [[cell.get("VarCharValue") for cell in row["Data"]] for row in result["ResultSet"]["Rows"]] != [["answer"], ["7"]]:
            raise RuntimeError("Native query returned unexpected actual rows")
        self.data["workload_finished_at"] = now()
        self.save()

    def collect(self):
        if self.args.logs_controls:
            self.collect_management(("logs.amazonaws.com",), self.args.wait_seconds)
            return
        requests = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("expected_category") and row.get("request_id")}
        deadline = time.monotonic() + self.args.wait_seconds
        def related(event):
            request = event.get("requestParameters") or {}
            return request.get("bucketName") == self.bindings["data_bucket"]
        while True:
            self.collect_delivery(requests, related)
            found = {row["event"].get("requestID") for capture in self.data["delivery"].values() for row in capture["events"]}
            missing = sorted(set(requests) - found)
            self.data["delivery_missing_calls"] = [requests[key] for key in missing]
            self.save()
            if not missing or time.monotonic() >= deadline:
                break
            time.sleep(min(30, max(0, deadline - time.monotonic())))
        self.collect_management(("glue.amazonaws.com", "athena.amazonaws.com", "sqs.amazonaws.com"))

    def collect_management(self, sources, wait_seconds=0):
        management = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("expected_category") == "Management" and row.get("request_id")}
        trails = self.clients["cloudtrail"]
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                self.data["history"] = collect_history(
                    lambda p: trails.lookup_events(**p), management,
                    start_time=self.data["captured_at"], end_time=self.data["workload_finished_at"],
                    event_sources=sources, previous=self.data.get("history"))
            except CollectionError as error:
                self.data["history"] = error.result
                self.save()
                raise
            self.data["collection_boundary"] = "Positive exact-request records; missing records are not observed within bounds, not proof of native absence. Log order is not API order."
            self.save()
            if not self.data["history"]["missing_calls"] or time.monotonic() >= deadline:
                return
            time.sleep(min(30, max(0, deadline - time.monotonic())))

    def cleanup(self):
        owned = self.data["owned"]
        errors = []
        # Collection can keep the control-plane connection idle for minutes.
        # Use a fresh provider connection for owned deletion, not hidden retries.
        self.clients["cloudtrail"].close()
        self.clients["cloudtrail"] = self.session.client("cloudtrail", config=CONFIG)
        def remove(label, service, method, parameters, absent=()):
            try:
                self.call(label, service, method, parameters, required=False)
                code = self.data["calls"][-1]["code"]
                if code != "Success" and code not in absent:
                    errors.append(label + ": " + code)
            except Exception as error:
                errors.append(label + ": " + str(error))
        if owned.get("log_group"):
            remove("cleanup-log-group", "logs", "delete_log_group", {"logGroupName": owned["log_group"]}, ("ResourceNotFoundException",))
            result = self.call("verify-log-group-absent", "logs", "describe_log_groups", {"logGroupNamePrefix": owned["log_group"]})
            if any(group["logGroupName"] == owned["log_group"] for group in result["logGroups"]):
                errors.append("owned log group remains after deletion")
        for trail in owned.get("trails", []):
            remove("cleanup-delete-" + trail, "cloudtrail", "delete_trail", {"Name": trail}, ("TrailNotFoundException",))
        if self.bindings.get("query_id"):
            remove("cleanup-query", "athena", "stop_query_execution", {"QueryExecutionId": self.bindings["query_id"]})
        if owned.get("workgroup"):
            remove("cleanup-workgroup", "athena", "delete_work_group", {"WorkGroup": owned["workgroup"], "RecursiveDeleteOption": True})
        if owned.get("database"):
            remove("cleanup-database", "glue", "delete_database", {"Name": owned["database"]}, ("EntityNotFoundException",))
        if owned.get("queue_url"):
            remove("cleanup-queue", "sqs", "delete_queue", {"QueueUrl": owned["queue_url"]}, ("AWS.SimpleQueueService.NonExistentQueue",))
        if owned.get("role"):
            remove("cleanup-policy", "iam", "delete_role_policy", {"RoleName": owned["role"], "PolicyName": "owned"}, ("NoSuchEntity",))
            remove("cleanup-role", "iam", "delete_role", {"RoleName": owned["role"]}, ("NoSuchEntity",))
        for bucket in owned.get("buckets", []):
            try:
                for page in self.clients["s3"].get_paginator("list_objects_v2").paginate(Bucket=bucket):
                    if page.get("Contents"):
                        result = self.call("cleanup-objects-" + bucket, "s3", "delete_objects", {"Bucket": bucket, "Delete": {"Objects": [{"Key": item["Key"]} for item in page["Contents"]]}})
                        if result.get("Errors"):
                            errors.append(bucket + ": " + json.dumps(result["Errors"]))
            except ClientError as error:
                if error.response["Error"]["Code"] != "NoSuchBucket":
                    errors.append(bucket + ": " + str(error))
            remove("cleanup-bucket-" + bucket, "s3", "delete_bucket", {"Bucket": bucket}, ("NoSuchBucket",))
        self.data["cleanup"] = {"finished_at": now(), "errors": errors, "complete": not errors}
        self.save()
        if errors:
            raise RuntimeError("Owned cleanup incomplete: " + "; ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--logs-controls", action="store_true",
                        help="Capture owned Logs management controls without provisioning trails or data planes")
    parser.add_argument("--wait-seconds", type=int, default=900)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--collect-only", action="store_true",
                        help="Only recollect Logs management history from an already cleaned capture")
    args = parser.parse_args()
    if args.cases is None:
        args.cases = Path("testdata/cloudtrail/audit/logs_probe_cases.json" if args.logs_controls else "testdata/cloudtrail/audit/service_probe_cases.json")
    if args.wait_seconds < 0:
        parser.error("wait-seconds must not be negative")
    if args.collect_only and (not args.logs_controls or args.cleanup_only):
        parser.error("collect-only requires logs-controls and cannot be combined with cleanup-only")
    os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
    def interrupted(signum, frame):
        raise RuntimeError("Interrupted; entering owned cleanup")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    probe = Probe(args)
    try:
        if args.collect_only:
            probe.data.setdefault("workload_finished_at", max(row["finished_at"] for row in probe.data["calls"]))
            probe.collect()
        elif not args.cleanup_only:
            probe.setup()
            probe.execute()
            probe.collect()
    except Exception as error:
        probe.data["failure"] = str(error)
        probe.save()
        raise
    finally:
        if not args.collect_only:
            probe.cleanup()


if __name__ == "__main__":
    main()
