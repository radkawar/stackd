#!/usr/bin/env python3
"""Capture exact-owned, free Cloud Control lifecycle behavior in the authorized account."""
import argparse
import json
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    config = Config(retries={"max_attempts": 0})
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts", config=config).get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("unexpected native account")
    client = session.client("cloudcontrol", config=config)
    logs = session.client("logs", config=config)
    name = "stackd-next-cfn-" + uuid.uuid4().hex[:12]
    report = {"account": identity["Account"], "region": "us-east-1", "name": name,
        "sources": ["https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-manage-requests.html", "https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-update.html"], "calls": [], "cleanup": {}}
    output = Path(args.output)

    def save():
        output.write_text(json.dumps(report, indent=2, default=str) + "\n")

    def call(label, method, **request):
        row = {"label": label, "operation": method.__name__, "request": request}
        try:
            result = method(**request)
            row.update(code="Success", output=result)
        except ClientError as error:
            result = None
            row.update(code=error.response["Error"]["Code"], output=error.response)
        report["calls"].append(row)
        save()
        return result

    def wait(label, result):
        if not result:
            return None
        token = result["ProgressEvent"]["RequestToken"]
        until = time.monotonic() + 180
        while time.monotonic() < until:
            result = call(label, client.get_resource_request_status, RequestToken=token)
            if result["ProgressEvent"]["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
                return result
            time.sleep(2)
        raise TimeoutError(label)

    typ = {"TypeName": "AWS::Logs::LogGroup"}
    ref = dict(typ, Identifier=name)
    token = str(uuid.uuid4())
    try:
        desired = json.dumps({"LogGroupName": name, "RetentionInDays": 1, "Tags": [{"Key": "owner", "Value": name}]})
        created = call("create", client.create_resource, **typ, DesiredState=desired, ClientToken=token)
        wait("create-progress", created)
        call("create-idempotent", client.create_resource, **typ, DesiredState=desired, ClientToken=token)
        call("token-conflict", client.create_resource, **typ, DesiredState=json.dumps({"LogGroupName": name + "-conflict"}), ClientToken=token)
        call("read", client.get_resource, **ref)
        call("list", client.list_resources, **typ, MaxResults=1)
        changed = call("update", client.update_resource, **ref, PatchDocument=json.dumps([
            {"op": "test", "path": "/RetentionInDays", "value": 1},
            {"op": "replace", "path": "/RetentionInDays", "value": 3}]))
        wait("update-progress", changed)
        call("read-updated", client.get_resource, **ref)
        wait("immutable-progress", call("immutable", client.update_resource, **ref,
            PatchDocument=json.dumps([{"op": "replace", "path": "/LogGroupName", "value": name + "-renamed"}])))
        wait("readonly-progress", call("readonly", client.update_resource, **ref,
            PatchDocument=json.dumps([{"op": "add", "path": "/Arn", "value": "not-an-arn"}])))
        wait("test-failure-progress", call("test-failure", client.update_resource, **ref,
            PatchDocument=json.dumps([{"op": "test", "path": "/RetentionInDays", "value": 99}])))
        wait("duplicate-progress", call("duplicate", client.create_resource, **typ, DesiredState=desired))
        wait("missing-progress", call("missing-delete", client.delete_resource, **typ, Identifier=name + "-missing"))
        if created:
            call("cancel-complete", client.cancel_resource_request, RequestToken=created["ProgressEvent"]["RequestToken"])
        call("requests", client.list_resource_requests, ResourceRequestStatusFilter={"Operations": ["CREATE"], "OperationStatuses": ["SUCCESS"]})
        deleted = call("delete", client.delete_resource, **ref)
        wait("delete-progress", deleted)
        call("read-deleted", client.get_resource, **ref)
    finally:
        try:
            logs.delete_log_group(logGroupName=name)
        except logs.exceptions.ResourceNotFoundException:
            pass
        remaining = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        report["cleanup"] = {"complete": not remaining, "remaining": [v["logGroupName"] for v in remaining]}
        save()
        if remaining:
            raise RuntimeError("owned native log groups remain")
    print(json.dumps({"name": name, "calls": len(report["calls"]), "cleanup": report["cleanup"]}))


if __name__ == "__main__":
    main()
