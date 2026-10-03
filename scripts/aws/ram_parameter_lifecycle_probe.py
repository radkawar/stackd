#!/usr/bin/env python3
"""Read-only-org discovery plus one exact-owned RAM/SSM lifecycle capture.

Does not enable organization sharing, accept recipient invitations, assume other
account credentials, or touch recipient resources. All parameter values are public
synthetic fixtures; the share and parameter are removed in finally.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import uuid
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError("Refusing to overwrite native evidence")
    config = Config(retries={"max_attempts": 0}, connect_timeout=10, read_timeout=30)
    clients = {name: boto3.client(name, region_name="us-east-1", config=config) for name in ("sts", "organizations", "ssm", "ram")}
    account = clients["sts"].get_caller_identity()["Account"]
    if account != args.account:
        raise ValueError("Unexpected native account")
    recipients = sorted(a["Id"] for page in clients["organizations"].get_paginator("list_accounts").paginate() for a in page["Accounts"] if a["Id"] != account and a.get("State", a.get("Status")) == "ACTIVE")
    if not recipients:
        raise ValueError("No current eligible account; no standing setting changed")
    recipient = recipients[0]
    name = "/stackd-ram-lifecycle-" + uuid.uuid4().hex[:12]
    arn = "arn:aws:ssm:us-east-1:" + account + ":parameter" + name
    evidence = {"schema_version": 1, "captured_at": datetime.now(timezone.utc).isoformat(), "recipient": recipient, "parameter": arn, "calls": [], "cleanup": [], "safety": "No organization mutations, recipient credentials or recipient resources. Exact-owned parameter/share only."}
    share = None
    created = False

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2, default=lambda x: x.isoformat(), sort_keys=True) + "\n")

    def call(label, service, operation, **request):
        try:
            response = getattr(clients[service], operation)(**request)
            metadata = response.pop("ResponseMetadata", {})
            result = {"label": label, "service": service, "operation": operation, "request": request, "code": "Success", "output": response, "request_id": metadata.get("RequestId")}
        except ClientError as error:
            result = {"label": label, "service": service, "operation": operation, "request": request, "code": error.response["Error"]["Code"], "message": error.response["Error"].get("Message"), "request_id": error.response.get("ResponseMetadata", {}).get("RequestId")}
        evidence["calls"].append(result)
        save()
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError(result["label"] + ": " + result["code"])
        return result["output"]

    try:
        require(call("create", "ssm", "put_parameter", Name=name, Value="synthetic-original", Type="String", Tier="Advanced"))
        created = True
        result = require(call("share", "ram", "create_resource_share", name=name[1:], resourceArns=[arn], principals=[recipient], allowExternalPrincipals=True))
        share = result["resourceShare"]["resourceShareArn"]
        deadline = time.monotonic() + 120
        while True:
            result = require(call("association-before-delete", "ram", "get_resource_share_associations", associationType="RESOURCE", resourceShareArns=[share]))
            rows = result.get("resourceShareAssociations", [])
            if rows and all(item["status"] in ("ASSOCIATED", "FAILED") for item in rows):
                if any(item["status"] == "FAILED" for item in rows):
                    raise RuntimeError("Resource association failed; settings left unchanged")
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Resource association did not settle")
            time.sleep(3)
        call("policy-before-delete", "ssm", "get_resource_policies", ResourceArn=arn)
        call("principal-before-delete", "ram", "get_resource_share_associations", associationType="PRINCIPAL", resourceShareArns=[share])
        require(call("delete", "ssm", "delete_parameter", Name=name))
        call("policy-after-delete", "ssm", "get_resource_policies", ResourceArn=arn)
        call("association-after-delete", "ram", "get_resource_share_associations", associationType="RESOURCE", resourceShareArns=[share])
        require(call("recreate", "ssm", "put_parameter", Name=name, Value="synthetic-recreated", Type="String", Tier="Advanced"))
        for index in range(4):
            call("policy-after-recreate-" + str(index), "ssm", "get_resource_policies", ResourceArn=arn)
            call("association-after-recreate-" + str(index), "ram", "get_resource_share_associations", associationType="RESOURCE", resourceShareArns=[share])
            if index != 3:
                time.sleep(10)
        evidence["completed"] = True
    except Exception as error:
        evidence["failure"] = type(error).__name__ + ": " + str(error)
        save()
        raise
    finally:
        for label, service, operation, request in ([('delete-share', 'ram', 'delete_resource_share', {'resourceShareArn': share})] if share else []) + ([('delete-parameter', 'ssm', 'delete_parameter', {'Name': name})] if created else []):
            result = call(label, service, operation, **request)
            evidence["cleanup"].append({"label": label, "code": result["code"]})
        save()
        print(json.dumps({"output": str(output), "completed": evidence.get("completed", False), "cleanup": evidence["cleanup"]}))


if __name__ == "__main__":
    main()
