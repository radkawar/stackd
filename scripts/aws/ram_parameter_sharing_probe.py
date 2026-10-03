#!/usr/bin/env python3
"""Capture/replay exact-owned RAM parameter access, permission switch and revocation.

Only synthetic values and owned IAM/SSM/RAM resources are mutated. No organization
settings or policies are changed. A loopback endpoint uses explicit local root
credentials; native credentials are never forwarded to a custom endpoint.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from urllib.parse import urlparse
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--endpoint")
    parser.add_argument("--account", required=True)
    parser.add_argument("--consumer-account", help="Loopback-only second account for cross-account replay")
    args = parser.parse_args()
    path = Path(args.output).resolve()
    if path.exists():
        raise ValueError("Refusing to overwrite evidence")
    options = {"region_name": "us-east-1", "config": Config(retries={"max_attempts": 0}, connect_timeout=10, read_timeout=30)}
    if args.endpoint:
        if urlparse(args.endpoint).hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Local endpoint must be loopback")
        options.update(endpoint_url=args.endpoint, aws_access_key_id=args.account, aws_secret_access_key="test")
    if args.consumer_account and not args.endpoint:
        raise ValueError("Cross-account credentials are accepted only for loopback replay")
    session = boto3.Session()
    sts = session.client("sts", **options)
    if sts.get_caller_identity()["Account"] != args.account:
        raise ValueError("Unexpected native account")
    clients = {name: session.client(name, **options) for name in ("ssm", "ram", "iam")}
    consumer_account = args.consumer_account or args.account
    if consumer_account != args.account:
        recipient_options = dict(options, aws_access_key_id=consumer_account)
        clients["iam"] = session.client("iam", **recipient_options)
        clients["recipient_ram"] = session.client("ram", **recipient_options)
    prefix = "stackd-ram-parameter-" + uuid.uuid4().hex[:12]
    parameter = "/" + prefix
    arn = "arn:aws:ssm:us-east-1:" + args.account + ":parameter/" + prefix
    evidence = {"schema_version": 1, "captured_at": datetime.now(timezone.utc).isoformat(), "endpoint": args.endpoint or "native AWS", "account": args.account, "region": "us-east-1", "prefix": prefix, "calls": [], "cleanup": [], "sources": ["https://docs.aws.amazon.com/ram/latest/userguide/shareable.html", "https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-shared-parameters.html"]}
    owned_user = owned_parameter = False
    key_id = None
    share_arn = None

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence, indent=2, default=lambda value: value.isoformat(), sort_keys=True) + "\n")

    def call(label, service, operation, **kwargs):
        try:
            result = getattr(clients[service], operation)(**kwargs)
            metadata = result.pop("ResponseMetadata", {})
            row = {"label": label, "service": service, "operation": operation, "request": kwargs, "code": "Success", "output": result, "request_id": metadata.get("RequestId")}
        except ClientError as error:
            row = {"label": label, "service": service, "operation": operation, "request": kwargs, "code": error.response["Error"]["Code"], "message": error.response["Error"].get("Message"), "request_id": error.response.get("ResponseMetadata", {}).get("RequestId")}
        evidence["calls"].append(row)
        save()
        return row

    def require(row):
        if row["code"] != "Success":
            raise RuntimeError(row["label"] + ": " + row["code"])
        return row["output"]

    def read_consumer(label, history=False):
        operation = "get_parameter_history" if history else "get_parameter"
        try:
            out = getattr(consumer, operation)(Name=arn)
            meta = out.pop("ResponseMetadata", {})
            row = {"label": label, "operation": operation, "code": "Success", "output": out, "request_id": meta.get("RequestId")}
        except ClientError as error:
            row = {"label": label, "operation": operation, "code": error.response["Error"]["Code"], "request_id": error.response.get("ResponseMetadata", {}).get("RequestId")}
        evidence["calls"].append(row)
        save()
        return row

    def cleanup(label, fn):
        try:
            fn()
            evidence["cleanup"].append({"label": label, "code": "Success"})
        except ClientError as error:
            evidence["cleanup"].append({"label": label, "code": error.response["Error"]["Code"]})
        save()

    save()
    try:
        user = require(call("create-user", "iam", "create_user", UserName=prefix))["User"]
        owned_user = True
        if consumer_account != args.account:
            policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["ssm:GetParameter", "ssm:GetParameterHistory"], "Resource": arn}]})
            require(call("consumer-identity-policy", "iam", "put_user_policy", UserName=prefix, PolicyName=prefix, PolicyDocument=policy))
        # Credentials are used only in memory, never copied to fixture/log output.
        key = clients["iam"].create_access_key(UserName=prefix)["AccessKey"]
        key_id = key["AccessKeyId"]
        consumer_options = dict(options, aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"])
        consumer = session.client("ssm", **consumer_options)
        require(call("put-advanced", "ssm", "put_parameter", Name=parameter, Value="ram-shared-value-v1", Type="String", Tier="Advanced"))
        owned_parameter = True
        require(call("overwrite-advanced", "ssm", "put_parameter", Name=parameter, Value="ram-shared-value-v2", Type="String", Tier="Advanced", Overwrite=True))
        read_consumer("before-sharing")
        share = require(call("create-share", "ram", "create_resource_share", name=prefix, resourceArns=[arn], principals=[user["Arn"]], permissionArns=["arn:aws:ram::aws:permission/AWSRAMDefaultPermissionSSMParameterReadOnly"], allowExternalPrincipals=True))
        share_arn = share["resourceShare"]["resourceShareArn"]
        deadline = time.monotonic() + (10 if args.endpoint else 180)
        while True:
            association = require(call("association", "ram", "get_resource_share_associations", associationType="RESOURCE", resourceShareArns=[share_arn]))
            failed = [item for item in association.get("resourceShareAssociations", []) if item["status"] == "FAILED"]
            if failed:
                evidence["association_failure"] = failed
                evidence["completed"] = consumer_account == args.account and all(item.get("statusMessage") == "Resources of specified type cannot be shared with the owning account." for item in failed)
                if not evidence["completed"]:
                    raise RuntimeError("Owned resource association failed")
                return
            if association.get("resourceShareAssociations") and all(x["status"] == "ASSOCIATED" for x in association["resourceShareAssociations"]):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned resource association did not complete")
            time.sleep(2)
        if consumer_account != args.account:
            invitations = require(call("recipient-invitations", "recipient_ram", "get_resource_share_invitations", resourceShareArns=[share_arn]))["resourceShareInvitations"]
            if len(invitations) != 1:
                raise RuntimeError("Expected one exact share invitation")
            require(call("accept-invitation", "recipient_ram", "accept_resource_share_invitation", resourceShareInvitationArn=invitations[0]["resourceShareInvitationArn"]))
        call("owner-resource-policy", "ssm", "get_resource_policies", ResourceArn=arn)
        shared = require(read_consumer("shared-direct-principal"))
        if shared["Parameter"]["Value"] != "ram-shared-value-v2":
            raise RuntimeError("Shared parameter returned incorrect bytes")
        if read_consumer("default-history-denied", history=True)["code"] != "AccessDeniedException":
            raise RuntimeError("Default permission must not grant historical values")
        require(call("replace-permission", "ram", "associate_resource_share_permission", resourceShareArn=share_arn, permissionArn="arn:aws:ram::aws:permission/AWSRAMPermissionSSMParameterReadOnlyWithHistory", replace=True))
        history = require(read_consumer("history-after-replace", history=True))
        if [item["Value"] for item in history["Parameters"]] != ["ram-shared-value-v1", "ram-shared-value-v2"]:
            raise RuntimeError("History permission did not expose original versions")
        require(call("disassociate-principal", "ram", "disassociate_resource_share", resourceShareArn=share_arn, principals=[user["Arn"]]))
        if read_consumer("after-revoke")["code"] != "AccessDeniedException":
            raise RuntimeError("Principal removal did not revoke shared access")
        evidence["completed"] = True
    except Exception as error:
        evidence["failure"] = type(error).__name__ + ": " + str(error)
        save()
        raise
    finally:
        if share_arn:
            cleanup("delete-share", lambda: clients["ram"].delete_resource_share(resourceShareArn=share_arn))
        if owned_parameter:
            cleanup("delete-parameter", lambda: clients["ssm"].delete_parameter(Name=parameter))
        if key_id:
            cleanup("delete-user-access-key", lambda: clients["iam"].delete_access_key(UserName=prefix, AccessKeyId=key_id))
        if owned_user:
            if consumer_account != args.account:
                cleanup("delete-consumer-policy", lambda: clients["iam"].delete_user_policy(UserName=prefix, PolicyName=prefix))
            cleanup("delete-user", lambda: clients["iam"].delete_user(UserName=prefix))
        print(json.dumps({"output": str(path), "completed": evidence.get("completed", False), "cleanup": evidence["cleanup"]}))


if __name__ == "__main__":
    main()
