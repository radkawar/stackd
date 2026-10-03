#!/usr/bin/env python3
"""Calibrate RemovePermission's lambda:Principal context with exact-owned resources."""
import argparse
import io
import json
from pathlib import Path
import time
import uuid
import zipfile

import boto3
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", required=True)
    parser.add_argument("--case", action="append", help="Run only the named case; repeatable")
    args = parser.parse_args()
    session = boto3.Session(region_name="us-east-1")
    sts, iam, lam = (session.client(service) for service in ("sts", "iam", "lambda"))
    identity = sts.get_caller_identity()
    account = identity["Account"]
    if account != args.account:
        raise RuntimeError("Unauthorized account")
    name = "stackd-next-policy-context-" + uuid.uuid4().hex[:10]
    arn = "arn:aws:lambda:us-east-1:" + account + ":function:" + name
    root = "arn:aws:iam::" + account + ":root"
    evidence = {"account": account, "functionArn": arn, "cases": [], "cleanup": []}
    role = None
    created = inline = False
    try:
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com", "AWS": identity["Arn"]}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        iam.put_role_policy(RoleName=name, PolicyName="owned-remove", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "lambda:RemovePermission", "Resource": arn}]}))
        inline = True
        source = io.BytesIO()
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("handler.py", "def handler(event, context):\n return None\n")
        time.sleep(10)
        lam.create_function(FunctionName=name, Role=role, Runtime="python3.12", Handler="handler.handler", Code={"ZipFile": source.getvalue()})
        created = True
        lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 60})
        cases = [
            ("array-empty-context", "Allow", "Principal", {"AWS": [root, role]}, "StringEquals", ""),
            ("mixed-kind-empty-context", "Allow", "Principal", {"AWS": root, "Service": "s3.amazonaws.com"}, "StringEquals", ""),
            ("mixed-kind-service-context", "Allow", "Principal", {"AWS": root, "Service": "s3.amazonaws.com"}, "StringEquals", "s3.amazonaws.com"),
            ("mixed-kind-account-context", "Allow", "Principal", {"AWS": root, "Service": "s3.amazonaws.com"}, "StringEquals", root),
            ("mixed-kind-any-service-context", "Allow", "Principal", {"AWS": root, "Service": "s3.amazonaws.com"}, "ForAnyValue:StringEquals", "s3.amazonaws.com"),
            ("mixed-kind-all-context", "Allow", "Principal", {"AWS": root, "Service": "s3.amazonaws.com"}, "ForAllValues:StringEquals", [root, "s3.amazonaws.com"]),
            ("mixed-kind-missing-context", "Allow", "Principal", {"AWS": root, "Service": "s3.amazonaws.com"}, "Null", "true"),
            ("mixed-kind-any-account-context", "Allow", "Principal", {"AWS": root, "Service": "s3.amazonaws.com"}, "ForAnyValue:StringEquals", root),
            ("duplicate-account-canonical-context", "Allow", "Principal", {"AWS": [account, root]}, "StringEquals", root),
            ("not-principal-empty-context", "Deny", "NotPrincipal", {"AWS": root}, "StringEquals", ""),
            ("not-principal-missing-context", "Deny", "NotPrincipal", {"AWS": root}, "Null", "true"),
            ("federated-domain-context", "Allow", "Principal", {"Federated": "cognito-identity.amazonaws.com"}, "StringEquals", "cognito-identity.amazonaws.com"),
            ("federated-empty-context", "Allow", "Principal", {"Federated": "cognito-identity.amazonaws.com"}, "StringEquals", ""),
        ]
        for label, effect, selector, principal, operator, value in cases:
            if args.case and label not in args.case:
                continue
            statement = {"Sid": "multiple", "Effect": effect, selector: principal, "Action": "lambda:InvokeFunction", "Resource": arn}
            lam.put_resource_policy(ResourceArn=arn, Policy=json.dumps({"Version": "2012-10-17", "Statement": [statement]}))
            condition = {operator: {"lambda:Principal": value}}
            restriction = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "lambda:RemovePermission", "Resource": arn, "Condition": condition}]}
            credentials = sts.assume_role(RoleArn=role, RoleSessionName="owned-" + uuid.uuid4().hex[:8], DurationSeconds=900, Policy=json.dumps(restriction))["Credentials"]
            limited = boto3.client("lambda", region_name="us-east-1", aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
            case = {"label": label, "statement": statement, "condition": condition}
            evidence["cases"].append(case)
            try:
                reply = limited.remove_permission(FunctionName=name, StatementId="multiple")
                case["requestId"] = reply["ResponseMetadata"]["RequestId"]
                case["outcome"] = "allowed"
            except ClientError as error:
                case["requestId"] = error.response["ResponseMetadata"]["RequestId"]
                case["error"] = error.response["Error"]["Code"]
    finally:
        if created:
            lam.delete_function(FunctionName=name)
            evidence["cleanup"].append("function-deleted")
        if inline:
            iam.delete_role_policy(RoleName=name, PolicyName="owned-remove")
            evidence["cleanup"].append("role-inline-policy-deleted")
        if role:
            iam.delete_role(RoleName=name)
            evidence["cleanup"].append("role-deleted")
        Path(args.output).write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({"cases": [{"label": case["label"], "outcome": case.get("outcome", case.get("error"))} for case in evidence["cases"]], "cleanup": evidence["cleanup"]}))


if __name__ == "__main__":
    main()
