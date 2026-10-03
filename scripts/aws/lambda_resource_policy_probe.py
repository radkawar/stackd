#!/usr/bin/env python3
"""Calibrate function resource policies on one exact-owned, non-invoked Lambda."""
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
    parser.add_argument("--extended", action="store_true")
    parser.add_argument("--validation", action="store_true")
    parser.add_argument("--federation", action="store_true")
    parser.add_argument("--federation-shapes", action="store_true")
    args = parser.parse_args()
    session = boto3.Session(region_name="us-east-1")
    account = session.client("sts").get_caller_identity()["Account"]
    if account != args.account:
        raise RuntimeError("Unauthorized account")
    lam, iam = session.client("lambda"), session.client("iam")
    name = "stackd-next-policy-" + uuid.uuid4().hex[:12]
    arn = "arn:aws:lambda:us-east-1:" + account + ":function:" + name
    result = {"account": account, "region": "us-east-1", "functionArn": arn, "cases": [], "cleanup": []}
    role = None
    created = False

    def call(label, operation, **request):
        case = {"label": label, "operation": operation, "request": request}
        result["cases"].append(case)
        try:
            out = getattr(lam, operation)(**request)
            case["requestId"] = out["ResponseMetadata"]["RequestId"]
            case["output"] = {k: v for k, v in out.items() if k != "ResponseMetadata"}
            return out
        except ClientError as error:
            case["requestId"] = error.response["ResponseMetadata"]["RequestId"]
            case["error"] = error.response["Error"]
            return None

    def put(label, principal="*", condition=None, **changes):
        statement = {"Sid": "replacement", "Effect": "Allow", "Principal": principal, "Action": "lambda:InvokeFunction", "Resource": arn}
        if condition is not None:
            statement["Condition"] = condition
        statement.update(changes)
        return call(label, "put_resource_policy", ResourceArn=arn, Policy=json.dumps({"Version": "2012-10-17", "Statement": [statement]}))

    try:
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        source = io.BytesIO()
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("handler.py", "def handler(event, context):\n return {'policy_probe': True}\n")
        time.sleep(10)
        lam.create_function(FunctionName=name, Runtime="python3.12", Handler="handler.handler", Role=role, Code={"ZipFile": source.getvalue()}, Publish=True, Tags={"stackd-probe": name})
        created = True
        lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 60})
        # No function invocation is part of this policy probe, even if a policy is public.
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=0)
        if args.federation_shapes:
            for label, principal in (
                ("federated-empty-string", {"Federated": ""}),
                ("federated-empty-array", {"Federated": []}),
                ("federated-null", {"Federated": None}),
                ("federated-number", {"Federated": 123}),
                ("federated-object", {"Federated": {"issuer": "accounts.google.com"}}),
                ("federated-mixed-type-array", {"Federated": ["accounts.google.com", 123]}),
                ("principal-empty-object", {}),
            ):
                put(label, principal)
            return
        if args.federation:
            for label, principal in (
                ("federated-google", {"Federated": "accounts.google.com"}),
                ("federated-facebook", {"Federated": "graph.facebook.com"}),
                ("federated-amazon", {"Federated": "www.amazon.com"}),
                ("federated-oidc-absent", {"Federated": "arn:aws:iam::" + account + ":oidc-provider/stackd-nonexistent.example"}),
                ("federated-oidc-other-account", {"Federated": "arn:aws:iam::111111111111:oidc-provider/stackd-nonexistent.example"}),
                ("federated-saml-absent", {"Federated": "arn:aws:iam::" + account + ":saml-provider/stackd-nonexistent"}),
                ("federated-saml-other-account", {"Federated": "arn:aws:iam::111111111111:saml-provider/stackd-nonexistent"}),
                ("federated-arbitrary-domain", {"Federated": "issuer.stackd.invalid"}),
                ("federated-malformed", {"Federated": "not a principal"}),
                ("federated-wildcard", {"Federated": "*"}),
                ("federated-array", {"Federated": ["accounts.google.com", "graph.facebook.com"]}),
                ("federated-mixed-aws", {"AWS": account, "Federated": "accounts.google.com"}),
                ("federated-mixed-aws-service", {"AWS": account, "Service": "s3.amazonaws.com", "Federated": "accounts.google.com"}),
            ):
                accepted = put(label, principal)
                if accepted and label.startswith("federated-mixed"):
                    call("remove-" + label, "remove_permission", FunctionName=name, StatementId="replacement")
            return
        if args.validation:
            statement = {"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": arn}
            for label, changes, omissions in (
                ("not-resource-other", {"NotResource": arn + "-other"}, ["Resource"]),
                ("not-resource-wildcard", {"NotResource": "*"}, ["Resource"]),
                ("not-principal-deny", {"Effect": "Deny", "NotPrincipal": {"AWS": account}}, ["Principal"]),
                ("action-global", {"Action": "*"}, []),
                ("action-unknown-lambda", {"Action": "lambda:NotAnOperation"}, []),
                ("not-action-foreign", {"NotAction": "s3:GetObject"}, ["Action"]),
                ("condition-foreign-service", {"Condition": {"StringEquals": {"s3:prefix": "fixed"}}}, []),
                ("condition-unknown-lambda", {"Condition": {"StringEquals": {"lambda:Unrecognized": "fixed"}}}, []),
                ("duplicate-resources", {"Resource": [arn, arn]}, []),
                ("resource-base-and-version", {"Resource": [arn, arn + ":1"]}, []),
                ("principal-mixed-kinds", {"Principal": {"AWS": account, "Service": "s3.amazonaws.com"}}, []),
                ("principal-federated", {"Principal": {"Federated": "cognito-identity.amazonaws.com"}}, []),
            ):
                candidate = {k: v for k, v in statement.items() if k not in omissions}
                candidate.update(changes)
                call(label, "put_resource_policy", ResourceArn=arn, Policy=json.dumps({"Version": "2012-10-17", "Statement": [candidate]}))
            call("missing-function-delete", "delete_resource_policy", ResourceArn=arn + "-absent")
            return
        if args.extended:
            array_policy = put("array-shapes", {"AWS": [account, "arn:aws:iam::" + account + ":root"]}, {"StringEquals": {"aws:SourceAccount": [account, "111111111111"]}}, Action=["lambda:InvokeFunction", "lambda:GetFunction"], Resource=[arn])
            if array_policy:
                call("add-after-array-policy", "add_permission", FunctionName=name, StatementId="added", Action="lambda:InvokeFunction", Principal=account)
                call("get-after-array-add", "get_resource_policy", ResourceArn=arn)
                call("remove-array-statement", "remove_permission", FunctionName=name, StatementId="replacement")
                call("get-after-array-remove", "get_resource_policy", ResourceArn=arn)
            statement = {"Sid": "single", "Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": arn}
            for label, document in (
                ("single-statement-object", {"Version": "2012-10-17", "Statement": statement}),
                ("empty-statements", {"Version": "2012-10-17", "Statement": []}),
                ("not-principal", {"Version": "2012-10-17", "Statement": [{k: v for k, v in statement.items() if k != "Principal"} | {"NotPrincipal": {"AWS": account}}]}),
                ("not-action", {"Version": "2012-10-17", "Statement": [{k: v for k, v in statement.items() if k != "Action"} | {"NotAction": "lambda:DeleteFunction"}]}),
                ("not-resource", {"Version": "2012-10-17", "Statement": [{k: v for k, v in statement.items() if k != "Resource"} | {"NotResource": arn}]}),
                ("old-version", {"Version": "2008-10-17", "Statement": [statement]}),
                ("no-version", {"Statement": [statement]}),
                ("no-sid", {"Version": "2012-10-17", "Statement": [{k: v for k, v in statement.items() if k != "Sid"}]}),
            ):
                call(label, "put_resource_policy", ResourceArn=arn, Policy=json.dumps(document))
            for label, key in (("unknown-aws-key", "aws:Unrecognized"), ("lambda-key", "lambda:FunctionUrlAuthType"), ("aws-region-key", "aws:RequestedRegion")):
                put(label, condition={"StringEquals": {key: "fixed"}})
            put("foreign-action", {"AWS": account}, Action="s3:GetObject")
            put("resource-array", {"AWS": account}, Resource=[arn])
            put("principal-role-array", {"AWS": [role, "arn:aws:iam::" + account + ":root"]})
            call("delete-before-absent-cas", "delete_resource_policy", ResourceArn=arn)
            call("delete-absent-with-revision", "delete_resource_policy", ResourceArn=arn, RevisionId=str(uuid.uuid4()))
            call("put-absent-with-revision", "put_resource_policy", ResourceArn=arn, Policy=json.dumps({"Version": "2012-10-17", "Statement": [statement]}), RevisionId=str(uuid.uuid4()))
            return
        call("get-absent", "get_resource_policy", ResourceArn=arn)
        call("delete-absent", "delete_resource_policy", ResourceArn=arn)
        call("legacy-add", "add_permission", FunctionName=name, StatementId="legacy", Action="lambda:InvokeFunction", Principal=account)
        previous = call("get-legacy", "get_resource_policy", ResourceArn=arn)
        changed = put("replace-legacy", {"AWS": account})
        call("legacy-get-replacement", "get_policy", FunctionName=name)
        if previous and changed:
            call("stale-put", "put_resource_policy", ResourceArn=arn, Policy=changed["Policy"], RevisionId=previous["RevisionId"])
            call("stale-delete", "delete_resource_policy", ResourceArn=arn, RevisionId=previous["RevisionId"])
            call("cas-delete", "delete_resource_policy", ResourceArn=arn, RevisionId=changed["RevisionId"])
            call("get-deleted", "get_resource_policy", ResourceArn=arn)
        put("wildcard-string")
        put("wildcard-aws", {"AWS": "*"})
        put("fixed-root", {"AWS": "arn:aws:iam::" + account + ":root"})
        put("service-unbounded", {"Service": "s3.amazonaws.com"})
        conditions = [
            ("source-account", "StringEquals", "aws:SourceAccount", account),
            ("source-account-case", "StringEquals", "AWS:SOURCEACCOUNT", account),
            ("source-account-like-fixed", "StringLike", "aws:SourceAccount", account),
            ("source-account-like-wild", "StringLike", "aws:SourceAccount", "*"),
            ("source-account-ifexists", "StringEqualsIfExists", "aws:SourceAccount", account),
            ("source-account-any", "ForAnyValue:StringEquals", "aws:SourceAccount", account),
            ("source-account-all", "ForAllValues:StringEquals", "aws:SourceAccount", account),
            ("source-account-negative", "StringNotEquals", "aws:SourceAccount", account),
            ("source-account-array", "StringEquals", "aws:SourceAccount", [account, "111111111111"]),
            ("source-account-array-wild", "StringEquals", "aws:SourceAccount", [account, "*"]),
            ("source-arn-fixed", "ArnEquals", "aws:SourceArn", "arn:aws:s3:::" + name),
            ("source-arn-like-bounded", "ArnLike", "aws:SourceArn", "arn:aws:s3:::" + name + "/*"),
            ("source-arn-like-unbounded", "ArnLike", "aws:SourceArn", "arn:aws:s3:::*"),
            ("source-arn-account-bound", "ArnLike", "aws:SourceArn", "arn:aws:execute-api:us-east-1:" + account + ":*"),
            ("principal-account", "StringEquals", "aws:PrincipalAccount", account),
            ("principal-org", "StringEquals", "aws:PrincipalOrgID", "o-1234567890"),
            ("principal-arn", "ArnEquals", "aws:PrincipalArn", role),
            ("source-ip", "IpAddress", "aws:SourceIp", "203.0.113.0/24"),
            ("source-ip-public", "IpAddress", "aws:SourceIp", "0.0.0.0/0"),
            ("source-vpc", "StringEquals", "aws:SourceVpc", "vpc-12345678"),
            ("custom-condition", "StringEquals", "custom:key", "fixed"),
        ]
        for label, operator, key, value in conditions:
            put(label, condition={operator: {key: value}})
        put("deny-wildcard", Effect="Deny")
        put("resource-wildcard", {"AWS": account}, Resource="*")
        put("resource-other", {"AWS": account}, Resource=arn + "-other")
        put("action-wildcard", {"AWS": account}, Action="lambda:*")
        for qualifier in ("$LATEST", "1"):
            target = arn + ":" + qualifier
            document = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "qualified", "Effect": "Allow", "Principal": {"AWS": account}, "Action": "lambda:InvokeFunction", "Resource": target}]})
            call("put-qualified-" + qualifier, "put_resource_policy", ResourceArn=target, Policy=document)
            call("get-qualified-" + qualifier, "get_resource_policy", ResourceArn=target)
            call("delete-qualified-" + qualifier, "delete_resource_policy", ResourceArn=target)
    finally:
        if created:
            try:
                lam.delete_function(FunctionName=name)
                result["cleanup"].append("function-and-versions-deleted")
            except Exception as error:
                result["cleanup"].append("function-delete-failed: " + str(error))
        if role:
            try:
                iam.delete_role(RoleName=name)
                result["cleanup"].append("role-deleted")
            except Exception as error:
                result["cleanup"].append("role-delete-failed: " + str(error))
        Path(args.output).write_text(json.dumps(result, indent=2, default=str) + "\n")
        print(json.dumps({"output": args.output, "cleanup": result["cleanup"], "cases": [{"label": c["label"], "error": c.get("error")} for c in result["cases"]]}))
        if any("failed:" in item for item in result["cleanup"]):
            raise RuntimeError("Exact-owned native cleanup failed; inspect retained fixture")


if __name__ == "__main__":
    main()
