#!/usr/bin/env python3
"""Probe template reuse and underlying permissions using only owned IAM resources."""

import datetime
import json
import os
import pathlib
import re
import time
import uuid

from aws_cli import call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    account = require_account(probe_args.account)["Account"]
    prefix = "stackd-acquire-" + uuid.uuid4().hex[:12]
    template = "arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1"
    policy = "arn:aws:iam::aws:policy/PowerUserAccess"
    roles = set()
    results = {}
    key = None
    user = False

    def observe(label, operation, parameters, env=None):
        try:
            result = call("iam", operation, parameters, env)
            results[label] = {"result": result}
            print(label + ": success", flush=True)
            return result
        except RuntimeError as error:
            code = re.search(r"\(([^)]+)\) when calling", str(error))
            if code is None:
                raise
            results[label] = {"error": {"code": code[1], "message": str(error)}}
            print(label + ": " + code[1], flush=True)
            return None

    def acquire(label, suffix, service="lambda.amazonaws.com", env=None):
        name = prefix + "-" + suffix
        roles.add(name)
        return observe(label, "acquire-role", {"TemplateArn": template, "ReplacementValues": {
            "RoleName": {"Values": [name]}, "AWSServiceName": {"Values": [service]},
        }}, env)

    def mutate(operation, suffix, **parameters):
        return call("iam", operation, {"RoleName": prefix + "-" + suffix, **parameters})

    try:
        acquire("created", "edited")
        mutate("update-role", "edited", MaxSessionDuration=7200)
        acquire("duration_changed", "edited")
        mutate("update-role", "edited", MaxSessionDuration=3600)
        acquire("duration_restored", "edited")
        mutate("tag-role", "edited", Tags=[{"Key": "Owner", "Value": "probe"}])
        acquire("tags_changed", "edited")
        mutate("untag-role", "edited", TagKeys=["Owner"])
        acquire("tags_restored", "edited")
        acquire("different_parameter", "edited", service="ec2.amazonaws.com")
        acquire("original_parameter_again", "edited")
        mutate("attach-role-policy", "edited", PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        acquire("attachment_changed", "edited")
        mutate("detach-role-policy", "edited", PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        acquire("attachment_restored", "edited")
        changed_trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
        mutate("update-assume-role-policy", "edited", PolicyDocument=changed_trust)
        acquire("trust_changed", "edited")
        mutate("update-assume-role-policy", "edited", PolicyDocument=changed_trust.replace("ec2.amazonaws.com", "lambda.amazonaws.com"))
        acquire("trust_restored", "edited")
        reformatted = {"Statement": {"Action": ["sts:AssumeRole"], "Effect": "Allow", "Principal": {"Service": ["lambda.amazonaws.com"]}}, "Version": "2012-10-17"}
        mutate("update-assume-role-policy", "edited", PolicyDocument=json.dumps(reformatted, indent=4))
        acquire("equivalent_trust_shape", "edited")
        acquire("role_name_case", "EDITED")
        mutate("put-role-permissions-boundary", "edited", PermissionsBoundary="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        acquire("boundary_added", "edited")
        mutate("delete-role-permissions-boundary", "edited")
        acquire("boundary_removed", "edited")
        observe("source_after_restore", "get-role", {"RoleName": prefix + "-edited"})
        listed = call("iam", "list-roles")["Roles"]
        results["listed_template_role"] = next(r for r in listed if r["RoleName"] == prefix + "-edited")

        # A role created through CreateRole has no template management metadata,
        # even when its current trust and attachments match the template.
        roles.add(prefix + "-ordinary")
        trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
        mutate("create-role", "ordinary", AssumeRolePolicyDocument=trust)
        mutate("attach-role-policy", "ordinary", PolicyArn=policy)
        acquire("ordinary_same_configuration", "ordinary")

        acquire("reuse_seed", "read")
        call("iam", "create-user", {"UserName": prefix})
        user = True
        resource = f"arn:aws:iam::{account}:role/{prefix}-"
        document = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:GetRole", "Resource": resource + "read", "Condition": {"ArnEquals": {"iam:RoleTemplateARN": template}}},
            {"Effect": "Allow", "Action": "iam:CreateRole", "Resource": [resource + "full", resource + "missingattachment"], "Condition": {"ArnEquals": {"iam:RoleTemplateARN": template}}},
            {"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": resource + "full", "Condition": {"ArnEquals": {"iam:RoleTemplateARN": template, "iam:PolicyARN": policy}}},
        ]}
        call("iam", "put-user-policy", {"UserName": prefix, "PolicyName": "probe", "PolicyDocument": json.dumps(document)})
        key = call("iam", "create-access-key", {"UserName": prefix})["AccessKey"]
        env = dict(os.environ, AWS_ACCESS_KEY_ID=key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"], AWS_SESSION_TOKEN="")
        # Credentials propagate asynchronously; STS identity tests readiness
        # without requiring IAM API permissions.
        deadline = time.monotonic() + 60
        while True:
            try:
                call("sts", "get-caller-identity", env=env)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        acquire("read_only_reuse", "read", env=env)
        acquire("underlying_permissions_only", "full", env=env)
        acquire("missing_attachment_permission", "missingattachment", env=env)
        observe("failed_create_state", "get-role", {"RoleName": prefix + "-missingattachment"})
        observe("template_read_without_permission", "get-role-template-version", {"TemplateArn": template}, env)
        observe("ordinary_read_without_template_context", "get-role", {"RoleName": prefix + "-read"}, env)
        document["Statement"].append({"Effect": "Allow", "Action": "iam:GetRoleTemplateVersion", "Resource": template})
        call("iam", "put-user-policy", {"UserName": prefix, "PolicyName": "probe", "PolicyDocument": json.dumps(document)})
        deadline = time.monotonic() + 60
        attempts = []
        while True:
            result = observe("template_read_scoped_permission", "get-role-template-version", {"TemplateArn": template}, env)
            attempts.append({"success": result is not None})
            if result or time.monotonic() >= deadline:
                break
            time.sleep(2)
        results["template_permission_propagation"] = attempts
        acquire("reuse_with_template_read", "read", env=env)
        acquire("create_with_template_read", "full", env=env)
        acquire("missing_attachment_with_template_read", "missingattachment", env=env)
        observe("missing_attachment_create_state", "get-role", {"RoleName": prefix + "-missingattachment"})
        document["Statement"][-1]["Condition"] = {"ArnEquals": {"iam:RoleTemplateARN": template}}
        call("iam", "put-user-policy", {"UserName": prefix, "PolicyName": "probe", "PolicyDocument": json.dumps(document)})
        deadline = time.monotonic() + 60
        while True:
            result = observe("direct_template_read_context_required", "get-role-template-version", {"TemplateArn": template}, env)
            if result is None or time.monotonic() >= deadline:
                break
            time.sleep(2)
        acquire("acquisition_template_read_context", "read", env=env)
    finally:
        if key:
            call("iam", "delete-access-key", {"UserName": prefix, "AccessKeyId": key["AccessKeyId"]})
        if user:
            for name in call("iam", "list-user-policies", {"UserName": prefix})["PolicyNames"]:
                call("iam", "delete-user-policy", {"UserName": prefix, "PolicyName": name})
            call("iam", "delete-user", {"UserName": prefix})
        for name in sorted(roles):
            try:
                attached = call("iam", "list-attached-role-policies", {"RoleName": name})["AttachedPolicies"]
            except RuntimeError as error:
                if "NoSuchEntity" in str(error):
                    continue
                raise
            for attachment in attached:
                call("iam", "detach-role-policy", {"RoleName": name, "PolicyArn": attachment["PolicyArn"]})
            call("iam", "delete-role", {"RoleName": name})
        if any(r["RoleName"].startswith(prefix) for r in call("iam", "list-roles")["Roles"]):
            raise RuntimeError("Owned role remains after cleanup")
        if any(u["UserName"] == prefix for u in call("iam", "list-users")["Users"]):
            raise RuntimeError("Owned user remains after cleanup")
        print("Owned roles, user and credentials removed", flush=True)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": "AWS IAM owned roles and restricted IAM user", "observations": results, "cleanup": "Owned roles, user, policies and access key deleted; account settings unchanged."}
    text = json.dumps(fixture, indent=2).replace(account, "111111111111").replace(prefix, "OWNED_ROLE")
    (root / '.stackd/probes/iam/role_acquisition.json').parent.mkdir(parents=True, exist_ok=True)
    (root / '.stackd/probes/iam/role_acquisition.json').write_text(text + "\n")


if __name__ == "__main__":
    main()
