#!/usr/bin/env python3
"""Probe IAM shared-OIDC write controls using owned roles/providers; clean up all.

Existing providers are never modified or deleted. The role has no permissions.
Only policy inputs and error classifications are saved, never credentials.
"""

import datetime
import argparse
import json
from pathlib import Path
import re
import subprocess
import uuid

from aws_cli import run as run_cli


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / '.stackd/probes/iam/oidc_trust_controls_aws.json'
COMMON = ["--endpoint-url", "https://iam.amazonaws.com", "--region", "us-east-1"]


def call(action, inputs):
    result = run_cli("iam", action, inputs, options=COMMON, timeout=30)
    out = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else {}
    match = re.search(r"An error occurred \(([^)]+)\).*?: (.*)", result.stderr)
    code = match.group(1) if match else ("" if not result.returncode else "CLIError")
    message = match.group(2) if match else ("" if not result.returncode else result.stderr)
    return out, code, message


def variants(principal, key):
    def statement(condition=None, **extra):
        row = {"Effect": "Allow", "Principal": {"Federated": principal},
               "Action": "sts:AssumeRoleWithWebIdentity"}
        if condition is not None:
            row["Condition"] = condition
        row.update(extra)
        return row

    yield "missing", statement()
    for op, value in [
            ("StringEquals", "owned-value"), ("StringEquals", "*"),
            ("StringEquals", "?"), ("StringEquals", "**"),
            ("StringEquals", "*?"), ("StringEquals", ""),
            ("StringEquals", ["*", "owned-value"]), ("StringEquals", []),
            ("StringLike", "owned:*"), ("StringLike", "*"),
            ("StringNotEquals", "owned-value"),
            ("StringEqualsIfExists", "owned-value"),
            ("StringLikeIfExists", "owned:*"),
            ("StringEqualsIgnoreCase", "owned-value"),
            ("ForAnyValue:StringEquals", "owned-value"),
            ("ForAllValues:StringEquals", "owned-value"),
            ("Null", "false"), ("Null", "true"),
            ("NumericEquals", "1"), ("Bool", "true")]:
        yield op + ":" + json.dumps(value), statement({op: {key: value}})
    yield "upper-key", statement({"StringEquals": {key.upper(): "owned-value"}})
    yield "deny-missing", statement(Effect="Deny")
    yield "tag-only-missing", statement(Action="sts:TagSession")
    yield "wildcard-action-missing", statement(Action="sts:*")
    good = statement({"StringEquals": {key: "owned-value"}})
    yield "valid-and-unrestricted", [good, statement()]
    yield "valid-and-deny", [good, statement(Effect="Deny")]
    yield "valid-separate-principal", [good, {"Effect": "Allow", "Principal": {"Federated": "accounts.google.com"}, "Action": "sts:AssumeRoleWithWebIdentity"}]


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extended", action="store_true", help="Probe operator edges and built-in provider controls")
    parser.add_argument("--github-existing", action="store_true", help="Reference the existing GitHub provider read-only, never modify it")
    parser.add_argument("--details", action="store_true", help="Resolve GitHub pattern and built-in claim alternatives")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    role_name = "stackd-oidc-controls-" + uuid.uuid4().hex[:12]
    providers, rows, skipped, referenced = [], [], [], []
    owned_role = False
    cleanup = []
    try:
        baseline = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Principal": {"Federated": "accounts.google.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"accounts.google.com:aud": "owned-only"}}}}
        _, code, message = call("create-role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps(baseline)})
        if code:
            raise RuntimeError(code + ": " + message)
        owned_role = True
        sources = [("cognito-identity.amazonaws.com", "cognito-identity.amazonaws.com", "cognito-identity.amazonaws.com:aud")]
        issuers = ["token.actions.githubusercontent.com", "gitlab.com", "app.terraform.io"]
        if args.extended:
            issuers = ["vstoken.actions.githubusercontent.com", "gitlab.com"]
            sources.extend((issuer, issuer, issuer + ":" + key) for issuer, key in [("accounts.google.com", "aud"), ("www.amazon.com", "app_id"), ("graph.facebook.com", "app_id")])
        if args.github_existing:
            identity = subprocess.run(["aws", "sts", "get-caller-identity", "--endpoint-url", "https://sts.us-east-1.amazonaws.com", "--region", "us-east-1", "--output", "json", "--no-cli-pager"], capture_output=True, text=True, timeout=30, check=True)
            account = json.loads(identity.stdout)["Account"]
            issuer = "token.actions.githubusercontent.com"
            arn = "arn:aws:iam::" + account + ":oidc-provider/" + issuer
            _, code, message = call("get-open-id-connect-provider", {"OpenIDConnectProviderArn": arn})
            if code:
                raise RuntimeError(code + ": " + message)
            referenced.append({"resource": arn, "owned": False, "access": "read-only reference; never modified or deleted"})
            sources, issuers = [(issuer, arn, issuer + ":sub")], []
            if args.details:
                sources.extend((issuer, issuer, issuer + ":sub") for issuer in ["accounts.google.com", "www.amazon.com", "graph.facebook.com"])
        for issuer in issuers:
            out, code, message = call("create-open-id-connect-provider", {"Url": "https://" + issuer, "ClientIDList": [role_name], "ThumbprintList": ["a" * 40]})
            if code == "EntityAlreadyExists":
                skipped.append(issuer)
                continue
            if code:
                raise RuntimeError(code + ": " + message)
            arn = out["OpenIDConnectProviderArn"]
            providers.append(arn)
            sources.append((issuer, arn, issuer + ":sub"))
        for issuer, principal, key in sources:
            cases = extended_variants(principal, key) if args.extended else variants(principal, key)
            if args.github_existing:
                cases = [*variants(principal, key), *extended_variants(principal, key)]
            if args.details:
                cases = detail_variants(principal, key)
            for name, statements in cases:
                document = {"Version": "2012-10-17", "Statement": statements}
                _, code, message = call("update-assume-role-policy", {"RoleName": role_name, "PolicyDocument": json.dumps(document)})
                rows.append({"issuer": issuer, "case": name, "document": document, "code": code, "message": message})
                print(issuer, name, code or "success", flush=True)
    finally:
        if owned_role:
            _, code, _ = call("delete-role", {"RoleName": role_name})
            cleanup.append({"resource": "role", "deleted": code == "", "absent": call("get-role", {"RoleName": role_name})[1] == "NoSuchEntity"})
        for arn in providers:
            _, code, _ = call("delete-open-id-connect-provider", {"OpenIDConnectProviderArn": arn})
            cleanup.append({"resource": arn, "deleted": code == "", "absent": call("get-open-id-connect-provider", {"OpenIDConnectProviderArn": arn})[1] == "NoSuchEntity"})
        complete = bool(cleanup) and all(row["deleted"] and row["absent"] for row in cleanup)
        fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": "AWS IAM us-east-1; mutations only to owned resources", "probe": "scripts/aws/iam_oidc_trust_controls_probe.py", "skipped_existing_providers": skipped, "existing_readonly_references": referenced, "cleanup_complete": complete, "cleanup": cleanup, "scenarios": rows}
        OUT.parent.mkdir(parents=True, exist_ok=True)
        output = OUT.with_name("oidc_trust_controls_edges_aws.json") if args.extended else OUT
        if args.extended:
            fixture["probe"] += " --extended"
        if args.github_existing:
            output = OUT.with_name("oidc_trust_controls_github_aws.json")
            fixture["probe"] += " --github-existing"
        if args.details:
            output = OUT.with_name("oidc_trust_controls_details_aws.json")
            fixture["probe"] += " --details"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(re.sub(r"arn:aws:iam::\d{12}:", "arn:aws:iam::123456789012:", json.dumps(fixture, indent=2)) + "\n")
        if not complete:
            raise RuntimeError("Owned-resource cleanup incomplete; inspect fixture")


def extended_variants(principal, key):
    def statement(condition=None, **extra):
        row = {"Effect": "Allow", "Principal": {"Federated": principal}, "Action": "sts:AssumeRoleWithWebIdentity"}
        if condition is not None:
            row["Condition"] = condition
        row.update(extra)
        return row

    if principal in ["accounts.google.com", "www.amazon.com", "graph.facebook.com"]:
        yield "missing", statement()
        for suffix in ["aud", "oaud", "app_id", "sub"]:
            yield "claim:" + suffix, statement({"StringEquals": {principal + ":" + suffix: "owned-value"}})
        for op in ["StringEquals", "StringLike", "StringEqualsIgnoreCase", "ForAnyValue:StringEquals", "ForAllValues:StringEquals", "StringEqualsIfExists", "StringNotEquals", "Null"]:
            value = "false" if op == "Null" else "owned-value"
            yield "operator:" + op, statement({op: {key: value}})
        for value in ["*", "?", "", [], ["*", "owned-value"]]:
            yield "value:" + json.dumps(value), statement({"StringEquals": {key: value}})
        yield "upper-key", statement({"StringEquals": {key.upper(): "owned-value"}})
        yield "deny-missing", statement(Effect="Deny")
        yield "tag-only-missing", statement(Action="sts:TagSession")
        return
    for op in ["StringLike", "StringEqualsIgnoreCase", "ForAnyValue:StringEquals", "ForAllValues:StringLike"]:
        for value in ["?", "**", "*?", "", [], ["*", "owned-value"]]:
            yield op + ":" + json.dumps(value), statement({op: {key: value}})
    yield "valid-and-invalid-operator", statement({"StringEquals": {key: "owned-value"}, "StringLike": {key: "*"}})
    yield "not-action-excludes-web", statement(**{"Action": "sts:TagSession"})
    yield "action-mixed-case", statement(Action="STS:assumerolewithwebidentity")
    yield "nested-path-private", {"Effect": "Allow", "Principal": {"Federated": principal + "/private"}, "Action": "sts:AssumeRoleWithWebIdentity"} if principal.startswith("arn:") else statement()


def detail_variants(principal, key):
    def statement(condition):
        return {"Effect": "Allow", "Principal": {"Federated": principal}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": condition}
    if not principal.startswith("arn:"):
        for suffix in ["amr", "email", "user_id", "id", "anything", "SUB"]:
            yield "claim:" + suffix, statement({"StringEquals": {principal + ":" + suffix: "owned-value"}})
        return
    for value in ["??", "?*", "*??", "??*", "*owned", "?owned", "owned*", "*?owned", " ", "${aws:username}"]:
        yield "pattern:" + value, statement({"StringLike": {key: value}})
    job = key.removesuffix(":sub") + ":job_workflow_ref"
    for value in ["owned-value", "*", "", []]:
        yield "job_workflow_ref:" + json.dumps(value), statement({"StringEquals": {job: value}})
    yield "invalid-sub-valid-job", statement({"StringEquals": {key: "*", job: "owned-value"}})
    yield "valid-sub-invalid-job", statement({"StringEquals": {key: "owned-value", job: "*"}})
    for suffix in ["/private", ".example.test", "other"]:
        row = statement({"StringEquals": {key: "owned-value"}})
        row["Principal"]["Federated"] += suffix
        yield "issuer-suffix:" + suffix, row


if __name__ == "__main__":
    main()
