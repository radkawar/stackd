#!/usr/bin/env python3
"""Capture grant trust using an owned key and temporary member-account roles."""

import datetime
import json
import os
import pathlib
import time

from aws_cli import call, observe as observe_cli


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    account = require_account(probe_args.account)["Account"]
    member = next(a["Id"] for a in call("organizations", "list-accounts")["Accounts"]
                  if a["JoinedMethod"] == "CREATED" and a["State"] == "ACTIVE" and a["Id"] != account)

    def environment(credentials):
        return dict(os.environ, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                    AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
                    AWS_SESSION_TOKEN=credentials["SessionToken"])

    member_env = environment(call("sts", "assume-role", {
        "RoleArn": f"arn:aws:iam::{member}:role/OrganizationAccountAccessRole",
        "RoleSessionName": "stackd-kms-grants", "DurationSeconds": 900,
    })["Credentials"])
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/grants.json'
    fixture = json.loads(path.read_text())
    fixture["observations"] = [row for row in fixture["observations"] if not row["case"].startswith("cross_")]
    fixture["cross_account_observed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    fixture["cross_account_capture_complete"] = False
    prefix = "stackd-grants-cross-" + str(time.time_ns())
    roles, grants = [], []
    key = None
    replacements = {account: "111111111111", member: "222222222222", prefix: "stackd-grants-cross"}

    def save():
        data = json.dumps(fixture, indent=2)
        for actual, normalized in replacements.items():
            data = data.replace(actual, normalized)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data + "\n")

    def observe(case, operation, parameters, env=None):
        row = {"case": case, "service": "kms", "operation": operation}
        row.update(observe_cli("kms", operation, parameters, env, paginate=False))
        result = row.get("output")
        if result is not None:
            output = dict(result)
            if "GrantId" in result:
                replacements.setdefault(result["GrantId"], f"{len(grants)+200:064x}")
                grants.append(result["GrantId"])
            if "GrantToken" in output:
                output["GrantToken"] = "<omitted>"
            row.update(output=output)
        fixture["observations"].append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return result

    def assume(role, policy=None):
        params = {"RoleArn": role["Arn"], "RoleSessionName": "target", "DurationSeconds": 900}
        if policy:
            params["Policy"] = json.dumps(policy)
        for attempt in range(30):
            try:
                return call("sts", "assume-role", params, member_env)
            except RuntimeError:
                if attempt == 29:
                    raise
                time.sleep(2)

    def create_grant(case, params, issuer=None):
        for attempt in range(30):
            grant = observe(case, "create-grant", params, issuer)
            if grant:
                return grant
            time.sleep(2)
        raise RuntimeError("Owned IAM role did not propagate to KMS")

    other = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}
    try:
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "kms:*", "Resource": "*"},
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{member}:root"}, "Action": "kms:CreateGrant", "Resource": "*"},
        ]}
        key = call("kms", "create-key", {"Description": "stackd cross-account grant probe", "Policy": json.dumps(policy)})["KeyMetadata"]
        replacements[key["KeyId"]] = "00000000-0000-4000-8000-000000000002"
        fixture["cross_account_key"] = key
        base = {"KeyId": key["Arn"]}
        save()
        print("Owned cross-account grant key: " + key["KeyId"], flush=True)
        for kind in ["owner", "trusted", "retire"]:
            role = call("iam", "create-role", {"RoleName": prefix + "-" + kind, "AssumeRolePolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{member}:root"}, "Action": "sts:AssumeRole"}]})}, member_env)["Role"]
            roles.append(role)
            replacements[role["RoleId"]] = "AROA" + str(len(roles)+200).zfill(17)
        for role, kind in zip(roles[:2], ["owner", "trusted"]):
            session, limited = assume(role), assume(role, other)
            session_env, limited_env = environment(session["Credentials"]), environment(limited["Credentials"])
            issuer = None if kind == "owner" else member_env
            for target, operation in [("session", "DescribeKey"), ("role", "Encrypt")]:
                arn = session["AssumedRoleUser"]["Arn"] if target == "session" else role["Arn"]
                grant = create_grant(f"cross_{kind}_{target}_create", dict(base, GranteePrincipal=arn, Operations=[operation]), issuer)
                params = dict(base, GrantTokens=[grant["GrantToken"]])
                if operation == "Encrypt":
                    params["Plaintext"] = "Y3Jvc3MgYWNjb3VudA=="
                op = "describe-key" if operation == "DescribeKey" else "encrypt"
                observe(f"cross_{kind}_{target}_no_identity_allow", op, params, session_env)
                observe(f"cross_{kind}_{target}_implicit_session_deny", op, params, limited_env)
            call("iam", "put-role-policy", {"RoleName": role["RoleName"], "PolicyName": "access", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kms:*", "Resource": key["Arn"]}]})}, member_env)
            time.sleep(10)
            observe(f"cross_{kind}_identity_allowed", "describe-key", base, session_env)
            observe(f"cross_{kind}_identity_allowed_limited", "describe-key", base, limited_env)

        role = roles[2]
        session, limited = assume(role), assume(role, other)
        for target in ["session", "role"]:
            arn = session["AssumedRoleUser"]["Arn"] if target == "session" else role["Arn"]
            for binding in ["retiring", "grantee"]:
                for limit in ["none", "session"]:
                    case = f"cross_retire_{target}_{binding}_{limit}"
                    params = dict(base, GranteePrincipal=arn if binding == "grantee" else f"arn:aws:iam::{account}:root", Operations=["RetireGrant"] if binding == "grantee" else ["DescribeKey"])
                    if binding == "retiring":
                        params["RetiringPrincipal"] = arn
                    grant = create_grant(case + "_create", params)
                    env = environment((session if limit == "none" else limited)["Credentials"])
                    observe(case, "retire-grant", {"GrantToken": grant["GrantToken"]}, env)
        fixture["cross_account_capture_complete"] = True
    finally:
        if key:
            for grant_id in set(grants):
                try:
                    call("kms", "revoke-grant", dict(base, GrantId=grant_id))
                except RuntimeError as error:
                    if "NotFoundException" not in str(error):
                        raise
            fixture["cleanup"].append(call("kms", "schedule-key-deletion", dict(base, PendingWindowInDays=7)))
        for role in roles:
            if role != roles[-1]:
                try:
                    call("iam", "delete-role-policy", {"RoleName": role["RoleName"], "PolicyName": "access"}, member_env)
                except RuntimeError as error:
                    if "NoSuchEntity" not in str(error):
                        raise
            call("iam", "delete-role", {"RoleName": role["RoleName"]}, member_env)
            fixture["cleanup"].append({"deleted_member_role": role["Arn"]})
        save()
        print("Cleanup recorded in " + str(path), flush=True)


if __name__ == "__main__":
    main()
