#!/usr/bin/env python3
"""Capture KMS session-principal and delegation behavior on owned resources."""

import base64
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
    identity = require_account(probe_args.account)
    account = identity["Account"]
    prefix = "stackd-grants-" + str(time.time_ns())
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/grants.json'
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "region": os.environ["AWS_DEFAULT_REGION"],
               "source": "Owned AWS KMS key, IAM roles/user and STS sessions; synthetic plaintext",
               "observations": [], "cleanup": [], "capture_complete": False}
    if path.exists():
        previous = json.loads(path.read_text())
        fixture["previous_runs"] = previous.get("previous_runs", []) + [{"observed_at": previous["observed_at"], "cleanup": previous["cleanup"]}]
    roles, users, grants = [], [], []
    key = boundary = access_key = None
    replacements = {account: "111111111111", prefix: "stackd-grants-probe"}

    def save():
        data = json.dumps(fixture, indent=2)
        for actual, normalized in replacements.items():
            data = data.replace(actual, normalized)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data + "\n")

    def observe(case, service, operation, parameters, env=None):
        row = {"case": case, "service": service, "operation": operation}
        row.update(observe_cli(service, operation, parameters, env, paginate=False))
        result = row.get("output")
        if result is not None:
            output = dict(result)
            for field in ["GrantToken", "Credentials", "NextMarker"]:
                if field in output:
                    output[field] = "<omitted>"
            if "GrantId" in output:
                replacements.setdefault(output["GrantId"], f"{len(grants)+1:064x}")
                grants.append(output["GrantId"])
            row.update(output=output)
        if row["code"] == 'ParamValidation':
            row['source'] = 'AWS CLI validation; request was not sent to AWS'
        fixture["observations"].append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return result

    def environment(credentials):
        return dict(os.environ, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                    AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
                    AWS_SESSION_TOKEN=credentials.get("SessionToken", ""))

    def assume(role, name, policy=None):
        params = {"RoleArn": role["Arn"], "RoleSessionName": name, "DurationSeconds": 900}
        if policy:
            params["Policy"] = json.dumps(policy)
        for attempt in range(30):
            try:
                result = call("sts", "assume-role", params)
                return environment(result["Credentials"]), result["AssumedRoleUser"]["Arn"]
            except RuntimeError:
                if attempt == 29:
                    raise
                time.sleep(2)

    allow_other = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}
    deny_kms = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"},
                              {"Effect": "Deny", "Action": "kms:*", "Resource": "*"}]}
    try:
        key = call("kms", "create-key", {"Description": "stackd grants conformance probe"})["KeyMetadata"]
        replacements[key["KeyId"]] = "00000000-0000-4000-8000-000000000001"
        fixture["key"] = key
        save()
        print("Owned grants key: " + key["KeyId"], flush=True)
        trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}]}
        for suffix in ["session", "role", "delegator"]:
            role = call("iam", "create-role", {"RoleName": prefix + "-" + suffix, "Path": "/probe/", "AssumeRolePolicyDocument": json.dumps(trust)})["Role"]
            roles.append(role)
            replacements[role["RoleId"]] = "AROA" + str(len(roles)).zfill(17)
        session_role, whole_role, delegator = roles
        empty, session_arn = assume(session_role, "target")
        limited, _ = assume(session_role, "target", allow_other)
        denied, _ = assume(session_role, "target", deny_kms)
        sibling, _ = assume(session_role, "sibling")
        repeated, _ = assume(session_role, "target")
        encrypted = call("kms", "encrypt", {"KeyId": key["Arn"], "Plaintext": base64.b64encode(b"grant plaintext").decode()})
        decrypt = {"CiphertextBlob": encrypted["CiphertextBlob"]}
        base = {"KeyId": key["Arn"]}
        grant = observe("session_create", "kms", "create-grant", dict(base, GranteePrincipal=session_arn, RetiringPrincipal=session_arn, Operations=["Decrypt", "RetireGrant"], Name="session"))
        if grant:
            for case, env in [("session_no_identity_allow", empty), ("session_implicit_session_deny", limited), ("session_explicit_session_deny", denied), ("session_sibling", sibling), ("session_repeated_name", repeated)]:
                observe(case, "kms", "decrypt", dict(decrypt, GrantTokens=[grant["GrantToken"]]), env)
            observe("session_list", "kms", "list-grants", dict(base, GrantId=grant["GrantId"]))
            observe("session_retirable", "kms", "list-retirable-grants", {"RetiringPrincipal": session_arn})
        for case, principal in [
            ("unissued_session", session_arn.rsplit("/", 1)[0] + "/unissued"),
            ("missing_role", session_arn.replace(session_role["RoleName"], prefix + "-missing")),
            ("session_role_path", session_arn.replace("assumed-role/", "assumed-role/probe/")),
            ("raw_session_id", session_role["RoleId"] + ":target"),
            ("unissued_federated_user", f"arn:aws:sts::{account}:federated-user/unissued"),
            ("missing_account_federated_user", "arn:aws:sts::123456789012:federated-user/unissued"),
        ]:
            observe(case, "kms", "create-grant", dict(base, GranteePrincipal=principal, Operations=["DescribeKey"]))
        role_empty, _ = assume(whole_role, "target")
        role_limited, _ = assume(whole_role, "target", allow_other)
        role_denied, _ = assume(whole_role, "target", deny_kms)
        role_grant = observe("role_create", "kms", "create-grant", dict(base, GranteePrincipal=whole_role["Arn"], Operations=["Decrypt", "RetireGrant"]))
        if role_grant:
            for case, env in [("role_no_identity_allow", role_empty), ("role_implicit_session_deny", role_limited), ("role_explicit_session_deny", role_denied)]:
                observe(case, "kms", "decrypt", dict(decrypt, GrantTokens=[role_grant["GrantToken"]]), env)
        # Boundary attachment is a current-policy change, independent of issuance.
        boundary = call("iam", "create-policy", {"PolicyName": prefix + "-boundary", "PolicyDocument": json.dumps(allow_other)})["Policy"]["Arn"]
        for role in [session_role, whole_role]:
            call("iam", "put-role-permissions-boundary", {"RoleName": role["RoleName"], "PermissionsBoundary": boundary})
        time.sleep(10)
        for case, env, active_grant in [("session_implicit_boundary_deny", empty, grant), ("role_implicit_boundary_deny", role_empty, role_grant)]:
            if active_grant:
                observe(case, "kms", "decrypt", dict(decrypt, GrantTokens=[active_grant["GrantToken"]]), env)
        for role in [session_role, whole_role]:
            call("iam", "delete-role-permissions-boundary", {"RoleName": role["RoleName"]})

        delegate_env, _ = assume(delegator, "target")
        parent1 = observe("delegate_parent_create", "kms", "create-grant", dict(base, GranteePrincipal=delegator["Arn"], Operations=["CreateGrant", "Decrypt"], Constraints={"EncryptionContextSubset": {"department": "IT"}}))
        parent2 = observe("delegate_second_create", "kms", "create-grant", dict(base, GranteePrincipal=delegator["Arn"], Operations=["Encrypt"], Constraints={"EncryptionContextSubset": {"project": "stackd"}}))
        if parent1 and parent2:
            tokens = [parent1["GrantToken"], parent2["GrantToken"]]
            child = dict(base, GranteePrincipal=session_arn, GrantTokens=tokens)
            observe("delegate_combined_operations", "kms", "create-grant", dict(child, Operations=["Decrypt", "Encrypt"], Constraints={"EncryptionContextEquals": {"department": "IT", "project": "stackd"}}), delegate_env)
            observe("delegate_second_only", "kms", "create-grant", dict(child, Operations=["Encrypt"], Constraints={"EncryptionContextEquals": {"department": "IT", "project": "stackd"}}), delegate_env)
            observe("delegate_broaden_constraint", "kms", "create-grant", dict(child, Operations=["Decrypt"]), delegate_env)
            observe("delegate_narrow_constraint", "kms", "create-grant", dict(child, Operations=["Decrypt"], Constraints={"EncryptionContextEquals": {"department": "IT", "project": "stackd"}}), delegate_env)
        user = call("iam", "create-user", {"UserName": prefix + "-federator"})["User"]
        users.append(user)
        call("iam", "put-user-policy", {"UserName": user["UserName"], "PolicyName": "federate", "PolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "sts:GetFederationToken", "Resource": "*"}]})})
        access_key = call("iam", "create-access-key", {"UserName": user["UserName"]})["AccessKey"]
        user_env = environment(access_key)
        time.sleep(10)
        fed = call("sts", "get-federation-token", {"Name": "stackd-grants-federated", "DurationSeconds": 900, "Policy": json.dumps(allow_other)}, user_env)
        fed_env = environment(fed["Credentials"])
        fed_grant = observe("federated_create", "kms", "create-grant", dict(base, GranteePrincipal=fed["FederatedUser"]["Arn"], RetiringPrincipal=fed["FederatedUser"]["Arn"], Operations=["Decrypt"]))
        if fed_grant:
            observe("federated_implicit_session_deny", "kms", "decrypt", dict(decrypt, GrantTokens=[fed_grant["GrantToken"]]), fed_env)
            observe("federated_retire", "kms", "retire-grant", {"GrantToken": fed_grant["GrantToken"]}, fed_env)
        if grant:
            observe("session_retire_limited", "kms", "retire-grant", {"GrantToken": grant["GrantToken"]}, limited)

        # A grant binds the role incarnation and session name, not issuance.
        future_arn = session_arn.rsplit("/", 1)[0] + "/future"
        future_id = session_role["RoleId"] + ":future"
        params = dict(base, Name="bound-session", GranteePrincipal=future_arn, RetiringPrincipal=future_arn, Operations=["DescribeKey"])
        bound = observe("lifecycle_create", "kms", "create-grant", params)
        observe("lifecycle_list_before", "kms", "list-grants", dict(base, GrantId=bound["GrantId"]))
        observe("lifecycle_filter_id", "kms", "list-grants", dict(base, GranteePrincipal=future_id))
        observe("lifecycle_retirable_id", "kms", "list-retirable-grants", {"RetiringPrincipal": future_id})
        observe("lifecycle_named_id_retry", "kms", "create-grant", dict(params, GranteePrincipal=future_id, RetiringPrincipal=future_id))
        call("iam", "delete-role", {"RoleName": session_role["RoleName"]})
        roles.remove(session_role)
        fixture["cleanup"].append({"deleted_role": session_role["Arn"]})
        time.sleep(10)
        observe("lifecycle_list_deleted", "kms", "list-grants", dict(base, GrantId=bound["GrantId"]))
        for suffix, principal in [("arn", future_arn), ("id", future_id)]:
            observe("lifecycle_filter_deleted_" + suffix, "kms", "list-grants", dict(base, GranteePrincipal=principal))
            observe("lifecycle_retirable_deleted_" + suffix, "kms", "list-retirable-grants", {"RetiringPrincipal": principal})
        observe("lifecycle_create_deleted_id", "kms", "create-grant", dict(base, GranteePrincipal=future_id, Operations=["DescribeKey"]))
        replacement = call("iam", "create-role", {"RoleName": session_role["RoleName"], "Path": "/probe/", "AssumeRolePolicyDocument": json.dumps(trust)})["Role"]
        roles.append(replacement)
        replacements[replacement["RoleId"]] = "AROA00000000000000004"
        observe("lifecycle_list_recreated", "kms", "list-grants", dict(base, GrantId=bound["GrantId"]))
        replacement_env, _ = assume(replacement, "future")
        observe("lifecycle_recreated_old_grant", "kms", "describe-key", dict(base, GrantTokens=[bound["GrantToken"]]), replacement_env)
        fresh = None
        for attempt in range(30):
            fresh = observe("lifecycle_recreated_named_grant", "kms", "create-grant", params)
            if fresh:
                break
            time.sleep(2)
        if not fresh:
            raise RuntimeError("Recreated IAM role did not propagate to KMS")
        observe("lifecycle_recreated_new_grant", "kms", "describe-key", dict(base, GrantTokens=[fresh["GrantToken"]]), replacement_env)
        observe("lifecycle_filter_recreated_arn", "kms", "list-grants", dict(base, GranteePrincipal=future_arn))
        fixture["capture_complete"] = True
    finally:
        if key:
            for grant_id in set(grants):
                try:
                    call("kms", "revoke-grant", {"KeyId": key["Arn"], "GrantId": grant_id})
                except RuntimeError as error:
                    if "NotFoundException" not in str(error):
                        fixture["cleanup"].append({"grant_revoke_error": str(error)})
            fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key["Arn"], "PendingWindowInDays": 7}))
        for user in users:
            if access_key:
                call("iam", "delete-access-key", {"UserName": user["UserName"], "AccessKeyId": access_key["AccessKeyId"]})
            call("iam", "delete-user-policy", {"UserName": user["UserName"], "PolicyName": "federate"})
            call("iam", "delete-user", {"UserName": user["UserName"]})
            fixture["cleanup"].append({"deleted_user": user["Arn"]})
        for role in roles:
            call("iam", "delete-role", {"RoleName": role["RoleName"]})
            fixture["cleanup"].append({"deleted_role": role["Arn"]})
        if boundary:
            call("iam", "delete-policy", {"PolicyArn": boundary})
            fixture["cleanup"].append({"deleted_policy": boundary})
        save()
        print("Cleanup recorded in " + str(path), flush=True)


if __name__ == "__main__":
    main()
