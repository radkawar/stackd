#!/usr/bin/env python3
"""Capture RCP syntax and owned SQS/STS/KMS authorization in a member account.

Temporarily enables RCPs if disabled. Attaches one policy to an existing member,
restricted to uniquely named probe resources and the owned role's ListQueues.
Restores the original policy-type setting and removes the owned resources.
The customer-managed KMS key is scheduled for deletion after seven days.
"""

import base64
import datetime
import json
import os
import re
import time
import uuid

from aws_cli import call
from organizations_inputs_probe import probe_parser, verified_account, capture_path


def main():
    args = probe_parser("resource_controls.json").parse_args()
    management = verified_account(args.account)
    path = capture_path(args.output)
    organization = call("organizations", "describe-organization")["Organization"]
    if organization["MasterAccountId"] != management or organization["FeatureSet"] != "ALL":
        raise RuntimeError("Probe requires the all-features management account")
    members = call("organizations", "list-accounts")["Accounts"]
    member = next(a["Id"] for a in members if a["Id"] != management and a["JoinedMethod"] == "CREATED" and a["State"] == "ACTIVE")
    root_info = call("organizations", "list-roots")["Roots"][0]
    root_id = root_info["Id"]
    initially_enabled = any(p["Type"] == "RESOURCE_CONTROL_POLICY" and p["Status"] == "ENABLED" for p in root_info["PolicyTypes"])
    name = "stackd-rcp-" + uuid.uuid4().hex[:12]
    role_arn = f"arn:aws:iam::{member}:role/{name}"
    queue_arn = f"arn:aws:sqs:us-east-1:{member}:{name}"
    manager_queue_arn = f"arn:aws:sqs:us-east-1:{management}:{name}"
    region_env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1")
    observations = {}
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": "Owned RCP resources in an existing AWS Organizations-created member; management-account and member-role requests", "rcp_initially_enabled": initially_enabled, "observations": observations, "cleanup": "Probe running"}
    policies, queues = [], []
    created_role = attached = enabled_here = False
    key_id = grant_id = attached_policy = None

    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in {"Credentials", "CiphertextBlob", "Plaintext"}}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    def save():
        text = json.dumps(fixture, indent=2).replace(management, "111111111111").replace(member, "222222222222").replace(name, "OWNED_RESOURCE")
        path.write_text(text + "\n")

    def observe(label, service, operation, parameters=None, env=None):
        try:
            result = call(service, operation, parameters, env)
            observations[label] = {"input": clean(parameters), "result": clean(result)}
            print(label + ": success", flush=True)
            save()
            return result
        except RuntimeError as error:
            code = re.search(r"\(([^)]+)\) when calling", str(error))
            if code is None:
                raise
            observations[label] = {"input": clean(parameters), "error": {"code": code[1], "message": str(error)}}
            print(label + ": " + code[1], flush=True)
            save()
            return None

    def assume(arn):
        result = call("sts", "assume-role", {"RoleArn": arn, "RoleSessionName": name, "DurationSeconds": 900})
        c = result["Credentials"]
        return dict(region_env, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])

    admin = assume(f"arn:aws:iam::{member}:role/OrganizationAccountAccessRole")
    try:
        # These policies are never attached; malformed documents must not become
        # stored policy state. Successful variants are deleted immediately.
        base = {"Version": "2012-10-17", "Statement": {"Effect": "Deny", "Principal": "*", "Action": "sqs:SendMessage", "Resource": queue_arn}}
        variants = [("valid", base), ("missing_version", {"Statement": base["Statement"]})]
        for label, field, value in [
            ("allow", "Effect", "Allow"), ("action_star", "Action", "*"),
            ("unknown_service", "Action", "stackdprobe:Read"), ("iam_service", "Action", "iam:CreateUser"),
            ("unknown_action", "Action", "sqs:StackdProbe"), ("uppercase_service", "Action", "SQS:SendMessage"),
            ("principal_object", "Principal", {"AWS": "*"}), ("principal_list", "Principal", ["*"]),
            ("principal_account", "Principal", {"AWS": f"arn:aws:iam::{member}:root"}),
        ]:
            st = dict(base["Statement"], **{field: value})
            variants.append((label, {"Version": "2012-10-17", "Statement": st}))
        for label, source, destination in [("not_action", "Action", "NotAction"), ("not_principal", "Principal", "NotPrincipal"), ("not_resource", "Resource", "NotResource")]:
            st = dict(base["Statement"])
            st[destination] = st.pop(source)
            variants.append((label, {"Version": "2012-10-17", "Statement": st}))
        variants.append(("old_version", dict(base, Version="2008-10-17")))
        for label, document in variants:
            result = observe("syntax_" + label, "organizations", "create-policy", {"Name": name + "-" + label, "Description": "stackd owned RCP probe", "Type": "RESOURCE_CONTROL_POLICY", "Content": json.dumps(document)})
            if result:
                pid = result["Policy"]["PolicySummary"]["Id"]
                policies.append(pid)
                call("organizations", "delete-policy", {"PolicyId": pid})
                policies.remove(pid)

        call("iam", "create-role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{management}:root"}, "Action": "sts:AssumeRole"}})}, admin)
        created_role = True
        call("iam", "attach-role-policy", {"RoleName": name, "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, admin)
        attached = True
        deadline = time.monotonic() + 90
        while True:
            try:
                owner = assume(role_arn)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        for env, account, arn, peer in [(admin, member, queue_arn, management), (region_env, management, manager_queue_arn, member)]:
            policy = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{peer}:root"}, "Action": "sqs:SendMessage", "Resource": arn}}
            queue = call("sqs", "create-queue", {"QueueName": name, "Attributes": {"Policy": json.dumps(policy)}}, env)["QueueUrl"]
            queues.append((queue, env))
        key = call("kms", "create-key", {"Description": name}, admin)["KeyMetadata"]
        key_id, key_arn = key["KeyId"], key["Arn"]
        grant = call("kms", "create-grant", {"KeyId": key_id, "GranteePrincipal": role_arn, "RetiringPrincipal": role_arn, "Operations": ["Encrypt"]}, admin)
        grant_id = grant["GrantId"]
        # IAM role permission propagation must be observed before attaching RCPs.
        deadline = time.monotonic() + 90
        while observe("baseline_member_send", "sqs", "send-message", {"QueueUrl": queues[0][0], "MessageBody": "baseline"}, owner) is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned role permissions did not propagate")
            time.sleep(2)
        observe("baseline_management_send", "sqs", "send-message", {"QueueUrl": queues[0][0], "MessageBody": "baseline"}, region_env)
        observe("baseline_member_to_management", "sqs", "send-message", {"QueueUrl": queues[1][0], "MessageBody": "baseline"}, owner)
        observe("baseline_encrypt", "kms", "encrypt", {"KeyId": key_id, "Plaintext": base64.b64encode(b"stackd RCP probe").decode()}, owner)
        observe("baseline_assume", "sts", "assume-role", {"RoleArn": role_arn, "RoleSessionName": name, "DurationSeconds": 900})
        if not initially_enabled:
            observe("enable_rcp", "organizations", "enable-policy-type", {"RootId": root_id, "PolicyType": "RESOURCE_CONTROL_POLICY"})
            enabled_here = True
        observe("managed_rcp", "organizations", "list-policies", {"Filter": "RESOURCE_CONTROL_POLICY"})
        document = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Principal": "*", "Action": ["sqs:SendMessage", "kms:Encrypt", "kms:RetireGrant", "sts:AssumeRole"], "Resource": [f"arn:aws:sqs:us-east-1:*:{name}", key_arn, role_arn]},
            {"Effect": "Deny", "Principal": "*", "Action": "sqs:ListQueues", "Resource": "*", "Condition": {"ArnEquals": {"aws:PrincipalArn": role_arn}}},
        ]}
        result = observe("create_rcp", "organizations", "create-policy", {"Name": name, "Description": "stackd owned RCP probe", "Type": "RESOURCE_CONTROL_POLICY", "Content": json.dumps(document)})
        attached_policy = result["Policy"]["PolicySummary"]["Id"]
        policies.append(attached_policy)
        observe("attach_rcp", "organizations", "attach-policy", {"PolicyId": attached_policy, "TargetId": member})
        deadline = time.monotonic() + 90
        while True:
            result = observe("restricted_member_send", "sqs", "send-message", {"QueueUrl": queues[0][0], "MessageBody": "restricted"}, owner)
            if result is None:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("RCP deny did not propagate")
            time.sleep(2)
        observe("restricted_management_send", "sqs", "send-message", {"QueueUrl": queues[0][0], "MessageBody": "restricted"}, region_env)
        observe("restricted_member_to_management", "sqs", "send-message", {"QueueUrl": queues[1][0], "MessageBody": "management remains accessible"}, owner)
        observe("restricted_list", "sqs", "list-queues", {"QueueNamePrefix": name}, owner)
        observe("restricted_encrypt", "kms", "encrypt", {"KeyId": key_id, "Plaintext": base64.b64encode(b"stackd RCP probe").decode()}, owner)
        observe("restricted_assume", "sts", "assume-role", {"RoleArn": role_arn, "RoleSessionName": name, "DurationSeconds": 900})
        observe("retire_grant_key_id", "kms", "retire-grant", {"KeyId": key_id, "GrantId": grant_id}, owner)
        observe("retire_grant_exemption", "kms", "retire-grant", {"KeyId": key_arn, "GrantId": grant_id}, owner)
        observe("detach_rcp", "organizations", "detach-policy", {"PolicyId": attached_policy, "TargetId": member})
        attached_policy = None
        deadline = time.monotonic() + 90
        while observe("restored_member_send", "sqs", "send-message", {"QueueUrl": queues[0][0], "MessageBody": "restored"}, owner) is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("RCP detach did not propagate")
            time.sleep(2)
    finally:
        failures = []

        def cleanup(service, operation, parameters, env=None):
            try:
                call(service, operation, parameters, env)
            except RuntimeError as error:
                failures.append(str(error))

        if attached_policy:
            cleanup("organizations", "detach-policy", {"PolicyId": attached_policy, "TargetId": member})
        for pid in policies:
            cleanup("organizations", "delete-policy", {"PolicyId": pid})
        if enabled_here:
            cleanup("organizations", "disable-policy-type", {"RootId": root_id, "PolicyType": "RESOURCE_CONTROL_POLICY"})
        for queue, env in queues:
            cleanup("sqs", "delete-queue", {"QueueUrl": queue}, env)
        if key_id:
            cleanup("kms", "schedule-key-deletion", {"KeyId": key_id, "PendingWindowInDays": 7}, admin)
            fixture["key_cleanup"] = clean(call("kms", "describe-key", {"KeyId": key_id}, admin))
        if attached:
            cleanup("iam", "detach-role-policy", {"RoleName": name, "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, admin)
        if created_role:
            cleanup("iam", "delete-role", {"RoleName": name}, admin)
        fixture["cleanup_errors"] = failures
        fixture["cleanup"] = "Owned policies, queues and role removed; KMS key scheduled for seven-day deletion; original RCP policy-type setting restored." if not failures else "Cleanup failures require recovery."
        fixture["final_policy_types"] = call("organizations", "list-roots")["Roots"][0]["PolicyTypes"]
        save()
        if failures:
            raise RuntimeError("Cleanup failures: " + "; ".join(failures))
        print(fixture["cleanup"], flush=True)


if __name__ == "__main__":
    main()
