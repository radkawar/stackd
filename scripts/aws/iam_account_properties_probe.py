#!/usr/bin/env python3
"""Capture account-property validation and denied Role Manager enablement.

Uses an owned IAM user explicitly denied service-linked-role creation. Requires
Role Manager initially disabled. Any unexpected enablement is restored before
cleanup; ordinary validation cases only request false values.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import time
import uuid

from aws_cli import call


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifecycle", action="store_true", help="Also create the absent Role Manager service-linked role and temporarily enable the feature; restore both afterward")
    parser.add_argument("--account", required=True)
    options = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    account = require_account(options.account)["Account"]
    before = call("iam", "get-account-properties")
    if before.get("Properties", {}).get("RoleManager/Enabled") != "false":
        raise RuntimeError("This probe requires Role Manager disabled before the run")
    initial_roles = {r["RoleName"] for r in call("iam", "list-roles", {"PathPrefix": "/aws-service-role/"})["Roles"]}
    manager_role = "AWSServiceRoleForIAMRoleManager"
    if options.lifecycle and manager_role in initial_roles:
        raise RuntimeError("Lifecycle capture requires the Role Manager service-linked role absent before the run")
    name = "stackd-properties-" + uuid.uuid4().hex[:12]
    observations = {"initial": {"result": before}}
    key = None
    created_user = False
    cleanup = "Probe interrupted before cleanup completed."

    def save():
        fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": "AWS IAM commercial account; owned account-property validation and permission probe", "observations": observations, "cleanup": cleanup}
        text = json.dumps(fixture, indent=2).replace(account, "111111111111").replace(name, "OWNED_USER")
        filename = "account_properties_lifecycle.json" if options.lifecycle else "account_properties.json"
        (root / '.stackd/probes/iam' / filename).parent.mkdir(parents=True, exist_ok=True)
        (root / '.stackd/probes/iam' / filename).write_text(text + "\n")

    def observe(label, operation, parameters=None, env=None):
        try:
            result = call("iam", operation, parameters, env)
            observations[label] = {"input": parameters, "result": result}
            save()
            print(label + ": success", flush=True)
            return result
        except RuntimeError as error:
            code = re.search(r"\(([^)]+)\) when calling", str(error))
            if code is None:
                raise
            observations[label] = {"input": parameters, "error": {"code": code[1], "message": str(error)}}
            save()
            print(label + ": " + code[1], flush=True)
            return None

    def delete_manager_role(label):
        result = observe(label, "delete-service-linked-role", {"RoleName": manager_role})
        if result is None:
            return None
        task = result["DeletionTaskId"]
        print("Deletion task: " + task, flush=True)
        deadline = time.monotonic() + 120
        while True:
            try:
                status = call("iam", "get-service-linked-role-deletion-status", {"DeletionTaskId": task})
            except RuntimeError as error:
                # Accepted jobs can be temporarily invisible. Poll the same ID.
                if "NoSuchEntity" not in str(error) or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
                continue
            if status["Status"] in {"SUCCEEDED", "FAILED"}:
                observations[label + "_status"] = {"result": status}
                save()
                print(label + ": " + status["Status"], flush=True)
                return status
            if time.monotonic() >= deadline:
                raise RuntimeError("Deletion task still pending: " + task)
            time.sleep(2)

    try:
        for label, properties in [
            ("empty", {}),
            ("missing_separator", {"RoleManager": "false"}),
            ("extra_separator", {"RoleManager/Enabled/Other": "false"}),
            ("unknown_namespace", {"StackdProbe/Enabled": "false"}),
            ("unknown_property", {"RoleManager/StackdProbe": "false"}),
            ("mixed_namespaces", {"RoleManager/Enabled": "false", "StackdProbe/Enabled": "false"}),
            ("unknown_property_same_namespace", {"RoleManager/Enabled": "false", "RoleManager/StackdProbe": "false"}),
            ("uppercase_false", {"RoleManager/Enabled": "FALSE"}),
            ("spaced_false", {"RoleManager/Enabled": "false "}),
            ("zero", {"RoleManager/Enabled": "0"}),
            ("false", {"RoleManager/Enabled": "false"}),
        ]:
            observe(label, "put-account-properties", {"Properties": properties})
        call("iam", "create-user", {"UserName": name})
        created_user = True
        document = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["iam:PutAccountProperties", "iam:GetAccountProperties"], "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:CreateServiceLinkedRole", "Resource": "*"},
        ]}
        call("iam", "put-user-policy", {"UserName": name, "PolicyName": "probe", "PolicyDocument": json.dumps(document)})
        key = call("iam", "create-access-key", {"UserName": name})["AccessKey"]
        env = dict(os.environ, AWS_ACCESS_KEY_ID=key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"], AWS_SESSION_TOKEN="")
        deadline = time.monotonic() + 60
        while True:
            if observe("user_read", "get-account-properties", env=env) is not None:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned user's read permission did not propagate")
            time.sleep(2)
        observe("enable_dependency_denied", "put-account-properties", {"Properties": {"RoleManager/Enabled": "true"}}, env)
        observe("after_denied_enable", "get-account-properties")
        observe("user_disable_without_dependency", "put-account-properties", {"Properties": {"RoleManager/Enabled": "false"}}, env)
        document["Statement"][0]["Condition"] = {"ForAnyValue:StringEquals": {"iam:AccountPropertyNamespaces": "RoleManager"}}
        call("iam", "put-user-policy", {"UserName": name, "PolicyName": "probe", "PolicyDocument": json.dumps(document)})
        # Observe after an explicit propagation interval; retain both decisions.
        time.sleep(10)
        observe("namespace_scoped_read", "get-account-properties", env=env)
        observe("namespace_scoped_disable", "put-account-properties", {"Properties": {"RoleManager/Enabled": "false"}}, env)
        if options.lifecycle:
            observe("explicit_service_role", "create-service-linked-role", {"AWSServiceName": "role-manager.iam.amazonaws.com"})
            observe("service_role", "get-role", {"RoleName": manager_role})
            observe("service_role_policies", "list-attached-role-policies", {"RoleName": manager_role})
            observe("service_role_suffix", "create-service-linked-role", {"AWSServiceName": "role-manager.iam.amazonaws.com", "CustomSuffix": "probe"})
            observe("enable_existing_role_dependency_denied", "put-account-properties", {"Properties": {"RoleManager/Enabled": "true"}}, env)
            observe("after_existing_role_enable", "get-account-properties")
            observe("enable", "put-account-properties", {"Properties": {"RoleManager/Enabled": "true"}})
            observe("enabled", "get-account-properties")
            observe("enable_again", "put-account-properties", {"Properties": {"RoleManager/Enabled": "true"}})
            delete_manager_role("delete_while_enabled")
            observe("after_enabled_delete", "get-account-properties")
            observe("role_after_enabled_delete", "get-role", {"RoleName": manager_role})
            observe("disable", "put-account-properties", {"Properties": {"RoleManager/Enabled": "false"}}, env)
            observe("disabled", "get-account-properties")
            deleted = delete_manager_role("delete_while_disabled")
            if deleted and deleted["Status"] == "SUCCEEDED":
                observe("automatic_enable", "put-account-properties", {"Properties": {"RoleManager/Enabled": "true"}})
                observe("automatic_role", "get-role", {"RoleName": manager_role})
                observe("automatic_enabled", "get-account-properties")
    finally:
        # Remove credentials before a failed account-feature cleanup can raise.
        if key:
            call("iam", "delete-access-key", {"UserName": name, "AccessKeyId": key["AccessKeyId"]})
        if created_user:
            for policy in call("iam", "list-user-policies", {"UserName": name})["PolicyNames"]:
                call("iam", "delete-user-policy", {"UserName": name, "PolicyName": policy})
            call("iam", "delete-user", {"UserName": name})
        cleanup = "Owned user and key deleted; restoring account properties and service-linked roles."
        save()
        current = call("iam", "get-account-properties")
        if current != before:
            call("iam", "put-account-properties", {"Properties": before["Properties"]})
        cleanup = "Owned user and key deleted; original account properties restored; service-linked role cleanup pending."
        save()
        if options.lifecycle:
            try:
                call("iam", "get-role", {"RoleName": manager_role})
            except RuntimeError as error:
                if "NoSuchEntity" not in str(error):
                    raise
            else:
                status = delete_manager_role("cleanup_service_role")
                if status is None or status["Status"] != "SUCCEEDED":
                    cleanup = "Owned user and key deleted; original account properties restored; owned Role Manager service-linked role deletion failed."
                    save()
                    raise RuntimeError("Owned Role Manager service-linked role was not deleted: " + json.dumps(status))
        roles = call("iam", "list-roles", {"PathPrefix": "/aws-service-role/"})["Roles"]
        unexpected = [r["RoleName"] for r in roles if r["RoleName"] not in initial_roles]
        if unexpected:
            raise RuntimeError("Unexpected service-linked role creation requires inspection: " + ", ".join(unexpected))
        if call("iam", "get-account-properties") != before:
            raise RuntimeError("Account properties did not return to their initial values")
        if any(u["UserName"] == name for u in call("iam", "list-users")["Users"]):
            raise RuntimeError("Owned user remains after cleanup")
        cleanup = "Owned user and key deleted; initial properties and service-linked roles preserved."
        save()
        print("Owned user/key removed; original properties and service-linked roles preserved", flush=True)


if __name__ == "__main__":
    main()
