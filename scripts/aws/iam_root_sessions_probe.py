#!/usr/bin/env python3
"""Capture centralized root transitions, restoring initially disabled IAM access.

Uses two existing Organizations-created members and short assumed-role/root
sessions. Supplies no password and does not change keys, MFA or certificates.
A recovery profile is created only when the target has no existing root
profile/password, and only that owned profile is deleted.
"""

import base64
import csv
import datetime
import io
import json
import os
import pathlib
import re
import time

from aws_cli import call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    destination = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/iam/root_sessions.json'
    environment = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_STS_REGIONAL_ENDPOINTS="regional")
    management = require_account(probe_args.account, env=environment)["Account"]
    organization = call("organizations", "describe-organization")["Organization"]
    services = call("organizations", "list-aws-service-access-for-organization")["EnabledServicePrincipals"]
    if organization["MasterAccountId"] != management or organization["FeatureSet"] != "ALL":
        raise RuntimeError("An all-features management account is required")
    if any(s["ServicePrincipal"] == "iam.amazonaws.com" for s in services):
        raise RuntimeError("Probe requires IAM trusted access initially disabled")
    members = [a["Id"] for a in call("organizations", "list-accounts")["Accounts"]
               if a["Id"] != management and a["State"] == "ACTIVE" and a["JoinedMethod"] == "CREATED"]
    delegate, target = members[:2]
    rows = []
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "Real AWS Organizations, IAM and regional STS; temporary centralized root access",
               "probe": "scripts/aws/iam_root_sessions_probe.py",
               "observations": rows, "cleanup": "Probe running"}
    own_features = own_delegate = own_profile = False
    trust_enabled = False
    audit = deleter = None

    def sanitize(value):
        if isinstance(value, dict):
            return {k: sanitize(v) for k, v in value.items() if k not in {"AccessKeyId", "SecretAccessKey", "SessionToken", "Password", "Content"}}
        if isinstance(value, list):
            return [sanitize(v) for v in value]
        return value

    def save():
        data = json.dumps(fixture, indent=2)
        for original, replacement in [(management, "111111111111"), (delegate, "222222222222"), (target, "333333333333"), (organization["Id"], "o-aaaaaaaaaa")]:
            data = data.replace(original, replacement)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(data + "\n")

    def observe(case, service, action, parameters=None, env=None):
        row = {"case": case, "service": service, "operation": action,
               "input": sanitize(parameters or {}), "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        started = time.monotonic()
        try:
            result = call(service, action, parameters, env or environment)
            row.update(code="Success", output=sanitize(result))
            if action == "get-credential-report":
                report = csv.DictReader(io.StringIO(base64.b64decode(result["Content"]).decode()))
                row["output"]["RootRow"] = next(r for r in report if r["user"] == "<root_account>")
        except RuntimeError as error:
            match = re.search(r"\(([^)]+)\) when calling", str(error))
            if match is None:
                raise
            row.update(code=match[1], message=str(error))
            result = None
        row["request_seconds"] = round(time.monotonic() - started, 3)
        rows.append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return result

    def session(result):
        if result is None:
            return None
        c = result["Credentials"]
        return dict(environment, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])

    def assume(case, task="IAMAuditRootUserCredentials", env=None):
        return session(observe(case, "sts", "assume-root", {"TargetPrincipal": target, "TaskPolicyArn": {"arn": "arn:aws:iam::aws:policy/root-task/" + task}, "DurationSeconds": 900}, env))

    def wait_assume(case, allowed, env=None):
        deadline = time.monotonic() + 90
        while True:
            result = assume(case, env=env)
            if (result is not None) == allowed:
                return result
            if time.monotonic() >= deadline:
                raise RuntimeError("AssumeRoot transition did not propagate: " + case)
            time.sleep(3)

    def admin_session(account):
        return session(call("sts", "assume-role", {"RoleArn": f"arn:aws:iam::{account}:role/OrganizationAccountAccessRole", "RoleSessionName": "stackd-root-probe", "DurationSeconds": 900}, environment))

    def observe_revocation(kind, env=None):
        started = time.monotonic()
        for offset in [0, 15, 60, 180]:
            time.sleep(max(0, started + offset - time.monotonic()))
            observe(f"{kind}_features_after_{offset}s", "iam", "list-organizations-features", env=env)
            assume(f"{kind}_session_after_{offset}s", env=env)
            if kind == "delegate" and offset in [0, 180]:
                assume(f"fresh_delegate_session_after_{offset}s", env=admin_session(delegate))

    admins = {account: admin_session(account) for account in [delegate, target]}
    try:
        observe("before_trust", "iam", "list-organizations-features")
        call("organizations", "enable-aws-service-access", {"ServicePrincipal": "iam.amazonaws.com"})
        trust_enabled = True
        initial = observe("initial_features", "iam", "list-organizations-features")
        if initial is None or initial.get("EnabledFeatures"):
            raise RuntimeError("Probe requires both root features initially disabled")
        own_features = True
        observe("ordinary_member_features", "iam", "list-organizations-features", env=admins[delegate])
        current = call("organizations", "list-delegated-administrators", {"ServicePrincipal": "iam.amazonaws.com"})
        if current["DelegatedAdministrators"]:
            raise RuntimeError("Probe requires no existing IAM delegated administrator")
        call("organizations", "register-delegated-administrator", {"AccountId": delegate, "ServicePrincipal": "iam.amazonaws.com"})
        own_delegate = True
        observe("delegate_features", "iam", "list-organizations-features", env=admins[delegate])
        observe("delegate_enable_credentials", "iam", "enable-organizations-root-credentials-management", env=admins[delegate])
        observe("manager_enable_credentials", "iam", "enable-organizations-root-credentials-management")
        for task in ["IAMAuditRootUserCredentials", "IAMDeleteRootUserCredentials", "IAMCreateRootUserPassword", "S3UnlockBucketPolicy", "SQSUnlockQueuePolicy"]:
            assume("credentials_only_" + task, task)
        audit = wait_assume("audit_enabled", True)
        delegate_audit = wait_assume("delegate_assume_enabled", True, admins[delegate])
        for action in ["get-user", "list-access-keys", "list-signing-certificates", "list-mfa-devices"]:
            observe("audit_" + action, "iam", action, env=audit)
        before = observe("profile_before", "iam", "get-login-profile", env=audit)
        summary = observe("summary_before", "iam", "get-account-summary", env=audit)
        if before is None and rows[-2]["code"] == "NoSuchEntity" and summary["SummaryMap"]["AccountPasswordPresent"] == 0:
            creator = assume("create_task", "IAMCreateRootUserPassword")
            deleter = assume("delete_task", "IAMDeleteRootUserCredentials")
            if creator is None or deleter is None:
                raise RuntimeError("Both root recovery task sessions are required")
            created = observe("create_profile", "iam", "create-login-profile", env=creator)
            if created is not None:
                own_profile = True
                observe("create_profile_duplicate", "iam", "create-login-profile", env=creator)
                observe("profile_after_create", "iam", "get-login-profile", env=audit)
                observe("summary_after_create", "iam", "get-account-summary", env=audit)
                generated = observe("generate_report", "iam", "generate-credential-report", env=admins[target])
                deadline = time.monotonic() + 45
                while generated and generated["State"] != "COMPLETE" and time.monotonic() < deadline:
                    time.sleep(2)
                    generated = observe("generate_report", "iam", "generate-credential-report", env=admins[target])
                observe("report_after_create", "iam", "get-credential-report", env=admins[target])
                if observe("delete_owned_profile", "iam", "delete-login-profile", env=deleter) is not None:
                    own_profile = False
                observe("profile_after_delete", "iam", "get-login-profile", env=audit)
                observe("summary_after_delete", "iam", "get-account-summary", env=audit)
        else:
            fixture["profile_mutation_skipped"] = "Target has an existing root profile/password or could not be audited"
        observe("delegate_enable_sessions", "iam", "enable-organizations-root-sessions", env=admins[delegate])
        observe("manager_enable_sessions", "iam", "enable-organizations-root-sessions")
        observe("delegate_disable_credentials", "iam", "disable-organizations-root-credentials-management", env=admins[delegate])
        observe("manager_disable_credentials", "iam", "disable-organizations-root-credentials-management")
        for task in ["IAMAuditRootUserCredentials", "IAMDeleteRootUserCredentials", "IAMCreateRootUserPassword", "S3UnlockBucketPolicy", "SQSUnlockQueuePolicy"]:
            assume("sessions_only_" + task, task)
        observe("delegate_disable_sessions", "iam", "disable-organizations-root-sessions", env=admins[delegate])
        observe("manager_disable_sessions", "iam", "disable-organizations-root-sessions")
        wait_assume("new_session_after_disable", False)
        observe("issued_session_after_disable", "iam", "get-user", env=audit)
        observe("manager_reenable_credentials", "iam", "enable-organizations-root-credentials-management")
        observe("manager_reenable_sessions", "iam", "enable-organizations-root-sessions")
        wait_assume("before_trust_disable", True)
        observe("trust_disable_with_delegate", "organizations", "disable-aws-service-access", {"ServicePrincipal": "iam.amazonaws.com"})
        call("organizations", "deregister-delegated-administrator", {"AccountId": delegate, "ServicePrincipal": "iam.amazonaws.com"})
        own_delegate = False
        observe_revocation("delegate", admins[delegate])
        observe("issued_session_after_deregister", "iam", "get-user", env=delegate_audit)
        call("organizations", "disable-aws-service-access", {"ServicePrincipal": "iam.amazonaws.com"})
        trust_enabled = False
        observe("features_without_trust", "iam", "list-organizations-features")
        observe_revocation("untrusted")
        observe("issued_session_without_trust", "iam", "get-user", env=audit)
        call("organizations", "enable-aws-service-access", {"ServicePrincipal": "iam.amazonaws.com"})
        trust_enabled = True
        observe("features_after_trust_restore", "iam", "list-organizations-features")
        fixture["capture_complete"] = True
    finally:
        failures = []

        def cleanup(service, action, parameters=None, env=None):
            try:
                call(service, action, parameters, env or environment)
            except RuntimeError as error:
                failures.append(str(error))

        if own_profile:
            cleanup("iam", "delete-login-profile", env=deleter)
        if own_delegate:
            cleanup("organizations", "deregister-delegated-administrator", {"AccountId": delegate, "ServicePrincipal": "iam.amazonaws.com"})
        if own_features:
            if not trust_enabled:
                call("organizations", "enable-aws-service-access", {"ServicePrincipal": "iam.amazonaws.com"})
                trust_enabled = True
            cleanup("iam", "disable-organizations-root-sessions")
            cleanup("iam", "disable-organizations-root-credentials-management")
            fixture["final_features"] = call("iam", "list-organizations-features")
        if trust_enabled:
            cleanup("organizations", "disable-aws-service-access", {"ServicePrincipal": "iam.amazonaws.com"})
        fixture["final_iam_trusted_access"] = any(s["ServicePrincipal"] == "iam.amazonaws.com" for s in call("organizations", "list-aws-service-access-for-organization")["EnabledServicePrincipals"])
        fixture["final_iam_delegates"] = call("organizations", "list-delegated-administrators", {"ServicePrincipal": "iam.amazonaws.com"})
        fixture["cleanup_errors"] = failures
        fixture["cleanup"] = "Owned recovery profile and IAM delegation removed; root features and IAM trusted access restored to disabled." if not failures else "Cleanup failures require recovery."
        save()
        print(fixture["cleanup"], flush=True)
        if failures:
            raise RuntimeError("; ".join(failures))


if __name__ == "__main__":
    main()
