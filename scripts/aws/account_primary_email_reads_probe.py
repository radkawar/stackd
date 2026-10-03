#!/usr/bin/env python3
"""Capture primary-email reads and authorization modes without sending email.

Temporarily enables Account trusted access if needed and restores it. Primary
email values remain private; the fixture compares them to Organizations metadata.
"""

import datetime
import json
import os
import pathlib

from aws_cli import AWSCLIError, call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    management = require_account(probe_args.account)["Account"]
    member = next(a for a in call("organizations", "list-accounts")["Accounts"]
                  if a["Id"] != management and a["State"] == "ACTIVE" and a["JoinedMethod"] == "CREATED")
    target = member["Id"]
    c = call("sts", "assume-role", {"RoleArn": f"arn:aws:iam::{target}:role/OrganizationAccountAccessRole", "RoleSessionName": "stackd-primary-email-reads", "DurationSeconds": 900})["Credentials"]
    env = dict(os.environ, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])
    services = call("organizations", "list-aws-service-access-for-organization")["EnabledServicePrincipals"]
    principal = "account.amazonaws.com"
    enabled = any(s["ServicePrincipal"] == principal for s in services)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS Account Management; commercial organization; read-only primary-email APIs",
               "initial_trusted_access": enabled, "observations": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/account/primary_email_reads.json'

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2).replace(management, "111111111111").replace(target, "222222222222")+"\n")

    def observe(name, operation, parameters, caller="management"):
        row = {"case": name, "operation": operation, "input": parameters, "caller": caller}
        try:
            result = call("account", operation, parameters, env if caller == "member" else None, error_format="json")
            row["code"] = "Success"
            if "PrimaryEmail" in result:
                row["output"] = {"email_matches_organizations": result["PrimaryEmail"] == member["Email"]}
            else:
                row["output"] = result
        except AWSCLIError as error:
            parsed = error.details
            row.update(code=parsed["Code"], error=parsed)
        fixture["observations"].append(row)
        save()
        print(name+": "+row["code"], flush=True)

    try:
        if not enabled:
            observe("email_without_trusted_access", "get-primary-email", {"AccountId": target})
            call("organizations", "enable-aws-service-access", {"ServicePrincipal": principal})
        for caller, account_id, label in [("management", target, "member"), ("management", management, "management_self"), ("member", target, "member_self")]:
            observe("email_"+label, "get-primary-email", {"AccountId": account_id}, caller)
            observe("status_"+label, "get-primary-email-update-status", {"AccountId": account_id}, caller)
        for caller in ["management", "member"]:
            observe("status_"+caller+"_standalone", "get-primary-email-update-status", {}, caller)
        fixture["capture_complete"] = True
    finally:
        if not enabled:
            call("organizations", "disable-aws-service-access", {"ServicePrincipal": principal})
        current = call("organizations", "list-aws-service-access-for-organization")["EnabledServicePrincipals"]
        restored = any(s["ServicePrincipal"] == principal for s in current) == enabled
        fixture["cleanup"] = {"trusted_access_restored": restored, "primary_email_operations_read_only": True}
        save()
        if not restored:
            raise RuntimeError("Account trusted access did not return to its original setting")


if __name__ == "__main__":
    main()
