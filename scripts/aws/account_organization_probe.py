#!/usr/bin/env python3
"""Capture Account Organizations-mode access, restoring trust and delegation.

Uses one existing CREATED member and its OrganizationAccountAccessRole. Changes
only Account Management trusted access and a delegation created by this run.
It does not modify regions, contacts, tags, account names or primary email.
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
    organization = call("organizations", "describe-organization")["Organization"]
    members = [a for a in call("organizations", "list-accounts")["Accounts"]
               if a["Id"] != management and a["State"] == "ACTIVE" and a["JoinedMethod"] == "CREATED"]
    target = members[0]["Id"]
    principal = "account.amazonaws.com"
    trusted = any(s["ServicePrincipal"] == principal for s in call("organizations", "list-aws-service-access-for-organization")["EnabledServicePrincipals"])
    delegates = call("organizations", "list-delegated-administrators", {"ServicePrincipal": principal})["DelegatedAdministrators"]
    if delegates:
        raise RuntimeError("An existing Account Management delegate is configured; leave its ownership unchanged.")
    region = "us-east-1"
    role = f"arn:aws:iam::{target}:role/OrganizationAccountAccessRole"
    issuer_env = dict(os.environ, AWS_REGION=region, AWS_DEFAULT_REGION=region, AWS_STS_REGIONAL_ENDPOINTS="regional")
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS Account Management and Organizations, existing CREATED member",
               "capture_complete": False, "observations": []}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/account/organization_regions.json'
    changed_trust = changed_delegate = False

    def save():
        text = json.dumps(fixture, indent=2).replace(management, "111111111111").replace(target, "222222222222").replace(organization["Id"], "o-exampleorg")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")

    def observe(case, service, operation, parameters=None, env=None):
        row = {"case": case, "service": service, "operation": operation, "input": parameters or {},
               "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        try:
            row["output"] = call(service, operation, parameters, env, paginate=False, error_format="json")
            row["code"] = "Success"
        except AWSCLIError as error:
            row["error"] = error.details
            row["code"] = row["error"]["Code"]
        fixture["observations"].append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return row.get("output")

    def session(policy=None):
        args = {"RoleArn": role, "RoleSessionName": "stackd-account-org", "DurationSeconds": 900}
        if policy is not None:
            args["Policy"] = json.dumps(policy)
        c = call("sts", "assume-role", args, issuer_env)["Credentials"]
        return dict(issuer_env, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])

    try:
        member_env = session()
        query = {"AccountId": target, "RegionName": region}
        observe("initial_management_target", "account", "get-region-opt-status", query)
        observe("initial_member_explicit_self", "account", "get-region-opt-status", query, member_env)
        if not trusted:
            changed_trust = True
            call("organizations", "enable-aws-service-access", {"ServicePrincipal": principal})
        observe("trusted_management_target", "account", "get-region-opt-status", query)
        observe("trusted_management_explicit_self", "account", "get-region-opt-status", {"AccountId": management, "RegionName": region})
        observe("trusted_member_explicit_self", "account", "get-region-opt-status", query, member_env)
        changed_delegate = True
        call("organizations", "register-delegated-administrator", {"AccountId": target, "ServicePrincipal": principal})
        observe("delegated_member_explicit_self", "account", "get-region-opt-status", query, member_env)
        resource = f'arn:aws:account::{management}:account/{organization["Id"]}/{target}'
        limited = session({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "account:GetRegionOptStatus", "Resource": resource, "Condition": {"StringEquals": {"account:TargetRegion": region}}}]})
        observe("delegated_scoped_allow", "account", "get-region-opt-status", query, limited)
        observe("delegated_wrong_region", "account", "get-region-opt-status", {"AccountId": target, "RegionName": "eu-west-1"}, limited)
        observe("delegated_wrong_arn_mode", "account", "get-region-opt-status", {"RegionName": region}, limited)
        fixture["capture_complete"] = True
    finally:
        if changed_delegate:
            call("organizations", "deregister-delegated-administrator", {"AccountId": target, "ServicePrincipal": principal})
        if changed_trust:
            call("organizations", "disable-aws-service-access", {"ServicePrincipal": principal})
        final_delegates = call("organizations", "list-delegated-administrators", {"ServicePrincipal": principal})["DelegatedAdministrators"]
        final_trust = any(s["ServicePrincipal"] == principal for s in call("organizations", "list-aws-service-access-for-organization")["EnabledServicePrincipals"])
        fixture["cleanup"] = {"delegates_restored": final_delegates == delegates, "trusted_access_restored": final_trust == trusted}
        save()
        if final_delegates != delegates or final_trust != trusted:
            raise RuntimeError("Account trusted access or delegation did not restore")


if __name__ == "__main__":
    main()
