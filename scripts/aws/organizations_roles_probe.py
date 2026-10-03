#!/usr/bin/env python3
"""Read the initial access and service-linked roles of an existing organization.

Uses a short STS session and makes no resource or policy mutations. This does
not establish fresh account creation timing or prove the role was never edited.
"""

import datetime
import json
import os

from aws_cli import call
from organizations_inputs_probe import probe_parser, verified_account, capture_path


def role_state(name, env=None):
    role = call("iam", "get-role", {"RoleName": name}, env)["Role"]
    attached = call("iam", "list-attached-role-policies", {"RoleName": name}, env)
    inline = call("iam", "list-role-policies", {"RoleName": name}, env)
    # Assumption itself updates last-used telemetry. Compare role semantics;
    # IDs, dates and session credentials are not fixture data.
    role = {key: value for key, value in role.items()
            if key not in {"RoleId", "CreateDate", "RoleLastUsed"}}
    return {"Role": role, "AttachedPolicies": attached["AttachedPolicies"],
            "InlinePolicyNames": inline["PolicyNames"]}


def main():
    args = probe_parser("organizations_roles.json").parse_args()
    verified_account(args.account)
    organization = call("organizations", "describe-organization")["Organization"]
    management = organization["MasterAccountId"]
    accounts = call("organizations", "list-accounts")["Accounts"]
    member = next(a for a in accounts if a["JoinedMethod"] == "CREATED" and a["State"] == "ACTIVE")
    name = "OrganizationAccountAccessRole"
    assumed = call("sts", "assume-role", {
        "RoleArn": f"arn:aws:iam::{member['Id']}:role/{name}",
        "RoleSessionName": "stackd-read-access-role", "DurationSeconds": 900,
    })
    credentials = assumed["Credentials"]
    env = dict(os.environ, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
               AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
               AWS_SESSION_TOKEN=credentials["SessionToken"])
    access = role_state(name, env)
    access["SessionArn"] = call("sts", "get-caller-identity", env=env)["Arn"]
    observations = {
        "AccessRole": access,
        "MemberServiceRole": role_state("AWSServiceRoleForOrganizations", env),
        "ManagementServiceRole": role_state("AWSServiceRoleForOrganizations"),
    }
    normalized = json.dumps(observations).replace(management, "111111111111").replace(member["Id"], "222222222222")
    fixture = {
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "Existing active AWS Organizations-created commercial member account and ALL-features management account; management-account STS AssumeRole and IAM reads",
        "comparison": "Role paths/names/trust/descriptions/session durations, managed attachments, inline policy names and usable access-role identity; account IDs normalized",
        "limitations": "Existing roles may have been edited since creation. Fresh creation, custom names, billing-mode provisioning, initialization delay, deletion and billing settings were not probed.",
        "observations": json.loads(normalized),
        "cleanup": "No resources created or policies changed. Temporary STS credentials remain only in memory and expire after 900 seconds.",
    }
    destination = capture_path(args.output)
    destination.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
