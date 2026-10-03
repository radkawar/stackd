#!/usr/bin/env python3
"""Capture name replacement and its Organizations/contact effects, then restore.

Uses an existing CREATED member and temporary synthetic names. The original name
stays in a private recovery file until restoration is verified. No email, contact,
role, policy or account-state changes are requested.
"""

import datetime
import json
import os
import pathlib
import subprocess
import tempfile

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
    c = call("sts", "assume-role", {"RoleArn": f"arn:aws:iam::{target}:role/OrganizationAccountAccessRole", "RoleSessionName": "stackd-account-name", "DurationSeconds": 900})["Credentials"]
    env = dict(os.environ, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])
    original = call("account", "get-account-information", env=env)
    contact = call("account", "get-contact-information", env=env)["ContactInformation"]
    with tempfile.NamedTemporaryFile(mode="w", prefix="stackd-account-name-", suffix=".json", delete=False) as recovery:
        json.dump({"AccountId": target, "AccountName": original["AccountName"]}, recovery)
        recovery_path = pathlib.Path(recovery.name)
    print("Recovery name: "+str(recovery_path), flush=True)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS Account Management; existing CREATED commercial member; temporary synthetic account names",
               "initial": {"AccountId": "222222222222", "AccountState": original["AccountState"], "AccountCreatedDate": original["AccountCreatedDate"],
                           "OrganizationsJoinedTimestamp": member["JoinedTimestamp"],
                           "creation_matches_organizations": datetime.datetime.fromisoformat(original["AccountCreatedDate"]) == datetime.datetime.fromisoformat(member["JoinedTimestamp"]),
                           "joined_minus_created_seconds": (datetime.datetime.fromisoformat(member["JoinedTimestamp"]) - datetime.datetime.fromisoformat(original["AccountCreatedDate"])).total_seconds()},
               "observations": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/account/information.json'

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2)+"\n")

    try:
        for name, value in [("whitespace", "  Stackd Name Probe  "), ("replace", "Stackd Renamed"), ("blank", " "), ("brackets", "Stackd <Name>")]:
            row = {"case": name, "input": {"AccountName": value}}
            try:
                call("account", "put-account-name", row["input"], env, error_format="json")
                row["code"] = "Success"
            except AWSCLIError as error:
                parsed = error.details
                row.update(code=parsed["Code"], error=parsed)
            info = call("account", "get-account-information", env=env)
            org = call("organizations", "describe-account", {"AccountId": target})["Account"]
            row["output"] = {"AccountName": "<original>" if info["AccountName"] == original["AccountName"] else info["AccountName"], "AccountState": info["AccountState"], "AccountCreatedDate": info["AccountCreatedDate"]}
            row["organizations_name_matches"] = org["Name"] == info["AccountName"]
            row["creation_date_unchanged"] = info["AccountCreatedDate"] == original["AccountCreatedDate"]
            row["primary_contact_unchanged"] = call("account", "get-contact-information", env=env)["ContactInformation"] == contact
            fixture["observations"].append(row)
            save()
            print(name+": "+row["code"]+", organization matches: "+str(row["organizations_name_matches"]), flush=True)
        sdk = subprocess.run(["go", "run", str(pathlib.Path(__file__).with_name("account_name_sdk_probe.go")), "--account", target], env=env, capture_output=True, text=True, check=True)
        fixture["sdk_blank_error"] = json.loads(sdk.stdout)
        fixture["capture_complete"] = True
    finally:
        call("account", "put-account-name", {"AccountName": original["AccountName"]}, env)
        restored = call("account", "get-account-information", env=env) == original
        org_restored = call("organizations", "describe-account", {"AccountId": target})["Account"]["Name"] == member["Name"]
        fixture["cleanup"] = {"original_account_information_restored": restored, "original_organizations_name_restored": org_restored}
        save()
        if restored and org_restored:
            recovery_path.unlink()
        else:
            raise RuntimeError("Original account name not yet restored in both services; recovery name retained at "+str(recovery_path))


if __name__ == "__main__":
    main()
