#!/usr/bin/env python3
"""Capture contact semantics using an existing Organizations-created test member.

Temporarily fills one absent alternate-contact slot with a reserved .invalid email
address, updates it and deletes it. Existing alternate contacts are untouched.
Primary contact and account-name writes use exactly their existing values.
Private contact details are omitted from the fixture. No primary-email API is used.
"""

import datetime
import copy
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
    members = [a for a in call("organizations", "list-accounts")["Accounts"]
               if a["Id"] != management and a["State"] == "ACTIVE" and a["JoinedMethod"] == "CREATED"]
    target = members[0]["Id"]
    role = f"arn:aws:iam::{target}:role/OrganizationAccountAccessRole"
    c = call("sts", "assume-role", {"RoleArn": role, "RoleSessionName": "stackd-contact-probe", "DurationSeconds": 900})["Credentials"]
    env = dict(os.environ, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/account/contacts.json'
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS Account Management; existing CREATED member",
               "capture_complete": False, "observations": []}
    contact_type = None
    changed = False

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2).replace(management, "111111111111").replace(target, "222222222222") + "\n")

    def observe(case, operation, parameters=None, private=False, summarize=None, caller_env=None):
        row = {"case": case, "operation": operation, "input": copy.deepcopy(parameters or {}),
               "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        if private:
            row["input"] = {"redacted": True, "fields": sorted((parameters or {}).keys())}
        result = None
        try:
            result = call("account", operation, parameters, caller_env or env, paginate=False, error_format="json")
            row["code"] = "Success"
            if summarize:
                row["summary"] = summarize(result)
            elif not private:
                row["output"] = result
        except AWSCLIError as error:
            parsed = error.details
            row["code"] = parsed["Code"]
            if not private:
                row["error"] = parsed
        fixture["observations"].append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return result

    try:
        for kind in ["operations", "OTHER", "Billing"]:
            observe("type_"+kind, "get-alternate-contact", {"AlternateContactType": kind}, private=True,
                    summarize=lambda x: {"AlternateContactType": x["AlternateContact"]["AlternateContactType"]})
        info = observe("account_information", "get-account-information", private=True,
                       summarize=lambda x: {"AccountId": x.get("AccountId"), "AccountState": x.get("AccountState"),
                                            "AccountCreatedDate": x.get("AccountCreatedDate"), "AccountNamePresent": bool(x.get("AccountName"))})
        if info:
            observe("put_unchanged_account_name", "put-account-name", {"AccountName": info["AccountName"]}, private=True)
            observe("account_information_after_unchanged_name", "get-account-information", private=True, summarize=lambda x: {"unchanged": x == info})
        primary = observe("primary_contact", "get-contact-information", private=True,
                          summarize=lambda x: {"fields": sorted(x.get("ContactInformation", {}).keys())})
        if primary:
            observe("put_unchanged_primary_contact", "put-contact-information", primary, private=True)
            observe("primary_contact_after_unchanged_write", "get-contact-information", private=True, summarize=lambda x: {"unchanged": x == primary})
        for kind in ["OPERATIONS", "SECURITY", "BILLING"]:
            result = observe("initial_"+kind.lower(), "get-alternate-contact", {"AlternateContactType": kind}, private=True,
                             summarize=lambda x: {"fields": sorted(x["AlternateContact"].keys())})
            if result is None and fixture["observations"][-1]["code"] == "ResourceNotFoundException":
                contact_type = kind
                break
        if contact_type is None:
            fixture["limitation"] = "All alternate contacts already exist; existing contacts were left untouched."
            return
        fixture["contact_type"] = contact_type
        query = {"AlternateContactType": contact_type}
        observe("missing_alternate_contact", "get-alternate-contact", query)
        observe("delete_missing_alternate_contact", "delete-alternate-contact", query)
        changed = True
        payload = dict(query, Name="  Stackd Contact Probe  ", Title="  Operations  ",
                       EmailAddress="  Probe+ops@Example.invalid  ", PhoneNumber=" +1 (202) 555-0100 ")
        observe("create_alternate_contact", "put-alternate-contact", payload)
        observe("get_created_alternate_contact", "get-alternate-contact", query)
        payload.update(Name="Stackd Updated", Title="Contact Probe", EmailAddress="probe2@example.invalid", PhoneNumber="2025550101")
        observe("replace_alternate_contact", "put-alternate-contact", payload)
        observe("get_replaced_alternate_contact", "get-alternate-contact", query)
        policy = {"Statement": {"Effect": "Allow", "Action": "account:*AlternateContact", "Resource": "*", "Condition": {"ForAnyValue:StringEquals": {"account:AlternateContactTypes": contact_type}}}}
        limited = call("sts", "assume-role", {"RoleArn": role, "RoleSessionName": "stackd-contact-condition", "DurationSeconds": 900, "Policy": json.dumps(policy)})["Credentials"]
        limited_env = dict(env, AWS_ACCESS_KEY_ID=limited["AccessKeyId"], AWS_SECRET_ACCESS_KEY=limited["SecretAccessKey"], AWS_SESSION_TOKEN=limited["SessionToken"])
        observe("contact_condition_allow", "get-alternate-contact", query, caller_env=limited_env)
        other = next(k for k in ["BILLING", "OPERATIONS", "SECURITY"] if k != contact_type)
        observe("contact_condition_deny", "get-alternate-contact", {"AlternateContactType": other}, caller_env=limited_env)
        observe("delete_alternate_contact", "delete-alternate-contact", query)
        observe("get_deleted_alternate_contact", "get-alternate-contact", query)
        observe("delete_alternate_contact_again", "delete-alternate-contact", query)
        fixture["capture_complete"] = True
    finally:
        if changed:
            query = {"AlternateContactType": contact_type}
            current = observe("cleanup_read", "get-alternate-contact", query)
            if current is not None:
                observe("cleanup_delete", "delete-alternate-contact", query)
            observe("cleanup_final", "get-alternate-contact", query)
            fixture["cleanup"] = {"alternate_contact_restored_absent": fixture["observations"][-1]["code"] == "ResourceNotFoundException"}
        else:
            fixture["cleanup"] = {"alternate_contacts_unchanged": True}
        save()


if __name__ == "__main__":
    main()
