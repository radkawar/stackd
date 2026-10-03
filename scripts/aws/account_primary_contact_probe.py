#!/usr/bin/env python3
"""Capture primary-contact normalization and optional-field replacement.

Uses an existing CREATED member. Changes only surrounding whitespace, country
code case, blank fields, and omission of an existing optional StateOrRegion field. Restores
the exact original contact. Private values stay in a mode-0600 recovery file
until restoration succeeds; the versioned fixture contains comparisons only.
"""

import datetime
import json
import os
import pathlib
import tempfile

from aws_cli import AWSCLIError, call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    management = require_account(probe_args.account)["Account"]
    target = next(a["Id"] for a in call("organizations", "list-accounts")["Accounts"]
                  if a["Id"] != management and a["State"] == "ACTIVE" and a["JoinedMethod"] == "CREATED")
    c = call("sts", "assume-role", {"RoleArn": f"arn:aws:iam::{target}:role/OrganizationAccountAccessRole", "RoleSessionName": "stackd-primary-contact", "DurationSeconds": 900})["Credentials"]
    env = dict(os.environ, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])
    original = call("account", "get-contact-information", env=env)["ContactInformation"]
    with tempfile.NamedTemporaryFile(mode="w", prefix="stackd-primary-contact-", suffix=".json", delete=False) as recovery:
        json.dump({"AccountId": target, "ContactInformation": original}, recovery)
        recovery_path = pathlib.Path(recovery.name)
    print("Recovery contact: "+str(recovery_path), flush=True)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS Account Management, existing CREATED member; private values replaced with native comparisons",
               "observations": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/account/primary_contact.json'

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2)+"\n")

    try:
        cases = []
        for field in sorted(original):
            if field == "CountryCode":
                continue
            payload = dict(original)
            payload[field] = " " + payload[field] + " "
            cases.append(("whitespace_"+field, payload))
            cases.append(("blank_"+field, dict(original, **{field: " "})))
        payload = dict(original, PhoneNumber=original["PhoneNumber"]+" ")
        cases.append(("trailing_whitespace_PhoneNumber", payload))
        payload = dict(original, CountryCode=original["CountryCode"].lower())
        cases.append(("lowercase_country", payload))
        if "StateOrRegion" in original:
            payload = dict(original)
            del payload["StateOrRegion"]
            cases.append(("omit_state_or_region", payload))
        for name, payload in cases:
            row = {"case": name}
            try:
                call("account", "put-contact-information", {"ContactInformation": payload}, env, error_format="json")
                row["code"] = "Success"
            except AWSCLIError as error:
                parsed = error.details
                row["code"] = parsed["Code"]
                row["reason"] = parsed.get("reason")
                row["invalid_fields"] = [f["name"] for f in parsed.get("fieldList", [])]
                message = parsed["Message"]
                for key, value in sorted(original.items(), key=lambda item: len(item[1]), reverse=True):
                    message = message.replace(value, "<"+key+">")
                row["message"] = message
            result = call("account", "get-contact-information", env=env)["ContactInformation"]
            row["matches_input"] = {key: result.get(key) == val for key, val in payload.items()}
            row["matches_original"] = {key: result.get(key) == val for key, val in original.items()}
            row["response_fields"] = sorted(result)
            row["empty_fields"] = sorted(k for k, v in result.items() if v == "")
            fixture["observations"].append(row)
            save()
            print(name+": "+row["code"], flush=True)
            call("account", "put-contact-information", {"ContactInformation": original}, env)
        fixture["capture_complete"] = True
    finally:
        call("account", "put-contact-information", {"ContactInformation": original}, env)
        restored = call("account", "get-contact-information", env=env)["ContactInformation"] == original
        fixture["cleanup"] = {"original_contact_restored": restored}
        save()
        if restored:
            recovery_path.unlink()
        else:
            raise RuntimeError("Original primary contact was not restored; recovery contact retained at "+str(recovery_path))


if __name__ == "__main__":
    main()
