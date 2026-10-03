#!/usr/bin/env python3
"""Capture Account Management region state and its regional STS boundary.

Reads the management account and an existing Organizations-created member.
--lifecycle enables one initially disabled member region, waits for completion,
checks STS behavior and restores DISABLED. It creates no compute resources and
does not change management-account regions or Organizations trusted access.
"""

import argparse
import datetime
import json
import os
import pathlib
import time

from aws_cli import call, observe as observe_cli


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifecycle", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    management = require_account(args.account)["Account"]
    members = [a for a in call("organizations", "list-accounts")["Accounts"]
               if a["Id"] != management and a["State"] == "ACTIVE" and a["JoinedMethod"] == "CREATED"]
    target = members[0]["Id"]
    role = f"arn:aws:iam::{target}:role/OrganizationAccountAccessRole"
    issuer_env = dict(os.environ, AWS_DEFAULT_REGION="us-west-2", AWS_REGION="us-west-2", AWS_STS_REGIONAL_ENDPOINTS="regional")
    credentials = call("sts", "assume-role", {"RoleArn": role, "RoleSessionName": "stackd-region-probe", "DurationSeconds": 3600}, issuer_env)["Credentials"]
    member_env = dict(os.environ, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"], AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"], AWS_SESSION_TOKEN=credentials["SessionToken"])
    destination = root / '.stackd/probes/account/regions.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS Account Management and regional STS; existing commercial management account and Organizations-created member",
               "capture_complete": False, "lifecycle": args.lifecycle, "member_session_region": "us-west-2", "observations": []}
    changed = False
    region = None

    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in {"AccessKeyId", "SecretAccessKey", "SessionToken"}}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    def save():
        text = json.dumps(fixture, indent=2).replace(management, "111111111111").replace(target, "222222222222")
        destination.write_text(text + "\n")

    def observe(case, service, operation, parameters=None, env=None):
        row = {"case": case, "service": service, "operation": operation, "input": parameters or {}, "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        started = time.monotonic()
        row.update(observe_cli(service, operation, parameters, env, paginate=False))
        result = row.get("output")
        if result is not None:
            row.update(output=clean(result))
        row["request_seconds"] = round(time.monotonic() - started, 3)
        fixture["observations"].append(row)
        save()
        print(case + ": " + row["code"] + (" " + result.get("RegionOptStatus", "") if result else ""), flush=True)
        return result

    def status(case):
        result = observe(case, "account", "get-region-opt-status", {"RegionName": region}, member_env)
        if result is None:
            raise RuntimeError("Unable to inspect the existing region transition")
        return result["RegionOptStatus"]

    def wait_for(expected, label):
        deadline = time.monotonic() + 900
        index = 0
        while True:
            current = status(f"{label}_{index}")
            if current == expected:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Region {region} is still {current}, awaiting {expected}")
            index += 1
            time.sleep(15)

    def sts_state(label):
        observe(label + "_member_identity", "sts", "get-caller-identity", env=dict(member_env, AWS_DEFAULT_REGION=region, AWS_REGION=region))
        issued = observe(label + "_assume_into_member", "sts", "assume-role", {"RoleArn": role, "RoleSessionName": "stackd-regional-boundary", "DurationSeconds": 900}, dict(os.environ, AWS_DEFAULT_REGION=region, AWS_REGION=region))

        if issued:
            c = issued["Credentials"]
            fresh = dict(os.environ, AWS_DEFAULT_REGION=region, AWS_REGION=region, AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"])
            observe(label + "_fresh_member_identity", "sts", "get-caller-identity", env=fresh)

    try:
        observe("member_issuer_region_identity", "sts", "get-caller-identity", env=dict(member_env, AWS_DEFAULT_REGION="us-west-2", AWS_REGION="us-west-2"))
        owner = observe("management_regions", "account", "list-regions")
        member = observe("member_regions", "account", "list-regions", env=member_env)
        if owner is None or member is None:
            raise RuntimeError("Cannot capture initial region states")
        enabled = {r["RegionName"] for r in owner["Regions"] if r["RegionOptStatus"] == "ENABLED"}
        region = next(r["RegionName"] for r in member["Regions"] if r["RegionOptStatus"] == "DISABLED" and r["RegionName"] in enabled)
        fixture["region"] = region
        observe("management_explicit_self", "account", "get-region-opt-status", {"RegionName": region, "AccountId": management})
        observe("management_target_member", "account", "get-region-opt-status", {"RegionName": region, "AccountId": target})
        observe("member_explicit_self", "account", "get-region-opt-status", {"RegionName": region, "AccountId": target}, member_env)
        for name in ["us-east-1", "unknown-region", "cn-north-1", "US-EAST-1"]:
            observe("member_get_" + name, "account", "get-region-opt-status", {"RegionName": name}, member_env)
        for limit in [1, 2]:
            page = observe(f"page_{limit}", "account", "list-regions", {"MaxResults": limit}, member_env)
            if page and page.get("NextToken"):
                observe(f"page_{limit}_next", "account", "list-regions", {"MaxResults": limit, "NextToken": page["NextToken"]}, member_env)
        observe("filter_disabled", "account", "list-regions", {"RegionOptStatusContains": ["DISABLED"]}, member_env)
        observe("filter_default", "account", "list-regions", {"RegionOptStatusContains": ["ENABLED_BY_DEFAULT"]}, member_env)
        observe("filter_empty", "account", "list-regions", {"RegionOptStatusContains": []}, member_env)
        observe("invalid_token", "account", "list-regions", {"NextToken": "invalid-token"}, member_env)
        sts_state("disabled")
        if args.lifecycle:
            # All following mutations are confined to this initially disabled region.
            changed = True
            observe("enable", "account", "enable-region", {"RegionName": region}, member_env)
            status("after_enable")
            observe("enable_again_pending", "account", "enable-region", {"RegionName": region}, member_env)
            observe("disable_while_enabling", "account", "disable-region", {"RegionName": region}, member_env)
            sts_state("enabling")
            wait_for("ENABLED", "wait_enabled")
            sts_state("enabled")
            observe("enable_again_enabled", "account", "enable-region", {"RegionName": region}, member_env)
            observe("disable", "account", "disable-region", {"RegionName": region}, member_env)
            status("after_disable")
            observe("disable_again_pending", "account", "disable-region", {"RegionName": region}, member_env)
            observe("enable_while_disabling", "account", "enable-region", {"RegionName": region}, member_env)
            sts_state("disabling")
            wait_for("DISABLED", "wait_disabled")
            sts_state("restored")
            # Region metadata and regional credential recognition converge independently.
            deadline = time.monotonic() + 600
            index = 0
            while True:
                observe(f"wait_auth_disabled_{index}", "sts", "get-caller-identity",
                        env=dict(member_env, AWS_DEFAULT_REGION=region, AWS_REGION=region))
                if fixture["observations"][-1]["code"] == "InvalidClientTokenId":
                    break
                if time.monotonic() >= deadline:
                    fixture["authentication_convergence"] = "Still accepted 600 seconds after DISABLED; right-censored observation."
                    break
                index += 1
                time.sleep(15)
            observe("disable_again_disabled", "account", "disable-region", {"RegionName": region}, member_env)
        fixture["capture_complete"] = True
    finally:
        if changed:
            current = status("cleanup_status")
            if current == "ENABLING":
                wait_for("ENABLED", "cleanup_wait_enabled")
                current = "ENABLED"
            if current == "ENABLED":
                observe("cleanup_disable", "account", "disable-region", {"RegionName": region}, member_env)
                current = "DISABLING"
            if current != "DISABLED":
                wait_for("DISABLED", "cleanup_wait_disabled")
            fixture["final_state"] = status("final_state")
        fixture["cleanup"] = "Selected member region restored to DISABLED; no compute resources requested, management regions and Organizations configuration unchanged." if changed else "Read-only probe; no resource or account-setting changes."
        save()


if __name__ == "__main__":
    main()
