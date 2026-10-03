#!/usr/bin/env python3
"""Capture IAM's mandatory MFA protection for a user's own MFA devices."""

import argparse
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
from iam_mfa_probe import MFAProbe, ROOT, call, otp
from iam_outbound_identity_probe import session_environment


def run(p):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    user, other = p.user("self"), p.user("other")
    environment = p.key(user, "self")
    p.inline(user, json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:EnableMFADevice", "iam:DeactivateMFADevice", "iam:ResyncMFADevice"], "Resource": [user["Arn"], other["Arn"]]}]}))
    devices = []
    for label, owner in (("first", user), ("second", user), ("other", other)):
        devices.append(p.device("create_" + label, owner["UserName"], {"VirtualMFADeviceName": p.prefix + "-" + label}))
    first, second, other_device = devices
    time.sleep(15)
    if p.pair("self_enable_first_key", "enable-mfa-device", user["UserName"], *first, environment=environment)["code"] != "Success":
        raise RuntimeError("Initial self enrollment failed")
    time.sleep(15)
    p.pair("self_enable_second_key", "enable-mfa-device", user["UserName"], *second, environment=environment)
    p.pair("self_enable_duplicate_key", "enable-mfa-device", user["UserName"], *first, delta=4, environment=environment)
    p.request("self_deactivate_key", "deactivate-mfa-device", {"UserName": user["UserName"], "SerialNumber": first[0]}, environment)
    p.request("self_deactivate_missing_key", "deactivate-mfa-device", {"UserName": user["UserName"], "SerialNumber": "arn:aws:iam::" + p.account + ":mfa/" + p.prefix + "-missing"}, environment)
    p.pair("self_resync_key", "resync-mfa-device", user["UserName"], *first, delta=4, environment=environment)
    p.pair("other_enable_key", "enable-mfa-device", other["UserName"], *other_device, environment=environment)
    time.sleep(15)
    step = int(time.time()) // 30 + 5
    issued = p.request("issue_mfa_session", "get-session-token", {"SerialNumber": first[0], "TokenCode": otp(first[1], step), "DurationSeconds": 900}, environment, "sts", code_step=step)
    if issued["code"] != "Success":
        raise RuntimeError("MFA session failed")
    session = session_environment(issued["output"])
    p.pair("self_enable_second_session", "enable-mfa-device", user["UserName"], *second, delta=4, environment=session)
    p.request("self_deactivate_first_session", "deactivate-mfa-device", {"UserName": user["UserName"], "SerialNumber": first[0]}, session)
    p.request("self_deactivate_last_session", "deactivate-mfa-device", {"UserName": user["UserName"], "SerialNumber": second[0]}, session)
    time.sleep(15)
    p.pair("self_reenroll_key", "enable-mfa-device", user["UserName"], *first, delta=8, environment=environment)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/mfa_self_management.json')
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    p = MFAProbe(probe_args.output)
    p.probe_name = "scripts/aws/iam_mfa_self_management_probe.py"
    p.documentation.append("https://aws.amazon.com/security/security-bulletins/AWS-2023-001/")
    try:
        run(p)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
