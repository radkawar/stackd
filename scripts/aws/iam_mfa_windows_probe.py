#!/usr/bin/env python3
"""Measure MFA windows with independent devices and users to isolate failed attempts."""

import argparse
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
from iam_mfa_probe import MFAProbe, ROOT, call, otp


def run(p):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    fixtures = []
    offsets = (-3, -2, -1, 0, 1, 2, 3)
    p.eligibility["offsets"] = offsets
    for index, delta in enumerate(offsets):
        user = p.user("window" + str(index))
        environment = p.key(user, "window" + str(index))
        name = user["UserName"]
        serial, seed = p.device("create_" + str(index), name, {"VirtualMFADeviceName": p.prefix + "-window" + str(index)})
        result = p.pair("enable_offset_" + str(delta), "enable-mfa-device", name, serial, seed, 0)
        if result["code"] == "Success":
            fixtures.append((delta, environment, serial, seed))
    # Avoid observing enrollment propagation as a code-window rejection.
    time.sleep(15)
    for delta, environment, serial, seed in fixtures:
        for index in range(2):
            step = int(time.time()) // 30 + delta
            p.request("use_offset_" + str(delta) + "_" + str(index), "get-session-token", {"DurationSeconds": 900, "SerialNumber": serial, "TokenCode": otp(seed, step)}, environment, "sts", code_step_offset=delta, code_step=step)
            time.sleep(2)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/mfa_verification.json')
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    p = MFAProbe(args.output)
    p.probe_name = "scripts/aws/iam_mfa_windows_probe.py"
    p.eligibility["window_mode"] = "verification"
    try:
        run(p)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
