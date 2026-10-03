#!/usr/bin/env python3
"""Locate the IAM enrollment code window using a fresh owned device per attempt."""

import argparse
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
from iam_mfa_probe import MFAProbe, ROOT, call


def run(p, anchor=False):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    user = p.user("pair-window")
    name = user["UserName"]
    if anchor:
        serial, seed = p.device("create", name, {"VirtualMFADeviceName": p.prefix + "-anchor"})
        p.pair("enable_anchor", "enable-mfa-device", name, serial, seed, 600)
        for delta in (1200, 1800, 1802):
            p.pair("resync_anchor_" + str(delta), "resync-mfa-device", name, serial, seed, delta)
        p.request("deactivate_anchor", "deactivate-mfa-device", {"UserName": name, "SerialNumber": serial})
        p.pair("reenroll_anchor", "enable-mfa-device", name, serial, seed, 1804)
        return
    attempt = 0

    def accepts(delta):
        nonlocal attempt
        attempt += 1
        serial, seed = p.device("create_" + str(attempt), name, {"VirtualMFADeviceName": p.prefix + "-" + str(attempt)})
        # Keep request transit away from the counter boundary.
        remaining = 30 - time.time() % 30
        if remaining < 3:
            time.sleep(remaining + 0.2)
        result = p.pair("offset_" + str(delta) + "_" + str(attempt), "enable-mfa-device", name, serial, seed, delta)
        if result["code"] not in ("Success", "InvalidAuthenticationCode"):
            raise RuntimeError("Unexpected enrollment response: " + result["code"])
        if result["code"] == "Success":
            p.request("deactivate_" + str(attempt), "deactivate-mfa-device", {"UserName": name, "SerialNumber": serial})
        deleted = p.request("delete_" + str(attempt), "delete-virtual-mfa-device", {"SerialNumber": serial})
        if deleted["code"] != "Success":
            raise RuntimeError("Device deletion failed")
        return result["code"] == "Success"

    for sign in (1, -1):
        low, high = 0, 1440
        if not accepts(0) or accepts(sign * high):
            raise RuntimeError("Window search endpoints changed")
        while high - low > 1:
            middle = (low + high) // 2
            if accepts(sign * middle):
                low = middle
            else:
                high = middle
        accepts(sign * low)
        accepts(sign * high)
        p.eligibility["positive" if sign == 1 else "negative"] = {"accepted_offset": sign * low, "rejected_offset": sign * high}


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/mfa_pair_window.json')
    parser.add_argument("--anchor", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    p = MFAProbe(args.output)
    p.probe_name = "scripts/aws/iam_mfa_pair_window_probe.py"
    try:
        run(p, args.anchor)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
