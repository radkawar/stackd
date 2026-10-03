#!/usr/bin/env python3
"""Capture MFA propagation, TOTP windows and accepted-pair reuse on owned resources."""

import argparse
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
from iam_mfa_probe import MFAProbe, ROOT, call, otp


def reuse(p):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    user = p.user("reuse")
    environment = p.key(user, "reuse")
    name = user["UserName"]
    serial, seed = p.device("create", name, {"VirtualMFADeviceName": p.prefix + "-reuse"})
    result = p.pair("enable", "enable-mfa-device", name, serial, seed)
    if result["code"] != "Success":
        raise RuntimeError("Enrollment failed")
    # Leave enrollment propagation and the enrolled counters behind, without
    # authentication attempts that could change the device's recent-use state.
    print("waiting for fresh counters", flush=True)
    time.sleep(35)
    time.sleep(30)
    step = int(time.time()) // 30
    for index, delta in enumerate((0, 1, 0, 2, 1, 2)):
        p.request("reuse_" + str(index), "get-session-token", {"DurationSeconds": 900, "SerialNumber": serial, "TokenCode": otp(seed, step + delta)}, environment, "sts", code_step=step + delta)
        time.sleep(2)
    for offset in (1, 2, 3, 4):
        second = step + offset
        p.request("resync_after_use_" + str(offset), "resync-mfa-device", {"UserName": name, "SerialNumber": serial, "AuthenticationCode1": otp(seed, second - 1), "AuthenticationCode2": otp(seed, second)}, second_step=second)


def run(p):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    user = p.user("timing")
    environment = p.key(user, "timing")
    name = user["UserName"]
    serial, seed = p.device("create", name, {"VirtualMFADeviceName": p.prefix + "-timing"})

    def auth(case, delta):
        step = int(time.time()) // 30 + delta
        return p.request(case, "get-session-token", {"DurationSeconds": 900, "SerialNumber": serial, "TokenCode": otp(seed, step)}, environment, "sts", code_step_offset=delta, code_step=step)["code"]

    def pair(case, action, delta=0, second=None):
        second = second if second is not None else int(time.time()) // 30 + delta
        return p.request(case, action, {"UserName": name, "SerialNumber": serial, "AuthenticationCode1": otp(seed, second - 1), "AuthenticationCode2": otp(seed, second)}, second_step_offset=delta, second_step=second)["code"], second

    code, initial = pair("enable", "enable-mfa-device")
    if code != "Success":
        raise RuntimeError("Enrollment failed")
    for attempt in range(30):
        if auth("enrollment_propagation_" + str(attempt), 0) == "Success":
            break
        time.sleep(1)
    else:
        raise RuntimeError("MFA did not become usable during observation")
    for delta in (-5, -4, -3, -2, -1, 0, 0, 1, 2, 3, 4, 5):
        auth("initial_window_" + str(len(p.observations)), delta)
    pair("resync_enrollment_pair", "resync-mfa-device", second=initial)
    code, future = pair("resync_future", "resync-mfa-device", 10)
    if code != "Success":
        raise RuntimeError("Future resynchronization failed")
    for attempt in range(12):
        auth("resync_old_" + str(attempt), 0)
        auth("resync_new_" + str(attempt), 10)
        time.sleep(1)
    for delta in (7, 8, 9, 10, 10, 11, 12, 13):
        auth("resynced_window_" + str(len(p.observations)), delta)
    pair("resync_same_pair", "resync-mfa-device", second=future)
    pair("resync_overlap_pair", "resync-mfa-device", second=future + 1)
    pair("resync_next_pair", "resync-mfa-device", second=future + 2)
    pair("resync_backwards", "resync-mfa-device")
    p.request("deactivate", "deactivate-mfa-device", {"UserName": name, "SerialNumber": serial})
    for attempt in range(12):
        auth("deactivation_propagation_" + str(attempt), 10)
        time.sleep(1)
    pair("reenroll_same_pair", "enable-mfa-device", second=future + 2)
    pair("reenroll_overlap_pair", "enable-mfa-device", second=future + 3)
    pair("reenroll_next_pair", "enable-mfa-device", second=future + 4)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/mfa_time.json')
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    p = MFAProbe(args.output)
    p.probe_name = "scripts/aws/iam_mfa_time_probe.py"
    p.eligibility["mode"] = "reuse" if args.reuse else "propagation"
    try:
        (reuse if args.reuse else run)(p)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
