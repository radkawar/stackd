#!/usr/bin/env python3
"""Isolate invalid-code bursts from MFA enrollment and synchronization changes."""

import argparse
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
from iam_mfa_probe import MFAProbe, ROOT, call, otp


def run(p, args):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    cases = []
    for count, quiet in ((n, q) for n in args.counts for q in args.quiet_seconds):
        label = "failures_" + str(count)
        if len(args.quiet_seconds) > 1:
            label += "_quiet_" + str(quiet)
        user = p.user(label)
        environment = p.key(user, label)
        environment["AWS_MAX_ATTEMPTS"] = "1"
        serial, seed = p.device("create_" + label, user["UserName"], {"VirtualMFADeviceName": p.prefix + "-" + label})
        if p.pair("enable_" + label, "enable-mfa-device", user["UserName"], serial, seed)["code"] != "Success":
            raise RuntimeError("Enrollment failed")
        sibling = None
        if args.sibling:
            sibling = p.device("create_sibling_" + label, user["UserName"], {"VirtualMFADeviceName": p.prefix + "-sibling-" + label})
            if p.pair("enable_sibling_" + label, "enable-mfa-device", user["UserName"], *sibling)["code"] != "Success":
                raise RuntimeError("Sibling enrollment failed")
        cases.append((count, label, environment, serial, seed, sibling, quiet))
    time.sleep(90)

    def auth(case, environment, serial, seed, offset):
        step = int(time.time()) // 30 + offset
        return p.request(case, "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step), "DurationSeconds": 900}, environment, "sts", code_step=step, code_step_offset=offset)

    blocked = []
    for count, label, environment, serial, seed, sibling, quiet in cases:
        for index in range(args.valid_prefix):
            name = "before_" + label + ("_" + str(index) if args.valid_prefix > 1 else "")
            if auth(name, environment, serial, seed, index-2)["code"] != "Success":
                raise RuntimeError("Established device did not authenticate before invalid attempts")
        for index in range(count):
            auth(label + "_invalid_" + str(index), environment, serial, seed, 100 + index)
        result = auth("after_" + label, environment, serial, seed, 1 if args.valid_prefix > 1 else -1)
        if result["code"] != "Success":
            blocked.append((time.monotonic() + quiet, label, environment, serial, seed))
            if sibling:
                auth("sibling_" + label, environment, *sibling, 0)
    for deadline, label, environment, serial, seed in sorted(blocked):
        time.sleep(max(0, deadline-time.monotonic()))
        auth("quiet_recovery_" + label, environment, serial, seed, 0)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/mfa_rejection.json')
    parser.add_argument("--counts", type=int, nargs="+", default=[0, 1, 5, 10])
    parser.add_argument("--quiet-seconds", type=int, nargs="+", default=[120])
    parser.add_argument("--valid-prefix", type=int, choices=[0, 1, 3], default=1)
    parser.add_argument("--sibling", action="store_true")
    parser.add_argument("--aligned", action="store_true")
    parser.add_argument("--odd-boundary", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    p = MFAProbe(args.output)
    p.eligibility.update(quiet_seconds=args.quiet_seconds, valid_prefix=args.valid_prefix)
    p.probe_name = "scripts/aws/iam_mfa_rejection_probe.py"
    try:
        if args.aligned:
            aligned(p, args.odd_boundary)
        else:
            run(p, args)
        p.complete = True
    finally:
        p.finish()


def aligned(p, odd_boundary):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    user = p.user("aligned")
    environment = p.key(user, "aligned")
    environment["AWS_MAX_ATTEMPTS"] = "1"
    serial, seed = p.device("create_aligned", user["UserName"], {"VirtualMFADeviceName": p.prefix + "-aligned"})
    if p.pair("enable_aligned", "enable-mfa-device", user["UserName"], serial, seed)["code"] != "Success":
        raise RuntimeError("Enrollment failed")
    time.sleep(20)
    boundary = (int(time.time()) // 180 + 1) * 180
    if boundary - time.time() < 20:
        boundary += 180
    if odd_boundary and boundary % 360 == 0:
        boundary += 180
    p.eligibility["observed_epoch_boundary"] = boundary
    p.write()
    print("observing UTC boundary", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(boundary)), flush=True)
    time.sleep(max(0, boundary - 14 - time.time()))

    def auth(case, offset):
        step = int(time.time()) // 30 + offset
        return p.request(case, "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step), "DurationSeconds": 900}, environment, "sts", code_step=step, code_step_offset=offset)

    if auth("before_boundary", 1)["code"] != "Success":
        raise RuntimeError("Established device did not authenticate")
    for index in range(8):
        auth("boundary_invalid_" + str(index), 100 + index)
    auth("boundary_limited", 2)
    for offset in (2, 62, 122, 182):
        time.sleep(max(0, boundary + offset - time.time()))
        if auth("boundary_recovery_" + str(offset), 2)["code"] == "Success":
            break


if __name__ == "__main__":
    main()
