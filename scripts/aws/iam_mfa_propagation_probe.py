#!/usr/bin/env python3
"""Observe MFA transition visibility with fresh codes and isolated owned devices."""

import argparse
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
    other = p.user("destination")
    other_environment = p.key(other, "destination")
    cases = []
    for transition in ("deactivate", "delete", "resync", "reassign"):
        for delay in (0, 12):
            label = transition + "_" + str(delay)
            user = p.user(label)
            environment = p.key(user, label)
            serial, seed = p.device("create_" + label, user["UserName"], {"VirtualMFADeviceName": p.prefix + "-" + label})
            result = p.pair("enable_" + label, "enable-mfa-device", user["UserName"], serial, seed)
            if result["code"] != "Success":
                raise RuntimeError("Enrollment failed: " + result["code"])
            cases.append((transition, delay, label, user, environment, serial, seed))
    time.sleep(15)

    def auth(label, environment, serial, seed, offset):
        step = int(time.time()) // 30 + offset
        return p.request(label, "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step), "DurationSeconds": 900}, environment, "sts", code_step=step, code_step_offset=offset)

    for transition, delay, label, user, environment, serial, seed in cases:
        # Stop after the first accepted code. Subsequent checks use different
        # counters, so a replay rejection cannot look like propagation.
        before = auth("before_" + label, environment, serial, seed, 1)
        if before["code"] != "Success":
            raise RuntimeError("Initial MFA verification failed: " + before["code"])
        started = time.monotonic()
        if transition == "resync":
            result = p.pair("transition_" + label, "resync-mfa-device", user["UserName"], serial, seed, 10)
        else:
            result = p.request("transition_" + label, "deactivate-mfa-device", {"UserName": user["UserName"], "SerialNumber": serial})
        if result["code"] != "Success":
            raise RuntimeError("MFA transition failed: " + result["code"])
        if transition == "delete":
            result = p.request("delete_" + label, "delete-virtual-mfa-device", {"SerialNumber": serial})
            if result["code"] != "Success":
                raise RuntimeError("Device deletion failed: " + result["code"])
        if transition == "reassign":
            result = p.pair("reassign_" + label, "enable-mfa-device", other["UserName"], serial, seed, 4)
            if result["code"] != "Success":
                raise RuntimeError("Device reassignment failed: " + result["code"])
            p.own("iam", "deactivate-mfa-device", {"UserName": other["UserName"], "SerialNumber": serial})
        p.request("list_" + label, "list-mfa-devices", {"UserName": user["UserName"]})
        if delay:
            time.sleep(delay)
        p.eligibility[label + "_elapsed_seconds"] = round(time.monotonic() - started, 3)
        auth("old_" + label, environment, serial, seed, 2)
        if transition == "resync":
            auth("new_" + label, environment, serial, seed, 11)
        if transition == "reassign":
            auth("new_" + label, other_environment, serial, seed, 5)
        p.request("issued_session_" + label, "get-caller-identity", {}, session_environment(before["output"]), "sts")

    user = p.user("enrollment")
    environment = p.key(user, "enrollment")
    serial, seed = p.device("create_enrollment", user["UserName"], {"VirtualMFADeviceName": p.prefix + "-enrollment"})
    result = p.pair("enable_enrollment", "enable-mfa-device", user["UserName"], serial, seed)
    if result["code"] != "Success":
        raise RuntimeError("Enrollment failed")
    for index in range(30):
        if auth("enrollment_" + str(index), environment, serial, seed, 1)["code"] == "Success":
            break
        time.sleep(1)
    else:
        raise RuntimeError("Enrollment did not become visible during observation")


def recreate(p, skip_early, replacement_offset, exhaust, replacement_delay):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    user = p.user("recreate")
    environment = p.key(user, "recreate")
    name = p.prefix + "-recreate"
    serial, old_seed = p.device("create_original", user["UserName"], {"VirtualMFADeviceName": name})
    p.pair("enable_original", "enable-mfa-device", user["UserName"], serial, old_seed)
    time.sleep(15)

    def auth(case, seed, offset):
        step = int(time.time()) // 30 + offset
        return p.request(case, "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step), "DurationSeconds": 900}, environment, "sts", code_step=step, code_step_offset=offset)

    if exhaust and time.time() % 180 > 90:
        time.sleep(180 - time.time() % 180 + 2)
    if auth("before_recreate", old_seed, 1)["code"] != "Success":
        raise RuntimeError("Initial MFA verification failed")
    if exhaust:
        for index in range(8):
            auth("exhaust_original_" + str(index), old_seed, 100 + index)
        auth("original_limited", old_seed, 2)
    p.request("deactivate_original", "deactivate-mfa-device", {"UserName": user["UserName"], "SerialNumber": serial})
    p.request("delete_original", "delete-virtual-mfa-device", {"SerialNumber": serial})
    if replacement_delay:
        time.sleep(replacement_delay)
    _, new_seed = p.device("create_replacement", user["UserName"], {"VirtualMFADeviceName": name})
    if p.pair("enable_replacement", "enable-mfa-device", user["UserName"], serial, new_seed, replacement_offset)["code"] != "Success":
        raise RuntimeError("Replacement enrollment failed")
    auth("old_immediate", old_seed, 2)
    if not skip_early:
        auth("new_immediate", new_seed, replacement_offset + 1)
    time.sleep(12)
    auth("old_later", old_seed, 2)
    auth("new_later", new_seed, replacement_offset + 1)
    auth("new_unspent_later", new_seed, replacement_offset - 1)
    time.sleep(30)
    recovered = auth("new_recovered", new_seed, replacement_offset + 1)
    if exhaust and recovered["code"] != "Success":
        time.sleep(180 - time.time() % 180 + 2)
        auth("new_after_boundary", new_seed, replacement_offset + 1)


def ordering(p, drift=False):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    cases = []
    sequences = (("future", [2, 1, 0]), ("current", [0, -1, 1]), ("past", [-2, 0, -1, 1]))
    if drift:
        sequences = (("future", [2, -2, 0, -2]), ("past", [-2, 2, 0, 2]))
    for label, offsets in sequences:
        user = p.user(label)
        environment = p.key(user, label)
        serial, seed = p.device("create_" + label, user["UserName"], {"VirtualMFADeviceName": p.prefix + "-" + label})
        if p.pair("enable_" + label, "enable-mfa-device", user["UserName"], serial, seed)["code"] != "Success":
            raise RuntimeError("Enrollment failed")
        cases.append((label, offsets, environment, serial, seed))
    time.sleep(90)
    for label, offsets, environment, serial, seed in cases:
        if drift:
            time.sleep((2 - time.time() % 30) % 30)
        current = int(time.time()) // 30
        for index, offset in enumerate(offsets):
            step = current + offset
            p.request(label + "_" + str(index), "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step), "DurationSeconds": 900}, environment, "sts", code_step=step, code_step_offset=offset)


def synchronization_codes(p):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    cases = []
    for transition in ("enroll", "resync", "recreate"):
        for order in ("first", "later"):
            label = transition + "_" + order
            user = p.user(label)
            environment = p.key(user, label)
            environment["AWS_MAX_ATTEMPTS"] = "1"
            name = p.prefix + "-" + label
            serial, seed = p.device("create_" + label, user["UserName"], {"VirtualMFADeviceName": name})
            if transition != "enroll":
                if p.pair("initial_" + label, "enable-mfa-device", user["UserName"], serial, seed)["code"] != "Success":
                    raise RuntimeError("Initial enrollment failed")
            cases.append((transition, order, label, user, environment, name, serial, seed))
    time.sleep(20)
    for transition, order, label, user, environment, name, serial, seed in cases:
        if transition != "enroll":
            step = int(time.time()) // 30 + 1
            if p.request("before_" + label, "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step)}, environment, "sts", code_step=step)["code"] != "Success":
                raise RuntimeError("Initial authentication failed")
        if transition == "recreate":
            p.request("deactivate_" + label, "deactivate-mfa-device", {"UserName": user["UserName"], "SerialNumber": serial})
            p.request("delete_" + label, "delete-virtual-mfa-device", {"SerialNumber": serial})
            serial, seed = p.device("replacement_" + label, user["UserName"], {"VirtualMFADeviceName": name})
        # Start early in a TOTP step so both synchronization codes remain inside
        # the ordinary acceptance window after propagation and all three calls.
        time.sleep((2 - time.time() % 30) % 30)
        action = "resync-mfa-device" if transition == "resync" else "enable-mfa-device"
        adjustment = 10 if transition == "resync" else 0
        if p.pair("synchronize_" + label, action, user["UserName"], serial, seed, adjustment)["code"] != "Success":
            raise RuntimeError("Synchronization failed")
        second = p.observations[-1]["second_step"]
        time.sleep(20)
        offsets = (-1, 0, 1) if order == "first" else (1, -1, 0)
        for offset in offsets:
            step = second + offset
            p.request("bootstrap_" + label + "_" + str(offset), "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step)}, environment, "sts", code_step=step, synchronization_offset=offset)


def synchronization_reuse(p):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    cases = []
    for consumed in (0, 1):
        label = "consumed_" + str(consumed)
        user = p.user(label)
        environment = p.key(user, label)
        environment["AWS_MAX_ATTEMPTS"] = "1"
        serial, seed = p.device("create_" + label, user["UserName"], {"VirtualMFADeviceName": p.prefix + "-" + label})
        if p.pair("enable_" + label, "enable-mfa-device", user["UserName"], serial, seed)["code"] != "Success":
            raise RuntimeError("Enrollment failed")
        cases.append((consumed, label, user, environment, serial, seed))
    time.sleep(60)
    for consumed, label, user, environment, serial, seed in cases:
        time.sleep((2 - time.time() % 30) % 30)
        first = int(time.time()) // 30
        def auth(case, offset):
            step = first + offset
            return p.request(case + "_" + label, "get-session-token", {"SerialNumber": serial, "TokenCode": otp(seed, step)}, environment, "sts", code_step=step)
        if auth("before", consumed)["code"] != "Success":
            raise RuntimeError("Initial authentication failed")
        if p.request("resync_" + label, "resync-mfa-device", {"UserName": user["UserName"], "SerialNumber": serial, "AuthenticationCode1": otp(seed, first), "AuthenticationCode2": otp(seed, first+1)}, second_step=first+1)["code"] != "Success":
            raise RuntimeError("Resynchronization failed")
        time.sleep(20)
        auth("replay", consumed)
        auth("unused", 1-consumed)
        auth("replay_after_unused", consumed)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/mfa_propagation.json')
    parser.add_argument("--recreate", action="store_true")
    parser.add_argument("--skip-early", action="store_true")
    parser.add_argument("--ordering", action="store_true")
    parser.add_argument("--drift", action="store_true")
    parser.add_argument("--synchronization-codes", action="store_true")
    parser.add_argument("--synchronization-reuse", action="store_true")
    parser.add_argument("--replacement-offset", type=int, default=0)
    parser.add_argument("--exhaust", action="store_true")
    parser.add_argument("--replacement-delay", type=int, default=0)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    p = MFAProbe(args.output)
    p.probe_name = "scripts/aws/iam_mfa_propagation_probe.py"
    try:
        if args.synchronization_reuse:
            synchronization_reuse(p)
        elif args.synchronization_codes:
            synchronization_codes(p)
        elif args.ordering or args.drift:
            ordering(p, args.drift)
        elif args.recreate:
            recreate(p, args.skip_early, args.replacement_offset, args.exhaust, args.replacement_delay)
        else:
            run(p)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
