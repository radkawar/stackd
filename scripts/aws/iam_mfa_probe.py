#!/usr/bin/env python3
"""Observe virtual MFA lifecycle and STS authentication on owned IAM users."""

import argparse
import base64
import hashlib
import hmac
from pathlib import Path
import struct
import sys
import time
import uuid

sys.dont_write_bytecode = True
from iam_last_access_probe import call
from iam_outbound_identity_probe import OutboundProbe, ROOT, operation, stamp


def otp(seed, step):
    digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return "%06d" % ((int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000)


class MFAProbe(OutboundProbe):
    def __init__(self, output):
        super().__init__(output)
        self.prefix = "stackd-mfa-" + uuid.uuid4().hex[:10]
        self.normalized_prefix = "stackd-mfa-fixture"
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")
        self.probe_name = "scripts/aws/iam_mfa_probe.py"
        self.documentation = ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_" + name + ".html" for name in
                              ("CreateVirtualMFADevice", "EnableMFADevice", "DeactivateMFADevice", "ResyncMFADevice", "ListVirtualMFADevices", "GetMFADevice")]
        self.limitations = ["Only uniquely owned users, keys and virtual devices are changed. Root MFA and existing devices are unchanged.",
                            "Seeds, QR payloads, authentication codes and issued credentials remain in memory. List results retain only owned devices.",
                            "Hardware and FIDO registration are not covered. Time windows are observations, not undocumented latency guarantees."]

    def normalize(self, value):
        if isinstance(value, dict):
            value = {k: v for k, v in value.items() if k not in ("Base32StringSeed", "QRCodePNG", "AuthenticationCode1", "AuthenticationCode2", "TokenCode")}
        return super().normalize(value)

    def request(self, case, action, parameters=None, environment=None, service="iam", **extra):
        requested_at = stamp()
        result = call(action, parameters, environment, service)
        record = dict(result)
        if "output" in result:
            output = dict(result["output"])
            if "VirtualMFADevices" in output:
                output["VirtualMFADevices"] = [d for d in output["VirtualMFADevices"] if self.prefix in d["SerialNumber"]]
            if "VirtualMFADevice" in output:
                output["device_fields"] = sorted(output["VirtualMFADevice"])
            record["output"] = output
        row = {"case": case, "service": service, "operation": operation(action), "input": parameters or {}, "requested_at": requested_at, "observed_at": stamp(), **record, **extra}
        if self.changes:
            row["state_changes_before"], self.changes = self.changes, []
        self.observations.append(self.normalize(row))
        self.write()
        print(case, result["code"], flush=True)
        return result

    def pair(self, case, action, user, serial, seed, delta=0, duplicate=False, reverse=False, environment=None):
        step = int(time.time()) // 30 + delta
        first, second = otp(seed, step - 1), otp(seed, step)
        if duplicate:
            first = second
        if reverse:
            first, second = second, first
        return self.request(case, action, {"UserName": user, "SerialNumber": serial, "AuthenticationCode1": first, "AuthenticationCode2": second}, environment,
                            second_step=step, second_step_offset=delta, duplicate_codes=duplicate, reversed_codes=reverse)

    def device(self, case, user, parameters):
        created = self.request(case, "create-virtual-mfa-device", parameters)
        if created["code"] != "Success":
            raise RuntimeError("Device creation failed")
        device = created["output"]["VirtualMFADevice"]
        serial = device["SerialNumber"]
        self.own("iam", "delete-virtual-mfa-device", {"SerialNumber": serial})
        self.own("iam", "deactivate-mfa-device", {"UserName": user, "SerialNumber": serial})
        seed = base64.b32decode(base64.b64decode(device["Base32StringSeed"]))
        return serial, seed


def run(p):
    identity = call("get-caller-identity", service="sts")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    user, other = p.user("owner"), p.user("other")
    environment = p.key(user, "owner")
    name = user["UserName"]
    parameters = {"VirtualMFADeviceName": p.prefix + "-phone", "Path": "/devices/", "Tags": [{"Key": "owner", "Value": "probe"}]}
    serial, seed = p.device("create", name, parameters)
    p.request("duplicate_create", "create-virtual-mfa-device", parameters)
    p.request("list_unassigned", "list-virtual-mfa-devices", {"AssignmentStatus": "Unassigned"})
    p.request("deactivate_unassigned", "deactivate-mfa-device", {"UserName": name, "SerialNumber": serial})
    p.pair("resync_unassigned", "resync-mfa-device", name, serial, seed)
    p.pair("enable_same_codes", "enable-mfa-device", name, serial, seed, duplicate=True)
    p.pair("enable_reversed_codes", "enable-mfa-device", name, serial, seed, reverse=True)
    enabled = p.pair("enable", "enable-mfa-device", name, serial, seed)
    if enabled["code"] not in ("Success", "EntityAlreadyExists"):
        raise RuntimeError("MFA enrollment failed")
    p.pair("enable_duplicate", "enable-mfa-device", name, serial, seed)
    p.pair("enable_other", "enable-mfa-device", other["UserName"], serial, seed)
    p.request("list_assigned", "list-virtual-mfa-devices", {"AssignmentStatus": "Assigned"})
    p.request("list_user", "list-mfa-devices", {"UserName": name})
    p.request("get_virtual", "get-mfa-device", {"UserName": name, "SerialNumber": serial})
    p.request("delete_assigned", "delete-virtual-mfa-device", {"SerialNumber": serial})
    p.request("delete_assigned_user", "delete-user", {"UserName": name})
    p.request("deactivate_other", "deactivate-mfa-device", {"UserName": other["UserName"], "SerialNumber": serial})
    p.pair("resync_other", "resync-mfa-device", other["UserName"], serial, seed)
    for delta in (0, 0, -1, 1, -2, 2, -10, 10):
        token = otp(seed, int(time.time()) // 30 + delta)
        p.request("sts_initial_" + str(len(p.observations)), "get-session-token", {"DurationSeconds": 900, "SerialNumber": serial, "TokenCode": token}, environment, "sts", code_step_offset=delta)
    for delta in (10, 0, 20, 21, 0):
        p.pair("resync_" + str(len(p.observations)), "resync-mfa-device", name, serial, seed, delta=delta)
        for offset in (delta, 0):
            p.request("sts_resynced_" + str(len(p.observations)), "get-session-token", {"DurationSeconds": 900, "SerialNumber": serial, "TokenCode": otp(seed, int(time.time()) // 30 + offset)}, environment, "sts", code_step_offset=offset)
    p.request("deactivate", "deactivate-mfa-device", {"UserName": name, "SerialNumber": serial})
    p.request("deactivate_again", "deactivate-mfa-device", {"UserName": name, "SerialNumber": serial})
    p.request("sts_deactivated", "get-session-token", {"DurationSeconds": 900, "SerialNumber": serial, "TokenCode": otp(seed, int(time.time()) // 30)}, environment, "sts")
    p.request("list_after_deactivate", "list-virtual-mfa-devices", {"AssignmentStatus": "Unassigned"})
    p.pair("reassign_other", "enable-mfa-device", other["UserName"], serial, seed)
    p.own("iam", "deactivate-mfa-device", {"UserName": other["UserName"], "SerialNumber": serial})
    p.request("list_other_after_reassign", "list-mfa-devices", {"UserName": other["UserName"]})


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/mfa.json')
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    p = MFAProbe(probe_args.output)
    try:
        run(p)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
