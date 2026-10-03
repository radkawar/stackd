#!/usr/bin/env python3
"""Capture one isolated t3.nano's screenshots, admission and verified cleanup.

Reuse InstanceCapture account guards and cleanup. No public networking, profile
credentials, packages or account-default changes. Screenshots contain only this
owned guest's boot console and synthetic text; audit evidence never retains a
screenshot body. --audit-only is a read-only harvest after complete cleanup.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import time

from ec2_instances_probe import InstanceCapture, interrupt
from ebs_encryption_probe import CONFIG, allow, now, policy

DOCS = [
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetConsoleScreenshot.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/troubleshoot-unreachable-instance.html#instance-console-screenshot",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html",
]
GUEST = r'''#!/bin/bash
set -eu
systemctl stop getty@tty1.service || true
chvt 1 || true
for phase in FIRST SECOND THIRD; do
    printf '\033[2J\033[HSTACKD SCREENSHOT %s\nActual owned EC2 guest console\n' "$phase" > /dev/tty1
    printf 'STACKD_SCREENSHOT %s\n' "$phase" > /dev/console
    sleep 25
done
'''


class ScreenshotCapture(InstanceCapture):
    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(scope="One isolated t3.nano with 8-GiB gp3 root; real screenshots, IAM, state, scope and WakeUp admission",
                documentation=DOCS, guest_program=GUEST, screenshots=[],
                bounds={"max_simultaneous_instances": 1, "experiment_seconds": args.live_seconds,
                    "instance_type": "t3.nano", "root_gib": 8, "public_network": False})
            self.save()

    def screenshot(self, label, iid, **kwargs):
        parameters = kwargs.pop("parameters", {})
        output = self.ec2(label, "get_console_screenshot", dict(InstanceId=iid, **parameters), **kwargs)
        if output.get("ImageData"):
            raw = base64.b64decode(output["ImageData"], validate=True)
            description = subprocess.check_output(["identify", "-format", "%m %w %h", "-"], input=raw, timeout=10).decode().split()
            pixels = subprocess.check_output(["convert", "-", "rgb:-"], input=raw, timeout=10)
            self.data["screenshots"].append({"label": label, "format": description[0],
                "width": int(description[1]), "height": int(description[2]), "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "pixels_sha256": hashlib.sha256(pixels).hexdigest()})
            self.save()
        return output

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.setup()
        request = self.request()
        request["BlockDeviceMappings"] = request["BlockDeviceMappings"][:1]
        request["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] = True
        request.pop("IamInstanceProfile")
        request["UserData"] = GUEST
        if self.data["owned"]["instances"]:
            raise RuntimeError("One-instance ownership limit reached")
        iid = self.launch("run-screenshot-guest", request, required=True)["Instances"][0]["InstanceId"]
        self.screenshot("pending", iid)
        self.state(iid, "running", "guest-running", seconds=120)
        for label, parameters in (("running-default", {}), ("running-wake-false", {"WakeUp": False}),
                ("running-wake-true", {"WakeUp": True}), ("running-dry-run", {"DryRun": True}),
                ("running-dry-wake", {"DryRun": True, "WakeUp": True})):
            self.screenshot(label, iid, parameters=parameters)
        for label, target, params in (("missing", "i-00000000000000000", {}),
                ("missing-dry-run", "i-00000000000000000", {"DryRun": True}),
                ("malformed", "invalid", {}), ("malformed-dry-run", "invalid", {"DryRun": True})):
            self.screenshot(label, target, parameters=params)
        other = self.session.client("ec2", region_name="us-west-2", config=CONFIG)
        self.screenshot("other-region", iid, client=other)
        arn = "arn:aws:ec2:" + self.args.region + ":" + self.args.account + ":instance/" + iid
        self.observe("owned-screenshot-policy", "iam", "put_role_policy", {
            "RoleName": self.data["launcher_role"], "PolicyName": "owned-launches",
            "PolicyDocument": json.dumps(policy([allow("ec2:GetConsoleScreenshot", arn)]))}, required=True)
        time.sleep(12)
        for label, resource, condition in (
                ("iam-instance", arn, None),
                ("iam-other-instance", arn[:-17] + "00000000000000000", None),
                ("iam-tag-match", arn, {"StringEquals": {"ec2:ResourceTag/suite": self.data["prefix"]}}),
                ("iam-tag-mismatch", arn, {"StringEquals": {"ec2:ResourceTag/suite": "other"}}),
                ("iam-type-match", arn, {"StringEquals": {"ec2:InstanceType": "t3.nano"}}),
                ("iam-type-mismatch", arn, {"StringEquals": {"ec2:InstanceType": "t3.micro"}}),
                ("iam-region-match", arn, {"StringEquals": {"ec2:Region": self.args.region}})):
            client = self.assumed(label, [allow("ec2:GetConsoleScreenshot", resource, condition)])
            self.screenshot(label, iid, client=client, caller=label, parameters={"DryRun": True})
        for attempt in range(4):
            self.screenshot("guest-frame-" + str(attempt), iid)
            self.ec2("guest-console-" + str(attempt), "get_console_output", {"InstanceId": iid, "Latest": True})
            time.sleep(15)
        self.ec2("stop-screenshot-guest", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.screenshot("stopping", iid)
        self.state(iid, "stopped", "guest-stopped", seconds=90)
        for label, params in (("stopped", {}), ("stopped-wake", {"WakeUp": True}),
                ("stopped-dry-run", {"DryRun": True}), ("stopped-dry-wake", {"DryRun": True, "WakeUp": True})):
            self.screenshot(label, iid, parameters=params)
        if len({image["pixels_sha256"] for image in self.data["screenshots"]}) == 1:
            self.data["gaps"].append("Captured frames have identical pixels despite the timed guest console writes; native screen unblanking and tty1-to-framebuffer mapping are not established.")
        self.data["capture_complete_at"] = now()
        self.save()

    def cleanup(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, signal.SIG_IGN)
        super().cleanup()
        for iid in self.data["owned"]["instances"]:
            self.screenshot("terminated", iid)
            self.screenshot("terminated-dry-run", iid, parameters={"DryRun": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/console_screenshot.json"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--audit-only", action="store_true")
    parser.add_argument("--live-seconds", type=int, default=360, choices=range(180, 421), metavar="180..420")
    args = parser.parse_args()
    capture = ScreenshotCapture(args)
    if args.audit_only:
        if not capture.data["cleanup"].get("complete"):
            raise RuntimeError("Complete owned cleanup before read-only audit harvest")
        capture.audit()
        return
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only:
            capture.run()
    except Exception as error:
        capture.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        capture.save()
        raise
    finally:
        capture.cleanup()


if __name__ == "__main__":
    main()
