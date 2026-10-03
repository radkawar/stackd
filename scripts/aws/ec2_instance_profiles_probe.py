#!/usr/bin/env python3
"""Capture owned EC2 IAM profile lifecycle and sanitized guest IMDS observations.

One t3.nano Linux guest, one 8-GiB gp3 root, isolated owned VPC/subnet/SG;
no public networking or account defaults. Credentials and tokens never leave the
guest. Reuses the instance probe's account guard, ledger and verified cleanup.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import signal
import time

from ec2_instances_probe import InstanceCapture, interrupt
from ebs_encryption_probe import allow, now, policy

GUEST = r'''#!/usr/bin/python3
import json, pathlib, time, urllib.request, urllib.error
base = "http://169.254.169.254/latest/"
boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
previous = None
key = None
for iteration in range(230):
    record = {"at": time.time(), "boot_id": boot}
    try:
        req = urllib.request.Request(base + "api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(req, timeout=3) as response: token = response.read().decode()
        for path in ("iam/", "iam/info", "iam/security-credentials/"):
            req = urllib.request.Request(base + "meta-data/" + path, headers={"X-aws-ec2-metadata-token": token})
            try:
                with urllib.request.urlopen(req, timeout=3) as response: code, body = response.status, response.read().decode()
            except urllib.error.HTTPError as error: code, body = error.code, ""
            value = {"status": code}
            if code == 200:
                if path == "iam/info": value["body"] = json.loads(body)
                else: value["body"] = body
            record[path] = value
        role = record["iam/security-credentials/"].get("body", "").strip()
        if role:
            req = urllib.request.Request(base + "meta-data/iam/security-credentials/" + role, headers={"X-aws-ec2-metadata-token": token})
            try:
                with urllib.request.urlopen(req, timeout=3) as response: code, body = response.status, response.read().decode()
                credentials = json.loads(body)
                record["credentials"] = {"status": code, **{k: credentials[k] for k in ("Code", "Message", "Type", "LastUpdated", "Expiration") if k in credentials}}
                newkey = credentials.get("AccessKeyId")
                record["credentials"]["changed_since_previous"] = key is not None and newkey != key
                key = newkey
                del credentials, body, newkey
            except urllib.error.HTTPError as error: record["credentials"] = {"status": error.code}
        del token
    except Exception as error: record["error_type"] = type(error).__name__
    comparable = dict(record)
    comparable.pop("at")
    if comparable != previous or iteration % 12 == 0:
        with open("/dev/console", "w") as console: console.write("STACKD_PROFILE " + json.dumps(record, separators=(",", ":")) + "\n")
    previous = comparable
    time.sleep(5)
'''


def userdata():
    encoded = base64.b64encode(GUEST.encode()).decode()
    return """#!/bin/bash
set -eu
umask 077
printf '%s' '""" + encoded + """' | base64 -d > /usr/local/sbin/stackd-profile-probe
chmod 700 /usr/local/sbin/stackd-profile-probe
cat > /etc/systemd/system/stackd-profile-probe.service <<'UNIT'
[Unit]
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/sbin/stackd-profile-probe
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now stackd-profile-probe.service
"""


class ProfileCapture(InstanceCapture):
    def ec2(self, label, method, parameters=None, **kwargs):
        parameters = parameters or {}
        if "DryRun" not in parameters or method not in ("associate_iam_instance_profile", "describe_iam_instance_profile_associations", "replace_iam_instance_profile_association", "disassociate_iam_instance_profile"):
            return super().ec2(label, method, parameters, **kwargs)
        # These models do not expose DryRun. Inject the actual Query field before
        # signing to observe the service rather than boto3's local KeyError.
        client = kwargs.get("client") or self.clients["ec2"]
        event = "before-call.ec2." + client.meta.method_to_api_mapping[method]
        def inject(params, **unused):
            params["body"]["DryRun"] = "true"
        client.meta.events.register_last(event, inject)
        try:
            result = super().ec2(label, method, {k: v for k, v in parameters.items() if k != "DryRun"}, **kwargs)
            self.data["calls"][-1]["input"]["DryRun"] = True
            self.save()
        finally:
            client.meta.events.unregister(event, inject)
        association = result.get("IamInstanceProfileAssociation")
        if association:
            self.ec2(label + "-undo-unmodeled-dryrun", "disassociate_iam_instance_profile", {"AssociationId": association["AssociationId"]}, required=True)
            time.sleep(5)
        return result

    def collect(self, iid, label):
        response = self.ec2(label, "get_console_output", {"InstanceId": iid, "Latest": True})
        text = re.sub(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]", "", response.get("Output", ""))
        observations = self.data.setdefault("profile_guest_observations", [])
        for match in re.finditer(r"STACKD_PROFILE (\{[^\r\n]+\})", text):
            try: value = json.loads(match[1])
            except json.JSONDecodeError: continue
            if not any(row["guest"]["at"] == value["at"] for row in observations):
                observations.append({"call": label, "instance": iid, "guest": value})
        self.save()

    def settle(self, iid, label, seconds=65):
        self.ec2(label + "-association", "describe_iam_instance_profile_associations", {"Filters": [{"Name": "instance-id", "Values": [iid]}]})
        self.ec2(label + "-instance", "describe_instances", {"InstanceIds": [iid]})
        time.sleep(seconds)
        self.ec2(label + "-association-after", "describe_iam_instance_profile_associations", {"Filters": [{"Name": "instance-id", "Values": [iid]}]})
        self.collect(iid, label + "-console")

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.data.update(scope=__doc__, bounds={"max_simultaneous_instances": 1, "experiment_seconds": self.args.live_seconds, "instance_type": "t3.nano", "root_gib": 8, "public_network": False}, guest_program=GUEST)
        self.data["documentation"] += ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + operation + ".html" for operation in ("AssociateIamInstanceProfile", "DisassociateIamInstanceProfile", "ReplaceIamInstanceProfileAssociation", "DescribeIamInstanceProfileAssociations")]
        self.data["documentation"] += ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_iam-ec2.html"]
        self.setup()
        first = self.data["guest_role"]
        second = self.data["prefix"] + "-second"
        empty = self.data["prefix"] + "-empty"
        for name in (second, empty):
            if name == second:
                self.observe("second-role", "iam", "create_role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps(policy([{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]))}, required=True)
            self.observe(name + "-profile", "iam", "create_instance_profile", {"InstanceProfileName": name}, required=True)
            if name == second: self.observe("second-profile-role", "iam", "add_role_to_instance_profile", {"InstanceProfileName": name, "RoleName": name}, required=True)
        actions = ["ec2:AssociateIamInstanceProfile", "ec2:DisassociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation", "ec2:DescribeIamInstanceProfileAssociations"]
        broad = [allow(actions + ["iam:PassRole"], "*")]
        self.observe("bounded-profile-policy", "iam", "put_role_policy", {"RoleName": self.data["launcher_role"], "PolicyName": "owned-launches", "PolicyDocument": json.dumps(policy(broad))}, required=True)
        request = self.request()
        request.pop("IamInstanceProfile")
        request["UserData"] = userdata()
        request["BlockDeviceMappings"] = request["BlockDeviceMappings"][:1]
        request["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] = True
        if self.data["owned"]["instances"]: raise RuntimeError("One-instance ownership guard")
        iid = self.launch("launch-no-profile", request, required=True)["Instances"][0]["InstanceId"]
        self.state(iid, "running", "running")
        self.settle(iid, "initial", 45)
        arn = "arn:aws:ec2:us-east-1:" + self.args.account + ":instance/" + iid
        profile_arn = "arn:aws:iam::" + self.args.account + ":instance-profile/" + first
        role_arn = "arn:aws:iam::" + self.args.account + ":role/" + first
        base = {"InstanceId": iid, "IamInstanceProfile": {"Name": first}}
        for label, params in (("missing-both", {}), ("missing-profile", {"InstanceId": iid}), ("empty-profile", {"InstanceId": iid, "IamInstanceProfile": {}}), ("bad-id", dict(base, InstanceId="bad")), ("absent-id", dict(base, InstanceId="i-00000000000000000")), ("absent-profile", dict(base, IamInstanceProfile={"Name": "stackd-absent-profile"})), ("both-profile-fields", dict(base, IamInstanceProfile={"Name": first, "Arn": profile_arn})), ("conflicting-profile-fields", dict(base, IamInstanceProfile={"Name": second, "Arn": profile_arn})), ("empty-role-profile", dict(base, IamInstanceProfile={"Name": empty}))):
            self.ec2("associate-" + label + "-dry", "associate_iam_instance_profile", dict(params, DryRun=True))
        for label, statements in (
            ("no-pass", [allow(actions, "*")]),
            ("pass-service", [allow(actions, arn), allow("iam:PassRole", role_arn, {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}})]),
            ("pass-associated", [allow(actions, arn), allow("iam:PassRole", role_arn, {"ArnEquals": {"iam:AssociatedResourceArn": arn}})]),
            ("pass-associated-wildcard", [allow(actions, arn), allow("iam:PassRole", role_arn, {"ArnLike": {"iam:AssociatedResourceArn": "arn:aws:ec2:us-east-1:" + self.args.account + ":instance/*"}})]),
            ("pass-associated-null", [allow(actions, arn), allow("iam:PassRole", role_arn, {"Null": {"iam:AssociatedResourceArn": "true"}})]),
            ("new-profile-condition", [allow(actions, arn, {"ArnEquals": {"ec2:NewInstanceProfile": profile_arn}}), allow("iam:PassRole", role_arn)]),
            ("profile-condition", [allow(actions, arn, {"ArnEquals": {"ec2:InstanceProfile": profile_arn}}), allow("iam:PassRole", role_arn)]),
            ("tag-condition", [allow(actions, arn, {"StringEquals": {"ec2:ResourceTag/suite": self.data["prefix"]}}), allow("iam:PassRole", role_arn)]),
            ("wrong-instance", [allow(actions, arn + "0"), allow("iam:PassRole", role_arn)]),
            ("no-permissions", [allow("ec2:DescribeRegions", "*")])):
            client = self.assumed(label, statements)
            self.ec2("iam-" + label + "-dry", "associate_iam_instance_profile", dict(base, DryRun=True), client=client, caller=label)
            if label == "no-permissions": self.ec2("iam-denied-bad-id", "associate_iam_instance_profile", dict(base, InstanceId="bad"), client=client, caller=label)
        for params in ({"MaxResults": 1}, {"MaxResults": 0}, {"MaxResults": 1001}, {"NextToken": "bad"}, {"AssociationIds": ["bad"]}, {"AssociationIds": ["iip-assoc-00000000000000000"]}, {"Filters": [{"Name": "bad", "Values": ["x"]}]}, {"DryRun": True}):
            self.ec2("describe-negative-" + str(len(self.data["calls"])), "describe_iam_instance_profile_associations", params)
        for name, values in (("state", ["associated"]), ("state", ["disassociated"]), ("state", ["assoc*"]), ("state", []), ("instance-id", ["i-*"]), ("instance-id", [iid]), ("tag:suite", [self.data["prefix"]])):
            self.ec2("describe-filter-" + str(len(self.data["calls"])), "describe_iam_instance_profile_associations", {"Filters": [{"Name": name, "Values": values}]})
        conflicting = self.ec2("associate-conflicting-actual", "associate_iam_instance_profile", dict(base, IamInstanceProfile={"Name": second, "Arn": profile_arn}))
        if conflicting.get("IamInstanceProfileAssociation"):
            self.ec2("disassociate-conflicting-actual", "disassociate_iam_instance_profile", {"AssociationId": conflicting["IamInstanceProfileAssociation"]["AssociationId"]}, required=True)
            time.sleep(10)
        assoc = self.ec2("associate-first", "associate_iam_instance_profile", base, required=True)["IamInstanceProfileAssociation"]["AssociationId"]
        self.ec2("associate-duplicate-immediate", "associate_iam_instance_profile", base)
        self.settle(iid, "first")
        self.ec2("associate-duplicate", "associate_iam_instance_profile", base)
        self.ec2("associate-duplicate-dry", "associate_iam_instance_profile", dict(base, DryRun=True))
        self.ec2("describe-id", "describe_iam_instance_profile_associations", {"AssociationIds": [assoc], "MaxResults": 5})
        self.ec2("describe-filter-profile", "describe_iam_instance_profile_associations", {"Filters": [{"Name": "iam-instance-profile.arn", "Values": [profile_arn]}]})
        no_pass = self.assumed("no-pass-replace", [allow(actions, "*")])
        self.ec2("replace-no-pass-dry", "replace_iam_instance_profile_association", {"AssociationId": assoc, "IamInstanceProfile": {"Name": second}, "DryRun": True}, client=no_pass, caller="no-pass-replace")
        self.ec2("replace-owner-dry", "replace_iam_instance_profile_association", {"AssociationId": assoc, "IamInstanceProfile": {"Name": second}, "DryRun": True})
        self.ec2("disassociate-no-pass-dry", "disassociate_iam_instance_profile", {"AssociationId": assoc, "DryRun": True}, client=no_pass, caller="no-pass-replace")
        for method in ("disassociate_iam_instance_profile", "replace_iam_instance_profile_association"):
            for bad in ("bad", "iip-assoc-00000000000000000"):
                params = {"AssociationId": bad}
                if method.startswith("replace"): params["IamInstanceProfile"] = {"Name": first}
                self.ec2(method + "-" + bad, method, params)
        same = self.ec2("replace-same", "replace_iam_instance_profile_association", {"AssociationId": assoc, "IamInstanceProfile": {"Name": first}})
        assoc = same.get("IamInstanceProfileAssociation", {}).get("AssociationId", assoc)
        replaced = self.ec2("replace-second", "replace_iam_instance_profile_association", {"AssociationId": assoc, "IamInstanceProfile": {"Name": second}}, required=True)
        old_assoc, assoc = assoc, replaced["IamInstanceProfileAssociation"]["AssociationId"]
        self.ec2("describe-replaced-id", "describe_iam_instance_profile_associations", {"AssociationIds": [old_assoc]})
        self.settle(iid, "second", 90)
        self.observe("remove-second-role", "iam", "remove_role_from_instance_profile", {"InstanceProfileName": second, "RoleName": second}, required=True)
        self.settle(iid, "removed-role", 80)
        self.observe("restore-second-role", "iam", "add_role_to_instance_profile", {"InstanceProfileName": second, "RoleName": second}, required=True)
        self.observe("deny-second-trust", "iam", "update_assume_role_policy", {"RoleName": second, "PolicyDocument": json.dumps(policy([{"Effect": "Deny", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]))}, required=True)
        # A fresh association forces a new credential-delivery decision; previously
        # issued credentials are not revoked by this trust change.
        self.ec2("disassociate-second", "disassociate_iam_instance_profile", {"AssociationId": assoc}, required=True)
        self.ec2("disassociate-repeat", "disassociate_iam_instance_profile", {"AssociationId": assoc})
        self.settle(iid, "disassociated", 45)
        self.ec2("replace-disassociated", "replace_iam_instance_profile_association", {"AssociationId": assoc, "IamInstanceProfile": {"Name": first}})
        denied_assoc = self.ec2("associate-denied-trust", "associate_iam_instance_profile", {"InstanceId": iid, "IamInstanceProfile": {"Name": second}}, required=True)["IamInstanceProfileAssociation"]["AssociationId"]
        self.settle(iid, "denied-trust", 75)
        self.ec2("disassociate-denied-trust", "disassociate_iam_instance_profile", {"AssociationId": denied_assoc}, required=True)
        self.settle(iid, "before-stop", 20)
        self.ec2("stop", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "stopped", "stopped")
        stopped_assoc = self.ec2("associate-stopped", "associate_iam_instance_profile", base, required=True)["IamInstanceProfileAssociation"]["AssociationId"]
        replaced = self.ec2("replace-stopped", "replace_iam_instance_profile_association", {"AssociationId": stopped_assoc, "IamInstanceProfile": {"Name": second}})
        stopped_assoc = replaced.get("IamInstanceProfileAssociation", {}).get("AssociationId", stopped_assoc)
        self.ec2("disassociate-stopped", "disassociate_iam_instance_profile", {"AssociationId": stopped_assoc}, required=True)
        self.ec2("associate-empty-stopped", "associate_iam_instance_profile", {"InstanceId": iid, "IamInstanceProfile": {"Name": empty}})
        self.ec2("start", "start_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "running", "restarted")
        self.settle(iid, "empty-profile", 75)
        self.ec2("terminate", "terminate_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "terminated", "terminal")
        self.ec2("associate-terminated", "associate_iam_instance_profile", base)
        self.ec2("describe-terminal", "describe_iam_instance_profile_associations", {"Filters": [{"Name": "instance-id", "Values": [iid]}]})
        self.data["gaps"].extend(["IMDS and association propagation is asynchronous; bounded polling does not define AWS timing guarantees.", "Role trust/membership changes do not prove old issued credentials are revoked. Credential secrets and identifiers were never retained.", "Only one instance was permitted; multi-result pagination token encoding remains unobserved."])
        self.data["capture_complete_at"] = now()
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/instance_profiles.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--live-seconds", type=int, default=1200, choices=range(300, 1201))
    args = parser.parse_args()
    args.audit_only = False
    capture = ProfileCapture(args)
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM): signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only: capture.run()
    except Exception as error:
        capture.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        capture.save()
        raise
    finally:
        capture.cleanup()


if __name__ == "__main__": main()
