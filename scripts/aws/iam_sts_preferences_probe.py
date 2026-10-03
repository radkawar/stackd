#!/usr/bin/env python3
"""Capture global STS token preferences and actual regional authentication.

Temporarily changes the account's global STS token version and restores the
original setting. Creates one owned role. Existing policies and regional opt-in
settings are unchanged. Credentials stay in memory; only token sizes and API
outcomes are recorded.
"""

import argparse
import json
from pathlib import Path
import sys
import time
import uuid

sys.dont_write_bytecode = True
from iam_last_access_probe import call as endpoint_call
from iam_outbound_identity_probe import OutboundProbe, ROOT, call, operation, policy, allow, stamp, session_environment


def capture_regions():
    result = call("ec2", "describe-regions", {"AllRegions": True})
    if result["code"] != "Success":
        raise RuntimeError("Region capture failed: " + result["code"])
    data = {"source": "AWS EC2 DescribeRegions(AllRegions=true), commercial partition", "observed_at": stamp(),
            "documentation": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html",
            "Regions": sorted(result["output"]["Regions"], key=lambda row: row["RegionName"])}
    (ROOT / "cmd/awsgen/regions.json").write_text(json.dumps(data, indent=2) + "\n")


class PreferenceProbe(OutboundProbe):
    def __init__(self, output):
        super().__init__(output)
        self.prefix = "stackd-sts-preferences-" + uuid.uuid4().hex[:10]
        self.normalized_prefix = "stackd-sts-preferences-fixture"
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")
        self.probe_name = "scripts/aws/iam_sts_preferences_probe.py"
        self.documentation = [
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetSecurityTokenServicePreferences.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html",
            "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html",
        ]
        self.limitations = [
            "Global endpoint preference is changed temporarily and restored. Existing policies, identities and regional opt-in configuration are unchanged.",
            "Only one uniquely owned role is created and deleted. Temporary session credentials remain in memory and expire normally.",
            "Commercial partition only. Token lengths are observations, not fixed encoding contracts.",
        ]
        self.original = None

    def record(self, case, service, action, result, parameters=None, **extra):
        row = {"case": case, "service": service, "operation": operation(action),
               "input": parameters or {}, "observed_at": stamp(), **result, **extra}
        if self.changes:
            row["state_changes_before"], self.changes = self.changes, []
        self.observations.append(self.normalize(row))
        self.write()
        print(case, result["code"], flush=True)

    def summary(self, case):
        result = call("iam", "get-account-summary")
        version = result.get("output", {}).get("SummaryMap", {}).get("GlobalEndpointTokenVersion")
        if "output" in result:
            result["output"] = {"GlobalEndpointTokenVersion": version}
        self.record(case, "iam", "get-account-summary", result)
        if result["code"] != "Success" or version not in (1, 2):
            raise RuntimeError("Unable to determine current STS token preference")
        return version

    def configure(self, version, case, environment=None):
        parameters = {"GlobalEndpointTokenVersion": version}
        result = self.query("iam", "set-security-token-service-preferences", parameters, environment, "us-east-1", "https://iam.amazonaws.com")
        self.record(case, "iam", "set-security-token-service-preferences", result, parameters)
        return result

    def authenticate(self, case, credentials, region):
        result = endpoint_call("get-caller-identity", {}, session_environment({"Credentials": credentials}), "sts", region)
        result.pop("output", None)
        self.record(case, "sts", "get-caller-identity", result, region=region)
        return result["code"]

    def service_authentication(self, case, credentials, service, action, region, tamper=False):
        environment = session_environment({"Credentials": credentials})
        if tamper:
            environment["AWS_SESSION_TOKEN"] = "invalid"
        result = endpoint_call(action, {}, environment, service, region, "https://" + service + "." + region + ".amazonaws.com")
        result.pop("output", None)
        self.record(case, service, action, result, region=region, invalid_token=tamper)

    def issue(self, case, action, parameters, global_endpoint=True):
        endpoint = "https://sts.amazonaws.com" if global_endpoint else "https://sts.us-east-1.amazonaws.com"
        result = endpoint_call(action, parameters, service="sts", endpoint=endpoint)
        credential = result.get("output", {}).get("Credentials")
        extra = {"endpoint": endpoint}
        if credential:
            extra["token_bytes"] = len(credential["SessionToken"])
        result.pop("output", None)
        self.record(case, "sts", action, result, parameters, **extra)
        if credential is None:
            raise RuntimeError("Credential issuance failed: " + result["code"])
        return credential

    def wait_version(self, phase, modern):
        deadline = time.monotonic() + 180
        expected = "Success" if modern else "InvalidClientTokenId"
        attempt = 0
        while time.monotonic() < deadline:
            credential = self.issue(phase + "_issue_" + str(attempt), "get-session-token", {"DurationSeconds": 900})
            code = self.authenticate(phase + "_use_" + str(attempt), credential, "ap-east-1")
            if code == expected:
                return
            if code not in ("Success", "InvalidClientTokenId"):
                raise RuntimeError("Unexpected regional credential response: " + code)
            attempt += 1
            time.sleep(2)
        raise RuntimeError("Token preference did not propagate within the observation window")

    def finish(self):
        super().finish()
        if self.original is not None:
            restored = self.summary("restored_preference") == self.original
            self.write(restored)
            if not restored:
                raise RuntimeError("Original STS token preference was not restored")


def run(p):
    capture_regions()
    identity = call("sts", "get-caller-identity")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    caller = identity["output"]
    p.account = caller["Account"]
    p.identifiers.update({caller["Arn"]: "<original-caller-arn>", caller["UserId"]: "<original-caller-id>"})
    p.original = p.summary("initial_preference")
    p.eligibility["original_token_version"] = p.original
    p.own("iam", "set-security-token-service-preferences", {"GlobalEndpointTokenVersion": "v" + str(p.original) + "Token"})
    for invalid in ("v3Token", "V1Token", "1", "", "v2token"):
        result = p.configure(invalid, "invalid_" + (invalid or "empty"))
        if result["code"] == "Success":
            raise RuntimeError("Unexpected acceptance of invalid token version")
    name = p.prefix + "-role"
    role = p.require("iam", "create-role", {"RoleName": name, "AssumeRolePolicyDocument": policy({"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": caller["Arn"]}})})["Role"]
    p.own("iam", "delete-role", {"RoleName": name}, {"service": "iam", "action": "get-role", "input": {"RoleName": name}})
    requests = [
        ("user", "get-session-token", {"DurationSeconds": 900}),
        ("federated", "get-federation-token", {"Name": "stackd-" + p.prefix[-10:], "DurationSeconds": 900, "Policy": policy(allow("sts:GetCallerIdentity"))}),
        ("role", "assume-role", {"RoleArn": role["Arn"], "RoleSessionName": "preference", "DurationSeconds": 900}),
    ]
    retained = {}
    for version in (1, 2):
        if p.configure("v" + str(version) + "Token", "set_v" + str(version))["code"] != "Success":
            raise RuntimeError("Unable to change STS token preference")
        p.summary("summary_v" + str(version))
        p.wait_version("propagate_v" + str(version), version == 2)
        for kind, action, parameters in requests:
            for global_endpoint in (True, False):
                case = "v" + str(version) + "_" + kind + ("_global" if global_endpoint else "_regional")
                credential = p.issue(case, action, parameters, global_endpoint)
                for region in ("us-east-1", "ap-east-1", "ap-northeast-3"):
                    p.authenticate(case + "_" + region, credential, region)
                if global_endpoint:
                    retained[(version, kind)] = credential
                if version == 1 and kind == "user" and global_endpoint:
                    for service, service_action in (("kms", "list-keys"), ("sqs", "list-queues")):
                        p.service_authentication("legacy_" + service, credential, service, service_action, "ap-east-1")
                        p.service_authentication("invalid_credential_" + service, credential, service, service_action, "us-east-1", True)
                if version == 1 and kind == "role" and global_endpoint:
                    p.configure("v2Token", "role_without_permission", session_environment({"Credentials": credential}))
        if version == 2:
            for (old, kind), credential in list(retained.items()):
                if old == 1:
                    p.authenticate("old_v1_after_v2_" + kind, credential, "ap-east-1")
    if p.configure("v1Token", "rapid_v1")["code"] != "Success":
        raise RuntimeError("Rapid v1 change failed")
    time.sleep(3)
    if p.configure("v2Token", "rapid_v2")["code"] != "Success":
        raise RuntimeError("Rapid v2 change failed")
    deadline = time.monotonic() + 25
    attempt = 0
    while time.monotonic() < deadline:
        credential = p.issue("rapid_issue_" + str(attempt), "get-session-token", {"DurationSeconds": 900})
        p.authenticate("rapid_use_" + str(attempt), credential, "ap-east-1")
        attempt += 1
    if p.configure("v1Token", "return_to_v1")["code"] != "Success":
        raise RuntimeError("Unable to return to v1")
    p.wait_version("propagate_return_to_v1", False)
    for (version, kind), credential in retained.items():
        if version == 2:
            p.authenticate("old_v2_after_v1_" + kind, credential, "ap-east-1")


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/sts_preferences.json')
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    p = PreferenceProbe(probe_args.output)
    try:
        run(p)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
