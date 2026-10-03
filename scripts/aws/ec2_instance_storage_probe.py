#!/usr/bin/env python3
"""Capture owned encrypted-root EC2 launch, KMS authority and stopped snapshots.

Reuses the instance/Capture ownership, network, guest, console and cleanup helpers.
At most two additional successfully running t3.nano guests in total, two live at
once, one isolated VPC, 8-GiB gp3 roots, one owned CMK and two owned IAM roles.
Only owned resources are changed; account defaults and existing key policies are
untouched. --cleanup-only resumes the ledger; --audit-only is read-only after
cleanup. Keys are scheduled for deletion, not represented as already absent.
"""
import argparse
import datetime
import json
from pathlib import Path
import signal
import time

from ec2_instances_probe import InstanceCapture, interrupt
from ebs_encryption_probe import allow, now, policy
from ebs_volume_controls_probe import sanitized

DOCS = [
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption-requirements.html",
    "https://docs.aws.amazon.com/ebs/latest/userguide/how-ebs-encryption-works.html",
    "https://docs.aws.amazon.com/kms/latest/developerguide/services-ebs.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RunInstances.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_StopInstances.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshot.html",
    "https://docs.aws.amazon.com/kms/latest/APIReference/API_ListGrants.html",
]
KMS_ACTIONS = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKey", "kms:ReEncrypt*"]


class StorageCapture(InstanceCapture):
    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(scope="Owned encrypted AL2023 8-GiB gp3 roots, at most two successfully running t3.nano guests total, isolated owned VPC/subnet/SG, owned role/profile and CMK; no standing policy/default mutations",
                cases={}, successful_instances=[], launch_case_limit=4)
            self.data["bounds"]["max_successfully_running_instances_total"] = 2
            self.data["documentation"].extend(DOCS)
            self.data["gaps"].append("The isolated VPC has no internet/NAT or STS VPC endpoint. Guest credentials are retrieved only for Code/Type/Expiration; no guest STS request or upstream credential-use claim.")
        self.save()

    def observe(self, label, service, method, parameters=None, **kwargs):
        result = super().observe(label, service, method, parameters, **kwargs)
        if method == "create_snapshot" and result:
            self.own("snapshots", result["SnapshotId"])
            self.save()
        return result

    def setup_storage(self):
        self.setup()
        p = self.data["prefix"]
        key = self.observe("owned-encryption-key", "kms", "create_key", {
            "Description": p + " isolated encrypted EC2 root authority capture",
            "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT",
            "Tags": [{"TagKey": "suite", "TagValue": p}]}, required=True)["KeyMetadata"]["Arn"]
        self.observe("owned-key-default-policy", "kms", "get_key_policy", {"KeyId": key, "PolicyName": "default"}, required=True)
        self.kms_statements = [allow(KMS_ACTIONS, key), allow("kms:CreateGrant", key, {"Bool": {"kms:GrantIsForAWSResource": "true"}})]
        self.bound_role(self.launch_statements + self.kms_statements)
        self.observe("owned-key-grants-before", "kms", "list_grants", {"KeyId": key}, required=True)
        time.sleep(10)

    def bound_role(self, statements):
        self.observe("bound-owned-storage-role", "iam", "put_role_policy", {
            "RoleName": self.data["launcher_role"], "PolicyName": "owned-launches",
            "PolicyDocument": json.dumps(policy(statements))}, required=True)

    def restricted(self, label, denied=None):
        # The session allow intersects the tightly scoped owned-role policy. This
        # avoids STS's 2,048-character session-policy limit duplicating resource ARNs.
        statements = [allow(["ec2:RunInstances", "ec2:CreateTags", "ec2:CreateSnapshot", "iam:PassRole", "kms:*"], "*")]
        if denied:
            statements.append({"Effect": "Deny", "Action": denied, "Resource": self.data["owned"]["key"]})
        return self.assumed(label, statements)

    def request(self):
        request = super().request()
        request["BlockDeviceMappings"] = [request["BlockDeviceMappings"][0]]
        request["BlockDeviceMappings"][0]["Ebs"].update(Encrypted=True, KmsKeyId=self.data["owned"]["key"], DeleteOnTermination=True)
        return request

    def launch_case(self, label, denied=None):
        if len(self.data["successful_instances"]) >= 2:
            self.data["cases"][label] = {"unobserved": "Two-successful-guests total bound reached; no further launch issued"}
            self.save()
            return None
        request = self.request()
        request["ClientToken"] = self.data["prefix"] + "-" + label
        if len(request["ClientToken"]) > 64:
            raise RuntimeError("Probe label exceeds bounded client-token length")
        client = self.restricted(label, denied)
        self.launch(label + "-dry", dict(request, DryRun=True), client=client, caller=label)
        result = self.launch(label + "-actual", request, client=client, caller=label)
        case = {"denied": denied or [], "admission_code": self.data["calls"][-1]["code"], "request_id": self.data["calls"][-1]["request_id"], "observations": []}
        self.data["cases"][label] = case
        self.save()
        if not result.get("Instances"):
            return None
        iid = result["Instances"][0]["InstanceId"]
        case["instance"] = iid
        case["admitted_state"] = result["Instances"][0]["State"]
        self.save()
        deadline = time.monotonic() + 240
        attempt = 0
        while time.monotonic() < deadline:
            described = self.ec2(label + "-state-" + str(attempt), "describe_instances", {"InstanceIds": [iid]})
            instances = [item for reservation in described.get("Reservations", []) for item in reservation["Instances"]]
            if instances:
                instance = instances[0]
                case["observations"].append({"at": now(), **{key: instance.get(key) for key in ("State", "StateReason", "StateTransitionReason", "BlockDeviceMappings")}})
                self.save()
                if instance["State"]["Name"] == "running":
                    self.data["successful_instances"].append(iid)
                    case["outcome"] = "running"
                    self.save()
                    return iid
                if instance["State"]["Name"] == "terminated":
                    case["outcome"] = "terminated-after-admission"
                    self.save()
                    return None
            time.sleep(5)
            attempt += 1
        case["outcome"] = "bounded-observation-expired"
        self.data["gaps"].append(label + ": state did not settle within 240 seconds; cleanup terminates the owned instance")
        self.ec2(label + "-bounded-terminate", "terminate_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "terminated", label + "-bounded-terminal")
        self.save()
        return None

    def root(self, iid, label):
        result = self.ec2(label + "-instance", "describe_instances", {"InstanceIds": [iid]}, required=True)
        instance = result["Reservations"][0]["Instances"][0]
        self.ec2(label + "-status", "describe_instance_status", {"InstanceIds": [iid], "IncludeAllInstances": True})
        self.ec2(label + "-root-attribute", "describe_instance_attribute", {"InstanceId": iid, "Attribute": "blockDeviceMapping"})
        volume = next(mapping["Ebs"]["VolumeId"] for mapping in instance["BlockDeviceMappings"] if mapping["DeviceName"] == instance["RootDeviceName"])
        self.ec2(label + "-volume", "describe_volumes", {"VolumeIds": [volume]}, required=True)
        self.observe(label + "-grants", "kms", "list_grants", {"KeyId": self.data["owned"]["key"]}, required=True)
        return volume

    def successful_guest(self, iid):
        first = self.console(iid, 1, "encrypted-first-guest")
        root = self.root(iid, "encrypted-running")
        self.data["successful_source"] = {"instance": iid, "root_volume": root, "first_guest_observed": first is not None}
        self.save()
        for label, flags in (("ordinary", {}), ("force", {"Force": True}), ("skip", {"SkipOsShutdown": True}), ("both", {"Force": True, "SkipOsShutdown": True})):
            self.ec2("stop-admission-" + label, "stop_instances", dict(InstanceIds=[iid], DryRun=True, **flags))
        self.ec2("stop-skip-os-shutdown", "stop_instances", {"InstanceIds": [iid], "SkipOsShutdown": True, "Force": False}, required=True)
        self.state(iid, "stopped", "encrypted-skip-stopped")
        self.root(iid, "encrypted-stopped")
        self.ec2("encrypted-start", "start_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "running", "encrypted-restarted")
        self.console(iid, 2, "encrypted-restart-guest")
        self.root(iid, "encrypted-restarted")
        self.ec2("stop-force-graceful", "stop_instances", {"InstanceIds": [iid], "Force": True, "SkipOsShutdown": False}, required=True)
        self.state(iid, "stopped", "encrypted-force-stopped")
        self.root(iid, "encrypted-force-stopped")
        prefix = "arn:aws:ec2:" + self.args.region + ":"
        snapshot_statements = [allow("ec2:CreateSnapshot", [prefix + self.args.account + ":volume/" + root, prefix + ":snapshot/*"]),
            allow("ec2:CreateTags", prefix + ":snapshot/*", {"StringEquals": {"ec2:CreateAction": "CreateSnapshot", "aws:RequestTag/suite": self.data["prefix"]}})]
        self.bound_role(self.launch_statements + self.kms_statements + snapshot_statements)
        time.sleep(10)
        client = self.restricted("snapshot-deny-all-kms", ["kms:*"])
        result = self.ec2("stopped-snapshot-deny-all-kms", "create_snapshot", {"VolumeId": root,
            "Description": self.data["prefix"] + " stopped encrypted root with caller KMS explicitly denied",
            "TagSpecifications": self.tags("snapshot")}, client=client, caller="snapshot-deny-all-kms")
        self.data["stopped_snapshot"] = {"request_code": self.data["calls"][-1]["code"], "snapshot_id": result.get("SnapshotId")}
        self.save()
        if result.get("SnapshotId"):
            deadline = time.monotonic() + 240
            attempt = 0
            while time.monotonic() < deadline:
                response = self.ec2("stopped-snapshot-state-" + str(attempt), "describe_snapshots", {"SnapshotIds": [result["SnapshotId"]]})
                if response.get("Snapshots") and response["Snapshots"][0]["State"] in ("completed", "error"):
                    self.data["stopped_snapshot"]["terminal"] = response["Snapshots"][0]
                    break
                time.sleep(10)
                attempt += 1
            else:
                self.data["gaps"].append("Stopped snapshot did not settle within 240 seconds; positive admission does not prove snapshot completion")
        self.observe("after-stopped-snapshot-grants", "kms", "list_grants", {"KeyId": self.data["owned"]["key"]})
        self.save()

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        self.data["experiment_deadline"] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.args.live_seconds)).isoformat()
        self.save()
        signal.alarm(self.args.live_seconds)
        self.setup_storage()
        source = self.launch_case("allow-kms")
        if source:
            self.successful_guest(source)
            self.ec2("terminate-encrypted-source", "terminate_instances", {"InstanceIds": [source]}, required=True)
            self.state(source, "terminated", "encrypted-source-terminal")
        else:
            self.data["gaps"].append("Fully allowed encrypted launch did not reach running; successful guest storage lifecycle was unavailable")
        for label, action in (("deny-grant", "kms:CreateGrant"), ("deny-data-key", "kms:GenerateDataKeyWithoutPlaintext"), ("deny-decrypt", "kms:Decrypt")):
            iid = self.launch_case(label, [action])
            self.observe(label + "-grants", "kms", "list_grants", {"KeyId": self.data["owned"]["key"]})
            if iid:
                self.console(iid, 1, label + "-guest", seconds=120)
                self.root(iid, label + "-running")
                self.ec2(label + "-terminate", "terminate_instances", {"InstanceIds": [iid]}, required=True)
                self.state(iid, "terminated", label + "-terminal")
        self.data["capture_complete_at"] = now()
        self.save()

    def cleanup(self):
        try:
            super().cleanup()
        finally:
            key = self.data["owned"].get("key")
            if key:
                response = self.observe("cleanup-owned-key-grants", "kms", "list_grants", {"KeyId": key})
                for grant in response.get("Grants", []):
                    self.observe("cleanup-owned-grant-" + grant["GrantId"], "kms", "revoke_grant", {"KeyId": key, "GrantId": grant["GrantId"]})
                remaining = self.observe("cleanup-owned-key-grants-after", "kms", "list_grants", {"KeyId": key})
                grants_verified = self.data["calls"][-1]["code"] == "Success" and not remaining.get("Truncated")
                self.data["cleanup"]["grant_absence_verified"] = grants_verified and not remaining.get("Grants")
                self.data["cleanup"]["remaining_grants"] = [grant["GrantId"] for grant in remaining.get("Grants", [])]
                described = self.observe("cleanup-key-state-before", "kms", "describe_key", {"KeyId": key})
                if described.get("KeyMetadata", {}).get("KeyState") != "PendingDeletion":
                    self.observe("cleanup-schedule-key-deletion", "kms", "schedule_key_deletion", {"KeyId": key, "PendingWindowInDays": 7})
                final = self.observe("cleanup-key-pending-deletion", "kms", "describe_key", {"KeyId": key})
                self.data["cleanup"]["key_deletion"] = final.get("KeyMetadata", {})
                scheduled = final.get("KeyMetadata", {}).get("KeyState") == "PendingDeletion"
                self.data["cleanup"]["key_scheduled_deletion_verified"] = scheduled
                self.data["cleanup"]["complete"] = self.data["cleanup"].get("complete", False) and scheduled and grants_verified and not self.data["cleanup"]["remaining_grants"]
                self.save()
                if not self.data["cleanup"]["complete"]:
                    raise RuntimeError("Owned encrypted-resource cleanup incomplete; inspect ledger and use --cleanup-only")

    def handoff(self):
        super().handoff()
        path = self.args.output.with_name(self.args.output.stem + "_handoff.json")
        summary = json.loads(path.read_text())
        summary.update(cases=self.data.get("cases", {}), successful_source=self.data.get("successful_source"),
            stopped_snapshot=self.data.get("stopped_snapshot"),
            runtime_boundary="Native encrypted AL2023/Nitro guest and KMS evidence only. QEMU/KVM firmware/device compatibility and local encrypted disk handling require separate real-runtime proof.")
        summary["kms_cloudtrail"] = [{"call_label": row.get("call_label"), "event": row["event"]}
            for row in self.data.get("cloudtrail", {}).get("events", []) if row["event"].get("eventSource") == "kms.amazonaws.com"]
        path.write_text(json.dumps(sanitized(summary), indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", choices=["us-east-1"], default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/instances_storage_encryption.json"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--audit-only", action="store_true")
    parser.add_argument("--live-seconds", type=int, choices=range(300, 1801), default=1800, metavar="300..1800")
    args = parser.parse_args()
    capture = StorageCapture(args)
    if args.audit_only:
        if not capture.data["cleanup"].get("complete"):
            raise RuntimeError("Finish owned cleanup before audit harvest")
        capture.audit()
        capture.handoff()
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
        capture.handoff()


if __name__ == "__main__":
    main()
