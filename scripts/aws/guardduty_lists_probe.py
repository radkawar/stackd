#!/usr/bin/env python3
"""Bounded native GuardDuty IP-list capture on an empty regional boundary.

Only exact-owned detectors, lists, and S3 sources are changed. Existing service
roles are never explicitly changed or deleted. No samples or traffic are sent.
"""
import argparse
import json
from pathlib import Path
import signal
import sys
import time
import uuid

from guardduty_probe import FEATURES, Probe, ROOT, now


KINDS = {
    "ip": ("ip_set", "IpSetId", "IpSetIds", "ipset", 1),
    "threat": ("threat_intel_set", "ThreatIntelSetId", "ThreatIntelSetIds", "threatintelset", 6),
}
SOURCES = [
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload-lists.html",
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-lists-prerequisites.html",
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-lists-update-procedure.html",
] + ["https://docs.aws.amazon.com/guardduty/latest/APIReference/API_" + op + kind + ".html"
     for kind in ("IPSet", "ThreatIntelSet") for op in ("Create", "Get", "Update", "Delete")]
SOURCES += ["https://docs.aws.amazon.com/guardduty/latest/APIReference/API_List" + kind + ".html"
            for kind in ("IPSets", "ThreatIntelSets", "TagsForResource")]


class ListsProbe(Probe):
    def __init__(self, args):
        super().__init__(args)
        self.prefix = "stackd-gd-lists-" + uuid.uuid4().hex[:16]
        self.tags = {"stackd-probe": self.prefix}
        self.bucket = None
        self.lists = {kind: [] for kind in KINDS}
        self.primary = {}
        self.fixture.update(
            sources=SOURCES,
            scope="Exact-owned IPSet/ThreatIntelSet lifecycle and private S3 TXT sources; empty regional detector boundary; all optional features disabled; no sample findings, synthetic traffic, or explicit changes to existing resources.",
            sanitization="Authorized account and caller identity replaced consistently by Probe. No credentials or authorization headers retained.",
            bounds={"observation_seconds": args.observe_seconds,
                    "cleanup_seconds": args.cleanup_seconds,
                    "poll_seconds": args.poll_seconds,
                    "sdk_total_max_attempts": 1},
            execution={"python": sys.executable, "profile": args.profile},
            transitions=[],
        )
        self.fixture["owned"].update(prefix=self.prefix, lists=self.lists, object_keys=[])
        self.fixture["limitations"].extend([
            "No detection traffic or sample findings are generated. Lifecycle admission is not evidence of detection effects.",
            "AWS documents list transitions normally within 15 minutes and sometimes 40 minutes; bounded pending observations do not establish eventual failure.",
            "Preexisting AWSServiceRoleForAmazonGuardDuty is not adopted for cleanup, even if a prior capture owns it. Its prior native deletion blocker remains outside this probe.",
        ])

    def policy_snapshot_after(self, source_path):
        source = json.loads(source_path.read_text())
        if not (source.get("detector_cleanup_verified")
                and source.get("owned", {}).get("prefix", "").startswith("stackd-gd-lists-")):
            raise RuntimeError("Snapshot requires a completed owned list capture")
        self.fixture["scope"] = "Read-only post-cleanup IAM policy snapshot for the preexisting GuardDuty service-linked role; no resources created, changed, or deleted."
        self.fixture["owned"] = {}
        self.fixture["source_fixture"] = str(source_path)
        self.fixture["limitations"] = [
            "Before-create, inactive-create, update, and pre-delete IAM policy snapshots were not captured. This post-cleanup snapshot cannot establish policy creation timing or granularity.",
            "The preexisting service-linked role and its previously reported deletion blocker are not adopted for cleanup.",
        ]
        self.require(self.call("sts", "get_caller_identity", "policy-snapshot-identity"))
        self.region = source["region"]
        self.fixture["region"] = self.region
        role = self.require(self.call("iam", "get_role", "policy-snapshot-role", RoleName="AWSServiceRoleForAmazonGuardDuty"))
        original = next(row for row in source["observations"] if row["case"] == "service-role-before")
        if role["Role"]["RoleId"] != original["output"]["Role"]["RoleId"]:
            raise RuntimeError("Service-linked role identity changed since source capture")
        marker = None
        for page in range(10):
            request = {"RoleName": "AWSServiceRoleForAmazonGuardDuty"}
            if marker:
                request["Marker"] = marker
            listed = self.require(self.call("iam", "list_role_policies", "post-cleanup-inline-policies-" + str(page), **request))
            for name in listed.get("PolicyNames", []):
                self.call("iam", "get_role_policy", "post-cleanup-inline-policy-" + name,
                          RoleName=request["RoleName"], PolicyName=name)
            if not listed.get("IsTruncated"):
                break
            marker = listed["Marker"]
        else:
            self.fixture["limitations"].append("IAM inline policy pagination exceeded the ten-page bound.")
        self.fixture["read_only_snapshot_complete"] = True
        self.fixture["finished_at"] = now()
        self.save()

    def operation(self, kind, verb, case, identifier=None, **fields):
        stem, id_key, _, _, _ = KINDS[kind]
        if identifier is not None:
            fields[id_key] = identifier
        operation = verb + "_" + stem + ("s" if verb == "list" else "")
        row = self.gd(operation, kind + "-" + case, DetectorId=self.detector, **fields)
        if verb == "create" and row["code"] == "Success":
            identifier = row["output"][id_key]
            if identifier not in self.lists[kind]:
                self.lists[kind].append(identifier)
                self.save()
        if verb == "get":
            self.fixture["transitions"].append({
                "kind": kind, "id": identifier, "case": case, "at": row["at"],
                "code": row["code"], "status": row["output"].get("Status"),
            })
            self.save()
        return row

    def create(self, kind, case, **fields):
        request = dict(Name=self.prefix + "-" + kind, Format="TXT", Activate=False,
                       Location=self.location("missing.txt"), ClientToken=uuid.uuid4().hex,
                       Tags=self.tags)
        request.update(fields)
        return self.operation(kind, "create", case, **request)

    def location(self, key):
        return "https://s3." + self.region + ".amazonaws.com/" + self.bucket + "/" + key

    def source_setup(self):
        name = self.prefix
        request = {"Bucket": name}
        if self.region != "us-east-1":
            request["CreateBucketConfiguration"] = {"LocationConstraint": self.region}
        created = self.call("s3", "create_bucket", "source-bucket-create", **request)
        if created["code"] != "Success":
            self.fixture["blocker"] = "Exact-owned S3 bucket creation failed: " + created["code"]
            self.save()
            return False
        self.bucket = name
        self.fixture["owned"]["bucket"] = name
        self.save()
        self.require(self.call("s3", "put_bucket_tagging", "source-bucket-tag", Bucket=name,
                               Tagging={"TagSet": [{"Key": key, "Value": value} for key, value in self.tags.items()]}))
        self.require(self.call("s3", "put_public_access_block", "source-bucket-private", Bucket=name,
                               PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                                               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}))
        for kind in KINDS:
            self.put_source(kind, "initial", "192.0.2.0/24\n198.51.100.1\n203.0.113.1\n")
        return True

    def put_source(self, kind, suffix, body):
        key = kind + ".txt"
        # Register exact key before the mutation so interruption still cleans it.
        if key not in self.fixture["owned"]["object_keys"]:
            self.fixture["owned"]["object_keys"].append(key)
            self.save()
        return self.require(self.call("s3", "put_object", kind + "-source-put-" + suffix,
                                      Bucket=self.bucket, Key=key, Body=body, ContentType="text/plain",
                                      ServerSideEncryption="AES256", Tagging="stackd-probe=" + self.prefix))

    def missing_cases(self, kind):
        missing = uuid.uuid4().hex
        for verb in ("get", "update", "delete"):
            self.operation(kind, verb, "missing-id-" + verb, missing)
        self.operation(kind, "list", "empty-list")
        for maximum in (0, 51):
            self.operation(kind, "list", "max-results-" + str(maximum), MaxResults=maximum)
        self.operation(kind, "list", "invalid-next-token", NextToken="not-a-native-token")

    def lifecycle_cases(self, kind):
        self.missing_cases(kind)
        self.create(kind, "create-invalid-format", Format="INVALID")
        self.create(kind, "create-empty-name", Name="")
        self.create(kind, "create-invalid-location", Location="not-a-location")
        self.create(kind, "create-invalid-owner-length", ExpectedBucketOwner="123")
        token = uuid.uuid4().hex
        row = self.create(kind, "create-inactive-missing-source", ClientToken=token)
        if row["code"] != "Success":
            self.fixture["limitations"].append(kind + " inactive missing-source creation failed; trying an existing exact-owned object next.")
            row = self.create(kind, "create-inactive-existing-source", Location=self.location(kind + ".txt"))
        if row["code"] != "Success":
            self.fixture["limitations"].append(kind + " lifecycle unavailable: " + row["code"] + "; see native error for prerequisite.")
            self.save()
            return
        identifier = row["output"][KINDS[kind][1]]
        self.primary[kind] = identifier
        original = {key: value for key, value in row["input"].items() if key != "DetectorId"}
        self.operation(kind, "create", "token-replay", **original)
        self.operation(kind, "create", "token-conflict-name", **dict(original, Name=self.prefix + "-changed"))
        self.operation(kind, "create", "token-conflict-tags", **dict(original, Tags=dict(self.tags, Changed="yes")))
        self.operation(kind, "get", "created", identifier)
        for case, fields in (
                ("update-empty", {}),
                ("update-empty-name", {"Name": ""}),
                ("update-long-name", {"Name": "x" * 301}),
                ("update-punctuation-name", {"Name": "owned!list.name"}),
                ("update-whitespace-name", {"Name": "  owned list _ -  "}),
                ("update-invalid-location", {"Location": "not-a-location"}),
                ("update-s3-uri", {"Location": "s3://" + self.bucket + "/" + kind + ".txt"}),
                ("update-wrong-owner-inactive", {"Location": self.location(kind + ".txt"), "ExpectedBucketOwner": "000000000000", "Activate": False}),
                ("update-invalid-owner-length", {"ExpectedBucketOwner": "123"}),
                ("update-inactive-missing-source", {"Name": self.prefix + "-" + kind + "-renamed", "Location": self.location("missing.txt"), "ExpectedBucketOwner": self.account, "Activate": False})):
            self.operation(kind, "update", case, identifier, **fields)
            self.operation(kind, "get", "after-" + case, identifier)
        arn = "arn:aws:guardduty:" + self.region + ":" + self.account + ":detector/" + self.detector + "/" + KINDS[kind][3] + "/" + identifier
        self.gd("list_tags_for_resource", kind + "-arn-shape-tags", ResourceArn=arn)
        self.gd("tag_resource", kind + "-tag-merge", ResourceArn=arn, Tags={"Extra": "one"})
        self.gd("list_tags_for_resource", kind + "-tags-merged", ResourceArn=arn)
        self.gd("untag_resource", kind + "-untag-extra", ResourceArn=arn, TagKeys=["Extra"])
        self.operation(kind, "get", "tags-after-untag", identifier)
        # One trusted set and six threat sets are the documented per-region limits.
        limit = KINDS[kind][4]
        for number in range(1, limit + 1):
            self.create(kind, "quota-create-" + str(number + 1), Name=self.prefix + "-" + kind + "-" + str(number),
                        Location=self.location(kind + ".txt"))
        token = None
        for page in range(10):
            fields = {"MaxResults": 1}
            if token:
                fields["NextToken"] = token
            listed = self.operation(kind, "list", "page-" + str(page), **fields)
            token = listed["output"].get("NextToken") if listed["code"] == "Success" else None
            if not token:
                break
        for case, fields in (
                ("activate-missing-source", {"Location": self.location("missing.txt"), "ExpectedBucketOwner": self.account}),
                ("activate-wrong-owner", {"Location": self.location(kind + ".txt"), "ExpectedBucketOwner": "000000000000"}),
                ("activate-owned-source", {"Location": self.location(kind + ".txt"), "ExpectedBucketOwner": self.account})):
            self.operation(kind, "update", case, identifier, Activate=True, **fields)
            self.operation(kind, "get", "after-" + case, identifier)

    def observe_activation(self):
        start = time.monotonic()
        deadline = start + self.args.observe_seconds
        remaining = dict(self.primary)
        self.fixture["activation_observation_started_at"] = now()
        while remaining:
            for kind, identifier in list(remaining.items()):
                row = self.operation(kind, "get", "activation-observe", identifier)
                status = row["output"].get("Status")
                if row["code"] != "Success" or status in ("ACTIVE", "ERROR", "INACTIVE"):
                    remaining.pop(kind)
            if not remaining or time.monotonic() >= deadline:
                break
            time.sleep(min(self.args.poll_seconds, max(0, deadline - time.monotonic())))
        self.fixture["activation_observation_elapsed_seconds"] = round(time.monotonic() - start, 3)
        self.fixture["activation_pending_at_bound"] = remaining
        for kind, identifier in self.primary.items():
            self.put_source(kind, "modified", "192.0.2.128/25\n203.0.113.2\n")
            self.operation(kind, "get", "after-source-modification-before-reactivation", identifier)
            self.operation(kind, "update", "reactivate-modified-source", identifier, Activate=True,
                           Location=self.location(kind + ".txt"), ExpectedBucketOwner=self.account)
            self.operation(kind, "get", "after-reactivation-request", identifier)
        self.save()

    def cleanup(self):
        self.cleanup_phase = True
        problems = []

        def attempt(label, fn):
            try:
                return fn()
            except Exception as error:
                problems.append({"step": label, "error": type(error).__name__ + ": " + str(error)})
                self.fixture["cleanup_problems"] = problems
                self.save()
                return None

        try:
            if self.detector:
                for kind, identifiers in self.lists.items():
                    for identifier in identifiers:
                        attempt(kind + "-delete", lambda k=kind, i=identifier: self.operation(k, "delete", "delete-owned", i))
                deadline = time.monotonic() + self.args.cleanup_seconds
                pending = {(kind, identifier) for kind, ids in self.lists.items() for identifier in ids}
                while pending:
                    for kind, identifier in list(pending):
                        row = attempt(kind + "-absence", lambda k=kind, i=identifier: self.operation(k, "get", "after-delete", i))
                        listed = attempt(kind + "-list-after-delete", lambda k=kind: self.operation(k, "list", "list-after-delete"))
                        if (row and listed and listed["code"] == "Success"
                                and identifier not in listed["output"].get(KINDS[kind][2], [])
                                and (row["code"] == "BadRequestException" or row["output"].get("Status") == "DELETED")):
                            pending.remove((kind, identifier))
                    if not pending or time.monotonic() >= deadline:
                        break
                    time.sleep(min(self.args.poll_seconds, max(0, deadline - time.monotonic())))
                self.fixture["list_cleanup_before_detector_verified"] = not pending
                self.fixture["list_cleanup_pending_at_bound"] = [list(pair) for pair in sorted(pending)]
                for kind, identifiers in self.lists.items():
                    for identifier in identifiers:
                        attempt(kind + "-delete-again", lambda k=kind, i=identifier: self.operation(k, "delete", "delete-owned-again", i))
                attempt("detector-suspend", lambda: self.gd("update_detector", "suspend-owned-detector", DetectorId=self.detector, Enable=False))
                attempt("detector-delete", lambda: self.gd("delete_detector", "delete-owned-detector", DetectorId=self.detector))
                after = attempt("detector-absence", lambda: self.gd("list_detectors", "detectors-after-cleanup"))
                self.fixture["detector_cleanup_verified"] = bool(after and after["code"] == "Success" and self.detector not in after["output"].get("DetectorIds", []))
            if self.bucket:
                # Never enumerate or empty another bucket. Delete only recorded owned keys.
                for key in self.fixture["owned"]["object_keys"]:
                    attempt("object-delete-" + key, lambda key=key: self.call("s3", "delete_object", "source-object-delete-" + key, Bucket=self.bucket, Key=key, ExpectedBucketOwner=self.account))
                attempt("bucket-delete", lambda: self.call("s3", "delete_bucket", "source-bucket-delete", Bucket=self.bucket, ExpectedBucketOwner=self.account))
                absent = attempt("bucket-absence", lambda: self.call("s3", "head_bucket", "source-bucket-absent", Bucket=self.bucket, ExpectedBucketOwner=self.account))
                self.fixture["bucket_cleanup_verified"] = bool(absent and absent["code"] in ("404", "NoSuchBucket", "NotFound"))
            role_id = self.fixture["owned"].get("service_role_id")
            if role_id and self.fixture.get("detector_cleanup_verified"):
                role = attempt("role-identity", lambda: self.call("iam", "get_role", "owned-role-identity", RoleName="AWSServiceRoleForAmazonGuardDuty"))
                if role and role["code"] == "Success" and role["output"]["Role"]["RoleId"] == role_id:
                    deleted = attempt("role-delete", lambda: self.call("iam", "delete_service_linked_role", "owned-role-delete", RoleName="AWSServiceRoleForAmazonGuardDuty"))
                    if deleted and deleted["code"] == "Success":
                        deadline = time.monotonic() + self.args.cleanup_seconds
                        while True:
                            status = attempt("role-delete-status", lambda: self.call("iam", "get_service_linked_role_deletion_status", "owned-role-delete-status", DeletionTaskId=deleted["output"]["DeletionTaskId"]))
                            if not status or status["code"] != "Success" or status["output"]["Status"] in ("SUCCEEDED", "FAILED") or time.monotonic() >= deadline:
                                break
                            time.sleep(self.args.poll_seconds)
                absent = attempt("role-absence", lambda: self.call("iam", "get_role", "owned-role-absent", RoleName="AWSServiceRoleForAmazonGuardDuty"))
                self.fixture["service_role_cleanup_verified"] = bool(absent and absent["code"] == "NoSuchEntity")
            elif self.fixture.get("service_role_preexisting"):
                self.fixture["preexisting_service_role_untouched"] = True
        finally:
            self.fixture["finished_at"] = now()
            self.fixture["cleanup_problems"] = problems
            self.save()
        if (problems or (self.detector and not self.fixture.get("detector_cleanup_verified"))
                or (self.bucket and not self.fixture.get("bucket_cleanup_verified"))
                or (self.fixture["owned"].get("service_role_id") and not self.fixture.get("service_role_cleanup_verified"))):
            raise RuntimeError("Owned cleanup not fully verified; inspect retained fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--regions", default="us-west-2,eu-north-1,eu-west-1")
    parser.add_argument("--output", type=Path, default=ROOT / ".stackd/probes/guardduty/ip_lists.json")
    parser.add_argument("--policy-snapshot-after", type=Path, help="Read-only SLR snapshot after this completed list capture")
    parser.add_argument("--observe-seconds", type=int, default=90)
    parser.add_argument("--cleanup-seconds", type=int, default=90)
    parser.add_argument("--poll-seconds", type=int, default=10)
    args = parser.parse_args()
    if args.observe_seconds < 0 or args.cleanup_seconds < 0 or args.poll_seconds < 1:
        parser.error("Observation/cleanup windows must be nonnegative and polling positive")
    if args.output.exists():
        args.output = args.output.with_name(args.output.stem + "-" + uuid.uuid4().hex[:12] + args.output.suffix)
    # Reuse detector admission and feature checks, but never sample/event cases.
    args.event_delivery_enabled = True
    args.event_delivery_only = True
    probe = ListsProbe(args)
    if args.policy_snapshot_after:
        probe.policy_snapshot_after(args.policy_snapshot_after)
        print(json.dumps({"fixture": str(args.output), "read_only": True}), flush=True)
        return

    def interrupted(signum, frame):
        raise InterruptedError("Signal " + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if probe.discover() and probe.detector_cases() and probe.source_setup():
            probe.fixture["requested_features"] = FEATURES
            for kind in KINDS:
                probe.lifecycle_cases(kind)
            probe.observe_activation()
    except BaseException as error:
        probe.fixture["interruption"] = {"type": type(error).__name__, "message": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()
        print(json.dumps({"fixture": str(args.output), "cleanup_finished_at": probe.fixture.get("finished_at")}), flush=True)


if __name__ == "__main__":
    main()
