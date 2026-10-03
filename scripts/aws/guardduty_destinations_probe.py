#!/usr/bin/env python3
"""Bounded native publishing-destination capture; only exact-owned AWS resources.

Reuses GuardDuty detector admission and safe sample-event boundary discovery.
No preexisting detector, bucket, key, or IAM role is explicitly changed.
"""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import signal
import sys
import time
import uuid

from guardduty_probe import FEATURES, Probe, ROOT, now


class DestinationsProbe(Probe):
    def __init__(self, args):
        super().__init__(args)
        self.prefix = "stackd-gd-dest-" + uuid.uuid4().hex[:16]
        self.tags = {"stackd-probe": self.prefix}
        self.bucket = None
        self.key = None
        self.destinations = []
        self.captured_objects = set()
        self.fixture.update(
            sources=["https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html"] + [
                "https://docs.aws.amazon.com/guardduty/latest/APIReference/API_" + op + "PublishingDestination" + ("s" if op == "List" else "") + ".html"
                for op in ("Create", "Describe", "List", "Update", "Delete")],
            scope="Exact-owned enabled detector, private S3 bucket and KMS key; all optional features disabled; at most one explicit AWS sample type; no synthetic traffic; no explicit IAM changes.",
            bounds={"observation_seconds": args.observe_seconds, "poll_seconds": args.poll_seconds,
                    "sdk_total_max_attempts": 1, "object_capture_max_bytes": 2 * 1024 * 1024},
            execution={"python": sys.executable, "profile": args.profile},
            objects=[],
        )
        self.fixture["owned"].update(prefix=self.prefix, destination_ids=self.destinations, object_keys=[])
        self.fixture["limitations"].extend([
            "Lifecycle admission and validation markers do not establish finding export format or timing.",
            "Zero findings exports in the bounded window is inconclusive; documented initial delivery is about five minutes.",
            "Existing service-linked role is never explicitly changed or deleted, including prior cleanup blockers.",
            "Decoded text is account-sanitized; byte lengths and SHA256 describe actual fetched bytes. Binary bodies are retained only for non-finding markers.",
        ])

    def operation(self, verb, case, identifier=None, **fields):
        if identifier is not None:
            fields["DestinationId"] = identifier
        row = self.gd(verb + "_publishing_destination" + ("s" if verb == "list" else ""),
                      case, DetectorId=self.detector, **fields)
        if verb == "create" and row["code"] == "Success":
            identifier = row["output"]["DestinationId"]
            if identifier not in self.destinations:
                self.destinations.append(identifier)
                self.save()
        return row

    def properties(self, suffix=""):
        return {"DestinationArn": "arn:aws:s3:::" + self.bucket + suffix, "KmsKeyArn": self.key["Arn"]}

    def create(self, case, **overrides):
        fields = {"DestinationType": "S3", "DestinationProperties": self.properties(),
                  "ClientToken": uuid.uuid4().hex}
        if self.fixture["create_tags_supported"]:
            fields["Tags"] = self.tags
        fields.update(overrides)
        return self.operation("create", case, **fields)

    def setup(self):
        # Avoid creating a global IAM role if it is absent; never adopt existing roles.
        if not self.fixture.get("service_role_preexisting"):
            self.fixture["blocker"] = "No preexisting GuardDuty service-linked role; refusing implicit global IAM creation."
            self.save()
            return False
        if not self.detector_cases():
            return False
        self.fixture["requested_features"] = FEATURES
        self.fixture["create_tags_supported"] = "Tags" in self.client("guardduty").meta.service_model.operation_model("CreatePublishingDestination").input_shape.members
        request = {"Bucket": self.prefix}
        if self.region != "us-east-1":
            request["CreateBucketConfiguration"] = {"LocationConstraint": self.region}
        self.require(self.call("s3", "create_bucket", "bucket-create", **request))
        self.bucket = self.prefix
        self.fixture["owned"]["bucket"] = self.bucket
        self.save()
        self.require(self.call("s3", "put_public_access_block", "bucket-private", Bucket=self.bucket,
                               PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                                               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}))
        self.require(self.call("s3", "put_bucket_tagging", "bucket-tag", Bucket=self.bucket,
                               Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in self.tags.items()]}))
        created = self.require(self.call("kms", "create_key", "key-create", Description=self.prefix,
                                         KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
                                         Tags=[{"TagKey": k, "TagValue": v} for k, v in self.tags.items()]))
        self.key = created["KeyMetadata"]
        self.fixture["owned"]["kms_key"] = self.key
        self.save()
        return True

    def policies(self):
        detector_arn = "arn:aws:guardduty:" + self.region + ":" + self.account + ":detector/" + self.detector
        self.fixture["owned"]["detector_arn"] = detector_arn
        condition = {"StringEquals": {"aws:SourceAccount": self.account, "aws:SourceArn": detector_arn}}
        principal = {"Service": "guardduty.amazonaws.com"}
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "EnableOwnedAccountPermissions", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::" + self.account + ":root"}, "Action": "kms:*", "Resource": "*"},
            {"Sid": "AllowGuardDutyKey", "Effect": "Allow", "Principal": principal, "Action": "kms:GenerateDataKey", "Resource": self.key["Arn"], "Condition": condition},
        ]}
        self.require(self.call("kms", "put_key_policy", "key-policy", KeyId=self.key["KeyId"], PolicyName="default", Policy=json.dumps(policy)))
        bucket_arn = "arn:aws:s3:::" + self.bucket
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "AllowGetBucketLocation", "Effect": "Allow", "Principal": principal, "Action": "s3:GetBucketLocation", "Resource": bucket_arn, "Condition": condition},
            {"Sid": "AllowPutObject", "Effect": "Allow", "Principal": principal, "Action": "s3:PutObject", "Resource": bucket_arn + "/*", "Condition": condition},
            {"Sid": "DenyUnencryptedUploads", "Effect": "Deny", "Principal": principal, "Action": "s3:PutObject", "Resource": bucket_arn + "/*", "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}}},
            {"Sid": "DenyIncorrectKey", "Effect": "Deny", "Principal": principal, "Action": "s3:PutObject", "Resource": bucket_arn + "/*", "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption-aws-kms-key-id": self.key["Arn"]}}},
            {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": bucket_arn + "/*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        ]}
        self.require(self.call("s3", "put_bucket_policy", "bucket-policy", Bucket=self.bucket, Policy=json.dumps(policy), ExpectedBucketOwner=self.account))

    def delete_unexpected(self, row):
        if row["code"] == "Success":
            self.operation("delete", "delete-unexpected-" + row["case"], row["output"]["DestinationId"])

    def negative_cases(self):
        missing = uuid.uuid4().hex
        for verb in ("describe", "update", "delete"):
            self.operation(verb, "missing-destination-" + verb, missing)
        self.operation("list", "empty-list")
        for fields, case in (({"MaxResults": 0}, "list-zero-limit"), ({"MaxResults": 51}, "list-large-limit"),
                             ({"NextToken": "not-a-native-token"}, "list-invalid-token")):
            self.operation("list", case, **fields)
        for case, fields in (
            ("create-invalid-type", {"DestinationType": "INVALID"}),
            ("create-empty-properties", {"DestinationProperties": {}}),
            ("create-missing-key", {"DestinationProperties": {"DestinationArn": self.properties()["DestinationArn"]}}),
            ("create-missing-bucket", {"DestinationProperties": {"KmsKeyArn": self.key["Arn"]}}),
            ("create-malformed-bucket", {"DestinationProperties": dict(self.properties(), DestinationArn="not-an-arn")}),
            ("create-malformed-key", {"DestinationProperties": dict(self.properties(), KmsKeyArn="not-an-arn")}),
            ("create-nonexistent-bucket", {"DestinationProperties": dict(self.properties(), DestinationArn="arn:aws:s3:::" + self.prefix + "-missing")}),
            ("create-nonexistent-key", {"DestinationProperties": dict(self.properties(), KmsKeyArn="arn:aws:kms:" + self.region + ":" + self.account + ":key/" + str(uuid.uuid4()))}),
        ):
            self.delete_unexpected(self.create(case, **fields))
        for omitted in ("DestinationProperties", "DestinationType"):
            fields = {"DestinationType": "S3", "DestinationProperties": self.properties(), "ClientToken": uuid.uuid4().hex}
            del fields[omitted]
            self.delete_unexpected(self.operation("create", "create-omitted-" + omitted, **fields))
        self.delete_unexpected(self.create("create-without-service-policies"))

    def folder(self, key):
        self.fixture["owned"]["object_keys"].append(key)
        self.save()
        self.require(self.call("s3", "put_object", "owned-folder-" + key, Bucket=self.bucket, Key=key, Body=b"",
                               ServerSideEncryption="aws:kms", SSEKMSKeyId=self.key["Arn"], ExpectedBucketOwner=self.account))

    def prefix_authority(self):
        """Compare GuardDuty admission with proven caller-side S3/KMS denial."""
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "guardduty:*", "Resource": "*"},
            {"Effect": "Deny", "Action": ["s3:*", "kms:*"], "Resource": "*"},
        ]}
        # Do not route this response through the fixture recorder: credentials
        # remain process-local. The short session creates no persistent IAM user.
        session = self.client("sts").get_federation_token(
            Name=self.prefix[:32], DurationSeconds=900, Policy=json.dumps(policy))
        credentials = session["Credentials"]
        self.fixture["restricted_caller"] = {
            "arn": session["FederatedUser"]["Arn"], "policy": policy,
            "expiration": str(credentials["Expiration"]),
        }
        self.folder("explicit-prefix/")
        self.folder("explicit-prefix/AWSLogs/" + self.account + "/GuardDuty/" + self.region + "/")
        baseline = self.create("admin-existing-prefix", DestinationProperties=self.properties("/explicit-prefix"))
        identifier = self.require(baseline)["DestinationId"]
        self.require(self.operation("delete", "admin-delete-baseline", identifier))
        saved = self.clients.copy()
        try:
            for service in ("guardduty", "s3", "kms"):
                client = self.session.client(
                    service, region_name=self.region, config=self.config,
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"])
                if service == "guardduty":
                    client.meta.events.register("after-call.guardduty", self.capture_wire)
                self.clients[(service, self.region)] = client
            self.call("s3", "list_objects_v2", "restricted-list-prefix", Bucket=self.bucket, Prefix="explicit-prefix/")
            self.call("s3", "head_object", "restricted-head-prefix", Bucket=self.bucket, Key="explicit-prefix/")
            self.call("kms", "describe_key", "restricted-describe-key", KeyId=self.key["KeyId"])
            for label, suffix in (("existing-prefix", "/explicit-prefix"), ("missing-prefix", "/missing-prefix"), ("root", "")):
                created = self.create("restricted-create-" + label, DestinationProperties=self.properties(suffix))
                if created["code"] == "Success":
                    identifier = created["output"]["DestinationId"]
                    self.operation("describe", "restricted-describe-" + label, identifier)
                    self.operation("update", "restricted-update-existing-prefix-" + label, identifier, DestinationProperties=self.properties("/explicit-prefix"))
                    self.require(self.operation("delete", "restricted-delete-" + label, identifier))
        finally:
            self.clients = saved
        self.fixture["prefix_authority_complete"] = True
        self.save()

    def lifecycle(self):
        token = uuid.uuid4().hex
        created = self.create("create-valid-encrypted-root", ClientToken=token)
        if created["code"] != "Success":
            self.folder("AWSLogs/" + self.account + "/GuardDuty/" + self.region + "/")
            time.sleep(5)
            created = self.create("create-valid-after-folder-and-propagation", ClientToken=uuid.uuid4().hex)
        if created["code"] != "Success":
            self.fixture["blocker"] = "Documented owned S3/KMS policies did not admit destination; see native errors."
            self.save()
            return
        identifier = created["output"]["DestinationId"]
        original = {k: v for k, v in created["input"].items() if k != "DetectorId"}
        self.operation("create", "token-replay", **original)
        self.operation("create", "token-mismatch-properties", **dict(original, DestinationProperties=self.properties("/changed")))
        if self.fixture["create_tags_supported"]:
            self.operation("create", "token-mismatch-tags", **dict(original, Tags=dict(self.tags, Changed="yes")))
        self.operation("describe", "describe-created", identifier)
        listed = self.operation("list", "list-created", MaxResults=1)
        if listed["code"] == "Success" and listed["output"].get("NextToken"):
            self.operation("list", "list-created-next-page", MaxResults=1, NextToken=listed["output"]["NextToken"])
        self.create("quota-second-destination")
        arn = "arn:aws:guardduty:" + self.region + ":" + self.account + ":detector/" + self.detector + "/publishingdestination/" + identifier
        self.fixture["destination_resource_arn"] = arn
        if self.fixture["create_tags_supported"]:
            self.gd("list_tags_for_resource", "destination-arn-tags", ResourceArn=arn)
            self.gd("tag_resource", "destination-tag-merge", ResourceArn=arn, Tags={"Extra": "one"})
            self.gd("list_tags_for_resource", "destination-tags-merged", ResourceArn=arn)
            self.gd("untag_resource", "destination-untag", ResourceArn=arn, TagKeys=["Extra"])
        self.capture_objects("after-root-create")
        for case, fields in (
            ("update-omitted-properties", {}),
            ("update-empty-properties", {"DestinationProperties": {}}),
            ("update-key-only", {"DestinationProperties": {"KmsKeyArn": self.key["Arn"]}}),
            ("update-bucket-only", {"DestinationProperties": {"DestinationArn": self.properties()["DestinationArn"]}}),
            ("update-invalid-key", {"DestinationProperties": dict(self.properties(), KmsKeyArn="invalid")}),
            ("update-nonexistent-prefix", {"DestinationProperties": self.properties("/explicit-prefix")}),
        ):
            self.operation("update", case, identifier, **fields)
            self.operation("describe", "after-" + case, identifier)
        self.folder("explicit-prefix/")
        self.folder("explicit-prefix/AWSLogs/" + self.account + "/GuardDuty/" + self.region + "/")
        self.operation("create", "token-mismatch-valid-prefix", **dict(original, DestinationProperties=self.properties("/explicit-prefix")))
        self.operation("describe", "after-token-mismatch-valid-prefix", identifier)
        updated = self.operation("update", "update-existing-prefix", identifier, DestinationProperties=self.properties("/explicit-prefix"))
        if updated["code"] != "Success":
            self.require(self.operation("update", "restore-root", identifier, DestinationProperties=self.properties()))
        self.operation("describe", "before-sample", identifier)
        self.capture_objects("after-prefix-update")
        self.require(self.gd("create_sample_findings", "explicit-owned-sample", DetectorId=self.detector,
                             FindingTypes=["Recon:EC2/PortProbeUnprotectedPort"]))
        start = time.monotonic()
        deadline = start + self.args.observe_seconds
        self.fixture["export_observation_started_at"] = now()
        poll = 0
        while True:
            self.operation("describe", "observe-destination-" + str(poll), identifier)
            self.capture_objects("observe-" + str(poll))
            if time.monotonic() >= deadline:
                break
            time.sleep(min(self.args.poll_seconds, max(0, deadline - time.monotonic())))
            poll += 1
        self.fixture["export_observation_elapsed_seconds"] = round(time.monotonic() - start, 3)
        listed = self.gd("list_findings", "findings-at-bound", DetectorId=self.detector)
        if listed["code"] == "Success" and listed["output"].get("FindingIds"):
            self.gd("get_findings", "sample-at-bound", DetectorId=self.detector, FindingIds=listed["output"]["FindingIds"][:50])
        self.fixture["export_observation_result"] = "Finding objects observed" if any(o.get("finding_records") for o in self.fixture["objects"]) else "Bounded inconclusive: no decoded finding export observed"
        self.save()
        self.operation("delete", "delete-primary", identifier)
        self.operation("describe", "describe-after-delete", identifier)
        self.operation("delete", "delete-primary-again", identifier)
        self.operation("list", "list-after-delete")

    def capture_objects(self, case):
        response = self.require(self.call("s3", "list_objects_v2", "objects-" + case, Bucket=self.bucket, ExpectedBucketOwner=self.account))
        if response.get("IsTruncated"):
            self.fixture["limitations"].append("Object capture truncated at first S3 page; cleanup still paginates all objects.")
        for obj in response.get("Contents", []):
            identity = (obj["Key"], obj["ETag"])
            if identity in self.captured_objects:
                continue
            self.captured_objects.add(identity)
            row = self.call("s3", "get_object", "object-fetch-" + case, Bucket=self.bucket, Key=obj["Key"], ExpectedBucketOwner=self.account)
            if row["code"] != "Success":
                continue
            result = row["output"]
            stream = result.pop("Body")
            try:
                data = stream.read(2 * 1024 * 1024 + 1)
            finally:
                stream.close()
            entry = {"key": obj["Key"], "case": case, "metadata": result, "fetched_bytes": len(data),
                     "owned_folder": obj["Key"] in self.fixture["owned"]["object_keys"]}
            if len(data) > 2 * 1024 * 1024:
                entry["capture_truncated"] = True
            else:
                entry["sha256"] = hashlib.sha256(data).hexdigest()
                try:
                    decoded = gzip.decompress(data) if data.startswith(b"\x1f\x8b") else data
                    entry["gzip"] = data.startswith(b"\x1f\x8b")
                    entry["decoded_utf8"] = decoded.decode("utf-8")
                    records = []
                    for line in entry["decoded_utf8"].splitlines():
                        try:
                            record = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(record, dict) and ("type" in record or "Type" in record):
                            records.append(record)
                    if records:
                        entry["finding_records"] = records
                except (OSError, UnicodeDecodeError) as error:
                    entry["decode_error"] = str(error)
                    if not obj["Key"].endswith(".jsonl.gz"):
                        entry["body_base64"] = base64.b64encode(data).decode("ascii")
            self.fixture["objects"].append(entry)
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

        if self.detector:
            for identifier in self.destinations:
                attempt("destination-delete", lambda i=identifier: self.operation("delete", "cleanup-destination", i))
            listed = attempt("destination-list", lambda: self.operation("list", "cleanup-destinations-list"))
            self.fixture["destinations_cleanup_verified"] = bool(listed and listed["code"] == "Success" and not listed["output"].get("Destinations") and not listed["output"].get("NextToken"))
            attempt("detector-suspend", lambda: self.gd("update_detector", "cleanup-detector-suspend", DetectorId=self.detector, Enable=False))
            attempt("detector-delete", lambda: self.gd("delete_detector", "cleanup-detector-delete", DetectorId=self.detector))
            listed = attempt("detector-list", lambda: self.gd("list_detectors", "cleanup-detectors-list"))
            self.fixture["detector_cleanup_verified"] = bool(listed and listed["code"] == "Success" and self.detector not in listed["output"].get("DetectorIds", []))
        if self.bucket:
            attempt("final-object-capture", lambda: self.capture_objects("cleanup-final"))
            # This bucket was created by this invocation. Enumerate actual service-created keys, never another bucket.
            for page in range(20):
                listed = attempt("objects-list", lambda: self.call("s3", "list_objects_v2", "cleanup-objects-list", Bucket=self.bucket, ExpectedBucketOwner=self.account))
                if not listed or listed["code"] != "Success":
                    break
                objects = [{"Key": obj["Key"]} for obj in listed["output"].get("Contents", [])]
                if not objects:
                    break
                deleted = attempt("objects-delete", lambda: self.call("s3", "delete_objects", "cleanup-objects-delete", Bucket=self.bucket, Delete={"Objects": objects}, ExpectedBucketOwner=self.account))
                if not deleted or deleted["code"] != "Success" or deleted["output"].get("Errors"):
                    problems.append({"step": "objects-delete", "error": "Deletion failed or returned per-key errors"})
                    break
            attempt("bucket-delete", lambda: self.call("s3", "delete_bucket", "cleanup-bucket-delete", Bucket=self.bucket, ExpectedBucketOwner=self.account))
            absent = attempt("bucket-absence", lambda: self.call("s3", "head_bucket", "cleanup-bucket-absence", Bucket=self.bucket, ExpectedBucketOwner=self.account))
            self.fixture["bucket_cleanup_verified"] = bool(absent and absent["http_status"] == 404)
        if self.key:
            attempt("key-schedule", lambda: self.call("kms", "schedule_key_deletion", "cleanup-key-schedule", KeyId=self.key["KeyId"], PendingWindowInDays=7))
            status = attempt("key-status", lambda: self.call("kms", "describe_key", "cleanup-key-status", KeyId=self.key["KeyId"]))
            self.fixture["kms_deletion_scheduled_verified"] = bool(status and status["code"] == "Success" and status["output"]["KeyMetadata"]["KeyState"] == "PendingDeletion")
            if status and status["code"] == "Success":
                self.fixture["remaining_kms_key"] = status["output"]["KeyMetadata"]
        self.fixture["preexisting_service_role_not_explicitly_changed"] = True
        self.fixture["cleanup_problems"] = problems
        self.fixture["finished_at"] = now()
        self.save()
        if problems or (self.detector and not self.fixture.get("detector_cleanup_verified")) or (self.bucket and not self.fixture.get("bucket_cleanup_verified")) or (self.key and not self.fixture.get("kms_deletion_scheduled_verified")):
            raise RuntimeError("Cleanup incomplete; exact remaining ownership and errors retained in fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--regions", default="us-west-2,eu-north-1,eu-west-1")
    parser.add_argument("--output", type=Path, default=ROOT / ".stackd/probes/guardduty/publishing_destinations.json")
    parser.add_argument("--observe-seconds", type=int, default=120)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--prefix-authority", action="store_true", help="Compare destination prefix admission using a short-lived caller explicitly denied all S3/KMS access; no sample finding")
    args = parser.parse_args()
    if not 0 <= args.observe_seconds <= 600 or args.poll_seconds < 1:
        parser.error("Observation must be 0..600 seconds and polling positive")
    if args.output.exists():
        args.output = args.output.with_name(args.output.stem + "-" + uuid.uuid4().hex[:12] + args.output.suffix)
    args.event_delivery_enabled = True
    args.event_delivery_only = True
    probe = DestinationsProbe(args)

    def interrupted(signum, frame):
        raise InterruptedError("Signal " + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if probe.discover() and probe.setup():
            if args.prefix_authority:
                probe.policies()
                probe.prefix_authority()
            else:
                probe.negative_cases()
                probe.policies()
                probe.lifecycle()
    except BaseException as error:
        probe.fixture["interruption"] = {"type": type(error).__name__, "message": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()
        print(json.dumps({"fixture": str(args.output), "finished_at": probe.fixture.get("finished_at")}), flush=True)


if __name__ == "__main__":
    main()
