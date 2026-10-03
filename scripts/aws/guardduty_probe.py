#!/usr/bin/env python3
"""Native GuardDuty calibration on an empty regional boundary only.

Never changes a preexisting detector, role, rule, or account setting. Captures
explicit sample findings, not simulated threats or actual monitoring evidence.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

from appregistry_capture import now


ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "clones/aws-sdk-go-v2/codegen/sdk-codegen/aws-models/guardduty.json"
SOURCES = [
    "https://docs.aws.amazon.com/guardduty/latest/APIReference/API_" + name + ".html"
    for name in ("CreateDetector", "GetDetector", "UpdateDetector", "DeleteDetector",
                 "ListDetectors", "CreateSampleFindings", "ListFindings", "GetFindings",
                 "ArchiveFindings", "UnarchiveFindings", "UpdateFindingsFeedback",
                 "GetFindingsStatistics", "CreateFilter", "GetFilter", "UpdateFilter",
                 "DeleteFilter", "ListFilters", "TagResource", "UntagResource", "ListTagsForResource")
] + ["https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html",
     "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"]
FEATURES = [
    {"Name": name, "Status": "DISABLED"}
    for name in ("S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION",
                 "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "AI_PROTECTION", "AI_ANALYST", "RUNTIME_MONITORING")
]
FEATURES[-1]["AdditionalConfiguration"] = [
    {"Name": name, "Status": "DISABLED"}
    for name in ("EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT")
]


class Probe:
    def __init__(self, args):
        self.args = args
        if args.output.exists():
            raise RuntimeError("Refusing to overwrite retained evidence")
        os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        self.session = boto3.Session(profile_name=args.profile, region_name="us-east-1")
        self.config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                             retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=40)
        self.clients = {}
        self.last_wire = None
        self.account = args.account
        self.detector = None
        self.region = None
        self.filters = set()
        self.cleanup_phase = False
        self.identity_arn = None
        self.identity_id = None
        self.fixture = {
            "captured_at": now(), "sources": SOURCES,
            "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__,
                    "api_version": "2017-11-28",
                    "go_model_sha256": hashlib.sha256(MODEL.read_bytes()).hexdigest(),
                    "go_model_revision": subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=ROOT / "clones/aws-sdk-go-v2", text=True).strip()},
            "scope": "Empty regional detector boundary; explicit AWS sample findings only; all optional features disabled; no existing resources changed.",
            "sanitization": "Account and caller identity replaced consistently. AWS-provided fictional sample threat details, IDs, timestamps, and request IDs retained. No credentials or authorization headers captured.",
            "observations": [], "cleanup": [], "owned": {}, "limitations": [],
        }

    def client(self, service, region=None):
        key = (service, region or self.region or "us-east-1")
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=key[1], config=self.config)
            if service == "guardduty":
                self.clients[key].meta.events.register("after-call.guardduty", self.capture_wire)
        return self.clients[key]

    def capture_wire(self, http_response, **kwargs):
        self.last_wire = json.loads(http_response.content) if http_response.content else None

    def sanitize(self, value):
        if isinstance(value, dict):
            return {key: ("<omitted: unrelated existing rule pattern>"
                          if key == "EventPattern" and not (self.detector and self.detector in item)
                          else self.sanitize(item))
                    for key, item in value.items()
                    if key.lower() not in ("secretaccesskey", "sessiontoken", "authorization", "credentials")}
        if isinstance(value, (list, tuple)):
            return [self.sanitize(item) for item in value]
        if isinstance(value, str):
            for original, replacement in ((self.identity_arn, "arn:aws:iam::123456789012:user/native-probe"),
                                          (self.identity_id, "NATIVEPROBEIDENTITY"),
                                          (self.account, "123456789012")):
                if original:
                    value = value.replace(original, replacement)
        return value

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(self.sanitize(self.fixture), indent=2, default=str) + "\n")

    def call(self, service, operation, case, region=None, **request):
        row = {"case": case, "service": service, "region": region or self.region or "us-east-1",
               "operation": operation, "input": copy.deepcopy(request), "at": now()}
        self.last_wire = None
        try:
            response = getattr(self.client(service, region), operation)(**request)
            row["code"] = "Success"
        except ClientError as error:
            response = error.response
            row["code"] = response["Error"]["Code"]
        metadata = response.pop("ResponseMetadata", {})
        row.update(http_status=metadata.get("HTTPStatusCode"), request_id=metadata.get("RequestId"),
                   output=response)
        if service == "guardduty":
            row["wire_output"] = self.last_wire
        if service == "sts" and row["code"] == "Success":
            if response["Account"] != self.account:
                raise RuntimeError("Only the authorized account may be probed")
            self.identity_arn, self.identity_id = response["Arn"], response["UserId"]
        self.fixture["cleanup" if self.cleanup_phase else "observations"].append(row)
        self.save()
        print(json.dumps({key: row[key] for key in ("case", "code", "request_id")}), flush=True)
        return row

    def gd(self, operation, case, **request):
        return self.call("guardduty", operation, case, **request)

    @staticmethod
    def require(row):
        if row["code"] != "Success":
            raise RuntimeError(row["case"] + ": " + row["code"])
        return row["output"]

    def discover(self):
        self.require(self.call("sts", "get_caller_identity", "authorized-identity"))
        role = self.call("iam", "get_role", "service-role-before", RoleName="AWSServiceRoleForAmazonGuardDuty")
        self.fixture["service_role_preexisting"] = role["code"] == "Success"
        for region in self.args.regions.split(","):
            detectors = self.call("guardduty", "list_detectors", "detectors-before-" + region, region=region)
            if detectors["code"] != "Success" or detectors["output"].get("DetectorIds"):
                continue
            rules = self.call("events", "list_rules", "event-rules-before-" + region, region=region, Limit=100)
            if rules["code"] != "Success" or rules["output"].get("NextToken"):
                continue
            # GuardDuty Finding has neither CloudTrail's eventSource nor userIdentity.
            # Require a structural exclusion as well as a native pattern check.
            unsafe = False
            event = {"id": str(uuid.uuid4()), "account": self.account, "source": "aws.guardduty",
                     "detail-type": "GuardDuty Finding", "time": now().split(".")[0] + "Z", "region": region,
                     "resources": [], "detail": {}}
            for rule in rules["output"].get("Rules", []):
                if not rule.get("State", "").startswith("ENABLED") or not rule.get("EventPattern"):
                    continue
                pattern = json.loads(rule["EventPattern"])
                excluded = any(
                    isinstance(pattern.get(key), list)
                    and all(isinstance(item, str) for item in pattern[key])
                    and expected not in pattern[key]
                    for key, expected in (("source", "aws.guardduty"), ("detail-type", "GuardDuty Finding")))
                excluded = excluded or any(
                    key.split(".")[0] in ("eventSource", "userIdentity")
                    and isinstance(values, list) and all(isinstance(item, str) for item in values)
                    for key, values in pattern.get("detail", {}).items())
                result = self.call("events", "test_event_pattern", "sample-rule-exclusion-" + rule["Name"],
                                   region=region, EventPattern=rule["EventPattern"], Event=json.dumps(event))
                if not excluded or result["code"] != "Success" or result["output"].get("Result"):
                    unsafe = True
            if unsafe:
                continue
            self.region = region
            self.fixture["region"] = region
            self.fixture["empty_boundary_verified"] = True
            break
        if self.region is None:
            self.fixture["blocker"] = "No requested region had an empty detector boundary and proven sample-event exclusion from existing EventBridge rules. Existing resources were not modified."
        self.save()
        return "blocker" not in self.fixture

    def detector_cases(self):
        before = self.require(self.gd("list_detectors", "empty-boundary-recheck"))
        if before.get("DetectorIds"):
            raise RuntimeError("Detector appeared after discovery; refusing to mutate it")
        role = self.call("iam", "get_role", "service-role-immediate-before",
                         RoleName="AWSServiceRoleForAmazonGuardDuty")
        if role["code"] not in ("Success", "NoSuchEntity"):
            raise RuntimeError("Cannot establish service role ownership")
        self.fixture["service_role_preexisting"] = role["code"] == "Success"
        token = uuid.uuid4().hex
        request = {"Enable": self.args.event_delivery_enabled, "ClientToken": token, "Features": FEATURES,
                   "Tags": {"stackd-probe": token}}
        created = self.gd("create_detector", "create-enabled-detector" if request["Enable"] else "create-disabled-detector", **request)
        if created["code"] != "Success":
            self.fixture["blocker"] = "Owned detector creation refused: " + created["code"]
            return False
        self.detector = created["output"]["DetectorId"]
        self.fixture["owned"]["detector_id"] = self.detector
        self.fixture["owned"]["client_token"] = token
        if request["Enable"]:
            self.fixture["enabled_at"] = created["at"]
        self.save()
        role = self.call("iam", "get_role", "service-role-after-create",
                         RoleName="AWSServiceRoleForAmazonGuardDuty")
        if not self.fixture["service_role_preexisting"] and role["code"] == "Success":
            self.fixture["owned"]["service_role_id"] = role["output"]["Role"]["RoleId"]
            self.save()
        detector = self.require(self.gd("get_detector", "detector-created", DetectorId=self.detector))
        if any(feature["Name"] not in ("CLOUD_TRAIL", "DNS_LOGS", "FLOW_LOGS")
               and feature["Status"] != "DISABLED" for feature in detector.get("Features", [])):
            raise RuntimeError("Optional feature unexpectedly enabled")
        if self.args.event_delivery_only or self.args.event_delivery_enabled:
            return True
        self.gd("create_detector", "detector-token-replay", **request)
        self.gd("create_detector", "detector-token-changed-tags",
                **dict(request, Tags={"stackd-probe": token, "Changed": "yes"}))
        self.gd("create_detector", "detector-new-token-conflict",
                **dict(request, ClientToken=uuid.uuid4().hex))
        for case, fields in (
                ("update-empty", {}), ("update-frequency", {"FindingPublishingFrequency": "ONE_HOUR"}),
                ("update-invalid-frequency", {"FindingPublishingFrequency": "INVALID"}),
                ("update-invalid-feature", {"Features": [{"Name": "INVALID", "Status": "DISABLED"}]}),
                ("update-invalid-feature-status", {"Features": [{"Name": "S3_DATA_EVENTS", "Status": "INVALID"}]}),
                ("update-conflicting-runtime", {"Features": [
                    {"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"},
                    {"Name": "RUNTIME_MONITORING", "Status": "DISABLED"}]})):
            self.gd("update_detector", case, DetectorId=self.detector, **fields)
        self.gd("get_detector", "detector-after-updates", DetectorId=self.detector)
        self.require(self.gd("update_detector", "enable-core-only", DetectorId=self.detector,
                             Enable=True, Features=FEATURES))
        self.fixture["brief_enabled_at"] = now()
        try:
            enabled = self.require(self.gd("get_detector", "detector-enabled", DetectorId=self.detector))
            for feature in enabled.get("Features", []):
                if feature["Name"] not in ("CLOUD_TRAIL", "DNS_LOGS", "FLOW_LOGS") and feature["Status"] != "DISABLED":
                    raise RuntimeError("Unexpected optional feature enabled; suspending owned detector")
        finally:
            self.require(self.gd("update_detector", "suspend-after-enable-calibration",
                                 DetectorId=self.detector, Enable=False))
            self.fixture["brief_disabled_at"] = now()
        self.gd("get_detector", "detector-resuspended", DetectorId=self.detector)
        arn = f"arn:aws:guardduty:{self.region}:{self.account}:detector/{self.detector}"
        self.gd("tag_resource", "detector-tag", ResourceArn=arn, Tags={"Purpose": "native-sample", "Empty": ""})
        self.gd("list_tags_for_resource", "detector-tags", ResourceArn=arn)
        self.gd("untag_resource", "detector-untag-missing", ResourceArn=arn, TagKeys=["Empty", "Absent"])
        self.gd("list_tags_for_resource", "detector-tags-after-untag", ResourceArn=arn)
        self.gd("tag_resource", "detector-reserved-tag", ResourceArn=arn, Tags={"aws:forbidden": "value"})
        for case, fields in (("detectors-max-zero", {"MaxResults": 0}),
                             ("detectors-max-large", {"MaxResults": 51}),
                             ("detectors-invalid-token", {"NextToken": "invalid"})):
            self.gd("list_detectors", case, **fields)
        self.gd("get_detector", "missing-detector", DetectorId="0" * 32)
        return True

    def all_findings(self, case, **fields):
        ids, token = [], None
        while True:
            request = dict(DetectorId=self.detector, MaxResults=50, **fields)
            if token:
                request["NextToken"] = token
            row = self.gd("list_findings", case + "-page-" + str(len(ids)), **request)
            result = self.require(row)
            ids.extend(result.get("FindingIds", []))
            token = result.get("NextToken")
            if not token:
                return ids

    def sample_cases(self, all_types=True):
        sample_type = "Backdoor:EC2/DenialOfService.Tcp"
        result = self.gd("create_sample_findings", "sample-while-disabled", DetectorId=self.detector,
                         FindingTypes=[sample_type])
        if result["code"] != "Success":
            self.require(self.gd("update_detector", "enable-core-only-for-samples",
                                 DetectorId=self.detector, Enable=True, Features=FEATURES))
            self.fixture["enabled_at"] = now()
            self.require(self.gd("get_detector", "enabled-features-confirmation", DetectorId=self.detector))
            self.require(self.gd("create_sample_findings", "sample-after-enable", DetectorId=self.detector,
                                 FindingTypes=[sample_type]))
        criterion = {"Criterion": {"type": {"Equals": [sample_type]}}}
        first_ids = []
        for attempt in range(18):
            first_ids = self.all_findings("sample-initial-" + str(attempt), FindingCriteria=criterion)
            if first_ids:
                break
            time.sleep(5)
        if not first_ids:
            raise RuntimeError("Sample finding did not become visible within 90 seconds")
        self.gd("get_findings", "sample-before-repeat", DetectorId=self.detector, FindingIds=first_ids)
        self.gd("create_sample_findings", "sample-repeated", DetectorId=self.detector, FindingTypes=[sample_type])
        time.sleep(3)
        repeated = self.all_findings("sample-repeated-list", FindingCriteria=criterion)
        after_repeat = self.require(self.gd("get_findings", "sample-after-repeat",
                                           DetectorId=self.detector, FindingIds=repeated))
        if not all_types:
            return after_repeat["Findings"]
        self.gd("create_sample_findings", "sample-invalid-type", DetectorId=self.detector, FindingTypes=["Invalid:NoSuch/Type"])
        self.gd("create_sample_findings", "sample-mixed-types", DetectorId=self.detector,
                FindingTypes=[sample_type, "Invalid:NoSuch/Type"])
        self.require(self.gd("create_sample_findings", "sample-all-types-omitted", DetectorId=self.detector))
        previous, stable = set(), 0
        ids = []
        for attempt in range(24):
            ids = self.all_findings("all-samples-" + str(attempt))
            current = set(ids)
            stable = stable + 1 if current == previous and len(current) > 1 else 0
            previous = current
            if stable >= 2:
                break
            time.sleep(5)
        findings, wire_findings = [], []
        for start in range(0, len(ids), 50):
            row = self.gd("get_findings", "sample-corpus-" + str(start),
                          DetectorId=self.detector, FindingIds=ids[start:start + 50])
            output = self.require(row)
            findings.extend(output.get("Findings", []))
            wire_findings.extend(row["wire_output"].get("findings", []))
        corpus_path = self.args.output.with_suffix(".samples.json")
        corpus = {"captured_at": now(), "source_capture": self.args.output.name,
                  "sdk": self.fixture["sdk"], "source_case": "sample-all-types-omitted",
                  "sanitization": self.fixture["sanitization"],
                  "findings": sorted(wire_findings, key=lambda finding: (finding["type"], finding["id"]))}
        corpus_path.write_text(json.dumps(self.sanitize(corpus), indent=2) + "\n")
        self.fixture["sample_corpus"] = {
            "source_case": "sample-all-types-omitted", "total_findings": len(findings),
            "types": sorted({finding["Type"] for finding in findings}),
            "corpus_file": corpus_path.name,
            "boundary": "All samples visible after omitted FindingTypes request and two stable scans; SDK-decoded AWS sample placeholders, not actual detected threats.",
        }
        self.save()
        self.gd("create_sample_findings", "sample-empty-types", DetectorId=self.detector, FindingTypes=[])
        return findings

    def finding_cases(self, findings):
        first = next(f for f in findings if f["Type"] == "Backdoor:EC2/DenialOfService.Tcp")
        fid, ftype = first["Id"], first["Type"]
        base = {"DetectorId": self.detector}
        self.gd("get_findings", "get-finding-missing", **base, FindingIds=["0" * 32])
        self.gd("get_findings", "get-finding-mixed", **base, FindingIds=[fid, "0" * 32])
        self.gd("get_findings", "get-finding-duplicate", **base, FindingIds=[fid, fid])
        self.gd("get_findings", "get-findings-empty", **base, FindingIds=[])
        for name, criterion in (
                ("type-equals", {"type": {"Equals": [ftype]}}),
                ("type-eq", {"type": {"Eq": [ftype]}}),
                ("type-not-equals", {"type": {"NotEquals": [ftype]}}),
                ("type-matches", {"type": {"Matches": ["Backdoor:*"]}}),
                ("type-not-matches", {"type": {"NotMatches": ["Backdoor:*"]}}),
                ("type-matches-case", {"type": {"Matches": ["backdoor:*"]}}),
                ("type-matches-question", {"type": {"Matches": ["Backdoor:EC2/DenialOfService.Tc?"]}}),
                ("type-alias-conflict", {"type": {"Eq": [ftype], "Equals": ["Recon:EC2/Portscan"]}}),
                ("type-or-values", {"type": {"Equals": [ftype, "Recon:EC2/Portscan"]}}),
                ("and-fields", {"type": {"Equals": [ftype]}, "severity": {"LessThan": 1}}),
                ("severity-range", {"severity": {"GreaterThanOrEqual": 7, "LessThan": 9}}),
                ("severity-alias-range", {"severity": {"Gte": 7, "Lt": 9}}),
                ("unknown-field", {"notAField": {"Equals": ["x"]}}),
                ("empty-condition", {"type": {}}),
                ("empty-equals", {"type": {"Equals": []}}),
                ("mixed-operator", {"type": {"Equals": [ftype], "NotEquals": [ftype]}}),
                ("numeric-string", {"severity": {"Equals": ["8"]}}),
                ("boolean", {"service.archived": {"Equals": ["false"]}}),
                ("timestamp", {"updatedAt": {"GreaterThan": 0}}),
                ("nested-resource", {"resource.instanceDetails.instanceId": {
                    "Equals": [first["Resource"]["InstanceDetails"]["InstanceId"]]}})):
            self.gd("list_findings", "criteria-" + name, **base, FindingCriteria={"Criterion": criterion}, MaxResults=50)
        for attribute in ("severity", "type", "updatedAt", "createdAt", "id", "notAField"):
            for order in ("ASC", "DESC"):
                self.gd("list_findings", "sort-" + attribute + "-" + order, **base,
                        SortCriteria={"AttributeName": attribute, "OrderBy": order}, MaxResults=5)
        for name, fields in (("zero", {"MaxResults": 0}), ("too-large", {"MaxResults": 51}),
                             ("invalid-token", {"NextToken": "invalid"}),
                             ("sort-invalid-order", {"SortCriteria": {"AttributeName": "severity", "OrderBy": "INVALID"}})):
            self.gd("list_findings", "finding-list-" + name, **base, **fields)
        page = self.require(self.gd("list_findings", "pagination-first", **base, MaxResults=2,
                                    SortCriteria={"AttributeName": "type", "OrderBy": "ASC"}))
        if page.get("NextToken"):
            request = dict(base, MaxResults=2, NextToken=page["NextToken"],
                           SortCriteria={"AttributeName": "type", "OrderBy": "ASC"})
            self.gd("list_findings", "pagination-next", **request)
            self.gd("list_findings", "pagination-replay", **request)
            self.gd("list_findings", "pagination-changed-query", **request,
                    FindingCriteria={"Criterion": {"type": {"Equals": [ftype]}}})
        for group in ("ACCOUNT", "DATE", "FINDING_TYPE", "RESOURCE", "SEVERITY"):
            self.gd("get_findings_statistics", "statistics-" + group, **base, GroupBy=group, MaxResults=100)
        self.gd("get_findings_statistics", "statistics-count-by-severity", **base,
                FindingStatisticTypes=["COUNT_BY_SEVERITY"])
        self.gd("get_findings_statistics", "statistics-filtered", **base, GroupBy="SEVERITY",
                FindingCriteria={"Criterion": {"type": {"Equals": [ftype]}}}, OrderBy="ASC")
        for name, fields in (
                ("neither", {}), ("both", {"GroupBy": "SEVERITY", "FindingStatisticTypes": ["COUNT_BY_SEVERITY"]}),
                ("invalid-type", {"FindingStatisticTypes": ["INVALID"]}),
                ("legacy-with-limit", {"FindingStatisticTypes": ["COUNT_BY_SEVERITY"], "MaxResults": 2}),
                ("invalid-group", {"GroupBy": "INVALID"})):
            self.gd("get_findings_statistics", "statistics-" + name, **base, **fields)
        for feedback in ("USEFUL", "NOT_USEFUL", "INVALID"):
            self.gd("update_findings_feedback", "feedback-" + feedback, **base, FindingIds=[fid],
                    Feedback=feedback, Comments="Owned native sample calibration")
            self.gd("get_findings", "after-feedback-" + feedback, **base, FindingIds=[fid])
        self.gd("update_findings_feedback", "feedback-missing", **base, FindingIds=["0" * 32], Feedback="USEFUL")
        for operation in ("archive_findings", "unarchive_findings"):
            self.gd(operation, operation + "-sample", **base, FindingIds=[fid])
            self.gd("get_findings", operation + "-get", **base, FindingIds=[fid])
            self.gd("list_findings", operation + "-default-list", **base,
                    FindingCriteria={"Criterion": {"id": {"Equals": [fid]}}})
            self.gd("list_findings", operation + "-archived-list", **base,
                    FindingCriteria={"Criterion": {"id": {"Equals": [fid]}, "service.archived": {"Equals": ["true"]}}})
            self.gd(operation, operation + "-missing", **base, FindingIds=["0" * 32])
            self.gd(operation, operation + "-empty", **base, FindingIds=[])

    def finding_transition_cases(self, findings):
        first = findings[0]
        base = {"DetectorId": self.detector}
        fid, ftype = first["Id"], first["Type"]
        self.gd("archive_findings", "transition-archive", **base, FindingIds=[fid])
        self.gd("update_findings_feedback", "transition-feedback", **base, FindingIds=[fid], Feedback="USEFUL")
        before = None
        for attempt in range(18):
            before = self.require(self.gd("get_findings", "transition-before-regeneration-" + str(attempt),
                                          **base, FindingIds=[fid]))
            service = before["Findings"][0]["Service"]
            if service.get("Archived") and service.get("UserFeedback") == "USEFUL":
                break
            time.sleep(5)
        old_count = before["Findings"][0]["Service"]["Count"]
        self.gd("create_sample_findings", "transition-regenerate", **base, FindingTypes=[ftype])
        for attempt in range(18):
            current = self.require(self.gd("get_findings", "transition-regenerated-" + str(attempt),
                                          **base, FindingIds=[fid]))
            if current["Findings"] and current["Findings"][0]["Service"]["Count"] > old_count:
                break
            time.sleep(5)
        duplicate_baseline = current["Findings"][0]["Service"]["Count"]
        self.gd("create_sample_findings", "transition-duplicate-types", **base, FindingTypes=[ftype, ftype])
        for attempt in range(12):
            duplicate = self.require(self.gd("get_findings", "transition-after-duplicate-types-" + str(attempt),
                                            **base, FindingIds=[fid]))
            if duplicate["Findings"][0]["Service"]["Count"] > duplicate_baseline:
                time.sleep(5)
                self.gd("get_findings", "transition-duplicate-settled", **base, FindingIds=[fid])
                break
            time.sleep(5)
        name = "stackd-gd-suppression-" + self.fixture["owned"]["client_token"][:8]
        suppressed_type = "Recon:EC2/Portscan"
        row = self.gd("create_filter", "transition-suppression-filter", **base, Name=name, Action="ARCHIVE",
                      FindingCriteria={"Criterion": {"type": {"Equals": [suppressed_type]}}})
        if row["code"] == "Success":
            self.filters.add(name)
            self.fixture["owned"]["filter_names"] = sorted(self.filters)
            self.save()
            self.gd("create_sample_findings", "transition-new-suppressed-sample", **base,
                    FindingTypes=[suppressed_type])
            for attempt in range(18):
                ids = self.all_findings("transition-suppressed-list-" + str(attempt),
                                       FindingCriteria={"Criterion": {"type": {"Equals": [suppressed_type]}}})
                if ids:
                    self.gd("get_findings", "transition-suppressed-get", **base, FindingIds=ids)
                    break
                time.sleep(5)

    def filter_cases(self):
        base = {"DetectorId": self.detector}
        prefix = "stackd-gd-" + self.fixture["owned"]["client_token"][:12]
        criterion = {"Criterion": {"type": {"Equals": ["Backdoor:EC2/DenialOfService.Tcp"]}}}
        token = uuid.uuid4().hex
        request = dict(base, Name=prefix, FindingCriteria=criterion, ClientToken=token,
                       Tags={"stackd-probe": "owned"})
        row = self.gd("create_filter", "filter-create-defaults", **request)
        if row["code"] != "Success":
            return
        self.filters.add(prefix)
        self.fixture["owned"]["filter_names"] = sorted(self.filters)
        self.save()
        self.gd("get_filter", "filter-get-defaults", **base, FilterName=prefix)
        self.gd("create_filter", "filter-token-replay", **request)
        self.gd("create_filter", "filter-token-changed", **dict(request, Description="changed"))
        renamed = self.gd("create_filter", "filter-token-changed-name", **dict(request, Name=prefix + "-token-name"))
        if renamed["code"] == "Success" and renamed["output"]["Name"] != prefix:
            self.filters.add(renamed["output"]["Name"])
            self.fixture["owned"]["filter_names"] = sorted(self.filters)
            self.save()
        self.gd("get_filter", "filter-token-new-name-get", **base, FilterName=prefix + "-token-name")
        self.gd("create_filter", "filter-name-conflict", **dict(request, ClientToken=uuid.uuid4().hex))
        self.gd("create_filter", "filter-name-conflict-implicit-token", **base, Name=prefix, FindingCriteria=criterion)
        self.gd("update_filter", "filter-update", **base, FilterName=prefix, Rank=4, Description="changed",
                FindingCriteria={"Criterion": {"severity": {"Gte": 7}}}, Action="ARCHIVE")
        self.gd("get_filter", "filter-get-updated", **base, FilterName=prefix)
        self.gd("update_filter", "filter-update-valid", **base, FilterName=prefix, Rank=1, Description="changed",
                FindingCriteria={"Criterion": {"severity": {"Gte": 7}}}, Action="ARCHIVE")
        self.gd("get_filter", "filter-get-valid-update", **base, FilterName=prefix)
        prior_ids = self.all_findings("filter-existing-sample-list",
                                      FindingCriteria={"Criterion": {"type": {"Equals": ["Backdoor:EC2/DenialOfService.Tcp"]}}})
        for attempt in range(3):
            time.sleep(5)
            self.gd("get_findings", "filter-existing-after-archive-rule-" + str(attempt), **base, FindingIds=prior_ids)
        self.gd("update_filter", "filter-clear-description", **base, FilterName=prefix, Description="")
        self.gd("get_filter", "filter-get-cleared-description", **base, FilterName=prefix)
        arn = f"arn:aws:guardduty:{self.region}:{self.account}:detector/{self.detector}/filter/{prefix}"
        self.gd("tag_resource", "filter-tag", ResourceArn=arn, Tags={"Purpose": "sample"})
        self.gd("list_tags_for_resource", "filter-tags", ResourceArn=arn)
        self.gd("untag_resource", "filter-untag", ResourceArn=arn, TagKeys=["Purpose"])
        for case, fields in (
                ("rank-zero", {"Rank": 0}), ("rank-high", {"Rank": 101}),
                ("invalid-action", {"Action": "INVALID"}),
                ("unknown-criteria", {"FindingCriteria": {"Criterion": {"unknownField": {"Equals": ["x"]}}}}),
                ("empty-criteria", {"FindingCriteria": {"Criterion": {}}}),
                ("empty-update", {})):
            self.gd("update_filter", "filter-" + case, **base, FilterName=prefix, **fields)
        self.gd("get_filter", "filter-after-empty-update", **base, FilterName=prefix)
        for suffix, fields in (
                ("second", {}), ("rank-collision", {"Rank": 4}), ("bad-name", {"Name": prefix + " space"}),
                ("bad-rank", {"Rank": -1}), ("bad-action", {"Action": "INVALID"}),
                ("unknown-field", {"FindingCriteria": {"Criterion": {"unknownField": {"Equals": ["x"]}}}})):
            params = dict(base, Name=prefix + "-" + suffix, FindingCriteria=criterion, **{})
            params.update(fields)
            row = self.gd("create_filter", "filter-create-" + suffix, **params)
            if row["code"] == "Success":
                self.filters.add(params["Name"])
                self.fixture["owned"]["filter_names"] = sorted(self.filters)
                self.save()
                self.gd("get_filter", "filter-get-" + suffix, **base, FilterName=params["Name"])
        self.gd("update_filter", "filter-move-rank-first", **base, FilterName=prefix + "-rank-collision", Rank=1)
        for name in sorted(self.filters):
            self.gd("get_filter", "filter-rank-after-move-" + name, **base, FilterName=name)
        page = self.gd("list_filters", "filter-list-page", **base, MaxResults=1)
        if page["code"] == "Success" and page["output"].get("NextToken"):
            self.gd("list_filters", "filter-list-next", **base, MaxResults=1, NextToken=page["output"]["NextToken"])
        self.gd("list_filters", "filter-list-invalid-token", **base, NextToken="invalid")
        self.gd("get_filter", "filter-get-missing", **base, FilterName=prefix + "-missing")
        self.gd("update_filter", "filter-update-missing", **base, FilterName=prefix + "-missing", Description="x")
        self.gd("delete_filter", "filter-delete-missing", **base, FilterName=prefix + "-missing")
        self.gd("delete_filter", "filter-delete", **base, FilterName=prefix)
        self.filters.discard(prefix)
        self.gd("get_filter", "filter-get-deleted", **base, FilterName=prefix)
        self.gd("delete_filter", "filter-delete-again", **base, FilterName=prefix)
        for name in sorted(self.filters):
            self.gd("get_filter", "filter-rank-after-delete-" + name, **base, FilterName=name)

    def sample_identity_cases(self, findings):
        base = {"DetectorId": self.detector}
        first = findings[0]
        fid, ftype = first["Id"], first["Type"]
        criteria = {"Criterion": {"type": {"Equals": [ftype]}}}

        def snapshot(case):
            ids = self.all_findings(case + "-list", FindingCriteria=criteria)
            return self.require(self.gd("get_findings", case + "-get", **base, FindingIds=ids))["Findings"]

        self.gd("archive_findings", "identity-archive", **base, FindingIds=[fid])
        self.gd("update_findings_feedback", "identity-old-feedback", **base, FindingIds=[fid], Feedback="USEFUL")
        for attempt in range(18):
            before = snapshot("identity-archive-settle-" + str(attempt))
            if any(f["Id"] == fid and f["Service"].get("Archived")
                   and f["Service"].get("UserFeedback") == "USEFUL" for f in before):
                break
            time.sleep(5)
        self.gd("create_sample_findings", "identity-regenerate-archived", **base, FindingTypes=[ftype])
        baseline = sum(f["Service"]["Count"] for f in before)
        for attempt in range(18):
            after = snapshot("identity-after-regeneration-" + str(attempt))
            if {f["Id"] for f in after} != {f["Id"] for f in before} or sum(f["Service"]["Count"] for f in after) > baseline:
                break
            time.sleep(5)
        self.fixture["archived_sample_regeneration"] = {
            "before_ids": [f["Id"] for f in before], "after_ids": [f["Id"] for f in after],
            "before_total_count": baseline, "after_total_count": sum(f["Service"]["Count"] for f in after),
        }
        active = [f for f in after if not f["Service"].get("Archived")]
        if active:
            active_id = active[0]["Id"]
            self.gd("update_findings_feedback", "identity-active-feedback", **base,
                    FindingIds=[active_id], Feedback="NOT_USEFUL")
            for attempt in range(18):
                before = snapshot("identity-feedback-settle-" + str(attempt))
                if any(f["Id"] == active_id and f["Service"].get("UserFeedback") == "NOT_USEFUL" for f in before):
                    break
                time.sleep(5)
            for case, requested in (("single", [ftype]), ("duplicate", [ftype, ftype])):
                baseline = sum(f["Service"]["Count"] for f in before)
                self.gd("create_sample_findings", "identity-active-" + case, **base, FindingTypes=requested)
                for attempt in range(18):
                    after = snapshot("identity-active-" + case + "-" + str(attempt))
                    if sum(f["Service"]["Count"] for f in after) > baseline:
                        break
                    time.sleep(5)
                before = after
        for attribute in ("service.eventLastSeen", "service.eventFirstSeen", "confidence", "region"):
            self.gd("list_findings", "identity-sort-" + attribute, **base,
                    SortCriteria={"AttributeName": attribute, "OrderBy": "ASC"})
        for label, description in (("punctuation", "bad!@#$"), ("unicode", "caf\u00e9")):
            name = "stackd-gd-description-" + label + "-" + self.fixture["owned"]["client_token"][:8]
            row = self.gd("create_filter", "description-" + label, **base, Name=name,
                          Description=description, FindingCriteria=criteria)
            if row["code"] == "Success":
                self.filters.add(name)
                self.fixture["owned"]["filter_names"] = sorted(self.filters)
                self.save()
                self.gd("get_filter", "description-" + label + "-get", **base, FilterName=name)

    def event_delivery_cases(self):
        name = "stackd-gd-event-" + uuid.uuid4().hex[:12]
        finding_type = "Backdoor:EC2/DenialOfService.Udp" if self.args.event_delivery_enabled else "Recon:EC2/Portscan"
        queue_url, rule_arn = None, None
        self.fixture["scope"] = ("Actual sample EventBridge delivery to an exact-owned queue/rule; all optional features disabled; detector "
                                 + ("enabled for core only." if self.args.event_delivery_enabled else "held disabled."))
        self.fixture["owned"].update(queue_name=name, rule_name=name)
        try:
            queue = self.require(self.call("sqs", "create_queue", "event-queue-create", QueueName=name,
                                          tags={"stackd-probe": name}, Attributes={"MessageRetentionPeriod": "3600"}))
            queue_url = queue["QueueUrl"]
            self.fixture["owned"]["queue_url"] = queue_url
            attrs = self.require(self.call("sqs", "get_queue_attributes", "event-queue-arn",
                                          QueueUrl=queue_url, AttributeNames=["QueueArn"]))
            queue_arn = attrs["Attributes"]["QueueArn"]
            pattern = {"source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"],
                       "detail": {"service": {"detectorId": [self.detector]}, "type": [finding_type]}}
            rule = self.require(self.call("events", "put_rule", "event-rule-create", Name=name,
                                         EventPattern=json.dumps(pattern), State="ENABLED",
                                         Tags=[{"Key": "stackd-probe", "Value": name}]))
            rule_arn = rule["RuleArn"]
            self.fixture["owned"]["rule_arn"] = rule_arn
            policy = {"Version": "2012-10-17", "Statement": [{
                "Sid": "ExactOwnedGuardDutyRule", "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
                "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn},
                                                    "StringEquals": {"aws:SourceAccount": self.account}}}]}
            self.require(self.call("sqs", "set_queue_attributes", "event-queue-policy", QueueUrl=queue_url,
                                   Attributes={"Policy": json.dumps(policy)}))
            targets = self.require(self.call("events", "put_targets", "event-target-create",
                                            Rule=name, Targets=[{"Id": "capture", "Arn": queue_arn}]))
            if targets.get("FailedEntryCount"):
                raise RuntimeError("Owned EventBridge target admission failed")
            self.save()
            time.sleep(10)
            self.require(self.gd("create_sample_findings", "event-sample-create", DetectorId=self.detector,
                                 FindingTypes=[finding_type]))
            for attempt in range(15):
                received = self.require(self.call("sqs", "receive_message", "event-receive-" + str(attempt),
                                                 QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=20))
                messages = received.get("Messages", [])
                if not messages:
                    continue
                events = [json.loads(message["Body"]) for message in messages]
                if any(event.get("source") != "aws.guardduty"
                       or event.get("detail", {}).get("service", {}).get("detectorId") != self.detector
                       for event in events):
                    raise RuntimeError("Unexpected event escaped exact detector filter")
                self.fixture["delivered_events"] = events
                if self.args.event_delivery_enabled:
                    self.require(self.gd("update_detector", "event-suspend-after-delivery",
                                         DetectorId=self.detector, Enable=False))
                    self.fixture["disabled_at"] = now()
                for message in messages:
                    self.require(self.call("sqs", "delete_message", "event-message-delete",
                                           QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]))
                ids = [event["detail"]["id"] for event in events]
                self.gd("get_findings", "event-corresponding-findings", DetectorId=self.detector, FindingIds=ids)
                break
            if not self.fixture.get("delivered_events"):
                self.fixture["limitations"].append("No matching delivered sample event within 300-second receive window; this does not establish permanent absence.")
            self.gd("list_findings", "event-sort-accountId", DetectorId=self.detector,
                    SortCriteria={"AttributeName": "accountId", "OrderBy": "ASC"})
        finally:
            self.cleanup_phase = True
            if rule_arn:
                self.call("events", "remove_targets", "event-target-remove", Rule=name, Ids=["capture"])
                self.call("events", "delete_rule", "event-rule-delete", Name=name)
                absent_rule = self.call("events", "describe_rule", "event-rule-absent", Name=name)
                self.fixture["event_rule_cleanup_verified"] = absent_rule["code"] == "ResourceNotFoundException"
            if queue_url:
                self.call("sqs", "delete_queue", "event-queue-delete", QueueUrl=queue_url)
                absent_queue = self.call("sqs", "get_queue_url", "event-queue-absent", QueueName=name)
                self.fixture["event_queue_cleanup_verified"] = absent_queue["code"] in (
                    "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
            self.fixture["finished_at"] = now()
            self.save()

    def cleanup(self):
        self.cleanup_phase = True
        if self.detector:
            self.gd("update_detector", "suspend-owned-detector", DetectorId=self.detector, Enable=False)
            self.fixture["disabled_at"] = now()
            for name in sorted(self.filters):
                self.gd("delete_filter", "delete-owned-filter-" + name, DetectorId=self.detector, FilterName=name)
            deleted = self.gd("delete_detector", "delete-owned-detector", DetectorId=self.detector)
            self.gd("get_detector", "owned-detector-absent", DetectorId=self.detector)
            remaining = self.gd("list_detectors", "regional-detectors-after")
            self.fixture["detector_cleanup_verified"] = (
                deleted["code"] == "Success" and remaining["code"] == "Success"
                and self.detector not in remaining["output"].get("DetectorIds", []))
            self.gd("delete_detector", "delete-owned-detector-again", DetectorId=self.detector)
        role_id = self.fixture["owned"].get("service_role_id")
        if role_id and self.fixture.get("detector_cleanup_verified"):
            for deletion_attempt in range(3):
                role = self.call("iam", "get_role", "owned-role-identity-recheck-" + str(deletion_attempt),
                                 RoleName="AWSServiceRoleForAmazonGuardDuty")
                if role["code"] == "NoSuchEntity":
                    break
                if role["code"] != "Success" or role["output"]["Role"]["RoleId"] != role_id:
                    break
                deleted = self.call("iam", "delete_service_linked_role",
                                    "delete-owned-service-role-" + str(deletion_attempt),
                                    RoleName="AWSServiceRoleForAmazonGuardDuty")
                if deleted["code"] != "Success":
                    break
                task_id, status = deleted["output"]["DeletionTaskId"], None
                for attempt in range(120):
                    status = self.call("iam", "get_service_linked_role_deletion_status",
                                       f"role-deletion-status-{deletion_attempt}-{attempt}", DeletionTaskId=task_id)
                    if status["code"] == "Success" and status["output"]["Status"] in ("SUCCEEDED", "FAILED"):
                        self.fixture["service_role_cleanup_status"] = status["output"]["Status"]
                        break
                    time.sleep(5)
                result = status["output"] if status and status["code"] == "Success" else {}
                reason = result.get("Reason", {})
                if result.get("Status") != "FAILED" or reason.get("RoleUsageList") or "internal" not in reason.get("Reason", "").lower():
                    break
            absent = self.call("iam", "get_role", "owned-service-role-absent",
                               RoleName="AWSServiceRoleForAmazonGuardDuty")
            self.fixture["service_role_cleanup_verified"] = absent["code"] == "NoSuchEntity"
        self.fixture["finished_at"] = now()
        self.save()
        if self.detector and not self.fixture.get("detector_cleanup_verified"):
            raise RuntimeError("Owned detector cleanup not verified; see native capture")
        if role_id and not self.fixture.get("service_role_cleanup_verified"):
            raise RuntimeError("Owned service role cleanup not verified; see native capture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--regions", default="us-west-2,eu-north-1,eu-west-1")
    parser.add_argument("--discover-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--owned-role-capture", type=Path)
    parser.add_argument("--transitions-only", action="store_true")
    parser.add_argument("--identity-only", action="store_true")
    parser.add_argument("--attach-detector-capture", type=Path)
    parser.add_argument("--event-delivery-only", action="store_true")
    parser.add_argument("--event-delivery-enabled", action="store_true")
    args = parser.parse_args()
    probe = Probe(args)
    if args.attach_detector_capture:
        source = json.loads(args.attach_detector_capture.read_text())
        probe.require(probe.call("sts", "get_caller_identity", "event-authorized-identity"))
        probe.detector = source["owned"]["detector_id"]
        probe.region = source["region"]
        detector = probe.require(probe.gd("get_detector", "event-owned-detector-check", DetectorId=probe.detector))
        if detector["Status"] != "DISABLED" or detector.get("Tags", {}).get("stackd-probe") != source["owned"]["client_token"]:
            raise RuntimeError("Attached detector is not the exact owned disabled resource")
        probe.fixture["detector_owner_capture"] = args.attach_detector_capture.name
        probe.fixture["region"] = probe.region
        probe.fixture["owned"]["detector_id"] = probe.detector
        probe.event_delivery_cases()
        return
    if not probe.discover() or args.discover_only:
        return
    if args.owned_role_capture:
        previous = json.loads(args.owned_role_capture.read_text())
        role_id = previous["owned"]["service_role_id"]
        if previous["service_role_preexisting"]:
            raise RuntimeError("Source capture does not establish owned role creation")
        role_row = probe.call("iam", "get_role", "inherited-owned-role-identity",
                              RoleName="AWSServiceRoleForAmazonGuardDuty")
        if role_row["code"] == "Success":
            if role_row["output"]["Role"]["RoleId"] != role_id:
                raise RuntimeError("Inherited role identity changed; refusing ownership")
            probe.fixture["owned"]["service_role_id"] = role_id
            probe.fixture["owned_role_source_capture"] = args.owned_role_capture.name
        elif role_row["code"] != "NoSuchEntity":
            raise RuntimeError("Cannot establish inherited role ownership")
        probe.save()
    try:
        if probe.detector_cases():
            if args.event_delivery_only or args.event_delivery_enabled:
                probe.event_delivery_cases()
            else:
                findings = probe.sample_cases(all_types=not (args.transitions_only or args.identity_only))
                if args.identity_only:
                    probe.sample_identity_cases(findings)
                elif args.transitions_only:
                    probe.filter_cases()
                    probe.finding_transition_cases(findings)
                else:
                    probe.finding_cases(findings)
                    probe.filter_cases()
    except BaseException as error:
        probe.fixture["interruption"] = {"type": type(error).__name__, "message": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
