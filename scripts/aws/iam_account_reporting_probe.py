#!/usr/bin/env python3
"""Capture two IAM reporting APIs with owned resources and verified cleanup.

Run explicitly with AWS CLI credentials. Queries use --no-paginate and small
bounded pages; unmanaged entity documents are discarded in memory. CLI debug
output is never written or printed: only owned XML policy fields are retained.
No account-wide setting or existing resource is changed.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

from aws_cli import run as run_cli, result as cli_result, raw_xml


ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / '.stackd/probes/iam/account_reporting.json'
COMMON = ["--endpoint-url", "https://iam.amazonaws.com", "--region", "us-east-1",
          "--no-paginate"]
SECTIONS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")
AWS_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
AWS_BOUNDARY = "arn:aws:iam::aws:policy/AWSCloud9SSMInstanceProfile"
DOCUMENT = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::stackd-probe-bucket/space + percent%/é"}]}, ensure_ascii=False)
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"}]})
LIMITATIONS = [
    "This capture establishes observations in the commercial AWS partition only. Summary quotas are the source account effective quotas, not evidence of universal defaults.",
    "Account authorization details is account-wide: unrelated rows are discarded immediately and retained only as aggregate section and policy-version counts.",
    "Observations are merged by scenario name across independently owned runs. Each summary delta is relative to its capture-run baseline; fixture-level baseline is the latest owned run.",
    "Zero MaxItems was rejected by the AWS CLI before a service request; its CLIValidationError is not a service error observation.",
    "Page contents can be smaller than MaxItems. The fixture establishes aggregate section budgets and marker/filter behavior, without assuming AWS marker format or stable managed-policy order.",
]


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def call(action, parameters=None, debug=False):
    seed = None
    if action == "create-virtual-mfa-device":
        # This CLI customization requires an outfile instead of JSON input.
        with tempfile.TemporaryDirectory(prefix="stackd-report-mfa-") as directory:
            output = Path(directory) / "seed"
            process = run_cli("iam", action, timeout=60, options=[*COMMON,
                "--virtual-mfa-device-name", parameters["VirtualMFADeviceName"],
                "--path", parameters.get("Path", "/"), "--outfile", str(output),
                "--bootstrap-method", "Base32StringSeed"])
            if process.returncode == 0:
                seed = base64.b64encode(output.read_bytes()).decode()
    else:
        process = run_cli("iam", action, parameters or {}, timeout=60,
                          options=[*COMMON, *(["--debug"] if debug else [])])
    result = cli_result(process, cli_error="CLIValidationError", cli_message=None)
    if seed is not None:
        result["output"]["VirtualMFADevice"]["Base32StringSeed"] = seed
    return result, raw_xml(process) if debug else None


class Probe:
    def __init__(self, phase="all", preserve=False):
        self.phase = phase
        self.previous = json.loads(DESTINATION.read_text()) if preserve and DESTINATION.exists() else {}
        self.prefix = "00-stackd-report-" + uuid.uuid4().hex[:10]
        self.path = "/" + self.prefix + "/"
        self.rows, self.cleanup, self.owned = [], [], []
        self.ids, self.account, self.baseline = {}, "", None
        self.started = stamp()
        self.capture_complete = False
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")
        self.journal.parent.mkdir(parents=True, exist_ok=True)

    def normalize(self, value):
        if isinstance(value, dict):
            return {key: self.normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            value = value.replace(self.prefix, "stackd-report-fixture")
            if self.account:
                value = value.replace(self.account, "123456789012")
            for actual, normalized in self.ids.items():
                value = value.replace(actual, normalized)
        return value

    def own(self, kind, identifier, extra=None):
        self.owned.append({"kind": kind, "id": identifier, **(extra or {})})
        self.journal.write_text(json.dumps({"prefix": self.prefix, "owned": self.owned}, indent=2) + "\n")

    def require(self, action, parameters=None):
        result, _ = call(action, parameters)
        if result["code"] != "Success":
            raise RuntimeError(action + ": " + result["code"] + ": " + result.get("message", ""))
        return result["output"]

    def checkpoint(self):
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        DESTINATION.write_text(json.dumps({"source": "Real AWS IAM; capture in progress", "cleanup_verified": False,
                                          "observations": self.combined_rows()}, indent=2, ensure_ascii=False) + "\n")

    def combined_rows(self):
        rows = {row["case"]: row for row in self.previous.get("observations", [])}
        rows.update({row["case"]: row for row in self.rows})
        for row in rows.values():
            entities = row.get("owned_entities", {})
            if "Policies" in entities:
                entities["Policies"] = [policy for policy in entities["Policies"] if policy.get("Arn") != AWS_POLICY]
            if "raw_policy_documents" in row:
                row["raw_policy_documents"] = [doc for doc in row["raw_policy_documents"] if doc.get("entity_arn") != AWS_POLICY]
        return list(rows.values())

    def summary(self, name, expected=None):
        attempts = []
        for attempt in range(8):
            output = self.require("get-account-summary")["SummaryMap"]
            delta = {key: value - self.baseline.get(key, 0) for key, value in output.items()} if self.baseline else {}
            attempts.append({"observed_at": stamp(), "delta": {key: value for key, value in delta.items() if value}})
            if expected is None or all(delta.get(key, 0) == value for key, value in expected.items()):
                break
            if attempt < 7:
                time.sleep(2)
        row = {"case": name, "operation": "GetAccountSummary", "observed_at": stamp(),
               "summary": output, "delta_from_baseline": {key: value for key, value in delta.items() if value},
               "attempts": attempts}
        if expected is not None:
            row["expected_owned_changes"] = expected
            row["expected_changes_observed"] = all(delta.get(key, 0) == value for key, value in expected.items())
        self.rows.append(row)
        self.checkpoint()
        if self.baseline is None:
            self.baseline = output
        print(name, json.dumps(row["delta_from_baseline"], sort_keys=True), flush=True)
        return output

    def details(self, name, parameters, raw=False, marker_from=None):
        result, body = call("get-account-authorization-details", parameters, debug=raw)
        recorded_input = dict(parameters)
        if "Marker" in recorded_input and marker_from:
            recorded_input["Marker"] = "<opaque-marker>"
        row = {"case": name, "operation": "GetAccountAuthorizationDetails", "input": recorded_input,
               "code": result["code"], "observed_at": stamp()}
        if marker_from:
            row["marker_from"] = marker_from
        if result["code"] != "Success":
            row["message"] = result.get("message", "")
            self.rows.append(self.normalize(row))
            self.checkpoint()
            print(name, result["code"], flush=True)
            return {}
        output = result["output"]
        row["top_level_fields"] = sorted(output)
        row["counts"] = {section: len(output.get(section, [])) for section in SECTIONS}
        row["total_entities"] = sum(row["counts"].values())
        row["is_truncated"] = output.get("IsTruncated")
        row["marker_present"] = "Marker" in output
        public_policies = [item for item in output.get("Policies", []) if ":iam::aws:policy/" in item.get("Arn", "")]
        if public_policies:
            row["aws_policy_statistics"] = {
                "count": len(public_policies),
                "zero_attachment_count": sum(item.get("AttachmentCount") == 0 for item in public_policies),
                "version_counts": [len(item.get("PolicyVersionList", [])) for item in public_policies],
                "contains_nondefault_version": any(not version.get("IsDefaultVersion") for item in public_policies for version in item.get("PolicyVersionList", [])),
            }
        row["owned_entities"] = {}
        for section in SECTIONS:
            selected = [item for item in output.get(section, [])
                        if self.prefix in item.get("Arn", "") or item.get("Arn") == AWS_BOUNDARY]
            if selected:
                row["owned_entities"][section] = selected
        # Retain owned policy encodings only, excluding unrelated XML records.
        if raw:
            row["raw_xml_observed"] = body is not None
            row["raw_policy_documents"] = []
            if body is not None:
                root = ET.fromstring(body)
                for element in root.iter():
                    element.tag = element.tag.rsplit("}", 1)[-1]
                result_node = root.find("GetAccountAuthorizationDetailsResult")
                row["raw_section_order"] = [child.tag for child in result_node if child.tag in SECTIONS]
                for section in SECTIONS:
                    for entity in result_node.findall(section + "/member"):
                        arn = entity.findtext("Arn", "")
                        if self.prefix not in arn and arn != AWS_BOUNDARY:
                            continue
                        for element in entity.iter():
                            if element.tag in ("PolicyDocument", "AssumeRolePolicyDocument", "Document"):
                                encoded = element.text or ""
                                row["raw_policy_documents"].append({"section": section, "entity_arn": arn,
                                    "field": element.tag, "wire_text": encoded,
                                    "url_decoded_json": json.loads(urllib.parse.unquote(encoded))})
        self.rows.append(self.normalize(row))
        self.checkpoint()
        print(name, row["counts"], "truncated=" + str(row["is_truncated"]), flush=True)
        return output

    def bounded_owned_details(self, name, entity_filter, raw=False):
        if entity_filter == "LocalManagedPolicy":
            # The account-wide API has no name/path selector and policy rows
            # are not name-ordered. Read bounded pages and retain owned rows
            # only; unrelated policy documents are discarded immediately.
            return self.policy_pages(name, entity_filter, raw)
        parameters = {"Filter": [entity_filter], "MaxItems": 10}
        # Up to three small pages; stop as soon as the owned entries appear.
        for page in range(3):
            output = self.details(name + ":page" + str(page + 1), parameters, raw=raw,
                                  marker_from=name + ":page" + str(page) if page else None)
            if any(self.prefix in item.get("Arn", "") for section in SECTIONS for item in output.get(section, [])):
                return output
            if not output.get("IsTruncated") or not output.get("Marker"):
                break
            parameters["Marker"] = output["Marker"]
        raise RuntimeError("Owned entities were not found within three bounded pages for " + entity_filter)

    def policy_pages(self, name, entity_filter, raw=False, target=None):
        maximum = min(1000, self.baseline.get("Policies", 0) + 2) if entity_filter == "LocalManagedPolicy" else 1000
        parameters = {"Filter": [entity_filter], "MaxItems": maximum}
        selected = []
        for page in range(20):
            output = self.details(name + ":page" + str(page + 1), parameters, raw=raw,
                                  marker_from=name + ":page" + str(page) if page else None)
            selected.extend(item for item in output.get("Policies", [])
                            if self.prefix in item.get("Arn", "") or item.get("Arn") in (AWS_POLICY, AWS_BOUNDARY))
            if target and any(item.get("Arn") == target for item in selected):
                break
            if not output.get("IsTruncated") or not output.get("Marker"):
                break
            parameters["Marker"] = output["Marker"]
        else:
            self.rows.append({"case": name + ":bounded_limit", "incomplete": True,
                              "reason": "Stopped after 20 bounded pages; unobserved policies are not proven absent."})
        return {"Policies": selected}

    def finish(self):
        failures = []
        # Detach every owned relationship before deleting the resources.
        users = [r["id"] for r in self.owned if r["kind"] == "user"]
        groups = [r["id"] for r in self.owned if r["kind"] == "group"]
        roles = [r["id"] for r in self.owned if r["kind"] == "role"]
        policies = [r["id"] for r in self.owned if r["kind"] == "policy"]
        for user in users:
            for group in groups:
                call("remove-user-from-group", {"UserName": user, "GroupName": group})
            call("delete-user-permissions-boundary", {"UserName": user})
        for role in roles:
            call("delete-role-permissions-boundary", {"RoleName": role})
        for kind, names in (("user", users), ("group", groups), ("role", roles)):
            field = kind.title() + "Name"
            for name in names:
                call("delete-" + kind + "-policy", {field: name, "PolicyName": "inline-encoding"})
                for arn in policies + [AWS_POLICY, AWS_BOUNDARY]:
                    call("detach-" + kind + "-policy", {field: name, "PolicyArn": arn})
        for record in reversed(self.owned):
            kind, identifier = record["kind"], record["id"]
            if kind == "mfa":
                for user in users:
                    call("deactivate-mfa-device", {"UserName": user, "SerialNumber": identifier})
                action, args = "delete-virtual-mfa-device", {"SerialNumber": identifier}
            elif kind == "profile":
                for role in roles:
                    call("remove-role-from-instance-profile", {"InstanceProfileName": identifier, "RoleName": role})
                action, args = "delete-instance-profile", {"InstanceProfileName": identifier}
            elif kind == "policy":
                versions, _ = call("list-policy-versions", {"PolicyArn": identifier})
                for version in versions.get("output", {}).get("Versions", []):
                    if not version["IsDefaultVersion"]:
                        call("delete-policy-version", {"PolicyArn": identifier, "VersionId": version["VersionId"]})
                action, args = "delete-policy", {"PolicyArn": identifier}
            elif kind == "saml":
                action, args = "delete-saml-provider", {"SAMLProviderArn": identifier}
            elif kind == "oidc":
                action, args = "delete-open-id-connect-provider", {"OpenIDConnectProviderArn": identifier}
            elif kind == "signing-certificate":
                action, args = "delete-signing-certificate", {"UserName": record["user"], "CertificateId": identifier}
            elif kind == "server-certificate":
                action, args = "delete-server-certificate", {"ServerCertificateName": identifier}
            else:
                action, args = "delete-" + kind, {kind.title() + "Name": identifier}
            result, _ = call(action, args)
            self.cleanup.append(self.normalize({"operation": action, "input": args, "code": result["code"]}))
            if result["code"] not in ("Success", "NoSuchEntity"):
                failures.append(record)
        for record in self.owned:
            kind, identifier = record["kind"], record["id"]
            if kind in ("user", "group", "role"):
                action, args = "get-" + kind, {kind.title() + "Name": identifier}
            elif kind == "profile":
                action, args = "get-instance-profile", {"InstanceProfileName": identifier}
            elif kind == "policy":
                action, args = "get-policy", {"PolicyArn": identifier}
            elif kind == "saml":
                action, args = "get-saml-provider", {"SAMLProviderArn": identifier}
            elif kind == "oidc":
                action, args = "get-open-id-connect-provider", {"OpenIDConnectProviderArn": identifier}
            elif kind == "server-certificate":
                action, args = "get-server-certificate", {"ServerCertificateName": identifier}
            else:
                continue
            result, _ = call(action, args)
            self.cleanup.append(self.normalize({"operation": action, "input": args, "code": result["code"]}))
            if result["code"] != "NoSuchEntity":
                failures.append(record)
        if self.baseline is not None:
            self.summary(self.phase + "_cleanup_summary")
        # Virtual MFA devices are independent of users; deleting their user is
        # not an absence check for the remaining unassigned virtual device.
        mfas = {record["id"] for record in self.owned if record["kind"] == "mfa"}
        if mfas:
            listed = self.require("list-virtual-mfa-devices", {"AssignmentStatus": "Any", "MaxItems": 1000})
            present = any(device["SerialNumber"] in mfas for device in listed["VirtualMFADevices"])
            verified = not present and not listed.get("IsTruncated", False)
            self.cleanup.append({"operation": "list-virtual-mfa-devices", "owned_devices_absent": verified})
            if not verified:
                failures.extend(record for record in self.owned if record["kind"] == "mfa")
        runs = self.previous.get("runs", []) + [{"phase": self.phase, "started_at": self.started,
                "finished_at": stamp(), "capture_complete": self.capture_complete,
                "cleanup_verified": not failures, "cleanup": self.cleanup}]
        completed = set(self.previous.get("completed_phases", []))
        if self.capture_complete:
            completed.add(self.phase)
        fixture = {"schema_version": 1,
                   "source": "Real AWS IAM API through AWS CLI; commercial partition; uniquely owned resources and read-only aggregate queries",
                   "endpoint": "https://iam.amazonaws.com", "region": "us-east-1", "started_at": self.started,
                   "finished_at": stamp(), "probe": "scripts/aws/iam_account_reporting_probe.py",
                   "api_version": "2010-05-08",
                   "aws_cli_version": subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
                   "documentation": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html",
                       "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"],
                   "sanitization": "Only owned entities and the public AWS policy used as an owned boundary are retained; other entities contribute counts only. Account, owned names and owned generated identifiers normalized; opaque markers omitted. MFA seeds/private keys/debug logs never retained.",
                   "limitations": LIMITATIONS,
                   "observations": self.combined_rows(), "cleanup": self.previous.get("cleanup", []) + self.cleanup,
                   "cleanup_verified": not failures and self.previous.get("cleanup_verified", True),
                   "capture_complete": self.previous.get("capture_complete", False) or self.capture_complete and (self.phase == "all" or {"summary", "pagination"} <= completed),
                   "completed_phases": sorted(completed), "runs": runs}
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        DESTINATION.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n")
        if failures:
            raise RuntimeError("Cleanup failed; owned-resource recovery journal: " + str(self.journal))
        self.journal.unlink(missing_ok=True)
        print("cleanup_verified", len(self.owned), "resources;", len(self.rows), "observations", flush=True)


def totp(seed, step):
    digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)


def run(p):
    global AWS_BOUNDARY
    identity = subprocess.run(["aws", "sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], capture_output=True, text=True, check=True)
    p.account = json.loads(identity.stdout)["Account"]
    if p.phase == "routing":
        run_routing_phase(p)
        p.capture_complete = True
        return
    p.summary("baseline")
    if p.phase == "summary":
        run_summary_phase(p)
        p.capture_complete = True
        return
    if p.phase == "pagination":
        run_pagination_phase(p)
        p.capture_complete = True
        return
    p.details("baseline_aws_managed", {"Filter": ["AWSManagedPolicy"], "MaxItems": 10})
    for candidate in ("AWSCloud9SSMInstanceProfile", "AWSDirectoryServiceDataFullAccess", "AWSAccountManagementReadOnlyAccess"):
        policy = p.require("get-policy", {"PolicyArn": "arn:aws:iam::aws:policy/" + candidate})["Policy"]
        if policy.get("AttachmentCount") == 0 and policy.get("PermissionsBoundaryUsageCount", 0) == 0:
            AWS_BOUNDARY = policy["Arn"]
            p.rows.append({"case": "unused_aws_policy_baseline", "operation": "GetPolicy", "output": policy, "observed_at": stamp()})
            break
    else:
        raise RuntimeError("No unused public policy found among three metadata candidates")
    for name, parameters in (("unknown_filter", {"Filter": ["Unknown"]}),
                             ("wrong_case_filter", {"Filter": ["user"]}),
                             ("invalid_marker", {"Filter": ["User"], "Marker": "not-an-aws-marker"}),
                             ("zero_maxitems", {"Filter": ["User"], "MaxItems": 0}),
                             ("too_large_maxitems", {"Filter": ["User"], "MaxItems": 1001})):
        p.details(name, parameters)
    names = {kind: [p.prefix + "-" + kind + suffix for suffix in ("a", "z")] for kind in ("user", "group", "role", "profile", "policy")}
    tags = [{"Key": "team", "Value": "space + slash/"}]
    for kind in ("user", "group", "role"):
        for index, name in enumerate(reversed(names[kind])):
            args = {kind.title() + "Name": name, "Path": p.path}
            if kind != "group" and index == 0:
                args["Tags"] = tags
            if kind == "role":
                args.update({"AssumeRolePolicyDocument": TRUST, "Description": "owned reporting fixture", "MaxSessionDuration": 7200})
            out = p.require("create-" + kind, args)[kind.title()]
            p.own(kind, name)
            p.ids[out[kind.title() + "Id"]] = {"user": "AIDA", "group": "AGPA", "role": "AROA"}[kind] + "REPORTFIXTURE" + ("Z" if index == 0 else "A")
    for name in names["profile"]:
        out = p.require("create-instance-profile", {"InstanceProfileName": name, "Path": p.path, "Tags": tags})["InstanceProfile"]
        p.own("profile", name)
        p.ids[out["InstanceProfileId"]] = "AIPAREPORTFIXTURE" + name[-1].upper()
    p.require("add-role-to-instance-profile", {"InstanceProfileName": names["profile"][0], "RoleName": names["role"][1]})
    p.summary("entities_created", {"Users": 2, "Groups": 2, "Roles": 2, "InstanceProfiles": 2})
    for kind in ("User", "Group", "Role"):
        p.bounded_owned_details("bare_" + kind.lower(), kind, raw=True)
    policies = []
    for name in names["policy"]:
        policy = p.require("create-policy", {"PolicyName": name, "Path": p.path, "Description": "owned policy description", "PolicyDocument": DOCUMENT, "Tags": tags})["Policy"]
        policies.append(policy["Arn"])
        p.own("policy", policy["Arn"])
        p.ids[policy["PolicyId"]] = "ANPAREPORTFIXTURE" + name[-1].upper()
    p.summary("unattached_policies", {"Policies": 2, "PolicyVersionsInUse": 0})
    p.require("create-policy-version", {"PolicyArn": policies[0], "PolicyDocument": DOCUMENT.replace("GetObject", "GetObjectVersion"), "SetAsDefault": False})
    p.require("create-policy-version", {"PolicyArn": policies[0], "PolicyDocument": DOCUMENT.replace("GetObject", "GetObjectAttributes"), "SetAsDefault": True})
    p.require("create-policy-version", {"PolicyArn": policies[0], "PolicyDocument": DOCUMENT.replace("GetObject", "ListBucket"), "SetAsDefault": False})
    p.summary("unattached_versions", {"Policies": 2, "PolicyVersionsInUse": 0})
    p.bounded_owned_details("unattached_policy_details", "LocalManagedPolicy", raw=True)
    policy = p.require("get-policy", {"PolicyArn": policies[0]})["Policy"]
    p.rows.append(p.normalize({"case": "policy_after_new_nondefault", "operation": "GetPolicy", "output": policy, "observed_at": stamp()}))
    p.require("put-user-permissions-boundary", {"UserName": names["user"][1], "PermissionsBoundary": policies[1]})
    p.summary("customer_boundary_only", {"Policies": 2, "PolicyVersionsInUse": 1})
    p.bounded_owned_details("customer_boundary_only_details", "LocalManagedPolicy", raw=True)
    p.require("put-role-permissions-boundary", {"RoleName": names["role"][1], "PermissionsBoundary": AWS_BOUNDARY})
    p.summary("aws_boundary_only", {"PolicyVersionsInUse": 2})
    p.policy_pages("aws_boundary_only_details", "AWSManagedPolicy", raw=True, target=AWS_BOUNDARY)
    p.require("delete-role-permissions-boundary", {"RoleName": names["role"][1]})
    p.require("attach-role-policy", {"RoleName": names["role"][1], "PolicyArn": AWS_BOUNDARY})
    p.summary("aws_attachment_only", {"PolicyVersionsInUse": 2})
    p.policy_pages("aws_attachment_only_details", "AWSManagedPolicy", raw=True, target=AWS_BOUNDARY)
    p.require("detach-role-policy", {"RoleName": names["role"][1], "PolicyArn": AWS_BOUNDARY})
    p.require("delete-user-permissions-boundary", {"UserName": names["user"][1]})
    p.summary("boundaries_and_extra_aws_removed", {"PolicyVersionsInUse": 0})
    for kind in ("user", "group", "role"):
        field, name = kind.title() + "Name", names[kind][1]
        p.require("put-" + kind + "-policy", {field: name, "PolicyName": "inline-encoding", "PolicyDocument": DOCUMENT})
        p.require("attach-" + kind + "-policy", {field: name, "PolicyArn": policies[0]})
        p.require("attach-" + kind + "-policy", {field: name, "PolicyArn": AWS_POLICY})
        if kind != "group":
            p.require("put-" + kind + "-permissions-boundary", {field: name, "PermissionsBoundary": policies[0]})
    p.require("add-user-to-group", {"UserName": names["user"][1], "GroupName": names["group"][1]})
    p.summary("attachments_and_boundaries", {"Policies": 2, "PolicyVersionsInUse": 1})
    for kind in ("User", "Group", "Role", "LocalManagedPolicy"):
        p.bounded_owned_details("configured_" + kind.lower(), kind, raw=True)
    for label, filters in (("default_filter", None), ("empty_filter", []), ("duplicate_filter", ["User", "User"]),
                           ("mixed_filter", ["Group", "User"]), ("all_filters", ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]),
                           ("aws_managed_attached", ["AWSManagedPolicy"])):
        parameters = {"MaxItems": 1000 if label == "aws_managed_attached" else 10}
        if filters is not None:
            parameters["Filter"] = filters
        p.details(label, parameters, raw=label == "all_filters")
    first = p.details("pagination_first", {"Filter": ["Group", "User", "LocalManagedPolicy"], "MaxItems": 1}, raw=True)
    if first.get("Marker"):
        marker = first["Marker"]
        p.details("pagination_next", {"Filter": ["Group", "User", "LocalManagedPolicy"], "MaxItems": 1, "Marker": marker}, marker_from="pagination_first")
        p.details("pagination_changed_maxitems", {"Filter": ["Group", "User", "LocalManagedPolicy"], "MaxItems": 3, "Marker": marker}, marker_from="pagination_first")
        p.details("pagination_reordered_filter", {"Filter": ["LocalManagedPolicy", "User", "Group"], "MaxItems": 1, "Marker": marker}, marker_from="pagination_first")
        p.details("pagination_changed_filter", {"Filter": ["Group"], "MaxItems": 1, "Marker": marker}, marker_from="pagination_first")
        p.details("pagination_omitted_filter", {"MaxItems": 1, "Marker": marker}, marker_from="pagination_first")
    summary_resources(p, names["user"][1])
    run_routing_phase(p)
    p.capture_complete = True


def run_summary_phase(p):
    user = p.prefix + "-summary-user"
    p.require("create-user", {"UserName": user, "Path": p.path})
    p.own("user", user)
    summary_resources(p, user)


def summary_resources(p, user):
    device = p.require("create-virtual-mfa-device", {"VirtualMFADeviceName": p.prefix + "-mfa", "Path": p.path})["VirtualMFADevice"]
    p.own("mfa", device["SerialNumber"])
    p.summary("unassigned_mfa", {"MFADevices": 1, "MFADevicesInUse": 0})
    seed = base64.b32decode(base64.b64decode(device["Base32StringSeed"]))
    step = int(time.time()) // 30
    p.require("enable-mfa-device", {"UserName": user, "SerialNumber": device["SerialNumber"], "AuthenticationCode1": totp(seed, step-1), "AuthenticationCode2": totp(seed, step)})
    p.summary("assigned_mfa", {"MFADevices": 1, "MFADevicesInUse": 1})
    metadata = (ROOT / "internal/services/iam/testdata/federation/metadata.xml").read_text()
    saml = p.require("create-saml-provider", {"Name": p.prefix + "-saml", "SAMLMetadataDocument": metadata})["SAMLProviderArn"]
    p.own("saml", saml)
    p.summary("saml_provider", {"Providers": 1})
    oidc = p.require("create-open-id-connect-provider", {"Url": "https://" + p.prefix + ".example.com", "ClientIDList": ["reporting"], "ThumbprintList": ["a" * 40]})["OpenIDConnectProviderArn"]
    p.own("oidc", oidc)
    p.summary("oidc_provider", {"Providers": 2})
    with tempfile.TemporaryDirectory(prefix="stackd-report-cert-") as directory:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.pem", "-out", "certificate.pem", "-days", "2", "-subj", "/CN=stackd-report.invalid"], cwd=directory, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        certificate = (Path(directory) / "certificate.pem").read_text()
        signing = p.require("upload-signing-certificate", {"UserName": user, "CertificateBody": certificate})["Certificate"]
        p.own("signing-certificate", signing["CertificateId"], {"user": user})
        p.ids[signing["CertificateId"]] = "REPORTSIGNINGCERTIFICATE"
        p.summary("user_signing_certificate", {"AccountSigningCertificatesPresent": 0})
        p.require("upload-server-certificate", {"ServerCertificateName": p.prefix + "-server", "Path": p.path, "CertificateBody": certificate, "PrivateKey": (Path(directory) / "private.pem").read_text()})
        p.own("server-certificate", p.prefix + "-server")
        p.summary("server_certificate", {"ServerCertificates": 1})


def run_pagination_phase(p):
    names = {kind: p.prefix + "-" + kind + "z" for kind in ("user", "group", "role", "profile", "policy")}
    tags = [{"Key": "team", "Value": "space + slash/"}]
    for kind in ("user", "group", "role"):
        args = {kind.title() + "Name": names[kind], "Path": p.path}
        if kind != "group":
            args["Tags"] = tags
        if kind == "role":
            args.update({"AssumeRolePolicyDocument": TRUST, "Description": "owned report", "MaxSessionDuration": 7200})
        out = p.require("create-" + kind, args)[kind.title()]
        p.own(kind, names[kind])
        p.ids[out[kind.title() + "Id"]] = {"user": "AIDA", "group": "AGPA", "role": "AROA"}[kind] + "REPORTFIXTUREZ"
        p.bounded_owned_details("bare_" + kind, kind.title(), raw=True)
    profile = p.require("create-instance-profile", {"InstanceProfileName": names["profile"], "Path": p.path, "Tags": tags})["InstanceProfile"]
    p.own("profile", names["profile"])
    p.ids[profile["InstanceProfileId"]] = "AIPAREPORTFIXTUREZ"
    p.require("add-role-to-instance-profile", {"InstanceProfileName": names["profile"], "RoleName": names["role"]})
    policy = p.require("create-policy", {"PolicyName": names["policy"], "Path": p.path, "PolicyDocument": DOCUMENT, "Description": "owned report", "Tags": tags})["Policy"]
    p.own("policy", policy["Arn"])
    p.ids[policy["PolicyId"]] = "ANPAREPORTFIXTUREZ"
    for kind in ("user", "group", "role"):
        field = kind.title() + "Name"
        p.require("put-" + kind + "-policy", {field: names[kind], "PolicyName": "inline-encoding", "PolicyDocument": DOCUMENT})
        p.require("attach-" + kind + "-policy", {field: names[kind], "PolicyArn": policy["Arn"]})
        p.require("attach-" + kind + "-policy", {field: names[kind], "PolicyArn": AWS_POLICY})
        if kind != "group":
            p.require("put-" + kind + "-permissions-boundary", {field: names[kind], "PermissionsBoundary": policy["Arn"]})
    p.require("add-user-to-group", {"UserName": names["user"], "GroupName": names["group"]})
    for kind in ("User", "Group", "Role"):
        p.bounded_owned_details("configured_" + kind.lower(), kind, raw=True)
    for label, filters in (("default_filter", None), ("empty_filter", []), ("duplicate_filter", ["User", "User"]),
                           ("mixed_filter", ["Group", "User"]), ("all_filters", ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"])):
        parameters = {"MaxItems": 10}
        if filters is not None:
            parameters["Filter"] = filters
        p.details(label, parameters, raw=label in ("default_filter", "all_filters"))
    first = p.details("pagination_first", {"Filter": ["Group", "User", "LocalManagedPolicy"], "MaxItems": 1}, raw=True)
    if first.get("Marker"):
        marker = first["Marker"]
        for label, filters, maximum in (("next", ["Group", "User", "LocalManagedPolicy"], 1),
                                       ("changed_maxitems", ["Group", "User", "LocalManagedPolicy"], 3),
                                       ("reordered_filter", ["LocalManagedPolicy", "User", "Group"], 1),
                                       ("changed_filter", ["Group"], 1), ("omitted_filter", None, 1)):
            parameters = {"MaxItems": maximum, "Marker": marker}
            if filters is not None:
                parameters["Filter"] = filters
            p.details("pagination_" + label, parameters, marker_from="pagination_first")


def run_routing_phase(p):
    """Read aggregate routing behavior without creating any resources."""
    p.details("section_order_role_group", {"Filter": ["Role", "Group"], "MaxItems": 1})
    p.details("section_order_role_policy", {"Filter": ["Role", "LocalManagedPolicy"], "MaxItems": 1})
    p.details("section_order_group_policy", {"Filter": ["LocalManagedPolicy", "Group"], "MaxItems": 1})
    counts = p.require("get-account-summary")["SummaryMap"]
    if counts.get("Users", 0) < 999 and counts.get("Groups", 0) > 0:
        p.details("pagination_crosses_sections", {"Filter": ["Group", "User"], "MaxItems": counts["Users"] + 1})
    first = p.details("pagination_default_first", {"MaxItems": 1})
    if first.get("Marker"):
        p.details("pagination_default_explicit_all", {
            "Filter": ["AWSManagedPolicy", "LocalManagedPolicy", "Role", "Group", "User"],
            "MaxItems": 1, "Marker": first["Marker"]}, marker_from="pagination_default_first")
        p.details("pagination_default_explicit_local", {
            "Filter": ["User", "Group", "Role", "LocalManagedPolicy"],
            "MaxItems": 1, "Marker": first["Marker"]}, marker_from="pagination_default_first")


if __name__ == "__main__":
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("all", "summary", "pagination", "routing"), default="all")
    parser.add_argument("--preserve", action="store_true", help="Merge successful earlier observations by case name")
    parser.add_argument("--account", required=True)
    arguments = parser.parse_args()
    require_account(arguments.account)
    probe = Probe(arguments.phase, arguments.preserve)
    try:
        run(probe)
    finally:
        probe.finish()
