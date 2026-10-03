#!/usr/bin/env python3
"""Capture IAM Organizations access reports with an isolated empty OU and SCP.

No account creation, moves, billing changes, shared policies, root policy types,
or delegated administrators are modified. IAM observer keys stay in memory;
only owned entities and normalized report metadata are retained.

Run initial, controls, final, and target-dependencies phases into separate
--output paths, then pass those paths to --merge to build the checked-in fixture. The optional
existing-controls phase borrows an active controls --journal for read-only sort
checks; it must finish before the controls phase deletes its owned resources.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
from aws_cli import run as run_cli, result as cli_result
from iam_last_access_probe import call as iam_call, operation, policy, allow

ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / '.stackd/probes/iam/organizations_access.json'
DOCS = [
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetOrganizationsAccessReport.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed-view-data-orgs.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_iam_service-accessed-data-orgs.html",
]
IAM_REPORTS = ["iam:GenerateOrganizationsAccessReport", "iam:GetOrganizationsAccessReport"]
ORG_READS = ["organizations:DescribeOrganization", "organizations:DescribeOrganizationalUnit", "organizations:DescribePolicy",
             "organizations:ListChildren", "organizations:ListParents", "organizations:ListPoliciesForTarget",
             "organizations:ListRoots", "organizations:ListTargetsForPolicy"]


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def service_projection(data):
    for row in data["observations"]:
        result = row.get("output", {})
        details = result.get("AccessDetails", [])
        if result.get("JobStatus") == "COMPLETED" and not result.get("IsTruncated", True) and len(details) > 400 and all(item.get("TotalAuthenticatedEntities") == 0 for item in details):
            data["services_source_case"] = row["case"]
            data["services"] = sorted([{"namespace": item["ServiceNamespace"], "name": item["ServiceName"],
                                         **({"default_region": item["Region"]} if "Region" in item else {})} for item in details], key=lambda item: item["namespace"])
            break
    for row in data["observations"]:
        result = row.get("output", {})
        details = result.get("AccessDetails", [])
        if row.get("input", {}).get("SortKey") == "LAST_AUTHENTICATED_TIME_ASCENDING" and not result.get("IsTruncated", True) and len(details) > 400 and all(item.get("TotalAuthenticatedEntities") == 0 for item in details):
            ranks = {item["ServiceNamespace"]: index for index, item in enumerate(details)}
            if "services" in data and {item["namespace"] for item in data["services"]} == set(ranks):
                data["time_sort_source_case"] = row["case"]
                for item in data["services"]:
                    item["time_sort_rank"] = ranks[item["namespace"]]
            break


def call(service, action, parameters=None, environment=None):
    if service in ("iam", "sts"):
        return iam_call(action, parameters or {}, environment, service)
    process = run_cli(service, action, parameters or {}, environment, timeout=60,
                      options=["--region", "us-east-1", "--no-paginate", "--debug"])
    return cli_result(process, cli_message="CLI rejected request; diagnostics discarded", debug=True)


class Probe:
    def __init__(self, output):
        self.output = output
        self.prefix = "stackd-org-access-" + uuid.uuid4().hex[:10]
        self.normalized_prefix = "stackd-org-access-fixture"
        self.started = stamp()
        self.account = ""
        self.identifiers, self.jobs, self.markers = {}, {}, {}
        self.setup, self.changes, self.observations, self.owned, self.cleanup = [], [], [], [], []
        self.complete = False
        self.eligibility = {}
        self.limitations = [
            "Only uniquely owned empty OU, customer SCP and IAM observers may be modified; no AWS accounts are created or moved and no existing policies, root policy types, billing or shared delegations are changed.",
            "Owned OUs contain no accounts, so inherited-policy versus direct-attachment activity attribution cannot be distinguished with these reports.",
            "Publication after four hours and credential expiration are not accelerated or inferred from job creation.",
        ]
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")
        self.cli_version = subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.strip()

    def normalize(self, value):
        if isinstance(value, dict):
            return {key: self.normalize(item) for key, item in value.items()
                    if key not in ("SecretAccessKey", "SessionToken", "Credentials", "MasterAccountEmail", "ManagementAccountEmail")}
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            value = re.sub(r"(?<=/authorization-details/)[a-zA-Z0-9_-]+", "<authorization-id>", value)
            value = re.sub(r"(?<=authorization id: )[a-zA-Z0-9_-]+", "<authorization-id>", value)
            for actual, replacement in sorted(self.identifiers.items(), key=lambda item: -len(item[0])):
                value = value.replace(actual, replacement)
            value = value.replace(self.prefix, self.normalized_prefix)
            if self.account:
                value = value.replace(self.account, "123456789012")
        return value

    def write(self, cleaned=False):
        data = {"schema_version": 1, "source": "Real AWS IAM and Organizations APIs, commercial partition",
                "probe": "scripts/aws/iam_organizations_access_probe.py", "endpoint": "https://iam.amazonaws.com", "region": "us-east-1",
                "started_at": self.started, "finished_at": stamp(), "aws_cli_version": self.cli_version,
                "documentation": DOCS, "eligibility": self.eligibility,
                "sanitization": "Owned names/IDs and management-account/organization paths normalized; caller ARN and ID redacted. No credential secrets, account email addresses, unrelated principal identities or CLI debug logs retained.",
                "setup": self.normalize(self.setup), "observations": self.observations,
                "capture_complete": self.complete, "cleanup_verified": cleaned, "cleanup": self.normalize(self.cleanup), "limitations": self.limitations}
        service_projection(data)
        self.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(data, indent=2) + "\n")
        temporary.replace(self.output)

    def observe(self, case, service, action, parameters=None, environment=None, credential="original"):
        parameters = parameters or {}
        result = call(service, action, parameters, environment)
        row = {"case": case, "service": service, "operation": operation(action), "input": parameters,
               "credential": credential, "observed_at": stamp(), **result}
        if case.startswith("target_dependency_") and action == "get-organizations-access-report" and "output" in row:
            # Root/account controls need only status and dependency failures.
            # Discard all account activity before retaining any observation.
            row["output"] = {key: value for key, value in row["output"].items() if key not in ("AccessDetails", "Marker")}
            row["omitted_output_fields"] = ["AccessDetails", "Marker"]
        if self.changes:
            row["state_changes_before"] = self.changes
            self.changes = []
        if parameters.get("JobId") in self.jobs:
            row["job_source_case"] = self.jobs[parameters["JobId"]]
        if parameters.get("Marker") in self.markers:
            row["marker_source_case"] = self.markers[parameters["Marker"]]
        if result["code"] == "Success":
            output = result["output"]
            if "JobId" in output:
                if output["JobId"] in self.jobs:
                    row["reused_job_source_case"] = self.jobs[output["JobId"]]
                else:
                    self.jobs[output["JobId"]] = case
                    self.identifiers[output["JobId"]] = "<job:" + case + ">"
            if "Marker" in output:
                self.markers[output["Marker"]] = case
                self.identifiers[output["Marker"]] = "<marker:" + case + ">"
        self.observations.append(self.normalize(row))
        self.write()
        print(case, result["code"], result.get("output", {}).get("JobStatus", ""), flush=True)
        return result

    def require(self, service, action, parameters):
        result = call(service, action, parameters)
        if result["code"] != "Success":
            # Record the failed mutation once. Reissuing a create merely to log
            # it could succeed and leave an untracked resource behind.
            self.observations.append(self.normalize({"case": "setup_failure_" + action, "service": service,
                                                      "operation": operation(action), "input": parameters,
                                                      "credential": "original", "observed_at": stamp(), **result}))
            self.write()
            raise RuntimeError(service + ":" + action + " failed: " + result["code"])
        row = {"service": service, "operation": operation(action), "input": parameters, "output": result["output"]}
        (self.changes if self.observations else self.setup).append(row)
        return result["output"]

    def own(self, service, action, parameters, verify=None):
        self.owned.append({"service": service, "action": action, "input": parameters, "verify": verify})
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self.journal.write_text(json.dumps({"prefix": self.prefix, "owned": self.owned}, indent=2) + "\n")

    def generate(self, case, path, policy_id=None, environment=None, credential="original"):
        parameters = {"EntityPath": path}
        if policy_id is not None:
            parameters["OrganizationsPolicyId"] = policy_id
        result = self.observe(case, "iam", "generate-organizations-access-report", parameters, environment, credential)
        return result.get("output", {}).get("JobId")

    def get(self, case, job, environment=None, credential="original", **extra):
        if not job:
            return None
        return self.observe(case, "iam", "get-organizations-access-report", {"JobId": job, **extra}, environment, credential)

    def wait_job(self, case, job, environment=None, credential="original", **extra):
        if not job:
            return None
        deadline = time.monotonic() + 60
        for index in range(30):
            result = self.get(case + ("_first" if index == 0 else "_poll_" + str(index)), job, environment, credential, **extra)
            if result.get("output", {}).get("JobStatus") != "IN_PROGRESS" or time.monotonic() >= deadline:
                return result
            time.sleep(1)
        self.limitations.append(case + " remained in progress at the bounded polling limit")
        return result

    def inline(self, user, document):
        parameters = {"UserName": user["UserName"], "PolicyName": "ReportPermissions", "PolicyDocument": document}
        self.require("iam", "put-user-policy", parameters)
        deletion = {"UserName": user["UserName"], "PolicyName": "ReportPermissions"}
        if not any(item["action"] == "delete-user-policy" and item["input"] == deletion for item in self.owned):
            self.own("iam", "delete-user-policy", deletion)

    def user(self, suffix):
        name = self.prefix + "-" + suffix
        user = self.require("iam", "create-user", {"UserName": name, "Path": "/org-access/"})["User"]
        self.identifiers[user["UserId"]] = "<user-id:" + suffix + ">"
        self.own("iam", "delete-user", {"UserName": name}, {"service": "iam", "action": "get-user", "input": {"UserName": name}})
        return user

    def key(self, user, label):
        value = self.require("iam", "create-access-key", {"UserName": user["UserName"]})["AccessKey"]
        self.identifiers[value["AccessKeyId"]] = "<access-key:" + label + ">"
        self.own("iam", "delete-access-key", {"UserName": user["UserName"], "AccessKeyId": value["AccessKeyId"]})
        environment = os.environ.copy()
        environment.update(AWS_ACCESS_KEY_ID=value["AccessKeyId"], AWS_SECRET_ACCESS_KEY=value["SecretAccessKey"], AWS_EC2_METADATA_DISABLED="true")
        environment.pop("AWS_SESSION_TOKEN", None)
        environment.pop("AWS_PROFILE", None)
        # IAM/STS may accept a fresh key before the Organizations endpoint does.
        # Only wait for credential recognition; an authorization denial is a
        # valid readiness result and is not mistaken for propagation.
        for _ in range(12):
            ready = call("organizations", "describe-organization", {}, environment)
            if ready["code"] not in ("UnrecognizedClientException", "InvalidClientTokenId"):
                break
            time.sleep(1)
        return environment

    def finish(self):
        failures = []
        for item in reversed(self.owned):
            try:
                result = call(item["service"], item["action"], item["input"])
            except Exception:
                result = {"code": "TransportFailure"}
            self.cleanup.append({"service": item["service"], "operation": operation(item["action"]), "input": item["input"], "code": result["code"]})
            already_disabled = item["service"] == "iam" and item["action"] == "disable-outbound-web-identity-federation" and result["code"] == "FeatureDisabled"
            if not already_disabled and result["code"] not in ("Success", "NoSuchEntity", "PolicyNotFoundException", "OrganizationalUnitNotFoundException", "PolicyNotAttachedException"):
                failures.append(item)
        for item in self.owned:
            verification = item.get("verify")
            if not verification:
                continue
            result = call(verification["service"], verification["action"], verification["input"])
            self.cleanup.append({"service": verification["service"], "operation": operation(verification["action"]), "input": verification["input"], "code": result["code"]})
            if result["code"] not in ("NoSuchEntity", "PolicyNotFoundException", "OrganizationalUnitNotFoundException"):
                failures.append(item)
        self.write(not failures)
        if failures:
            raise RuntimeError("Cleanup incomplete; owned-resource recovery journal: " + str(self.journal))
        self.journal.unlink(missing_ok=True)
        print("cleanup_verified", len(self.owned), flush=True)


def service_metadata(probe):
    """Capture names/default regions/order from one owned empty OU only."""
    identity = probe.require("sts", "get-caller-identity", {})
    probe.account = identity["Account"]
    probe.identifiers.update({identity["Arn"]: "<original-caller-arn>", identity["UserId"]: "<original-caller-id>"})
    org = probe.require("organizations", "describe-organization", {})["Organization"]
    root = probe.require("organizations", "list-roots", {})["Roots"][0]
    owner = org.get("ManagementAccountId", org.get("MasterAccountId"))
    if owner != probe.account or org["FeatureSet"] != "ALL" or not any(x["Type"] == "SERVICE_CONTROL_POLICY" and x["Status"] == "ENABLED" for x in root["PolicyTypes"]):
        raise RuntimeError("Existing configuration does not admit the owned reporting capture")
    probe.identifiers.update({org["Id"]: "o-aaaaaaaaaa", root["Id"]: "r-abcd"})
    probe.eligibility = {"management_account": True, "feature_set": org["FeatureSet"], "root_policy_types": root["PolicyTypes"]}
    ou = probe.require("organizations", "create-organizational-unit", {"ParentId": root["Id"], "Name": probe.prefix})["OrganizationalUnit"]
    probe.identifiers[ou["Id"]] = "ou-abcd-00000004"
    probe.own("organizations", "delete-organizational-unit", {"OrganizationalUnitId": ou["Id"]},
              {"service": "organizations", "action": "describe-organizational-unit", "input": {"OrganizationalUnitId": ou["Id"]}})
    job = probe.generate("metadata_generate", org["Id"] + "/" + root["Id"] + "/" + ou["Id"])
    for suffix, sort_key in [("names", "SERVICE_NAMESPACE_ASCENDING"), ("time", "LAST_AUTHENTICATED_TIME_ASCENDING")]:
        result = probe.wait_job("metadata_" + suffix, job, MaxItems=1000, SortKey=sort_key)
        out = (result or {}).get("output", {})
        if out.get("JobStatus") != "COMPLETED" or out.get("IsTruncated", True) or any(x.get("TotalAuthenticatedEntities") != 0 for x in out.get("AccessDetails", [])):
            raise RuntimeError("Owned empty OU report was not complete and empty of authenticated entities")


def run(probe):
    identity = call("sts", "get-caller-identity")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable; diagnostics discarded")
    identity = identity["output"]
    probe.account = identity["Account"]
    probe.identifiers[identity["Arn"]] = "<original-caller-arn>"
    probe.identifiers[identity["UserId"]] = "<original-caller-id>"
    organization = call("organizations", "describe-organization")
    if organization["code"] != "Success":
        probe.eligibility = {"organization_error": organization["code"]}
        probe.generate("standalone_or_unavailable_organization", "o-aaaaaaaaaa/r-abcd")
        return
    organization = organization["output"]["Organization"]
    probe.identifiers[organization["Id"]] = "o-aaaaaaaaaa"
    owner = organization.get("ManagementAccountId", organization.get("MasterAccountId"))
    probe.eligibility = {"management_account": owner == probe.account, "feature_set": organization.get("FeatureSet"),
                         "available_policy_types": organization.get("AvailablePolicyTypes", [])}
    roots = call("organizations", "list-roots")
    if roots["code"] != "Success":
        probe.eligibility["list_roots_error"] = roots["code"]
        probe.generate("unavailable_roots", organization["Id"] + "/r-abcd")
        return
    root = roots["output"]["Roots"][0]
    probe.identifiers[root["Id"]] = "r-abcd"
    probe.eligibility["root_policy_types"] = root.get("PolicyTypes", [])
    root_path = organization["Id"] + "/" + root["Id"]
    if owner != probe.account or not any(item.get("Type") == "SERVICE_CONTROL_POLICY" and item.get("Status") == "ENABLED" for item in root.get("PolicyTypes", [])):
        probe.generate("organization_ineligible", root_path + "/" + probe.account)
        return
    ou = probe.require("organizations", "create-organizational-unit", {"ParentId": root["Id"], "Name": probe.prefix})["OrganizationalUnit"]
    probe.identifiers[ou["Id"]] = "ou-abcd-00000001"
    probe.own("organizations", "delete-organizational-unit", {"OrganizationalUnitId": ou["Id"]},
              {"service": "organizations", "action": "describe-organizational-unit", "input": {"OrganizationalUnitId": ou["Id"]}})
    path = root_path + "/" + ou["Id"]
    created = probe.require("organizations", "create-policy", {"Name": probe.prefix, "Description": "Temporary owned stackd report behavior capture", "Type": "SERVICE_CONTROL_POLICY", "Content": policy(allow(["s3:GetObject", "iam:GetUser", "sqs:SendMessage"]))})["Policy"]
    policy_id = created["PolicySummary"]["Id"]
    probe.identifiers[policy_id] = "p-owned001"
    probe.own("organizations", "delete-policy", {"PolicyId": policy_id}, {"service": "organizations", "action": "describe-policy", "input": {"PolicyId": policy_id}})
    attachment = {"PolicyId": policy_id, "TargetId": ou["Id"]}
    probe.require("organizations", "attach-policy", attachment)
    probe.own("organizations", "detach-policy", attachment)
    job = probe.generate("generate_owned_selected_policy", path, policy_id)
    probe.wait_job("get_owned_selected_policy", job)
    full_job = probe.generate("generate_owned_ou_no_policy", path)
    probe.wait_job("get_owned_ou_no_policy", full_job)
    reporter = probe.user("reporter")
    other = probe.user("other")
    probe.inline(reporter, policy(allow(IAM_REPORTS)))
    probe.inline(other, policy(allow(IAM_REPORTS), allow(ORG_READS)))
    key = probe.key(reporter, "reporter-one")
    second_key = probe.key(reporter, "reporter-two")
    other_key = probe.key(other, "other")
    # Wait only for newly issued IAM credentials to propagate, not report data.
    for attempt in range(10):
        authentication = call("sts", "get-caller-identity", environment=key)
        if authentication["code"] == "Success":
            break
        time.sleep(1)
    iam_only = probe.generate("generate_observer_iam_only", path, policy_id, key, "reporter_one")
    probe.wait_job("get_observer_iam_only", iam_only, key, "reporter_one")
    probe.get("get_admin_job_iam_only", job, key, "reporter_one")
    probe.inline(reporter, policy(allow(IAM_REPORTS), allow(ORG_READS)))
    observer_job = probe.generate("generate_observer_full_reads", path, policy_id, key, "reporter_one")
    probe.wait_job("get_observer_full_reads", observer_job, key, "reporter_one")
    if observer_job:
        for label, environment in (("same_user_other_key", second_key), ("different_user", other_key), ("original_caller", None)):
            probe.get("ownership_" + label, observer_job, environment, label)
    sorting_and_validation(probe, path, root_path, policy_id, job, full_job)
    policy_controls(probe, path, policy_id)
    # The management-account report contains aggregate namespace/account-path/
    # timestamp fields, not IAM identity details. No root/OU-wide activity is read.
    management = probe.generate("generate_management_selected_policy", root_path + "/" + probe.account, policy_id)
    probe.wait_job("get_management_selected_policy", management, MaxItems=2)


def sorting_and_validation(probe, path, root_path, policy_id, job, full_job):
    for sort in ("SERVICE_NAMESPACE_ASCENDING", "SERVICE_NAMESPACE_DESCENDING", "LAST_AUTHENTICATED_TIME_ASCENDING", "LAST_AUTHENTICATED_TIME_DESCENDING"):
        probe.get("sort_" + sort.lower(), job, MaxItems=2, SortKey=sort)
    first = probe.get("pagination_first", job, MaxItems=1)
    marker = first.get("output", {}).get("Marker")
    if marker:
        for label, target, sort in (("same", job, "SERVICE_NAMESPACE_ASCENDING"), ("changed_sort", job, "SERVICE_NAMESPACE_DESCENDING"), ("changed_job", full_job, "SERVICE_NAMESPACE_ASCENDING")):
            probe.get("pagination_" + label, target, MaxItems=2, SortKey=sort, Marker=marker)
    for label, parameters in (("missing_job", {"JobId": "00000000-0000-0000-0000-000000000000"}),
                               ("short_job", {"JobId": "bad"}), ("non_uuid", {"JobId": "x" * 36}),
                               ("invalid_marker", {"JobId": job, "Marker": "invalid"}),
                               ("max_zero", {"JobId": job, "MaxItems": 0}), ("max_large", {"JobId": job, "MaxItems": 1001}),
                               ("empty_sort", {"JobId": job, "SortKey": ""}), ("invalid_sort", {"JobId": job, "SortKey": "INVALID"})):
        probe.observe("get_validation_" + label, "iam", "get-organizations-access-report", parameters)
    for label, value in (("short", "bad"), ("missing_ou", root_path + "/ou-abcd-99999999"),
                         ("wrong_root", path.replace(root_path, root_path.split("/")[0] + "/r-zzzz")),
                         ("wrong_org", path.replace(root_path.split("/")[0], "o-zzzzzzzzzz")),
                         ("trailing_slash", path + "/"), ("missing_account_in_owned_ou", path + "/999999999999")):
        created = probe.generate("path_" + label, value, policy_id)
        probe.wait_job("path_result_" + label, created)
    for label, value in (("missing_policy", "p-notexist0"), ("short_policy", "bad"), ("empty_policy", "")):
        created = probe.generate("policy_id_" + label, path, value)
        probe.wait_job("policy_id_result_" + label, created)


def policy_controls(probe, path, policy_id):
    a = "arn:aws:s3:::" + probe.prefix + "-a/*"
    b = "arn:aws:s3:::" + probe.prefix + "-b/*"
    cases = [
        ("deny_only", policy({"Effect": "Deny", "Action": "s3:*", "Resource": "*"})),
        ("condition_allow", policy(allow("s3:GetObject", Condition={"StringEquals": {"aws:username": "nobody"}}))),
        ("condition_deny", policy(allow("s3:GetObject"), {"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"StringEquals": {"aws:username": "nobody"}}})),
        ("bucket_only", policy(allow("s3:GetObject", a.removesuffix("/*")))),
        ("same_resource_deny", policy(allow("s3:GetObject", a), {"Effect": "Deny", "Action": "s3:*", "Resource": a})),
        ("disjoint_resource_deny", policy(allow("s3:GetObject", a), {"Effect": "Deny", "Action": "s3:*", "Resource": b})),
    ]
    for label, document in cases:
        probe.require("organizations", "update-policy", {"PolicyId": policy_id, "Content": document})
        job = probe.generate("selection_generate_" + label, path, policy_id)
        probe.wait_job("selection_get_" + label, job)
    probe.require("organizations", "update-policy", {"PolicyId": policy_id, "Content": policy(allow("*"))})
    job = probe.generate("pending_generate", path, policy_id)
    probe.get("pending_before_update", job)
    probe.require("organizations", "update-policy", {"PolicyId": policy_id, "Content": policy(allow("sns:Publish"))})
    probe.get("pending_after_update", job)
    probe.wait_job("pending_completed", job)
    current = probe.generate("pending_regenerate", path, policy_id)
    probe.wait_job("pending_regenerated", current)


def run_controls(probe):
    """Use fresh policy IDs and fresh observers to avoid cached-input ambiguity."""
    probe.normalized_prefix = "stackd-org-access-controls"
    identity = call("sts", "get-caller-identity")["output"]
    probe.account = identity["Account"]
    probe.identifiers.update({identity["Arn"]: "<original-caller-arn>", identity["UserId"]: "<original-caller-id>"})
    org = call("organizations", "describe-organization")["output"]["Organization"]
    root = call("organizations", "list-roots")["output"]["Roots"][0]
    if org.get("ManagementAccountId", org.get("MasterAccountId")) != probe.account:
        raise RuntimeError("Controls require management-account credentials")
    probe.identifiers.update({org["Id"]: "o-aaaaaaaaaa", root["Id"]: "r-abcd"})
    probe.eligibility = {"management_account": True, "feature_set": org["FeatureSet"], "root_policy_types": root["PolicyTypes"]}
    ou = probe.require("organizations", "create-organizational-unit", {"ParentId": root["Id"], "Name": probe.prefix})["OrganizationalUnit"]
    probe.identifiers[ou["Id"]] = "ou-abcd-00000002"
    probe.own("organizations", "delete-organizational-unit", {"OrganizationalUnitId": ou["Id"]},
              {"service": "organizations", "action": "describe-organizational-unit", "input": {"OrganizationalUnitId": ou["Id"]}})
    path = org["Id"] + "/" + root["Id"] + "/" + ou["Id"]
    policy_number = 1

    def fresh_policy(label, document):
        nonlocal policy_number
        created = probe.require("organizations", "create-policy", {"Name": probe.prefix + "-" + label, "Description": "Temporary owned report control", "Type": "SERVICE_CONTROL_POLICY", "Content": document})["Policy"]["PolicySummary"]
        probe.identifiers[created["Id"]] = "p-control" + str(policy_number).zfill(3)
        policy_number += 1
        probe.own("organizations", "delete-policy", {"PolicyId": created["Id"]},
                  {"service": "organizations", "action": "describe-policy", "input": {"PolicyId": created["Id"]}})
        return created["Id"]

    a = "arn:aws:s3:::" + probe.prefix + "-a/*"
    b = "arn:aws:s3:::" + probe.prefix + "-b/*"
    cases = [
        ("deny_only", policy({"Effect": "Deny", "Action": "s3:*", "Resource": "*"})),
        ("condition_allow", policy(allow("s3:GetObject", Condition={"StringEquals": {"aws:username": "nobody"}}))),
        ("condition_deny", policy(allow("s3:GetObject"), {"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"StringEquals": {"aws:username": "nobody"}}})),
        ("bucket_only", policy(allow("s3:GetObject", a.removesuffix("/*")))),
        ("same_resource_deny", policy(allow("s3:GetObject", a), {"Effect": "Deny", "Action": "s3:*", "Resource": a})),
        ("disjoint_resource_deny", policy(allow("s3:GetObject", a), {"Effect": "Deny", "Action": "s3:*", "Resource": b})),
    ]
    for label, document in cases:
        pid = fresh_policy(label, document)
        job = probe.generate("fresh_selection_generate_" + label, path, pid)
        probe.wait_job("fresh_selection_get_" + label, job, MaxItems=1000)
        probe.generate("fresh_selection_repeat_" + label, path, pid)

    pid = fresh_policy("all_services", policy(allow("*")))
    job = probe.generate("fresh_all_services_generate", path, pid)
    probe.wait_job("fresh_all_services_get", job, MaxItems=1000)
    probe.generate("cache_before_change", path, pid)
    probe.require("organizations", "update-policy", {"PolicyId": pid, "Content": policy(allow("sns:Publish"))})
    after = probe.generate("cache_after_change", path, pid)
    probe.get("cache_after_change_get", after, MaxItems=1)

    reference = fresh_policy("permissions", policy(allow(["s3:GetObject", "iam:GetUser", "sqs:SendMessage"])))
    # Newly created observers avoid permission propagation being confused with a
    # reused report after modifying the caller's policy.
    dependency_actions = ["DescribePolicy", "ListChildren", "ListParents", "ListPoliciesForTarget", "ListRoots", "ListTargetsForPolicy"]
    profiles = [("all_reads", policy(allow(IAM_REPORTS), allow(["organizations:Describe*", "organizations:List*"]))),
                ("narrow_reads", policy(allow(IAM_REPORTS), allow(ORG_READS))),
                ("iam_only", policy(allow(IAM_REPORTS)))]
    for action in dependency_actions:
        profiles.append(("deny_" + action.lower(), policy(allow(IAM_REPORTS), allow(["organizations:Describe*", "organizations:List*"]),
                                                        {"Effect": "Deny", "Action": "organizations:" + action, "Resource": "*"})))
    for label, permissions in profiles:
        user = probe.user(label)
        probe.inline(user, permissions)
        env = probe.key(user, label)
        for attempt in range(10):
            if call("sts", "get-caller-identity", environment=env)["code"] == "Success":
                break
            time.sleep(1)
        for mode, selected in (("policy", reference), ("ou", None)):
            generated = probe.generate("permissions_" + label + "_" + mode + "_generate", path, selected, env, label)
            probe.wait_job("permissions_" + label + "_" + mode + "_get", generated, env, label, MaxItems=1)
        if label == "all_reads":
            # Get authorization is tested independently from generation by
            # keeping IAM Get while explicitly denying all Organizations reads.
            probe.inline(user, policy(allow(IAM_REPORTS), {"Effect": "Deny", "Action": "organizations:*", "Resource": "*"}))
            for attempt in range(10):
                check = probe.observe("get_after_org_deny_confirm_" + str(attempt), "organizations", "describe-organization", {}, env, label)
                if check["code"] != "Success":
                    break
                time.sleep(1)
            probe.get("get_after_org_deny", generated, env, label, MaxItems=1)
    probe.limitations.extend([
        "Fresh selector controls use distinct SCP IDs; those policies are unattached to the empty owned OU, so they describe service eligibility with zero activity.",
        "Immediate repeated Generate calls can reuse an existing job; only observed UUID equality and timestamps are recorded, with no undocumented cache lifetime assumed.",
        "Concurrent report quota was not saturated, and management/member-account configuration was not modified to test ineligibility.",
    ])


def run_existing_controls(probe, journal):
    """Read-only controls while the main probe still owns its empty OU/SCPs."""
    state = json.loads(journal.read_text())
    probe.prefix = state["prefix"]
    probe.normalized_prefix = "stackd-org-access-controls"
    identity = call("sts", "get-caller-identity")["output"]
    probe.account = identity["Account"]
    probe.identifiers.update({identity["Arn"]: "<original-caller-arn>", identity["UserId"]: "<original-caller-id>"})
    org = call("organizations", "describe-organization")["output"]["Organization"]
    root = call("organizations", "list-roots")["output"]["Roots"][0]
    probe.identifiers.update({org["Id"]: "o-aaaaaaaaaa", root["Id"]: "r-abcd"})
    ou = next(item["input"]["OrganizationalUnitId"] for item in state["owned"] if item["action"] == "delete-organizational-unit")
    probe.identifiers[ou] = "ou-abcd-00000002"
    pids = [item["input"]["PolicyId"] for item in state["owned"] if item["action"] == "delete-policy"]
    for index, pid in enumerate(pids):
        probe.identifiers[pid] = "p-control" + str(index + 1).zfill(3)
    path = org["Id"] + "/" + root["Id"] + "/" + ou
    # No-policy empty OU still has FullAWSAccess; no real account activity.
    full = probe.generate("sort_full_generate", path)
    probe.wait_job("sort_full_get", full, MaxItems=1000)
    for sort in ("LAST_AUTHENTICATED_TIME_ASCENDING", "LAST_AUTHENTICATED_TIME_DESCENDING"):
        probe.get("sort_full_" + sort.lower(), full, MaxItems=1000, SortKey=sort)
    three = probe.generate("sort_three_generate", path, pids[7])
    result = probe.wait_job("sort_three_get", three, MaxItems=1000)
    for sort in ("LAST_AUTHENTICATED_TIME_ASCENDING", "LAST_AUTHENTICATED_TIME_DESCENDING"):
        probe.get("sort_three_" + sort.lower(), three, MaxItems=1000, SortKey=sort)
    created = datetime.datetime.fromisoformat(result["output"]["JobCreationDate"]).timestamp()
    for age in (30, 55, 61, 70):
        remaining = created + age - time.time()
        if remaining > 0:
            time.sleep(remaining)
        current = probe.generate("cache_age_" + str(age), path, pids[7])
        probe.get("cache_age_" + str(age) + "_get", current, MaxItems=1)
    probe.limitations.append("Read-only controls borrow the empty OU and SCPs owned by the controls phase, whose cleanup is recorded separately. Cache ages are measured from AWS JobCreationDate, not asserted as a published AWS TTL.")


def run_final(probe):
    """Bounded permission, cache and quota controls after earlier jobs settle."""
    probe.normalized_prefix = "stackd-org-access-final"
    identity = call("sts", "get-caller-identity")["output"]
    probe.account = identity["Account"]
    probe.identifiers.update({identity["Arn"]: "<original-caller-arn>", identity["UserId"]: "<original-caller-id>"})
    org = call("organizations", "describe-organization")["output"]["Organization"]
    root = call("organizations", "list-roots")["output"]["Roots"][0]
    probe.identifiers.update({org["Id"]: "o-aaaaaaaaaa", root["Id"]: "r-abcd"})
    probe.eligibility = {"management_account": org.get("ManagementAccountId", org.get("MasterAccountId")) == probe.account,
                         "feature_set": org["FeatureSet"], "root_policy_types": root["PolicyTypes"]}
    if not probe.eligibility["management_account"]:
        raise RuntimeError("Final controls require management credentials")
    ou = probe.require("organizations", "create-organizational-unit", {"ParentId": root["Id"], "Name": probe.prefix})["OrganizationalUnit"]
    probe.identifiers[ou["Id"]] = "ou-abcd-00000003"
    probe.own("organizations", "delete-organizational-unit", {"OrganizationalUnitId": ou["Id"]},
              {"service": "organizations", "action": "describe-organizational-unit", "input": {"OrganizationalUnitId": ou["Id"]}})
    root_path = org["Id"] + "/" + root["Id"]
    path = root_path + "/" + ou["Id"]
    management = root_path + "/" + probe.account
    policies = []
    for index, actions in enumerate((["s3:GetObject", "iam:GetUser", "sqs:SendMessage"], "*", "*")):
        created = probe.require("organizations", "create-policy", {"Name": probe.prefix + "-" + str(index), "Description": "Temporary owned report control", "Type": "SERVICE_CONTROL_POLICY", "Content": policy(allow(actions))})["Policy"]["PolicySummary"]
        probe.identifiers[created["Id"]] = "p-final" + str(index + 1).zfill(4)
        probe.own("organizations", "delete-policy", {"PolicyId": created["Id"]},
                  {"service": "organizations", "action": "describe-policy", "input": {"PolicyId": created["Id"]}})
        policies.append(created)
    selected = policies[0]["Id"]
    broad_reads = allow(["organizations:Describe*", "organizations:List*"])
    resource_arns = ["arn:aws:organizations::" + probe.account + ":*", "arn:aws:organizations::aws:policy/*"]
    scope_iam = policy(allow("iam:GetOrganizationsAccessReport"),
                       allow("iam:GenerateOrganizationsAccessReport", "arn:aws:iam::" + probe.account + ":access-report/" + path,
                             Condition={"StringEquals": {"iam:OrganizationsPolicyId": selected}}), broad_reads)
    scoped_actions = [a for a in ORG_READS if a not in ("organizations:DescribeOrganization", "organizations:ListRoots")]
    profiles = [
        ("deny_describepolicy", policy(allow(IAM_REPORTS), broad_reads, {"Effect": "Deny", "Action": "organizations:DescribePolicy", "Resource": "*"})),
        ("scoped_org_reads", policy(allow(IAM_REPORTS), allow(["organizations:DescribeOrganization", "organizations:ListRoots"]), allow(scoped_actions, resource_arns))),
        ("scoped_describepolicy", policy(allow(IAM_REPORTS), allow([a for a in ORG_READS if a != "organizations:DescribePolicy"]), allow("organizations:DescribePolicy", resource_arns))),
        ("scoped_iam", scope_iam),
        ("iam_only_management", policy(allow(IAM_REPORTS))),
    ]
    observer = None
    for label, permissions in profiles:
        user = probe.user(label)
        probe.inline(user, permissions)
        env = probe.key(user, label)
        for attempt in range(10):
            if call("sts", "get-caller-identity", environment=env)["code"] == "Success":
                break
            time.sleep(1)
        if label.startswith("scoped_") and label != "scoped_iam":
            probe.observe(label + "_direct_describepolicy", "organizations", "describe-policy", {"PolicyId": selected}, env, label)
        modes = [("policy", path, selected), ("ou", path, None)]
        if label == "iam_only_management":
            modes = [("management", management, None)]
        for mode, target, pid in modes:
            job = probe.generate("final_permissions_" + label + "_" + mode + "_generate", target, pid, env, label)
            probe.wait_job("final_permissions_" + label + "_" + mode + "_get", job, env, label, MaxItems=1)
        if label == "scoped_iam":
            probe.generate("scoped_iam_wrong_policy", path, policies[1]["Id"], env, label)
            probe.generate("scoped_iam_wrong_path", management, selected, env, label)
        if label == "scoped_org_reads":
            observer = env

    # The controlled quota burst has at most one pending job before the next
    # attempt, and stops at the first rejection. All accepted jobs are drained.
    pending = probe.generate("quota_first_generate", path, policies[1]["Id"])
    first = probe.get("quota_first_state", pending, MaxItems=1)
    if first.get("output", {}).get("JobStatus") == "IN_PROGRESS":
        second = probe.generate("quota_second_generate", path, policies[2]["Id"])
        if second:
            probe.wait_job("quota_second_drain", second, MaxItems=1)
        else:
            probe.generate("quota_other_owner_generate", path, policies[2]["Id"], observer, "scoped_org_reads")
    probe.wait_job("quota_first_drain", pending, MaxItems=1)
    retry = probe.generate("quota_after_completion_generate", path, policies[2]["Id"])
    probe.wait_job("quota_after_completion_drain", retry, MaxItems=1)

    # Idle, small report: measure actual UUID equality at both sides of one
    # minute, without a competing outstanding report or a modeled timer.
    original = probe.generate("idle_cache_generate", path, selected)
    output = probe.wait_job("idle_cache_get", original, MaxItems=1)["output"]
    created = datetime.datetime.fromisoformat(output["JobCreationDate"]).timestamp()
    for age in (59, 61):
        remaining = created + age - time.time()
        if remaining > 0:
            time.sleep(remaining)
        current = probe.generate("idle_cache_age_" + str(age), path, selected)
        probe.wait_job("idle_cache_age_" + str(age) + "_get", current, MaxItems=1)
    managed = probe.generate("management_cache_selected", management, selected)
    probe.wait_job("management_cache_get", managed, MaxItems=1)
    probe.generate("management_cache_different_policy", management, policies[1]["Id"])
    omitted = probe.generate("management_cache_omitted_policy", management)
    probe.wait_job("management_cache_omitted_get", omitted, MaxItems=1)
    probe.limitations.append("The quota burst is bounded to two distinct owned SCP selectors and one other-owner attempt; accepted/rejected requests establish observed behavior, not a documented account quota.")


def run_target_dependencies(probe):
    probe.normalized_prefix = "stackd-org-access-targets"
    identity = call("sts", "get-caller-identity")["output"]
    probe.account = identity["Account"]
    probe.identifiers.update({identity["Arn"]: "<original-caller-arn>", identity["UserId"]: "<original-caller-id>"})
    org = call("organizations", "describe-organization")["output"]["Organization"]
    root = call("organizations", "list-roots")["output"]["Roots"][0]
    probe.identifiers.update({org["Id"]: "o-aaaaaaaaaa", root["Id"]: "r-abcd"})
    if org.get("ManagementAccountId", org.get("MasterAccountId")) != probe.account:
        raise RuntimeError("Target controls require management credentials")
    probe.eligibility = {"management_account": True, "feature_set": org["FeatureSet"], "root_policy_types": root["PolicyTypes"]}
    created = probe.require("organizations", "create-policy", {"Name": probe.prefix, "Description": "Temporary owned metadata-only report control", "Type": "SERVICE_CONTROL_POLICY", "Content": policy(allow("s3:GetObject"))})["Policy"]["PolicySummary"]
    pid = created["Id"]
    probe.identifiers[pid] = "p-target0001"
    probe.own("organizations", "delete-policy", {"PolicyId": pid}, {"service": "organizations", "action": "describe-policy", "input": {"PolicyId": pid}})
    root_path = org["Id"] + "/" + root["Id"]
    for label, action, path, selected in [("root_deny_listparents", "organizations:ListParents", root_path, None),
                                           ("management_deny_listtargets", "organizations:ListTargetsForPolicy", root_path + "/" + probe.account, pid)]:
        user = probe.user(label)
        probe.inline(user, policy(allow(IAM_REPORTS), allow(["organizations:Describe*", "organizations:List*"]),
                                  {"Effect": "Deny", "Action": action, "Resource": "*"}))
        env = probe.key(user, label)
        job = probe.generate("target_dependency_" + label + "_generate", path, selected, env, label)
        probe.wait_job("target_dependency_" + label + "_get", job, env, label, MaxItems=1)
    probe.limitations.append("Root and management target dependency controls retain only job status, errors and aggregate counts; all AccessDetails and markers are discarded before recording to exclude unrelated account activity.")


def merge_captures(inputs, output):
    values = [json.loads(path.read_text()) for path in inputs]
    if not all(value["capture_complete"] and value["cleanup_verified"] for value in values):
        raise RuntimeError("Only completed captures with verified cleanup can be merged")
    merged = values[0]
    for value in values[1:]:
        rows = value["observations"]
        if rows:
            rows[0]["state_changes_before"] = value["setup"] + rows[0].get("state_changes_before", [])
        merged["observations"].extend(rows)
        merged["cleanup"].extend(value["cleanup"])
        merged["limitations"].extend(value["limitations"])
        merged["finished_at"] = value["finished_at"]
        if "services" in value and "services" not in merged:
            merged["services"] = value["services"]
            merged["services_source_case"] = value["services_source_case"]
    names = [row["case"] for row in merged["observations"]]
    if len(names) != len(set(names)):
        raise RuntimeError("Capture case names overlap")
    merged["documentation"] = DOCS
    merged["limitations"] = list(dict.fromkeys(merged["limitations"]))
    service_projection(merged)
    encoded = json.dumps(merged, indent=2)
    encoded = re.sub(r"(?<=/authorization-details/)[a-zA-Z0-9_-]+", "<authorization-id>", encoded)
    encoded = re.sub(r"(?<=authorization id: )[a-zA-Z0-9_-]+", "<authorization-id>", encoded)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(encoded + "\n")
    temporary.replace(output)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DESTINATION)
    parser.add_argument("--phase", choices=("initial", "controls", "existing-controls", "final", "target-dependencies", "service-metadata"), default="initial")
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--merge", type=Path, nargs="+")
    parser.add_argument("--account")
    arguments = parser.parse_args()
    if arguments.merge:
        merge_captures(arguments.merge, arguments.output)
        return
    if not arguments.account:
        parser.error("--account is required for native capture")
    require_account(arguments.account)
    if arguments.phase == "existing-controls" and arguments.journal is None:
        parser.error("--phase existing-controls requires --journal")
    probe = Probe(arguments.output)
    try:
        if arguments.phase == "existing-controls":
            run_existing_controls(probe, arguments.journal)
        elif arguments.phase == "final":
            run_final(probe)
        elif arguments.phase == "target-dependencies":
            run_target_dependencies(probe)
        elif arguments.phase == "service-metadata":
            service_metadata(probe)
        else:
            (run_controls if arguments.phase == "controls" else run)(probe)
        probe.complete = True
    finally:
        probe.finish()


if __name__ == "__main__":
    main()
