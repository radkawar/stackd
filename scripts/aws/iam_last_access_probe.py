#!/usr/bin/env python3
"""Capture IAM last-access behavior using only uniquely owned IAM resources.

Requires AWS CLI credentials authorized for owned IAM resources and STS role
assumption. Activity publication can take four hours; this probe never waits
that long. It retains no secrets, unrelated entity details, or debug logs.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import urllib.parse
import xml.etree.ElementTree as ET

from aws_cli import run as run_cli, result as cli_result
from signed_requests import signed_post

ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / '.stackd/probes/iam/last_access.json'
DOCUMENTATION = [
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateServiceLastAccessedDetails.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetServiceLastAccessedDetails.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetServiceLastAccessedDetailsWithEntities.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPoliciesGrantingServiceAccess.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html",
]

REPORT_ACTIONS = ["iam:GenerateServiceLastAccessedDetails", "iam:GetServiceLastAccessedDetails",
                  "iam:GetServiceLastAccessedDetailsWithEntities", "iam:ListPoliciesGrantingServiceAccess"]


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)}, separators=(",", ":"))


def allow(actions, resource="*", **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}


def operation(action):
    return "".join(part.upper() if part == "mfa" else part.title() for part in action.split("-"))


def call(action, parameters=None, environment=None, service="iam", region="us-east-1", endpoint=None):
    if service == "iam-query":
        return raw_query(action, parameters or {}, environment)
    endpoint = endpoint or ("https://iam.amazonaws.com" if service == "iam" else "https://sts." + region + ".amazonaws.com")
    process = run_cli(service, action, parameters or {}, environment, timeout=60,
                      options=["--endpoint-url", endpoint, "--region", region, "--no-paginate", "--debug"])
    result = cli_result(process, cli_message="AWS CLI rejected request; diagnostics discarded", debug=True)
    if result["code"] == "CLIError" and service == "iam":
        return raw_query(action, parameters or {}, environment)
    return result


def raw_query(action, parameters, environment=None, service="iam"):
    """Bypass only CLI parameter validation; authenticate normal IAM/STS Query calls."""
    fields = {"Action": operation(action), "Version": "2010-05-08" if service == "iam" else "2011-06-15"}
    endpoint = "iam.amazonaws.com" if service == "iam" else "sts.us-east-1.amazonaws.com"
    def encode(key, value):
        if isinstance(value, list):
            for index, item in enumerate(value, 1):
                encode(key + ".member." + str(index), item)
        elif isinstance(value, dict):
            for name, item in value.items():
                encode(key + "." + name, item)
        else:
            fields[key] = str(value).lower() if isinstance(value, bool) else str(value)
    for key, value in parameters.items():
        encode(key, value)
    body = urllib.parse.urlencode(fields).encode()
    response = signed_post(endpoint, service, body,
                           {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}, environment)
    xml = ET.fromstring(response.body)
    for element in xml.iter():
        element.tag = element.tag.rsplit("}", 1)[-1]
    error = xml.find("Error")
    if error is not None:
        return {"code": error.findtext("Code"), "message": error.findtext("Message"), "http_status": response.status, "transport": "signed_query"}
    def decode(element):
        children = list(element)
        if children and all(child.tag == "member" for child in children):
            return [decode(child) for child in children]
        if children:
            return {child.tag: decode(child) for child in children}
        text = element.text or ""
        if element.tag in ("PoliciesGrantingServiceAccess", "ServicesLastAccessed", "EntityDetailsList", "Policies", "TrackedActionsLastAccessed"):
            return []
        if text in ("true", "false"):
            return text == "true"
        if element.tag in ("TotalAuthenticatedEntities",):
            return int(text)
        return text
    result = xml.find(operation(action) + "Result")
    return {"code": "Success", "output": decode(result) if result is not None else {}, "http_status": response.status, "transport": "signed_query"}


class Probe:
    def __init__(self):
        self.prefix = "stackd-last-access-" + uuid.uuid4().hex[:10]
        self.started = stamp()
        self.account = ""
        self.identifiers = {}
        self.observations, self.setup, self.changes, self.cleanup, self.owned = [], [], [], [], []
        self.jobs, self.markers = {}, {}
        self.complete = False
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")
        self.cli_version = subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.strip()
        self.limitations = [
            "AWS documents recent activity publication usually within four hours; this run polls report jobs for at most 60 seconds and does not wait for that publication window.",
            "No account-wide policies, SCPs, root settings, or unrelated entities are inspected or modified.",
            "Session expiration is not accelerated on AWS; distinct live role sessions test job ownership, not elapsed credential expiration.",
        ]

    def normalize(self, value):
        if isinstance(value, dict):
            return {key: self.normalize(item) for key, item in value.items()
                    if key not in ("SecretAccessKey", "SessionToken", "Credentials")}
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            for actual, replacement in sorted(self.identifiers.items(), key=lambda item: -len(item[0])):
                value = value.replace(actual, replacement)
            value = value.replace(self.prefix, "stackd-last-access-fixture")
            if self.account:
                value = value.replace(self.account, "123456789012")
        return value

    def write(self, cleanup_verified=False):
        fixture = {"schema_version": 1, "source": "Real AWS IAM API through AWS CLI; commercial partition",
                   "api_version": "2010-05-08", "endpoint": "https://iam.amazonaws.com", "region": "us-east-1",
                   "aws_cli_version": self.cli_version, "probe": "scripts/aws/iam_last_access_probe.py",
                   "started_at": self.started, "finished_at": stamp(), "documentation": DOCUMENTATION,
                   "sanitization": "Only reports for owned entities retained. Account, owned names and entity IDs normalized; job IDs and markers retain causal case references. Credential secrets, debug logs and unrelated entity details discarded.",
                   "setup": self.normalize(self.setup), "observations": self.observations,
                   "capture_complete": self.complete, "cleanup_verified": cleanup_verified,
                   "cleanup": self.normalize(self.cleanup), "limitations": self.limitations}
        if hasattr(self, "service_names"):
            fixture["services"] = self.service_names
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        temporary = DESTINATION.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(fixture, indent=2) + "\n")
        temporary.replace(DESTINATION)

    def own(self, delete_action, delete_input, verify=None):
        self.owned.append({"action": delete_action, "input": delete_input, "verify": verify})
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self.journal.write_text(json.dumps({"prefix": self.prefix, "owned": self.owned}, indent=2) + "\n")

    def require(self, action, parameters, environment=None, service="iam", record=True):
        result = call(action, parameters, environment, service)
        if action == "create-role":
            for _ in range(10):
                if result["code"] != "MalformedPolicyDocument" or "Invalid principal" not in result.get("message", ""):
                    break
                time.sleep(2)
                result = call(action, parameters, environment, service)
        if result["code"] != "Success":
            raise RuntimeError(self.normalize(action + ": " + result["code"] + ": " + result.get("message", "")))
        if record:
            item = {"operation": operation(action), "input": parameters, "output": result["output"]}
            if not self.observations:
                self.setup.append(item)
            else:
                self.changes.append(item)
        return result["output"]

    def observe(self, case, action, parameters, environment=None, credential="original", service="iam"):
        result = call(action, parameters, environment, service)
        row = {"case": case, "operation": operation(action), "input": parameters, "credential": credential,
               "observed_at": stamp(), **result}
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
                self.jobs[output["JobId"]] = case
                self.identifiers[output["JobId"]] = "<job:" + case + ">"
            if "Marker" in output:
                self.markers[output["Marker"]] = case
                self.identifiers[output["Marker"]] = "<marker:" + case + ">"
        self.observations.append(self.normalize(row))
        self.write()
        output = result.get("output", {})
        print(case, result["code"], output.get("JobStatus", ""),
              "services=" + str(len(output.get("ServicesLastAccessed", []))) if "ServicesLastAccessed" in output else "", flush=True)
        return result

    def generate(self, case, arn, granularity=None, environment=None, credential="original"):
        parameters = {"Arn": arn}
        if granularity is not None:
            parameters["Granularity"] = granularity
        result = self.observe(case, "generate-service-last-accessed-details", parameters, environment, credential)
        return result.get("output", {}).get("JobId")

    def wait_job(self, case, job, environment=None, credential="original"):
        if not job:
            return None
        deadline = time.monotonic() + 60
        index = 0
        while True:
            result = self.observe(case + ("_first" if index == 0 else "_poll_" + str(index)),
                                  "get-service-last-accessed-details", {"JobId": job}, environment, credential)
            if result.get("output", {}).get("JobStatus") != "IN_PROGRESS" or time.monotonic() >= deadline:
                return result
            time.sleep(1)
            index += 1

    def user(self, suffix):
        name = self.prefix + "-" + suffix
        params = {"UserName": name, "Path": "/stackd-last-access/"}
        value = self.require("create-user", params)["User"]
        self.identifiers[value["UserId"]] = "<user-id:" + suffix + ">"
        self.own("delete-user", {"UserName": name}, {"action": "get-user", "input": {"UserName": name}})
        return value

    def inline(self, kind, name, label, document):
        params = {kind.title() + "Name": name, "PolicyName": label, "PolicyDocument": document}
        self.require("put-" + kind + "-policy", params)
        delete = {kind.title() + "Name": name, "PolicyName": label}
        if not any(item["action"] == "delete-" + kind + "-policy" and item["input"] == delete for item in self.owned):
            self.own("delete-" + kind + "-policy", delete)

    def key(self, user, label):
        value = self.require("create-access-key", {"UserName": user["UserName"]})["AccessKey"]
        self.identifiers[value["AccessKeyId"]] = "<access-key:" + label + ">"
        self.own("delete-access-key", {"UserName": user["UserName"], "AccessKeyId": value["AccessKeyId"]})
        environment = os.environ.copy()
        environment.update(AWS_ACCESS_KEY_ID=value["AccessKeyId"], AWS_SECRET_ACCESS_KEY=value["SecretAccessKey"], AWS_EC2_METADATA_DISABLED="true")
        environment.pop("AWS_SESSION_TOKEN", None)
        environment.pop("AWS_PROFILE", None)
        return environment

    def finish(self):
        failures = []
        for owned in reversed(self.owned):
            try:
                result = call(owned["action"], owned["input"])
            except RuntimeError:
                result = {"code": "CLITransportFailure"}
            self.cleanup.append({"operation": operation(owned["action"]), "input": owned["input"], "code": result["code"]})
            if result["code"] not in ("Success", "NoSuchEntity"):
                failures.append(owned)
        for owned in self.owned:
            verify = owned.get("verify")
            if verify:
                result = call(verify["action"], verify["input"])
                self.cleanup.append({"operation": operation(verify["action"]), "input": verify["input"], "code": result["code"]})
                if result["code"] != "NoSuchEntity":
                    failures.append(owned)
        self.write(not failures)
        if failures:
            raise RuntimeError("Owned-resource cleanup incomplete; recovery journal: " + str(self.journal))
        self.journal.unlink(missing_ok=True)
        print("cleanup_verified", len(self.owned), flush=True)


def run(probe):
    identity = probe.require("get-caller-identity", {}, service="sts", record=False)
    probe.account = identity["Account"]
    probe.identifiers[identity["Arn"]] = "<original-caller-arn>"
    probe.identifiers[identity["UserId"]] = "<original-caller-id>"
    target, member, empty, observer = [probe.user(name) for name in ("target", "member", "empty", "observer")]
    groups = []
    for suffix in ("zgroup", "agroup"):
        name = probe.prefix + "-" + suffix
        group = probe.require("create-group", {"GroupName": name, "Path": "/stackd-last-access/"})["Group"]
        probe.identifiers[group["GroupId"]] = "<group-id:" + suffix + ">"
        probe.own("delete-group", {"GroupName": name}, {"action": "get-group", "input": {"GroupName": name}})
        groups.append(group)
    role_name = probe.prefix + "-role"
    trust = policy({"Effect": "Allow", "Principal": {"AWS": observer["Arn"]}, "Action": "sts:AssumeRole"})
    role = probe.require("create-role", {"RoleName": role_name, "Path": "/stackd-last-access/", "AssumeRolePolicyDocument": trust})["Role"]
    probe.identifiers[role["RoleId"]] = "<role-id:role>"
    probe.own("delete-role", {"RoleName": role_name}, {"action": "get-role", "input": {"RoleName": role_name}})
    policies = []
    for suffix, document in (("shared", policy(allow(["sqs:SendMessage", "s3:GetObject"]))),
                             ("unused", policy(allow("sns:Publish"))),
                             ("boundary", policy(allow("dynamodb:ListTables")))):
        value = probe.require("create-policy", {"PolicyName": probe.prefix + "-" + suffix,
                                                "Path": "/stackd-last-access/", "PolicyDocument": document})["Policy"]
        probe.identifiers[value["PolicyId"]] = "<policy-id:" + suffix + ">"
        probe.own("delete-policy", {"PolicyArn": value["Arn"]}, {"action": "get-policy", "input": {"PolicyArn": value["Arn"]}})
        policies.append(value)
    probe.inline("user", target["UserName"], "z-direct", policy(allow(["s3:GetObject", "iam:GetUser", "iam:PassRole", "ec2:DescribeInstances"]),
                                                                {"Effect": "Deny", "Action": "sqs:*", "Resource": "*"}))
    probe.inline("group", groups[0]["GroupName"], "a-group", policy(allow("lambda:ListFunctions")))
    probe.inline("group", groups[1]["GroupName"], "z-group", policy(allow("iam:GetUser")))
    probe.inline("role", role_name, "role-inline", policy(allow("kms:ListKeys"), allow(REPORT_ACTIONS)))
    probe.inline("user", observer["UserName"], "observer", policy(allow(REPORT_ACTIONS), allow("sts:AssumeRole", role["Arn"])))
    for group, users in ((groups[0], [target, member]), (groups[1], [target])):
        for user in users:
            parameters = {"GroupName": group["GroupName"], "UserName": user["UserName"]}
            probe.require("add-user-to-group", parameters)
            probe.own("remove-user-from-group", parameters)
    for kind, name in (("user", target["UserName"]), ("group", groups[0]["GroupName"]), ("role", role_name)):
        parameters = {kind.title() + "Name": name, "PolicyArn": policies[0]["Arn"]}
        probe.require("attach-" + kind + "-policy", parameters)
        probe.own("detach-" + kind + "-policy", parameters)
    observer_key = probe.key(observer, "observer-one")
    observer_key_two = probe.key(observer, "observer-two")
    target_key = probe.key(target, "target")
    member_key = probe.key(member, "member")
    report_permission = policy(allow(REPORT_ACTIONS))
    probe.inline("user", member["UserName"], "report-permissions", report_permission)
    # Setup is complete before the first report; all subsequent mutations retain
    # their causal place in state_changes_before on the following observation.
    jobs = {}
    for label, arn, granularity in (("empty", empty["Arn"], None), ("user", target["Arn"], None),
                                     ("user_action", target["Arn"], "ACTION_LEVEL"), ("group", groups[0]["Arn"], None),
                                     ("group_action", groups[0]["Arn"], "ACTION_LEVEL"), ("role", role["Arn"], "ACTION_LEVEL"),
                                     ("policy", policies[0]["Arn"], "ACTION_LEVEL"), ("unused_policy", policies[1]["Arn"], None)):
        jobs[label] = probe.generate("generate_" + label, arn, granularity)
    for label, job in jobs.items():
        probe.wait_job("get_" + label, job)
    selection(probe, empty)
    for label in ("empty", "user", "group", "role", "policy", "unused_policy"):
        for namespace in ("s3", "iam", "stackdunmodeled"):
            probe.observe("entities_" + label + "_" + namespace, "get-service-last-accessed-details-with-entities",
                          {"JobId": jobs[label], "ServiceNamespace": namespace})
    grant_input = {"Arn": target["Arn"], "ServiceNamespaces": ["sqs", "s3", "iam", "lambda", "ec2", "dynamodb"]}
    probe.observe("grants_user_graph", "list-policies-granting-service-access", grant_input)
    for label, arn in (("group", groups[0]["Arn"]), ("role", role["Arn"]), ("empty", empty["Arn"]), ("policy_invalid", policies[0]["Arn"])):
        probe.observe("grants_" + label, "list-policies-granting-service-access", {**grant_input, "Arn": arn})
    probe.require("put-user-permissions-boundary", {"UserName": target["UserName"], "PermissionsBoundary": policies[2]["Arn"]})
    probe.own("delete-user-permissions-boundary", {"UserName": target["UserName"]})
    probe.observe("grants_boundary_ignored", "list-policies-granting-service-access", grant_input)
    boundary_job = probe.generate("generate_user_boundary", target["Arn"])
    probe.wait_job("get_user_boundary", boundary_job)
    # The boundary is removed before tiny owned-user activity or session probes.
    probe.require("delete-user-permissions-boundary", {"UserName": target["UserName"]})
    for label, namespaces in (("reverse", ["iam", "s3", "sqs"]), ("duplicate", ["s3", "s3", "iam"]),
                               ("unknown", ["stackdunmodeled"]), ("uppercase", ["S3", "IAM"]),
                               ("action_suffix", ["s3:GetObject"]), ("empty", []), ("empty_string", [""]),
                               ("hyphen", ["execute-api"]), ("underscore", ["stackd_unknown"]),
                               ("too_long", ["x" * 65]), ("too_many", ["s3"] * 201)):
        probe.observe("grants_namespaces_" + label, "list-policies-granting-service-access", {"Arn": target["Arn"], "ServiceNamespaces": namespaces})
    for label, arn in (("wrong_path", target["Arn"].replace("/stackd-last-access/", "/other/")),
                       ("pathless", target["Arn"].replace("/stackd-last-access/", "/")),
                       ("missing", target["Arn"] + "-missing"), ("cross_account", target["Arn"].replace(probe.account, "999999999999")),
                       ("root", "arn:aws:iam::" + probe.account + ":root"), ("bad_service", target["Arn"].replace(":iam:", ":s3:")),
                       ("bad_partition", target["Arn"].replace("arn:aws:", "arn:aws-cn:")), ("short", "bad")):
        probe.observe("grants_arn_" + label, "list-policies-granting-service-access", {**grant_input, "Arn": arn})
        generated = probe.generate("generate_arn_" + label, arn)
        if label != "root":
            probe.wait_job("get_arn_" + label, generated)
    for value in ("", "service_level", "INVALID"):
        probe.generate("generate_granularity_" + (value or "empty"), target["Arn"], value)
    for label, params in (("unknown_job", {"JobId": "00000000-0000-0000-0000-000000000000"}),
                           ("short_job", {"JobId": "bad"}), ("non_uuid", {"JobId": "x" * 36}),
                           ("max_zero", {"JobId": jobs["user"], "MaxItems": 0}),
                           ("max_large", {"JobId": jobs["user"], "MaxItems": 1001}),
                           ("invalid_marker", {"JobId": jobs["user"], "Marker": "invalid"})):
        probe.observe("get_validation_" + label, "get-service-last-accessed-details", params)
        probe.observe("entities_validation_" + label, "get-service-last-accessed-details-with-entities", {**params, "ServiceNamespace": "s3"})
    probe.observe("grants_invalid_marker", "list-policies-granting-service-access", {**grant_input, "Marker": "invalid"})
    for namespace in ("S3", "s3:GetObject", "", "x" * 65):
        probe.observe("entities_namespace_" + (namespace[:12] or "empty"), "get-service-last-accessed-details-with-entities",
                      {"JobId": jobs["user"], "ServiceNamespace": namespace})
    pagination(probe, jobs)
    ownership(probe, observer, observer_key, observer_key_two, member_key, role, target, target_key, jobs)
    # Existing completed reports should remain immutable across source mutation.
    probe.inline("user", target["UserName"], "after-report", policy(allow("sns:Publish")))
    probe.observe("old_job_after_new_permission", "get-service-last-accessed-details", {"JobId": jobs["user"]})
    new_job = probe.generate("generate_after_new_permission", target["Arn"])
    probe.wait_job("get_after_new_permission", new_job)


def pagination(probe, jobs):
    result = probe.observe("page_services_first", "get-service-last-accessed-details", {"JobId": jobs["user"], "MaxItems": 1})
    marker = result.get("output", {}).get("Marker")
    if marker:
        for label, job, maximum in (("next", jobs["user"], 1), ("larger", jobs["user"], 2), ("different_job", jobs["role"], 1)):
            probe.observe("page_services_" + label, "get-service-last-accessed-details", {"JobId": job, "MaxItems": maximum, "Marker": marker})
        probe.observe("page_services_marker_in_entities", "get-service-last-accessed-details-with-entities", {"JobId": jobs["user"], "ServiceNamespace": "s3", "Marker": marker})
    result = probe.observe("page_entities_first", "get-service-last-accessed-details-with-entities", {"JobId": jobs["policy"], "ServiceNamespace": "s3", "MaxItems": 1})
    marker = result.get("output", {}).get("Marker")
    if marker:
        for label, job, namespace in (("next", jobs["policy"], "s3"), ("different_service", jobs["policy"], "sqs"), ("different_job", jobs["group"], "s3")):
            probe.observe("page_entities_" + label, "get-service-last-accessed-details-with-entities", {"JobId": job, "ServiceNamespace": namespace, "MaxItems": 1, "Marker": marker})


def selection(probe, user):
    samples = [
        ("allow", policy(allow("s3:GetObject"))),
        ("deny_only", policy({"Effect": "Deny", "Action": "s3:*", "Resource": "*"})),
        ("allow_and_deny", policy(allow("s3:GetObject"), {"Effect": "Deny", "Action": "s3:*", "Resource": "*"})),
        ("condition_missing", policy(allow("s3:GetObject", Condition={"StringEquals": {"aws:username": "nobody"}}))),
        ("impossible_resource", policy(allow("s3:GetObject", "arn:aws:iam::123456789012:user/nobody"))),
        ("unknown_action", policy(allow("s3:StackdUnmodeledAction"))),
        ("unknown_service", policy(allow("stackdunmodeled:Read"))),
        ("service_wildcard", policy(allow("s*:Get*"))),
        ("action_wildcard", policy(allow("s3:Get*"))),
        ("uppercase_action", policy(allow("S3:GETOBJECT"))),
        ("not_action", policy({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"})),
        ("not_resource", policy({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "*"})),
        ("passrole_only", policy(allow("iam:PassRole"))),
    ]
    for label, document in samples:
        # IAM policy validation itself may reject unknown service wildcards; that
        # response remains an API observation rather than an invented report.
        write = probe.observe("selection_put_" + label, "put-user-policy", {"UserName": user["UserName"], "PolicyName": "selection", "PolicyDocument": document})
        if write["code"] != "Success":
            continue
        delete = {"UserName": user["UserName"], "PolicyName": "selection"}
        if not any(item["action"] == "delete-user-policy" and item["input"] == delete for item in probe.owned):
            probe.own("delete-user-policy", delete)
        probe.observe("selection_" + label, "list-policies-granting-service-access", {"Arn": user["Arn"], "ServiceNamespaces": ["s3", "sqs", "iam"]})
        if label in ("deny_only", "allow_and_deny", "condition_missing", "unknown_action", "passrole_only"):
            job = probe.generate("generate_selection_" + label, user["Arn"], "ACTION_LEVEL")
            probe.wait_job("get_selection_" + label, job)
    probe.inline("user", user["UserName"], "selection", policy(allow("s3:GetObject")))
    probe.inline("user", user["UserName"], "separate-deny", policy({"Effect": "Deny", "Action": "s3:*", "Resource": "*"}))
    probe.observe("selection_cross_policy_deny", "list-policies-granting-service-access", {"Arn": user["Arn"], "ServiceNamespaces": ["s3"]})


def ownership(probe, observer, key_one, key_two, member_key, role, target, target_key, jobs):
    job = probe.generate("generate_observer_user", target["Arn"], environment=key_one, credential="observer_key_one")
    if job:
        probe.wait_job("get_observer_user", job, key_one, "observer_key_one")
        for label, environment in (("same_user_other_key", key_two), ("different_user", member_key), ("original_caller", None)):
            probe.observe("ownership_" + label, "get-service-last-accessed-details", {"JobId": job}, environment, label)
            probe.observe("ownership_entities_" + label, "get-service-last-accessed-details-with-entities", {"JobId": job, "ServiceNamespace": "s3"}, environment, label)
    role_sessions = []
    for name in ("one", "two"):
        params = {"RoleArn": role["Arn"], "RoleSessionName": "last-access-" + name, "DurationSeconds": 900}
        response = call("assume-role", params, key_one, service="sts")
        if response["code"] != "Success":
            probe.observations.append(probe.normalize({"case": "assume_role_" + name, "operation": "AssumeRole", "input": params, **response}))
            continue
        credentials = response["output"]["Credentials"]
        probe.identifiers[credentials["AccessKeyId"]] = "<role-access-key:" + name + ">"
        environment = os.environ.copy()
        environment.update(AWS_ACCESS_KEY_ID=credentials["AccessKeyId"], AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
                           AWS_SESSION_TOKEN=credentials["SessionToken"], AWS_EC2_METADATA_DISABLED="true")
        environment.pop("AWS_PROFILE", None)
        role_sessions.append(environment)
        probe.observations.append(probe.normalize({"case": "assume_role_" + name, "operation": "AssumeRole", "input": params,
                                                  "code": "Success", "credential": "observer_key_one",
                                                  "expiration": credentials["Expiration"]}))
    if len(role_sessions) == 2:
        role_job = probe.generate("generate_role_session", target["Arn"], environment=role_sessions[0], credential="role_session_one")
        if role_job:
            probe.wait_job("get_role_session", role_job, role_sessions[0], "role_session_one")
            probe.observe("ownership_same_role_other_session", "get-service-last-accessed-details", {"JobId": role_job}, role_sessions[1], "role_session_two")
            probe.observe("ownership_entities_same_role_other_session", "get-service-last-accessed-details-with-entities", {"JobId": role_job, "ServiceNamespace": "s3"}, role_sessions[1], "role_session_two")
    probe.observe("activity_owned_user_get_user", "get-user", {"UserName": target["UserName"]}, target_key, "target_key")
    probe.observe("activity_owned_user_denied_list_policies", "list-user-policies", {"UserName": target["UserName"]}, target_key, "target_key")
    refreshed = probe.generate("generate_after_owned_activity", target["Arn"], "ACTION_LEVEL")
    probe.wait_job("get_after_owned_activity", refreshed)
    # Revocation checks the permission gate independently of job ownership.
    probe.inline("user", observer["UserName"], "observer", policy(allow("sts:AssumeRole", role["Arn"])))
    if job:
        probe.observe("ownership_permissions_revoked", "get-service-last-accessed-details", {"JobId": job}, key_one, "observer_key_one")


def followup(probe):
    user = probe.user("followup")
    arn = user["Arn"]
    resource_a = "arn:aws:s3:::" + probe.prefix + "-a/*"
    resource_b = "arn:aws:s3:::" + probe.prefix + "-b/*"
    deny = lambda resource="*", **extra: {"Effect": "Deny", "Action": "s3:*", "Resource": resource, **extra}
    cases = [
        ("conditional_deny", policy(allow("s3:GetObject"), deny(Condition={"StringEquals": {"aws:username": "nobody"}}))),
        ("bucket_resource", policy(allow("s3:GetObject", resource_a.removesuffix("/*")))),
        ("deny_disjoint", policy(allow("s3:GetObject", resource_a), deny(resource_b))),
        ("deny_same", policy(allow("s3:GetObject", resource_a), deny(resource_a))),
        ("deny_partial", policy(allow("s3:*"), deny(resource_a))),
        ("allow_notresource_same", policy(allow("s3:GetObject", resource_a), {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": resource_a})),
        ("deny_notresource_same", policy(allow("s3:GetObject", resource_a), {"Effect": "Deny", "Action": "s3:GetObject", "NotResource": resource_a})),
        ("deny_notresource_disjoint", policy(allow("s3:GetObject", resource_a), {"Effect": "Deny", "Action": "s3:GetObject", "NotResource": resource_b})),
    ]
    for label, document in cases:
        probe.inline("user", user["UserName"], "followup", document)
        probe.observe("resource_selection_" + label, "list-policies-granting-service-access", {"Arn": arn, "ServiceNamespaces": ["s3"]})
    for label, parameters in (("empty_list", {"Arn": arn, "ServiceNamespaces": []}),
                              ("empty_namespace", {"Arn": arn, "ServiceNamespaces": [""]}),
                              ("short_arn", {"Arn": "bad", "ServiceNamespaces": ["s3"]})):
        probe.observe("raw_grants_" + label, "list-policies-granting-service-access", parameters)
    probe.inline("user", user["UserName"], "followup", policy(allow("s3:GetObject")))
    job = probe.generate("generate_followup", arn)
    for label, parameters in (("short_job", {"JobId": "bad"}), ("max_zero", {"JobId": job, "MaxItems": 0}),
                              ("empty_marker", {"JobId": job, "Marker": ""})):
        probe.observe("raw_get_" + label, "get-service-last-accessed-details", parameters)
        probe.observe("raw_entities_" + label, "get-service-last-accessed-details-with-entities", {**parameters, "ServiceNamespace": "s3"})
    probe.observe("raw_entities_empty_namespace", "get-service-last-accessed-details-with-entities", {"JobId": job, "ServiceNamespace": ""})
    probe.wait_job("get_followup", job)
    # Completed service results stay frozen if the source changes or disappears.
    # WithEntities separately resolves current identity metadata and existence. Record pending status without assuming the AWS
    # worker cannot run between two requests.
    pending = probe.generate("generate_before_source_mutation", arn, "ACTION_LEVEL")
    probe.observe("pending_before_source_mutation", "get-service-last-accessed-details", {"JobId": pending})
    probe.inline("user", user["UserName"], "followup", policy(allow("sns:Publish")))
    probe.wait_job("get_after_pending_source_mutation", pending)
    probe.observe("get_old_after_source_mutation", "get-service-last-accessed-details", {"JobId": job})
    # ListPolicies has no MaxItems. A 200-namespace request establishes whether
    # the service truncates namespace rows under that modeled limit.
    with urllib.request.urlopen("https://servicereference.us-east-1.amazonaws.com/", timeout=30) as response:
        namespaces = [item["service"] for item in json.load(response)][:200]
    for attempt in range(4):
        result = probe.observe("grants_many_namespaces_" + str(attempt), "list-policies-granting-service-access", {"Arn": arn, "ServiceNamespaces": namespaces})
        if result["code"] == "Success":
            marker = result.get("output", {}).get("Marker")
            if marker:
                probe.observe("grants_many_namespaces_next", "list-policies-granting-service-access", {"Arn": arn, "ServiceNamespaces": namespaces, "Marker": marker})
            break
        match = re.search(r"Invalid service namespace: \[(.*)\]", result.get("message", ""))
        if not match:
            break
        invalid = {item.strip() for item in match[1].split(",")}
        namespaces = [item for item in namespaces if item not in invalid]
    reporter = probe.user("followup-reporter")
    probe.inline("user", reporter["UserName"], "reporter", policy(allow(REPORT_ACTIONS)))
    credentials = probe.key(reporter, "followup-reporter")
    # Retry an initial credential/permission propagation delay without treating
    # it as a lasting API authorization contract.
    owned_job = None
    for attempt in range(6):
        owned_job = probe.generate("generate_followup_reporter_" + str(attempt), arn, environment=credentials, credential="followup_reporter")
        if owned_job:
            break
        time.sleep(2)
    if owned_job:
        probe.wait_job("get_followup_reporter", owned_job, credentials, "followup_reporter")
        probe.inline("user", reporter["UserName"], "reporter", policy({"Effect": "Deny", "Action": REPORT_ACTIONS, "Resource": "*"}))
        for attempt in range(10):
            result = probe.observe("revoked_reporter_" + str(attempt), "get-service-last-accessed-details", {"JobId": owned_job}, credentials, "followup_reporter")
            if result["code"] == "AccessDenied":
                break
            time.sleep(2)
    probe.require("delete-user-policy", {"UserName": user["UserName"], "PolicyName": "followup"})
    probe.require("delete-user", {"UserName": user["UserName"]})
    probe.observe("get_completed_after_source_deleted", "get-service-last-accessed-details", {"JobId": job})
    probe.observe("entities_completed_after_source_deleted", "get-service-last-accessed-details-with-entities", {"JobId": job, "ServiceNamespace": "s3"})
    probe.generate("generate_deleted_source", arn)


def selection_edges(probe):
    user = probe.user("deny-edges")
    resource = "arn:aws:s3:::" + probe.prefix + "-a/*"
    cases = [
        ("resource_exact", policy(allow("s3:GetObject", resource), {"Effect": "Deny", "Action": "s3:*", "Resource": resource})),
        ("resource_namespace", policy(allow("s3:GetObject", resource), {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::*"})),
        ("resource_all", policy(allow("s3:GetObject", resource), {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"})),
        ("conditional_deny_ifexists", policy(allow("s3:GetObject"), {"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"StringEqualsIfExists": {"aws:username": "nobody"}}})),
        ("conditional_deny_null", policy(allow("s3:GetObject"), {"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"Null": {"aws:username": "true"}}})),
        ("conditional_allow_and_deny", policy(allow("s3:GetObject", Condition={"StringEquals": {"aws:username": "nobody"}}), {"Effect": "Deny", "Action": "s3:*", "Resource": "*"})),
    ]
    for label, document in cases:
        probe.inline("user", user["UserName"], "deny-edges", document)
        probe.observe("deny_edges_" + label, "list-policies-granting-service-access", {"Arn": user["Arn"], "ServiceNamespaces": ["s3"]})
        if label == "resource_exact":
            probe.observe("deny_edges_current_document", "get-user-policy", {"UserName": user["UserName"], "PolicyName": "deny-edges"})
            time.sleep(5)
            probe.observe("deny_edges_resource_exact_settled", "list-policies-granting-service-access", {"Arn": user["Arn"], "ServiceNamespaces": ["s3"]})
            job = probe.generate("generate_deny_edges_exact", user["Arn"])
            probe.wait_job("get_deny_edges_exact", job)


def pending_snapshot(probe):
    user = probe.user("pending")
    probe.inline("user", user["UserName"], "pending", policy(allow("s3:GetObject")))
    created = probe.observe("pending_query_generate", "generate-service-last-accessed-details", {"Arn": user["Arn"], "Granularity": "ACTION_LEVEL"}, service="iam-query")
    if created["code"] != "Success":
        return
    job = created["output"]["JobId"]
    probe.observe("pending_query_before_mutation", "get-service-last-accessed-details-with-entities", {"JobId": job, "ServiceNamespace": "s3"}, service="iam-query")
    probe.observe("pending_query_mutate", "put-user-policy", {"UserName": user["UserName"], "PolicyName": "pending", "PolicyDocument": policy(allow("sns:Publish"))}, service="iam-query")
    probe.observe("pending_query_after_mutation", "get-service-last-accessed-details", {"JobId": job}, service="iam-query")
    probe.wait_job("pending_query_completed", job)


def service_names(probe):
    value = probe.require("create-policy", {"PolicyName": probe.prefix + "-names", "Path": "/stackd-last-access/", "PolicyDocument": policy(allow("*"))})["Policy"]
    probe.identifiers[value["PolicyId"]] = "<policy-id:service-names>"
    probe.own("delete-policy", {"PolicyArn": value["Arn"]}, {"action": "get-policy", "input": {"PolicyArn": value["Arn"]}})
    job = probe.generate("generate_service_names", value["Arn"])
    deadline = time.monotonic() + 60
    page, names, marker = 0, [], None
    while True:
        parameters = {"JobId": job, "MaxItems": 1000}
        if marker:
            parameters["Marker"] = marker
        result = probe.observe("get_service_names_" + str(page), "get-service-last-accessed-details", parameters)
        output = result.get("output", {})
        if result["code"] != "Success" or output.get("JobStatus") == "FAILED":
            raise RuntimeError("Unable to capture service display names")
        if output.get("JobStatus") == "IN_PROGRESS":
            if time.monotonic() >= deadline:
                raise RuntimeError("Service name report did not complete within bounded polling interval")
            time.sleep(1)
            page += 1
            continue
        for item in output.get("ServicesLastAccessed", []):
            if item.get("TotalAuthenticatedEntities", 0) or "LastAuthenticated" in item:
                raise RuntimeError("Unexpected activity in report for newly created unattached owned policy")
            names.append({"namespace": item["ServiceNamespace"], "name": item["ServiceName"]})
        marker = output.get("Marker") if output.get("IsTruncated") else None
        if not marker:
            break
        page += 1
    probe.service_names = names


def pending_policy_snapshot(probe):
    value = probe.require("create-policy", {"PolicyName": probe.prefix + "-pending-policy", "Path": "/stackd-last-access/", "PolicyDocument": policy(allow("*"))})["Policy"]
    probe.identifiers[value["PolicyId"]] = "<policy-id:pending-policy>"
    probe.own("delete-policy", {"PolicyArn": value["Arn"]}, {"action": "get-policy", "input": {"PolicyArn": value["Arn"]}})
    job = probe.generate("pending_policy_generate", value["Arn"])
    probe.observe("pending_policy_before_mutation", "get-service-last-accessed-details", {"JobId": job}, service="iam-query")
    probe.observe("pending_policy_new_default", "create-policy-version", {"PolicyArn": value["Arn"], "SetAsDefault": True, "PolicyDocument": policy(allow("sns:Publish"))})
    probe.own("delete-policy-version", {"PolicyArn": value["Arn"], "VersionId": "v1"})
    probe.observe("pending_policy_after_mutation", "get-service-last-accessed-details", {"JobId": job}, service="iam-query")
    probe.wait_job("pending_policy_completed", job)
    changed = probe.generate("pending_policy_regenerate", value["Arn"])
    probe.wait_job("pending_policy_regenerated", changed)


def report_controls(probe):
    user = probe.user("report-controls")
    resource_a = "arn:aws:s3:::" + probe.prefix + "-a/*"
    resource_b = "arn:aws:s3:::" + probe.prefix + "-b/*"
    cases = [
        ("bucket_only", policy(allow("s3:GetObject", resource_a.removesuffix("/*")))),
        ("same_exact_action_deny", policy(allow("s3:GetObject", resource_a), {"Effect": "Deny", "Action": "s3:GetObject", "Resource": resource_a})),
        ("disjoint_resource_deny", policy(allow("s3:GetObject", resource_a), {"Effect": "Deny", "Action": "s3:*", "Resource": resource_b})),
        ("conditional_service_deny", policy(allow("s3:GetObject"), {"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"StringEquals": {"aws:username": "nobody"}}})),
    ]
    for label, document in cases:
        probe.inline("user", user["UserName"], "report-controls", document)
        job = probe.generate("report_controls_generate_" + label, user["Arn"], "ACTION_LEVEL")
        probe.wait_job("report_controls_get_" + label, job)


def entity_snapshots(probe):
    users = [probe.user("entities-" + suffix) for suffix in ("a", "b", "c")]
    group_name = probe.prefix + "-entity-graph"
    group = probe.require("create-group", {"GroupName": group_name, "Path": "/stackd-last-access/"})["Group"]
    probe.identifiers[group["GroupId"]] = "<group-id:entity-graph>"
    probe.own("delete-group", {"GroupName": group_name}, {"action": "get-group", "input": {"GroupName": group_name}})
    probe.inline("group", group_name, "entity-graph", policy(allow("s3:GetObject")))
    association = {"GroupName": group_name, "UserName": users[0]["UserName"]}
    probe.require("add-user-to-group", association)
    probe.own("remove-user-from-group", association)
    managed = probe.require("create-policy", {"PolicyName": probe.prefix + "-entity-graph", "Path": "/stackd-last-access/", "PolicyDocument": policy(allow("s3:GetObject"))})["Policy"]
    probe.identifiers[managed["PolicyId"]] = "<policy-id:entity-graph>"
    probe.own("delete-policy", {"PolicyArn": managed["Arn"]}, {"action": "get-policy", "input": {"PolicyArn": managed["Arn"]}})
    attachment = {"UserName": users[2]["UserName"], "PolicyArn": managed["Arn"]}
    probe.require("attach-user-policy", attachment)
    probe.own("detach-user-policy", attachment)
    jobs = {}
    for label, arn in (("group", group["Arn"]), ("policy", managed["Arn"]), ("user", users[0]["Arn"])):
        jobs[label] = probe.generate("entity_snapshot_generate_" + label, arn)
        probe.wait_job("entity_snapshot_get_" + label, jobs[label])
        probe.observe("entity_snapshot_initial_" + label, "get-service-last-accessed-details-with-entities", {"JobId": jobs[label], "ServiceNamespace": "s3"})
    renamed = probe.prefix + "-entities-a-renamed"
    probe.require("update-user", {"UserName": users[0]["UserName"], "NewUserName": renamed, "NewPath": "/last-access-renamed/"})
    probe.own("delete-user", {"UserName": renamed}, {"action": "get-user", "input": {"UserName": renamed}})
    for label in ("group", "user"):
        probe.observe("entity_snapshot_renamed_" + label, "get-service-last-accessed-details-with-entities", {"JobId": jobs[label], "ServiceNamespace": "s3"})
    probe.require("remove-user-from-group", {"GroupName": group_name, "UserName": renamed})
    probe.observe("entity_snapshot_removed_group_member", "get-service-last-accessed-details-with-entities", {"JobId": jobs["group"], "ServiceNamespace": "s3"})
    probe.observe("entity_snapshot_removed_source_user_permission", "get-service-last-accessed-details-with-entities", {"JobId": jobs["user"], "ServiceNamespace": "s3"})
    association = {"GroupName": group_name, "UserName": users[1]["UserName"]}
    probe.require("add-user-to-group", association)
    probe.own("remove-user-from-group", association)
    probe.observe("entity_snapshot_added_group_member", "get-service-last-accessed-details-with-entities", {"JobId": jobs["group"], "ServiceNamespace": "s3"})
    probe.require("detach-user-policy", attachment)
    probe.observe("entity_snapshot_detached_policy", "get-service-last-accessed-details-with-entities", {"JobId": jobs["policy"], "ServiceNamespace": "s3"})
    attachment = {"UserName": users[1]["UserName"], "PolicyArn": managed["Arn"]}
    probe.require("attach-user-policy", attachment)
    probe.own("detach-user-policy", attachment)
    probe.observe("entity_snapshot_new_policy_attachment", "get-service-last-accessed-details-with-entities", {"JobId": jobs["policy"], "ServiceNamespace": "s3"})
    probe.require("delete-user", {"UserName": renamed})
    for label in ("group", "user"):
        probe.observe("entity_snapshot_deleted_" + label, "get-service-last-accessed-details-with-entities", {"JobId": jobs[label], "ServiceNamespace": "s3"})


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("full", "selection", "followup", "edges", "pending", "names", "pending-policy", "report-controls", "entities"), default="full")
    parser.add_argument("--output", type=Path, default=DESTINATION)
    parser.add_argument("--account", required=True)
    arguments = parser.parse_args()
    require_account(arguments.account)
    global_destination(arguments.output)
    probe = Probe()
    try:
        if arguments.phase == "full":
            run(probe)
            followup(probe)
            selection_edges(probe)
            pending_snapshot(probe)
            pending_policy_snapshot(probe)
            report_controls(probe)
            entity_snapshots(probe)
        else:
            identity = probe.require("get-caller-identity", {}, service="sts", record=False)
            probe.account = identity["Account"]
            probe.identifiers[identity["Arn"]] = "<original-caller-arn>"
            probe.identifiers[identity["UserId"]] = "<original-caller-id>"
            if arguments.phase == "selection":
                selection(probe, probe.user("selection"))
            elif arguments.phase == "followup":
                followup(probe)
            elif arguments.phase == "edges":
                selection_edges(probe)
            elif arguments.phase == "pending":
                pending_snapshot(probe)
            elif arguments.phase == "names":
                service_names(probe)
            elif arguments.phase == "pending-policy":
                pending_policy_snapshot(probe)
            elif arguments.phase == "report-controls":
                report_controls(probe)
            else:
                entity_snapshots(probe)
        probe.complete = True
    finally:
        probe.finish()


def global_destination(path):
    global DESTINATION
    DESTINATION = path


if __name__ == "__main__":
    main()
