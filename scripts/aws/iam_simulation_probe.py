#!/usr/bin/env python3
"""Capture IAM simulation diagnostics with controlled policies and owned users.

AWS CLI credentials are required. Custom cases are read-only; principal cases
create and remove uniquely named IAM resources. No account-wide policy or SCP
is changed. Normalized identifiers preserve their length so statement source
positions remain meaningful. Raw debug logs and authentication headers are
discarded. Use --preserve to retain earlier completed phase observations.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import uuid

from aws_cli import CLITimeout, run as run_cli, result as cli_result


ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / '.stackd/probes/iam/simulation.json'
COMMON = ["--endpoint-url", "https://iam.amazonaws.com", "--region", "us-east-1",
          "--no-paginate"]
RESOURCE_A = "arn:aws:s3:::stackd-simulation/a"
RESOURCE_B = "arn:aws:s3:::stackd-simulation/b"


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def policy(*statements, pretty=False):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)},
                      indent=2 if pretty else None, separators=None if pretty else (",", ":"))


def statement(effect="Allow", action="s3:GetObject", resource="*", **extra):
    return {"Effect": effect, "Action": action, "Resource": resource, **extra}


ALLOW = policy(statement())
DENY = policy(statement("Deny"))
ALLOW_ALL = policy(statement(action="*"))


def context_entry(name, values, kind="string"):
    return {"ContextKeyName": name, "ContextKeyValues": values, "ContextKeyType": kind}


def call(action, parameters=None, debug=False):
    try:
        process = run_cli("iam", action, parameters or {}, timeout=90,
                          options=[*COMMON, *(["--debug"] if debug else [])])
    except CLITimeout:
        return {"code": "CLITimeout", "message": "CLI request exceeded the bounded timeout"}
    return cli_result(process, cli_error="CLIValidationError", cli_message=None, debug=debug)


class Probe:
    def __init__(self, phase, preserve):
        self.phase, self.started = phase, stamp()
        self.cli_version = subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.strip()
        self.previous = json.loads(DESTINATION.read_text()) if preserve and DESTINATION.exists() else {}
        if self.previous and not self.previous.get("cleanup_verified"):
            raise RuntimeError("Preserved fixture has unverified cleanup; reconcile its owned-resource journal first")
        self.prefix = "stackd-sim-" + uuid.uuid4().hex[:10]
        self.account, self.caller_arn, self.identifiers = "", "", {}
        self.rows, self.owned, self.cleanup, self.setup = [], [], [], []
        self.pending_changes = []
        self.complete = False
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")

    def normalize(self, value):
        if isinstance(value, dict):
            return {key: self.normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            if self.caller_arn:
                value = value.replace(self.caller_arn, "arn:aws:iam::123456789012:user/stackd-sim-fixture000-probe")
            value = value.replace(self.prefix, "stackd-sim-fixture000")
            if self.account:
                value = value.replace(self.account, "123456789012")
            for actual, replacement in self.identifiers.items():
                value = value.replace(actual, replacement)
        return value

    def require(self, action, parameters=None):
        result = call(action, parameters)
        if result["code"] != "Success":
            raise RuntimeError(action + ": " + result["code"] + ": " + result.get("message", ""))
        if not action.startswith(("get-", "list-", "simulate-")):
            self.pending_changes.append({"operation": "".join(part.title() for part in action.split("-")), "input": parameters or {}})
        return result["output"]

    def own(self, kind, identifier, **extra):
        self.owned.append({"kind": kind, "id": identifier, **extra})
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self.journal.write_text(json.dumps({"prefix": self.prefix, "owned": self.owned}, indent=2) + "\n")

    def capture(self, case, parameters, principal=False, marker_from=None, result=None):
        action = "simulate-principal-policy" if principal else "simulate-custom-policy"
        result = result if result is not None else call(action, parameters, debug=True)
        row = {"case": case, "operation": "SimulatePrincipalPolicy" if principal else "SimulateCustomPolicy",
               "input": dict(parameters), "observed_at": stamp(), "phase": self.phase, **result}
        if "Marker" in row["input"] and marker_from:
            row["input"]["Marker"] = "<opaque-marker>"
        if marker_from:
            row["marker_source_case"] = marker_from
        if self.pending_changes:
            row["state_changes_before"] = self.pending_changes
            self.pending_changes = []
        marker = result.get("output", {}).get("Marker")
        if marker:
            row["output"] = dict(result["output"], Marker="<opaque-marker>")
        self.rows.append(self.normalize(row))
        self.write(False)
        decisions = [(item.get("EvalActionName"), item.get("EvalDecision")) for item in result.get("output", {}).get("EvaluationResults", [])]
        print(case, result["code"], decisions, flush=True)
        return result

    def batch(self, cases, principal=False):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            action = "simulate-principal-policy" if principal else "simulate-custom-policy"
            results = executor.map(lambda item: call(action, item[1], debug=True), cases)
            for (name, parameters), result in zip(cases, results):
                self.capture(name, parameters, principal=principal, result=result)

    def write(self, cleanup_verified):
        rows = {row["case"]: row for row in self.previous.get("observations", [])}
        rows.update({row["case"]: row for row in self.rows})
        completed = set(self.previous.get("completed_phases", []))
        if self.complete:
            completed.add(self.phase)
        fixture = {"schema_version": 1, "source": "Real AWS IAM simulation APIs; commercial partition; AWS CLI",
                   "api_version": "2010-05-08", "endpoint": "https://iam.amazonaws.com", "region": "us-east-1",
                   "aws_cli_version": self.cli_version,
                   "started_at": min(self.started, self.previous.get("started_at", self.started)), "finished_at": stamp(), "probe": "scripts/aws/iam_simulation_probe.py",
                   "reproduction_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "documentation": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html",
                                     "https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html",
                                     "https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html"],
                   "sanitization": "Controlled policy inputs, owned IAM identities, and hypothetical resources only. Authenticated caller IDs are normalized. Account/name/ID replacements inside policy documents preserve string length for diagnostic positions; caller ARNs in validation errors are separately redacted. Opaque markers omitted. No authentication headers or raw debug logs retained.",
                   "setup": self.previous.get("setup", []) + self.normalize(self.setup),
                   "observations": sorted(rows.values(), key=lambda row: row["observed_at"]), "completed_phases": sorted(completed),
                   "replay": "Apply each observation state_changes_before mutation list in order before evaluating its input, including before error observations. These record successful operations, not desired setup. Setup is a resource/document index, not a single simultaneous account snapshot.",
                   "capture_complete": self.complete, "cleanup_verified": cleanup_verified,
                   "limitations": ["A CLIValidationError is local SDK input validation, not an AWS service response.",
                                   "Observed policy simulator behavior is not a claim that live service authorization behaves identically.",
                                   "No live Organizations policy or account-wide policy was modified; SCP cases supply hypothetical policy documents.",
                                   "IAM source and exclusion ARN path behavior is recorded as observed, including differences from documented ARN selection.",
                                   "Default Custom simulation without CallerArn supplies aws:userid, but its exact value was not established; it did not equal the authenticated user ID, account ID, empty string, anonymous, or ANONYMOUS_PRINCIPAL. Presence and tested equality observations are retained without an invented value."],
                   "cleanup": self.previous.get("cleanup", []) + self.normalize(self.cleanup)}
        temporary = DESTINATION.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(fixture, indent=2) + "\n")
        temporary.replace(DESTINATION)

    def finish(self):
        failures = []
        for record in reversed(self.owned):
            kind, identifier = record["kind"], record["id"]
            if kind == "attachment":
                entity = record["entity_kind"]
                action, parameters = "detach-" + entity + "-policy", {entity.title() + "Name": record["name"], "PolicyArn": identifier}
            elif kind == "inline":
                entity = record["entity_kind"]
                action, parameters = "delete-" + entity + "-policy", {entity.title() + "Name": record["name"], "PolicyName": identifier}
            elif kind == "boundary":
                entity = record["entity_kind"]
                action, parameters = "delete-" + entity + "-permissions-boundary", {entity.title() + "Name": record["name"]}
            elif kind == "membership":
                action, parameters = "remove-user-from-group", {"GroupName": identifier, "UserName": record["name"]}
            elif kind == "policy":
                versions = call("list-policy-versions", {"PolicyArn": identifier})
                for version in versions.get("output", {}).get("Versions", []):
                    if not version["IsDefaultVersion"]:
                        call("delete-policy-version", {"PolicyArn": identifier, "VersionId": version["VersionId"]})
                action, parameters = "delete-policy", {"PolicyArn": identifier}
            else:
                action, parameters = "delete-" + kind, {kind.title() + "Name": identifier}
            result = call(action, parameters)
            self.cleanup.append({"operation": action, "input": parameters, "code": result["code"]})
            if result["code"] not in ("Success", "NoSuchEntity"):
                failures.append(record)
        for record in self.owned:
            kind, identifier = record["kind"], record["id"]
            if kind not in ("user", "group", "role", "policy"):
                continue
            parameters = {"PolicyArn": identifier} if kind == "policy" else {kind.title() + "Name": identifier}
            result = call("get-" + kind, parameters)
            self.cleanup.append({"operation": "get-" + kind, "input": parameters, "code": result["code"]})
            if result["code"] != "NoSuchEntity":
                failures.append(record)
        self.write(not failures)
        if failures:
            raise RuntimeError("Cleanup incomplete; see owned-resource journal " + str(self.journal))
        self.journal.unlink(missing_ok=True)
        print("cleanup_verified;", len(self.rows), "observations", flush=True)


def custom_cases():
    cases = []
    def add(name, policies=None, **parameters):
        cases.append((name, {"PolicyInputList": policies if policies is not None else [ALLOW], "ActionNames": ["s3:GetObject"], **parameters}))
    add("custom_default_resource")
    add("custom_single_resource", ResourceArns=[RESOURCE_A])
    add("custom_two_resources_allowed", ResourceArns=[RESOURCE_A, RESOURCE_B])
    add("custom_two_resources_mixed", [policy(statement(resource=RESOURCE_A))], ResourceArns=[RESOURCE_A, RESOURCE_B])
    add("custom_duplicate_resources", ResourceArns=[RESOURCE_A, RESOURCE_A])
    add("custom_duplicate_actions", ActionNames=["s3:GetObject", "s3:GetObject", "s3:PutObject"])
    add("custom_allow_two_statements", [policy(statement(Sid="First"), statement(Sid="Second"))])
    add("custom_deny_overrides_allow", [policy(statement(Sid="Allow"), statement("Deny", Sid="Deny"))])
    add("custom_multiple_policies_allow", [ALLOW, ALLOW])
    add("custom_multiple_policies_deny", [ALLOW, DENY])
    add("custom_pretty_positions", [policy(statement(Sid="First"), statement("Deny", action="s3:PutObject", Sid="Second"), pretty=True)], ActionNames=["s3:GetObject", "s3:PutObject"])
    add("custom_crlf_positions", [" \r\n" + policy(statement(), pretty=True).replace("\n", "\r\n") + "\r\n "])
    add("custom_singleton_statement", [json.dumps({"Statement": statement()})])
    for name, effect, action, resource in (
        ("relevant", "Allow", "s3:GetObject", "*"), ("irrelevant_action", "Allow", "s3:PutObject", "*"),
        ("irrelevant_resource", "Allow", "s3:GetObject", RESOURCE_B), ("deny", "Deny", "s3:GetObject", "*")):
        doc = policy(statement(effect, action, resource, Condition={"StringEquals": {"stack:missing": "yes"}}))
        add("missing_" + name, [doc], ResourceArns=[RESOURCE_A])
        add("missing_with_other_allow_" + name, [ALLOW, doc], ResourceArns=[RESOURCE_A])
    for operator, value in (("StringEqualsIfExists", "yes"), ("StringNotEqualsIfExists", "yes"), ("Null", "true"),
                            ("Null", "false"), ("ForAllValues:StringEquals", "yes"), ("ForAnyValue:StringEquals", "yes")):
        add("missing_operator_" + operator.replace(":", "_") + "_" + value,
            [policy(statement(Condition={operator: {"stack:missing": value}}))], ResourceArns=[RESOURCE_A])
    add("missing_resource_variable", [policy(statement(resource="arn:aws:s3:::stackd-simulation/${aws:username}"))], ResourceArns=[RESOURCE_A])
    add("missing_irrelevant_resource_variable", [policy(statement(action="s3:PutObject", resource="arn:aws:s3:::stackd-simulation/${aws:username}"))], ResourceArns=[RESOURCE_A])
    for name, boundary in (("allow", ALLOW), ("implicit", policy(statement(action="s3:PutObject"))), ("deny", DENY)):
        add("boundary_" + name, PermissionsBoundaryPolicyInputList=[boundary], ResourceArns=[RESOURCE_A, RESOURCE_B])
    add("boundary_deny_over_identity_deny", [DENY], PermissionsBoundaryPolicyInputList=[DENY])
    add("boundary_missing_context", PermissionsBoundaryPolicyInputList=[policy(statement(Condition={"StringEquals": {"stack:boundary": "yes"}}))])
    add("invalid_two_boundaries", PermissionsBoundaryPolicyInputList=[ALLOW, ALLOW])
    for name, action in (("wildcard", "s3:*"), ("unknown_service", "madeup:Action"), ("unknown_action", "s3:MadeUp"),
                         ("mixed_case", "S3:gEtObJeCt"), ("no_colon", "GetObject"), ("empty_suffix", "s3:"),
                         ("space", "s3:Get Object")):
        add("action_" + name, ActionNames=[action])
    for name, resource in (("not_arn", "not-an-arn"), ("partial_arn", "arn:aws:s3"), ("wrong_type", "arn:aws:iam::123456789012:user/fictional")):
        add("resource_" + name, ResourceArns=[resource])
    for name, values, kind in (("empty", [""], "string"), ("two_scalar", ["a", "b"], "string"),
                               ("numeric_bad", ["abc"], "numeric"), ("numeric_nan", ["NaN"], "numeric"),
                               ("boolean_uppercase", ["TRUE"], "boolean"), ("boolean_bad", ["yes"], "boolean"),
                               ("date_bad", ["tomorrow"], "date"), ("ip_bad", ["999.0.0.1"], "ip"),
                               ("binary_bad", ["!base64"], "binary"), ("bad_type", ["a"], "unknown")):
        add("context_" + name, ContextEntries=[context_entry("stack:test", values, kind)])
    add("context_duplicate_names", ContextEntries=[context_entry("stack:test", ["a"]), context_entry("stack:test", ["b"])])
    add("context_duplicate_case", ContextEntries=[context_entry("stack:test", ["a"]), context_entry("STACK:TEST", ["b"])])
    add("invalid_marker", Marker="not-a-simulation-marker")
    add("maxitems_zero", MaxItems=0)
    add("maxitems_too_large", MaxItems=1001)
    add("invalid_policy_json", ["{"])
    add("invalid_policy_version", ['{"Version":"2099-01-01","Statement":[]}'])
    add("empty_policy_list", [])
    for name, levels in (("allow", [[ALLOW_ALL], [ALLOW_ALL]]), ("deny", [[ALLOW_ALL], [DENY]]),
                         ("implicit", [[ALLOW_ALL], [policy(statement(action="s3:PutObject"))]]),
                         ("union_within_level", [[DENY, ALLOW_ALL], [ALLOW_ALL]]), ("empty_level", [[]])):
        add("organizations_" + name, OrderedOrganizationPolicyInputList=[{"ServiceControlPolicyInputList": docs} for docs in levels])
    return cases


def pagination(probe):
    parameters = {"PolicyInputList": [ALLOW_ALL], "ActionNames": ["s3:PutObject", "iam:GetUser", "s3:GetObject"],
                  "ResourceArns": [RESOURCE_A, RESOURCE_B], "MaxItems": 1}
    first = probe.capture("pagination_first", parameters)
    marker = first.get("output", {}).get("Marker")
    if marker:
        for name, change in (("same", {}), ("maxitems", {"MaxItems": 2}),
                             ("actions", {"ActionNames": ["s3:DeleteObject"]}),
                             ("policy", {"PolicyInputList": [DENY]}),
                             ("resources", {"ResourceArns": [RESOURCE_B]}),
                             ("reorder", {"ActionNames": list(reversed(parameters["ActionNames"]))})):
            probe.capture("pagination_changed_" + name, {**parameters, **change, "Marker": marker}, marker_from="pagination_first")


def custom_extra_cases(account):
    cases = []
    def add(name, policies=None, **parameters):
        cases.append((name, {"PolicyInputList": policies if policies is not None else [ALLOW_ALL], "ActionNames": ["s3:GetObject"], **parameters}))
    for name, action in (("wildcard", "s3:*"), ("unknown_service", "madeup:Action"), ("unknown_action", "s3:MadeUp"),
                         ("empty_suffix", "s3:"), ("space", "s3:Get Object"), ("no_colon", "GetObject")):
        add("action_allow_all_" + name, ActionNames=[action])
    operators = (("StringEqualsIfExists", "yes"), ("Null", "true"), ("ForAllValues:StringEquals", "yes"),
                 ("StringNotEquals", "yes"), ("StringNotEqualsIfExists", "yes"))
    for operator, value in operators:
        label = operator.replace(":", "_")
        condition = {operator: {"stack:missing": value}}
        add("missing_irrelevant_operator_" + label, [policy(statement(action="s3:PutObject", Condition=condition))])
        condition = {**condition, "StringEquals": {"stack:present": "expected"}}
        add("missing_failing_present_operator_" + label, [policy(statement(Condition=condition))],
            ContextEntries=[context_entry("stack:present", ["different"])])
    add("missing_negated_relevant", [policy(statement(Condition={"StringNotEquals": {"stack:missing": "yes"}}))])
    add("missing_with_unconditional_deny", [DENY, policy(statement(Condition={"StringEquals": {"stack:missing": "yes"}}))])
    add("missing_case_variants", [policy(statement(Condition={"StringEquals": {"STACK:missing": "yes"}}),
                                         statement(Condition={"StringEquals": {"stack:missing": "yes"}}))])
    add("missing_variable_default_resource_hit", [policy(statement(resource="arn:aws:s3:::stackd-simulation/${stack:key, 'a'}"))], ResourceArns=[RESOURCE_A])
    add("missing_variable_default_resource_miss", [policy(statement(resource="arn:aws:s3:::stackd-simulation/${stack:key, 'different'}"))], ResourceArns=[RESOURCE_A])
    add("missing_variable_default_condition", [policy(statement(Condition={"StringEquals": {"stack:present": "${stack:key, 'different'}"}}))],
        ContextEntries=[context_entry("stack:present", ["observed"])])
    add("missing_variable_condition", [policy(statement(Condition={"StringEquals": {"stack:present": "${stack:key}"}}))],
        ContextEntries=[context_entry("stack:present", ["observed"])])
    add("context_short_name", [policy(statement(Condition={"StringEquals": {"x": "yes"}}))], ContextEntries=[context_entry("x", ["yes"])])
    for value in ("TRUE", "yes", "1", "false"):
        add("context_boolean_used_" + value, [policy(statement(Condition={"Bool": {"stack:bool": "true"}}))],
            ContextEntries=[context_entry("stack:bool", [value], "boolean")])
    add("custom_singleton_pretty_positions", [json.dumps({"Statement": statement()}, indent=2)])
    add("custom_latin1_positions", [json.dumps({"Id": "caf\u00e9", "Statement": [statement()]}, ensure_ascii=False)])
    add("custom_cr_only_positions", [policy(statement(), pretty=True).replace("\n", "\r")])
    resources = {kind: "arn:aws:ec2:us-east-1:" + account + ":" + kind + "/" + identifier
                 for kind, identifier in (("instance", "i-0123456789abcdef0"), ("image", "ami-0123456789abcdef0"),
                                          ("security-group", "sg-0123456789abcdef0"), ("network-interface", "eni-0123456789abcdef0"),
                                          ("subnet", "subnet-0123456789abcdef0"), ("volume", "vol-0123456789abcdef0"))}
    resources["image"] = resources["image"].replace(":" + account + ":", "::")
    options = {"EC2-VPC-InstanceStore": ["instance", "image", "security-group", "network-interface"],
               "EC2-VPC-InstanceStore-Subnet": ["instance", "image", "security-group", "network-interface", "subnet"],
               "EC2-VPC-EBS": ["instance", "image", "security-group", "network-interface", "volume"],
               "EC2-VPC-EBS-Subnet": list(resources)}
    for option, kinds in options.items():
        add("resource_handling_" + option, ActionNames=["ec2:RunInstances"], ResourceArns=[resources[kind] for kind in kinds], ResourceHandlingOption=option)
        add("resource_handling_missing_" + option, ActionNames=["ec2:RunInstances"], ResourceArns=[resources["instance"]], ResourceHandlingOption=option)
    add("resource_handling_unknown", ResourceHandlingOption="fictional")
    add("resource_handling_other_action", ResourceArns=[RESOURCE_A], ResourceHandlingOption="EC2-VPC-EBS")
    return cases


def principal_extra_phase(probe):
    name = probe.prefix + "-extra-user"
    parameters = {"UserName": name, "Path": "/simulation/"}
    user = probe.require("create-user", parameters)["User"]
    probe.own("user", name)
    probe.setup.append({"operation": "CreateUser", "input": parameters, "arn": user["Arn"]})
    parameters = {"PolicyName": probe.prefix + "-extra-managed", "Path": "/simulation/", "PolicyDocument": ALLOW}
    managed = probe.require("create-policy", parameters)["Policy"]["Arn"]
    probe.own("policy", managed)
    probe.setup.append({"operation": "CreatePolicy", "input": parameters, "arn": managed})
    probe.require("attach-user-policy", {"UserName": name, "PolicyArn": managed})
    probe.own("attachment", managed, entity_kind="user", name=name)
    inline = "ExtraInline"
    parameters = {"UserName": name, "PolicyName": inline, "PolicyDocument": policy(statement(action="s3:PutObject"))}
    probe.require("put-user-policy", parameters)
    probe.own("inline", inline, entity_kind="user", name=name)
    probe.setup.append({"operation": "PutUserPolicy", "input": parameters})
    base = {"PolicySourceArn": user["Arn"], "ActionNames": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], "ResourceArns": [RESOURCE_A]}
    cases = [("principal_extra_baseline", base)]
    for label, arn in (("full", managed), ("pathless", managed.replace("/simulation/", "/")),
                       ("wrong_path", managed.replace("/simulation/", "/wrong-path/"))):
        cases.append(("principal_extra_exclude_arn_" + label, {**base, "PolicyExclusionList": [{"PolicyArn": arn}]}))
    cases.append(("principal_extra_exclude_user_managed", {**base, "PolicyExclusionList": [{"PolicyType": "user-managed"}]}))
    cases.append(("principal_extra_inline_exclusion_additional_policy", {**base, "PolicyInputList": [policy(statement(action="s3:DeleteObject"))],
                                                                        "PolicyExclusionList": [{"PolicyType": "inline"}]}))
    for label, policy_name, attachment_name in (("name_prefix", "Extra*", name), ("owner_prefix", inline, probe.prefix + "*"),
                                                ("owner_question", inline, name[:-1] + "?"), ("owner_two_stars", inline, "stackd*extra*"),
                                                ("name_question", "ExtraInlin?", name)):
        exclusion = {"InlinePolicyIdentifier": {"PolicyName": policy_name, "AttachmentType": "user", "AttachmentName": attachment_name}}
        cases.append(("principal_extra_exclude_inline_" + label, {**base, "PolicyExclusionList": [exclusion]}))
    probe.batch(cases, principal=True)
    probe.require("put-user-permissions-boundary", {"UserName": name, "PermissionsBoundary": managed})
    probe.own("boundary", managed, entity_kind="user", name=name)
    for label, exclusions in (("baseline", []), ("full", [{"PolicyArn": managed}]),
                               ("pathless", [{"PolicyArn": managed.replace("/simulation/", "/")}])):
        probe.capture("principal_extra_customer_boundary_" + label, {**base, "PolicyExclusionList": exclusions}, principal=True)
    probe.require("delete-user-permissions-boundary", {"UserName": name})
    aws_policy = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    probe.require("attach-user-policy", {"UserName": name, "PolicyArn": aws_policy})
    probe.own("attachment", aws_policy, entity_kind="user", name=name)
    aws_base = {**base, "ActionNames": ["s3:GetObjectAcl", "s3:PutObject"]}
    for label, exclusions in (("baseline", []), ("type", [{"PolicyType": "aws-managed"}]), ("arn", [{"PolicyArn": aws_policy}])):
        probe.capture("principal_extra_aws_exclude_" + label, {**aws_base, "PolicyExclusionList": exclusions}, principal=True)
    probe.require("put-user-permissions-boundary", {"UserName": name, "PermissionsBoundary": aws_policy})
    probe.own("boundary", aws_policy, entity_kind="user", name=name)
    for label, exclusions in (("baseline", []), ("type", [{"PolicyType": "aws-managed"}]), ("arn", [{"PolicyArn": aws_policy}]),
                               ("boundary", [{"PolicyType": "permission-boundary"}])):
        probe.capture("principal_extra_aws_boundary_exclude_" + label, {**aws_base, "PolicyExclusionList": exclusions}, principal=True)


def composition_phase(probe):
    name = probe.prefix + "-composition"
    user = probe.require("create-user", {"UserName": name, "Path": "/simulation/"})["User"]
    probe.own("user", name)
    probe.identifiers[user["UserId"]] = "AIDASIMFIXTURE0000000"
    base = {"PolicyInputList": [], "ActionNames": ["s3:GetObject"], "ResourceArns": [RESOURCE_A], "CallerArn": user["Arn"]}
    root_arn = "arn:aws:iam::" + probe.account + ":root"
    implicit = policy(statement(action="s3:PutObject"))
    direct = policy(statement(resource="arn:aws:s3:::stackd-simulation/*", Principal={"AWS": user["Arn"]}))
    delegated = policy(statement(resource="arn:aws:s3:::stackd-simulation/*", Principal={"AWS": root_arn}))
    cases = [("composition_resource_wildcard_invalid", {**base, "ResourcePolicy": policy(statement(Principal={"AWS": user["Arn"]}))})]
    for grant, document in (("direct", direct), ("root", delegated)):
        for label, identity, boundary in (("no_identity", [], None), ("identity", [ALLOW], None),
                                           ("boundary_implicit", [], implicit), ("boundary_deny", [], DENY),
                                           ("identity_boundary_implicit", [ALLOW], implicit)):
            parameters = {**base, "PolicyInputList": identity, "ResourcePolicy": document}
            if boundary is not None:
                parameters["PermissionsBoundaryPolicyInputList"] = [boundary]
            cases.append(("composition_same_" + grant + "_" + label, parameters))
    for label, identity, boundary in (("no_identity", [], None), ("identity", [ALLOW], None),
                                       ("boundary_allow", [ALLOW], ALLOW), ("boundary_implicit", [ALLOW], implicit),
                                       ("boundary_deny", [ALLOW], DENY)):
        parameters = {**base, "PolicyInputList": identity, "ResourcePolicy": direct, "ResourceOwner": "arn:aws:iam::999999999999:root"}
        if boundary is not None:
            parameters["PermissionsBoundaryPolicyInputList"] = [boundary]
        cases.append(("composition_cross_" + label, parameters))
    cases.append(("composition_resource_scp_deny", {**base, "PolicyInputList": [ALLOW], "ResourcePolicy": direct,
                                                    "OrderedOrganizationPolicyInputList": [{"ServiceControlPolicyInputList": [DENY]}]}))
    for label, owner in (("same", probe.account), ("cross", "999999999999")):
        cases.append(("composition_numeric_owner_" + label, {**base, "PolicyInputList": [ALLOW], "ResourcePolicy": direct, "ResourceOwner": owner}))
    for label, key, value in (("principal_arn", "aws:PrincipalArn", user["Arn"]), ("username", "aws:username", name),
                              ("userid", "aws:userid", user["UserId"]), ("principal_account", "aws:PrincipalAccount", probe.account)):
        cases.append(("composition_custom_auto_" + label, {**base, "PolicyInputList": [policy(statement(Condition={"StringEquals": {key: value}}))]}))
    cases.append(("composition_custom_auto_override", {**base, "PolicyInputList": [policy(statement(Condition={"StringEquals": {"aws:username": "override"}}))],
                                                       "ContextEntries": [context_entry("aws:username", ["override"])]}))
    probe.batch(cases)
    for label, key, value in (("principal_arn", "aws:PrincipalArn", user["Arn"]), ("username", "aws:username", name),
                              ("userid", "aws:userid", user["UserId"]), ("principal_account", "aws:PrincipalAccount", probe.account)):
        probe.capture("composition_principal_auto_" + label,
                      {"PolicySourceArn": user["Arn"], "ActionNames": ["s3:GetObject"], "ResourceArns": [RESOURCE_A],
                       "PolicyInputList": [policy(statement(Condition={"StringEquals": {key: value}}))]}, principal=True)


def composition_input_cases(probe):
    caller = "arn:aws:iam::" + probe.account + ":user/stackd-simulation-hypothetical"
    base = {"PolicyInputList": [], "ActionNames": ["s3:GetObject"], "CallerArn": caller}
    cases = []
    for label, resource in (("wildcard", "*"), ("arn", "arn:aws:s3:::stackd-simulation/*")):
        for request_label, resources in (("omitted", []), ("explicit_wildcard", ["*"]), ("explicit_arn", [RESOURCE_A])):
            parameters = {**base, "ResourcePolicy": policy(statement(resource=resource, Principal={"AWS": caller}))}
            if resources:
                parameters["ResourceArns"] = resources
            cases.append(("composition_resource_shape_" + label + "_" + request_label, parameters))
    for label, key in (("principal_arn", "aws:PrincipalArn"), ("username", "aws:username"),
                       ("userid", "aws:userid"), ("principal_account", "aws:PrincipalAccount")):
        cases.append(("composition_no_caller_presence_" + label,
                      {"ActionNames": ["s3:GetObject"], "PolicyInputList": [policy(statement(Condition={"Null": {key: "false"}}))]}))
    for kind in ("group", "role"):
        name = "stackd-simulation-hypothetical-" + kind
        cases.append(("composition_" + kind + "_auto_username",
                      {"ActionNames": ["s3:GetObject"], "CallerArn": "arn:aws:iam::" + probe.account + ":" + kind + "/simulation/" + name,
                       "PolicyInputList": [policy(statement(Condition={"StringEquals": {"aws:username": name}}))]}))
    return cases


def caller_default_cases(probe, caller_id):
    probe.identifiers[caller_id] = "AIDA" + "0" * (len(caller_id) - 4)
    cases = []
    for label, key, value in (("userid_authenticated", "aws:userid", caller_id),
                              ("userid_anonymous_principal", "aws:userid", "ANONYMOUS_PRINCIPAL"),
                              ("userid_anonymous", "aws:userid", "anonymous"),
                              ("userid_empty", "aws:userid", ""),
                              ("userid_account", "aws:userid", probe.account),
                              ("account_authenticated", "aws:PrincipalAccount", probe.account),
                              ("account_anonymous", "aws:PrincipalAccount", "anonymous"),
                              ("account_zero", "aws:PrincipalAccount", "000000000000")):
        cases.append(("composition_no_caller_value_" + label,
                      {"ActionNames": ["s3:GetObject"], "PolicyInputList": [policy(statement(Condition={"StringEquals": {key: value}}))]}))
    return cases


def principal_phase(probe):
    names, arns = {}, {}
    for kind in ("user", "group", "role"):
        name = probe.prefix + "-" + kind
        parameters = {kind.title() + "Name": name, "Path": "/simulation/"}
        if kind == "role":
            parameters["AssumeRolePolicyDocument"] = policy({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})
        output = probe.require("create-" + kind, parameters)[kind.title()]
        names[kind], arns[kind] = name, output["Arn"]
        probe.own(kind, name)
        probe.identifiers[output[kind.title() + "Id"]] = output[kind.title() + "Id"][:4] + "SIMFIXTURE0000000"
        probe.setup.append({"operation": "Create" + kind.title(), "input": parameters, "arn": output["Arn"]})
    managed_doc = policy(statement(action="s3:DeleteObject", Sid="ManagedDelete"), pretty=True)
    boundary_doc = policy(statement(action=["s3:GetObject", "s3:PutObject"], Sid="BoundaryReadWrite"), pretty=True)
    policies = {}
    for index, (label, document) in enumerate((("managed", managed_doc), ("boundary", boundary_doc)), 1):
        parameters = {"PolicyName": probe.prefix + "-" + label, "Path": "/simulation/", "PolicyDocument": document}
        output = probe.require("create-policy", parameters)["Policy"]
        policies[label] = output["Arn"]
        probe.own("policy", output["Arn"])
        probe.identifiers[output["PolicyId"]] = "ANPASIMFIXTURE" + str(index).zfill(8)
        probe.setup.append({"operation": "CreatePolicy", "input": parameters, "arn": output["Arn"]})
    for kind, action, resource in (("user", "s3:GetObject", RESOURCE_A), ("group", "s3:PutObject", RESOURCE_B), ("role", "s3:GetObject", "*")):
        inline = kind.title() + "Inline"
        document = policy(statement(action=action, resource=resource, Sid=inline), pretty=True)
        parameters = {kind.title() + "Name": names[kind], "PolicyName": inline, "PolicyDocument": document}
        probe.require("put-" + kind + "-policy", parameters)
        probe.own("inline", inline, entity_kind=kind, name=names[kind])
        probe.setup.append({"operation": "Put" + kind.title() + "Policy", "input": parameters})
        probe.require("attach-" + kind + "-policy", {kind.title() + "Name": names[kind], "PolicyArn": policies["managed"]})
        probe.own("attachment", policies["managed"], entity_kind=kind, name=names[kind])
    probe.require("add-user-to-group", {"UserName": names["user"], "GroupName": names["group"]})
    probe.own("membership", names["group"], name=names["user"])
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    base = {"PolicySourceArn": arns["user"], "ActionNames": actions, "ResourceArns": [RESOURCE_A, RESOURCE_B]}
    for kind in ("user", "group", "role"):
        probe.capture("principal_" + kind + "_sources", {**base, "PolicySourceArn": arns[kind]}, principal=True)
    cases = []
    def add(name, **parameters):
        cases.append((name, {**base, **parameters}))
    for kind in ("user", "group", "role"):
        add("principal_" + kind + "_wrong_path", PolicySourceArn=arns[kind].replace("/simulation/", "/wrong-path/"))
        add("principal_" + kind + "_missing", PolicySourceArn=arns[kind] + "-missing")
    add("principal_cross_account_source", PolicySourceArn=arns["user"].replace(probe.account, "999999999999"))
    add("principal_root_source", PolicySourceArn="arn:aws:iam::" + probe.account + ":root")
    add("principal_assumed_role_source", PolicySourceArn="arn:aws:sts::" + probe.account + ":assumed-role/fictional/session")
    add("principal_invalid_source", PolicySourceArn="not-an-arn-but-long-enough")
    add("principal_additional_policy", PolicyInputList=[ALLOW_ALL])
    add("principal_default_resource", ResourceArns=[])
    for kind in ("user", "group", "role"):
        add("principal_caller_" + kind, CallerArn=arns[kind])
    probe.batch(cases, principal=True)
    probe.require("put-user-permissions-boundary", {"UserName": names["user"], "PermissionsBoundary": policies["boundary"]})
    probe.own("boundary", policies["boundary"], entity_kind="user", name=names["user"])
    probe.capture("principal_attached_boundary", base, principal=True)
    probe.capture("principal_replacement_boundary", {**base, "PermissionsBoundaryPolicyInputList": [managed_doc]}, principal=True)
    cases = []
    for kind in ("inline", "user-managed", "aws-managed", "permission-boundary", "scp", "rcp", "bogus"):
        add("principal_exclude_type_" + kind, PolicyExclusionList=[{"PolicyType": kind}])
    for label, arn in policies.items():
        add("principal_exclude_arn_" + label, PolicyExclusionList=[{"PolicyArn": arn}])
    add("principal_exclude_unknown_arn", PolicyExclusionList=[{"PolicyArn": policies["managed"] + "-missing"}])
    add("principal_exclude_boundary_with_override", PermissionsBoundaryPolicyInputList=[DENY], PolicyExclusionList=[{"PolicyType": "permission-boundary"}])
    for label, identifier in (
        ("user", {"PolicyName": "UserInline", "AttachmentType": "user", "AttachmentName": names["user"]}),
        ("group", {"PolicyName": "GroupInline", "AttachmentType": "group", "AttachmentName": names["group"]}),
        ("name_only", {"PolicyName": "UserInline"}),
        ("wildcard", {"PolicyName": "*", "AttachmentType": "user", "AttachmentName": names["user"]}),
        ("owner_wildcard", {"PolicyName": "UserInline", "AttachmentType": "user", "AttachmentName": "*"}),
        ("wrong_owner", {"PolicyName": "UserInline", "AttachmentType": "user", "AttachmentName": names["group"]}),
        ("wrong_type", {"PolicyName": "UserInline", "AttachmentType": "group", "AttachmentName": names["user"]}),
        ("bad_type", {"PolicyName": "UserInline", "AttachmentType": "bogus", "AttachmentName": names["user"]})):
        add("principal_exclude_inline_" + label, PolicyExclusionList=[{"InlinePolicyIdentifier": identifier}])
    add("principal_exclude_empty", PolicyExclusionList=[{}])
    add("principal_exclude_union_multiple", PolicyExclusionList=[{"PolicyType": "inline", "PolicyArn": policies["managed"]}])
    probe.batch(cases, principal=True)
    # The same policy can contribute as both identity permission and boundary.
    probe.require("attach-user-policy", {"UserName": names["user"], "PolicyArn": policies["boundary"]})
    probe.own("attachment", policies["boundary"], entity_kind="user", name=names["user"])
    for label, exclusion in (("none", []), ("user_managed", [{"PolicyType": "user-managed"}]),
                             ("boundary", [{"PolicyType": "permission-boundary"}]),
                             ("arn", [{"PolicyArn": policies["boundary"]}])):
        probe.capture("principal_dual_use_" + label, {**base, "PolicyExclusionList": exclusion}, principal=True)
    resource_doc = policy(statement(resource="arn:aws:s3:::stackd-simulation/*", Principal={"AWS": "*"}))
    custom = {"PolicyInputList": [], "ActionNames": ["s3:GetObject"], "ResourceArns": [RESOURCE_A], "ResourcePolicy": resource_doc}
    cases = [("resource_policy_missing_caller", custom)]
    for label, caller in list(arns.items()) + [("root", "arn:aws:iam::" + probe.account + ":root"), ("assumed_role", "arn:aws:sts::" + probe.account + ":assumed-role/fictional/session")]:
        cases.append(("resource_policy_caller_" + label, {**custom, "CallerArn": caller}))
    for label, owner in (("same", "arn:aws:iam::" + probe.account + ":root"), ("cross", "arn:aws:iam::999999999999:root"),
                          ("user", arns["user"]), ("invalid", "not-an-arn")):
        cases.append(("resource_policy_owner_" + label, {**custom, "CallerArn": arns["user"], "ResourceOwner": owner}))
    probe.batch(cases)
    for kind in ("user", "group", "role"):
        probe.capture("principal_resource_policy_" + kind, {**base, "PolicySourceArn": arns[kind], "ActionNames": ["s3:GetObject"], "ResourcePolicy": resource_doc}, principal=True)
    # Current stored default versions and membership must affect the next call.
    probe.require("delete-user-permissions-boundary", {"UserName": names["user"]})
    changed = policy(statement("Deny", action="s3:DeleteObject", Sid="NewDefaultDeny"))
    probe.require("create-policy-version", {"PolicyArn": policies["managed"], "PolicyDocument": changed, "SetAsDefault": True})
    probe.setup.append({"operation": "CreatePolicyVersion", "input": {"PolicyArn": policies["managed"], "PolicyDocument": changed, "SetAsDefault": True}})
    probe.capture("principal_current_default_version", base, principal=True)
    probe.require("remove-user-from-group", {"UserName": names["user"], "GroupName": names["group"]})
    probe.require("detach-user-policy", {"UserName": names["user"], "PolicyArn": policies["boundary"]})
    probe.capture("principal_group_membership_removed", base, principal=True)


def run(probe):
    identity = subprocess.run(["aws", "sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], capture_output=True, text=True, check=True)
    caller = json.loads(identity.stdout)
    probe.account, probe.caller_arn = caller["Account"], caller["Arn"]
    if probe.phase in ("custom", "all"):
        probe.batch(custom_cases())
        pagination(probe)
    if probe.phase in ("principal", "all"):
        principal_phase(probe)
    if probe.phase in ("custom-extra", "all"):
        probe.batch(custom_extra_cases(probe.account))
    if probe.phase in ("principal-extra", "all"):
        principal_extra_phase(probe)
    if probe.phase in ("composition", "all"):
        composition_phase(probe)
    if probe.phase in ("composition-inputs", "all"):
        probe.batch(composition_input_cases(probe))
    if probe.phase in ("caller-defaults", "all"):
        probe.batch(caller_default_cases(probe, caller["UserId"]))
    probe.complete = True


if __name__ == "__main__":
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("custom", "principal", "custom-extra", "principal-extra", "composition", "composition-inputs", "caller-defaults", "all"), default="all")
    parser.add_argument("--preserve", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    probe = Probe(args.phase, args.preserve)
    try:
        run(probe)
    finally:
        probe.finish()
