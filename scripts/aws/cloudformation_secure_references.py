"""Opt-in CFN secure-reference calibration; only exact owned, free resources.

Native invocation is documented on cloudformation_probe.py. Public payloads are
synthetic; IAM passwords and access-key secrets are generated only in memory and
redacted by the parent ledger before persistence. No account policy is changed.
"""
import copy
import hashlib
import json
from pathlib import Path
import secrets
import time
import uuid

import boto3
from botocore.config import Config

REFERENCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references-secretsmanager.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references-ssm-secure-strings.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ChangePassword.html",
    "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html",
]


def reference(name, suffix=""):
    return "{{resolve:secretsmanager:" + name + suffix + "}}"


def parameter(probe, logical, value):
    name = probe.resource("ssm", "/" + probe.data["prefix"] + "/" + logical.lower())
    return {"Type": "AWS::SSM::Parameter", "Properties": {
        "Name": name, "Type": "String", "Tier": "Standard", "Value": value,
        "Description": "Owned public secure-reference observation", "Tags": {
            "stackd-probe": probe.data["prefix"]}}}


def template(resources):
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}


def observe(probe, label, stack, resources):
    probe.snapshot(label, stack)
    probe.cfn(label + "-template", "get_template", {"StackName": stack})
    values = {}
    for logical, resource in resources.items():
        if resource["Type"] != "AWS::SSM::Parameter":
            continue
        result = probe.call(label + "-value-" + logical, "ssm", "get_parameter", {
            "Name": resource["Properties"]["Name"], "WithDecryption": False}, required=False)
        if result:
            values[logical] = result["Parameter"]["Value"]
    probe.data["secure_references"]["observations"][label] = values
    probe.save()


def rollback_evidence(probe, label, operation, logicals):
    """Never confuse preflight rejection with a forward/rollback round trip."""
    token = probe.data["prefix"] + "-" + operation
    transitions = probe.data["event_snapshots"][label]["transitions"]
    counts = {logical: sum(event.get("ClientRequestToken") == token and
                          event["LogicalResourceId"] == logical and
                          event["ResourceStatus"] == "UPDATE_COMPLETE"
                          for event in transitions) for logical in logicals}
    round_trip = all(count >= 2 for count in counts.values())
    probe.data["secure_references"]["observations"][label].update(
        resource_round_trip_observed=round_trip, round_trip_event_counts=counts)
    if not round_trip:
        probe.data["secure_references"]["restrictions"].append(
            label + ": forward and rollback resource completions not both observed; "
            "retained values are not selector rollback proof")
    probe.save()
    return round_trip


def update(probe, label, stack, body):
    result = probe.cfn(label + "-update", "update_stack", {
        "StackName": stack, "TemplateBody": json.dumps(body),
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "ClientRequestToken": probe.data["prefix"] + "-" + label}, required=False)
    if not result:
        return None
    return probe.wait_stack(label, stack, {
        "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"})["StackStatus"]


def create_optional(probe, key, body):
    # Persist the attempt before the request, including synchronous validation denials.
    name = probe.data["prefix"] + "-" + key
    owned = probe.data["owned"]["stacks"][key] = {"name": name}
    probe.save()
    result = probe.cfn("create-" + key, "create_stack", {
        "StackName": name, "TemplateBody": json.dumps(body),
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "ClientRequestToken": name + "-create",
        "Tags": [{"Key": "stackd-probe", "Value": probe.data["prefix"]}]}, required=False)
    if result:
        owned["id"] = result["StackId"]
        probe.save()
        return result["StackId"]
    return None


def secure_references(probe):
    evidence = probe.data["secure_references"] = {
        "source": "native AWS" if not probe.args.endpoint else "local replay (not AWS evidence)",
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "observations": {}, "restrictions": [],
        "focus": probe.args.secure_reference_focus,
        "safety": {"managed_keys_only": True, "standing_settings_mutated": False,
                   "public_secret_payloads": True, "passwords_captured": False,
                   "cost_ceiling_usd": 0.10, "max_owned_secrets": 1,
                   "max_owned_secure_parameters": 1, "max_owned_users": 1},
        "evidence_boundary": "GetParameter contains only public fixture values. GetTemplate and full event calls retain literal references. IAM password-use assertions require successful self ChangePassword, never GetLoginProfile alone. Failed cases are native restrictions/permissions, not emulator results.",
        "replay": "Repeat cloudformation_probe.py --secure-dynamic-references --endpoint http://127.0.0.1:4566 --account LOCAL_ACCOUNT --output /tmp/cfn-secure-local.json; separate test-only credentials are enforced. Compare secure_references.observations and labeled calls, not volatile IDs/timestamps. --cleanup-only --endpoint resumes exact-owned local cleanup.",
    }
    probe.data["scope"] = "One owned managed-key secret, one standard SecureString, owned CFN SSM/IAM/SQS resources; no standing policies or paid compute"
    probe.data["documentation"] = list(dict.fromkeys(probe.data["documentation"] + REFERENCES))
    probe.data["bounds"].update(stack_wait_seconds=600, max_calls=2000)
    probe.save()
    if probe.args.secure_reference_focus == "ssm-login":
        ssm_login(probe)
        probe.data["workflow_complete"] = True
        probe.save()
        return
    name = probe.data["prefix"] + "/public"
    probe.call("secure-secret-preflight", "secretsmanager", "describe_secret", {"SecretId": name}, required=False)
    if probe.data["calls"][-1]["code"] != "ResourceNotFoundException":
        raise RuntimeError("Secret absence not proven; refusing ambiguous ownership")
    probe.resource("secret", name)
    first = json.dumps({"string": "public-one", "number": 42, "boolean": True,
                        "object": {"nested": "public"}, "array": [1, "public"], "null": None})
    created = probe.call("secure-secret-create", "secretsmanager", "create_secret", {
        "Name": name, "SecretString": first, "ClientRequestToken": str(uuid.uuid4()),
        "Tags": [{"Key": "stackd-probe", "Value": probe.data["prefix"]}]}, required=False)
    if not created:
        evidence["restrictions"].append("Secret creation denied; Secrets Manager scenarios unavailable")
        probe.save()
    else:
        version_one = created["VersionId"]
        probe.call("secure-stage-pin", "secretsmanager", "update_secret_version_stage", {
            "SecretId": name, "VersionStage": "PROBE_OLD", "MoveToVersionId": version_one})
        second = first.replace("public-one", "public-two")
        version_two = probe.call("secure-secret-rotate-two", "secretsmanager", "put_secret_value", {
            "SecretId": name, "SecretString": second, "ClientRequestToken": str(uuid.uuid4())})["VersionId"]
        cases = {
            "omitted": reference(name), "empty-segments": reference(name, "::::"),
            "explicit": reference(name, ":SecretString"),
            "string": reference(name, ":SecretString:string"),
            "omitted-string-key": reference(name, "::string"),
            "current": reference(name, ":SecretString:string:AWSCURRENT"),
            "stage": reference(name, ":SecretString:string:PROBE_OLD"),
            "version": reference(name, ":SecretString:string::" + version_one),
            **{key: reference(name, ":SecretString:" + key)
               for key in ("number", "boolean", "object", "array", "null", "missing")},
        }
        if probe.args.secure_reference_focus != "all":
            cases = {}
        pending = []
        for key, value in cases.items():
            resources = {"Value": parameter(probe, "case-" + key, value)}
            stack = create_optional(probe, "secure-" + key, template(resources))
            if stack:
                pending.append((key, stack, resources))
        for key, stack, resources in pending:
            status = probe.wait_stack("secure-" + key, stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})["StackStatus"]
            observe(probe, "syntax-" + key, stack, resources)
            evidence["observations"]["syntax-" + key]["stack_status"] = status
            probe.save()
        lifecycle(probe, name, version_one, version_two, first)
    if probe.args.secure_reference_focus == "all":
        ssm_login(probe)
    probe.data["workflow_complete"] = True
    probe.save()


def lifecycle(probe, name, version_one, version_two, first):
    resources = {
        "Current": parameter(probe, "lifecycle-current", reference(name, ":SecretString:string")),
        "Pinned": parameter(probe, "lifecycle-pinned", reference(name, ":SecretString:string::" + version_one)),
        "Stage": parameter(probe, "lifecycle-stage", reference(name, ":SecretString:string:PROBE_OLD")),
        "Marker": parameter(probe, "lifecycle-marker", "public-marker-one"),
    }
    body = template(resources)
    stack = create_optional(probe, "secure-lifecycle", body)
    if not stack:
        return
    status = probe.wait_stack("secure-lifecycle", stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})["StackStatus"]
    observe(probe, "lifecycle-initial", stack, resources)
    if status != "CREATE_COMPLETE":
        return
    probe.call("secure-secret-rotate-three", "secretsmanager", "put_secret_value", {
        "SecretId": name, "SecretString": first.replace("public-one", "public-three"),
        "ClientRequestToken": str(uuid.uuid4())})
    observe(probe, "rotation-without-update", stack, resources)
    unrelated = copy.deepcopy(body)
    unrelated["Resources"]["Marker"]["Properties"]["Value"] = "public-marker-two"
    update(probe, "secure-unrelated", stack, unrelated)
    observe(probe, "rotation-unrelated-update", stack, resources)
    changed = copy.deepcopy(unrelated)
    for logical in ("Current", "Pinned", "Stage"):
        changed["Resources"][logical]["Properties"]["Description"] = "Changed resource forces reference resolution"
    update(probe, "secure-changed", stack, changed)
    observe(probe, "rotation-changed-resource", stack, resources)
    # Rotate again, then force an ordered failure after all three referencing
    # resources update. The previous literal selector must drive rollback.
    probe.call("secure-secret-rotate-four", "secretsmanager", "put_secret_value", {
        "SecretId": name, "SecretString": first.replace("public-one", "public-four"),
        "ClientRequestToken": str(uuid.uuid4())})
    failing = copy.deepcopy(changed)
    for logical in ("Current", "Pinned", "Stage"):
        failing["Resources"][logical]["Properties"]["Description"] = "Attempted update before ordered rollback"
    failing["Resources"]["Pinned"]["Properties"]["Value"] = reference(name, ":SecretString:string::" + version_two)
    failing["Resources"]["Stage"]["Properties"]["Value"] = reference(name, ":SecretString:string:AWSCURRENT")
    failing["Resources"]["BadQueue"] = probe.bad_queue("secure-rollback-failure", ["Current", "Pinned", "Stage"])
    status = update(probe, "secure-selector-rollback", stack, failing)
    observe(probe, "selector-rollback", stack, resources)
    probe.data["secure_references"]["observations"]["selector-rollback"]["stack_status"] = status
    rollback_evidence(probe, "selector-rollback", "secure-selector-rollback", ("Current", "Pinned", "Stage"))
    probe.save()


def ssm_login(probe):
    evidence = probe.data["secure_references"]
    secure = "/" + probe.data["prefix"] + "/password"
    passwords = ["Aa1!" + secrets.token_urlsafe(32) for _ in range(4)]
    probe.sensitive_values.extend(passwords)
    probe.call("secure-parameter-preflight", "ssm", "get_parameter", {"Name": secure}, required=False)
    if probe.data["calls"][-1]["code"] != "ParameterNotFound":
        raise RuntimeError("Secure parameter absence not proven")
    probe.resource("secure-parameter", secure)
    put = probe.call("secure-parameter-create", "ssm", "put_parameter", {
        "Name": secure, "Type": "SecureString", "Tier": "Standard", "Value": passwords[0],
        "Tags": [{"Key": "stackd-probe", "Value": probe.data["prefix"]}]}, required=False)
    if not put:
        evidence["restrictions"].append("SecureString creation denied; SSM secure scenarios unavailable")
        probe.save()
        return
    ref = "{{resolve:ssm-secure:" + secure + ":1}}"
    unsupported = {"Value": parameter(probe, "unsupported-secure", ref)}
    rejected = create_optional(probe, "secure-unsupported", template(unsupported))
    if rejected:
        probe.wait_stack("secure-unsupported", rejected, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
        observe(probe, "ssm-secure-unsupported-property", rejected, unsupported)
    user = probe.resource("iam-user", probe.data["prefix"] + "-login")
    resources = {"User": {"Type": "AWS::IAM::User", "Properties": {
        "UserName": user, "LoginProfile": {"Password": ref, "PasswordResetRequired": False},
        "Tags": [{"Key": "stackd-probe", "Value": probe.data["prefix"]}],
        "Policies": [{"PolicyName": "owned-self-change", "PolicyDocument": {
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:ChangePassword",
            "Resource": "arn:aws:iam::" + probe.account + ":user/" + user}]}}]}},
        "Marker": parameter(probe, "login-marker", "public-marker-one")}
    body = template(resources)
    stack = create_optional(probe, "secure-login", body)
    if not stack:
        return
    status = probe.wait_stack("secure-login", stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})["StackStatus"]
    observe(probe, "ssm-secure-login-initial", stack, resources)
    if status != "CREATE_COMPLETE":
        evidence["restrictions"].append("IAM LoginProfile stack failed; password-use proof unavailable; inspect native events")
        probe.save()
        return
    key = probe.call("secure-login-access-key", "iam", "create_access_key", {"UserName": user}, required=False)
    if key:
        credentials = key["AccessKey"]
        probe.sensitive_values.extend([credentials["AccessKeyId"], credentials["SecretAccessKey"]])
        config = Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=30,
                        ignore_configured_endpoint_urls=True)
        reader = boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                               aws_secret_access_key=credentials["SecretAccessKey"], region_name="us-east-1")
        probe.readers = {"iam": reader.client("iam", endpoint_url=probe.args.endpoint, config=config)}
    else:
        evidence["restrictions"].append("IAM CreateAccessKey denied; GetLoginProfile is not password-use proof")
    def prove(label, password):
        if not key:
            return
        # Only bounded IAM propagation retries; no credential output or debug logs.
        for attempt in range(15):
            probe.call(label + "-" + str(attempt), "iam", "change_password", {
                "OldPassword": password, "NewPassword": passwords[3]}, caller="reader", required=False)
            code = probe.data["calls"][-1]["code"]
            if code not in ("InvalidClientTokenId", "AccessDenied", "AccessDeniedException"):
                break
            time.sleep(2)
        evidence["observations"][label] = {"password_use_code": code}
        if code == "Success":
            probe.call(label + "-restore", "iam", "update_login_profile", {
                "UserName": user, "Password": password}, required=False)
        probe.save()
    prove("login-version-one-proof", passwords[0])
    probe.call("secure-parameter-rotate", "ssm", "put_parameter", {
        "Name": secure, "Type": "SecureString", "Tier": "Standard", "Value": passwords[1], "Overwrite": True})
    unrelated = copy.deepcopy(body)
    unrelated["Resources"]["Marker"]["Properties"]["Value"] = "public-marker-two"
    update(probe, "login-unrelated", stack, unrelated)
    prove("login-unrelated-retains-one", passwords[0])
    changed = copy.deepcopy(unrelated)
    changed["Resources"]["User"]["Properties"]["LoginProfile"]["Password"] = "{{resolve:ssm-secure:" + secure + ":2}}"
    update(probe, "login-version-two", stack, changed)
    prove("login-version-two-proof", passwords[1])
    failing = copy.deepcopy(changed)
    failing["Resources"]["User"]["Properties"]["LoginProfile"]["Password"] = ref
    failing["Resources"]["BadQueue"] = probe.bad_queue("login-rollback-failure", "User")
    update(probe, "login-selector-rollback", stack, failing)
    observe(probe, "ssm-secure-login-rollback", stack, resources)
    if rollback_evidence(probe, "ssm-secure-login-rollback", "login-selector-rollback", ("User",)):
        prove("login-rollback-restores-two", passwords[1])


def cleanup_before_stacks(probe, cleanup):
    """Delete owned user keys before CFN user deletion, including interrupted runs."""
    for resource in probe.data["owned"]["resources"]:
        if resource["kind"] != "iam-user":
            continue
        name = resource["name"]
        user = probe.call("cleanup-login-owner-" + name, "iam", "get_user", {"UserName": name}, required=False)
        if probe.data["calls"][-1]["code"] == "NoSuchEntity":
            continue
        if {"Key": "stackd-probe", "Value": probe.data["prefix"]} not in user.get("User", {}).get("Tags", []):
            cleanup["errors"].append({"user": name, "error": "Unique user ownership tag not confirmed"})
            continue
        result = probe.call("cleanup-login-keys-" + name, "iam", "list_access_keys", {"UserName": name}, required=False)
        if result.get("IsTruncated"):
            cleanup["errors"].append({"user": name, "error": "Owned access-key listing unexpectedly truncated"})
        for key in result.get("AccessKeyMetadata", []):
            probe.call("cleanup-login-key", "iam", "delete_access_key", {
                "UserName": name, "AccessKeyId": key["AccessKeyId"]}, required=False)


def cleanup_direct(probe, cleanup):
    """Resolve attempted creates by name plus owner tag, never ambiguous deletion."""
    for resource in probe.data["owned"]["resources"]:
        kind, name = resource["kind"], resource["name"]
        if kind not in ("secret", "secure-parameter"):
            continue
        service = "secretsmanager" if kind == "secret" else "ssm"
        operation = "describe_secret" if kind == "secret" else "get_parameter"
        request = {"SecretId": name} if kind == "secret" else {"Name": name}
        result = probe.call("cleanup-direct-inspect-" + name, service, operation, request, required=False)
        absent = "ResourceNotFoundException" if kind == "secret" else "ParameterNotFound"
        if probe.data["calls"][-1]["code"] == absent:
            continue
        tags = result.get("Tags", []) if kind == "secret" else probe.call(
            "cleanup-direct-tags-" + name, "ssm", "list_tags_for_resource", {
                "ResourceType": "Parameter", "ResourceId": name}, required=False).get("TagList", [])
        if {"Key": "stackd-probe", "Value": probe.data["prefix"]} not in tags:
            cleanup["errors"].append({"resource": name, "error": "Unique ownership tag not confirmed"})
            continue
        probe.call("cleanup-direct-delete-" + name, service,
                   "delete_secret" if kind == "secret" else "delete_parameter",
                   {"SecretId": name, "ForceDeleteWithoutRecovery": True} if kind == "secret" else {"Name": name}, required=False)
        # Force deletion is asynchronous. Describe may briefly expose a tombstone.
        for attempt in range(31):
            probe.call("cleanup-direct-absence-" + str(attempt) + "-" + name,
                       service, operation, request, required=False)
            if probe.data["calls"][-1]["code"] == absent:
                break
            time.sleep(2)
