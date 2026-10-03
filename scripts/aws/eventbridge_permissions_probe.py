#!/usr/bin/env python3
"""Capture EventBridge bus policies on unique buses and an owned IAM role."""
import argparse
import datetime
import gzip
import json
import os
from pathlib import Path
import re
import time
import uuid

from aws_cli import call, observe


def policy_language_cases(arn, member):
    """Independent full-policy admission cases beyond the basic API forms."""
    head, bus_name = arn.split(":event-bus/", 1)
    return [
        ("action-all", {"Action": "*"}),
        ("not-action", {"Action": None, "NotAction": "events:PutEvents"}),
        ("not-resource", {"Resource": None, "NotResource": arn + "-other"}),
        ("not-principal", {"Effect": "Deny", "Principal": None, "NotPrincipal": {"AWS": member}}),
        ("unknown-action-pattern", {"Action": "events:NoSuch*"}),
        ("resource-region-wildcard", {"Resource": arn.replace(":us-east-1:", ":*:")}),
        ("resource-account-wildcard", {"Resource": arn.replace(head.split(":")[4], "*")}),
        ("resource-partition-wildcard", {"Resource": arn.replace("arn:aws:", "arn:*:")}),
        ("resource-bus-wildcard", {"Resource": head + ":event-bus/*"}),
        ("resource-rule-wildcard", {"Resource": head + ":rule/*"}),
        ("resource-other-rule-bus", {"Resource": head + ":rule/other/*"}),
        ("resource-own-rule", {"Resource": head + ":rule/" + bus_name + "/owned"}),
        ("resource-own-rule-pattern", {"Resource": head + ":rule/" + bus_name + "/*"}),
        ("resource-array-unrelated", {"Resource": [arn, arn + "-other"]}),
    ]


def capture_creator_authority(run, env, account, member, prefix):
    """Isolate creator conditions from earlier bus-policy propagation."""
    buses = [(prefix + "-strict", "StringEquals", member),
             (prefix + "-if-exists", "StringEqualsIfExists", member),
             (prefix + "-wrong", "StringEquals", account)]
    attempted = []
    try:
        for name, operator, creator in buses:
            label = name[len(prefix) + 1:]
            run(label + "-create-bus", "CreateEventBus", {"Name": name})
            statement = {"Sid": "creator", "Effect": "Allow", "Principal": {"AWS": member},
                         "Action": ["events:PutRule", "events:DescribeRule", "events:DeleteRule"],
                         "Resource": "arn:aws:events:us-east-1:" + account + ":rule/" + name + "/*",
                         "Condition": {operator: {"events:creatorAccount": creator}}}
            run(label + "-grant", "PutPermission", {"EventBusName": name,
                "Policy": json.dumps({"Version": "2012-10-17", "Statement": [statement]}, separators=(",", ":"))})
        started = time.monotonic()
        for seconds in [0, 30, 60]:
            remaining = seconds - (time.monotonic() - started)
            if remaining > 0:
                time.sleep(remaining)
            for name, _, creator in buses:
                if creator == account and seconds == 60:
                    continue
                rule = "fresh-" + str(seconds)
                attempted.append((name, rule))
                run(name[len(prefix) + 1:] + "-create-" + str(seconds), "PutRule", {
                    "EventBusName": "arn:aws:events:us-east-1:" + account + ":event-bus/" + name,
                    "Name": rule, "EventPattern": '{"source":["stackd.creator"]}'}, "member")
    finally:
        for name, rule in attempted:
            call("events", "delete-rule", {"EventBusName": name, "Name": rule}, env)
        for name, _, _ in buses:
            call("events", "delete-event-bus", {"Name": name}, env)


def capture_permission_boundaries(run, env, account, member, prefix):
    """Capture action admission and authority without the IAM lifecycle probe."""
    name = prefix + "-actions"
    arn = "arn:aws:events:us-east-1:" + account + ":event-bus/" + name
    with gzip.open("internal/iam/catalog/data/catalog.json.gz", "rt") as source:
        actions = next(service["actions"] for service in json.load(source) if service["prefix"] == "events")
    call("events", "create-event-bus", {"Name": name}, env)
    try:
        for action in actions:
            document = {"Version": "2012-10-17", "Statement": [{"Sid": "admission", "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::" + account + ":root"},
                "Action": action["name"], "Resource": arn}]}
            run(action["name"], "PutPermission", {"EventBusName": name,
                "Policy": json.dumps(document, separators=(",", ":"))}, section="action_admission", metadata=action)
    finally:
        call("events", "delete-event-bus", {"Name": name}, env)

    section = "permission_administration_authority"
    for label, actions in [("exact", ["events:PutPermission", "events:RemovePermission"]),
                           ("wildcard", ["events:Put*", "events:Remove*"])]:
        buses = [prefix + "-" + label + "-deny-owner", prefix + "-" + label + "-grant-member"]
        policies = []
        try:
            for bus, effect, principal in zip(buses, ["Deny", "Allow"], ["*", {"AWS": member}]):
                run(label + "-" + effect.lower() + "-create", "CreateEventBus", {"Name": bus}, section=section)
                document = {"Version": "2012-10-17", "Statement": [{"Sid": "administration", "Effect": effect,
                    "Principal": principal, "Action": actions,
                    "Resource": "arn:aws:events:us-east-1:" + account + ":event-bus/" + bus}]}
                policies.append(json.dumps(document, separators=(",", ":")))
                run(label + "-" + effect.lower() + "-policy", "PutPermission",
                    {"EventBusName": bus, "Policy": policies[-1]}, section=section)
            time.sleep(30)
            run(label + "-owner-remove-missing", "RemovePermission", {"EventBusName": buses[0], "StatementId": "missing"}, section=section)
            run(label + "-owner-identical-policy", "PutPermission", {"EventBusName": buses[0], "Policy": policies[0]}, section=section)
            run(label + "-owner-describe-policy", "DescribeEventBus", {"Name": buses[0]}, section=section)
            for form, bus in [("name", buses[1]), ("arn", "arn:aws:events:us-east-1:" + account + ":event-bus/" + buses[1])]:
                run(label + "-member-remove-missing-by-" + form, "RemovePermission",
                    {"EventBusName": bus, "StatementId": "missing"}, "member", section=section)
                run(label + "-member-identical-policy-by-" + form, "PutPermission",
                    {"EventBusName": bus, "Policy": policies[1]}, "member", section=section)
        finally:
            for bus in buses:
                call("events", "delete-event-bus", {"Name": bus}, env)

    name = prefix + "-delete"
    created = run("wildcard-delete-create", "CreateEventBus", {"Name": name}, section=section)
    if created["code"] != "Success":
        raise RuntimeError("Cannot create owned deletion probe bus")
    deleted = False
    try:
        document = {"Version": "2012-10-17", "Statement": [{"Sid": "deny-delete", "Effect": "Deny",
            "Principal": "*", "Action": "events:Delete*",
            "Resource": "arn:aws:events:us-east-1:" + account + ":event-bus/" + name}]}
        result = run("wildcard-delete-policy", "PutPermission", {"EventBusName": name,
            "Policy": json.dumps(document, separators=(",", ":"))}, section=section)
        if result["code"] != "Success":
            raise RuntimeError("Delete deny policy was not installed")
        time.sleep(30)
        deleted = run("wildcard-delete-owner", "DeleteEventBus", {"Name": name}, section=section)["code"] == "Success"
    finally:
        if not deleted:
            call("events", "remove-permission", {"EventBusName": name, "RemoveAllPermissions": True}, env)
            call("events", "delete-event-bus", {"Name": name}, env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--member-account", required=True)
    parser.add_argument("--permission-boundaries", action="store_true",
                        help="refresh only action admission and permission/deletion authority sections")
    args = parser.parse_args()
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1")
    account = call("sts", "get-caller-identity", env=env)["Account"]
    if account != args.account:
        raise RuntimeError("Caller account differs from --account")
    member = args.member_account
    credentials = call("sts", "assume-role", {
        "RoleArn": "arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole",
        "RoleSessionName": "stackd-events-permissions", "DurationSeconds": 3600}, env)["Credentials"]
    member_env = dict(env, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                      AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
                      AWS_SESSION_TOKEN=credentials["SessionToken"])
    if call("sts", "get-caller-identity", env=member_env)["Account"] != member:
        raise RuntimeError("Unexpected member role account")
    name = "stackd-events-permissions-" + uuid.uuid4().hex[:10]
    arn = "arn:aws:events:us-east-1:" + account + ":event-bus/" + name
    role_arn = "arn:aws:iam::" + account + ":role/" + name
    rule_arn = "arn:aws:events:us-east-1:" + account + ":rule/" + name + "/*"
    auth_name = name + "-auth"
    auth_arn = "arn:aws:events:us-east-1:" + account + ":event-bus/" + auth_name
    role_bus = name + "-role"
    role_bus_arn = "arn:aws:events:us-east-1:" + account + ":event-bus/" + role_bus
    controls_name = name + "-controls"
    controls_arn = "arn:aws:events:us-east-1:" + account + ":event-bus/" + controls_name
    path = Path(".stackd/probes/eventbridge/permissions.json")
    capture = {
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "Unique management-account buses in us-east-1/us-west-2, owned IAM role, and existing member administration role used only as caller. No organization settings or existing resources changed.",
        "sources": ["https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html",
                    "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RemovePermission.html",
                    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus-perms.html",
                    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-conditions.html"],
        "observations": [], "cleanup": False}
    if args.permission_boundaries:
        capture = json.loads(path.read_text())
        for section in ["action_admission", "permission_administration_authority"]:
            capture[section] = {"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "observations": [], "cleanup": False}
        capture["action_admission"]["source"] = "All actions in internal/iam/catalog/data/catalog.json.gz events service, full Allow policies on one fresh owned event bus"
    role_exists = False
    role_env = {}
    west = dict(env, AWS_DEFAULT_REGION="us-west-2")

    def save():
        text = json.dumps(capture, indent=2)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")

    def run(label, action, request, actor="owner", service="events", expected=None, section=None, metadata=None):
        operation = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", action)
        operation = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", operation).lower()
        actor_env = {"owner": env, "member": member_env, "owner-west": west, "owned-role": role_env}[actor]
        started = time.monotonic()
        samples = []
        while True:
            result = observe(service, operation, request, actor_env, paginate=False)
            samples.append(dict(seconds=round(time.monotonic() - started, 3), **result))
            if expected is None or result["code"] == expected or time.monotonic() - started >= 180:
                break
            print(label + ": waiting for propagation (" + result["code"] + ")", flush=True)
            time.sleep(3)
        observation = dict(case=label, action=action, input=request,
                           actor=actor, service=service, **result)
        if expected is not None:
            observation["samples"] = samples
        if metadata is not None:
            observation["metadata"] = metadata
        destination = capture[section] if section else capture
        destination["observations"].append(observation)
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    def describe(label):
        return run(label, "DescribeEventBus", {"Name": name})

    def put(label, **fields):
        return run(label, "PutPermission", dict(EventBusName=name, **fields))

    def statement(sid, **fields):
        return dict(Sid=sid, Effect="Allow", Principal={"AWS": member},
                    Action="events:PutEvents", Resource=arn, **fields)

    def policy(statements):
        return json.dumps({"Version": "2012-10-17", "Statement": statements}, separators=(",", ":"))

    def full(label, statements, **fields):
        return put(label, Policy=policy(statements), **fields)

    def clear(label):
        return run(label, "RemovePermission", {"EventBusName": name, "RemoveAllPermissions": True})

    def events(label, source="stackd.permissions", detail_type="accepted", expected=None):
        return run(label, "PutEvents", {"Entries": [{"EventBusName": auth_arn,
            "Source": source, "DetailType": detail_type, "Detail": "{}"}]}, "member", expected=expected)

    def grant_events(label, value):
        return run(label, "PutPermission", {"EventBusName": auth_name, "Policy": policy([value])})

    def assume_owned(label, expected_id):
        nonlocal role_env
        request = {"RoleArn": role_arn, "RoleSessionName": label, "DurationSeconds": 900}
        started = time.monotonic()
        samples = []
        while True:
            result = observe("sts", "assume-role", request, env)
            public = {"code": result["code"]}
            if result["code"] == "Success":
                output = result["output"]
                public["output"] = {"AssumedRoleUser": output["AssumedRoleUser"]}
                ready = output["AssumedRoleUser"]["AssumedRoleId"].startswith(expected_id + ":")
            else:
                public["error"] = result["error"]
                ready = False
            samples.append(dict(seconds=round(time.monotonic() - started, 3), **public))
            if ready or time.monotonic() - started >= 180:
                break
            time.sleep(3)
        capture["observations"].append(dict(case=label, service="sts", action="AssumeRole",
            actor="owner", input=request, samples=samples, **public))
        save()
        if not ready:
            raise RuntimeError("Owned role session did not propagate")
        issued = output["Credentials"]
        role_env = dict(env, AWS_ACCESS_KEY_ID=issued["AccessKeyId"],
                        AWS_SECRET_ACCESS_KEY=issued["SecretAccessKey"], AWS_SESSION_TOKEN=issued["SessionToken"])

    def role_events(label, expected=None):
        return run(label, "PutEvents", {"Entries": [{"EventBusName": role_bus_arn,
            "Source": "stackd.permissions", "DetailType": "role", "Detail": "{}"}]}, "owned-role", expected=expected)

    if args.permission_boundaries:
        capture_permission_boundaries(run, env, account, member, name)
        for section in ["action_admission", "permission_administration_authority"]:
            capture[section]["cleanup"] = True
        save()
        print("cleanup: True", flush=True)
        return

    try:
        run("create-bus", "CreateEventBus", {"Name": name})
        trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": account}, "Action": "sts:AssumeRole"}]})
        result = run("create-owned-role", "CreateRole", {"RoleName": name, "AssumeRolePolicyDocument": trust}, service="iam")
        if result["code"] != "Success":
            raise RuntimeError("Cannot create owned role")
        role_exists = True
        first_role_id = result["output"]["Role"]["RoleId"]
        quota_request = {"ServiceCode": "events", "QuotaCode": "L-FC354966"}
        applied = run("applied-policy-size-quota", "GetServiceQuota", quota_request, service="service-quotas")
        run("default-policy-size-quota", "GetAWSDefaultServiceQuota", quota_request, service="service-quotas")
        policy_limit = int(applied["output"]["Quota"]["Value"])
        describe("describe-without-policy")
        run("remove-absent-without-policy", "RemovePermission", {"EventBusName": name, "StatementId": "absent"})
        clear("remove-all-without-policy")
        put("put-no-parameters")
        put("put-missing-principal", Action="events:PutEvents", StatementId="missing")
        put("simple-first", Action="events:PutEvents", Principal=member, StatementId="first")
        describe("describe-simple-first")
        put("simple-identical", Action="events:PutEvents", Principal=member, StatementId="first")
        put("simple-replace-principal", Action="events:PutEvents", Principal=account, StatementId="first")
        describe("describe-simple-replaced")
        put("simple-second", Action="events:PutEvents", Principal=member, StatementId="second")
        run("list-with-policy", "ListEventBuses", {"NamePrefix": name})
        for action in ["events:PutRule", "events:PutTargets", "events:DescribeEventBus", "events:NoSuchAction", "events:*"]:
            put("simple-action-" + action.split(":")[1], Action=action, Principal=member, StatementId="action")
        for label, principal in [("star", "*"), ("invalid-account", "000000000000"),
                                 ("root-arn", "arn:aws:iam::" + member + ":root"), ("short", "123")]:
            put("simple-principal-" + label, Action="events:PutEvents", Principal=principal, StatementId="principal")
        for label, condition in [
            ("organization", {"Type": "StringEquals", "Key": "aws:PrincipalOrgID", "Value": "o-1234567890"}),
            ("source", {"Type": "StringEquals", "Key": "events:source", "Value": "stackd.permissions"}),
            ("operator", {"Type": "StringLike", "Key": "aws:PrincipalOrgID", "Value": "o-*"}),
            ("bad-organization", {"Type": "StringEquals", "Key": "aws:PrincipalOrgID", "Value": "not-an-org"})]:
            put("simple-condition-" + label, Action="events:PutEvents", Principal="*", StatementId="condition", Condition=condition)
        describe("describe-after-simple-cases")
        full("full-two-statements", [statement("fullA"), statement("fullB")])
        describe("describe-full-merge")
        changed = statement("fullA")
        changed["Principal"] = {"AWS": account}
        full("full-overlap-and-new", [changed, statement("fullC")])
        describe("describe-full-overlap")
        full("full-with-simple-fields", [statement("mixed")], Action="events:PutEvents", Principal=member, StatementId="mixed")
        full("full-with-simple-sid", [statement("mixed")], StatementId="mixed")
        full("full-duplicate-sids", [statement("duplicate"), statement("duplicate")])
        no_sid = statement("ignored")
        del no_sid["Sid"]
        full("full-missing-sid", [no_sid])
        full("full-object-statement", statement("object"))
        describe("describe-full-shapes")
        for label, value in [("empty-object", "{}"), ("empty-statements", policy([])),
                             ("null", "null"), ("malformed", "{"), ("empty", "")]:
            put("full-" + label, Policy=value)
        for label, changes in [
            ("missing-resource", {"Resource": None}), ("other-resource", {"Resource": arn + "-other"}),
            ("wildcard-resource", {"Resource": "*"}), ("iam-action", {"Action": "iam:ListUsers"}),
            ("unknown-event-action", {"Action": "events:NoSuchAction"}),
            ("wildcard-action", {"Action": "events:*"}),
            ("service-principal", {"Principal": {"Service": "events.amazonaws.com"}}),
            ("propagating-role-principal", {"Principal": {"AWS": role_arn}}),
            ("string-principal", {"Principal": "*"}),
            ("unknown-principal", {"Principal": {"AWS": "000000000000"}}),
            ("deny", {"Effect": "Deny", "Principal": {"AWS": member}})]:
            value = statement("validation")
            value.update(changes)
            value = {key: val for key, val in value.items() if val is not None}
            full("full-" + label, [value])
        describe("describe-after-validation")
        for label, changes in policy_language_cases(arn, member):
            value = statement("language")
            value.update(changes)
            full("language-" + label, [{key: val for key, val in value.items() if val is not None}])
        run("remove-unknown", "RemovePermission", {"EventBusName": name, "StatementId": "unknown"})
        run("remove-no-selector", "RemovePermission", {"EventBusName": name})
        run("remove-false-no-selector", "RemovePermission", {"EventBusName": name, "RemoveAllPermissions": False})
        run("remove-false-with-selector", "RemovePermission", {"EventBusName": name, "StatementId": "fullB", "RemoveAllPermissions": False})
        run("remove-true-with-selector", "RemovePermission", {"EventBusName": name, "StatementId": "fullA", "RemoveAllPermissions": True})
        describe("describe-after-remove-selectors")
        clear("clear-before-size")
        tiny = policy([statement("size")])
        put("full-whitespace-over-10k", Policy=tiny + " " * 10240)
        clear("clear-after-whitespace-size")
        for size in [10240, 10241, policy_limit - 1, policy_limit, policy_limit + 1]:
            value = statement("size")
            value["Principal"] = {"AWS": "arn:aws:iam::" + member + ":root"}
            value["Condition"] = {"StringEquals": {"events:source": ""}}
            value["Condition"]["StringEquals"]["events:source"] = "x" * (size - len(policy([value])))
            full("full-compact-bytes-" + str(size), [value])
        describe("describe-after-size")
        clear("clear-before-role")
        run("create-role-bus", "CreateEventBus", {"Name": role_bus})
        role_statement = statement("role")
        role_statement["Principal"] = {"AWS": role_arn}
        role_statement["Resource"] = role_bus_arn
        run("full-existing-role-principal", "PutPermission", {"EventBusName": role_bus, "Policy": policy([role_statement])}, expected="Success")
        run("describe-role-before-delete", "DescribeEventBus", {"Name": role_bus})
        assume_owned("assume-original-role", first_role_id)
        role_events("original-role-events", expected="Success")
        run("delete-owned-role", "DeleteRole", {"RoleName": name}, service="iam")
        role_exists = False
        deleted_at = time.monotonic()
        run("describe-role-after-delete", "DescribeEventBus", {"Name": role_bus})
        clear("clear-before-cross-account")
        run("create-authorization-bus", "CreateEventBus", {"Name": auth_name})
        events("member-events-without-resource-grant")
        event_grant = statement("eventGrant")
        event_grant["Resource"] = auth_arn
        event_grant["Condition"] = {"StringEquals": {"events:source": "stackd.permissions", "events:detail-type": "accepted"}, "Bool": {"events:eventBusInvocation": "false"}}
        grant_events("grant-member-filtered-events", event_grant)
        events("member-events-allowed", expected="Success")
        events("member-events-wrong-source", source="stackd.other")
        events("member-events-wrong-detail-type", detail_type="other")
        run("member-mixed-authorized-events", "PutEvents", {"Entries": [
            {"EventBusName": auth_arn, "Source": "stackd.permissions", "DetailType": "accepted", "Detail": "{}"},
            {"EventBusName": auth_arn, "Source": "stackd.other", "DetailType": "accepted", "Detail": "{}"}]}, "member")
        event_grant["Condition"]["Bool"]["events:eventBusInvocation"] = "true"
        grant_events("grant-only-bus-invocations", event_grant)
        events("member-direct-events-bus-invocation-true", expected="AccessDeniedException")
        run("create-controls-bus", "CreateEventBus", {"Name": controls_name})
        controls = statement("ruleGrant")
        controls.update(Action=["events:PutRule", "events:DescribeRule", "events:DeleteRule", "events:EnableRule", "events:DisableRule", "events:PutTargets", "events:ListTargetsByRule", "events:RemoveTargets"], Resource=rule_arn.replace(name, controls_name))
        controls["Condition"] = {"StringEquals": {"events:creatorAccount": member}}
        run("grant-member-strict-creator", "PutPermission", {"EventBusName": controls_name, "Policy": policy([controls])})
        rule = {"EventBusName": controls_arn, "Name": "member-created"}
        run("member-create-strict-creator", "PutRule", dict(rule, EventPattern='{"source":["stackd.permissions"]}'), "member", expected="Success")
        controls["Condition"] = {"StringEqualsIfExists": {"events:creatorAccount": member}}
        run("grant-member-creator-if-exists", "PutPermission", {"EventBusName": controls_name, "Policy": policy([controls])})
        run("member-create-creator-if-exists", "PutRule", dict(rule, EventPattern='{"source":["stackd.permissions"]}'), "member")
        run("owner-describe-member-rule", "DescribeRule", rule)
        run("member-describe-own-rule", "DescribeRule", rule, "member")
        run("member-disable-own-rule", "DisableRule", rule, "member")
        targets = {"EventBusName": controls_arn, "Rule": "member-created"}
        run("member-put-own-target", "PutTargets", dict(targets, Targets=[{"Id": "owned", "Arn": "arn:aws:sqs:us-east-1:" + account + ":" + name}]), "member")
        run("member-list-own-targets", "ListTargetsByRule", targets, "member")
        run("member-remove-own-target", "RemoveTargets", dict(targets, Ids=["owned"]), "member")
        owner_rule = {"EventBusName": controls_arn, "Name": "owner-created"}
        run("owner-create-rule", "PutRule", dict(owner_rule, EventPattern='{"source":["stackd.permissions"]}'))
        run("member-update-owner-rule", "PutRule", dict(owner_rule, EventPattern='{"source":["stackd.other"]}'), "member")
        run("member-describe-owner-rule", "DescribeRule", owner_rule, "member")
        run("member-delete-owner-rule", "DeleteRule", owner_rule, "member")
        run("member-delete-own-rule", "DeleteRule", rule, "member")
        run("owner-delete-rule", "DeleteRule", owner_rule)
        run("create-west-bus", "CreateEventBus", {"Name": name}, "owner-west")
        west_arn = "arn:aws:events:us-west-2:" + account + ":event-bus/" + name
        run("east-describe-west-arn", "DescribeEventBus", {"Name": west_arn})
        run("west-describe-east-arn", "DescribeEventBus", {"Name": arn}, "owner-west")
        run("east-put-rule-west-arn", "PutRule", {"EventBusName": west_arn, "Name": "cross-region", "EventPattern": '{"source":["stackd.permissions"]}'})
        run("west-list-rules", "ListRules", {"EventBusName": name}, "owner-west")
        run("east-list-rules", "ListRules", {"EventBusName": name})
        run("east-permission-west-arn", "PutPermission", {"EventBusName": west_arn, "Action": "events:PutEvents", "Principal": member, "StatementId": "cross-region"})
        elapsed = time.monotonic() - deleted_at
        if elapsed < 60:
            time.sleep(60 - elapsed)
        run("describe-role-deleted-after-sixty-seconds", "DescribeEventBus", {"Name": role_bus})
        result = run("recreate-owned-role", "CreateRole", {"RoleName": name, "AssumeRolePolicyDocument": trust}, service="iam")
        if result["code"] != "Success":
            raise RuntimeError("Cannot recreate owned role")
        role_exists = True
        second_role_id = result["output"]["Role"]["RoleId"]
        assume_owned("assume-recreated-role", second_role_id)
        run("describe-role-after-recreate", "DescribeEventBus", {"Name": role_bus})
        role_events("recreated-role-events-before-rebind")
        time.sleep(60)
        role_events("recreated-role-events-after-sixty-seconds")
        run("describe-role-after-sixty-seconds", "DescribeEventBus", {"Name": role_bus})
        run("resubmit-identical-role-policy", "PutPermission", {"EventBusName": role_bus, "Policy": policy([role_statement])})
        run("describe-role-after-identical-policy", "DescribeEventBus", {"Name": role_bus})
        role_events("recreated-role-events-after-identical-policy")
        run("remove-bound-role-statement", "RemovePermission", {"EventBusName": role_bus, "StatementId": "role"})
        run("describe-after-role-statement-removed", "DescribeEventBus", {"Name": role_bus})
        run("rebind-role-principal", "PutPermission", {"EventBusName": role_bus, "Policy": policy([role_statement])}, expected="Success")
        run("describe-role-after-rebind", "DescribeEventBus", {"Name": role_bus})
        role_events("recreated-role-events-after-rebind", expected="Success")
        capture_creator_authority(run, env, account, member, name + "-creator")
    finally:
        cleanup = []
        cleanup.append(observe("events", "delete-event-bus", {"Name": auth_name}, env))
        cleanup.append(observe("events", "delete-event-bus", {"Name": role_bus}, env))
        for actor_env, bus_name in [(env, name), (env, controls_name), (west, name)]:
            for rule_name in ["member-created", "owner-created", "cross-region"]:
                cleanup.append(observe("events", "remove-targets", {"EventBusName": bus_name, "Rule": rule_name, "Ids": ["owned"]}, actor_env))
                cleanup.append(observe("events", "delete-rule", {"EventBusName": bus_name, "Name": rule_name}, actor_env))
            cleanup.append(observe("events", "delete-event-bus", {"Name": bus_name}, actor_env))
        if role_exists:
            cleanup.append(observe("iam", "delete-role", {"RoleName": name}, env))
        failures = [result for result in cleanup if result["code"] not in ["Success", "ResourceNotFoundException", "NoSuchEntity"]]
        if failures:
            raise RuntimeError("Owned cleanup failed: " + json.dumps(failures))
        capture["cleanup"] = True
        save()
        print("cleanup: True", flush=True)


if __name__ == "__main__":
    main()
