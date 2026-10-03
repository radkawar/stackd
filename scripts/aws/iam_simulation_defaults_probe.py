#!/usr/bin/env python3
"""Bounded, read-only probes of implicit IAM custom-simulation context.

Run --capture --phase baseline first; controls/variables are independent bounded
follow-ups. All policies and CallerArn values are fixture-controlled. No AWS
resources, identities or credentials are created, and no credential values or
authentication headers are retained. Only confirmed current behavior is retained;
discovery-only candidates and character reconstruction are deliberately excluded.
"""

import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from iam_simulation_probe import call, policy, stamp, statement


ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / '.stackd/probes/iam/simulation_defaults.json'
CALLER = "arn:aws:iam::123456789012:user/simulation/default-probe"
KEY = "aws:userid"
DEFAULT_USER_ID = "STUB_PRINCIPAL_FOR_POLICY_SIMULATOR"


def cases(phase):
    rows = []

    def add(label, operator, value, key=KEY, **parameters):
        request = {"ActionNames": ["s3:GetObject"],
                   "PolicyInputList": [policy(statement(Condition={operator: {key: value}}))],
                   **parameters}
        rows.append((phase + "_" + label, request))

    operators = [("null_false", "Null", "false"), ("null_true", "Null", "true"),
                 ("like_any", "StringLike", "*"), ("notlike_any", "StringNotLike", "*"),
                 ("equals_empty", "StringEquals", ""), ("not_equals_empty", "StringNotEquals", ""),
                 ("equals_star", "StringEquals", "*"), ("equals_self", "StringEquals", "${aws:userid}"),
                 ("any_like", "ForAnyValue:StringLike", "*"), ("all_like", "ForAllValues:StringLike", "*"),
                 ("any_not_empty", "ForAnyValue:StringNotEquals", ""), ("all_not_empty", "ForAllValues:StringNotEquals", ""),
                 ("ifexists_equals", "StringEqualsIfExists", "stackd-explicit"),
                 ("ifexists_not_equals", "StringNotEqualsIfExists", "stackd-explicit"),
                 ("any_equals_self", "ForAnyValue:StringEquals", "${aws:userid}"),
                 ("bool_false", "Bool", "false"), ("numeric_zero", "NumericEquals", "0")]

    if phase == "baseline":
        for label, operator, value in operators:
            add("userid_" + label, operator, value)
        for label, key in [("account", "aws:PrincipalAccount"), ("arn", "aws:PrincipalArn"),
                           ("username", "aws:username"), ("missing", "stack:missing")]:
            add(label + "_present", "Null", "false", key=key)
            add(label + "_like_any", "StringLike", "*", key=key)
            add(label + "_equals_self", "StringEquals", "${" + key + "}", key=key)
    elif phase == "controls":
        for label, kind, values in [("string", "string", ["stackd-explicit"]),
                                    ("list", "stringList", ["stackd-explicit"]),
                                    ("empty_string", "string", [""])]:
            entries = [{"ContextKeyName": KEY, "ContextKeyType": kind, "ContextKeyValues": values}]
            for suffix, operator, value in operators:
                if suffix not in ("null_false", "like_any", "equals_self", "ifexists_equals", "any_like", "bool_false", "numeric_zero"):
                    continue
                add(label + "_" + suffix, operator, value, ContextEntries=entries)
        for suffix, operator, value in operators:
            if suffix not in ("null_false", "like_any", "equals_self", "ifexists_equals", "any_like", "bool_false", "numeric_zero"):
                continue
            add("caller_userid_" + suffix, operator, value, CallerArn=CALLER)
        for label, key, expected in [("account", "aws:PrincipalAccount", "123456789012"),
                                     ("arn", "aws:PrincipalArn", CALLER), ("username", "aws:username", "default-probe")]:
            add("caller_" + label + "_present", "Null", "false", key=key, CallerArn=CALLER)
            add("caller_" + label + "_expected", "StringEquals", expected, key=key, CallerArn=CALLER)
    elif phase == "variables":
        for suffix, parameters in [("default", {}), ("caller", {"CallerArn": CALLER})]:
            add(suffix + "_self_inequality", "StringNotEquals", "${aws:userid}", **parameters)
    elif phase == "verified":
        for attempt in range(3):
            add("default_exact_repeat" + str(attempt + 1), "StringEquals", DEFAULT_USER_ID)
        add("default_not_equals", "StringNotEquals", DEFAULT_USER_ID)
        add("default_case_sensitive", "StringEquals", DEFAULT_USER_ID.lower())
        add("default_ignore_case", "StringEqualsIgnoreCase", DEFAULT_USER_ID.lower())
        add("default_variable", "StringEquals", "${aws:userid}", key="stack:provided", ContextEntries=[{"ContextKeyName": "stack:provided", "ContextKeyType": "string", "ContextKeyValues": [DEFAULT_USER_ID]}])
        rows.append((phase + "_resource_variable", {"ActionNames": ["s3:GetObject"], "PolicyInputList": [policy(statement(resource="arn:aws:s3:::stackd-simulation/${aws:userid}"))], "ResourceArns": ["arn:aws:s3:::stackd-simulation/" + DEFAULT_USER_ID]}))
        for label, caller in [("first", CALLER), ("second", "arn:aws:iam::999999999999:user/other")]:
            add("caller_" + label + "_exact", "StringEquals", caller, CallerArn=caller)
            add("caller_" + label + "_not_default", "StringEquals", DEFAULT_USER_ID, CallerArn=caller)
        for label, parameters in [("default", {}), ("caller", {"CallerArn": CALLER})]:
            add("override_" + label, "StringEquals", "stackd-explicit", ContextEntries=[{"ContextKeyName": "AWS:USERID", "ContextKeyType": "string", "ContextKeyValues": ["stackd-explicit"]}], **parameters)
    elif phase == "empty":
        for kind, values in [("string", [""]), ("stringList", [""]), ("stringList", ["", "known"])]:
            label = kind + ("_mixed" if len(values) > 1 else "")
            for suffix, operator, value in [("null_false", "Null", "false"), ("null_true", "Null", "true"),
                                             ("any_like", "ForAnyValue:StringLike", "*"), ("any_equals_empty", "ForAnyValue:StringEquals", ""),
                                             ("all_equals_empty", "ForAllValues:StringEquals", ""), ("all_equals_known", "ForAllValues:StringEquals", "known")]:
                add(label + "_" + suffix, operator, value, key="stack:empty", ContextEntries=[{"ContextKeyName": "stack:empty", "ContextKeyType": kind, "ContextKeyValues": values}])
    return rows


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true", required=True)
    parser.add_argument("--phase", required=True, choices=("baseline", "controls", "variables", "verified", "empty"))
    parser.add_argument("--account", required=True)
    arguments = parser.parse_args()
    require_account(arguments.account)
    started = stamp()
    inputs = cases(arguments.phase)
    previous = json.loads(DESTINATION.read_text()) if DESTINATION.exists() else {}
    fixture = {"schema_version": 1,
               "source": "Real AWS IAM SimulateCustomPolicy; controlled policies, context entries and hypothetical callers only",
               "endpoint": "https://iam.amazonaws.com", "region": "us-east-1", "api_version": "2010-05-08",
               "probe": "scripts/aws/iam_simulation_defaults_probe.py",
               "aws_cli_version": subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
               "documentation": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html",
                                 "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-userid"],
               "sanitization": "All retained inputs are fixture-controlled. Caller account is verified with STS before capture; no authenticated identity or credential is retained. Raw debug logs and authentication headers are discarded.",
               "resource_writes": False, "cleanup_verified": True, "capture_complete": False,
               "observations": previous.get("observations", []), "capture_runs": previous.get("capture_runs", [])}
    run = {"phase": arguments.phase, "started_at": started, "capture_complete": False, "observations": 0}
    fixture["capture_runs"].append(run)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = executor.map(lambda item: call("simulate-custom-policy", item[1], debug=True), inputs)
        for (name, parameters), result in zip(inputs, results):
            fixture["observations"][:] = [item for item in fixture["observations"] if item["case"] != name]
            row = {"case": name, "phase": arguments.phase, "operation": "SimulateCustomPolicy", "observed_at": stamp(), "input": parameters, **result}
            fixture["observations"].append(row)
            run["observations"] += 1
            run["finished_at"] = stamp()
            DESTINATION.parent.mkdir(parents=True, exist_ok=True)
            DESTINATION.write_text(json.dumps(fixture, indent=2) + "\n")
            decisions = [item["EvalDecision"] for item in result.get("output", {}).get("EvaluationResults", [])]
            print(name, result["code"], decisions, flush=True)
    run["capture_complete"] = True
    fixture["capture_complete"] = all(item["capture_complete"] for item in fixture["capture_runs"])
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(json.dumps(fixture, indent=2) + "\n")


if __name__ == "__main__":
    main()
