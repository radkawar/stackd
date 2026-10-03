#!/usr/bin/env python3
"""Read-only IAM simulation input and resource-template observations.

Run explicitly with --capture. Every policy/resource is hypothetical; this
script creates no AWS resources and retains no credentials or raw debug logs.
"""

import argparse
import concurrent.futures
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from iam_simulation_probe import ALLOW_ALL, call, policy, stamp, statement


ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / '.stackd/probes/iam/simulation_inputs.json'


def cases():
    rows = []

    def add(name, **parameters):
        rows.append((name, {"PolicyInputList": [ALLOW_ALL],
                           "ActionNames": ["s3:GetObject"], **parameters}))

    for label, entry in [
        ("absent_all", {}),
        ("absent_type", {"ContextKeyName": "stack:key", "ContextKeyValues": ["yes"]}),
        ("absent_values", {"ContextKeyName": "stack:key", "ContextKeyType": "string"}),
        ("empty_scalar", {"ContextKeyName": "stack:key", "ContextKeyType": "string", "ContextKeyValues": []}),
        ("empty_list", {"ContextKeyName": "stack:key", "ContextKeyType": "stringList", "ContextKeyValues": []}),
        ("absent_name", {"ContextKeyType": "string", "ContextKeyValues": ["yes"]}),
        ("name_without_colon", {"ContextKeyName": "abcde", "ContextKeyType": "string", "ContextKeyValues": ["yes"]}),
    ]:
        add("input_context_" + label, ContextEntries=[entry])

    formats = {
        "numeric": ["01.00", "+1", "1e2", "0x10", " 1 ", "1e9999", "Infinity"],
        "date": ["2035", "2035-01", "2035-01-02", "2035-01-02T03:04Z", "2035-01-02T03:04:05.123+02:00", "0", "1735787045", "2035-01-02T03:04:05"],
        "ip": ["192.0.2.1", "192.0.2.0/24", "2001:db8::1", "fe80::1%eth0", "192.000.002.1"],
        "binary": ["eWVz", "eWVz\n", "YQ", "YQ==", "YR==", "", "YQ-_"],
    }
    for kind, values in formats.items():
        for index, value in enumerate(values):
            add(f"input_context_{kind}_{index}", ContextEntries=[{"ContextKeyName": "stack:key", "ContextKeyType": kind, "ContextKeyValues": [value]}])

    for kind, value, expected in [("numeric", "01.00", "1"), ("numeric", "01.00", "01.00"),
                                  ("date", "2035-01-02", "2035-01-02"), ("ip", "2001:0db8::1", "2001:db8::1"),
                                  ("binary", "YQ", "YQ==")]:
        add(f"input_coercion_{kind}_{len(rows)}", PolicyInputList=[policy(statement(Condition={"StringEquals": {"stack:key": expected}}))],
            ContextEntries=[{"ContextKeyName": "stack:key", "ContextKeyType": kind, "ContextKeyValues": [value]}])
    for label, kind, value, candidates in [
        ("numeric", "numeric", "01.00", ["1.00", "1", "1.0", "01.00", "1E+0"]),
        ("date", "date", "2035-01-02", ["2035-01-02", "2035-01-02T00:00:00Z", "2035-01-02T00:00:00.000Z", "2035-01-02T00:00:00+00:00", "2051308800", "Tue Jan 02 00:00:00 UTC 2035"]),
        ("date_zero", "date", "0", ["1970-01-01T00:00:00.000Z", "0000-01-01T00:00:00.000Z", "0"]),
        ("date_offset", "date", "2035-01-02T03:04:05+02:00", ["2035-01-02T03:04:05.000+02:00", "2035-01-02T01:04:05.000Z"]),
        ("date_fraction", "date", "2035-01-02T03:04:05.123456Z", ["2035-01-02T03:04:05.123Z", "2035-01-02T03:04:05.123456Z"]),
        ("ip", "ip", "2001:0db8::1", ["2001:0db8::1", "2001:db8::1", "2001:db8:0:0:0:0:0:1", "/2001:db8:0:0:0:0:0:1"]),
        ("binary", "binary", "YQ==", ["YQ==", "a", "61", "[97]"]),
    ]:
        names = ["stackprobe:Candidate" + str(index) for index in range(len(candidates))]
        add("input_canonical_" + label, ActionNames=names,
            PolicyInputList=[policy(*[statement(action=name, Condition={"StringEquals": {"stack:key": text}}) for name, text in zip(names, candidates)])],
            ContextEntries=[{"ContextKeyName": "stack:key", "ContextKeyType": kind, "ContextKeyValues": [value]}])

    resources = {
        "s3_objects": ["arn:aws:s3:::stackd-simulation/a", "arn:aws:s3:::stackd-simulation/b"],
        "s3_buckets": ["arn:aws:s3:::stackd-a", "arn:aws:s3:::stackd-b"],
        "iam_users": ["arn:aws:iam::123456789012:user/one", "arn:aws:iam::123456789012:user/two"],
        "iam_roles": ["arn:aws:iam::123456789012:role/one", "arn:aws:iam::123456789012:role/two"],
        "sqs_queues": ["arn:aws:sqs:us-east-1:123456789012:one", "arn:aws:sqs:us-east-1:123456789012:two"],
        "kms_keys": ["arn:aws:kms:us-east-1:123456789012:key/one", "arn:aws:kms:us-east-1:123456789012:key/two"],
        "lambda_functions": ["arn:aws:lambda:us-east-1:123456789012:function:one", "arn:aws:lambda:us-east-1:123456789012:function:two"],
        "ec2_instances": ["arn:aws:ec2:us-east-1:123456789012:instance/i-00000000000000001", "arn:aws:ec2:us-east-1:123456789012:instance/i-00000000000000002"],
    }
    actions = ["s3:GetObject", "s3:ListBucket", "s3:ListAllMyBuckets", "iam:GetUser", "iam:ListUsers", "iam:PassRole", "sts:GetCallerIdentity", "sts:AssumeRole", "sqs:SendMessage", "kms:Encrypt", "lambda:InvokeFunction", "ec2:DescribeInstances", "madeup:Action", "s3:*", "s3:MadeUp"]
    for name, arns in resources.items():
        add("input_resources_" + name, ActionNames=actions, ResourceArns=arns)
        add("input_resources_known_" + name, ActionNames=actions[:-3], ResourceArns=arns)
    add("input_resources_global_mix", ActionNames=actions, ResourceArns=["*", resources["s3_objects"][0]])
    add("input_resources_partitions", ActionNames=["sqs:SendMessage", "iam:GetUser"], ResourceArns=["arn:aws-cn:sqs:cn-north-1:123456789012:one", "arn:aws-us-gov:sqs:us-gov-west-1:123456789012:two"])
    add("input_action_groups_default", ActionNames=["s3:GetObject", "s3:MadeUp"])
    add("input_action_groups_unknown", ActionNames=["s3:MadeUp", "madeup:Action"], ResourceArns=resources["s3_objects"])
    add("input_action_groups_unknown_single", ActionNames=["s3:MadeUp"], ResourceArns=resources["s3_objects"])
    add("input_action_groups_madeup_single", ActionNames=["madeup:Action"], ResourceArns=resources["s3_objects"])
    for name, kind, values, operator, expected in [
        ("numeric_string", "string", ["1"], "NumericEquals", "1"),
        ("numeric_numeric", "numeric", ["1"], "NumericEquals", "1"),
        ("numeric_leading_zero", "numeric", ["010"], "NumericEquals", "10"),
        ("numeric_overflow", "numeric", ["1e9999"], "NumericGreaterThan", "1e100"),
        ("numeric_string_negative", "numeric", ["1"], "StringNotEquals", "1"),
        ("numeric_null", "numeric", ["1"], "Null", "false"),
        ("string_list_one", "stringList", ["yes"], "StringEquals", "yes"),
        ("string_list_many", "stringList", ["yes", "no"], "StringEquals", "yes"),
        ("string_list_many_negative", "stringList", ["yes", "no"], "StringNotEquals", "yes"),
        ("string_list_any", "stringList", ["yes", "no"], "ForAnyValue:StringEquals", "yes"),
        ("numeric_list_any_string", "numericList", ["1", "2"], "ForAnyValue:StringEquals", "1"),
        ("numeric_list_all_string_negative", "numericList", ["1", "2"], "ForAllValues:StringNotEquals", "1"),
        ("boolean_string", "string", ["true"], "Bool", "true"),
        ("date_string", "string", ["2035-01-02"], "DateEquals", "2035-01-02"),
        ("ip_string", "string", ["192.0.2.1"], "IpAddress", "192.0.2.0/24"),
        ("binary_string", "string", ["YQ=="], "BinaryEquals", "YQ=="),
        ("numeric_scalar_string", "numeric", ["1"], "StringEquals", "1"),
        ("numeric_list_scalar", "numericList", ["1"], "NumericEquals", "1"),
        ("numeric_scalar_any_string", "numeric", ["1"], "ForAnyValue:StringEquals", "1"),
        ("numeric_list_original_text", "numericList", ["01.00"], "ForAnyValue:StringEquals", "01.00"),
        ("numeric_list_normalized_text", "numericList", ["01.00"], "ForAnyValue:StringEquals", "1"),
        ("numeric_bad_string", "string", ["bad"], "NumericEquals", "1"),
        ("boolean_bad_string", "string", ["yes"], "Bool", "false"),
        ("date_bad_string", "string", ["bad"], "DateEquals", "2035-01-02"),
        ("ip_bad_string", "string", ["bad"], "IpAddress", "192.0.2.0/24"),
        ("binary_bad_string", "string", ["bad"], "BinaryEquals", "YQ=="),
        ("date_scalar_numeric", "date", ["1970-01-01"], "NumericEquals", "0"),
        ("numeric_scalar_date", "numeric", ["0"], "DateEquals", "1970-01-01"),
    ]:
        add("input_type_match_" + name, PolicyInputList=[policy(statement(Condition={operator: {"stack:key": expected}}))],
            ContextEntries=[{"ContextKeyName": "stack:key", "ContextKeyType": kind, "ContextKeyValues": values}])
    for index, value in enumerate(["arn::s3:::name", "arn:aws::::name", "arn:unknown:s3:::name", "arn:aws:s3:::", "arn:aws:s3:region:account:name", "arn:aws:s3:::*"]):
        add("input_resource_format_" + str(index), ResourceArns=[value])
    return rows


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true", required=True)
    parser.add_argument("--case-prefix", action="append", default=[])
    parser.add_argument("--account", required=True)
    arguments = parser.parse_args()
    require_account(arguments.account)
    started = stamp()
    previous = json.loads(DESTINATION.read_text()) if arguments.case_prefix and DESTINATION.exists() else {}
    observations = previous.get("observations", [])
    fixture = {"schema_version": 1, "source": "Real AWS IAM SimulateCustomPolicy; hypothetical policies and resources only",
               "endpoint": "https://iam.amazonaws.com", "region": "us-east-1", "started_at": started,
               "probe": "scripts/aws/iam_simulation_inputs_probe.py", "resource_writes": False, "cleanup_verified": True,
               "documentation": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_ContextEntry.html", "https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html"],
               "sanitization": "All resource ARNs and context values are fixture-controlled. Authentication headers and raw debug logs are discarded.",
               "observations": observations, "capture_complete": False}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        inputs = cases()
        if arguments.case_prefix:
            inputs = [item for item in inputs if any(item[0].startswith(prefix) for prefix in arguments.case_prefix)]
        results = executor.map(lambda item: call("simulate-custom-policy", item[1], debug=True), inputs)
        for (name, parameters), result in zip(inputs, results):
            observations[:] = [item for item in observations if item["case"] != name]
            observations.append({"case": name, "operation": "SimulateCustomPolicy", "input": parameters, "observed_at": stamp(), **result})
            fixture["finished_at"] = stamp()
            DESTINATION.parent.mkdir(parents=True, exist_ok=True)
            DESTINATION.write_text(json.dumps(fixture, indent=2) + "\n")
            print(name, result["code"], flush=True)
    fixture["capture_complete"] = True
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(json.dumps(fixture, indent=2) + "\n")


if __name__ == "__main__":
    main()
