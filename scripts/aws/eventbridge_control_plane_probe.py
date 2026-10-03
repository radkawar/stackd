#!/usr/bin/env python3
"""Capture EventBridge bus/rule/target semantics using uniquely owned resources."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import uuid

from aws_cli import call, observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1")
    account = call("sts", "get-caller-identity", env=env)["Account"]
    if account != args.account:
        raise RuntimeError("Caller account differs from --account")
    name = "stackd-events-controls-" + uuid.uuid4().hex[:10]
    path = Path(".stackd/probes/eventbridge/control_plane.json")
    capture = {"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scope": "Owned event bus/rules and nonexistent owned-name SQS targets; no existing resources changed",
               "observations": [], "cleanup": False}

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(capture, indent=2) + "\n")

    def run(label, action, request):
        operation = re.sub(r"(?<!^)(?=[A-Z])", "-", action).lower()
        result = observe("events", operation, request, env, paginate=False)
        capture["observations"].append(dict(case=label, action=action, input=request, **result))
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    rule = {"Name": "paid", "EventBusName": name}
    targets = {"Rule": "paid", "EventBusName": name}
    arn = "arn:aws:events:us-east-1:" + account + ":event-bus/" + name
    rule_arn = "arn:aws:events:us-east-1:" + account + ":rule/" + name + "/paid"
    queue_arn = "arn:aws:sqs:us-east-1:" + account + ":" + name
    try:
        run("create-bus", "CreateEventBus", {"Name": name, "Description": "capture", "Tags": [{"Key": "owner", "Value": "test"}]})
        run("create-duplicate", "CreateEventBus", {"Name": name})
        run("describe-bus", "DescribeEventBus", {"Name": name})
        run("list-bus-prefix", "ListEventBuses", {"NamePrefix": name})
        run("get-bus-tags", "ListTagsForResource", {"ResourceARN": arn})
        run("create-rule", "PutRule", dict(rule, EventPattern='{"source":["stackd.controls"]}', State="DISABLED", Description="first", Tags=[{"Key": "owner", "Value": "rule"}]))
        run("describe-rule", "DescribeRule", rule)
        run("invalid-update", "PutRule", dict(rule, EventPattern='{"source":[{"unknown":"x"}]}'))
        run("after-invalid-update", "DescribeRule", rule)
        run("replace-rule", "PutRule", dict(rule, EventPattern='{"source":["stackd.controls"]}', Tags=[{"Key": "owner", "Value": "ignored-update"}]))
        run("after-replace", "DescribeRule", rule)
        run("rule-tags-after-replace", "ListTagsForResource", {"ResourceARN": rule_arn})
        run("list-rules", "ListRules", {"EventBusName": name})
        run("put-static-target", "PutTargets", dict(targets, Targets=[{"Id": "one", "Arn": queue_arn, "Input": "null", "RetryPolicy": {"MaximumRetryAttempts": 0}}]))
        run("list-static-target", "ListTargetsByRule", targets)
        run("replace-target", "PutTargets", dict(targets, Targets=[{"Id": "one", "Arn": queue_arn}]))
        run("list-replaced-target", "ListTargetsByRule", targets)
        run("delete-rule-with-target", "DeleteRule", rule)
        run("delete-bus-with-rule", "DeleteEventBus", {"Name": name})
        run("remove-unknown-target", "RemoveTargets", dict(targets, Ids=["unknown"]))
        run("remove-target", "RemoveTargets", dict(targets, Ids=["one"]))
        run("disable-rule", "DisableRule", rule)
        run("describe-disabled", "DescribeRule", rule)
        run("enable-rule", "EnableRule", rule)
        run("describe-enabled", "DescribeRule", rule)
        run("tag-rule", "TagResource", {"ResourceARN": rule_arn, "Tags": [{"Key": "second", "Value": "value"}]})
        run("list-rule-tags", "ListTagsForResource", {"ResourceARN": rule_arn})
        run("untag-rule", "UntagResource", {"ResourceARN": rule_arn, "TagKeys": ["owner", "absent"]})
        run("remaining-rule-tags", "ListTagsForResource", {"ResourceARN": rule_arn})
        run("partial-events", "PutEvents", {"Entries": [
            {"EventBusName": name, "Source": "stackd.controls", "DetailType": "control", "Detail": "{}"},
            {"EventBusName": name, "Source": "stackd.controls", "DetailType": "control", "Detail": "{"},
            {"EventBusName": name + "-missing", "Source": "stackd.controls", "DetailType": "control", "Detail": "{}"},
            {"EventBusName": name, "Source": "aws.iam", "DetailType": "control", "Detail": "{}"}]})
        run("delete-rule", "DeleteRule", rule)
        run("delete-rule-again", "DeleteRule", rule)
        run("delete-bus", "DeleteEventBus", {"Name": name})
        run("delete-bus-again", "DeleteEventBus", {"Name": name})
        run("describe-missing-bus", "DescribeEventBus", {"Name": name})
        run("delete-rule-missing-bus", "DeleteRule", rule)
    finally:
        for operation, request in [("remove-targets", dict(targets, Ids=["one"])),
                                   ("delete-rule", rule), ("delete-event-bus", {"Name": name})]:
            result = observe("events", operation, request, env)
            if result["code"] not in ["Success", "ResourceNotFoundException"]:
                raise RuntimeError("Owned cleanup failed: " + json.dumps(result))
        capture["cleanup"] = True
        save()
        print("cleanup: True", flush=True)


if __name__ == "__main__":
    main()
