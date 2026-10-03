#!/usr/bin/env python3
"""Capture owned, free EC2/SQS/SSM tag controls and exact cleanup."""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import observe, call
from signed_requests import observe_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/resourcegroupstaggingapi/controls.json"))
    args = parser.parse_args()
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="1")
    identity = call("sts", "get-caller-identity", env=env)
    if identity["Account"] != args.account:
        raise RuntimeError("Only the authorized native account may be probed")
    name = "stackd-tags-owned-" + uuid.uuid4().hex[:12]
    account = identity["Account"]
    path = args.output
    fixture = {"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "region": "us-east-1", "identity": identity,
               "scope": "Exclusively owned free EC2 key pair, SQS queue and two SSM standard parameters; no instances or standing identity/policy changes.",
               "observations": [], "cleanup": [], "owned": {"name": name}}
    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2) + "\n")
    def native(service, operation, request, case):
        row = dict(case=case, service=service, operation=operation, input=request)
        row.update(observe(service, operation, request, env, paginate=False))
        # EC2 returns private key material; only public resource metadata is evidence.
        row.get("output", {}).pop("KeyMaterial", None)
        fixture["observations"].append(row)
        save()
        return row
    def tagging(operation, request, case):
        row = dict(case=case, service="resourcegroupstaggingapi", operation=operation, input=request)
        row.update(observe_json("tagging.us-east-1.amazonaws.com", "tagging", "ResourceGroupsTaggingAPI_20170126." + operation, request, env))
        fixture["observations"].append(row)
        save()
        return row
    queue = None
    save()
    try:
        pair = native("ec2", "create-key-pair", {"KeyName": name, "KeyType": "ed25519", "TagSpecifications": [{"ResourceType": "key-pair", "Tags": [{"Key": "stackd-probe", "Value": name}]}]}, "create-key-pair")
        if pair["code"] != "Success":
            raise RuntimeError("Owned key creation failed: " + pair["code"])
        key_arn = f"arn:aws:ec2:us-east-1:{account}:key-pair/" + pair["output"]["KeyPairId"]
        q = native("sqs", "create-queue", {"QueueName": name, "tags": {"stackd-probe": name}}, "create-queue")
        if q["code"] != "Success":
            raise RuntimeError("Owned queue creation failed: " + q["code"])
        queue = q["output"]["QueueUrl"]
        queue_arn = f"arn:aws:sqs:us-east-1:{account}:" + name
        parameter = "/" + name
        never = parameter + "-never"
        for parameter_name, tags in ((parameter, [{"Key": "stackd-probe", "Value": name}]), (never, [])):
            result = native("ssm", "put-parameter", {"Name": parameter_name, "Type": "String", "Value": "owned-tag-control", "Tags": tags}, "create-" + ("tagged" if tags else "never-tagged"))
            if result["code"] != "Success":
                raise RuntimeError("Owned parameter creation failed")
        parameter_arn = f"arn:aws:ssm:us-east-1:{account}:parameter" + parameter
        never_arn = f"arn:aws:ssm:us-east-1:{account}:parameter" + never
        arns = [key_arn, queue_arn, parameter_arn]
        fixture["owned"].update(arns=arns, never_arn=never_arn, queue_url=queue)
        save()
        tagging("GetResources", {"ResourceARNList": arns + [never_arn]}, "explicit-including-never-tagged")
        tagging("GetResources", {"ResourceARNList": [parameter_arn], "ResourcesPerPage": 1}, "arn-list-pagination-conflict")
        tagging("GetResources", {"ResourceARNList": [parameter_arn], "TagFilters": [{"Key": "stackd-probe"}]}, "arn-list-tag-filter-conflict")
        tagging("GetResources", {"ResourceARNList": [parameter_arn], "ResourceTypeFilters": ["ssm"]}, "arn-list-type-filter-conflict")
        tagging("GetResources", {"ExcludeCompliantResources": True}, "exclude-without-details")
        tagging("TagResources", {"ResourceARNList": arns + [f"arn:aws:ssm:us-east-1:{account}:parameter/{name}-absent"], "Tags": {"owner-roundtrip": "updated"}}, "mixed-native-mutations")
        native("ec2", "describe-key-pairs", {"KeyNames": [name]}, "ec2-native-after-tagging")
        native("sqs", "list-queue-tags", {"QueueUrl": queue}, "sqs-native-after-tagging")
        native("ssm", "list-tags-for-resource", {"ResourceType": "Parameter", "ResourceId": parameter}, "ssm-native-after-tagging")
        request = {"TagFilters": [{"Key": "stackd-probe", "Values": [name]}], "ResourcesPerPage": 1}
        for attempt in range(6):
            first = tagging("GetResources", request, "filtered-first-page-" + str(attempt))
            if first.get("output", {}).get("ResourceTagMappingList"):
                break
            time.sleep(5)
        token = first.get("output", {}).get("PaginationToken", "")
        while token:
            page = tagging("GetResources", dict(request, PaginationToken=token), "filtered-next-page")
            token = page.get("output", {}).get("PaginationToken", "")
        tagging("GetTagValues", {"Key": "stackd-probe"}, "current-probe-values")
        native("ssm", "remove-tags-from-resource", {"ResourceType": "Parameter", "ResourceId": parameter, "TagKeys": ["stackd-probe", "owner-roundtrip"]}, "native-remove-last-tags")
        tagging("GetResources", {"ResourceARNList": [parameter_arn, never_arn]}, "explicit-after-native-untag")
        tagging("GetResources", {"ResourceTypeFilters": ["ssm:parameter"]}, "previously-tagged-discovery")
        tagging("TagResources", {"ResourceARNList": [parameter_arn], "Tags": {"aws:reserved": "no"}}, "reserved-tag")
        tagging("GetResources", {"ResourceARNList": [parameter_arn], "IncludeComplianceDetails": True}, "current-policy-compliance")
    finally:
        for service, action, request in (("ssm", "delete-parameters", {"Names": ["/" + name, "/" + name + "-never"]}),
                                         ("sqs", "delete-queue", {"QueueUrl": queue}) if queue else ("sqs", "get-queue-url", {"QueueName": name}),
                                         ("ec2", "delete-key-pair", {"KeyName": name})):
            fixture["cleanup"].append(native(service, action, request, "cleanup-" + service))
        for service, action, request in (("ec2", "describe-key-pairs", {"KeyNames": [name]}), ("sqs", "get-queue-url", {"QueueName": name}), ("ssm", "get-parameters", {"Names": ["/" + name, "/" + name + "-never"]})):
            fixture["cleanup"].append(native(service, action, request, "absence-" + service))
        save()
    print(json.dumps({"fixture": str(path), "observations": len(fixture["observations"]), "cleanup": fixture["cleanup"]}))


if __name__ == "__main__":
    main()
