#!/usr/bin/env python3
"""Re-run the exclusively owned native CloudWatch/RGTA dashboard boundary."""
import argparse
import datetime
import json
import os
from pathlib import Path
import uuid
from aws_cli import call, observe
from signed_requests import observe_json

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/resourcegroupstaggingapi/dashboard.json"))
    args = parser.parse_args()
    identity = call("sts", "get-caller-identity")
    if identity["Account"] != args.account:
        raise RuntimeError("Only authorized native account may be probed")
    name = "stackd-tag-dashboard-owned-" + uuid.uuid4().hex[:10]
    arn = "arn:aws:cloudwatch::" + identity["Account"] + ":dashboard/" + name
    environment = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="1")
    rows = []
    def native(label, operation, parameters):
        rows.append({"case": label, "service": "cloudwatch", "operation": operation, "input": parameters,
                     **observe("cloudwatch", operation, parameters, environment)})
    try:
        native("create", "put-dashboard", {"DashboardName": name, "DashboardBody": '{"widgets":[]}'})
        native("native-tag", "tag-resource", {"ResourceARN": arn, "Tags": [{"Key": "stackd-tagging-dashboard", "Value": name}]})
        native("native-tags", "list-tags-for-resource", {"ResourceARN": arn})
        for label, operation, parameters in (("direct-discovery", "GetResources", {"ResourceARNList": [arn]}),
                                             ("tagging-mutation", "TagResources", {"ResourceARNList": [arn], "Tags": {"roundtrip": "rgta"}}),
                                             ("after-tagging-discovery", "GetResources", {"ResourceARNList": [arn]})):
            rows.append({"case": label, "operation": operation, "input": parameters,
                         **observe_json("tagging.us-east-1.amazonaws.com", "tagging", "ResourceGroupsTaggingAPI_20170126." + operation, parameters)})
        native("native-after-tagging", "list-tags-for-resource", {"ResourceARN": arn})
    finally:
        native("cleanup", "delete-dashboards", {"DashboardNames": [name]})
        native("absence", "get-dashboard", {"DashboardName": name})
        destination = args.output
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps({"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scope": "Exclusively owned empty dashboard, no standing policy/resource changes", "name": name, "arn": arn, "observations": rows}, indent=2) + "\n")
    print(json.dumps({"fixture": str(destination), "cleanup": rows[-2:]}))

if __name__ == "__main__":
    main()
