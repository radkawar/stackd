#!/usr/bin/env python3
"""Capture five free CodeBuild absent-ARN controls; never create a compute fleet.

Run: PYTHONPATH=scripts/aws python3 -P scripts/aws/resource_tagging_codebuild_fleet_probe.py
"""
import argparse
import datetime
import json
from pathlib import Path
import uuid

from aws_cli import call
from codebuild_probe import request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/resourcegroupstaggingapi/codebuild_fleets.json"))
    args = parser.parse_args()
    identity = call("sts", "get-caller-identity")
    if identity["Account"] != args.account:
        raise RuntimeError("Only the authorized native probe account may be used")
    arn = ("arn:aws:codebuild:us-east-1:" + identity["Account"]
           + ":fleet/stackd-tag-update-absent-" + uuid.uuid4().hex[:12]
           + ":" + str(uuid.uuid4()))
    controls = [
        ("missing", "UpdateFleet", {"arn": arn, "tags": [{"key": "owner", "value": "native"}]}),
        ("invalid-arn", "UpdateFleet", {"arn": "not-an-arn", "tags": []}),
        ("reserved", "UpdateFleet", {"arn": arn, "tags": [{"key": "aws:owner", "value": "native"}]}),
        ("empty-key", "UpdateFleet", {"arn": arn, "tags": [{"key": "", "value": "native"}]}),
        ("absence", "BatchGetFleets", {"names": [arn]}),
    ]
    rows = []
    for label, operation, parameters in controls:
        rows.append({"case": label, "operation": operation, "input": parameters,
                     **request(operation, parameters)})
    fixture = {
        "source": "native AWS CodeBuild",
        "observed_date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "account": identity["Account"], "region": "us-east-1", "arn": arn,
        "scope": "Five signed absent-ARN/malformed-ARN controls only; no CreateFleet, no reserved capacity, no resources created.",
        "observations": rows,
    }
    destination = args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(fixture, indent=2) + "\n")
    print(json.dumps({"fixture": str(destination), "results": [(row["case"], row["code"]) for row in rows]}))


if __name__ == "__main__":
    main()
