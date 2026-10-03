#!/usr/bin/env python3
"""Capture native EKS absent-parent behavior without creating any resources."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import uuid


def invoke(region, operation, payload):
    process = subprocess.run(["aws", "--region", region, "--endpoint-url", f"https://eks.{region}.amazonaws.com",
                              "eks", operation, "--cli-input-json", json.dumps(payload), "--output", "json"],
                             text=True, capture_output=True, timeout=90)
    return {"region": region, "operation": operation, "input": payload, "exitCode": process.returncode,
            "output": json.loads(process.stdout) if process.stdout.strip() else None, "error": process.stderr.strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--other-region", default="us-west-2")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    identity = json.loads(subprocess.run(["aws", "--region", args.region, "--endpoint-url", f"https://sts.{args.region}.amazonaws.com",
                                        "sts", "get-caller-identity", "--output", "json"], check=True, capture_output=True, text=True).stdout)
    cluster = "stackd-ng-absent-" + uuid.uuid4().hex
    rows = []
    for region in (args.region, args.other_region):
        absent = invoke(region, "describe-cluster", {"name": cluster})
        if "(ResourceNotFoundException)" not in absent["error"]:
            raise RuntimeError("Refusing capture without a confirmed absent unique cluster: " + json.dumps(absent))
        rows.append(absent)
        base = {"clusterName": cluster, "nodegroupName": "workers"}
        for operation, payload in [
            ("list-nodegroups", {"clusterName": cluster}),
            ("describe-nodegroup", base),
            ("delete-nodegroup", base),
            ("update-nodegroup-config", dict(base, scalingConfig={"desiredSize": 1})),
            ("update-nodegroup-version", dict(base, version="1.33")),
            ("create-nodegroup", dict(base, nodeRole=f"arn:aws:iam::{identity['Account']}:role/stackd-absent-node-role",
                                      subnets=["subnet-0123456789abcdef0"], scalingConfig={"minSize": 0, "maxSize": 1, "desiredSize": 0})),
        ]:
            rows.append(invoke(region, operation, payload))
    result = {"capturedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "account": identity["Account"],
              "scope": "Unique absent parent in two native regions; no cluster, nodegroup, EC2 or IAM resources were created or mutated.",
              "sources": ["https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateNodegroup.html",
                          "https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateNodegroupVersion.html"],
              "calls": rows, "cleanup": {"createdResources": [], "required": False}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "capturedCalls": len(rows), "createdResources": []}))


if __name__ == "__main__":
    main()
