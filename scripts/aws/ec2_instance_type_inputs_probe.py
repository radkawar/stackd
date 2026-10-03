#!/usr/bin/env python3
"""Read-only EC2 instance-type admission observations; never overwrite evidence."""
import argparse
import json
from pathlib import Path

from ebs_encryption_probe import Capture, now


class InstanceTypeInputsCapture(Capture):
    def __init__(self, args):
        super().__init__(args)
        self.data.update(
            schema_version=1,
            prefix="stackd-ec2-instance-type-inputs-readonly",
            scope="Read-only DescribeInstanceTypes unknown enum, mixed selection, dry-run and server-ahead-model admission; no mutations",
            documentation=["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceTypes.html"],
            owned={},
            cleanup={"not_required": True, "reason": "No mutations or resource creation"},
            complete=False,
        )
        self.data.pop("payload", None)
        self.data.pop("sessions", None)
        self.save()

    def run(self):
        for label, parameters in (
            ("unknown-type", {"InstanceTypes": ["stackd.invalid"]}),
            ("mixed-known-and-unknown", {"InstanceTypes": ["t3.nano", "stackd.invalid"]}),
            ("unknown-type-dry-run", {"InstanceTypes": ["stackd.invalid"], "DryRun": True}),
            ("server-ahead-model-t8i", {"InstanceTypes": ["t8i.nano"]}),
        ):
            self.observe(label, "ec2", "describe_instance_types", parameters)
        self.data.update(complete=True, capture_complete_at=now())
        self.save()
        print(json.dumps({"calls": len(self.data["calls"]), "mutations": 0}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/instance_type_inputs.json"))
    args = parser.parse_args()
    args.audit_only = False
    args.cleanup_only = False
    if args.region != "us-east-1":
        parser.error("This probe is scoped to us-east-1")
    if args.output.exists():
        parser.error("Refusing to overwrite native evidence")
    InstanceTypeInputsCapture(args).run()
