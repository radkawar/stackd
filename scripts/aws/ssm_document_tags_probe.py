#!/usr/bin/env python3
"""Capture native tagging for one owned inert Command document, then delete it.

No instances, SendCommand calls, IAM mutations or standing resource changes.
Credentials remain in the SDK. Use --cleanup-only with the same output after an
interruption; the ledger binds cleanup to the verified account and owned name.
"""
import argparse
import json
from pathlib import Path
import signal
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

REGION = "us-east-1"
PREFIX = "stackd-document-tags-"
CONFIG = Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)
REFERENCES = [
    "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_" + action + ".html"
    for action in ("AddTagsToResource", "RemoveTagsFromResource", "ListTagsForResource")
]


def interrupted(signum, unused):
    raise InterruptedError("Native document probe interrupted: " + str(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    session = boto3.Session(region_name=REGION)
    identity = session.client("sts", config=CONFIG).get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside the authorized native account")
    client = session.client("ssm", config=CONFIG)
    if args.cleanup_only:
        data = json.loads(args.output.read_text())
        if data["account"] != args.account or data["region"] != REGION or not data["name"].startswith(PREFIX):
            raise RuntimeError("Cleanup ownership scope mismatch")
    else:
        if args.output.exists():
            raise RuntimeError("Refusing to overwrite evidence; choose a new output path")
        data = {
            "source": "native AWS", "account": args.account, "region": REGION,
            "name": PREFIX + uuid.uuid4().hex[:12], "sdk": {"boto3": boto3.__version__},
            "scope": {"max_owned_documents": 1, "instances": 0, "commands_executed": 0,
                      "standing_resources_mutated": False},
            "references": REFERENCES, "calls": [],
        }
    name = data["name"]

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(json.dumps(data, indent=2, default=str) + "\n")
        temporary.replace(args.output)

    def observe(label, method, **parameters):
        row = {"label": label, "operation": client.meta.method_to_api_mapping[method], "input": parameters}
        try:
            output = getattr(client, method)(**parameters)
            metadata = output.pop("ResponseMetadata", {})
            row.update(code="Success", output=output, request_id=metadata.get("RequestId"))
        except ClientError as error:
            row.update(code=error.response["Error"]["Code"], error=error.response["Error"],
                       request_id=error.response.get("ResponseMetadata", {}).get("RequestId"))
        data["calls"].append(row)
        save()
        print(label + ": " + row["code"], flush=True)
        return row

    def cleanup():
        if not any(row["label"] == "create-with-tags" and row["code"] == "Success" for row in data["calls"]):
            return
        deleted = observe("cleanup", "delete_document", Name=name)
        if deleted["code"] not in ("Success", "InvalidDocument"):
            raise RuntimeError("Cleanup failed; rerun --cleanup-only with this output")
        absent = observe("cleanup-absence", "describe_document", Name=name)
        if absent["code"] != "InvalidDocument":
            raise RuntimeError("Owned document absence was not proved")

    save()
    if args.cleanup_only:
        cleanup()
        return
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        created = observe("create-with-tags", "create_document", Name=name, DocumentType="Command",
            Content=json.dumps({"schemaVersion": "2.2", "mainSteps": [
                {"action": "aws:runShellScript", "name": "inert", "inputs": {"runCommand": ["echo never-executed"]}}]}),
            Tags=[{"Key": "source", "Value": "native"}])
        if created["code"] != "Success":
            raise RuntimeError("Owned document creation failed")
        base = {"ResourceType": "Document", "ResourceId": name}
        observe("list-created", "list_tags_for_resource", **base)
        observe("overwrite-add", "add_tags_to_resource", **base,
                Tags=[{"Key": "source", "Value": "overwritten"}, {"Key": "empty", "Value": ""}])
        observe("list-overwritten", "list_tags_for_resource", **base)
        observe("reserved-key", "add_tags_to_resource", **base, Tags=[{"Key": "AWS:blocked", "Value": "blocked"}])
        observe("fill-to-50", "add_tags_to_resource", **base, Tags=[{"Key": "k" + str(i), "Value": "x"} for i in range(48)])
        observe("exceed-50", "add_tags_to_resource", **base, Tags=[{"Key": "overflow", "Value": "x"}])
        observe("list-owned-arn", "list_tags_for_resource", ResourceType="Document",
                ResourceId="arn:aws:ssm:" + REGION + ":" + args.account + ":document/" + name)
        observe("remove-absent", "remove_tags_from_resource", **base, TagKeys=["absent"])
        observe("remove-last", "remove_tags_from_resource", **base, TagKeys=["source", "empty"] + ["k" + str(i) for i in range(48)])
        observe("list-empty", "list_tags_for_resource", **base)
        for method, extra in (("list_tags_for_resource", {}),
                              ("add_tags_to_resource", {"Tags": [{"Key": "x", "Value": "y"}]}),
                              ("remove_tags_from_resource", {"TagKeys": ["x"]})):
            observe("missing-" + method, method, ResourceType="Document", ResourceId=name + "-missing", **extra)
        observe("managed-list", "list_tags_for_resource", ResourceType="Document", ResourceId="AWS-RunShellScript")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
