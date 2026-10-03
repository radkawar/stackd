#!/usr/bin/env python3
"""Capture exclusively owned free MSK configuration controls; never launch brokers."""
import argparse
import base64
import datetime as dt
import json
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudtrail_events import CollectionError, collect_history
from cloudtrail_service_probe import document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/kafka/controls.json"))
    args = parser.parse_args()
    config = Config(region_name="us-east-1", retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)
    session = boto3.Session()
    identity = session.client("sts", config=config).get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Calibration authorized only for designated account")
    client = session.client("kafka", config=config)
    trail = session.client("cloudtrail", config=config)
    prefix = "stackd-msk-owned-" + uuid.uuid4().hex[:12]
    destination = args.output
    if destination.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    start = dt.datetime.now(dt.timezone.utc)
    fixture = {"retrieved_at": start.isoformat(), "region": "us-east-1", "identity": document(identity),
               "scope": "Uniquely owned free MSK configuration only. No cluster, brokers, VPC, secrets, billed fleet, standing trail or unrelated resource mutation.",
               "prefix": prefix, "owned": [], "calls": [], "cleanup": [],
               "documentation": ["https://docs.aws.amazon.com/msk/1.0/apireference/configurations.html",
                                 "https://docs.aws.amazon.com/msk/1.0/apireference/configurations-arn.html",
                                 "https://docs.aws.amazon.com/msk/1.0/apireference/configurations-arn-revisions-revision.html"]}

    def serial(value):
        if isinstance(value, bytes):
            return base64.b64encode(value).decode()
        raise TypeError(type(value).__name__)

    def save():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(document(fixture), default=serial, indent=2) + "\n")

    def call(label, operation, **request):
        row = {"label": label, "operation": client.meta.method_to_api_mapping[operation],
               "input": request, "started_at": dt.datetime.now(dt.timezone.utc)}
        try:
            output = getattr(client, operation)(**request)
            metadata = output.pop("ResponseMetadata")
            row.update(code="Success", output=output)
        except ClientError as error:
            output = {}
            metadata = error.response["ResponseMetadata"]
            row.update(code=error.response["Error"]["Code"], error=error.response["Error"])
        row.update(request_id=metadata["RequestId"], http_status=metadata["HTTPStatusCode"],
                   finished_at=dt.datetime.now(dt.timezone.utc))
        fixture["calls"].append(row)
        save()
        print(label + ": " + row["code"], flush=True)
        return row, output

    save()
    try:
        call("versions", "list_kafka_versions", MaxResults=100)
        fixture["owned"].append({"name": prefix})
        save()
        row, created = call("create", "create_configuration", Name=prefix, Description="owned free calibration", KafkaVersions=["3.9.x"],
                            ServerProperties=b"auto.create.topics.enable=false\nnum.partitions=3\nlog.retention.ms=600000\n")
        if row["code"] != "Success":
            raise RuntimeError("Configuration creation failed")
        arn = created["Arn"]
        fixture["owned"][0]["arn"] = arn
        save()
        call("duplicate", "create_configuration", Name=prefix, ServerProperties=b"num.partitions=1\n")
        call("describe", "describe_configuration", Arn=arn)
        call("revision-one", "describe_configuration_revision", Arn=arn, Revision=1)
        call("update", "update_configuration", Arn=arn, Description="second retained revision", ServerProperties=b"auto.create.topics.enable=true\nnum.partitions=5\nlog.retention.ms=700000\n")
        call("revision-one-after-update", "describe_configuration_revision", Arn=arn, Revision=1)
        call("revision-two", "describe_configuration_revision", Arn=arn, Revision=2)
        call("missing-revision", "describe_configuration_revision", Arn=arn, Revision=99)
        call("revisions-page", "list_configuration_revisions", Arn=arn, MaxResults=1)
        call("unknown-property", "update_configuration", Arn=arn, ServerProperties=b"stackd.unknown.property=1\n")
        call("invalid-property-value", "update_configuration", Arn=arn, ServerProperties=b"num.partitions=zero\n")
        call("empty-properties", "update_configuration", Arn=arn, ServerProperties=b"")
        call("describe-final", "describe_configuration", Arn=arn)
    finally:
        # Discover only the exact pre-recorded unique name if the create response was lost.
        for owned in fixture["owned"]:
            if "arn" not in owned:
                token = None
                for _ in range(20):
                    request = {"MaxResults": 100}
                    if token:
                        request["NextToken"] = token
                    _, output = call("cleanup-discovery", "list_configurations", **request)
                    matches = [v for v in output.get("Configurations", []) if v["Name"] == owned["name"]]
                    if matches:
                        owned["arn"] = matches[0]["Arn"]
                        break
                    token = output.get("NextToken")
                    if not token:
                        break
            if "arn" not in owned:
                fixture["cleanup"].append({"name": owned["name"], "gone": True, "evidence": "exact-name discovery absent"})
                continue
            row, _ = call("delete", "delete_configuration", Arn=owned["arn"])
            gone = False
            for attempt in range(20):
                row, _ = call("absence-" + str(attempt), "describe_configuration", Arn=owned["arn"])
                if row["code"] == "BadRequestException" and row.get("error", {}).get("Message") == "Configuration ARN does not exist.":
                    gone = True
                    break
                time.sleep(3)
            fixture["cleanup"].append({"arn": owned["arn"], "gone": gone, "absence_code": row["code"]})
            save()
            if not gone:
                raise RuntimeError("Owned configuration cleanup unproven: " + owned["arn"])
    requests = {row["request_id"]: row["label"] for row in fixture["calls"]}
    try:
        fixture["management_history"] = collect_history(lambda p: trail.lookup_events(**p), requests,
            start_time=start, event_sources=["kafka.amazonaws.com"], max_pages=10, rounds=12, wait_seconds=20)
    except CollectionError as error:
        fixture["management_history"] = error.result
        save()
        raise
    save()
    print(json.dumps({"fixture": str(destination), "calls": len(fixture["calls"]),
                      "owned_resources_gone": all(v["gone"] for v in fixture["cleanup"]),
                      "management_matches": len(fixture["management_history"]["events"]), "billed_brokers": 0}))


if __name__ == "__main__":
    main()
