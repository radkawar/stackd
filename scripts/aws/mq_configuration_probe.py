#!/usr/bin/env python3
"""Capture revision/list behavior on one exact-owned MQ configuration, no broker."""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid

from aws_cli import call, observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    region = "us-east-1"
    environment = dict(os.environ, AWS_REGION=region, AWS_DEFAULT_REGION=region,
                       AWS_ENDPOINT_URL_MQ=f"https://mq.{region}.amazonaws.com",
                       AWS_ENDPOINT_URL_STS=f"https://sts.{region}.amazonaws.com")
    account = call("sts", "get-caller-identity", env=environment)["Account"]
    if account != args.account:
        raise RuntimeError("Unexpected native calibration account")
    evidence = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source": "Native AWS MQ configuration without a broker",
        "account": account, "region": region,
        "references": ["https://docs.aws.amazon.com/amazon-mq/latest/api-reference/configurations-configuration-id-revisions.html",
                       "https://docs.aws.amazon.com/amazon-mq/latest/api-reference/configurations-configuration-id-revisions-configuration-revision.html"],
        "observations": [], "cleanup": {},
        "limitations": ["One ActiveMQ 5.18 configuration, no broker, user, runtime or concurrent writer calibration"],
    }
    configuration = None

    def record(case, operation, parameters):
        result = observe("mq", operation, parameters, environment, paginate=False)
        evidence["observations"].append({"case": case, "operation": operation,
                                         "input": parameters, "result": result})
        return result

    def update(step):
        xml = '<broker xmlns="http://activemq.apache.org/schema/core" advisorySupport="' + ("true" if step % 2 else "false") + '"/>'
        return record(f"update-{step}", "update-configuration", {
            "ConfigurationId": configuration["Id"],
            "Data": base64.b64encode(xml.encode()).decode(),
            "Description": f"revision-step-{step}",
        })

    try:
        name = "stackd-revision-" + uuid.uuid4().hex[:16]
        created = record("create", "create-configuration", {"Name": name, "EngineType": "ACTIVEMQ", "EngineVersion": "5.18"})
        if created["code"] != "Success":
            raise RuntimeError("Native configuration creation failed; see retained observation")
        configuration = created["output"]
        evidence["owned"] = {"id": configuration["Id"], "arn": configuration["Arn"], "name": name}
        for step in range(1, 7):
            if update(step)["code"] != "Success":
                raise RuntimeError("Native revision creation failed; see retained observation")
        base = {"ConfigurationId": configuration["Id"]}
        record("all-before-append", "list-configuration-revisions", base)
        first = record("first-page", "list-configuration-revisions", dict(base, MaxResults=5))
        if first["code"] != "Success" or not first["output"].get("NextToken"):
            raise RuntimeError("Native first page did not return a continuation")
        token = first["output"]["NextToken"]
        if update(7)["code"] != "Success":
            raise RuntimeError("Native append failed; see retained observation")
        continued = record("continuation-after-append", "list-configuration-revisions", dict(base, MaxResults=5, NextToken=token))
        if continued["code"] == "Success" and continued["output"].get("NextToken"):
            record("terminal-page", "list-configuration-revisions", dict(base, MaxResults=5, NextToken=continued["output"]["NextToken"]))
        record("all-after-append", "list-configuration-revisions", base)
        record("invalid-token", "list-configuration-revisions", dict(base, MaxResults=5, NextToken="invalid"))
        for maximum in [0, 1, 4, 101]:
            record(f"max-results-{maximum}", "list-configuration-revisions", dict(base, MaxResults=maximum))
        for revision in ["0", "-1", "abc", "999", "01", "+1", "-0", "1.0", "2147483647", "2147483648", "-2147483648", "-2147483649"]:
            record(f"revision-{revision}", "describe-configuration-revision", dict(base, ConfigurationRevision=revision))
    finally:
        try:
            if configuration is not None:
                deleted = record("delete-owned", "delete-configuration", {"ConfigurationId": configuration["Id"]})
                if deleted["code"] != "Success":
                    raise RuntimeError("Owned configuration deletion failed")
                absent = record("owned-absent", "describe-configuration", {"ConfigurationId": configuration["Id"]})
                evidence["cleanup"]["configuration_absent"] = absent["code"] == "NotFoundException"
                if not evidence["cleanup"]["configuration_absent"]:
                    raise RuntimeError("Owned configuration deletion was not observed")
        finally:
            with args.output.open("x") as output:
                json.dump(evidence, output, indent=2)
                output.write("\n")
    for row in evidence["observations"]:
        result = row["result"]
        print(json.dumps({"case": row["case"], "result": result.get("error", result.get("output", result))}))


if __name__ == "__main__":
    main()
