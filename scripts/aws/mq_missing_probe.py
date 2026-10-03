#!/usr/bin/env python3
"""Capture MQ missing-resource errors using read-only native requests."""
import argparse
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
    broker = "b-" + str(uuid.uuid4())
    configuration = "c-" + str(uuid.uuid4())
    observations = []
    requests = [
        ("describe-broker", {"BrokerId": broker}),
        ("describe-user", {"BrokerId": broker, "Username": "missing-user"}),
        ("list-users", {"BrokerId": broker}),
        ("describe-configuration", {"ConfigurationId": configuration}),
        ("describe-configuration-revision", {"ConfigurationId": configuration, "ConfigurationRevision": "1"}),
        ("list-configuration-revisions", {"ConfigurationId": configuration}),
        ("list-tags", {"ResourceArn": f"arn:aws:mq:{region}:{account}:broker:missing:{broker}"}),
        ("list-tags", {"ResourceArn": f"arn:aws:mq:{region}:{account}:configuration:{configuration}"}),
    ]
    for operation, parameters in requests:
        observations.append({"operation": operation, "input": parameters,
                             "result": observe("mq", operation, parameters, environment, paginate=False)})
    evidence = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source": "Native AWS read-only MQ requests through AWS CLI JSON errors",
        "account": account,
        "region": region,
        "references": ["https://docs.aws.amazon.com/amazon-mq/latest/api-reference/configurations-configuration-id.html",
                       "https://docs.aws.amazon.com/amazon-mq/latest/api-reference/brokers-broker-id.html"],
        "observations": observations,
        "limitations": ["Missing randomly generated IDs only; no existing-resource, user, revision or mutation-error calibration"],
        "cleanup": {"native_resources_created": []},
    }
    with args.output.open("x") as output:
        json.dump(evidence, output, indent=2)
        output.write("\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
