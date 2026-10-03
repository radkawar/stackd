#!/usr/bin/env python3
"""Capture free DocumentDB read/error contracts; never provision an AWS engine."""
import argparse
import datetime
import json
import secrets
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing a probe outside the authorized account")
    client = session.client("docdb")
    name = "stackd-next-docdb-" + secrets.token_hex(6)
    observations = []
    for operation, parameters in [
        ("describe_db_clusters", {"DBClusterIdentifier": name}),
        ("describe_db_instances", {"DBInstanceIdentifier": name}),
        ("describe_db_cluster_snapshots", {"DBClusterSnapshotIdentifier": name}),
        ("describe_db_cluster_parameter_groups", {"DBClusterParameterGroupName": name}),
        ("describe_db_clusters", {"MaxRecords": 1}),
        ("describe_db_engine_versions", {"Engine": "docdb", "EngineVersion": "5.0"}),
    ]:
        try:
            response = getattr(client, operation)(**parameters)
            meta = response.pop("ResponseMetadata")
            observations.append({"operation": operation, "parameters": parameters,
                                 "request_id": meta["RequestId"], "status": meta["HTTPStatusCode"],
                                 "response": response})
        except ClientError as error:
            response = error.response
            observations.append({"operation": operation, "parameters": parameters,
                                 "request_id": response["ResponseMetadata"]["RequestId"],
                                 "status": response["ResponseMetadata"]["HTTPStatusCode"],
                                 "error": response["Error"]})
    evidence = {"captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "account": identity["Account"], "region": "us-east-1", "owned_prefix": name,
                "mutations": [], "cleanup": "No AWS resources created or modified; read-only probe.",
                "sources": ["https://docs.aws.amazon.com/documentdb/latest/developerguide/API_DescribeDBClusters.html",
                            "https://docs.aws.amazon.com/documentdb/latest/developerguide/functional-differences.html"],
                "observations": observations}
    Path(args.output).write_text(json.dumps(evidence, indent=2, default=str) + "\n")
    print(json.dumps({"observations": len(observations), "mutations": 0, "output": args.output}))


if __name__ == "__main__":
    main()
