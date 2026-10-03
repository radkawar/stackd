#!/usr/bin/env python3
"""Capture free, exclusively owned RDS parameter controls; never launch a DB."""
import argparse
import datetime
import json
from pathlib import Path
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/rds/controls.json"))
    args = parser.parse_args()
    config = Config(region_name="us-east-1", retries={"max_attempts": 0}, connect_timeout=10, read_timeout=30)
    session = boto3.Session()
    identity = session.client("sts", config=config).get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Calibration authorized only for designated account")
    rds = session.client("rds", config=config)
    data = session.client("rds-data", config=config)
    prefix = "stackd-rds-owned-" + uuid.uuid4().hex[:12]
    destination = args.output
    fixture = {"retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "region": "us-east-1", "identity": {k: identity[k] for k in ("Account", "Arn", "UserId")},
               "scope": "Four uniquely owned free parameter groups only. No database, existing resource, secret, or default group mutation.",
               "documentation": ["https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBParameterGroup.html",
                                 "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ResetDBParameterGroup.html",
                                 "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBCluster.html",
                                 "https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_ExecuteStatement.html"],
               "observations": [], "owned": [], "cleanup": []}

    def save():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2, default=str) + "\n")

    def observe(client, action, request, case):
        row = {"case": case, "operation": action, "input": request}
        try:
            out = getattr(client, action)(**request)
            metadata = out.pop("ResponseMetadata")
            row.update(code="Success", output=out, request_id=metadata["RequestId"], http_status=metadata["HTTPStatusCode"])
        except ClientError as error:
            out = error.response
            row.update(code=out["Error"]["Code"], message=out["Error"]["Message"],
                       request_id=out["ResponseMetadata"]["RequestId"], http_status=out["ResponseMetadata"]["HTTPStatusCode"])
        fixture["observations"].append(row)
        save()
        return row

    save()
    try:
        for family, engine in (("postgres17", "postgres"), ("mysql8.4", "mysql"),
                               ("aurora-postgresql17", "aurora-postgresql"), ("aurora-mysql8.0", "aurora-mysql")):
            cluster = engine.startswith("aurora-")
            name = prefix + "-" + engine
            key = "DBClusterParameterGroupName" if cluster else "DBParameterGroupName"
            suffix = "db_cluster_parameter_group" if cluster else "db_parameter_group"
            owned = {"name": name, "cluster": cluster}
            # Ownership retained before sending create closes response-loss cleanup gap.
            fixture["owned"].append(owned)
            save()
            created = observe(rds, "create_" + suffix, {key: name, "DBParameterGroupFamily": family,
                "Description": "stackd owned free RDS calibration", "Tags": [{"Key": "stackd-probe", "Value": prefix}]}, engine + "-create")
            if created["code"] != "Success":
                raise RuntimeError("Owned parameter group creation failed: " + created["code"])
            observe(rds, "create_" + suffix, {key: name, "DBParameterGroupFamily": family,
                "Description": "stackd owned duplicate"}, engine + "-duplicate")
            param = "statement_timeout" if "postgres" in engine else "max_connections"
            observe(rds, "modify_" + suffix, {key: name, "Parameters": [
                {"ParameterName": param, "ParameterValue": "5000" if "postgres" in engine else "151", "ApplyMethod": "immediate"}]}, engine + "-modify")
            observe(rds, "describe_db_cluster_parameters" if cluster else "describe_db_parameters", {key: name, "Source": "user"}, engine + "-user-parameters")
            observe(rds, "modify_" + suffix, {key: name, "Parameters": [
                {"ParameterName": "stackd_missing_parameter", "ParameterValue": "1", "ApplyMethod": "immediate"}]}, engine + "-unknown-parameter")
            observe(rds, "reset_" + suffix, {key: name, "ResetAllParameters": True}, engine + "-reset")
        absent = prefix + "-absent"
        observe(rds, "describe_db_instances", {"DBInstanceIdentifier": absent}, "missing-instance")
        observe(rds, "describe_db_clusters", {"DBClusterIdentifier": absent}, "missing-cluster")
        observe(data, "execute_statement", {"resourceArn": f"arn:aws:rds:us-east-1:{identity['Account']}:cluster:{absent}",
            "secretArn": f"arn:aws:secretsmanager:us-east-1:{identity['Account']}:secret:{absent}-AbCdEf", "sql": "SELECT 1"}, "missing-data-cluster")
    finally:
        failed = []
        for owned in reversed(fixture["owned"]):
            cluster = owned["cluster"]
            key = "DBClusterParameterGroupName" if cluster else "DBParameterGroupName"
            suffix = "db_cluster_parameter_group" if cluster else "db_parameter_group"
            deletion = observe(rds, "delete_" + suffix, {key: owned["name"]}, "cleanup-" + owned["name"])
            absence = observe(rds, "describe_" + suffix + "s", {key: owned["name"]}, "absence-" + owned["name"])
            expected = "DBParameterGroupNotFound"
            gone = absence["code"] == expected
            fixture["cleanup"].append({"name": owned["name"], "gone": gone, "delete_code": deletion["code"], "absence_code": absence["code"]})
            if not gone:
                failed.append(owned["name"])
            save()
        if failed:
            raise RuntimeError("Owned cleanup unproven: " + ", ".join(failed))
    print(json.dumps({"fixture": str(destination), "observations": len(fixture["observations"]),
                      "owned_resources_gone": len(fixture["cleanup"]), "database_engines_provisioned": 0}))


if __name__ == "__main__":
    main()
