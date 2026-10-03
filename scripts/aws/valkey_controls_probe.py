#!/usr/bin/env python3
"""Capture owned free ElastiCache/MemoryDB controls; never provision a cluster."""
import argparse
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[2] / ".stackd/probes/valkey/controls.json")
    parser.add_argument("--services", nargs="+", choices=("elasticache", "memorydb"), default=("elasticache", "memorydb"))
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    output = args.output
    if output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    config = Config(region_name="us-east-1", retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts", config=config).get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Native calibration is restricted to the authorized account")
    clients = {name: session.client(name, config=config) for name in ("elasticache", "memorydb", "cloudtrail")}
    prefix = "stackd-valkey-" + uuid.uuid4().hex[:12]
    fixture = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "region": "us-east-1",
               "identity": document(identity), "prefix": prefix,
               "scope": "Two uniquely owned free parameter groups and two users. No cache/database cluster, subnet, standing resource or account default mutation.",
               "calls": [], "owned": [], "cleanup": [],
               "redaction": "Owner sanitization replaces supplied passwords; this is not a statement about AWS redaction.",
               "unverified": ["billable cluster lifecycle", "AWS TLS/replication/storage behavior", "distributed MemoryDB durability", "CloudTrail data events"]}

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document(fixture), indent=2) + "\n")

    def call(service, operation, parameters, case):
        recorded = json.loads(json.dumps(parameters))
        if "Passwords" in recorded:
            recorded["Passwords"] = ["<owner-redacted>"] * len(recorded["Passwords"])
        if "AuthenticationMode" in recorded and "Passwords" in recorded["AuthenticationMode"]:
            recorded["AuthenticationMode"]["Passwords"] = ["<owner-redacted>"] * len(recorded["AuthenticationMode"]["Passwords"])
        row = {"service": service, "operation": operation, "input": recorded, "case": case}
        try:
            result = getattr(clients[service], operation)(**parameters)
            metadata = result.pop("ResponseMetadata")
            row.update(code="Success", output=document(result))
        except ClientError as error:
            metadata = error.response["ResponseMetadata"]
            row.update(code=error.response["Error"]["Code"], message=error.response["Error"]["Message"])
        row.update(request_id=metadata["RequestId"], http_status=metadata["HTTPStatusCode"])
        fixture["calls"].append(row)
        save()
        print(case + ": " + row["code"], flush=True)
        return row

    save()
    try:
        for service in args.services:
            versions = "describe_cache_engine_versions" if service == "elasticache" else "describe_engine_versions"
            call(service, versions, {"Engine": "valkey", "DefaultOnly": True}, service + "-default-version")
            name = prefix + ("-ec" if service == "elasticache" else "-md")
            key = "CacheParameterGroupName" if service == "elasticache" else "ParameterGroupName"
            family_key = "CacheParameterGroupFamily" if service == "elasticache" else "Family"
            family = "valkey8" if service == "elasticache" else "memorydb_valkey7"
            create = "create_cache_parameter_group" if service == "elasticache" else "create_parameter_group"
            modify = "modify_cache_parameter_group" if service == "elasticache" else "update_parameter_group"
            reset = "reset_cache_parameter_group" if service == "elasticache" else "reset_parameter_group"
            fixture["owned"].append({"service": service, "kind": "parameters", "name": name})
            save()
            row = call(service, create, {key: name, family_key: family, "Description": "stackd owned free native calibration"}, service + "-parameters-create")
            if row["code"] != "Success":
                raise RuntimeError("Parameter creation failed: " + row["code"])
            call(service, create, {key: name, family_key: family, "Description": "duplicate"}, service + "-parameters-duplicate")
            param_key = "ParameterNameValues"
            call(service, modify, {key: name, param_key: [{"ParameterName": "timeout", "ParameterValue": "37"}]}, service + "-parameters-update")
            describe = "describe_cache_parameters" if service == "elasticache" else "describe_parameters"
            call(service, describe, {key: name, **({"Source": "user"} if service == "elasticache" else {})}, service + "-parameters-user")
            call(service, modify, {key: name, param_key: [{"ParameterName": "stackd-missing-setting", "ParameterValue": "1"}]}, service + "-parameters-unknown")
            call(service, reset, {key: name, "AllParameters": True} if service == "memorydb" else {key: name, "ResetAllParameters": True}, service + "-parameters-reset")
            user = name + "-user"
            fixture["owned"].append({"service": service, "kind": "user", "name": user})
            save()
            password = "Stackd-" + uuid.uuid4().hex + "!"
            request = {"UserId": user, "UserName": user, "Engine": "VALKEY", "AccessString": "on ~app:* +@read +ping", "Passwords": [password]} if service == "elasticache" else {"UserName": user, "AccessString": "on ~app:* +@read +ping", "AuthenticationMode": {"Type": "password", "Passwords": [password]}}
            row = call(service, "create_user", request, service + "-user-create")
            if row["code"] != "Success":
                raise RuntimeError("User creation failed: " + row["code"])
            call(service, "create_user", request, service + "-user-duplicate")
            call(service, "describe_users", {"UserId": user} if service == "elasticache" else {"UserName": user}, service + "-user-describe")
            call(service, "modify_user" if service == "elasticache" else "update_user", {"UserId": user, "AccessString": "on ~app:* +@read +@write +ping"} if service == "elasticache" else {"UserName": user, "AccessString": "on ~app:* +@read +@write +ping"}, service + "-user-update")
    finally:
        for owned in reversed(fixture["owned"]):
            service, kind, name = owned["service"], owned["kind"], owned["name"]
            if kind == "user":
                delete, describe = "delete_user", "describe_users"
                parameters = {"UserId": name} if service == "elasticache" else {"UserName": name}
                absent = "UserNotFound" if service == "elasticache" else "UserNotFoundFault"
            else:
                delete = "delete_cache_parameter_group" if service == "elasticache" else "delete_parameter_group"
                describe = "describe_cache_parameter_groups" if service == "elasticache" else "describe_parameter_groups"
                parameters = {"CacheParameterGroupName": name} if service == "elasticache" else {"ParameterGroupName": name}
                absent = "CacheParameterGroupNotFound" if service == "elasticache" else "ParameterGroupNotFoundFault"
            row = call(service, delete, parameters, service + "-cleanup-" + kind)
            deadline = time.monotonic() + 300
            while True:
                check = call(service, describe, parameters, service + "-absence-" + kind)
                if check["code"] == absent:
                    break
                if row["code"] in ("InvalidUserState", "InvalidUserStateFault"):
                    row = call(service, delete, parameters, service + "-cleanup-retry-" + kind)
                if time.monotonic() >= deadline:
                    raise RuntimeError("Owned native cleanup unproven: " + name)
                time.sleep(10)
            fixture["cleanup"].append({**owned, "gone": True, "delete_code": row["code"], "absence_code": check["code"]})
            save()
        fixture["workload_finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        requests = {row["request_id"]: row["case"] + "-" + str(i) for i, row in enumerate(fixture["calls"])}
        try:
            fixture["history"] = collect_history(lambda p: clients["cloudtrail"].lookup_events(**p), requests,
                start_time=fixture["captured_at"], end_time=fixture["workload_finished_at"],
                event_sources=("elasticache.amazonaws.com", "memorydb.amazonaws.com"), rounds=3, wait_seconds=30)
        except CollectionError as error:
            fixture["history"] = error.result
        save()
    print(json.dumps({"fixture": str(output), "requests": len(fixture["calls"]), "owned_gone": len(fixture["cleanup"]), "billed_clusters": 0}))


if __name__ == "__main__":
    main()
