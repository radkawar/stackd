#!/usr/bin/env python3
"""Capture exact-request ECR/CodeBuild CloudTrail evidence without starting builds.

Run with PYTHONPATH=scripts/aws python3 -B -P. --harvest accepts existing native
capture paths and performs only reads. Without it, create one tagged role/project,
exercise source-auth admission using synthetic sentinels, and delete both in finally.
--collect-only resumes history collection from an already cleaned output fixture.
"""
import argparse
import datetime
import json
import os
import pathlib
import time
import uuid

from aws_cli import call, observe, require_account
from codebuild_probe import request
from cloudtrail_events import CollectionError, collect_history

REGION = "us-east-1"
SENTINEL = "stackd-synthetic-source-auth-not-a-real-credential"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--harvest", nargs="+")
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--rounds", type=int, default=12)
    parser.add_argument("--wait-seconds", type=int, default=30)
    args = parser.parse_args()
    account = args.account
    os.environ.update(AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION, AWS_MAX_ATTEMPTS="1")
    identity = require_account(account)
    output = pathlib.Path(args.output)
    if args.collect_only:
        evidence = json.loads(output.read_text())
        if evidence["account"] != account or evidence["region"] != REGION or not evidence["cleanup_verified"]:
            raise RuntimeError("Refusing unowned or incompletely cleaned evidence")
    else:
        if output.exists():
            raise RuntimeError("Refusing to overwrite an existing capture")
        evidence = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "source": "native AWS ECR/CodeBuild exact-request CloudTrail capture",
                    "account": account, "region": REGION, "actor": identity["Arn"],
                    "calls": [], "cleanup": [], "cleanup_verified": bool(args.harvest),
                    "bounds": {"builds": 0, "roles": 0 if args.harvest else 1,
                               "projects": 0 if args.harvest else 1, "history_pages_per_round": 20,
                               "history_rounds": args.rounds, "wait_seconds": args.wait_seconds},
                    "documentation": ["https://docs.aws.amazon.com/AmazonECR/latest/userguide/logging-using-cloudtrail.html",
                                      "https://docs.aws.amazon.com/codebuild/latest/userguide/service-name-info-in-cloudtrail.html",
                                      "https://docs.aws.amazon.com/codebuild/latest/userguide/understanding-service-name-entries.html"]}

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + "\n")

    def record(label, operation, parameters, result, cleanup=False):
        evidence["cleanup" if cleanup else "calls"].append(
            {"label": label, "service": "codebuild", "operation": operation,
             "parameters": parameters, **result})
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    def cb(label, operation, parameters, cleanup=False):
        return record(label, operation, parameters, request(operation, parameters), cleanup)

    if args.harvest and not args.collect_only:
        starts = []
        seen = set()
        for filename in args.harvest:
            capture = json.loads(pathlib.Path(filename).read_text())
            if capture["account"] != account or capture["region"] != REGION:
                raise RuntimeError("Refusing capture from another account or region")
            starts.append(capture["observed_at"])
            service = pathlib.Path(filename).parent.name
            if service not in ("ecr", "codebuild"):
                raise RuntimeError("Only ECR/CodeBuild captures are supported")
            for row in capture.get("observations", []) + capture.get("cleanup", []):
                if not row.get("request_id") or ":" in row["operation"]:
                    continue
                boundary = (service, row["request_id"])
                if boundary in seen:
                    continue
                seen.add(boundary)
                evidence["calls"].append({"label": service + ":" + row["case"] + ":" + row["request_id"],
                                          "service": service, "capture": filename, **row})
        evidence["history_start"] = min(starts)
        save()
    elif not args.collect_only:
        prefix = "stackd-audit-cb-" + uuid.uuid4().hex[:12]
        evidence["owned_prefix"] = prefix
        evidence["history_start"] = evidence["observed_at"]
        role = project = False
        save()
        try:
            trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": account}}}]}
            created = observe("iam", "create-role", {"RoleName": prefix, "AssumeRolePolicyDocument": json.dumps(trust), "Tags": [{"Key": "stackd-owner", "Value": prefix}]})
            role = created["code"] == "Success"
            record("create_role", "iam:CreateRole", {"RoleName": prefix}, created)
            if not role:
                raise RuntimeError("Owned role creation failed")
            parameters = {"name": prefix, "serviceRole": created["output"]["Role"]["Arn"],
                          "source": {"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands: [true]\n"},
                          "artifacts": {"type": "NO_ARTIFACTS"},
                          "environment": {"type": "LINUX_CONTAINER", "image": "aws/codebuild/standard:7.0", "computeType": "BUILD_GENERAL1_SMALL",
                                          "environmentVariables": [{"name": "AUDIT_SENTINEL", "value": SENTINEL, "type": "PLAINTEXT"}]},
                          "timeoutInMinutes": 5, "queuedTimeoutInMinutes": 5,
                          "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}},
                          "tags": [{"key": "stackd-owner", "value": prefix}]}
            auth_source = {"type": "GITHUB", "location": "https://github.com/stackd-audit/nonexistent.git",
                           "auth": {"type": "OAUTH", "resource": SENTINEL}}
            secondary = {**auth_source, "sourceIdentifier": "secondary"}
            result = cb("create_rejected_auth", "CreateProject", {**parameters, "timeoutInMinutes": 0,
                                                                "source": auth_source, "secondarySources": [secondary]})
            project = result["code"] == "Success"
            if project:
                raise RuntimeError("Expected timeout rejection unexpectedly created the owned project")
            time.sleep(10)
            result = cb("create_project", "CreateProject", parameters)
            project = result["code"] == "Success"
            if not project:
                raise RuntimeError("Owned project creation failed")
            cb("update_primary_auth", "UpdateProject", {"name": prefix, "source": auth_source})
            cb("update_auth", "UpdateProject", {"name": prefix, "source": auth_source, "secondarySources": [secondary]})
            cb("update_rejected_auth", "UpdateProject", {"name": prefix, "timeoutInMinutes": 0, "source": auth_source, "secondarySources": [secondary]})
            cb("read_project", "BatchGetProjects", {"names": [prefix, prefix + "-missing"]})
            cb("missing_project_auth", "UpdateProject", {"name": prefix + "-missing", "source": auth_source, "secondarySources": [secondary]})
            cb("restore_source", "UpdateProject", {"name": prefix, "source": parameters["source"], "secondarySources": []})
            cb("missing_build_auth", "StartBuild", {"projectName": prefix + "-missing", "sourceAuthOverride": auth_source["auth"], "secondarySourcesOverride": [secondary], "environmentVariablesOverride": parameters["environment"]["environmentVariables"]})
            evidence["capture_complete"] = True
        except Exception as error:
            evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
            raise
        finally:
            cleanup_errors = []
            for label, cleanup in [
                ("delete_project", lambda: cb("delete_project", "DeleteProject", {"name": prefix}, True) if project else None),
                ("delete_role", lambda: record("delete_role", "iam:DeleteRole", {"RoleName": prefix}, observe("iam", "delete-role", {"RoleName": prefix}), True) if role else None),
                ("verify_project_absent", lambda: cb("verify_project_absent", "BatchGetProjects", {"names": [prefix]}, True)),
                ("verify_role_absent", lambda: record("verify_role_absent", "iam:GetRole", {"RoleName": prefix}, observe("iam", "get-role", {"RoleName": prefix}), True)),
            ]:
                try:
                    cleanup()
                except Exception as error:
                    cleanup_errors.append({"label": label, "type": type(error).__name__, "message": str(error)})
            results = {row["label"]: row for row in evidence["cleanup"]}
            evidence["cleanup_errors"] = cleanup_errors
            evidence["cleanup_verified"] = (not cleanup_errors and results.get("verify_project_absent", {}).get("output", {}).get("projectsNotFound") == [prefix]
                                             and results.get("verify_role_absent", {}).get("code") == "NoSuchEntity")
            save()
    requests = {row["request_id"]: row["label"] for row in evidence["calls"] + evidence["cleanup"]
                if row.get("request_id") and ":" not in row["operation"]}
    sources = sorted({row["service"] + ".amazonaws.com" for row in evidence["calls"] if ":" not in row["operation"]})
    try:
        evidence["cloudtrail"] = collect_history(
            lambda parameters: call("cloudtrail", "lookup-events", parameters, paginate=False, error_format="json"),
            requests, start_time=evidence["history_start"], event_sources=sources,
            max_pages=20, rounds=args.rounds, wait_seconds=args.wait_seconds)
    except CollectionError as error:
        evidence["cloudtrail"] = error.result
        raise
    finally:
        save()
    print(json.dumps({"output": str(output), "events": len(evidence["cloudtrail"]["events"]),
                      "missing_calls": evidence["cloudtrail"]["missing_calls"], "cleanup_verified": evidence["cleanup_verified"]}), flush=True)
    return 0 if evidence["cleanup_verified"] and not evidence["cloudtrail"]["missing_calls"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
