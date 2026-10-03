#!/usr/bin/env python3
"""Capture source-authority admission with one owned role/project, no credentials.

Run: PYTHONPATH=scripts/aws python3 -P scripts/aws/codebuild_source_authority_probe.py --account ACCOUNT_ID
No source credentials are imported/read. At most three immediately stopped small
builds; five-minute timeout, 240-second wall bound, estimated ceiling USD 0.10.
"""
import argparse
import datetime
import json
import os
import time
import uuid

from aws_cli import observe as cli, require_account
from codebuild_probe import CAPTURES, request

REGION = "us-east-1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    account = parser.parse_args().account
    os.environ.update(AWS_DEFAULT_REGION=REGION, AWS_REGION=REGION, AWS_MAX_ATTEMPTS="1")
    require_account(account)
    prefix = "stackd-source-authority-" + uuid.uuid4().hex[:12]
    CAPTURES.mkdir(parents=True, exist_ok=True)
    path = CAPTURES / (prefix + ".json")
    evidence = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source": "native AWS CodeBuild admission only", "owned_prefix": prefix,
                "account": account, "region": REGION,
                "bounds": {"roles": 1, "projects": 1, "imported_credentials": 0,
                           "maximum_builds": 3, "wall_seconds": 240, "cost_ceiling_usd": 0.10},
                "observations": [], "cleanup": [], "cleanup_verified": False}
    role = project = False
    builds = []
    started = time.monotonic()

    def save():
        path.write_text(json.dumps(evidence, indent=2) + "\n")

    def record(case, operation, parameters, result, cleanup=False):
        evidence["cleanup" if cleanup else "observations"].append(
            {"case": case, "operation": operation, "parameters": parameters, **result})
        save()
        print(case + ": " + result["code"], flush=True)
        return result

    def cb(case, operation, parameters, cleanup=False):
        if not cleanup and time.monotonic() - started > 240:
            raise RuntimeError("Admission wall bound exceeded")
        return record(case, operation, parameters, request(operation, parameters), cleanup)

    def dependency(case, operation, parameters, cleanup=False):
        return record(case, "iam:" + operation, parameters, cli("iam", operation, parameters), cleanup)

    try:
        save()
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": account}}}]}
        created = dependency("create_role", "create-role", {"RoleName": prefix, "AssumeRolePolicyDocument": json.dumps(trust), "Tags": [{"Key": "stackd-owner", "Value": prefix}]})
        if created["code"] != "Success":
            raise RuntimeError("Owned role creation failed")
        role = True
        parameters = {"name": prefix, "serviceRole": created["output"]["Role"]["Arn"],
                      "source": {"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands: [true]\n"},
                      "artifacts": {"type": "NO_ARTIFACTS"},
                      "environment": {"type": "LINUX_CONTAINER", "image": "aws/codebuild/standard:7.0", "computeType": "BUILD_GENERAL1_SMALL"},
                      "timeoutInMinutes": 5, "queuedTimeoutInMinutes": 5,
                      "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}},
                      "tags": [{"key": "stackd-owner", "value": prefix}]}
        time.sleep(10)
        foreign = {"type": "GITHUB", "location": "https://foreign.example.invalid/owner/repository.git"}
        foreign_create = cb("create_foreign_github", "CreateProject", {**parameters, "source": foreign})
        if foreign_create["code"] == "Success":
            project = True
        else:
            if cb("create_baseline", "CreateProject", parameters)["code"] != "Success":
                raise RuntimeError("Owned project creation failed")
            project = True
        cases = [
            ("github_canonical", "GITHUB", "https://github.com/owner/repository.git"),
            ("github_foreign", "GITHUB", "https://foreign.example.invalid/owner/repository.git"),
            ("github_suffix", "GITHUB", "https://github.com.foreign.example.invalid/owner/repository.git"),
            ("github_443", "GITHUB", "https://github.com:443/owner/repository.git"),
            ("github_8443", "GITHUB", "https://github.com:8443/owner/repository.git"),
            ("github_uppercase", "GITHUB", "https://GITHUB.COM/owner/repository.git"),
            ("github_userinfo", "GITHUB", "https://owner@github.com/owner/repository.git"),
            ("github_trailing_dot", "GITHUB", "https://github.com./owner/repository.git"),
            ("bitbucket_canonical", "BITBUCKET", "https://bitbucket.org/owner/repository.git"),
            ("bitbucket_foreign", "BITBUCKET", "https://foreign.example.invalid/owner/repository.git"),
            ("gitlab_canonical", "GITLAB", "https://gitlab.com/owner/repository.git"),
            ("gitlab_foreign", "GITLAB", "https://foreign.example.invalid/owner/repository.git"),
            ("github_enterprise", "GITHUB_ENTERPRISE", "https://foreign.example.invalid/owner/repository.git"),
            ("gitlab_self_managed", "GITLAB_SELF_MANAGED", "https://foreign.example.invalid/owner/repository.git"),
            ("github_enterprise_port", "GITHUB_ENTERPRISE", "https://foreign.example.invalid:8443/owner/repository.git"),
        ]
        for case, provider, url in cases:
            cb("update_" + case, "UpdateProject", {"name": prefix, "source": {"type": provider, "location": url}})
        if cb("restore_baseline", "UpdateProject", {"name": prefix, "source": parameters["source"]})["code"] != "Success":
            raise RuntimeError("Baseline update failed")
        for provider in ("GITHUB", "BITBUCKET", "GITLAB"):
            result = cb("override_foreign_" + provider.lower(), "StartBuild", {"projectName": prefix, "sourceTypeOverride": provider, "sourceLocationOverride": foreign["location"]})
            if result["code"] == "Success":
                build = result["output"]["build"]["id"]
                builds.append(build)
                cb("stop_admitted_" + provider.lower(), "StopBuild", {"id": build}, cleanup=True)
        evidence["capture_complete"] = True
    except Exception as error:
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for build in builds:
            cb("stop_cleanup", "StopBuild", {"id": build}, cleanup=True)
        if project:
            cb("delete_project", "DeleteProject", {"name": prefix}, cleanup=True)
        if role:
            dependency("delete_role", "delete-role", {"RoleName": prefix}, cleanup=True)
        absent = cb("verify_project_absent", "BatchGetProjects", {"names": [prefix]}, cleanup=True)
        role_absent = dependency("verify_role_absent", "get-role", {"RoleName": prefix}, cleanup=True)
        evidence["cleanup_verified"] = absent.get("output", {}).get("projectsNotFound") == [prefix] and role_absent["code"] == "NoSuchEntity"
        save()
        print(str(path), flush=True)


if __name__ == "__main__":
    main()
