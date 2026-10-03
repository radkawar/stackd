#!/usr/bin/env python3
"""Capture owned native CodeBuild controls and four bounded small builds.

Run: PYTHONPATH=scripts/aws python3 -P scripts/aws/codebuild_probe.py --account ACCOUNT_ID
One project, one role/inline policy, one bucket and one log group. No fleets,
EC2 guests, standing credentials, account-wide scans or configuration changes.
"""
import argparse
import datetime
import hashlib
import http.client
import io
import json
import os
import pathlib
import tempfile
import time
import urllib.error
import uuid
import zipfile

from aws_cli import observe as observe_cli, require_account, result as cli_result, run
from signed_requests import signed_post

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGION = "us-east-1"
CAPTURES = ROOT / ".stackd/probes/codebuild"


def request(operation, parameters):
    response = signed_post("codebuild.us-east-1.amazonaws.com", "codebuild", json.dumps(parameters).encode(),
                           {"content-type": "application/x-amz-json-1.1",
                            "x-amz-target": "CodeBuild_20161006." + operation})
    output = json.loads(response.body)
    if 200 <= response.status < 300:
        return {"code": "Success", "output": output, "http_status": response.status, "request_id": response.request_id}
    return {"code": output["__type"].split("#")[-1], "error": output, "http_status": response.status, "request_id": response.request_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--resume", help="Prior owned capture basename; skip already-started scenarios and preserve the four-build total")
    args = parser.parse_args()
    account = args.account
    os.environ["AWS_DEFAULT_REGION"] = REGION
    os.environ["AWS_REGION"] = REGION
    os.environ["AWS_MAX_ATTEMPTS"] = "1"
    identity = require_account(account)
    previous = None
    if args.resume:
        if pathlib.Path(args.resume).name != args.resume:
            raise RuntimeError("Resume must name a capture inside .stackd/probes/codebuild")
        previous = json.loads((CAPTURES / args.resume).read_text())
        if previous["account"] != account or not previous["owned_prefix"].startswith("stackd-buildowner-cb-") or not previous["cleanup_verified"]:
            raise RuntimeError("Refusing unowned or incompletely cleaned capture")
    prefix = previous["owned_prefix"] if previous else "stackd-buildowner-cb-" + uuid.uuid4().hex[:12]
    directory = CAPTURES
    directory.mkdir(parents=True, exist_ok=True)
    suffix = "-resume-" + uuid.uuid4().hex[:6] if previous else ""
    path = directory / (prefix + suffix + ".json")
    role = project = bucket = prefix
    group = "/aws/codebuild/" + prefix
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "native AWS CodeBuild", "account": account, "region": REGION,
               "actor": identity["Arn"], "owned_prefix": prefix,
               "semantic_inventory": "semantic_inventory.json",
               "bounds": {"unique_projects": 1, "unique_builds": 4, "compute": "BUILD_GENERAL1_SMALL",
                          "timeout_minutes": 5, "queued_timeout_minutes": 5, "auto_retries": 0,
                          "max_wall_seconds": 1800, "cost_ceiling_usd": 1,
                          "compute_upper_estimate_usd": 0.20, "roles": 1, "inline_policies": 1,
                          "s3_buckets": 1, "source_bytes": 65536, "ec2_guests": 0},
               "observations": [], "cleanup": [], "builds": [], "capture_complete": False}
    if previous:
        fixture["resumes_capture"] = args.resume
    prior_builds = (previous.get("prior_builds", []) + previous["builds"]) if previous else []
    prior_cases = set(previous.get("prior_cases", [])) if previous else set()
    if previous:
        prior_cases.update(row["case"].removesuffix("_start") for row in previous["observations"]
                           if row.get("operation") == "StartBuild" and row.get("code") == "Success")
    fixture["prior_builds"] = prior_builds
    fixture["prior_cases"] = sorted(prior_cases)
    owned = set()
    started = time.monotonic()

    def save():
        path.write_text(json.dumps(fixture, indent=2) + "\n")

    def record(case, operation, parameters, result, cleanup=False):
        fixture["cleanup" if cleanup else "observations"].append({
            "case": case, "operation": operation, "parameters": parameters, **result})
        save()
        print(case + ": " + result["code"], flush=True)
        return result

    def observe(case, operation, parameters, cleanup=False):
        if not cleanup and time.monotonic() - started > 1800:
            raise RuntimeError("CodeBuild capture wall bound reached")
        for attempt in range(3):
            try:
                result = request(operation, parameters)
                break
            except (http.client.RemoteDisconnected, TimeoutError, urllib.error.URLError) as error:
                fixture.setdefault("transport_failures", []).append({"case": case, "attempt": attempt + 1, "type": type(error).__name__})
                save()
                if attempt == 2 or operation == "StartBuild":
                    raise
                time.sleep(1)
        return record(case, operation, parameters, result, cleanup)

    def dependency(case, service, operation, parameters, cleanup=False):
        for attempt in range(2):
            try:
                result = observe_cli(service, operation, parameters, paginate=False)
                if service == "logs" and operation == "get-log-events":
                    for key in ("nextForwardToken", "nextBackwardToken"):
                        if key in result.get("output", {}):
                            result["output"][key] = "[REDACTED PAGINATION TOKEN]"
                return record(case, service + ":" + operation, parameters, result, cleanup)
            except RuntimeError as error:
                fixture.setdefault("transport_failures", []).append({"case": case, "attempt": attempt + 1, "type": type(error).__name__, "message": str(error)})
                save()
                if attempt == 1:
                    raise

    def require(result, case):
        if result["code"] != "Success":
            raise RuntimeError(case + " failed: " + result["code"])
        return result["output"]

    def wait_build(build_id, case, stop_in_build=False, cleanup=False):
        deadline = time.monotonic() + (90 if cleanup else 650)
        stopped = False
        previous = None
        while time.monotonic() < deadline:
            result = request("BatchGetBuilds", {"ids": [build_id]})
            builds = result.get("output", {}).get("builds", [])
            build = builds[0] if builds else {}
            state = (build.get("buildStatus"), build.get("currentPhase"), build.get("buildComplete"))
            if state != previous or result["code"] != "Success":
                record(case + "_status", "BatchGetBuilds", {"ids": [build_id]}, result, cleanup)
                previous = state
            if not build:
                return None
            if build.get("buildComplete"):
                return build
            if stop_in_build and not stopped and build.get("currentPhase") == "BUILD":
                observe(case + "_stop", "StopBuild", {"id": build_id}, cleanup)
                stopped = True
            time.sleep(5)
        observe(case + "_wall_stop", "StopBuild", {"id": build_id}, cleanup=True)
        fixture.setdefault("limits_reached", []).append(case + "_build_wait")
        save()
        return None

    try:
        save()
        missing_id = prefix + ":00000000-0000-4000-8000-000000000000"
        observe("missing_projects", "BatchGetProjects", {"names": [project]})
        observe("missing_start", "StartBuild", {"projectName": project})
        observe("missing_stop", "StopBuild", {"id": missing_id})
        observe("missing_builds", "BatchGetBuilds", {"ids": [missing_id]})
        observe("missing_delete_build", "BatchDeleteBuilds", {"ids": [missing_id]})
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": account}, "ArnEquals": {"aws:SourceArn": f"arn:aws:codebuild:{REGION}:{account}:project/{project}"}}}]}
        created = require(dependency("create_role", "iam", "create-role", {"RoleName": role, "AssumeRolePolicyDocument": json.dumps(trust), "Tags": [{"Key": "stackd-owner", "Value": prefix}]}), "create role")
        owned.add("role")
        role_arn = created["Role"]["Arn"]
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:aws:logs:{REGION}:{account}:log-group:{group}:*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:GetBucketAcl", "s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"}]}
        require(dependency("put_owned_policy", "iam", "put-role-policy", {"RoleName": role, "PolicyName": "owned-build", "PolicyDocument": json.dumps(policy)}), "put role policy")
        owned.add("policy")
        success_spec = {"version": "0.2", "env": {"variables": {"PROBE_VALUE": "buildspec"}, "exported-variables": ["PROBE_RESULT"]}, "phases": {
            "pre_build": {"commands": ["export PROBE_RESULT=retained-shell", "mkdir -p output"]},
            "build": {"commands": ["test \"$PROBE_RESULT\" = retained-shell", "test \"$PROBE_VALUE\" = start-override", "test \"$(cat input.txt)\" = stackd-owned-source", "printf 'stackd-build-success:%s\\n' \"$PROBE_RESULT\" | tee output/result.txt"]},
            "post_build": {"commands": ["echo stackd-post-build"]}}, "artifacts": {"files": ["output/result.txt"]}}
        project_input = {"name": project, "description": "Owned bounded native behavior evidence", "serviceRole": role_arn,
                         "source": {"type": "NO_SOURCE", "buildspec": json.dumps(success_spec)},
                         "artifacts": {"type": "NO_ARTIFACTS"},
                         "environment": {"type": "LINUX_CONTAINER", "image": "aws/codebuild/standard:7.0", "computeType": "BUILD_GENERAL1_SMALL", "privilegedMode": False, "imagePullCredentialsType": "CODEBUILD", "environmentVariables": [{"name": "PROBE_VALUE", "value": "project", "type": "PLAINTEXT"}]},
                         "timeoutInMinutes": 5, "queuedTimeoutInMinutes": 5, "autoRetryLimit": 0,
                         "logsConfig": {"cloudWatchLogs": {"status": "ENABLED", "groupName": group, "streamName": "owned"}, "s3Logs": {"status": "DISABLED"}},
                         "tags": [{"key": "stackd-owner", "value": prefix}]}
        time.sleep(10)
        project_result = observe("create_project", "CreateProject", project_input)
        if project_result["code"] != "Success":
            fixture["blocked_workloads"] = {"create_project_error": project_result["code"], "not_observed": ["build command execution", "failure", "cancellation", "timeout", "logs", "artifacts"]}
            return 1
        owned.add("project")
        observe("duplicate_project", "CreateProject", project_input)
        observe("batch_project_and_missing", "BatchGetProjects", {"names": [project, project + "-absent"]})
        observe("update_project", "UpdateProject", {"name": project, "description": "Owned updated description", "tags": [{"key": "stackd-owner", "value": prefix}, {"key": "purpose", "value": "native"}]})
        observe("invalid_timeout", "UpdateProject", {"name": project, "timeoutInMinutes": 4})
        observe("project_after_rejected_update", "BatchGetProjects", {"names": [project]})
        owned.add("bucket")
        require(dependency("create_bucket", "s3api", "create-bucket", {"Bucket": bucket}), "create bucket")
        require(dependency("create_logs", "logs", "create-log-group", {"logGroupName": group, "tags": {"stackd-owner": prefix}}), "create log group")
        owned.add("logs")
        with tempfile.TemporaryDirectory(prefix=prefix, dir=directory) as temp:
            source_path = pathlib.Path(temp) / "source.zip"
            with zipfile.ZipFile(source_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("input.txt", "stackd-owned-source\n")
                archive.writestr("buildspec.yml", json.dumps(success_spec))
            upload = cli_result(run("s3api", "put-object", {"Bucket": bucket, "Key": "source.zip"},
                                    options=["--body", str(source_path)], timeout=45))
            require(record("upload_source", "s3api:put-object", {"Bucket": bucket, "Key": "source.zip", "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest()}, upload), "upload source")
        require(observe("source_artifacts_update", "UpdateProject", {"name": project, "source": {"type": "S3", "location": bucket + "/source.zip"}, "artifacts": {"type": "S3", "location": bucket, "path": "artifacts", "name": "result.zip", "namespaceType": "BUILD_ID", "packaging": "ZIP"}}), "source update")
        failure_spec = {"version": "0.2", "phases": {"pre_build": {"commands": ["mkdir -p output", "printf 'stackd-failed-build-artifact\\n' > output/result.txt"]}, "build": {"commands": ["echo stackd-intentional-failure", "exit 7", "echo stackd-must-not-run"], "finally": ["echo stackd-failure-finally"]}, "post_build": {"commands": ["echo stackd-failure-post"]}}, "artifacts": {"files": ["output/result.txt"]}}
        cancel_spec = {"version": "0.2", "phases": {"build": {"commands": ["echo stackd-cancel-start", "sleep 180", "echo stackd-cancel-must-not-finish"]}}}
        timeout_spec = {"version": "0.2", "phases": {"build": {"commands": ["echo stackd-timeout-start", "sleep 360", "echo stackd-timeout-must-not-finish"]}}}
        for case, spec in [("success", None), ("failure", failure_spec), ("cancellation", cancel_spec), ("timeout", timeout_spec)]:
            if case in prior_cases:
                continue
            if len(prior_builds) + len(fixture["builds"]) >= 4:
                raise RuntimeError("Build cardinality bound reached")
            parameters = {"projectName": project, "timeoutInMinutesOverride": 5, "queuedTimeoutInMinutesOverride": 5, "autoRetryLimitOverride": 0,
                          "environmentVariablesOverride": [{"name": "PROBE_VALUE", "value": "start-override", "type": "PLAINTEXT"}]}
            if spec is not None:
                parameters["buildspecOverride"] = json.dumps(spec)
                if case != "failure":
                    parameters["artifactsOverride"] = {"type": "NO_ARTIFACTS"}
            result = observe(case + "_start", "StartBuild", parameters)
            if result["code"] != "Success":
                fixture["blocked_workloads"] = {"start_build_error": result["code"], "not_observed": ["build command execution", "failure", "cancellation", "timeout", "logs", "artifacts"]}
                break
            build_id = result["output"]["build"]["id"]
            fixture["builds"].append(build_id)
            save()
            final = wait_build(build_id, case, stop_in_build=case == "cancellation")
            if final:
                logs = final.get("logs", {})
                if logs.get("streamName"):
                    dependency(case + "_logs", "logs", "get-log-events", {"logGroupName": logs["groupName"], "logStreamName": logs["streamName"], "startFromHead": True, "limit": 1000})
                observe(case + "_stop_terminal", "StopBuild", {"id": build_id})
                if case in {"success", "failure"} and final.get("buildStatus") in {"SUCCEEDED", "FAILED"}:
                    listing = require(dependency("artifact_keys", "s3api", "list-objects-v2", {"Bucket": bucket, "Prefix": "artifacts/"}), "list artifacts")
                    for item in listing.get("Contents", []):
                        with tempfile.TemporaryDirectory(prefix=prefix, dir=directory) as temp:
                            local = pathlib.Path(temp) / "artifact.zip"
                            process = run("s3api", "get-object", options=["--bucket", bucket, "--key", item["Key"], str(local)], timeout=45)
                            downloaded = cli_result(process)
                            if process.returncode:
                                downloaded["client_diagnostic"] = process.stderr
                            require(record("artifact_download", "s3api:get-object", {"Bucket": bucket, "Key": item["Key"]}, downloaded), "download artifact")
                            with zipfile.ZipFile(io.BytesIO(local.read_bytes())) as archive:
                                contents = {name: archive.read(name).decode() for name in archive.namelist()}
                            fixture["observations"].append({"case": "artifact_bytes", "operation": "ArtifactZIP", "files": contents})
                            save()
        observe("owned_build_history", "ListBuildsForProject", {"projectName": project, "sortOrder": "ASCENDING"})
        observe("project_after_overrides", "BatchGetProjects", {"names": [project]})
        fixture["capture_complete"] = True
    except Exception as error:
        fixture["capture_failure"] = {"type": type(error).__name__, "message": str(error) if isinstance(error, RuntimeError) else "Transport/capture exception; diagnostics discarded"}
    finally:
        for build_id in fixture["builds"]:
            try:
                observe("cleanup_stop", "StopBuild", {"id": build_id}, cleanup=True)
                wait_build(build_id, "cleanup", cleanup=True)
            except Exception as error:
                fixture["cleanup"].append({"build": build_id, "failure_type": type(error).__name__})
        if fixture["builds"]:
            observe("delete_owned_builds", "BatchDeleteBuilds", {"ids": fixture["builds"]}, cleanup=True)
            observe("verify_builds_absent", "BatchGetBuilds", {"ids": fixture["builds"]}, cleanup=True)
        cleanup_steps = []
        if "project" in owned:
            try:
                observe("delete_owned_project", "DeleteProject", {"name": project}, cleanup=True)
                observe("verify_project_absent", "BatchGetProjects", {"names": [project]}, cleanup=True)
            except Exception as error:
                fixture["cleanup"].append({"project": project, "failure_type": type(error).__name__})
        if "logs" in owned:
            cleanup_steps += [("delete_owned_logs", "logs", "delete-log-group", {"logGroupName": group}),
                              ("verify_logs_absent", "logs", "describe-log-groups", {"logGroupNamePrefix": group})]
        if "bucket" in owned:
            try:
                listing = dependency("list_owned_objects", "s3api", "list-objects-v2", {"Bucket": bucket}, cleanup=True)
                for item in listing.get("output", {}).get("Contents", []):
                    dependency("delete_owned_object", "s3api", "delete-object", {"Bucket": bucket, "Key": item["Key"]}, cleanup=True)
            except Exception as error:
                fixture["cleanup"].append({"bucket": bucket, "failure_type": type(error).__name__})
            cleanup_steps += [("delete_owned_bucket", "s3api", "delete-bucket", {"Bucket": bucket}),
                              ("verify_bucket_absent", "s3api", "head-bucket", {"Bucket": bucket})]
        if "policy" in owned:
            cleanup_steps.append(("delete_owned_policy", "iam", "delete-role-policy", {"RoleName": role, "PolicyName": "owned-build"}))
        if "role" in owned:
            cleanup_steps += [("delete_owned_role", "iam", "delete-role", {"RoleName": role}),
                              ("verify_role_absent", "iam", "get-role", {"RoleName": role})]
        for case, service, operation, parameters in cleanup_steps:
            try:
                dependency(case, service, operation, parameters, cleanup=True)
            except Exception as error:
                fixture["cleanup"].append({"case": case, "failure_type": type(error).__name__})
        checks = {row.get("case"): row for row in fixture["cleanup"]}
        fixture["cleanup_verified"] = all([
            "role" not in owned or checks.get("verify_role_absent", {}).get("code") == "NoSuchEntity",
            "project" not in owned or checks.get("verify_project_absent", {}).get("output", {}).get("projectsNotFound") == [project],
            "bucket" not in owned or checks.get("verify_bucket_absent", {}).get("code") in {"404", "NoSuchBucket", "NotFound"},
            "logs" not in owned or checks.get("verify_logs_absent", {}).get("output", {}).get("logGroups") == [],
            not fixture["builds"] or sorted(checks.get("verify_builds_absent", {}).get("output", {}).get("buildsNotFound", [])) == sorted(fixture["builds"]),
        ])
        fixture["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save()
        print(str(path.relative_to(ROOT)) + " cleanup_verified=" + str(fixture["cleanup_verified"]), flush=True)
    return 0 if fixture["capture_complete"] and fixture["cleanup_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
