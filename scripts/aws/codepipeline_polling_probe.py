#!/usr/bin/env python3
"""Capture native S3 polling with exact-owned S3-to-Manual pipelines, no compute.

Evidence is saved after every request. Expected polls are bounded by five minutes;
negative observations never establish a polling interval or indefinite absence.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import time
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import require_account
from signed_requests import signed_post

REGION = "us-east-1"
SOURCES = [
    "https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-S3.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PipelineMetadata.html",
    "https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-requirements.html#metadata.pollingDisabledAt",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ExecutionTrigger.html",
]


def archive(value):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as zipped:
        zipped.writestr(zipfile.ZipInfo("owned.json", (2026, 1, 1, 0, 0, 0)), json.dumps({"owned": value}))
    return result.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-errors", action="store_true", help="also observe owned missing/denied key recovery")
    args = parser.parse_args()
    account = args.account
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    native_env = dict(os.environ, AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
                      AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    actor = require_account(account, env=native_env)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10,
                    read_timeout=30, ignore_configured_endpoint_urls=True)
    session = boto3.Session(region_name=REGION)
    clients = {service: session.client(service, config=config) for service in ("sts", "iam", "s3")}
    sdk_actor = clients["sts"].get_caller_identity()
    if sdk_actor["Account"] != account or sdk_actor["Arn"] != actor["Arn"]:
        raise RuntimeError("SDK and signed-request identities do not match")
    name = "stackd-polling-" + uuid.uuid4().hex[:16]
    owned = {"pipelines": []}
    started = time.monotonic()
    overall_seconds = 3000 if args.source_errors else 2400
    evidence = {
        "source": "Native AWS CodePipeline S3 source polling", "source_urls": SOURCES,
        "account": account, "region": REGION, "actor": actor, "sdk_actor": sdk_actor,
        "observed_at": datetime.now(timezone.utc).isoformat(), "prefix": name,
        "bounds": {"pipelines": 4 if args.source_errors else 3, "buckets": 1, "roles": 1, "compute": 0,
                   "expected_poll_seconds": 300, "overall_seconds_excluding_cleanup": overall_seconds},
        "documented": {"omitted_polling": "Equivalent to true",
                       "inactive_disable": "After 30 days of no executions, polling is disabled; metadata.pollingDisabledAt reports the timestamp",
                       "inactive_disable_native_observed": False},
        "limitations": ["Bounded observation windows do not prove indefinite non-triggering.",
                        "Observed latencies are not a promised AWS polling cadence.",
                        "Thirty-day inactivity and reactivation are not exercised.",
                        "No EventBridge rules or CloudTrail trails are created."],
        "owned": owned, "calls": [], "observations": [], "cleanup": [],
        "complete": False, "cleanup_verified": False,
    }
    declarations = {}
    latest = {}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    def guard():
        if time.monotonic() - started >= overall_seconds:
            raise RuntimeError("Overall native observation deadline reached")

    def retain(row, cleanup=False):
        row["observed_at"] = datetime.now(timezone.utc).isoformat()
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        evidence["cleanup" if cleanup else "calls"].append(row)
        save()
        print(row["label"] + ": " + row["code"], flush=True)
        return row

    def note(label, **values):
        row = {"label": label, "elapsed_seconds": round(time.monotonic() - started, 3), **values}
        evidence["observations"].append(row)
        save()
        print("OBSERVATION " + json.dumps(row, default=str), flush=True)

    def sdk(service, method, parameters, *, label=None, cleanup=False, allowed=("Success",)):
        if not cleanup:
            guard()
        try:
            result = getattr(clients[service], method)(**parameters)
            metadata = result.pop("ResponseMetadata", {})
            code = "Success"
        except ClientError as error:
            result = error.response["Error"]
            metadata = error.response.get("ResponseMetadata", {})
            code = result["Code"]
        captured = {key: {"sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
                    if key == "Body" else value for key, value in parameters.items()}
        row = retain({"label": label or method, "service": service, "operation": method,
                      "parameters": captured, "code": code, "output": result,
                      "http_status": metadata.get("HTTPStatusCode"), "request_id": metadata.get("RequestId")}, cleanup)
        if code not in allowed:
            raise RuntimeError(json.dumps(row, default=str))
        return result

    def cp(label, operation, parameters, *, strict=True, cleanup=False, attempt=0):
        if not cleanup:
            guard()
        time.sleep(1.1)
        response = signed_post("codepipeline.us-east-1.amazonaws.com", "codepipeline", json.dumps(parameters).encode(),
                               {"content-type": "application/x-amz-json-1.1",
                                "x-amz-target": "CodePipeline_20150709." + operation})
        result = json.loads(response.body or b"{}")
        code = "Success" if response.status == 200 else result["__type"].split("#")[-1]
        row = retain({"label": label, "service": "codepipeline", "operation": operation,
                      "parameters": copy.deepcopy(parameters), "code": code,
                      "output" if code == "Success" else "error": result,
                      "http_status": response.status, "request_id": response.request_id}, cleanup)
        if code == "ThrottlingException" and attempt < 3:
            time.sleep(5)
            return cp(label, operation, parameters, strict=strict, cleanup=cleanup, attempt=attempt + 1)
        if strict and code != "Success":
            raise RuntimeError(json.dumps(row))
        return row

    def history(pipeline, label):
        rows = cp(label, "ListPipelineExecutions", {"pipelineName": pipeline, "maxResults": 100})["output"]
        if rows.get("nextToken"):
            raise RuntimeError("Unexpected history pagination in bounded owned probe")
        latest[pipeline] = rows.get("pipelineExecutionSummaries", [])
        return latest[pipeline]

    def snapshot(pipeline, execution_id, label):
        run = cp(label + "/execution", "GetPipelineExecution", {
            "pipelineName": pipeline, "pipelineExecutionId": execution_id})["output"]
        actions = cp(label + "/actions", "ListActionExecutions", {
            "pipelineName": pipeline, "filter": {"pipelineExecutionId": execution_id}})["output"]
        cp(label + "/state", "GetPipelineState", {"name": pipeline})
        note(label, pipeline=pipeline, execution=run["pipelineExecution"], actions=actions)

    def observe(label, pipelines, seconds):
        deadline = time.monotonic() + seconds
        before = {pipeline: [row["pipelineExecutionId"] for row in latest.get(pipeline, [])] for pipeline in pipelines}
        while True:
            for pipeline in pipelines:
                history(pipeline, label + "/" + pipeline.rsplit("-", 1)[-1])
            if time.monotonic() >= deadline:
                break
            time.sleep(min(12, max(0, deadline - time.monotonic())))
        note(label, window_seconds=seconds, before=before,
             after={pipeline: latest[pipeline] for pipeline in pipelines})

    def wait_revision(label, pipelines, version, seconds=300):
        deadline = time.monotonic() + seconds
        observed = {}
        while True:
            for pipeline in pipelines:
                if pipeline in observed:
                    continue
                for row in history(pipeline, label + "/history"):
                    if any(revision.get("revisionId") == version for revision in row.get("sourceRevisions", [])):
                        observed[pipeline] = row
                        snapshot(pipeline, row["pipelineExecutionId"], label + "/binding")
                        break
            if len(observed) == len(pipelines) or time.monotonic() >= deadline:
                break
            time.sleep(min(12, max(0, deadline - time.monotonic())))
        note(label, expected_version=version, observations=observed,
             missing=[pipeline for pipeline in pipelines if pipeline not in observed], bound_seconds=seconds)
        return observed

    def put(label, key, body):
        result = sdk("s3", "put_object", {"Bucket": name, "Key": key, "Body": body}, label=label)
        sdk("s3", "head_object", {"Bucket": name, "Key": key}, label=label + "/head")
        return result

    def update(label, pipeline, polling, key="source.zip"):
        declaration = copy.deepcopy(declarations[pipeline])
        configuration = declaration["stages"][0]["actions"][0]["configuration"]
        configuration["S3ObjectKey"] = key
        if polling is None:
            configuration.pop("PollForSourceChanges", None)
        else:
            configuration["PollForSourceChanges"] = polling
        row = cp(label, "UpdatePipeline", {"pipeline": declaration}, strict=False)
        if row["code"] == "Success":
            declarations[pipeline] = row["output"]["pipeline"]
            cp(label + "/get", "GetPipeline", {"name": pipeline})
        return row

    def transient(label, declaration, *, full_window=False):
        pipeline = declaration["name"]
        cp(label + "/create", "CreatePipeline", {"pipeline": declaration})
        owned["pipelines"].append(pipeline)
        save()
        if full_window:
            observe(label + "/window", [pipeline], 60)
        else:
            deadline = time.monotonic() + 60
            while not history(pipeline, label + "/initial-history"):
                if time.monotonic() >= deadline:
                    break
                time.sleep(5)
        cp(label + "/state", "GetPipelineState", {"name": pipeline})
        for run in latest.get(pipeline, []):
            snapshot(pipeline, run["pipelineExecutionId"], label + "/binding")
        note(label, history=latest.get(pipeline, []))
        cp(label + "/delete", "DeletePipeline", {"name": pipeline}, cleanup=True)
        gone = cp(label + "/verify-deleted", "GetPipeline", {"name": pipeline}, strict=False, cleanup=True)
        if gone["code"] != "PipelineNotFoundException":
            raise RuntimeError("Transient pipeline deletion not verified")
        owned["pipelines"].remove(pipeline)
        owned.setdefault("deleted_pipelines", []).append(pipeline)
        save()

    def poll_error(label, pipeline, code):
        deadline = time.monotonic() + 300
        while True:
            state = cp(label + "/state", "GetPipelineState", {"name": pipeline})["output"]
            failures = [action.get("latestExecution", {}) for stage in state.get("stageStates", [])
                        if stage["stageName"] == "Source" for action in stage.get("actionStates", [])
                        if action.get("latestExecution", {}).get("errorDetails", {}).get("code") == code]
            if failures or time.monotonic() >= deadline:
                history(pipeline, label + "/history")
                note(label, expected_error=code, observed_failures=failures, bound_seconds=300)
                return
            time.sleep(12)

    try:
        role = sdk("iam", "create_role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"},
                                                     "Action": "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": name}]})["Role"]
        owned["role"] = name
        sdk("iam", "put_role_policy", {"RoleName": name, "PolicyName": "owned", "PolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*",
                "Resource": ["arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"]}]})})
        owned["policy"] = True
        sdk("s3", "create_bucket", {"Bucket": name})
        owned["bucket"] = name
        sdk("s3", "put_bucket_versioning", {"Bucket": name, "VersioningConfiguration": {"Status": "Enabled"}})
        initial = put("initial-source", "source.zip", archive("initial"))
        for mode in ("omitted", "true", "false"):
            pipeline = name + "-" + mode
            configuration = {"S3Bucket": name, "S3ObjectKey": "source.zip"}
            if mode != "omitted":
                configuration["PollForSourceChanges"] = mode
            declaration = {"name": pipeline, "roleArn": role["Arn"], "pipelineType": "V2", "executionMode": "SUPERSEDED",
                "artifactStore": {"type": "S3", "location": name}, "stages": [
                    {"name": "Source", "actions": [{"name": "S3Input" if mode == "true" else "Source", "actionTypeId": {
                        "category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                        "configuration": configuration, "outputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]},
                    {"name": "Gate", "actions": [{"name": "Review", "actionTypeId": {
                        "category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                        "configuration": {"CustomData": "Exact-owned native S3 polling calibration"}, "runOrder": 1}]}]}
            deadline = time.monotonic() + 60
            while True:
                row = cp("create-" + mode, "CreatePipeline", {"pipeline": declaration}, strict=False)
                if row["code"] == "Success":
                    owned["pipelines"].append(pipeline)
                    declarations[pipeline] = row["output"]["pipeline"]
                    save()
                    break
                if "not authorized to perform AssumeRole" not in row.get("error", {}).get("message", "") or time.monotonic() >= deadline:
                    raise RuntimeError(json.dumps(row))
                time.sleep(3)
            cp("get-created-" + mode, "GetPipeline", {"name": pipeline})
        main_pipeline, control, disabled = owned["pipelines"]
        wait_revision("create-baseline", owned["pipelines"], initial["VersionId"])
        observe("create-no-source-change", owned["pipelines"], 60)
        update("enable-false-with-unchanged-source", disabled, "true")
        observe("enable-unchanged-source-window", [disabled], 90)
        update("restore-disabled-after-unchanged-enable", disabled, "false")
        put("unrelated-key-upload", "unrelated.zip", archive("unrelated"))
        observe("unrelated-key-window", owned["pipelines"], 60)
        second_body = archive("changed")
        second = put("new-source-version", "source.zip", second_body)
        changed = wait_revision("new-version-detection", [main_pipeline, control], second["VersionId"])
        history(disabled, "false-after-positive-control")
        if len(changed) != 2:
            raise RuntimeError("Required omitted/true new-version detection was not observed within five minutes")
        same = put("same-bytes-new-version", "source.zip", second_body)
        note("same-bytes-control", previous=second, current=same,
             identical_etag=second["ETag"] == same["ETag"], distinct_version=second["VersionId"] != same["VersionId"])
        wait_revision("same-bytes-version-detection", [main_pipeline, control], same["VersionId"])
        update("disable-with-unchanged-source", main_pipeline, "false")
        update("reenable-with-unchanged-source", main_pipeline, "true")
        observe("retained-cursor-unchanged-window", [main_pipeline], 90)
        positive = put("post-toggle-positive-version", "source.zip", archive("after-unchanged-toggle"))
        wait_revision("post-toggle-positive-detection", [main_pipeline, control], positive["VersionId"])
        for value in ("", "True", "TRUE", "False", "FALSE", "1", "0", "yes", " true ", "null"):
            row = update("admission-" + repr(value), disabled, value)
            if row["code"] == "Success":
                update("restore-false-after-admission", disabled, "false")
        update("disable-main", main_pipeline, "false")
        fourth = put("version-while-disabled", "source.zip", archive("while-disabled"))
        wait_revision("enabled-control-while-main-disabled", [control], fourth["VersionId"])
        observe("disabled-window", [main_pipeline, disabled], 60)
        update("reenable-main", main_pipeline, "true")
        wait_revision("reenable-existing-version", [main_pipeline], fourth["VersionId"])
        update("unchanged-enabled-update", main_pipeline, "true")
        observe("unchanged-update-window", [main_pipeline], 90)
        alternate = put("alternate-key-upload", "alternate.zip", archive("alternate"))
        update("changed-key-update", main_pipeline, "true", "alternate.zip")
        wait_revision("changed-key-existing-version", [main_pipeline], alternate["VersionId"])
        if args.source_errors:
            for value in ("True", "False", "yes", "1"):
                candidate = copy.deepcopy(declarations[control])
                candidate.pop("version", None)
                candidate["name"] = name + "-flag"
                candidate["stages"][0]["actions"][0]["configuration"]["PollForSourceChanges"] = value
                transient("effective-flag-" + value, candidate)
            multiple = copy.deepcopy(declarations[control])
            multiple.pop("version", None)
            multiple["name"] = name + "-multi"
            first = multiple["stages"][0]["actions"][0]
            first["name"] = "SourceOne"
            other = copy.deepcopy(first)
            other["name"] = "SourceTwo"
            other["configuration"]["S3ObjectKey"] = "alternate.zip"
            other["outputArtifacts"][0]["name"] = "OtherZip"
            multiple["stages"][0]["actions"].append(other)
            transient("two-source-create", multiple, full_window=True)
            missing_create = copy.deepcopy(declarations[control])
            missing_create.pop("version", None)
            missing_create["name"] = name + "-missing"
            missing_create["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"] = "absent-at-create.zip"
            transient("missing-create", missing_create, full_window=True)
            update("missing-key-update", main_pipeline, "true", "missing.zip")
            poll_error("missing-key-poll", main_pipeline, "ConfigurationError")
            restored = put("missing-key-created", "missing.zip", archive("now-present"))
            wait_revision("missing-key-recovery", [main_pipeline], restored["VersionId"])
            sdk("s3", "put_bucket_policy", {"Bucket": name, "Policy": json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Deny", "Principal": {"AWS": role["Arn"]}, "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                "Resource": "arn:aws:s3:::" + name + "/missing.zip"}]})}, label="deny-exact-owned-source")
            owned["bucket_policy"] = True
            time.sleep(20)
            denied = put("source-version-while-denied", "missing.zip", archive("denied-then-restored"))
            poll_error("denied-key-poll", main_pipeline, "PermissionError")
            sdk("s3", "delete_bucket_policy", {"Bucket": name}, label="restore-owned-source-access")
            owned["bucket_policy"] = False
            wait_revision("denied-key-recovery-same-version", [main_pipeline], denied["VersionId"])
        else:
            evidence["limitations"].append("Missing/denied-source cursor behavior not exercised; rerun with --source-errors for bounded controls.")
        for pipeline in owned["pipelines"]:
            cp("final-metadata", "GetPipeline", {"name": pipeline})
            history(pipeline, "final-history")
        evidence["complete"] = True
        save()
    except BaseException as error:
        evidence["failure"] = str(error)
        save()
        raise
    finally:
        failures = []

        def remove(service, operation, parameters, allowed=("Success",)):
            try:
                if service == "codepipeline":
                    row = cp("cleanup-" + operation, operation, parameters, strict=False, cleanup=True)
                    if row["code"] not in allowed:
                        raise RuntimeError(json.dumps(row))
                    return row.get("output", {})
                return sdk(service, operation, parameters, cleanup=True, allowed=allowed)
            except Exception as error:
                failures.append(str(error))
                return {}

        for pipeline in owned["pipelines"]:
            remove("codepipeline", "DeletePipeline", {"name": pipeline})
            remove("codepipeline", "GetPipeline", {"name": pipeline}, ("PipelineNotFoundException",))
        if owned.get("bucket_policy"):
            remove("s3", "delete_bucket_policy", {"Bucket": name})
        if owned.get("bucket"):
            # Bound cleanup pagination as well; this probe creates only a few dozen objects.
            for page in range(10):
                versions = remove("s3", "list_object_versions", {"Bucket": name})
                objects = [{"Key": item["Key"], "VersionId": item["VersionId"]}
                           for kind in ("Versions", "DeleteMarkers") for item in versions.get(kind, [])]
                if objects:
                    result = remove("s3", "delete_objects", {"Bucket": name, "Delete": {"Objects": objects}})
                    if result.get("Errors"):
                        failures.append(json.dumps(result["Errors"]))
                        break
                if not versions.get("IsTruncated"):
                    break
            remove("s3", "delete_bucket", {"Bucket": name})
            remove("s3", "head_bucket", {"Bucket": name}, ("404",))
        if owned.get("policy"):
            remove("iam", "delete_role_policy", {"RoleName": name, "PolicyName": "owned"})
        if owned.get("role"):
            remove("iam", "delete_role", {"RoleName": name})
            remove("iam", "get_role", {"RoleName": name}, ("NoSuchEntity",))
        evidence["cleanup_errors"] = failures
        evidence["cleanup_verified"] = not failures
        save()
        if failures:
            raise RuntimeError("Owned cleanup failed: " + json.dumps(failures))
    print(json.dumps({"output": str(args.output), "complete": evidence["complete"],
                      "cleanup_verified": evidence["cleanup_verified"]}), flush=True)


if __name__ == "__main__":
    main()
