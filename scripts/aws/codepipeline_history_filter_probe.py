#!/usr/bin/env python3
"""Capture native action-history filters with one S3/manual-approval V2 pipeline.

Only uniquely owned resources in the probe account; no compute or customer KMS
keys. Retains every response and exact cleanup. ListActionExecutions uses the
shared signed transport so malformed filters reach AWS rather than SDK checks.
"""
import argparse
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import time
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from signed_requests import signed_post

REGION = "us-east-1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    account = args.account
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    session = boto3.Session(region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30,
                    ignore_configured_endpoint_urls=True)
    clients = {name: session.client(name, config=config) for name in ("sts", "iam", "s3", "codepipeline")}
    actor = clients["sts"].get_caller_identity()
    if actor["Account"] != account:
        raise RuntimeError("Refusing non-probe account")
    name = "stackd-history-" + uuid.uuid4().hex[:20]
    owned = {}
    evidence = {"source": "native AWS CodePipeline action history", "account": account, "region": REGION,
                "actor": actor["Arn"], "observed_at": datetime.now(timezone.utc).isoformat(),
                "prefix": name, "owned": owned, "calls": [], "cleanup": [], "snapshots": [],
                "bounds": {"pipelines": 1, "roles": 1, "buckets": 1, "compute": 0, "wait_seconds": 180},
                "complete": False, "cleanup_verified": False}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    def call(service, method, parameters, *, label=None, cleanup=False, allowed=("Success",)):
        try:
            output = getattr(clients[service], method)(**parameters)
            metadata = output.pop("ResponseMetadata", {})
            code = "Success"
        except ClientError as error:
            output = error.response["Error"]
            metadata = error.response.get("ResponseMetadata", {})
            code = output["Code"]
        row = {"service": service, "operation": clients[service].meta.method_to_api_mapping[method],
               "label": label or method, "parameters": {k: "<owned ZIP bytes>" if k == "Body" else v for k, v in parameters.items()},
               "code": code, "output": output, "request_id": metadata.get("RequestId"), "http_status": metadata.get("HTTPStatusCode")}
        evidence["cleanup" if cleanup else "calls"].append(row)
        save()
        print(row["label"] + ": " + code, flush=True)
        if code not in allowed:
            raise RuntimeError(json.dumps(row, default=str))
        return output

    def history(label, filter_value=None, **extra):
        parameters = {"pipelineName": name, **extra}
        if filter_value is not None:
            parameters["filter"] = filter_value
        response = signed_post("codepipeline.us-east-1.amazonaws.com", "codepipeline", json.dumps(parameters).encode(),
                               {"content-type": "application/x-amz-json-1.1", "x-amz-target": "CodePipeline_20150709.ListActionExecutions"})
        output = json.loads(response.body)
        code = "Success" if response.status == 200 else output["__type"].split("#")[-1]
        row = {"label": label, "parameters": parameters, "code": code,
               "output" if code == "Success" else "error": output,
               "http_status": response.status, "request_id": response.request_id}
        evidence["calls"].append(row)
        save()
        print(label + ": " + row["code"], flush=True)
        return row

    def latest(execution, time_range):
        return {"latestInPipelineExecution": {"pipelineExecutionId": execution, "startTimeRange": time_range}}

    def snapshot(label, execution):
        history(label + "/all")
        history(label + "/execution", {"pipelineExecutionId": execution})
        for time_range in ("All", "Latest"):
            history(label + "/" + time_range, latest(execution, time_range))
        evidence["snapshots"].append({"label": label, "execution": execution})
        save()

    def wait_state(predicate):
        deadline = time.monotonic() + 180
        while True:
            state = call("codepipeline", "get_pipeline_state", {"name": name})
            if predicate(state):
                return state
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned pipeline state wait expired")
            time.sleep(2)

    def action(state, stage, action_name):
        return next((a.get("latestExecution", {}) for s in state.get("stageStates", []) if s["stageName"] == stage
                     for a in s.get("actionStates", []) if a["actionName"] == action_name), {})

    def wait_approval(stage, action_name, previous=None):
        return wait_state(lambda state: action(state, stage, action_name).get("token") not in (None, previous))

    def approve(stage, action_name, status):
        state = wait_approval(stage, action_name)
        token = action(state, stage, action_name)["token"]
        call("codepipeline", "put_approval_result", {"pipelineName": name, "stageName": stage,
             "actionName": action_name, "token": token, "result": {"status": status, "summary": "Owned filter capture"}})
        return token

    def wait_execution(execution, status):
        deadline = time.monotonic() + 180
        while True:
            result = call("codepipeline", "get_pipeline_execution", {"pipelineName": name, "pipelineExecutionId": execution})
            if result["pipelineExecution"]["status"] == status:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned execution wait expired")
            time.sleep(2)

    try:
        role = call("iam", "create_role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": name}]})["Role"]
        owned["role"] = name
        call("iam", "put_role_policy", {"RoleName": name, "PolicyName": "owned", "PolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"]},
                {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
                 "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com", "kms:CallerAccount": account}}}]})})
        owned["policy"] = True
        call("s3", "create_bucket", {"Bucket": name}); owned["bucket"] = name
        call("s3", "put_bucket_versioning", {"Bucket": name, "VersioningConfiguration": {"Status": "Enabled"}})
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("config.json", '{"owned":true}')
        call("s3", "put_object", {"Bucket": name, "Key": "source.zip", "Body": archive.getvalue()})
        def gate(action_name):
            return {"name": action_name, "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"}, "runOrder": 1}
        declaration = {"name": name, "roleArn": role["Arn"], "pipelineType": "V2", "executionMode": "QUEUED",
            "artifactStore": {"type": "S3", "location": name}, "stages": [
                {"name": "Source", "actions": [{"name": "Source", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                  "configuration": {"S3Bucket": name, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"},
                  "outputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]},
                {"name": "Gate", "actions": [gate("Accept"), gate("Retry")]},
                {"name": "Final", "actions": [gate("Finish")]}]}
        deadline = time.monotonic() + 60
        while True:
            result = call("codepipeline", "create_pipeline", {"pipeline": declaration}, allowed=("Success", "InvalidStructureException"))
            if "Code" not in result:
                break
            if "not authorized to perform AssumeRole" not in result.get("Message", "") or time.monotonic() >= deadline:
                raise RuntimeError(json.dumps(result))
            time.sleep(2)
        owned["pipeline"] = name
        state = wait_approval("Gate", "Retry")
        first = next(s["latestExecution"]["pipelineExecutionId"] for s in state["stageStates"] if s["stageName"] == "Gate")
        evidence["first_execution"] = first
        snapshot("initial", first)
        approve("Gate", "Accept", "Approved")
        old_token = approve("Gate", "Retry", "Rejected")
        wait_execution(first, "Failed")
        snapshot("failed", first)
        call("codepipeline", "retry_stage_execution", {"pipelineName": name, "pipelineExecutionId": first, "stageName": "Gate", "retryMode": "FAILED_ACTIONS"})
        wait_approval("Gate", "Retry", old_token)
        snapshot("failed-actions-retry", first)
        old_token = approve("Gate", "Retry", "Rejected")
        wait_execution(first, "Failed")
        call("codepipeline", "retry_stage_execution", {"pipelineName": name, "pipelineExecutionId": first, "stageName": "Gate", "retryMode": "ALL_ACTIONS"})
        wait_approval("Gate", "Retry", old_token)
        snapshot("all-actions-retry", first)
        approve("Gate", "Accept", "Approved")
        approve("Gate", "Retry", "Approved")
        wait_approval("Final", "Finish")
        snapshot("final-stage", first)
        old_token = approve("Final", "Finish", "Rejected")
        wait_execution(first, "Failed")
        call("codepipeline", "retry_stage_execution", {"pipelineName": name, "pipelineExecutionId": first, "stageName": "Final", "retryMode": "FAILED_ACTIONS"})
        wait_approval("Final", "Finish", old_token)
        snapshot("final-retry", first)
        approve("Final", "Finish", "Approved")
        wait_execution(first, "Succeeded")
        second = call("codepipeline", "start_pipeline_execution", {"name": name})["pipelineExecutionId"]
        evidence["second_execution"] = second
        wait_state(lambda state: any(s.get("latestExecution", {}).get("pipelineExecutionId") == second and s["stageName"] == "Gate" for s in state.get("stageStates", [])))
        snapshot("later-old", first)
        snapshot("later-new", second)
        missing = str(uuid.uuid4())
        history("missing-execution", {"pipelineExecutionId": missing})
        for time_range in ("All", "Latest"):
            history("missing-latest/" + time_range, latest(missing, time_range))
            history("both-same/" + time_range, {"pipelineExecutionId": first, **latest(first, time_range)})
            history("both-different/" + time_range, {"pipelineExecutionId": second, **latest(first, time_range)})
            history("both-missing/" + time_range, {"pipelineExecutionId": missing, **latest(first, time_range)})
            history("both-latest-missing/" + time_range, {"pipelineExecutionId": first, **latest(missing, time_range)})
        history("invalid-range", latest(first, "Unknown"))
        history("missing-range", {"latestInPipelineExecution": {"pipelineExecutionId": first}})
        history("missing-id", {"latestInPipelineExecution": {"startTimeRange": "All"}})
        history("empty-latest", {"latestInPipelineExecution": {}})
        for time_range in ("All", "Latest"):
            filter_value = latest(first, time_range)
            page = history("page/" + time_range + "/1", filter_value, maxResults=1)
            token = page.get("output", {}).get("nextToken")
            if token:
                history("page-cross-range/" + time_range, latest(first, "Latest" if time_range == "All" else "All"), maxResults=1, nextToken=token)
                history("page-cross-id/" + time_range, latest(second, time_range), maxResults=1, nextToken=token)
                history("page-cross-filter/" + time_range, {"pipelineExecutionId": first}, maxResults=1, nextToken=token)
            index = 2
            while token:
                page = history("page/" + time_range + "/" + str(index), filter_value, maxResults=1, nextToken=token)
                token = page.get("output", {}).get("nextToken")
                index += 1
                if index > 20:
                    raise RuntimeError("Unbounded history pages")
        evidence["complete"] = True
    finally:
        failures = []
        def remove(service, method, parameters, allowed=("Success",)):
            try:
                return call(service, method, parameters, cleanup=True, allowed=allowed)
            except Exception as error:
                failures.append(str(error))
                return {}
        if owned.get("pipeline"):
            remove("codepipeline", "delete_pipeline", {"name": name})
            remove("codepipeline", "get_pipeline", {"name": name}, ("PipelineNotFoundException",))
        if owned.get("bucket"):
            versions = remove("s3", "list_object_versions", {"Bucket": name})
            objects = [{"Key": row["Key"], "VersionId": row["VersionId"]} for kind in ("Versions", "DeleteMarkers") for row in versions.get(kind, [])]
            if objects:
                result = remove("s3", "delete_objects", {"Bucket": name, "Delete": {"Objects": objects}})
                if result.get("Errors"):
                    failures.append(json.dumps(result["Errors"]))
            remove("s3", "delete_bucket", {"Bucket": name})
            remove("s3", "head_bucket", {"Bucket": name}, ("404",))
        if owned.get("policy"):
            remove("iam", "delete_role_policy", {"RoleName": name, "PolicyName": "owned"})
        if owned.get("role"):
            remove("iam", "delete_role", {"RoleName": name})
            remove("iam", "get_role", {"RoleName": name}, ("NoSuchEntity",))
        evidence["cleanup_verified"] = not failures
        evidence["cleanup_errors"] = failures
        save()
        if failures:
            raise RuntimeError("Owned cleanup failed: " + json.dumps(failures))
    print(json.dumps({"output": str(args.output), "complete": evidence["complete"], "cleanup_verified": evidence["cleanup_verified"]}))


if __name__ == "__main__":
    main()
