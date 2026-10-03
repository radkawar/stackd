#!/usr/bin/env python3
"""Capture native pipeline-variable semantics with exact-owned S3/manual pipelines.

No compute. Requests and failures are saved incrementally, never overwritten by a
later run. Raw signed CodePipeline calls bypass SDK parameter validation.
"""
import argparse
import copy
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

from aws_cli import require_account
from signed_requests import signed_post

REGION = "us-east-1"
SOURCES = [
    "https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-variables.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PipelineVariableDeclaration.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_StartPipelineExecution.html",
    "https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/codepipeline/2015-07-09/service-2.json",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    account = args.account
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    actor = require_account(account)
    session = boto3.Session(region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10,
                    read_timeout=30, ignore_configured_endpoint_urls=True)
    clients = {name: session.client(name, config=config) for name in ("iam", "s3")}
    name = "stackd-variables-" + uuid.uuid4().hex[:16]
    owned = {"pipelines": []}
    evidence = {"source": "native AWS CodePipeline pipeline-level variables", "source_urls": SOURCES,
                "account": account, "region": REGION, "actor": actor["Arn"],
                "observed_at": datetime.now(timezone.utc).isoformat(), "prefix": name,
                "model": {"service": "codepipeline", "api_version": "2015-07-09"},
                "bounds": {"pipelines": 2, "roles": 1, "buckets": 1, "compute": 0, "wait_seconds": 180},
                "owned": owned, "calls": [], "cleanup": [], "complete": False,
                "cleanup_verified": False}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    def retain(row, cleanup=False):
        evidence["cleanup" if cleanup else "calls"].append(row)
        save()
        print(row["label"] + ": " + row["code"], flush=True)
        return row

    def sdk(service, method, parameters, *, cleanup=False, allowed=("Success",)):
        try:
            output = getattr(clients[service], method)(**parameters)
            metadata = output.pop("ResponseMetadata", {})
            code = "Success"
        except ClientError as error:
            output = error.response["Error"]
            metadata = error.response.get("ResponseMetadata", {})
            code = output["Code"]
        row = retain({"label": method, "service": service, "operation": method,
                      "parameters": {k: "<owned ZIP bytes>" if k == "Body" else v for k, v in parameters.items()},
                      "code": code, "output": output, "http_status": metadata.get("HTTPStatusCode"),
                      "request_id": metadata.get("RequestId")}, cleanup)
        if code not in allowed:
            raise RuntimeError(json.dumps(row, default=str))
        return output

    def cp(label, operation, parameters, *, strict=True, cleanup=False, attempt=0):
        time.sleep(1.1)
        response = signed_post("codepipeline.us-east-1.amazonaws.com", "codepipeline",
                               json.dumps(parameters).encode(),
                               {"content-type": "application/x-amz-json-1.1",
                                "x-amz-target": "CodePipeline_20150709." + operation})
        output = json.loads(response.body or b"{}")
        code = "Success" if response.status == 200 else output["__type"].split("#")[-1]
        row = retain({"label": label, "operation": operation, "parameters": parameters,
                      "code": code, "output" if code == "Success" else "error": output,
                      "http_status": response.status, "request_id": response.request_id}, cleanup)
        if code == "ThrottlingException" and attempt < 3:
            time.sleep(5)
            return cp(label, operation, parameters, strict=strict, cleanup=cleanup, attempt=attempt + 1)
        if strict and code != "Success":
            raise RuntimeError(json.dumps(row))
        return row

    def wait(label, observe, predicate):
        deadline = time.monotonic() + 180
        while True:
            value = observe()
            if predicate(value):
                return value
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned wait expired: " + label)
            time.sleep(2)

    def execution(pipeline, execution_id, label):
        return cp(label, "GetPipelineExecution", {"pipelineName": pipeline,
                  "pipelineExecutionId": execution_id})["output"]["pipelineExecution"]

    def actions(pipeline, execution_id, label):
        return cp(label, "ListActionExecutions", {"pipelineName": pipeline,
                  "filter": {"pipelineExecutionId": execution_id}})["output"]

    def snapshot(pipeline, execution_id, label):
        execution(pipeline, execution_id, label + "/execution")
        cp(label + "/history", "ListPipelineExecutions", {"pipelineName": pipeline})
        actions(pipeline, execution_id, label + "/actions")

    def approval(pipeline, execution_id, status, previous=None):
        def observe():
            state = cp("approval-state", "GetPipelineState", {"name": pipeline})["output"]
            for stage in state.get("stageStates", []):
                if stage["stageName"] == "Gate" and stage.get("latestExecution", {}).get("pipelineExecutionId") == execution_id:
                    return stage["actionStates"][0].get("latestExecution", {})
            return {}
        state = wait("approval", observe, lambda row: row.get("token") not in (None, previous))
        cp("approval-" + status, "PutApprovalResult", {"pipelineName": pipeline,
           "stageName": "Gate", "actionName": "Review", "token": state["token"],
           "result": {"status": status, "summary": "Exact-owned variable calibration"}})
        return state["token"]

    def terminal(pipeline, execution_id, status):
        return wait(status, lambda: execution(pipeline, execution_id, "wait-" + status),
                    lambda row: row["status"] == status)

    def stop(pipeline, execution_id):
        cp("stop-owned-execution", "StopPipelineExecution", {"pipelineName": pipeline,
           "pipelineExecutionId": execution_id, "abandon": True}, strict=False)

    def create(declaration, label):
        deadline = time.monotonic() + 60
        while True:
            row = cp(label, "CreatePipeline", {"pipeline": declaration}, strict=False)
            if row["code"] == "Success":
                owned["pipelines"].append(declaration["name"])
                save()
                return
            message = row.get("error", {}).get("message", "")
            if "not authorized to perform AssumeRole" not in message or time.monotonic() >= deadline:
                raise RuntimeError(json.dumps(row))
            time.sleep(2)

    try:
        role = sdk("iam", "create_role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": name}]})["Role"]
        owned["role"] = name
        sdk("iam", "put_role_policy", {"RoleName": name, "PolicyName": "owned", "PolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"]},
                {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
                 "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com", "kms:CallerAccount": account}}}]})})
        owned["policy"] = True
        sdk("s3", "create_bucket", {"Bucket": name}); owned["bucket"] = name
        sdk("s3", "put_bucket_versioning", {"Bucket": name, "VersioningConfiguration": {"Status": "Enabled"}})
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("owned.json", '{"owned":true}')
        sdk("s3", "put_object", {"Bucket": name, "Key": "source.zip", "Body": archive.getvalue()})
        declaration = {"name": name, "roleArn": role["Arn"], "pipelineType": "V2", "executionMode": "QUEUED",
            "artifactStore": {"type": "S3", "location": name},
            "variables": [{"name": "Zulu", "defaultValue": "z-default", "description": "last alphabetically"},
                          {"name": "Alpha", "description": "required"},
                          {"name": "Middle", "defaultValue": "m-default"}],
            "stages": [
                {"name": "Source", "actions": [{"name": "Source", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {"S3Bucket": name, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"},
                    "outputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]},
                {"name": "Gate", "actions": [{"name": "Review", "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                    "configuration": {"CustomData": "Zulu=#{variables.Zulu};Alpha=#{variables.Alpha};Middle=#{variables.Middle}"}, "runOrder": 1}]}]}
        create(declaration, "create-required")
        cp("required-get-pipeline", "GetPipeline", {"name": name})
        time.sleep(5)
        initial = cp("required-initial-automatic-history", "ListPipelineExecutions", {"pipelineName": name})["output"]
        for row in initial.get("pipelineExecutionSummaries", []):
            snapshot(name, row["pipelineExecutionId"], "required-initial-auto")
            stop(name, row["pipelineExecutionId"])

        starts = [
            ("missing-overrides", None), ("empty-overrides", []),
            ("missing-required", [{"name": "Zulu", "value": "z"}]),
            ("unknown-and-missing", [{"name": "Unknown", "value": "x"}]),
            ("unknown-with-required", [{"name": "Alpha", "value": "a"}, {"name": "Unknown", "value": "x"}]),
            ("duplicate-override", [{"name": "Alpha", "value": "first"}, {"name": "Alpha", "value": "last"}]),
            ("empty-override-value", [{"name": "Alpha", "value": ""}]),
            ("invalid-override-name", [{"name": "bad.name", "value": "x"}]),
            ("case-sensitive-override", [{"name": "alpha", "value": "x"}]),
            ("override-order-zulu-alpha", [{"name": "Zulu", "value": "z-override"}, {"name": "Alpha", "value": "a"}]),
            ("override-order-alpha-zulu", [{"name": "Alpha", "value": "a"}, {"name": "Zulu", "value": "z-override"}]),
            ("override-equals-default", [{"name": "Middle", "value": "m-default"}, {"name": "Alpha", "value": "a"}]),
        ]
        for label, overrides in starts:
            parameters = {"name": name, "clientRequestToken": str(uuid.uuid4())}
            if overrides is not None:
                parameters["variables"] = overrides
            row = cp(label, "StartPipelineExecution", parameters, strict=False)
            if row["code"] == "Success":
                execution(name, row["output"]["pipelineExecutionId"], label + "/binding")
                stop(name, row["output"]["pipelineExecutionId"])

        token = str(uuid.uuid4())
        overrides = [{"name": "Middle", "value": "m-override"}, {"name": "Alpha", "value": "#{codepipeline.PipelineExecutionId}"}]
        first = cp("start-ordered-overrides", "StartPipelineExecution", {"name": name, "clientRequestToken": token, "variables": overrides})["output"]["pipelineExecutionId"]
        for label, values in [("token-identical", overrides), ("token-reordered", list(reversed(overrides))),
                              ("token-changed-value", [{"name": "Middle", "value": "changed"}, overrides[1]]),
                              ("token-missing-required", []),
                              ("token-duplicate", [{"name": "Alpha", "value": "a"}, {"name": "Alpha", "value": "b"}]),
                              ("token-empty-value", [{"name": "Alpha", "value": ""}]),
                              ("token-unknown", [{"name": "Unknown", "value": "x"}])]:
            row = cp(label, "StartPipelineExecution", {"name": name, "clientRequestToken": token, "variables": values}, strict=False)
            if row["code"] == "Success" and row["output"]["pipelineExecutionId"] != first:
                execution(name, row["output"]["pipelineExecutionId"], label + "/binding")
                stop(name, row["output"]["pipelineExecutionId"])
        revision = sdk("s3", "put_object", {"Bucket": name, "Key": "source.zip", "Body": archive.getvalue()})["VersionId"]
        for label, action_name in (("token-changed-source-revision", "Source"), ("token-invalid-source-action", "Unknown")):
            row = cp(label, "StartPipelineExecution", {"name": name, "clientRequestToken": token, "variables": overrides,
                     "sourceRevisions": [{"actionName": action_name, "revisionType": "S3_OBJECT_VERSION_ID", "revisionValue": revision}]}, strict=False)
            if row["code"] == "Success" and row["output"]["pipelineExecutionId"] != first:
                stop(name, row["output"]["pipelineExecutionId"])
        wait("manual action", lambda: actions(name, first, "wait-manual"),
             lambda row: any(a["actionName"] == "Review" and a["status"] == "InProgress" for a in row.get("actionExecutionDetails", [])))
        snapshot(name, first, "overrides-at-manual")
        old_token = approval(name, first, "Rejected")
        terminal(name, first, "Failed")
        cp("retry-same-execution", "RetryStageExecution", {"pipelineName": name, "pipelineExecutionId": first, "stageName": "Gate", "retryMode": "FAILED_ACTIONS"})
        approval(name, first, "Approved", old_token)
        terminal(name, first, "Succeeded")
        snapshot(name, first, "retried-bindings")

        shapes = [
            ("duplicate-declaration", [{"name": "Alpha", "defaultValue": "one"}, {"name": "Alpha", "defaultValue": "two"}]),
            ("invalid-declaration-dot", [{"name": "bad.name", "defaultValue": "x"}]),
            ("invalid-declaration-empty", [{"name": "", "defaultValue": "x"}]),
            ("valid-declaration-punctuation", [{"name": "A_B-C@1", "defaultValue": "x"}]),
            ("empty-default", [{"name": "Alpha", "defaultValue": ""}]),
            ("omitted-default", [{"name": "Alpha"}]),
            ("multiple-required-order", [{"name": "Zulu"}, {"name": "Alpha"}, {"name": "Middle"}]),
            ("name-too-long", [{"name": "A" * 129, "defaultValue": "x"}]),
            ("default-too-long", [{"name": "Alpha", "defaultValue": "x" * 1001}]),
            ("description-too-long", [{"name": "Alpha", "description": "x" * 201}]),
            ("empty-declarations", []),
        ]
        for label, variables in shapes:
            candidate = copy.deepcopy(declaration)
            candidate["variables"] = variables
            candidate["stages"][1]["actions"][0]["configuration"] = {"CustomData": "owned"}
            row = cp(label, "UpdatePipeline", {"pipeline": candidate}, strict=False)
            if row["code"] == "Success":
                cp(label + "/get", "GetPipeline", {"name": name})
                if label in ("empty-default", "omitted-default", "empty-declarations", "multiple-required-order"):
                    started = cp(label + "/start", "StartPipelineExecution", {"name": name}, strict=False)
                    if started["code"] == "Success":
                        execution(name, started["output"]["pipelineExecutionId"], label + "/binding")
                        stop(name, started["output"]["pipelineExecutionId"])
        for label in ("v1-variables", "reserved-action-namespace", "source-variable-reference", "undeclared-variable-reference"):
            candidate = copy.deepcopy(declaration)
            if label == "v1-variables":
                candidate["pipelineType"] = "V1"
                candidate["executionMode"] = "SUPERSEDED"
            elif label == "reserved-action-namespace":
                candidate["stages"][0]["actions"][0]["namespace"] = "variables"
            elif label == "source-variable-reference":
                candidate["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"] = "#{variables.Zulu}"
            else:
                candidate["stages"][1]["actions"][0]["configuration"]["CustomData"] = "#{variables.Unknown}"
            cp(label, "UpdatePipeline", {"pipeline": candidate}, strict=False)

        updated = copy.deepcopy(declaration)
        updated["variables"] = [{"name": "Middle", "defaultValue": "m-updated"},
                                {"name": "Alpha", "defaultValue": "a-updated", "description": "now optional"},
                                {"name": "Zulu", "defaultValue": "z-updated"}]
        cp("update-defaults-and-order", "UpdatePipeline", {"pipeline": updated})
        cp("updated-get-pipeline", "GetPipeline", {"name": name})
        snapshot(name, first, "old-binding-after-update")
        later = cp("start-updated-defaults", "StartPipelineExecution", {"name": name})["output"]["pipelineExecutionId"]
        approval(name, later, "Approved")
        terminal(name, later, "Succeeded")
        snapshot(name, later, "new-default-bindings")
        replay = cp("token-replay-after-update", "StartPipelineExecution", {"name": name, "clientRequestToken": token, "variables": overrides}, strict=False)
        if replay["code"] == "Success" and replay["output"]["pipelineExecutionId"] != first:
            stop(name, replay["output"]["pipelineExecutionId"])
        defaults = copy.deepcopy(updated)
        defaults["name"] = name + "-defaults"
        create(defaults, "create-defaults")
        for label in ("namespace-no-declarations-v1", "namespace-no-declarations-v2",
                      "namespace-empty-declarations", "reference-no-declarations", "omitted-pipeline-type"):
            candidate = copy.deepcopy(updated)
            candidate["stages"][1]["actions"][0]["configuration"] = {"CustomData": "owned"}
            if label == "omitted-pipeline-type":
                candidate.pop("pipelineType")
                candidate["executionMode"] = "SUPERSEDED"
            else:
                candidate.pop("variables")
                if label == "namespace-no-declarations-v1":
                    candidate["pipelineType"] = "V1"
                    candidate["executionMode"] = "SUPERSEDED"
                if label == "namespace-empty-declarations":
                    candidate["variables"] = []
                if label == "reference-no-declarations":
                    candidate["stages"][1]["actions"][0]["configuration"]["CustomData"] = "#{variables.Unknown}"
                else:
                    candidate["stages"][0]["actions"][0]["namespace"] = "variables"
            cp(label, "UpdatePipeline", {"pipeline": candidate}, strict=False)
        automatic = wait("automatic defaults execution", lambda: cp("defaults-auto-history", "ListPipelineExecutions", {"pipelineName": defaults["name"]})["output"],
                         lambda row: bool(row.get("pipelineExecutionSummaries")))
        auto_id = automatic["pipelineExecutionSummaries"][0]["pipelineExecutionId"]
        approval(defaults["name"], auto_id, "Approved")
        terminal(defaults["name"], auto_id, "Succeeded")
        snapshot(defaults["name"], auto_id, "automatic-default-bindings")
        evidence["complete"] = True
    except Exception as error:
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
        if owned.get("bucket"):
            while True:
                versions = remove("s3", "list_object_versions", {"Bucket": name})
                objects = [{"Key": row["Key"], "VersionId": row["VersionId"]} for kind in ("Versions", "DeleteMarkers") for row in versions.get(kind, [])]
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
        evidence["cleanup_verified"] = not failures
        evidence["cleanup_errors"] = failures
        save()
        if failures:
            raise RuntimeError("Owned cleanup failed: " + json.dumps(failures))
    print(json.dumps({"output": str(args.output), "complete": evidence["complete"], "cleanup_verified": evidence["cleanup_verified"]}))


if __name__ == "__main__":
    main()
