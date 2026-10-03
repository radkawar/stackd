#!/usr/bin/env python3
"""Capture native Lambda pipeline jobs without ever retaining artifact credentials."""
import argparse
import base64
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
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import require_account
from signed_requests import signed_post

REGION = "us-east-1"
SOURCES = [
    "https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-Lambda.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PutJobSuccessResult.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PutJobFailureResult.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_JobData.html",
]
SECRET_KEYS = {"accesskeyid", "secretaccesskey", "sessiontoken", "aws_access_key_id",
               "aws_secret_access_key", "aws_session_token"}

# Never print the event, return it, or send it to an exception logger. Only this
# redacted copy leaves the function. Artifact clients remain invocation-local.
FUNCTION = r'''
import base64,copy,hashlib,io,json,os,time,zipfile
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

CONFIG = Config(retries={"total_max_attempts": 1},connect_timeout=5,read_timeout=10)

def call(client, method, **parameters):
    try:
        output = getattr(client,method)(**parameters)
        metadata = output.pop("ResponseMetadata",{})
        return {"code":"Success","http_status":metadata.get("HTTPStatusCode"),
                "request_id":metadata.get("RequestId"),"output":output}
    except ClientError as error:
        return {"code":error.response["Error"]["Code"],"error":error.response["Error"],
                "http_status":error.response.get("ResponseMetadata",{}).get("HTTPStatusCode"),
                "request_id":error.response.get("ResponseMetadata",{}).get("RequestId")}

def handler(event, context):
    job = event["CodePipeline.job"]
    data = job["data"]
    credentials = data["artifactCredentials"]
    redacted = copy.deepcopy(event)
    redacted["CodePipeline.job"]["data"]["artifactCredentials"] = {
        key:("[REDACTED]" if key in ("accessKeyId","secretAccessKey","sessionToken") else value)
        for key,value in credentials.items()}
    options = dict(region_name="us-east-1",config=CONFIG,
                   aws_access_key_id=credentials["accessKeyId"],
                   aws_secret_access_key=credentials["secretAccessKey"],
                   aws_session_token=credentials["sessionToken"])
    artifact_s3 = boto3.client("s3",**options)
    own_s3 = boto3.client("s3",config=CONFIG)
    pipeline = boto3.client("codepipeline",config=CONFIG)
    settings = json.loads(data["actionConfiguration"]["configuration"].get("UserParameters","{}"))
    mode = settings.get("mode","success")
    record = {"event":redacted,"mode":mode,"request_id":context.aws_request_id,
              "function_arn":context.invoked_function_arn,"callbacks":[],"started_at":time.time()}
    key = "captures/" + mode + "/" + context.aws_request_id + ".json"

    def persist():
        own_s3.put_object(Bucket=os.environ["CAPTURE_BUCKET"],Key=key,
                          Body=json.dumps(record,default=str).encode(),ContentType="application/json")

    def callback(label,method,**parameters):
        result = call(pipeline,method,**parameters)
        record["callbacks"].append({"label":label,"operation":method,"parameters":parameters,**result})
        return result

    try:
        if mode == "continuation" and not data.get("continuationToken"):
            identity = boto3.client("sts",**options).get_caller_identity()
            record["artifact_principal_arn"] = identity["Arn"]
            record["callback_principal_arn"] = boto3.client("sts",config=CONFIG).get_caller_identity()["Arn"]
            try:
                response = artifact_s3.get_object(Bucket=os.environ["ARTIFACT_BUCKET"],Key="unrelated-owned.txt")
                body = response["Body"].read()
                response["Body"].close()
                record["unrelated_owned_read"] = {"code":"Success","body":body.decode()}
            except ClientError as error:
                record["unrelated_owned_read"] = {"code":error.response["Error"]["Code"],"error":error.response["Error"]}
            unknown = "00000000-0000-0000-0000-000000000001"
            artifact_callback = call(boto3.client("codepipeline",**options),"put_job_success_result",jobId=unknown)
            record["artifact_credentials_unknown_callback"] = artifact_callback
            callback("execution-role-unknown-callback","put_job_success_result",jobId=unknown)
            mixed = callback("continuation-with-variables","put_job_success_result",jobId=job["id"],
                     continuationToken=json.dumps({"firstJobId":job["id"],"phase":2}),outputVariables={"Mixed":"owned"})
            if mixed["code"] == "Success":
                record["ordinary_return"] = {"phase":1,"mixed_callback_accepted":True}
                persist()
                return record["ordinary_return"]
            callback("continuation","put_job_success_result",jobId=job["id"],
                     continuationToken=json.dumps({"firstJobId":job["id"],"phase":2}),
                     executionDetails={"summary":"owned first phase","externalExecutionId":"owned-first-"+context.aws_request_id,"percentComplete":25})
            record["ordinary_return"] = {"phase":1}
            persist()
            return record["ordinary_return"]
        if mode == "pending":
            record["ordinary_return"] = {"statusCode":200,"body":"ordinary return without callback"}
            persist()
            return record["ordinary_return"]
        if mode == "no-output":
            callback("success-without-output","put_job_success_result",jobId=job["id"],outputVariables={"Produced":"no-output"})
        elif mode == "failure":
            failure = {"type":"JobFailed","message":"owned explicit failure","externalExecutionId":"owned-failure-"+context.aws_request_id}
            callback("failure","put_job_failure_result",jobId=job["id"],failureDetails=failure)
            callback("repeat-failure","put_job_failure_result",jobId=job["id"],failureDetails=failure)
            callback("success-after-failure","put_job_success_result",jobId=job["id"])
        else:
            if data.get("continuationToken"):
                first_id = json.loads(data["continuationToken"])["firstJobId"]
                record["first_job_id"] = first_id
                record["continuation_job_id_stable"] = first_id == job["id"]
                if first_id != job["id"]:
                    callback("old-job-during-continuation","put_job_success_result",jobId=first_id)
            source = data["inputArtifacts"][0]["location"]["s3Location"]
            response = artifact_s3.get_object(Bucket=source["bucketName"],Key=source["objectKey"])
            body = response["Body"].read()
            response["Body"].close()
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                text = archive.read("input.txt")
            output = b"lambda-produced:" + text.upper()
            archive_bytes = io.BytesIO()
            with zipfile.ZipFile(archive_bytes,"w",zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(zipfile.ZipInfo("transformed.txt",(2026,1,1,0,0,0)),output)
            destination = data["outputArtifacts"][0]["location"]["s3Location"]
            uploaded = artifact_s3.put_object(Bucket=destination["bucketName"],Key=destination["objectKey"],
                                              Body=archive_bytes.getvalue(),ContentType="application/zip")
            digest = hashlib.sha256(output).hexdigest()
            record["produced"] = {"text":output.decode(),"sha256":digest,"base64":base64.b64encode(output).decode(),
                                  "artifact_version_id":uploaded.get("VersionId"),"artifact_etag":uploaded.get("ETag")}
            success_parameters = dict(jobId=job["id"],
                     executionDetails={"summary":"owned transform complete","externalExecutionId":"owned-final-"+context.aws_request_id,"percentComplete":100},
                     currentRevision={"revision":"owned-lambda-revision","changeIdentifier":"owned-lambda-change","revisionSummary":"owned callback revision"},
                     outputVariables={"Produced":"yes","ContentDigest":digest})
            callback("success","put_job_success_result",**success_parameters)
            callback("exact-repeat-success","put_job_success_result",**success_parameters)
            callback("repeat-success","put_job_success_result",jobId=job["id"])
            callback("failure-after-success","put_job_failure_result",jobId=job["id"],
                     failureDetails={"type":"JobFailed","message":"owned late failure"})
        record["ordinary_return"] = {"finished":True}
    except Exception as error:
        # Error type/code is enough to diagnose this bounded probe; never retain
        # exception repr or locals, which could expose artifact credentials.
        record["handler_error_type"] = type(error).__name__
        if isinstance(error,ClientError):
            record["handler_error_code"] = error.response["Error"]["Code"]
        record["ordinary_return"] = {"finished":False}
    persist()
    return record["ordinary_return"]
'''


def fingerprint(body):
    return {"length": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "base64": base64.b64encode(body).decode()}


def safe(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in SECRET_KEYS else safe(item)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(item) for item in value]
    if isinstance(value, bytes):
        return fingerprint(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--pending-only", action="store_true", help="only measure ordinary return and post-abandon callback fencing")
    args = parser.parse_args()
    account = args.account
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    environment = dict(os.environ, AWS_PROFILE=args.profile, AWS_REGION=REGION,
                       AWS_DEFAULT_REGION=REGION, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    actor = require_account(account, env=environment)
    session = boto3.Session(profile_name=args.profile, region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10,
                    read_timeout=30, ignore_configured_endpoint_urls=True)
    clients = {name: session.client(name, config=config) for name in ("sts", "iam", "s3", "lambda", "logs", "codepipeline")}
    if clients["sts"].get_caller_identity()["Arn"] != actor["Arn"]:
        raise RuntimeError("SDK and signed identity mismatch")
    clients["codepipeline-west"] = session.client("codepipeline", region_name="us-west-2", config=config)
    model = session._session.get_component("data_loader").load_service_model("codepipeline", "service-2")
    name = "stackd-cplambda-" + uuid.uuid4().hex[:12]
    source, destination = name + "-source", name + "-destination"
    function_name, pipeline_role, function_role = name, name + "-pipeline", name + "-function"
    log_group = "/aws/lambda/" + function_name
    owned = {"buckets": [], "roles": [], "policies": [], "function": False, "pipeline": False, "log_group": False}
    started = time.monotonic()
    evidence = {"source": "Native AWS CodePipeline Lambda", "source_urls": SOURCES,
                "model": {"botocore_version": botocore.__version__, "api_version": model["metadata"]["apiVersion"],
                          "sha256": hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest()},
                "account": account, "region": REGION, "actor": actor, "prefix": name,
                "observed_at": datetime.now(timezone.utc).isoformat(), "owned": owned,
                "bounds": {"buckets": 2, "pipelines": 1, "roles": 2, "functions": 1,
                           "function_timeout_seconds": 30, "execution_wait_seconds": 240,
                           "pending_observation_seconds": 20, "overall_seconds_excluding_cleanup": 1200},
                "calls": [], "observations": [], "function_records": [], "cleanup": [], "limitations": [],
                "complete": False, "cleanup_verified": False}
    captured_keys = set()
    active_execution = None

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(safe(evidence), indent=2, default=str) + "\n")

    def retain(row, cleanup=False):
        row = safe(row)
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        evidence["cleanup" if cleanup else "calls"].append(row)
        save()
        print(row["label"] + ": " + row["code"], flush=True)
        return row

    def note(label, **values):
        value = safe({"label": label, **values})
        evidence["observations"].append(value)
        save()
        print("OBSERVATION " + json.dumps(value, default=str), flush=True)

    def sdk(service, method, parameters, *, label=None, cleanup=False, allowed=("Success",)):
        if not cleanup and time.monotonic() - started > 1200:
            raise RuntimeError("Overall native observation deadline reached")
        try:
            result = getattr(clients[service], method)(**parameters)
            metadata = result.pop("ResponseMetadata", {})
            if method == "get_object":
                stream = result.pop("Body")
                try:
                    body = stream.read()
                finally:
                    stream.close()
                result["Body"] = json.loads(body) if parameters["Key"].startswith("captures/") else fingerprint(body)
            code = "Success"
        except ClientError as error:
            result, metadata = error.response["Error"], error.response.get("ResponseMetadata", {})
            code = result["Code"]
        captured = safe(parameters)
        if method == "create_function":
            captured["Code"] = {"ZipFile": {"sha256": hashlib.sha256(parameters["Code"]["ZipFile"]).hexdigest()}}
        row = retain({"label": label or method, "service": service, "operation": method,
                      "parameters": captured, "code": code, "output": result,
                      "http_status": metadata.get("HTTPStatusCode"), "request_id": metadata.get("RequestId")}, cleanup)
        if code not in allowed:
            raise RuntimeError(json.dumps(row, default=str))
        return result

    def cp(label, operation, parameters, *, strict=True, cleanup=False):
        if not cleanup and time.monotonic() - started > 1200:
            raise RuntimeError("Overall native observation deadline reached")
        time.sleep(1.1)
        response = signed_post("codepipeline.us-east-1.amazonaws.com", "codepipeline", json.dumps(parameters).encode(),
                               {"content-type": "application/x-amz-json-1.1",
                                "x-amz-target": "CodePipeline_20150709." + operation}, environment)
        result = json.loads(response.body or b"{}")
        code = "Success" if response.status == 200 else result["__type"].split("#")[-1]
        row = retain({"label": label, "service": "codepipeline", "operation": operation,
                      "parameters": parameters, "code": code, "output" if code == "Success" else "error": result,
                      "http_status": response.status, "request_id": response.request_id}, cleanup)
        if strict and code != "Success":
            raise RuntimeError(json.dumps(row))
        return row

    def collect():
        listed = sdk("s3", "list_objects_v2", {"Bucket": destination, "Prefix": "captures/"}, label="captures/list")
        if listed.get("IsTruncated"):
            raise RuntimeError("Unexpected capture pagination")
        for entry in listed.get("Contents", []):
            if entry["Key"] in captured_keys:
                continue
            record = sdk("s3", "get_object", {"Bucket": destination, "Key": entry["Key"]}, label="captures/get")["Body"]
            captured_keys.add(entry["Key"])
            evidence["function_records"].append(record)
            note("function-job", mode=record["mode"], job_id=record["event"]["CodePipeline.job"]["id"],
                 continuation_token=record["event"]["CodePipeline.job"]["data"].get("continuationToken"),
                 callbacks=record["callbacks"], authority={key: record[key] for key in
                 ("artifact_principal_arn", "callback_principal_arn", "unrelated_owned_read", "artifact_credentials_unknown_callback") if key in record})
        return evidence["function_records"]

    def snapshot(label, execution):
        actions = cp(label + "/actions", "ListActionExecutions", {
            "pipelineName": name, "filter": {"pipelineExecutionId": execution}})["output"].get("actionExecutionDetails", [])
        cp(label + "/state", "GetPipelineState", {"name": name})
        return actions

    def wait_execution(label, execution=None, expected=None):
        nonlocal active_execution
        deadline = time.monotonic() + 240
        while True:
            if execution is None:
                history = cp(label + "/find", "ListPipelineExecutions", {"pipelineName": name})["output"]
                rows = history.get("pipelineExecutionSummaries", [])
                if rows:
                    execution = rows[0]["pipelineExecutionId"]
            if execution:
                active_execution = execution
                run = cp(label + "/wait", "GetPipelineExecution", {
                    "pipelineName": name, "pipelineExecutionId": execution})["output"]["pipelineExecution"]
                collect()
                if run["status"] not in ("InProgress", "Stopping"):
                    active_execution = None
                    actions = snapshot(label, execution)
                    note(label, execution=run, actions=actions)
                    if expected and run["status"] != expected:
                        raise RuntimeError(label + " expected " + expected + " got " + run["status"])
                    return execution, actions
            if time.monotonic() >= deadline:
                raise RuntimeError(label + " execution wait deadline")
            time.sleep(5)

    def update(label, configuration, strict=True):
        candidate = copy.deepcopy(declaration)
        candidate["stages"][1]["actions"][0]["configuration"] = configuration
        return cp(label, "UpdatePipeline", {"pipeline": candidate}, strict=strict)

    def mode_configuration(mode):
        return {"FunctionName": function_name, "UserParameters": json.dumps({"mode": mode})}

    def observe_pending(execution):
        nonlocal active_execution
        active_execution = execution
        deadline = time.monotonic() + 90
        while not any(row["mode"] == "pending" for row in collect()):
            if time.monotonic() >= deadline:
                raise RuntimeError("Pending function invocation deadline")
            time.sleep(3)
        pending = next(row for row in evidence["function_records"] if row["mode"] == "pending")
        time.sleep(20)
        actions = snapshot("pending/after-normal-return", execution)
        logs = sdk("logs", "filter_log_events", {"logGroupName": log_group}, label="pending/runtime-return-proof")
        reports = [row for row in logs.get("events", []) if "REPORT RequestId: " + pending["request_id"] in row["message"]]
        note("ordinary-return-remains-pending", observation_seconds=20, request_id=pending["request_id"], actions=actions,
             runtime_report_observed=bool(reports))
        if not reports:
            evidence["limitations"].append("No matching CloudWatch REPORT event visible at bounded lookup; function-side record is persisted immediately before its ordinary return.")
        transform = next(row for row in actions if row["stageName"] == "Transform")
        if transform["status"] != "InProgress":
            raise RuntimeError("Normal return unexpectedly completed action")
        cp("pending/abandon", "StopPipelineExecution", {"pipelineName": name, "pipelineExecutionId": execution, "abandon": True, "reason": "Owned bounded native observation complete"})
        wait_execution("pending/stopped", execution, "Stopped")
        cp("callback/after-abandon", "PutJobSuccessResult", {"jobId": pending["event"]["CodePipeline.job"]["id"]}, strict=False)
        time.sleep(5)
        wait_execution("pending/after-late-callback", execution, "Stopped")
        cp("pending/delete", "DeletePipeline", {"name": name})
        owned["pipeline"] = False
        cp("pending/deleted-proof", "GetPipeline", {"name": name}, strict=False)
        cp("callback/after-delete", "PutJobSuccessResult", {"jobId": pending["event"]["CodePipeline.job"]["id"]}, strict=False)
        evidence["limitations"].append("No timeout-duration inference: pending action was observed for 20 seconds after its function record and explicitly abandoned. Wrong-account scope and output-variable size boundaries were not measured.")

    try:
        for role_name, principal in ((pipeline_role, "codepipeline.amazonaws.com"), (function_role, "lambda.amazonaws.com")):
            sdk("iam", "create_role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}),
                "Tags": [{"Key": "stackd-probe", "Value": name}]})
            owned["roles"].append(role_name)
        function_arn = "arn:aws:lambda:" + REGION + ":" + account + ":function:" + function_name
        s3_resources = ["arn:aws:s3:::" + bucket + suffix for bucket in (source, destination) for suffix in ("", "/*")]
        policies = {
            pipeline_role: [{"Effect": "Allow", "Action": "s3:*", "Resource": s3_resources},
                            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": [function_arn, function_arn + "-missing"]}],
            function_role: [{"Effect": "Allow", "Action": ["codepipeline:PutJobSuccessResult", "codepipeline:PutJobFailureResult"], "Resource": "*"},
                            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + destination + "/captures/*"},
                            {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                             "Resource": "arn:aws:logs:" + REGION + ":" + account + ":log-group:" + log_group + ":*"}],
        }
        for role_name, statements in policies.items():
            sdk("iam", "put_role_policy", {"RoleName": role_name, "PolicyName": "owned", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})
            owned["policies"].append(role_name)
        for bucket in (source, destination):
            sdk("s3", "create_bucket", {"Bucket": bucket})
            owned["buckets"].append(bucket)
            sdk("s3", "put_public_access_block", {"Bucket": bucket, "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}})
            sdk("s3", "put_bucket_versioning", {"Bucket": bucket, "VersioningConfiguration": {"Status": "Enabled"}})
        sdk("s3", "put_object", {"Bucket": source, "Key": "unrelated-owned.txt", "Body": b"owned unrelated authority marker\n"})
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr("entry.py", FUNCTION)
        sdk("logs", "create_log_group", {"logGroupName": log_group})
        owned["log_group"] = True
        deadline = time.monotonic() + 75
        while True:
            result = sdk("lambda", "create_function", {"FunctionName": function_name, "Role": "arn:aws:iam::" + account + ":role/" + function_role,
                "Runtime": "python3.12", "Handler": "entry.handler", "Timeout": 30, "MemorySize": 128,
                "Code": {"ZipFile": package.getvalue()}, "Environment": {"Variables": {"ARTIFACT_BUCKET": source, "CAPTURE_BUCKET": destination}},
                "Tags": {"stackd-probe": name}}, allowed=("Success", "InvalidParameterValueException"))
            if "FunctionArn" in result:
                owned["function"] = True
                break
            if "cannot be assumed" not in result.get("Message", "") or time.monotonic() >= deadline:
                raise RuntimeError("Function role admission failed: " + json.dumps(result))
            time.sleep(5)
        clients["lambda"].get_waiter("function_active_v2").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
        sdk("lambda", "put_function_event_invoke_config", {"FunctionName": function_name, "MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60})
        source_bytes = io.BytesIO()
        with zipfile.ZipFile(source_bytes, "w") as zipped:
            zipped.writestr(zipfile.ZipInfo("input.txt", (2026, 1, 1, 0, 0, 0)), b"owned source bytes\n")
        sdk("s3", "put_object", {"Bucket": source, "Key": "source.zip", "Body": source_bytes.getvalue()})
        declaration = {"name": name, "roleArn": "arn:aws:iam::" + account + ":role/" + pipeline_role,
            "pipelineType": "V2", "executionMode": "SUPERSEDED", "artifactStore": {"type": "S3", "location": source}, "stages": [
                {"name": "Source", "actions": [{"name": "Source", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {"S3Bucket": source, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, "outputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]},
                {"name": "Transform", "actions": [{"name": "Transform", "actionTypeId": {"category": "Invoke", "owner": "AWS", "provider": "Lambda", "version": "1"},
                    "configuration": mode_configuration("pending" if args.pending_only else "continuation"), "inputArtifacts": [{"name": "SourceZip"}], "outputArtifacts": [{"name": "ProducedZip"}], "namespace": "LambdaResult", "runOrder": 1}]},
                {"name": "Deploy", "actions": [{"name": "Deploy", "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {"BucketName": destination, "Extract": "true", "ObjectKey": "deployed", "CacheControl": "#{LambdaResult.Produced}"},
                    "inputArtifacts": [{"name": "ProducedZip"}], "runOrder": 1}]}]}
        cp("create", "CreatePipeline", {"pipeline": declaration})
        owned["pipeline"] = True
        if args.pending_only:
            history = cp("pending/find", "ListPipelineExecutions", {"pipelineName": name})["output"]
            observe_pending(history["pipelineExecutionSummaries"][0]["pipelineExecutionId"])
            evidence["complete"] = True
            save()
            return
        execution, actions = wait_execution("continuation", expected="Succeeded")
        records = [row for row in collect() if row["mode"] == "continuation"]
        if len(records) != 2:
            raise RuntimeError("Expected two bounded continuation invocations")
        transform = next(row for row in actions if row["stageName"] == "Transform")
        note("job-versus-action-identity", action_execution_id=transform["actionExecutionId"],
             job_ids=[row["event"]["CodePipeline.job"]["id"] for row in records],
             continuation_tokens=[row["event"]["CodePipeline.job"]["data"].get("continuationToken") for row in records])
        produced = next(row["produced"] for row in records if "produced" in row)
        deployed = sdk("s3", "get_object", {"Bucket": destination, "Key": "deployed/transformed.txt"}, label="produced/deployed-bytes")
        note("real-output-consumed", lambda_produced=produced, deployed=deployed,
             identical=produced["sha256"] == deployed["Body"]["sha256"], output_variable_consumed=deployed.get("CacheControl") == "yes")
        if produced["sha256"] != deployed["Body"]["sha256"] or deployed.get("CacheControl") != "yes":
            raise RuntimeError("Lambda-produced artifact/output variable not consumed")
        first_job = records[0]["event"]["CodePipeline.job"]["id"]
        cp("callback/old-after-completion", "PutJobSuccessResult", {"jobId": first_job}, strict=False)
        sdk("codepipeline-west", "put_job_success_result", {"jobId": first_job}, label="callback/wrong-region", allowed=("Success", "JobNotFoundException", "InvalidJobStateException"))
        unknown = "00000000-0000-0000-0000-000000000001"
        cp("callback/unknown-success", "PutJobSuccessResult", {"jobId": unknown}, strict=False)
        cp("callback/unknown-failure", "PutJobFailureResult", {"jobId": unknown, "failureDetails": {"type": "JobFailed", "message": "owned unknown job"}}, strict=False)
        cp("callback/malformed-id", "PutJobSuccessResult", {"jobId": "not-a-uuid"}, strict=False)
        update("failure/update", mode_configuration("failure"))
        execution = cp("failure/start", "StartPipelineExecution", {"name": name})["output"]["pipelineExecutionId"]
        wait_execution("failure", execution, "Failed")
        update("no-output/update", mode_configuration("no-output"))
        execution = cp("no-output/start", "StartPipelineExecution", {"name": name})["output"]["pipelineExecutionId"]
        wait_execution("no-output", execution, "Failed")
        update("admission/missing-function-name", {"UserParameters": "owned"}, strict=False)
        update("admission/unknown-configuration", dict(mode_configuration("success"), Unknown="owned"), strict=False)
        update("admission/unknown-function", {"FunctionName": function_name + "-missing"}, strict=False)
        execution = cp("missing-function/start", "StartPipelineExecution", {"name": name})["output"]["pipelineExecutionId"]
        wait_execution("missing-function", execution, "Failed")
        update("pending/update", mode_configuration("pending"))
        execution = cp("pending/start", "StartPipelineExecution", {"name": name})["output"]["pipelineExecutionId"]
        observe_pending(execution)
        evidence["limitations"].append("Wrong-scope calibration uses us-west-2, not another account. Only the two-phase continuation path was executed. Artifact credential authority check is an unrelated key read and an unknown-job callback, not a broad permission enumeration.")
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
                    row = cp("cleanup/" + operation, operation, parameters, strict=False, cleanup=True)
                    if row["code"] not in allowed:
                        raise RuntimeError(json.dumps(row))
                    return row.get("output", {})
                return sdk(service, operation, parameters, cleanup=True, allowed=allowed)
            except Exception as error:
                failures.append(str(error))
                return {}

        if owned["pipeline"]:
            if active_execution:
                remove("codepipeline", "StopPipelineExecution", {"pipelineName": name, "pipelineExecutionId": active_execution, "abandon": True}, ("Success", "PipelineExecutionNotStoppableException"))
            remove("codepipeline", "DeletePipeline", {"name": name})
            remove("codepipeline", "GetPipeline", {"name": name}, ("PipelineNotFoundException",))
        if owned["function"]:
            remove("lambda", "delete_function", {"FunctionName": function_name})
            remove("lambda", "get_function", {"FunctionName": function_name}, ("ResourceNotFoundException",))
        if owned["log_group"]:
            remove("logs", "delete_log_group", {"logGroupName": log_group})
            remaining = remove("logs", "describe_log_groups", {"logGroupNamePrefix": log_group})
            if any(row["logGroupName"] == log_group for row in remaining.get("logGroups", [])):
                failures.append("Owned log group remained")
        for bucket in owned["buckets"]:
            for page in range(10):
                versions = remove("s3", "list_object_versions", {"Bucket": bucket})
                entries = [{"Key": row["Key"], "VersionId": row["VersionId"]}
                           for kind in ("Versions", "DeleteMarkers") for row in versions.get(kind, [])]
                if entries:
                    removed = remove("s3", "delete_objects", {"Bucket": bucket, "Delete": {"Objects": entries}})
                    if removed.get("Errors"):
                        failures.append(json.dumps(removed["Errors"]))
                        break
                if not versions.get("IsTruncated"):
                    break
            remove("s3", "delete_bucket", {"Bucket": bucket})
            remove("s3", "head_bucket", {"Bucket": bucket}, ("404",))
        for role_name in owned["policies"]:
            remove("iam", "delete_role_policy", {"RoleName": role_name, "PolicyName": "owned"})
        for role_name in owned["roles"]:
            remove("iam", "delete_role", {"RoleName": role_name})
            remove("iam", "get_role", {"RoleName": role_name}, ("NoSuchEntity",))
        evidence["cleanup_errors"] = failures
        evidence["cleanup_verified"] = not failures
        save()
        if failures:
            raise RuntimeError("Owned cleanup failed: " + json.dumps(failures))
    print(json.dumps({"output": str(args.output), "complete": evidence["complete"], "cleanup_verified": evidence["cleanup_verified"]}), flush=True)


if __name__ == "__main__":
    main()
