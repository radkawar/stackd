#!/usr/bin/env python3
"""Capture bounded native S3 deploy behavior; clean only exact-owned resources."""
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
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import require_account
from signed_requests import signed_post

REGION = "us-east-1"
SOURCES = [
    "https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-S3Deploy.html",
    "https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-S3.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_RetryStageExecution.html",
]


def fingerprint(body):
    return {"length": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "base64": base64.b64encode(body).decode()}


def archive(opaque_keys=False):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED) as zipped:
        if opaque_keys:
            for key, body, mode in [
                ("/leading.txt", b"leading slash\n", 0o100644),
                ("nested/link", b"../target.txt", 0o120777),
                ("duplicate.txt", b"first duplicate\n", 0o100644),
                ("duplicate.txt", b"last duplicate\n", 0o100644),
                ("windows\\key.txt", b"literal backslash key\n", 0o100644),
                ("nested/../relative.txt", b"literal relative key\n", 0o100644),
            ]:
                entry = zipfile.ZipInfo(key, (2026, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = mode << 16
                zipped.writestr(entry, body)
        else:
            for key, body in [("index.html", b"<html>owned deploy</html>\n"),
                              ("nested/", b""), ("nested/config.json", b'{"owned":true}\n'),
                              ("asset.bin", bytes(range(16))), ("README", b"owned plain text\n")]:
                zipped.writestr(zipfile.ZipInfo(key, (2026, 1, 1, 0, 0, 0)), body)
            for key in ("app.js", "style.css", "image.svg", "plain.txt", "config.xml",
                        "image.png", "image.jpg", "font.woff2", "source.map", "UPPER.HTML"):
                zipped.writestr(zipfile.ZipInfo(key, (2026, 1, 1, 0, 0, 0)), b"owned MIME calibration\n")
    return result.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", default="default")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--mime-only", action="store_true", help="only capture extraction MIME and directory behavior")
    modes.add_argument("--opaque-keys-only", action="store_true", help="capture literal ZIP names and symlink/duplicate entries without host extraction")
    modes.add_argument("--missing-key-only", action="store_true", help="capture Extract=false without ObjectKey at execution")
    args = parser.parse_args()
    account = args.account
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    native_env = dict(os.environ, AWS_PROFILE=args.profile, AWS_REGION=REGION,
                      AWS_DEFAULT_REGION=REGION, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    actor = require_account(account, env=native_env)
    session = boto3.Session(profile_name=args.profile, region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10,
                    read_timeout=30, ignore_configured_endpoint_urls=True)
    clients = {name: session.client(name, config=config) for name in ("sts", "iam", "s3", "kms")}
    sdk_actor = clients["sts"].get_caller_identity()
    if sdk_actor["Arn"] != actor["Arn"]:
        raise RuntimeError("SDK and signed identity mismatch")
    name = "stackd-s3deploy-" + uuid.uuid4().hex[:16]
    source, destination = name + "-source", name + "-destination"
    owned = {"buckets": [], "pipeline": False, "role": False, "policy": False}
    started = time.monotonic()
    evidence = {"source": "Native AWS CodePipeline S3 deploy", "source_urls": SOURCES,
                "account": account, "region": REGION, "actor": actor, "prefix": name,
                "observed_at": datetime.now(timezone.utc).isoformat(), "owned": owned,
                "bounds": {"buckets": 2, "pipelines": 1, "roles": 1, "compute": 0,
                           "execution_wait_seconds": 240, "overall_seconds_excluding_cleanup": 1800},
                "calls": [], "observations": [], "cleanup": [], "limitations": [],
                "complete": False, "cleanup_verified": False}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    def retain(row, cleanup=False):
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        evidence["cleanup" if cleanup else "calls"].append(row)
        save()
        print(row["label"] + ": " + row["code"], flush=True)
        return row

    def guard(cleanup):
        if not cleanup and time.monotonic() - started > 1800:
            raise RuntimeError("Native observation overall deadline reached")

    def note(label, **values):
        evidence["observations"].append({"label": label, **values})
        save()
        print("OBSERVATION " + json.dumps({"label": label, **values}, default=str), flush=True)

    def sdk(service, method, parameters, *, label=None, cleanup=False, allowed=("Success",)):
        guard(cleanup)
        try:
            result = getattr(clients[service], method)(**parameters)
            metadata = result.pop("ResponseMetadata", {})
            if method == "get_object":
                stream = result.pop("Body")
                try:
                    result["Body"] = fingerprint(stream.read())
                finally:
                    stream.close()
            code = "Success"
        except ClientError as error:
            result, metadata = error.response["Error"], error.response.get("ResponseMetadata", {})
            code = result["Code"]
        captured = {key: fingerprint(value) if isinstance(value, bytes) else value
                    for key, value in parameters.items()}
        row = retain({"label": label or method, "service": service, "operation": method,
                      "parameters": captured, "code": code, "output": result,
                      "http_status": metadata.get("HTTPStatusCode"), "request_id": metadata.get("RequestId")}, cleanup)
        if code not in allowed:
            raise RuntimeError(json.dumps(row, default=str))
        return result

    def cp(label, operation, parameters, *, strict=True, cleanup=False):
        guard(cleanup)
        time.sleep(1.1)
        response = signed_post("codepipeline.us-east-1.amazonaws.com", "codepipeline", json.dumps(parameters).encode(),
                               {"content-type": "application/x-amz-json-1.1",
                                "x-amz-target": "CodePipeline_20150709." + operation}, native_env)
        result = json.loads(response.body or b"{}")
        code = "Success" if response.status == 200 else result["__type"].split("#")[-1]
        row = retain({"label": label, "service": "codepipeline", "operation": operation,
                      "parameters": copy.deepcopy(parameters), "code": code,
                      "output" if code == "Success" else "error": result,
                      "http_status": response.status, "request_id": response.request_id}, cleanup)
        if strict and code != "Success":
            raise RuntimeError(json.dumps(row))
        return row

    def update(label, configuration, source_key="source.zip", strict=True):
        candidate = copy.deepcopy(declaration)
        candidate["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"] = source_key
        candidate["stages"][1]["actions"][0]["configuration"] = configuration
        return cp(label, "UpdatePipeline", {"pipeline": candidate}, strict=strict)

    def snapshot(label, execution):
        actions = cp(label + "/actions", "ListActionExecutions", {
            "pipelineName": name, "filter": {"pipelineExecutionId": execution}})["output"]
        cp(label + "/state", "GetPipelineState", {"name": name})
        cp(label + "/history", "ListPipelineExecutions", {"pipelineName": name})
        return actions.get("actionExecutionDetails", [])

    def wait_execution(label, execution=None, expected=None):
        deadline = time.monotonic() + 240
        while True:
            if execution is None:
                history = cp(label + "/find", "ListPipelineExecutions", {"pipelineName": name})["output"]
                rows = history.get("pipelineExecutionSummaries", [])
                if rows:
                    execution = rows[0]["pipelineExecutionId"]
            if execution:
                run = cp(label + "/wait", "GetPipelineExecution", {
                    "pipelineName": name, "pipelineExecutionId": execution})["output"]["pipelineExecution"]
                if run["status"] not in ("InProgress", "Stopping"):
                    actions = snapshot(label, execution)
                    note(label, execution=run, actions=actions)
                    if expected and run["status"] != expected:
                        raise RuntimeError(label + " expected " + expected + " got " + run["status"])
                    return execution, actions
            if time.monotonic() >= deadline:
                raise RuntimeError(label + " execution wait deadline")
            time.sleep(5)

    def execute(label, expected=None):
        row = cp(label + "/start", "StartPipelineExecution", {"name": name})
        return wait_execution(label, row["output"]["pipelineExecutionId"], expected)

    def objects(label):
        listed = sdk("s3", "list_objects_v2", {"Bucket": destination}, label=label + "/list")
        if listed.get("IsTruncated"):
            raise RuntimeError("Unexpected owned-object pagination")
        for item in listed.get("Contents", []):
            sdk("s3", "get_object", {"Bucket": destination, "Key": item["Key"]}, label=label + "/get/" + item["Key"])
            sdk("s3", "get_object_acl", {"Bucket": destination, "Key": item["Key"]}, label=label + "/acl/" + item["Key"])

    try:
        role = sdk("iam", "create_role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"},
                                                       "Action": "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": name}]})["Role"]
        owned["role"] = True
        resources = ["arn:aws:s3:::" + bucket + suffix for bucket in (source, destination) for suffix in ("", "/*")]
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": resources}]}
        sdk("iam", "put_role_policy", {"RoleName": name, "PolicyName": "owned", "PolicyDocument": json.dumps(policy)})
        owned["policy"] = True
        for bucket in (source, destination):
            sdk("s3", "create_bucket", {"Bucket": bucket})
            owned["buckets"].append(bucket)
            sdk("s3", "put_public_access_block", {"Bucket": bucket, "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}})
            sdk("s3", "put_bucket_versioning", {"Bucket": bucket, "VersioningConfiguration": {"Status": "Enabled"}})
        sdk("s3", "put_bucket_ownership_controls", {"Bucket": destination,
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}})
        body = archive(args.opaque_keys_only)
        uploaded = sdk("s3", "put_object", {"Bucket": source, "Key": "source.zip", "Body": body})
        sdk("s3", "put_object", {"Bucket": source, "Key": "corrupt.zip", "Body": b"owned corrupt archive\x00\xff"})
        basic = {"BucketName": destination, "Extract": "true", "CacheControl": "private, max-age=60", "CannedACL": "private"}
        if args.missing_key_only:
            basic["Extract"] = "false"
        declaration = {"name": name, "roleArn": role["Arn"], "pipelineType": "V2", "executionMode": "SUPERSEDED",
            "artifactStore": {"type": "S3", "location": source}, "stages": [
                {"name": "Source", "actions": [{"name": "Source", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {"S3Bucket": source, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"},
                    "outputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]},
                {"name": "Deploy", "actions": [{"name": "Deploy", "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": basic, "inputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]}]}
        deadline = time.monotonic() + 75
        while True:
            row = cp("create", "CreatePipeline", {"pipeline": declaration}, strict=False)
            if row["code"] == "Success":
                owned["pipeline"] = True
                break
            if "not authorized to perform AssumeRole" not in row.get("error", {}).get("message", "") or time.monotonic() > deadline:
                raise RuntimeError(json.dumps(row))
            time.sleep(5)
        if args.missing_key_only:
            wait_execution("missing-object-key", expected="Failed")
            objects("missing-object-key")
            evidence["complete"] = True
            save()
            return
        wait_execution("extract", expected=None if args.opaque_keys_only else "Succeeded")
        objects("extract")
        if args.opaque_keys_only:
            evidence["limitations"].append("Single mixed ZIP observes leading slash, nested/../ path, symlink-marked bytes and duplicate name; it cannot independently attribute a whole-archive rejection.")
            evidence["complete"] = True
            save()
            return
        if args.mime_only:
            evidence["limitations"].append("MIME-only capture; names carry extensions but payloads are deliberately plain text.")
            evidence["complete"] = True
            save()
            return
        raw = dict(basic, Extract="false", ObjectKey="raw/source.zip")
        update("raw/update", raw)
        execute("raw", "Succeeded")
        objects("raw")
        deployed = sdk("s3", "get_object", {"Bucket": destination, "Key": "raw/source.zip"}, label="raw/byte-comparison")
        note("raw-source-byte-equality", expected=fingerprint(body), actual=deployed["Body"],
             identical=deployed["Body"]["sha256"] == fingerprint(body)["sha256"], source_version=uploaded["VersionId"])
        matrix = [("missing-bucket", {"Extract": "true"}), ("missing-extract", {"BucketName": destination}),
                  ("false-missing-key", {"BucketName": destination, "Extract": "false"}),
                  ("unknown-config", dict(basic, Unknown="owned")),
                  ("content-type-config", dict(basic, ContentType="text/plain")),
                  ("true-object-key", dict(basic, ObjectKey="prefix/"))]
        matrix += [("extract-" + repr(value), dict(basic, Extract=value, ObjectKey="noncanonical.zip"))
                   for value in ("", "True", "TRUE", "False", "FALSE", "1", "0", "yes", " true ", "null")]
        admitted = {}
        for label, configuration in matrix:
            row = update("admission/" + label, configuration, strict=False)
            admitted[label] = row["code"]
        note("admission-matrix", results=admitted, runtime_inference=False)
        for label, configuration in [("true-object-key", dict(basic, ObjectKey="prefix/")),
                                     ("extract-'True'", dict(basic, Extract="True", ObjectKey="upper.zip")),
                                     ("extract-'yes'", dict(basic, Extract="yes", ObjectKey="yes.zip"))]:
            if admitted[label] == "Success":
                update("runtime/" + label + "/update", configuration)
                execute("runtime/" + label)
                objects("runtime/" + label)
        update("corrupt/update", basic, "corrupt.zip")
        execute("corrupt", "Failed")
        update("deny/update", raw)
        sdk("s3", "put_bucket_policy", {"Bucket": destination, "Policy": json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Principal": {"AWS": role["Arn"]}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + destination + "/*"}]})}, label="deny/current-put")
        owned["bucket_policy"] = True
        denied_id, denied_actions = execute("denied", "Failed")
        sdk("s3", "delete_bucket_policy", {"Bucket": destination}, label="restore/current-put")
        owned["bucket_policy"] = False
        time.sleep(5)
        cp("retry/same-execution", "RetryStageExecution", {"pipelineName": name, "stageName": "Deploy",
            "pipelineExecutionId": denied_id, "retryMode": "FAILED_ACTIONS"})
        _, recovered_actions = wait_execution("retry-recovered", denied_id, "Succeeded")
        note("retry-source-identity", before=[a for a in denied_actions if a["stageName"] == "Source"],
             after=[a for a in recovered_actions if a["stageName"] == "Source"], source_regenerated=False)
        objects("recovered")
        key = sdk("kms", "describe_key", {"KeyId": "alias/aws/s3"}, label="kms/existing-key", allowed=("Success", "NotFoundException", "AccessDeniedException"))
        if "KeyMetadata" in key:
            key_arn = key["KeyMetadata"]["Arn"]
            policy["Statement"].append({"Effect": "Allow", "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"], "Resource": key_arn})
            sdk("iam", "put_role_policy", {"RoleName": name, "PolicyName": "owned", "PolicyDocument": json.dumps(policy)})
            update("kms/update", dict(raw, ObjectKey="kms/source.zip", KMSEncryptionKeyARN=key_arn))
            execute("kms")
            objects("kms")
        else:
            evidence["limitations"].append("Existing AWS-managed S3 KMS key unavailable; no new key created.")
        evidence["limitations"].append("Admission alone does not establish behavior for noncanonical Extract values not executed; no public ACL, cross-account KMS, or malformed-path extraction attempted.")
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
            remove("codepipeline", "DeletePipeline", {"name": name})
            remove("codepipeline", "GetPipeline", {"name": name}, ("PipelineNotFoundException",))
        if owned.get("bucket_policy"):
            remove("s3", "delete_bucket_policy", {"Bucket": destination})
        for bucket in owned["buckets"]:
            for page in range(10):
                versions = remove("s3", "list_object_versions", {"Bucket": bucket})
                entries = [{"Key": item["Key"], "VersionId": item["VersionId"]}
                           for kind in ("Versions", "DeleteMarkers") for item in versions.get(kind, [])]
                if entries:
                    result = remove("s3", "delete_objects", {"Bucket": bucket, "Delete": {"Objects": entries}})
                    if result.get("Errors"):
                        failures.append(json.dumps(result["Errors"]))
                        break
                if not versions.get("IsTruncated"):
                    break
            remove("s3", "delete_bucket", {"Bucket": bucket})
            remove("s3", "head_bucket", {"Bucket": bucket}, ("404",))
        if owned["policy"]:
            remove("iam", "delete_role_policy", {"RoleName": name, "PolicyName": "owned"})
        if owned["role"]:
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
