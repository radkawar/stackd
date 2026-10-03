#!/usr/bin/env python3
"""Observe native Scheduler CodePipeline templated targets with exact-owned cleanup.

One pipeline, versioned bucket, queue, group, two roles and six schedule names;
900 seconds observation plus 300 seconds cleanup reserve. No compute or polling.
"""
import argparse
from datetime import datetime, timedelta, timezone
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

from aws_cli import call as cli_call
from codepipeline_s3_deploy_probe import fingerprint
from scheduler_pipes_probe import REGION, document, verify_absence

SOURCES = [
    "https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-templated.html",
    "https://docs.aws.amazon.com/scheduler/latest/APIReference/API_Target.html",
    "https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_StartPipelineExecution.html",
]


def archive(marker):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zipped:
        zipped.writestr(zipfile.ZipInfo("marker.txt", (2026, 1, 1, 0, 0, 0)), marker)
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native observations")
    review = json.loads(args.review.read_text())
    if review.get("allowed") is not True or review.get("account") != args.account:
        raise RuntimeError("Approved account-scoped ethics review required")
    native_env = dict(os.environ, AWS_PROFILE="default", AWS_REGION=REGION,
                      AWS_DEFAULT_REGION=REGION, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    actor = cli_call("sts", "get-caller-identity", env=native_env)
    session = boto3.Session(profile_name="default", region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=5,
                    read_timeout=15, ignore_configured_endpoint_urls=True)
    clients = {s: session.client(s, config=config)
               for s in ("sts", "iam", "s3", "sqs", "scheduler", "codepipeline")}
    sdk_actor = clients["sts"].get_caller_identity()
    if actor["Account"] != args.account or actor["Arn"] != ('arn:aws:iam::' + args.account + ':user/Delegated') or sdk_actor["Arn"] != actor["Arn"]:
        raise RuntimeError("Unapproved or inconsistent native identity")
    credentials = session.get_credentials().get_frozen_credentials()
    secrets = [s for s in (credentials.secret_key, credentials.token) if s]
    name = "stackd-schedcp-" + uuid.uuid4().hex[:12]
    pipeline_arn = f"arn:aws:codepipeline:{REGION}:{args.account}:{name}"
    group_arn = f"arn:aws:scheduler:{REGION}:{args.account}:schedule-group/{name}"
    owned = {"roles": {}, "queues": {}, "schedules": []}
    started = time.monotonic()
    evidence = {"source": "native AWS Scheduler CodePipeline templated target", "source_urls": SOURCES,
                "actor": actor, "sdk_actor": sdk_actor, "account": args.account, "region": REGION,
                "started_at": datetime.now(timezone.utc).isoformat(), "prefix": name,
                "review": str(args.review), "bounds": review["bounds"], "owned": owned,
                "calls": [], "observations": {}, "cleanup": [], "limitations": [],
                "complete": False, "cleanup_verified": False,
                "boundary": "Actual pipeline history, execution variables and S3 bytes; no CloudTrail attribution claim."}
    cleaning = False

    def save():
        text = json.dumps(document(evidence), indent=2, default=str)
        for secret in secrets:
            text = text.replace(secret, "<redacted-credential>")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")

    def guard():
        if time.monotonic() - started >= (1200 if cleaning else 900):
            raise RuntimeError("Native probe deadline reached")

    def call(label, service, operation, parameters, optional=False):
        guard()
        row = {"label": label, "service": service, "operation": operation,
               "parameters": {k: fingerprint(v) if isinstance(v, bytes) else v for k, v in parameters.items()},
               "elapsed_seconds": round(time.monotonic() - started, 3)}
        evidence["cleanup" if cleaning else "calls"].append(row)
        try:
            result = getattr(clients[service], operation)(**parameters)
            if operation == "get_object":
                stream = result.pop("Body")
                try:
                    result["Body"] = fingerprint(stream.read())
                finally:
                    stream.close()
            row.update(code="Success", output=result)
        except ClientError as error:
            result = error.response
            row.update(code=result["Error"]["Code"], error=result)
        except Exception as error:
            row.update(code=type(error).__name__, transport_error=str(error))
            save()
            raise
        metadata = result.get("ResponseMetadata", {})
        row.update(request_id=metadata.get("RequestId"), http_status=metadata.get("HTTPStatusCode"))
        save()
        print(label + ": " + row["code"], flush=True)
        if row["code"] != "Success" and not optional:
            raise RuntimeError(label + ": " + json.dumps(result, default=str))
        return result

    def history(label):
        return call(label, "codepipeline", "list_pipeline_executions", {
            "pipelineName": name, "maxResults": 30}).get("pipelineExecutionSummaries", [])

    def await_execution(label, baseline, seconds=175):
        deadline = min(started + 895, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            rows = [row for row in history(label + "/history") if row["pipelineExecutionId"] not in baseline]
            if rows:
                execution_id = rows[0]["pipelineExecutionId"]
                execution = call(label + "/execution", "codepipeline", "get_pipeline_execution", {
                    "pipelineName": name, "pipelineExecutionId": execution_id})["pipelineExecution"]
                if execution["status"] not in ("InProgress", "Stopping"):
                    actions = call(label + "/actions", "codepipeline", "list_action_executions", {
                        "pipelineName": name, "filter": {"pipelineExecutionId": execution_id}})
                    observation = {"summary": rows[0], "execution": execution, "actions": actions}
                    if execution["status"] == "Succeeded":
                        observation["artifact"] = call(label + "/artifact", "s3", "get_object", {
                            "Bucket": name, "Key": "deploy/" + execution_id + ".zip"})
                    evidence["observations"][label] = observation
                    save()
                    return observation
            time.sleep(5)
        evidence["limitations"].append({"label": label, "not_observed_seconds": seconds})
        save()
        return None

    def schedule(label, input_value=None, arn=None, disabled=False, update=False):
        if not update and len(owned["schedules"]) >= 6:
            raise RuntimeError("Six schedule hard cap")
        target = {"Arn": arn or pipeline_arn, "RoleArn": owned["roles"]["scheduler"]["Arn"],
                  "DeadLetterConfig": {"Arn": owned["queues"]["dlq"]["arn"]},
                  "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}
        if input_value is not None:
            target["Input"] = input_value
        parameters = {"Name": label, "GroupName": name, "Target": target,
                      "FlexibleTimeWindow": {"Mode": "OFF"}, "State": "DISABLED" if disabled else "ENABLED",
                      "ScheduleExpression": "at(" + (datetime.now(timezone.utc) + timedelta(seconds=65)).strftime("%Y-%m-%dT%H:%M:%S") + ")"}
        result = call("admission/" + label, "scheduler", "update_schedule" if update else "create_schedule", parameters, optional=True)
        if "Error" not in result:
            if not update:
                owned["schedules"].append(label)
                save()
            call("get/" + label, "scheduler", "get_schedule", {"Name": label, "GroupName": name})
        return "Error" not in result

    def role_policy(deny=False):
        statements = [{"Effect": "Allow", "Action": "codepipeline:StartPipelineExecution", "Resource": pipeline_arn},
                      {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": owned["queues"]["dlq"]["arn"]}]
        if deny:
            statements.append({"Effect": "Deny", "Action": "codepipeline:StartPipelineExecution", "Resource": pipeline_arn})
        call("scheduler-policy-" + ("deny" if deny else "allow"), "iam", "put_role_policy", {
            "RoleName": owned["roles"]["scheduler"]["RoleName"], "PolicyName": "owned",
            "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})

    def receive_dlq(label, seconds):
        deadline = min(started + 895, time.monotonic() + seconds)
        messages = []
        while time.monotonic() < deadline:
            result = call(label + "/receive", "sqs", "receive_message", {
                "QueueUrl": owned["queues"]["dlq"]["url"], "WaitTimeSeconds": 5,
                "MaxNumberOfMessages": 10, "MessageAttributeNames": ["All"], "MessageSystemAttributeNames": ["All"]})
            for message in result.get("Messages", []):
                messages.append(message)
                call(label + "/ack", "sqs", "delete_message", {
                    "QueueUrl": owned["queues"]["dlq"]["url"], "ReceiptHandle": message["ReceiptHandle"]})
            if messages:
                break
        evidence["observations"][label + "/dlq"] = messages
        save()
        return messages

    save()
    try:
        call("bucket", "s3", "create_bucket", {"Bucket": name})
        owned["bucket"] = name
        save()
        call("versioning", "s3", "put_bucket_versioning", {"Bucket": name, "VersioningConfiguration": {"Status": "Enabled"}})
        call("encryption", "s3", "put_bucket_encryption", {"Bucket": name, "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}})
        old = call("source-old", "s3", "put_object", {"Bucket": name, "Key": "source/input.zip", "Body": archive("old-owned-source\n")})
        latest = call("source-latest", "s3", "put_object", {"Bucket": name, "Key": "source/input.zip", "Body": archive("latest-owned-source\n")})
        evidence["source_versions"] = {"old": old["VersionId"], "latest": latest["VersionId"]}
        queue = call("dlq", "sqs", "create_queue", {"QueueName": name, "tags": {"stackd-probe": name}})
        owned["queues"]["dlq"] = {"name": name, "url": queue["QueueUrl"]}
        save()
        owned["queues"]["dlq"]["arn"] = call("dlq-arn", "sqs", "get_queue_attributes", {
            "QueueUrl": queue["QueueUrl"], "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        for kind in ("pipeline", "scheduler"):
            statement = {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com" if kind == "pipeline" else "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
            if kind == "scheduler":
                statement["Condition"] = {"StringEquals": {"aws:SourceAccount": args.account}, "ArnEquals": {"aws:SourceArn": group_arn}}
            role = call("role-" + kind, "iam", "create_role", {"RoleName": name + "-" + kind,
                "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
                "Tags": [{"Key": "stackd-probe", "Value": name}]})["Role"]
            owned["roles"][kind] = role
            save()
        call("pipeline-policy", "iam", "put_role_policy", {"RoleName": owned["roles"]["pipeline"]["RoleName"], "PolicyName": "owned",
            "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetBucketVersioning", "s3:GetBucketLocation", "s3:GetBucketAcl", "s3:ListBucket"], "Resource": "arn:aws:s3:::" + name},
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging", "s3:PutObject", "s3:PutObjectAcl"],
                 "Resource": "arn:aws:s3:::" + name + "/*"},
                {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
                 "Condition": {"StringEquals": {"kms:ViaService": "s3." + REGION + ".amazonaws.com", "kms:CallerAccount": args.account},
                               "StringLike": {"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::" + name + "/*"}}}]})})
        role_policy()
        call("group", "scheduler", "create_schedule_group", {"Name": name})
        owned["group"] = name
        save()
        time.sleep(15)
        declaration = {"name": name, "roleArn": owned["roles"]["pipeline"]["Arn"], "pipelineType": "V2", "executionMode": "QUEUED",
            "artifactStore": {"type": "S3", "location": name}, "variables": [{"name": "Marker", "defaultValue": "default-marker"}],
            "stages": [{"name": "Source", "actions": [{"name": "Source", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "configuration": {"S3Bucket": name, "S3ObjectKey": "source/input.zip", "PollForSourceChanges": "false"}, "outputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]},
                {"name": "Deploy", "actions": [{"name": "Deploy", "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {"BucketName": name, "Extract": "false", "ObjectKey": "deploy/#{codepipeline.PipelineExecutionId}.zip"}, "inputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]}]}
        call("pipeline", "codepipeline", "create_pipeline", {"pipeline": declaration})
        owned["pipeline"] = name
        save()
        # One disabled schedule name is reused for admission variants; no foreign execution.
        foreign = pipeline_arn.replace(args.account, "111122223333")
        admitted = schedule("arn-admission", arn=foreign, disabled=True)
        schedule("arn-admission", arn=pipeline_arn + "/invalid", disabled=True, update=admitted)
        initial = await_execution("initial", set(), 140)
        if not initial:
            raise RuntimeError("Initial automatic execution did not settle")
        if initial["execution"]["status"] != "Succeeded":
            evidence["limitations"].append({"label": "initial", "status": initial["execution"]["status"]})
            save()
        baseline = {r["pipelineExecutionId"] for r in history("before-omitted")}
        if schedule("omitted"):
            await_execution("omitted", baseline)
        payload = {"name": name + "-never-created", "variables": [{"name": "Marker", "value": "input-marker"}],
                   "sourceRevisions": [{"actionName": "Source", "revisionType": "S3_OBJECT_VERSION_ID", "revisionValue": old["VersionId"]}],
                   "clientRequestToken": str(uuid.uuid4())}
        for label in ("supplied-first", "supplied-repeat"):
            baseline = {r["pipelineExecutionId"] for r in history("before-" + label)}
            if schedule(label, json.dumps(payload)):
                observed = await_execution(label, baseline)
                if observed is None:
                    receive_dlq(label, 10)
                    # Isolate the remaining overrides after a native name-redirection failure.
                    payload.pop("name", None)
        baseline = {r["pipelineExecutionId"] for r in history("before-deny")}
        role_policy(deny=True)
        time.sleep(15)
        if schedule("deny", "owned deny marker"):
            receive_dlq("deny", 160)
        evidence["observations"]["deny/new_executions"] = [r for r in history("after-deny") if r["pipelineExecutionId"] not in baseline]
        role_policy()
        time.sleep(15)
        baseline = {r["pipelineExecutionId"] for r in history("before-recovery")}
        if schedule("recovery", "not JSON: owned recovery marker"):
            await_execution("recovery", baseline)
        evidence["complete"] = all(
            evidence["observations"].get(k, {}).get("execution", {}).get("status") == "Succeeded"
            and "artifact" in evidence["observations"].get(k, {})
            for k in ("initial", "omitted", "supplied-first", "supplied-repeat", "recovery")
        ) and any(
            message.get("MessageAttributes", {}).get("ERROR_CODE", {}).get("StringValue") == "AccessDeniedException"
            for message in evidence["observations"].get("deny/dlq", [])
        ) and not evidence["observations"]["deny/new_executions"]
        save()
    except Exception as error:
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        save()
        raise
    finally:
        cleaning = True
        failures = []

        def cleanup(label, service, operation, parameters, absent=()):
            try:
                result = call(label, service, operation, parameters, optional=True)
                if result.get("Error", {}).get("Code") not in (None, *absent):
                    failures.append(label)
                return result
            except Exception as error:
                failures.append(label + ": " + str(error))
                return {}

        for schedule_name in owned["schedules"]:
            cleanup("delete-schedule/" + schedule_name, "scheduler", "delete_schedule", {"Name": schedule_name, "GroupName": name}, ("ResourceNotFoundException",))
            result = cleanup("absent-schedule/" + schedule_name, "scheduler", "get_schedule", {"Name": schedule_name, "GroupName": name}, ("ResourceNotFoundException",))
            if result.get("Error", {}).get("Code") != "ResourceNotFoundException":
                failures.append("schedule-still-present/" + schedule_name)
        if owned.get("group"):
            cleanup("delete-group", "scheduler", "delete_schedule_group", {"Name": name}, ("ResourceNotFoundException",))
        if owned.get("pipeline"):
            result = cleanup("cleanup-history", "codepipeline", "list_pipeline_executions", {"pipelineName": name})
            for execution in result.get("pipelineExecutionSummaries", []):
                if execution["status"] in ("InProgress", "Stopping"):
                    cleanup("stop-owned", "codepipeline", "stop_pipeline_execution", {"pipelineName": name, "pipelineExecutionId": execution["pipelineExecutionId"], "abandon": True})
            cleanup("delete-pipeline", "codepipeline", "delete_pipeline", {"name": name})
            result = cleanup("absent-pipeline", "codepipeline", "get_pipeline", {"name": name}, ("PipelineNotFoundException",))
            if result.get("Error", {}).get("Code") != "PipelineNotFoundException":
                failures.append("pipeline-still-present")
        if owned.get("bucket"):
            while time.monotonic() - started < 1180:
                versions = cleanup("owned-versions", "s3", "list_object_versions", {"Bucket": name})
                objects = [{"Key": item["Key"], "VersionId": item["VersionId"]}
                           for item in versions.get("Versions", []) + versions.get("DeleteMarkers", [])]
                if not objects:
                    break
                deleted = cleanup("delete-owned-versions", "s3", "delete_objects", {"Bucket": name, "Delete": {"Objects": objects}})
                if deleted.get("Errors"):
                    failures.append("object-version-deletion-errors")
                    break
            cleanup("delete-bucket", "s3", "delete_bucket", {"Bucket": name}, ("NoSuchBucket",))
        for role in owned["roles"].values():
            cleanup("delete-policy/" + role["RoleName"], "iam", "delete_role_policy", {"RoleName": role["RoleName"], "PolicyName": "owned"}, ("NoSuchEntity",))
            cleanup("delete-role/" + role["RoleName"], "iam", "delete_role", {"RoleName": role["RoleName"]}, ("NoSuchEntity",))
        for queue in owned["queues"].values():
            cleanup("delete-dlq", "sqs", "delete_queue", {"QueueUrl": queue["url"]}, ("AWS.SimpleQueueService.NonExistentQueue",))
        evidence["absence_verification"] = verify_absence(clients, owned)
        final_absence = {r["resource"]: r["absent"] for r in evidence["absence_verification"]}
        evidence["cleanup_failures"] = failures
        evidence["cleanup_verified"] = not failures and bool(final_absence) and all(final_absence.values())
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save()
        print(json.dumps({"output": str(args.output), "complete": evidence["complete"], "cleanup_verified": evidence["cleanup_verified"], "failure": evidence.get("failure")}), flush=True)
    if not evidence["complete"] or not evidence["cleanup_verified"]:
        raise RuntimeError("Native workflow or exact-owned cleanup incomplete; retained evidence")


if __name__ == "__main__":
    main()
