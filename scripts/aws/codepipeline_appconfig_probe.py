#!/usr/bin/env python3
"""Capture one native S3 -> CodePipeline -> AppConfig deployment and remove it.

One V2 pipeline, versioned bucket, pipeline/consumer IAM roles and AppConfig
application/environment/profile/zero-duration strategy. --build adds one small
five-minute-bounded CodeBuild project, role and log group. No customer KMS keys
or account-setting changes. Uses the official SDK and bounded history collector.
"""
import argparse
import base64
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

from cloudtrail_events import CollectionError, collect_history, collect_s3
from codepipeline_forwarded_identity import conditions, discover, exact_statement

REGION = "us-east-1"


def main():
    global REGION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--region", default=REGION, help="Commercial AWS region for the owned capture")
    parser.add_argument("--build", action="store_true", help="Run one small native CodeBuild transformation before deployment")
    parser.add_argument("--artifact-condition", type=json.loads,
                        help="Consumer S3 read IAM Condition as JSON; {} grants unconditional reads; omitted grants none")
    parser.add_argument("--artifact-trail", action="store_true", help="Capture exact-owned S3 reads through a temporary data trail")
    parser.add_argument("--discover-called-via", action="store_true", help="Calibrate the native forwarding value with bounded tagged sessions")
    args = parser.parse_args()
    REGION = args.region
    account = args.account
    if args.discover_called_via:
        if args.artifact_condition is not None:
            parser.error("--discover-called-via supplies its own artifact conditions")
        args.artifact_condition = conditions()
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite existing native evidence")
    session = boto3.Session(region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)
    clients = {name: session.client(name, config=config) for name in
               ("sts", "s3", "iam", "codepipeline", "codebuild", "appconfig", "cloudtrail", "logs")}
    actor = clients["sts"].get_caller_identity()
    if actor["Account"] != account:
        raise RuntimeError("Refusing non-probe account")
    prefix = "stackd-pipeline-" + uuid.uuid4().hex[:20]
    content = b'{"source":"native-codepipeline","enabled":true,"value":17}'
    expected_content = content.replace(b':17}', b':18}') if args.build else content
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("config.json", content)
    started = datetime.now(timezone.utc)
    owned = {}
    requests = {}
    evidence = {"source": "native AWS CodePipeline/AppConfig", "account": account,
                "region": REGION, "actor": actor["Arn"], "observed_at": started.isoformat(),
                "prefix": prefix, "owned": owned, "calls": [], "cleanup": [],
                "bounds": {"pipelines": 1, "pipeline_type": "V2", "buckets": 1,
                           "roles": 3 if args.build else 2, "builds": 1 if args.build else 0, "customer_kms_keys": 0,
                           "execution_wait_seconds": 480, "build_timeout_minutes": 5 if args.build else None},
                "complete": False, "cleanup_verified": False}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    def call(service, method, parameters=None, *, label=None, cleanup=False, allowed=("Success",), api_client=None):
        parameters = parameters or {}
        api_client = api_client or clients[service]
        operation = api_client.meta.method_to_api_mapping[method]
        try:
            output = getattr(api_client, method)(**parameters)
            metadata = output.pop("ResponseMetadata", {})
            for field in ("Body", "Content"):
                if field in output and hasattr(output[field], "read"):
                    with output[field] as stream:
                        output[field] = {"base64": base64.b64encode(stream.read()).decode()}
            code = "Success"
        except ClientError as error:
            metadata = error.response.get("ResponseMetadata", {})
            output = error.response["Error"]
            code = output["Code"]
        request_id = metadata.get("RequestId")
        recorded_parameters = {key: ("<owned ZIP bytes>" if key == "Body" else value)
                               for key, value in parameters.items()}
        row = {"service": service, "operation": operation, "label": label or operation,
               "parameters": recorded_parameters, "code": code, "output": output,
               "request_id": request_id, "http_status": metadata.get("HTTPStatusCode")}
        evidence["cleanup" if cleanup else "calls"].append(row)
        if request_id and service in ("appconfig", "codepipeline", "codebuild") and not cleanup:
            requests[request_id] = row["label"]
        save()
        print(service + ":" + row["label"] + ": " + code, flush=True)
        if code not in allowed:
            raise RuntimeError(service + ":" + operation + ": " + json.dumps(output, default=str))
        return output

    def create_after_role_propagation(service, method, parameters, *, code, message):
        """Bound only the two captured fresh-role service-assumption refusals."""
        deadline = time.monotonic() + 60
        while True:
            output = call(service, method, parameters, allowed=("Success", code))
            if output.get("Code") != code:
                return output
            if output.get("Message") != message or time.monotonic() >= deadline:
                raise RuntimeError(service + ":" + method + ": " + json.dumps(output))
            time.sleep(2)

    def collect_artifact_events(request_ids):
        try:
            evidence["artifact_events"] = collect_s3(
                lambda p: clients["s3"].list_objects_v2(**p),
                lambda p: clients["s3"].get_object(**p), request_ids,
                bucket=prefix, prefix="audit/",
                related=lambda event: (event.get("requestParameters") or {}).get("bucketName") == prefix,
                previous=evidence.get("artifact_events"))
        except CollectionError as error:
            evidence["artifact_events"] = error.result
            save()
            raise
        save()
        return evidence["artifact_events"]["events"]

    try:
        role = call("iam", "create_role", {"RoleName": prefix, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": prefix}]})["Role"]
        owned["role"] = role["RoleName"]
        bucket_arn = "arn:aws:s3:::" + prefix
        call("iam", "put_role_policy", {"RoleName": prefix, "PolicyName": "pipeline", "PolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": [bucket_arn, bucket_arn + "/*"]},
                {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
                 "Condition": {"StringEquals": {"kms:ViaService": "s3." + REGION + ".amazonaws.com", "kms:CallerAccount": account}}}]} )})
        owned["role_policy"] = True
        bucket_request = {"Bucket": prefix}
        if REGION != "us-east-1":
            bucket_request["CreateBucketConfiguration"] = {"LocationConstraint": REGION}
        call("s3", "create_bucket", bucket_request); owned["bucket"] = prefix
        call("s3", "put_bucket_versioning", {"Bucket": prefix, "VersioningConfiguration": {"Status": "Enabled"}})
        uploaded = call("s3", "put_object", {"Bucket": prefix, "Key": "source.zip", "Body": archive.getvalue()})
        evidence["source_version"] = uploaded["VersionId"]
        if args.artifact_trail:
            evidence["bounds"]["data_trails"] = 1
            evidence["bounds"]["data_delivery_wait_seconds"] = 1200
            trail_arn = "arn:aws:cloudtrail:" + REGION + ":" + account + ":trail/" + prefix
            call("s3", "put_bucket_policy", {"Bucket": prefix, "Policy": json.dumps({
                "Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl",
                     "Resource": bucket_arn, "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
                    {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject",
                     "Resource": bucket_arn + "/audit/AWSLogs/" + account + "/*",
                     "Condition": {"StringEquals": {"aws:SourceArn": trail_arn, "s3:x-amz-acl": "bucket-owner-full-control"}}}]})})
            call("cloudtrail", "create_trail", {"Name": prefix, "S3BucketName": prefix, "S3KeyPrefix": "audit",
                 "IsMultiRegionTrail": False, "IncludeGlobalServiceEvents": False})
            owned["trail"] = prefix
            call("cloudtrail", "put_event_selectors", {"TrailName": prefix, "AdvancedEventSelectors": [
                {"Name": "owned-artifact-reads", "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "readOnly", "Equals": ["true"]},
                    {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                    {"Field": "resources.ARN", "StartsWith": [bucket_arn + "/source.zip", bucket_arn + "/" + prefix[:20]]}]}]})
            call("cloudtrail", "start_logging", {"Name": prefix})
        if args.build:
            build_name = prefix + "-build"
            build_role = call("iam", "create_role", {"RoleName": build_name, "AssumeRolePolicyDocument": json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
                "Tags": [{"Key": "stackd-probe", "Value": prefix}]})["Role"]
            owned["build_role"] = build_name
            log_arn = "arn:aws:logs:" + REGION + ":" + account + ":log-group:" + build_name
            call("iam", "put_role_policy", {"RoleName": build_name, "PolicyName": "build", "PolicyDocument": json.dumps({
                "Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"], "Resource": bucket_arn + "/*"},
                    {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:GetBucketAcl"], "Resource": bucket_arn},
                    {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": log_arn + ":*"},
                    {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
                     "Condition": {"StringEquals": {"kms:ViaService": "s3." + REGION + ".amazonaws.com", "kms:CallerAccount": account}}}]} )})
            owned["build_role_policy"] = True
            call("logs", "create_log_group", {"logGroupName": build_name, "tags": {"stackd-probe": prefix}})
            owned["build_logs"] = build_name
            project = create_after_role_propagation("codebuild", "create_project", {
                "name": build_name, "serviceRole": build_role["Arn"], "timeoutInMinutes": 5, "queuedTimeoutInMinutes": 5,
                "source": {"type": "CODEPIPELINE", "buildspec": json.dumps({"version": 0.2, "phases": {"build": {"commands": [
                    "python3 -c \"import json,pathlib; p=pathlib.Path('config.json'); d=json.loads(p.read_text()); d['value']+=1; p.write_text(json.dumps(d,separators=(',',':')))\""
                ]}}, "artifacts": {"files": ["config.json"]}})},
                "artifacts": {"type": "CODEPIPELINE"},
                "environment": {"type": "LINUX_CONTAINER", "image": "aws/codebuild/standard:7.0", "computeType": "BUILD_GENERAL1_SMALL"},
                "logsConfig": {"cloudWatchLogs": {"status": "ENABLED", "groupName": build_name}},
                "tags": [{"key": "stackd-probe", "value": prefix}]}, code="InvalidInputException",
                message="CodeBuild is not authorized to perform: sts:AssumeRole on service role. Please verify that: 1) The provided service role exists, 2) The role name is case-sensitive and matches exactly, and 3) The role has the necessary trust policy configured.")["project"]
            owned["build_project"] = build_name
            call("iam", "put_role_policy", {"RoleName": prefix, "PolicyName": "codebuild", "PolicyDocument": json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["codebuild:StartBuild", "codebuild:BatchGetBuilds", "codebuild:StopBuild"], "Resource": project["arn"]}]})})
            owned["codebuild_policy"] = True
        application = call("appconfig", "create_application", {"Name": prefix, "Tags": {"stackd-probe": prefix}})
        owned["application"] = application["Id"]
        environment = call("appconfig", "create_environment", {"ApplicationId": application["Id"], "Name": "probe"})
        owned["environment"] = environment["Id"]
        profile = call("appconfig", "create_configuration_profile", {"ApplicationId": application["Id"], "Name": "pipeline",
                        "LocationUri": "codepipeline://" + prefix, "Type": "AWS.Freeform"})
        owned["profile"] = profile["Id"]
        strategy = call("appconfig", "create_deployment_strategy", {"Name": prefix, "DeploymentDurationInMinutes": 0,
                        "FinalBakeTimeInMinutes": 0, "GrowthFactor": 100, "GrowthType": "LINEAR", "ReplicateTo": "NONE"})
        owned["strategy"] = strategy["Id"]
        appconfig_resources = ["arn:aws:appconfig:" + REGION + ":" + account + ":application/" + application["Id"],
                               "arn:aws:appconfig:" + REGION + ":" + account + ":application/" + application["Id"] + "/*",
                               "arn:aws:appconfig:" + REGION + ":" + account + ":deploymentstrategy/" + strategy["Id"]]
        call("iam", "put_role_policy", {"RoleName": prefix, "PolicyName": "appconfig", "PolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["appconfig:StartDeployment", "appconfig:StopDeployment", "appconfig:GetDeployment"],
            "Resource": appconfig_resources}]})})
        owned["appconfig_policy"] = True
        consumer_name = prefix + "-consumer"
        consumer_role = call("iam", "create_role", {"RoleName": consumer_name, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::" + account + ":root"},
            "Action": ["sts:AssumeRole", "sts:TagSession"] if args.discover_called_via else "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": prefix}]})["Role"]
        owned["consumer_role"] = consumer_name
        consumer_statements = [{"Effect": "Allow", "Action": "appconfig:StartDeployment", "Resource": appconfig_resources}]
        if args.artifact_condition is not None:
            artifact_statement = {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"], "Resource": "arn:aws:s3:::" + prefix + "/*"}
            if args.artifact_condition:
                artifact_statement["Condition"] = args.artifact_condition
            evidence["consumer_artifact_condition"] = args.artifact_condition
            consumer_statements.extend([
                artifact_statement,
                {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "arn:aws:kms:" + REGION + ":" + account + ":key/*",
                 "Condition": {"StringEquals": {"kms:ViaService": "s3." + REGION + ".amazonaws.com"}}},
            ])
            evidence["consumer_artifact_read_grant"] = True
        if args.discover_called_via:
            consumer_statements.append(exact_statement("arn:aws:s3:::" + prefix + "/*"))
        call("iam", "put_role_policy", {"RoleName": consumer_name, "PolicyName": "deploy", "PolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": consumer_statements})})
        owned["consumer_policy"] = True
        if args.artifact_trail:
            readiness_requests = {}
            for attempt in range(40):
                call("s3", "get_object", {"Bucket": prefix, "Key": "source.zip"}, label="TrailReadiness")
                readiness_requests[evidence["calls"][-1]["request_id"]] = "TrailReadiness"
                if any(row["call_label"] == "TrailReadiness" for row in collect_artifact_events(readiness_requests)):
                    break
                time.sleep(30)
            else:
                raise RuntimeError("Owned data trail did not deliver a source read within 1200 seconds")
        pipeline = {"name": prefix, "roleArn": role["Arn"], "pipelineType": "V2", "executionMode": "SUPERSEDED",
                    "artifactStore": {"type": "S3", "location": prefix}, "stages": [
            {"name": "Source", "actions": [{"name": "Source", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
              "configuration": {"S3Bucket": prefix, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, "outputArtifacts": [{"name": "Configuration"}], "runOrder": 1}]},
            {"name": "Deploy", "actions": [{"name": "AppConfig", "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "AppConfig", "version": "1"},
              "configuration": {"Application": application["Id"], "Environment": environment["Id"], "ConfigurationProfile": profile["Id"],
                                "DeploymentStrategy": strategy["Id"], "InputArtifactConfigurationPath": "config.json"},
              "inputArtifacts": [{"name": "Configuration"}], "runOrder": 1}]}]}
        if args.build:
            pipeline["stages"].insert(1, {"name": "Build", "actions": [{"name": "Build",
                "actionTypeId": {"category": "Build", "owner": "AWS", "provider": "CodeBuild", "version": "1"},
                "configuration": {"ProjectName": build_name}, "inputArtifacts": [{"name": "Configuration"}],
                "outputArtifacts": [{"name": "BuiltConfiguration"}], "runOrder": 1}]})
            pipeline["stages"][-1]["actions"][0]["inputArtifacts"] = [{"name": "BuiltConfiguration"}]
        create_after_role_propagation("codepipeline", "create_pipeline",
            {"pipeline": pipeline, "tags": [{"key": "stackd-probe", "value": prefix}]},
            code="InvalidStructureException", message="CodePipeline is not authorized to perform AssumeRole on role " + role["Arn"])
        owned["pipeline"] = prefix
        deadline = time.monotonic() + 480
        retried_stages = set()
        while True:
            executions = call("codepipeline", "list_pipeline_executions", {"pipelineName": prefix, "maxResults": 10})["pipelineExecutionSummaries"]
            if executions:
                owned["execution"] = executions[0]["pipelineExecutionId"]
                state = call("codepipeline", "get_pipeline_execution", {"pipelineName": prefix, "pipelineExecutionId": owned["execution"]})["pipelineExecution"]
                if state["status"] == "Failed":
                    actions = call("codepipeline", "list_action_executions", {"pipelineName": prefix,
                                   "filter": {"pipelineExecutionId": owned["execution"]}})["actionExecutionDetails"]
                    failed = [action for action in actions if action["status"] == "Failed"]
                    result = failed[0].get("output", {}).get("executionResult", {}) if len(failed) == 1 else {}
                    build_refusal = args.build and len(failed) == 1 and failed[0]["stageName"] == "Build" and (
                        "is not authorized to perform: codebuild:StartBuild on resource: " + project["arn"] +
                        " because no identity-based policy allows the codebuild:StartBuild action") in result.get("externalExecutionSummary", "")
                    deployment_refusal = len(failed) == 1 and failed[0]["stageName"] == "Deploy" and (
                        result.get("errorDetails", {}).get("code") == "PermissionError")
                    source_refusal = len(failed) == 1 and failed[0]["stageName"] == "Source" and (
                        result.get("errorDetails", {}).get("code") == "PermissionError" and
                        "The provided role cannot be assumed:" in result.get("externalExecutionSummary", "") and
                        role["Arn"] in result.get("externalExecutionSummary", ""))
                    if len(failed) == 1 and failed[0]["stageName"] not in retried_stages and (build_refusal or deployment_refusal or source_refusal):
                        # Preserve the actual fresh-role refusal and retry only
                        # that stage once. A persistent permission error still fails.
                        stage = failed[0]["stageName"]
                        evidence.setdefault("role_policy_retries", []).append({"wait_seconds": 15, "stage": stage, "failed_action": failed[0]["actionExecutionId"]})
                        time.sleep(15)
                        call("codepipeline", "retry_stage_execution", {"pipelineName": prefix, "stageName": stage,
                             "pipelineExecutionId": owned["execution"], "retryMode": "FAILED_ACTIONS"})
                        retried_stages.add(stage)
                        continue
                if state["status"] not in ("InProgress", "Stopping"):
                    evidence["execution_status"] = state["status"]
                    break
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned pipeline did not reach a terminal state within 480 seconds")
            time.sleep(5)
        call("codepipeline", "get_pipeline_state", {"name": prefix})
        actions = call("codepipeline", "list_action_executions", {"pipelineName": prefix, "filter": {"pipelineExecutionId": owned["execution"]}})["actionExecutionDetails"]
        if args.build:
            build_ids = call("codebuild", "list_builds_for_project", {"projectName": build_name}).get("ids", [])
            owned["build_ids"] = build_ids
            if build_ids:
                call("codebuild", "batch_get_builds", {"ids": build_ids})
        deployments = call("appconfig", "list_deployments", {"ApplicationId": application["Id"], "EnvironmentId": environment["Id"]})
        for deployment in deployments.get("Items", []):
            call("appconfig", "get_deployment", {"ApplicationId": application["Id"], "EnvironmentId": environment["Id"], "DeploymentNumber": deployment["DeploymentNumber"]})
        if evidence["execution_status"] != "Succeeded":
            raise RuntimeError("Owned native pipeline ended " + evidence["execution_status"])
        consumed = call("appconfig", "get_configuration", {"Application": application["Id"], "Environment": environment["Id"],
                        "Configuration": profile["Id"], "ClientId": prefix})
        if base64.b64decode(consumed["Content"]["base64"]) != expected_content:
            raise RuntimeError("Native AppConfig did not return the actual source artifact bytes")
        artifacts = sorted({(artifact["s3location"]["bucket"], artifact["s3location"]["key"])
                            for action in actions for direction in ("input", "output")
                            for artifact in action.get(direction, {}).get(direction + "Artifacts", [])})
        artifact_versions = []
        for bucket, key in artifacts:
            metadata = call("s3", "head_object", {"Bucket": bucket, "Key": key}, label="HeadPipelineArtifact")
            artifact_versions.append({"Bucket": bucket, "Key": key, "VersionId": metadata["VersionId"]})
            call("s3", "get_object", {"Bucket": bucket, "Key": key}, label="GetPipelineArtifact")
        deployed_version = consumed["ConfigurationVersion"]
        deployment_request = {"ApplicationId": application["Id"], "EnvironmentId": environment["Id"],
                              "ConfigurationProfileId": profile["Id"], "DeploymentStrategyId": strategy["Id"], "ConfigurationVersion": deployed_version}
        call("appconfig", "start_deployment", deployment_request, label="StartDeploymentCompletedActionVersion")
        # Keep temporary credential material only in the SDK clients, never in evidence.
        assumed = clients["sts"].assume_role(RoleArn=consumer_role["Arn"], RoleSessionName="appconfig-only", DurationSeconds=900)
        credentials = assumed["Credentials"]
        evidence["consumer_session"] = {"arn": assumed["AssumedRoleUser"]["Arn"], "expiration": str(credentials["Expiration"]),
                                        "request_id": assumed["ResponseMetadata"]["RequestId"]}
        consumer = {service: session.client(service, config=config, aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
                    for service in ("appconfig", "s3", "codepipeline")}
        call("s3", "get_object", {"Bucket": artifacts[0][0], "Key": artifacts[0][1]}, label="ConsumerArtifactRead",
             api_client=consumer["s3"], allowed=("Success", "AccessDenied"))
        call("codepipeline", "get_pipeline", {"name": prefix}, label="ConsumerCodePipelineDenied",
             api_client=consumer["codepipeline"], allowed=("AccessDenied", "AccessDeniedException"))
        observed_deployment_codes = ("Success", "AccessDeniedException", "BadRequestException", "ResourceNotFoundException", "ConflictException", "InternalServerException")
        call("appconfig", "start_deployment", deployment_request, label="StartDeploymentConsumer",
             api_client=consumer["appconfig"], allowed=observed_deployment_codes)
        consumer_deployment_succeeded = evidence["calls"][-1]["code"] == "Success"
        if args.discover_called_via:
            discover(session, clients, config, consumer_role["Arn"], deployment_request, call, evidence, save)
        for location in artifact_versions:
            call("s3", "delete_object", location, label="DeleteExactPipelineArtifactVersion")
            call("s3", "get_object", location, label="DeletedPipelineArtifactAbsent", allowed=("NoSuchVersion",))
        call("appconfig", "start_deployment", deployment_request, label="StartDeploymentAfterArtifactRemoval",
             api_client=consumer["appconfig"], allowed=observed_deployment_codes)
        call("appconfig", "start_deployment", deployment_request, label="StartDeploymentRootAfterArtifactRemoval",
             allowed=observed_deployment_codes)
        call("codepipeline", "delete_pipeline", {"name": prefix})
        call("codepipeline", "get_pipeline", {"name": prefix}, allowed=("PipelineNotFoundException",))
        del owned["pipeline"]
        call("appconfig", "start_deployment", deployment_request, label="StartDeploymentAfterPipelineRemoval",
             api_client=consumer["appconfig"], allowed=observed_deployment_codes)
        call("appconfig", "start_deployment", deployment_request, label="StartDeploymentRootAfterPipelineRemoval",
             allowed=observed_deployment_codes)
        call("appconfig", "start_deployment", {**deployment_request, "ConfigurationVersion": str(uuid.uuid4())},
             label="StartDeploymentUnknownActionVersion", allowed=observed_deployment_codes)
        if args.artifact_trail:
            direct_reads = {row["request_id"] for row in evidence["calls"] if row["label"] == "ConsumerArtifactRead"}
            for attempt in range(40):
                rows = collect_artifact_events({})
                forwarded = [row["event"] for row in rows if row["event"].get("eventName") == "GetObject" and
                             row["event"].get("requestID") not in direct_reads and
                             row["event"].get("userIdentity", {}).get("sessionContext", {}).get("sessionIssuer", {}).get("arn") == consumer_role["Arn"]]
                if forwarded:
                    evidence["consumer_forwarded_reads"] = forwarded
                    save()
                    if not consumer_deployment_succeeded or any(not event.get("errorCode") for event in forwarded):
                        break
                time.sleep(30)
            else:
                raise RuntimeError("Owned consumer forwarded S3 read matching the deployment outcome was not delivered within 1200 seconds")
        evidence["complete"] = True
    except Exception as error:
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cleanup_errors = []

        def cleanup(service, method, parameters, allowed=("Success",)):
            try:
                return call(service, method, parameters, cleanup=True, allowed=allowed)
            except Exception as error:
                cleanup_errors.append({"service": service, "operation": method, "error": str(error)})
                return {}

        if "pipeline" in owned:
            cleanup("codepipeline", "delete_pipeline", {"name": prefix})
            cleanup("codepipeline", "get_pipeline", {"name": prefix}, ("PipelineNotFoundException",))
        if "build_project" in owned:
            build_ids = cleanup("codebuild", "list_builds_for_project", {"projectName": owned["build_project"]}).get("ids", [])
            owned["build_ids"] = build_ids
            if build_ids:
                builds = cleanup("codebuild", "batch_get_builds", {"ids": build_ids}).get("builds", [])
                for build in builds:
                    if build["buildStatus"] == "IN_PROGRESS":
                        cleanup("codebuild", "stop_build", {"id": build["id"]})
                stopped_deadline = time.monotonic() + 90
                while any(build["buildStatus"] == "IN_PROGRESS" for build in builds):
                    if time.monotonic() >= stopped_deadline:
                        cleanup_errors.append({"service": "codebuild", "error": "Owned build did not stop within 90 seconds", "ids": build_ids})
                        break
                    time.sleep(2)
                    builds = cleanup("codebuild", "batch_get_builds", {"ids": build_ids}).get("builds", [])
                deleted = cleanup("codebuild", "batch_delete_builds", {"ids": build_ids})
                if deleted.get("buildsNotDeleted"):
                    cleanup_errors.append({"service": "codebuild", "buildsNotDeleted": deleted["buildsNotDeleted"]})
            cleanup("codebuild", "delete_project", {"name": owned["build_project"]})
            remaining = cleanup("codebuild", "batch_get_projects", {"names": [owned["build_project"]]})
            if remaining.get("projects") or owned["build_project"] not in remaining.get("projectsNotFound", []):
                cleanup_errors.append({"service": "codebuild", "error": "Owned project absence not verified"})
        if "build_logs" in owned:
            cleanup("logs", "delete_log_group", {"logGroupName": owned["build_logs"]})
            groups = cleanup("logs", "describe_log_groups", {"logGroupNamePrefix": owned["build_logs"]}).get("logGroups", [])
            if any(group["logGroupName"] == owned["build_logs"] for group in groups):
                cleanup_errors.append({"service": "logs", "error": "Owned log group remains"})
        if owned.get("build_role_policy"):
            cleanup("iam", "delete_role_policy", {"RoleName": owned["build_role"], "PolicyName": "build"})
        if "build_role" in owned:
            cleanup("iam", "delete_role", {"RoleName": owned["build_role"]})
            cleanup("iam", "get_role", {"RoleName": owned["build_role"]}, ("NoSuchEntity",))
        if owned.get("codebuild_policy"):
            cleanup("iam", "delete_role_policy", {"RoleName": prefix, "PolicyName": "codebuild"})
        if "environment" in owned:
            rows = cleanup("appconfig", "list_deployments", {"ApplicationId": owned["application"], "EnvironmentId": owned["environment"]}).get("Items", [])
            for row in rows:
                if row["State"] in ("DEPLOYING", "BAKING", "VALIDATING"):
                    cleanup("appconfig", "stop_deployment", {"ApplicationId": owned["application"], "EnvironmentId": owned["environment"], "DeploymentNumber": row["DeploymentNumber"]})
            cleanup("appconfig", "delete_environment", {"ApplicationId": owned["application"], "EnvironmentId": owned["environment"], "DeletionProtectionCheck": "BYPASS"})
        if "profile" in owned:
            cleanup("appconfig", "delete_configuration_profile", {"ApplicationId": owned["application"], "ConfigurationProfileId": owned["profile"], "DeletionProtectionCheck": "BYPASS"})
        if "application" in owned:
            cleanup("appconfig", "delete_application", {"ApplicationId": owned["application"]})
            cleanup("appconfig", "get_application", {"ApplicationId": owned["application"]}, ("ResourceNotFoundException",))
        if "strategy" in owned:
            cleanup("appconfig", "delete_deployment_strategy", {"DeploymentStrategyId": owned["strategy"]})
            cleanup("appconfig", "get_deployment_strategy", {"DeploymentStrategyId": owned["strategy"]}, ("ResourceNotFoundException",))
        if "trail" in owned:
            cleanup("cloudtrail", "delete_trail", {"Name": prefix})
            cleanup("cloudtrail", "get_trail", {"Name": prefix}, ("TrailNotFoundException",))
        if "bucket" in owned:
            try:
                for page in clients["s3"].get_paginator("list_object_versions").paginate(Bucket=prefix):
                    objects = [{"Key": item["Key"], "VersionId": item["VersionId"]} for item in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                    if objects:
                        deleted = cleanup("s3", "delete_objects", {"Bucket": prefix, "Delete": {"Objects": objects, "Quiet": True}})
                        if deleted.get("Errors"):
                            cleanup_errors.append({"service": "s3", "errors": deleted["Errors"]})
                cleanup("s3", "delete_bucket", {"Bucket": prefix})
                cleanup("s3", "head_bucket", {"Bucket": prefix}, ("404",))
            except Exception as error:
                cleanup_errors.append({"service": "s3", "error": str(error)})
        if owned.get("consumer_policy"):
            cleanup("iam", "delete_role_policy", {"RoleName": owned["consumer_role"], "PolicyName": "deploy"})
        if "consumer_role" in owned:
            cleanup("iam", "delete_role", {"RoleName": owned["consumer_role"]})
            cleanup("iam", "get_role", {"RoleName": owned["consumer_role"]}, ("NoSuchEntity",))
        if owned.get("appconfig_policy"):
            cleanup("iam", "delete_role_policy", {"RoleName": prefix, "PolicyName": "appconfig"})
        if owned.get("role_policy"):
            cleanup("iam", "delete_role_policy", {"RoleName": prefix, "PolicyName": "pipeline"})
        if "role" in owned:
            cleanup("iam", "delete_role", {"RoleName": prefix})
            cleanup("iam", "get_role", {"RoleName": prefix}, ("NoSuchEntity",))
        evidence["cleanup_errors"] = cleanup_errors
        evidence["cleanup_verified"] = not cleanup_errors
        save()
        if requests:
            def lookup(parameters):
                return clients["cloudtrail"].lookup_events(**parameters)

            def related(event):
                issuer = event.get("userIdentity", {}).get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
                return issuer in ("arn:aws:iam::" + account + ":role/" + prefix, "arn:aws:iam::" + account + ":role/" + prefix + "-build",
                                  "arn:aws:iam::" + account + ":role/" + prefix + "-consumer")

            try:
                evidence["cloudtrail"] = collect_history(lookup, requests, start_time=started, event_sources=("codepipeline.amazonaws.com", "appconfig.amazonaws.com", "codebuild.amazonaws.com"),
                                                         rounds=12, wait_seconds=30, max_pages=20, related=related)
            except CollectionError as error:
                evidence["cloudtrail"] = error.result
            save()
    if not evidence["cleanup_verified"]:
        raise RuntimeError("Exact-owned cleanup is incomplete; inspect " + str(args.output))
    print(json.dumps({"output": str(args.output), "complete": evidence["complete"], "cleanup_verified": evidence["cleanup_verified"]}))


if __name__ == "__main__":
    main()
