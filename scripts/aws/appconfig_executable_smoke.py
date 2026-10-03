#!/usr/bin/env python3
"""Exercise deployed bytes, owner authority and real Lambda effects through SDKs."""
import argparse
import base64
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess
from appconfig_feature_flags_scenario import run as run_feature_flags


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--telemetry-directory", required=True, help="directory containing the built Lambda telemetry helpers")
    args = parser.parse_args()
    state = Path(args.state_directory).resolve()
    state.mkdir(parents=True, exist_ok=True)
    require(not any(state.iterdir()), "fresh exact-owned state directory required")
    with socket.socket() as listener:
        listener.bind(("0.0.0.0", 0))
        port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true")
    process = StackdProcess(state)
    command = [str(Path(args.binary).resolve()), "-listen", f"0.0.0.0:{port}", "-public-endpoint", endpoint, "-database", str(state / "state.sqlite"), "-clock-start", "2026-09-28T12:00:00Z", "-docker-host", args.docker_host, "-compute-endpoint", f"http://host.docker.internal:{port}"]
    command += ["-lambda-telemetry-directory", str(Path(args.telemetry_directory).resolve())]
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1")
    clients = {service: session.client(service, endpoint_url=endpoint, config=Config(retries={"max_attempts": 0}, read_timeout=120, s3={"addressing_style": "path"})) for service in ("appconfig", "appconfigdata", "iam", "lambda", "s3", "ssm", "secretsmanager", "kms", "cloudwatch", "sts")}
    app, data, iam, functions, objects, parameters, secrets, keys, alarms, sts = [clients[s] for s in ("appconfig", "appconfigdata", "iam", "lambda", "s3", "ssm", "secretsmanager", "kms", "cloudwatch", "sts")]
    name = "stackd-appconfig-smoke-" + uuid.uuid4().hex[:8]
    report = {"observations": {}, "controllers": process.runs, "cleanup": []}
    cleanup = []
    profiles = []
    environments = []
    application = None

    def save():
        (state / "report.json").write_text(json.dumps(report, default=str, indent=2) + "\n")

    def control(path, payload=None):
        request = urllib.request.Request(endpoint + path, data=json.dumps(payload or {}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response)

    def advance(seconds):
        control("/_stackd/clock", {"advance": f"{seconds}s"})
        return control("/_stackd/jobs/drain?limit=4096")

    def expect_error(callback, *codes):
        try:
            callback()
        except ClientError as exc:
            require(exc.response["Error"]["Code"] in codes, str(exc))
            return exc.response["Error"]
        raise AssertionError("Expected " + "/".join(codes))

    def role(suffix, principal, actions):
        role_name = name + suffix
        arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        cleanup.append(("role:" + role_name, lambda: iam.delete_role(RoleName=role_name)))
        iam.put_role_policy(RoleName=role_name, PolicyName="owned", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}))
        cleanup.append(("role-policy:" + role_name, lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="owned")))
        return role_name, arn

    def profile(suffix, **kwargs):
        result = app.create_configuration_profile(ApplicationId=application, Name=name + suffix, **kwargs)
        profiles.append(result["Id"])
        return result["Id"]

    def hosted(pid, content, label):
        return app.create_hosted_configuration_version(ApplicationId=application, ConfigurationProfileId=pid, ContentType="application/json", Content=json.dumps(content).encode(), VersionLabel=label)["VersionNumber"]

    def deploy(pid, version, strategy=None, env=None):
        return app.start_deployment(ApplicationId=application, EnvironmentId=env or environment_id, ConfigurationProfileId=pid, DeploymentStrategyId=strategy or immediate, ConfigurationVersion=str(version))

    def begin(pid, env=None):
        return data.start_configuration_session(ApplicationIdentifier=application, EnvironmentIdentifier=env or environment_id, ConfigurationProfileIdentifier=pid, RequiredMinimumPollIntervalInSeconds=15)["InitialConfigurationToken"]

    def poll(token):
        result = data.get_latest_configuration(ConfigurationToken=token)
        content = result["Configuration"].read()
        return content, result["NextPollConfigurationToken"], result

    try:
        process.start(command, endpoint, environment=environment)
        account = sts.get_caller_identity()["Account"]
        created_application = app.create_application(Name=name, Description="", Tags={"owner": name})
        application = created_application["Id"]
        require(created_application.get("Description") == "" and "Description" not in app.get_application(ApplicationId=application), "empty Description mutation/read presence differs")
        environment_id = app.create_environment(ApplicationId=application, Name="production")["Id"]
        environments.append(environment_id)
        for strategy_name, duration, bake, growth in (("instant", 0, 0, 100), ("gradual", 2, 1, 50)):
            created = app.create_deployment_strategy(Name=name + strategy_name, DeploymentDurationInMinutes=duration, FinalBakeTimeInMinutes=bake, GrowthFactor=growth, GrowthType="LINEAR", ReplicateTo="NONE")["Id"]
            cleanup.append(("strategy:" + created, lambda sid=created: app.delete_deployment_strategy(DeploymentStrategyId=sid)))
            if strategy_name == "instant":
                immediate = created
            else:
                gradual = created
        replicated_name = name + "-replicated"
        replicated = app.create_deployment_strategy(Name=replicated_name, Description="replicated strategy", DeploymentDurationInMinutes=2, FinalBakeTimeInMinutes=0, GrowthFactor=25, GrowthType="LINEAR", ReplicateTo="SSM_DOCUMENT")["Id"]
        def remove_replicated_strategy():
            app.delete_deployment_strategy(DeploymentStrategyId=replicated)
            expect_error(lambda: parameters.get_document(Name=replicated_name), "InvalidDocument")
        cleanup.append(("replicated-strategy:" + replicated, remove_replicated_strategy))
        document = parameters.get_document(Name=replicated_name)
        require(document["DocumentType"] == "DeploymentStrategy" and json.loads(document["Content"])["growthFactor"] == 25, "strategy did not create a real SSM document")
        app.update_deployment_strategy(DeploymentStrategyId=replicated, GrowthFactor=50)
        latest = parameters.get_document(Name=replicated_name, DocumentVersion="$LATEST")
        default = parameters.get_document(Name=replicated_name, DocumentVersion="$DEFAULT")
        require(json.loads(latest["Content"])["growthFactor"] == 50 and json.loads(default["Content"])["growthFactor"] == 25, "strategy replication lost SSM version/default semantics")
        report["observations"]["ssm_strategy_replication"] = {"latest": latest["DocumentVersion"], "default": default["DocumentVersion"]}
        pid = profile("-settings", LocationUri="hosted", Validators=[{"Type": "JSON_SCHEMA", "Content": json.dumps({"type": "object", "properties": {"color": {"type": "string"}}, "required": ["color"], "additionalProperties": False})}])
        blue = hosted(pid, {"color": "blue"}, "blue")
        report["observations"]["no_deployment"] = expect_error(lambda: begin(pid), "ResourceNotFoundException")
        deploy(pid, blue)
        initial = begin(pid)
        content, token, response = poll(initial)
        require(json.loads(content) == {"color": "blue"} and response["VersionLabel"] == "blue", "initial deployed bytes")
        report["observations"]["token_replay"] = expect_error(lambda: poll(initial), "BadRequestException")
        report["observations"]["early_poll"] = expect_error(lambda: poll(token), "BadRequestException")
        advance(15)
        process.stop()
        process.start(command, endpoint, environment=environment)
        content, token, _ = poll(token)
        require(content == b"", "no-change after token/controller restart")
        report["observations"]["restart_no_change"] = True
        green = hosted(pid, {"color": "green"}, "green")
        rollout = deploy(pid, green, gradual)
        advance(120)
        baking = app.get_deployment(ApplicationId=application, EnvironmentId=environment_id, DeploymentNumber=rollout["DeploymentNumber"])
        require(baking["State"] == "BAKING", "rollout did not enter final bake")
        content, token, _ = poll(token)
        require(json.loads(content) == {"color": "green"}, "rollout bytes not delivered")
        stopped = app.stop_deployment(ApplicationId=application, EnvironmentId=environment_id, DeploymentNumber=rollout["DeploymentNumber"])
        advance(15)
        content, token, _ = poll(token)
        require(json.loads(content) == {"color": "blue"}, "stop did not restore prior bytes")
        report["observations"]["rollout_stop"] = {"bake": baking["State"], "stop": stopped["State"]}
        cli_file = state / "cli-configuration.json"
        cli_token = begin(pid)
        cli = subprocess.run(["aws", "--endpoint-url", endpoint, "appconfigdata", "get-latest-configuration", "--configuration-token", cli_token, str(cli_file)], env=environment, capture_output=True, text=True, check=True)
        require(json.loads(cli_file.read_bytes()) == {"color": "blue"}, "unmodified CLI configuration bytes")
        report["observations"]["cli"] = json.loads(cli.stdout)
        bucket = name + "-effects"
        objects.create_bucket(Bucket=bucket)
        cleanup.append(("bucket:" + bucket, lambda: objects.delete_bucket(Bucket=bucket)))
        _, execution_role = role("-lambda", "lambda.amazonaws.com", ["s3:PutObject", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"])
        handler = '''import base64,json,os,boto3\ndef handler(event,context):\n s3=boto3.client("s3")\n if "Type" in event:\n  s3.put_object(Bucket=os.environ["BUCKET"],Key="extension",Body=json.dumps(event).encode())\n  content=json.loads(base64.b64decode(event.get("Content","e30=")))\n  if content.get("oversized"): return {"Content":base64.b64encode(b"x"*((2<<20)+1)).decode()}\n  content["extension"]=True\n  return {"Content":base64.b64encode(json.dumps(content).encode()).decode()}\n content=json.loads(base64.b64decode(event["content"]))\n s3.put_object(Bucket=os.environ["BUCKET"],Key="validation",Body=json.dumps(content).encode())\n if content.get("fail"): raise ValueError("rejected by actual Lambda validator")\n return {}\n'''
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("handler.py", handler)
        function = functions.create_function(FunctionName=name, Runtime="python3.13", Role=execution_role, Handler="handler.handler", Timeout=15, Code={"ZipFile": archive.getvalue()}, Environment={"Variables": {"BUCKET": bucket}})["FunctionArn"]
        cleanup.append(("function:" + function, lambda: functions.delete_function(FunctionName=function)))
        deadline = time.monotonic() + 90
        while True:
            configuration = functions.get_function_configuration(FunctionName=function)
            report["observations"]["lambda_state"] = {key: configuration.get(key) for key in ("State", "StateReason", "StateReasonCode")}
            if configuration.get("State") == "Active":
                break
            require(configuration.get("State") != "Failed", "real Lambda runtime failed: " + json.dumps(report["observations"]["lambda_state"]))
            require(time.monotonic() < deadline, "real Lambda runtime readiness: " + json.dumps(report["observations"]["lambda_state"]))
            advance(1)
            time.sleep(.1)
        validator_profile = profile("-validator", LocationUri="hosted", Validators=[{"Type": "LAMBDA", "Content": function}])
        functions.add_permission(FunctionName=function, StatementId="appconfig", Action="lambda:InvokeFunction", Principal="appconfig.amazonaws.com", SourceAccount=account)
        accepted = hosted(validator_profile, {"accepted": True}, "accepted")
        deploy(validator_profile, accepted)
        require(json.loads(objects.get_object(Bucket=bucket, Key="validation")["Body"].read()) == {"accepted": True}, "validator did not execute actual customer code")
        functions.remove_permission(FunctionName=function, StatementId="appconfig")
        report["observations"]["validator_authority_denial"] = expect_error(lambda: app.validate_configuration(ApplicationId=application, ConfigurationProfileId=validator_profile, ConfigurationVersion=str(accepted)), "BadRequestException", "AccessDenied", "AccessDeniedException")
        functions.add_permission(FunctionName=function, StatementId="appconfig", Action="lambda:InvokeFunction", Principal="appconfig.amazonaws.com", SourceAccount=account)
        app.validate_configuration(ApplicationId=application, ConfigurationProfileId=validator_profile, ConfigurationVersion=str(accepted))
        rejected = hosted(validator_profile, {"fail": True}, "rejected")
        report["observations"]["validator_failure"] = expect_error(lambda: deploy(validator_profile, rejected), "BadRequestException")
        content, _, _ = poll(begin(validator_profile))
        require(json.loads(content) == {"accepted": True}, "failed validation changed deployed bytes")
        extension_role_name, extension_role = role("-extension", "appconfig.amazonaws.com", ["lambda:InvokeFunction"])
        extension = app.create_extension(Name=name + "-extension", Actions={"PRE_CREATE_HOSTED_CONFIGURATION_VERSION": [{"Name": "mutate", "Uri": function, "RoleArn": extension_role}]})["Id"]
        cleanup.append(("extension:" + extension, lambda: app.delete_extension(ExtensionIdentifier=extension)))
        extension_profile = profile("-extension", LocationUri="hosted")
        association = app.create_extension_association(ExtensionIdentifier=extension, ResourceIdentifier=f"arn:aws:appconfig:us-east-1:{account}:application/{application}/configurationprofile/{extension_profile}")["Id"]
        cleanup.append(("association:" + association, lambda: app.delete_extension_association(ExtensionAssociationId=association)))
        mutated_version = hosted(extension_profile, {"value": "source"}, "extension")
        mutated = app.get_hosted_configuration_version(ApplicationId=application, ConfigurationProfileId=extension_profile, VersionNumber=mutated_version)["Content"].read()
        require(json.loads(mutated) == {"value": "source", "extension": True}, "Lambda extension output did not change owned bytes")
        require(json.loads(objects.get_object(Bucket=bucket, Key="extension")["Body"].read())["Type"] == "PreCreateHostedConfigurationVersion", "extension runtime effect missing")
        report["observations"]["transformed_payload_quota"] = expect_error(lambda: hosted(extension_profile, {"oversized": True}, "oversized"), "PayloadTooLargeException")
        after_large = hosted(extension_profile, {"value": "after-rejection"}, "after-large")
        require(after_large == mutated_version + 1, "rejected Lambda transformation consumed a hosted version")
        report["observations"]["real_lambda_validator_extension"] = True
        retrieval_name, retrieval_role = role("-retrieval", "appconfig.amazonaws.com", ["ssm:GetParameter", "ssm:GetDocument", "s3:GetObject", "s3:GetObjectVersion", "secretsmanager:GetSecretValue", "kms:Decrypt"])
        parameter_name = "/" + name
        parameters.put_parameter(Name=parameter_name, Type="String", Value='{"external":1}')
        cleanup.append(("parameter:" + parameter_name, lambda: parameters.delete_parameter(Name=parameter_name)))
        external = profile("-parameter", LocationUri="ssm-parameter://" + parameter_name, RetrievalRoleArn=retrieval_role)
        deploy(external, 1)
        parameters.put_parameter(Name=parameter_name, Type="String", Value='{"external":2}', Overwrite=True)
        content, _, _ = poll(begin(external))
        require(json.loads(content) == {"external": 1}, "mutable source replaced admitted version")
        iam.put_role_policy(RoleName=retrieval_name, PolicyName="owned", PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ssm:GetParameter","Resource":"*"}]}')
        report["observations"]["source_authority_denial"] = expect_error(lambda: deploy(external, 2), "BadRequestException", "AccessDenied", "AccessDeniedException")
        iam.put_role_policy(RoleName=retrieval_name, PolicyName="owned", PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetDocument","s3:GetObject","s3:GetObjectVersion","secretsmanager:GetSecretValue","kms:Decrypt"],"Resource":"*"}]}')
        deploy(external, 2)
        content, _, _ = poll(begin(external))
        require(json.loads(content) == {"external": 2}, "current restored source role authority")
        report["observations"]["current_source_version_authority"] = True
        objects.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        object_version = objects.put_object(Bucket=bucket, Key="external.json", ContentType="application/json", Body=b'{"s3":"original"}')["VersionId"]
        objects.put_object(Bucket=bucket, Key="external.json", ContentType="application/json", Body=b'{"s3":"new"}')
        object_profile = profile("-s3", LocationUri=f"s3://{bucket}/external.json", RetrievalRoleArn=retrieval_role)
        deploy(object_profile, object_version)
        content, _, _ = poll(begin(object_profile))
        require(json.loads(content) == {"s3": "original"}, "exact S3 version source")
        secret_name = name + "-secret"
        secret = secrets.create_secret(Name=secret_name, SecretString='{"secret":"original"}')
        cleanup.append(("secret:" + secret["ARN"], lambda: secrets.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True)))
        secrets.put_secret_value(SecretId=secret["ARN"], SecretString='{"secret":"new"}')
        secret_profile = profile("-secret", LocationUri="secretsmanager://" + secret["ARN"], RetrievalRoleArn=retrieval_role)
        deploy(secret_profile, secret["VersionId"])
        content, _, _ = poll(begin(secret_profile))
        require(json.loads(content) == {"secret": "original"}, "exact Secrets Manager version source")
        schema_name, document_name = name + "-schema", name + "-document"
        parameters.create_document(Name=schema_name, DocumentType="ApplicationConfigurationSchema", DocumentFormat="JSON", Content='{"type":"object","required":["document"],"properties":{"document":{"type":"string"}},"additionalProperties":false}')
        cleanup.append(("document-schema:" + schema_name, lambda: parameters.delete_document(Name=schema_name, Force=True)))
        parameters.create_document(Name=document_name, DocumentType="ApplicationConfiguration", DocumentFormat="JSON", Content='{"document":"original"}', Requires=[{"Name": schema_name, "Version": "1"}])
        cleanup.append(("document:" + document_name, lambda: parameters.delete_document(Name=document_name)))
        parameters.update_document(Name=document_name, DocumentVersion="$LATEST", DocumentFormat="JSON", Content='{"document":"new"}')
        document_profile = profile("-document", LocationUri="ssm-document://" + document_name, RetrievalRoleArn=retrieval_role)
        deploy(document_profile, "1")
        content, _, _ = poll(begin(document_profile))
        require(json.loads(content) == {"document": "original"}, "exact schema-validated SSM document version")
        report["observations"]["s3_secrets_document_versions"] = True
        key = keys.create_key(Description=name)["KeyMetadata"]
        cleanup.append(("key:" + key["KeyId"], lambda: keys.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)))
        encrypted_profile = profile("-encrypted", LocationUri="hosted", KmsKeyIdentifier=key["Arn"])
        encrypted_version = hosted(encrypted_profile, {"encrypted": True}, "encrypted")
        keys.disable_key(KeyId=key["KeyId"])
        report["observations"]["disabled_key"] = expect_error(lambda: app.get_hosted_configuration_version(ApplicationId=application, ConfigurationProfileId=encrypted_profile, VersionNumber=encrypted_version), "BadRequestException", "DisabledException", "KMSInvalidStateException")
        keys.enable_key(KeyId=key["KeyId"])
        deploy(encrypted_profile, encrypted_version)
        content, _, _ = poll(begin(encrypted_profile))
        require(json.loads(content) == {"encrypted": True}, "real KMS hosted content")
        _, alarm_role = role("-alarm", "appconfig.amazonaws.com", ["cloudwatch:DescribeAlarms"])
        alarm_name = name + "-alarm"
        alarms.put_metric_alarm(AlarmName=alarm_name, Namespace="AppConfigSmoke", MetricName="Failure", ComparisonOperator="GreaterThanThreshold", EvaluationPeriods=1, Period=60, Statistic="Sum", Threshold=0)
        cleanup.append(("alarm:" + alarm_name, lambda: alarms.delete_alarms(AlarmNames=[alarm_name])))
        alarm_environment = app.create_environment(ApplicationId=application, Name="alarm", Monitors=[{"AlarmArn": f"arn:aws:cloudwatch:us-east-1:{account}:alarm:{alarm_name}", "AlarmRoleArn": alarm_role}])["Id"]
        environments.append(alarm_environment)
        alarms.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="owned baseline")
        deploy(pid, blue, env=alarm_environment)
        advance(1)
        alarm_deployment = deploy(pid, green, gradual, alarm_environment)
        alarms.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="actual owner state")
        advance(60)
        observed = app.get_deployment(ApplicationId=application, EnvironmentId=alarm_environment, DeploymentNumber=alarm_deployment["DeploymentNumber"])
        require(observed["State"] == "ROLLED_BACK", "current CloudWatch alarm did not roll back")
        report["observations"]["cloudwatch_alarm_rollback"] = observed["State"]
        report["observations"]["feature_flags"] = run_feature_flags(endpoint)
        save()
    finally:
        if process.process is not None and process.process.poll() is None:
            for description, callback in reversed(cleanup):
                try:
                    if description.startswith("bucket:"):
                        versions = objects.list_object_versions(Bucket=description[7:])
                        for item in versions.get("Versions", []) + versions.get("DeleteMarkers", []):
                            objects.delete_object(Bucket=description[7:], Key=item["Key"], VersionId=item["VersionId"])
                    callback()
                    report["cleanup"].append({"resource": description, "deleted": True})
                except Exception as exc:
                    report["cleanup"].append({"resource": description, "error": str(exc)})
            if application:
                for env in reversed(environments):
                    try:
                        app.delete_environment(ApplicationId=application, EnvironmentId=env, DeletionProtectionCheck="BYPASS")
                        report["cleanup"].append({"environment": env, "deleted": True})
                    except Exception as exc:
                        report["cleanup"].append({"environment": env, "error": str(exc)})
                for pid in reversed(profiles):
                    try:
                        for version in app.list_hosted_configuration_versions(ApplicationId=application, ConfigurationProfileId=pid).get("Items", []):
                            app.delete_hosted_configuration_version(ApplicationId=application, ConfigurationProfileId=pid, VersionNumber=version["VersionNumber"])
                        app.delete_configuration_profile(ApplicationId=application, ConfigurationProfileId=pid, DeletionProtectionCheck="BYPASS")
                        report["cleanup"].append({"profile": pid, "deleted": True})
                    except Exception as exc:
                        report["cleanup"].append({"profile": pid, "error": str(exc)})
                try:
                    app.delete_application(ApplicationId=application)
                    report["cleanup"].append({"application": application, "deleted": True})
                except Exception as exc:
                    report["cleanup"].append({"application": application, "error": str(exc)})
        try:
            process.stop(timeout=60)
        finally:
            save()
    require(all("error" not in row for row in report["cleanup"]), "exact-owned cleanup failed; inspect report")
    print(json.dumps({"report": str(state / "report.json"), "observations": list(report["observations"]), "controllers": process.runs}, indent=2))


if __name__ == "__main__":
    main()
