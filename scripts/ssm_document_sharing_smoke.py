#!/usr/bin/env python3
"""Run real local stackd processes and signed SDK SSM/AppConfig sharing flows.

Starts an isolated SQLite server, reopens it, consumes actual shared configuration
bytes through AppConfig, and cleans only resources created by this script. No AWS
endpoint is used. Example: python3 -B -P scripts/ssm_document_sharing_smoke.py
--binary /tmp/stackd --state-directory /tmp/ssm-sharing-smoke --output /tmp/ssm-sharing.json
"""
import argparse
import json
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


OWNER = "111122223333"
CONSUMER = "444455556666"
REGION = "us-east-1"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Smoke:
    def __init__(self, args):
        self.args = args
        self.state = args.state_directory.resolve()
        self.state.mkdir(parents=True, exist_ok=False)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.prefix = "stackd-sharing-" + secrets.token_hex(5)
        self.process = None
        self.log = None
        self.cleanup_actions = []
        self.evidence = {"source": "local executable + signed SDK + retained SQLite + AppConfig data plane", "cases": []}

    def client(self, service, account=OWNER, key=None, secret="test", region=REGION):
        return boto3.client(service, region_name=region, endpoint_url=self.endpoint,
                            aws_access_key_id=key or account, aws_secret_access_key=secret,
                            config=Config(retries={"max_attempts": 0}, connect_timeout=3, read_timeout=30))

    def own(self, fn, **kwargs):
        self.cleanup_actions.append((fn, kwargs))

    def note(self, case, **facts):
        row = {"case": case, **facts}
        self.evidence["cases"].append(row)
        print(json.dumps(row), flush=True)

    def deny(self, case, fn, **kwargs):
        try:
            fn(**kwargs)
        except ClientError as error:
            self.note(case, error=error.response["Error"]["Code"])
            return
        raise RuntimeError(case + " unexpectedly succeeded")

    def start(self):
        self.log = (self.state / "server.log").open("ab")
        self.process = subprocess.Popen([str(self.args.binary.resolve()), "-listen", f"127.0.0.1:{self.port}",
            "-database", str(self.state / "state.sqlite"), "-account-id", OWNER], stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("server exited: " + (self.state / "server.log").read_text()[-4000:])
            try:
                if self.client("sts").get_caller_identity()["Account"] == OWNER:
                    return
            except Exception:
                pass
            time.sleep(.1)
        raise RuntimeError("server startup deadline")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=60)
        self.process = None
        if self.log:
            self.log.close()
            self.log = None

    def run(self):
        self.start()
        owner = self.client("ssm")
        reader = self.client("ssm", CONSUMER)
        schema, name, command = (self.prefix + suffix for suffix in ("-schema", "-config", "-command"))
        arn = f"arn:aws:ssm:{REGION}:{OWNER}:document/{name}"
        content = json.dumps({"marker": self.prefix})
        owner.create_document(Name=schema, DocumentType="ApplicationConfigurationSchema",
            Content=json.dumps({"type": "object", "properties": {"marker": {"type": "string"}}, "additionalProperties": False}))
        self.own(owner.delete_document, Name=schema, Force=True)
        owner.create_document(Name=name, DocumentType="ApplicationConfiguration", Content=content,
            Requires=[{"Name": schema, "Version": "1"}])
        self.own(owner.delete_document, Name=name)
        self.own(owner.modify_document_permission, Name=name, PermissionType="Share", AccountIdsToRemove=[CONSUMER])
        self.deny("unshared-content-rejected", reader.get_document, Name=arn)
        owner.modify_document_permission(Name=name, PermissionType="Share", AccountIdsToAdd=[CONSUMER])
        require(reader.get_document(Name=arn)["Content"] == content, "shared source differs")
        self.note("shared-exact-content", bytes=len(content))
        description = reader.describe_document(Name=arn)["Document"]
        require(description["Owner"] == OWNER, "shared description owner differs")
        listing = reader.list_documents(Filters=[{"Key": "Owner", "Values": ["Private"]}])
        require(any(row["Name"] == arn for row in listing["DocumentIdentifiers"]), "shared discovery missing ARN")
        self.deny("wrong-region-rejected", self.client("ssm", CONSUMER, region="us-west-2").get_document, Name=arn)
        self.deny("unshared-version-rejected", reader.get_document, Name=arn, DocumentVersion="2")
        self.deny("share-is-not-mutation-authority", reader.delete_document, Name=name)
        self.deny("shared-delete-rejected", owner.delete_document, Name=name)

        iam = self.client("iam", CONSUMER)
        user = self.prefix + "-reader"
        iam.create_user(UserName=user)
        self.own(iam.delete_user, UserName=user)
        key = iam.create_access_key(UserName=user)["AccessKey"]
        self.own(iam.delete_access_key, UserName=user, AccessKeyId=key["AccessKeyId"])
        denied = self.client("ssm", CONSUMER, key=key["AccessKeyId"], secret=key["SecretAccessKey"])
        self.deny("share-without-identity-policy-rejected", denied.get_document, Name=arn)
        allow = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ssm:GetDocument", "Resource": arn}]})
        iam.put_user_policy(UserName=user, PolicyName="read", PolicyDocument=allow)
        self.own(iam.delete_user_policy, UserName=user, PolicyName="read")
        require(denied.get_document(Name=arn)["Content"] == content, "identity plus share read failed")
        iam.put_user_policy(UserName=user, PolicyName="read", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "ssm:*", "Resource": "*"}]}))
        self.deny("current-identity-denial-rejected", denied.get_document, Name=arn)

        role_name = self.prefix + "-retrieval"
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "appconfig.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]
        self.own(iam.delete_role, RoleName=role_name)
        iam.put_role_policy(RoleName=role_name, PolicyName="source", PolicyDocument=allow)
        self.own(iam.delete_role_policy, RoleName=role_name, PolicyName="source")
        app = self.client("appconfig", CONSUMER)
        application = app.create_application(Name=self.prefix)
        self.own(app.delete_application, ApplicationId=application["Id"])
        environment = app.create_environment(ApplicationId=application["Id"], Name="consumer")
        self.own(app.delete_environment, ApplicationId=application["Id"], EnvironmentId=environment["Id"], DeletionProtectionCheck="BYPASS")
        profile = app.create_configuration_profile(ApplicationId=application["Id"], Name="shared", LocationUri="ssm-document://" + arn, RetrievalRoleArn=role["Arn"])
        self.own(app.delete_configuration_profile, ApplicationId=application["Id"], ConfigurationProfileId=profile["Id"], DeletionProtectionCheck="BYPASS")
        strategy = app.create_deployment_strategy(Name=self.prefix, DeploymentDurationInMinutes=0, GrowthFactor=100, FinalBakeTimeInMinutes=0, ReplicateTo="NONE")
        self.own(app.delete_deployment_strategy, DeploymentStrategyId=strategy["Id"])
        deployment_args = dict(ApplicationId=application["Id"], EnvironmentId=environment["Id"], ConfigurationProfileId=profile["Id"], DeploymentStrategyId=strategy["Id"], ConfigurationVersion="1")
        deployed = app.start_deployment(**deployment_args)
        require(deployed["State"] == "COMPLETE", "zero-duration deployment incomplete")
        data = self.client("appconfigdata", CONSUMER)
        def consume():
            session = data.start_configuration_session(ApplicationIdentifier=application["Id"], EnvironmentIdentifier=environment["Id"], ConfigurationProfileIdentifier=profile["Id"])
            out = data.get_latest_configuration(ConfigurationToken=session["InitialConfigurationToken"])
            require(out["Configuration"].read().decode() == content, "AppConfig did not deliver shared owner bytes")
        consume()
        self.note("actual-appconfig-consumer", content=content, source_account=OWNER, consuming_account=CONSUMER)
        self.stop()
        self.start()
        require(reader.get_document(Name=arn)["Content"] == content, "restart lost share or content")
        consume()
        self.note("sqlite-process-restart", source_and_deployed_bytes_retained=True)
        iam.put_role_policy(RoleName=role_name, PolicyName="source", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "ssm:GetDocument", "Resource": "*"}]}))
        self.deny("appconfig-current-role-denial", app.start_deployment, **deployment_args)
        iam.put_role_policy(RoleName=role_name, PolicyName="source", PolicyDocument=allow)
        owner.modify_document_permission(Name=name, PermissionType="Share", AccountIdsToAdd=[CONSUMER], AccountIdsToRemove=[CONSUMER], SharedDocumentVersion="$ALL")
        self.deny("removal-wins-over-addition", reader.get_document, Name=arn)
        self.deny("appconfig-revoked-source-rejected", app.start_deployment, **deployment_args)

        # Existing Run Command consumes the same owner content loader. Actual
        # guest execution is covered by the managed-agent harness; this case
        # verifies admission authority without creating a pretend managed node.
        command_arn = f"arn:aws:ssm:{REGION}:{OWNER}:document/{command}"
        owner.create_document(Name=command, DocumentType="Command", Content=json.dumps({"schemaVersion": "2.2", "mainSteps": [{"action": "aws:runShellScript", "name": "marker", "inputs": {"runCommand": ["printf shared-document"]}}]}))
        self.own(owner.delete_document, Name=command)
        self.own(owner.modify_document_permission, Name=command, PermissionType="Share", AccountIdsToRemove=[CONSUMER])
        owner.modify_document_permission(Name=command, PermissionType="Share", AccountIdsToAdd=[CONSUMER], SharedDocumentVersion="$ALL")
        sent = reader.send_command(DocumentName=command_arn, DocumentVersion="1", Targets=[{"Key": "tag:" + self.prefix, "Values": ["not-present"]}])
        require(sent["Command"]["TargetCount"] == 0, "isolated smoke selected unexpected node")
        self.note("shared-run-command-admission", target_count=0)
        owner.modify_document_permission(Name=command, PermissionType="Share", AccountIdsToRemove=[CONSUMER])
        self.deny("revoked-run-command-rejected", reader.send_command, DocumentName=command_arn, Targets=[{"Key": "tag:" + self.prefix, "Values": ["not-present"]}])

    def cleanup(self):
        errors = []
        if self.process is not None and self.process.poll() is None:
            for fn, kwargs in reversed(self.cleanup_actions):
                try:
                    fn(**kwargs)
                except Exception as error:
                    errors.append({"operation": fn.__name__, "error": str(error)})
        self.stop()
        self.evidence["cleanup"] = {"completed": not errors, "errors": errors}
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(self.evidence, indent=2) + "\n")
        if errors:
            raise RuntimeError("owned cleanup failed: " + json.dumps(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    smoke = Smoke(parser.parse_args())
    try:
        smoke.run()
    finally:
        smoke.cleanup()


if __name__ == "__main__":
    main()
