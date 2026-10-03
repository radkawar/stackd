#!/usr/bin/env python3
"""Exercise local signed SSM -> CodeBuild/ECS native execution, never AWS.

Requires a running stackd with Docker and a container-reachable compute endpoint.
Only uniquely named owned resources are changed; generated secret values are not
printed. Use python3 -B -P scripts/ssm_consumers_smoke.py --endpoint http://... .
Use --secret-references to exercise Secrets Manager pass-through references only.
"""
import argparse
import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


TERMINAL = {"SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def eventually(check, description, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.2)
    raise RuntimeError("observation deadline: " + description)


def policy(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


class Smoke:
    def __init__(self, args):
        self.args = args
        self.prefix = "stackd-ssm-consumers-" + secrets.token_hex(5)
        self.session = boto3.Session(aws_access_key_id=args.access_key,
                                     aws_secret_access_key=args.secret_key,
                                     region_name=args.region)
        self.clients = {}
        self.cleanup_actions = []
        self.builds, self.tasks = [], []
        self.private_values = []
        self.evidence = []

    def client(self, service, region=None):
        key = service, region or self.args.region
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=key[1], endpoint_url=self.args.endpoint,
                config=Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=30))
        return self.clients[key]

    def own(self, cleanup, **arguments):
        self.cleanup_actions.append((cleanup, arguments))

    def safe(self, document):
        text = json.dumps(document, default=str)
        require(not any(value in text for value in self.private_values), "secret value escaped into a public consumer response or log")

    def note(self, case, **facts):
        record = {"case": case, **facts}
        self.safe(record)
        self.evidence.append(record)
        print(json.dumps(record), flush=True)

    def role(self, suffix, service):
        iam = self.client("iam")
        name = self.prefix + "-" + suffix
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=policy([
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]))["Role"]
        self.own(iam.delete_role, RoleName=name)
        statements = [{"Effect": "Allow", "Action": ["ssm:GetParameters", "kms:Decrypt", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}]
        if self.args.secret_references and suffix in ("build", "execution"):
            statements.append({"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": self.secret_arn})
        iam.put_role_policy(RoleName=name, PolicyName="consumer", PolicyDocument=policy(statements))
        self.own(iam.delete_role_policy, RoleName=name, PolicyName="consumer")
        return role

    def deny(self, role, action):
        self.client("iam").put_role_policy(RoleName=role["RoleName"], PolicyName="consumer-denial",
            PolicyDocument=policy([{"Effect": "Deny", "Action": action, "Resource": "*"}]))

    def undeny(self, role):
        self.client("iam").delete_role_policy(RoleName=role["RoleName"], PolicyName="consumer-denial")

    def parameter(self, suffix, value, key=None, region=None):
        ssm = self.client("ssm", region)
        name = "/" + self.prefix + "/" + suffix
        arguments = {"Name": name, "Value": value, "Type": "SecureString" if key else "String"}
        if key:
            arguments["KeyId"] = key
        ssm.put_parameter(**arguments)
        self.own(ssm.delete_parameter, Name=name)
        self.private_values.append(value)
        return name

    def setup(self):
        self.account = self.client("sts").get_caller_identity()["Account"]
        self.key = self.client("kms").create_key(Description=self.prefix)["KeyMetadata"]
        self.own(self.client("kms").schedule_key_deletion, KeyId=self.key["KeyId"], PendingWindowInDays=7)
        self.secret = secrets.token_hex(24)
        self.refs, self.expected = {}, {}
        if self.args.secret_references:
            self.setup_secret_references()
        else:
            self.secure = self.parameter("secure", self.secret, self.key["Arn"])
            for index in range(12):
                name = "P" + str(index)
                content = secrets.token_hex(18)
                self.refs[name] = self.parameter("batch-" + str(index), content)
                self.expected[name] = hashlib.sha256(content.encode()).hexdigest()
            self.other_region = "us-west-2" if self.args.region != "us-west-2" else "us-east-1"
            remote_value = secrets.token_hex(18)
            remote_name = self.parameter("secure", remote_value, region=self.other_region)
            self.remote = "arn:aws:ssm:" + self.other_region + ":" + self.account + ":parameter" + remote_name
            self.remote_hash = hashlib.sha256(remote_value.encode()).hexdigest()
        self.group = "/stackd/" + self.prefix
        self.client("logs").create_log_group(logGroupName=self.group)
        self.own(self.client("logs").delete_log_group, logGroupName=self.group)
        self.build_role = self.role("build", "codebuild.amazonaws.com")
        self.execution_role = self.role("execution", "ecs-tasks.amazonaws.com")
        self.task_role = self.role("task", "ecs-tasks.amazonaws.com")
        self.deny(self.task_role, ["ssm:*", "secretsmanager:*"] if self.args.secret_references else "ssm:*")
        self.own(self.client("iam").delete_role_policy, RoleName=self.task_role["RoleName"], PolicyName="consumer-denial")

    def setup_secret_references(self):
        sm = self.client("secretsmanager")
        previous = secrets.token_hex(24)
        self.private_values.extend([previous, self.secret])
        secret = sm.create_secret(Name=self.prefix, SecretString=previous, KmsKeyId=self.key["Arn"])
        self.secret_arn = secret["ARN"]
        self.own(sm.delete_secret, SecretId=self.secret_arn, ForceDeleteWithoutRecovery=True)
        sm.put_secret_value(SecretId=self.secret_arn, SecretString=self.secret)
        self.secure = "/aws/reference/secretsmanager/" + self.prefix
        self.refs = {"CURRENT": self.secure + ":AWSCURRENT", "PREVIOUS": self.secure + ":AWSPREVIOUS"}
        self.expected = {"CURRENT": hashlib.sha256(self.secret.encode()).hexdigest(),
                         "PREVIOUS": hashlib.sha256(previous.encode()).hexdigest()}

    def hash_check(self, name, digest):
        return 'test "$(printf %s "$' + name + '" | sha256sum | cut -d " " -f 1)" = ' + digest

    def logs(self, build):
        location = build.get("logs", {})
        if not location.get("streamName"):
            return ""
        try:
            out = self.client("logs").get_log_events(logGroupName=location["groupName"], logStreamName=location["streamName"], startFromHead=True)
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return ""
            raise
        text = "\n".join(event["message"] for event in out["events"])
        self.safe(text)
        return text

    def run_build(self, expected="SUCCEEDED", **kwargs):
        cb = self.client("codebuild")
        overrides = [{"name": "PRECEDENCE", "value": "start-wins", "type": "PLAINTEXT"}]
        overrides.extend(kwargs.pop("environmentVariablesOverride", []))
        build = cb.start_build(projectName=self.prefix, environmentVariablesOverride=overrides, **kwargs)["build"]
        self.builds.append(build["id"])
        self.safe(build)
        def terminal():
            current = cb.batch_get_builds(ids=[build["id"]])["builds"][0]
            self.safe(current)
            return current if current["buildStatus"] in TERMINAL else None
        result = eventually(terminal, "build completion")
        require(result["buildStatus"] == expected, "unexpected build status: " + result["buildStatus"] + " " + json.dumps(result.get("phases"), default=str))
        return result

    def codebuild(self):
        cb = self.client("codebuild")
        commands = [self.hash_check("TOKEN", hashlib.sha256(self.secret.encode()).hexdigest()),
                    'test "$PRECEDENCE" = start-wins', 'test "$PROJECT_WINS" = project-wins']
        commands.extend(self.hash_check(name, digest) for name, digest in self.expected.items())
        printed = "PREVIOUS" if self.args.secret_references else "P0"
        commands.extend(['printf "%s\\n" "$TOKEN" "$' + printed + '"', "printf 'PARAMETER-CONSUMER-OK\\n'"])
        buildspec = json.dumps({"version": "0.2", "env": {"parameter-store": {
            **self.refs, "PRECEDENCE": "/" + self.prefix + "/missing-buildspec",
            "PROJECT_WINS": "/" + self.prefix + "/missing-shadowed"}},
            "phases": {"build": {"commands": commands}}})
        cb.create_project(name=self.prefix, serviceRole=self.build_role["Arn"],
            source={"type": "NO_SOURCE", "buildspec": buildspec}, artifacts={"type": "NO_ARTIFACTS"},
            environment={"type": "LINUX_CONTAINER", "image": self.args.image,
                "computeType": "BUILD_GENERAL1_SMALL", "imagePullCredentialsType": "SERVICE_ROLE",
                "environmentVariables": [{"name": "TOKEN", "type": "PARAMETER_STORE", "value": self.secure},
                    {"name": "PRECEDENCE", "type": "PARAMETER_STORE", "value": "/" + self.prefix + "/missing-project"},
                    {"name": "PROJECT_WINS", "type": "PLAINTEXT", "value": "project-wins"}]},
            logsConfig={"cloudWatchLogs": {"status": "ENABLED", "groupName": self.group, "streamName": "build"}})
        self.own(cb.delete_project, name=self.prefix)
        result = self.run_build()
        output = eventually(lambda: text if "PARAMETER-CONSUMER-OK" in (text := self.logs(result)) else None, "masked build logs")
        require("***" in output, "Parameter Store values were not masked in CodeBuild logs")
        self.safe(cb.batch_get_projects(names=[self.prefix]))
        if self.args.secret_references:
            self.note("codebuild-secret-reference-runtime", status=result["buildStatus"], project_parameter_store=True,
                      buildspec_parameter_store=True, stages=["AWSCURRENT", "AWSPREVIOUS"], masked=True,
                      build_id=result["id"])
            for action in ("secretsmanager:GetSecretValue", "kms:Decrypt"):
                error_code = "ValidationException"
                self.deny(self.build_role, action)
                try:
                    failed = self.run_build("FAILED")
                    require(error_code in json.dumps(failed["phases"], default=str), "secret authority denial did not fail preparation")
                    require(not any(phase["phaseType"] == "BUILD" for phase in failed["phases"]), "secret authority denial started build commands")
                finally:
                    self.undeny(self.build_role)
                self.note("codebuild-secret-reference-denial", action=action, error=error_code, status=failed["buildStatus"], build_id=failed["id"])
            restored = self.run_build()
            self.note("codebuild-secret-reference-authority-restored", status=restored["buildStatus"], build_id=restored["id"])
            return
        self.note("codebuild-runtime", status=result["buildStatus"], batched_parameters=12, precedence=True, masked=True)
        missing = self.run_build("FAILED", environmentVariablesOverride=[{"name": "TOKEN", "type": "PARAMETER_STORE", "value": "/" + self.prefix + "/missing"}])
        require("SSM parameter" in json.dumps(missing["phases"], default=str), "missing parameter did not fail preparation")
        missing_buildspec = self.run_build("FAILED", buildspecOverride=json.dumps({
            "version": "0.2", "env": {"parameter-store": {"MISSING": "/" + self.prefix + "/missing-buildspec"}},
            "phases": {"build": {"commands": ["exit 99"]}}}))
        require("SSM parameter" in json.dumps(missing_buildspec["phases"], default=str), "missing buildspec parameter did not fail preparation")
        for action in ("ssm:GetParameters", "kms:Decrypt"):
            self.deny(self.build_role, action)
            try:
                failed = self.run_build("FAILED")
                require("AccessDenied" in json.dumps(failed["phases"], default=str), "current authority denial did not fail preparation")
            finally:
                self.undeny(self.build_role)
            self.note("codebuild-authority-denial", action=action, status=failed["buildStatus"])
        self.note("codebuild-missing", project_status=missing["buildStatus"], buildspec_status=missing_buildspec["buildStatus"])

    def definition(self, secrets_spec, suffix="normal"):
        ecs = self.client("ecs")
        commands = [self.hash_check("TOKEN", hashlib.sha256(self.secret.encode()).hexdigest())]
        if not self.args.secret_references:
            commands.append(self.hash_check("REMOTE", self.remote_hash))
        commands.extend(self.hash_check(name, digest) for name, digest in self.expected.items())
        result = ecs.register_task_definition(family=self.prefix + "-" + suffix, networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"], cpu="256", memory="512",
            executionRoleArn=self.execution_role["Arn"], taskRoleArn=self.task_role["Arn"],
            containerDefinitions=[{"name": "consumer", "image": self.args.image, "essential": True,
                "entryPoint": ["/bin/sh", "-c"], "command": ["set -e; " + "; ".join(commands)],
                "environment": [{"name": "TOKEN", "value": "plaintext-loses"}], "secrets": secrets_spec}])["taskDefinition"]
        self.own(ecs.deregister_task_definition, taskDefinition=result["taskDefinitionArn"])
        self.safe(result)
        return result["taskDefinitionArn"]

    def run_task(self, definition, failed=False):
        ecs = self.client("ecs")
        out = ecs.run_task(cluster=self.cluster, taskDefinition=definition, launchType="FARGATE",
            networkConfiguration={"awsvpcConfiguration": {"subnets": [self.subnet], "securityGroups": [self.group_id]}})
        require(not out.get("failures") and len(out["tasks"]) == 1, "ECS task admission failed")
        task = out["tasks"][0]["taskArn"]
        self.tasks.append(task)
        def stopped():
            result = ecs.describe_tasks(cluster=self.cluster, tasks=[task])["tasks"][0]
            self.safe(result)
            return result if result["lastStatus"] == "STOPPED" else None
        result = eventually(stopped, "ECS parameter consumer completion")
        if failed:
            require(result.get("stopCode") == "TaskFailedToStart" and all("exitCode" not in c for c in result["containers"]), "failed parameter dependency started customer code")
        else:
            require(result.get("stopCode") == "EssentialContainerExited" and result["containers"][0].get("exitCode") == 0,
                    "ECS native parameter verification failed: " + json.dumps(result, default=str))
        return result

    def ecs(self):
        ec2, ecs = self.client("ec2"), self.client("ecs")
        vpc = ec2.create_vpc(CidrBlock="10.247.0.0/24")["Vpc"]["VpcId"]
        self.own(ec2.delete_vpc, VpcId=vpc)
        self.subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.247.0.0/24", AvailabilityZone=self.args.region + "a")["Subnet"]["SubnetId"]
        self.own(ec2.delete_subnet, SubnetId=self.subnet)
        self.group_id = ec2.create_security_group(VpcId=vpc, GroupName=self.prefix, Description=self.prefix)["GroupId"]
        self.own(ec2.delete_security_group, GroupId=self.group_id)
        self.cluster = ecs.create_cluster(clusterName=self.prefix)["cluster"]["clusterArn"]
        self.own(ecs.delete_cluster, cluster=self.cluster)
        refs = [{"name": name, "valueFrom": reference} for name, reference in self.refs.items()]
        refs.append({"name": "TOKEN", "valueFrom": self.secure})
        if not self.args.secret_references:
            refs.append({"name": "REMOTE", "valueFrom": self.remote})
        definition = self.definition(refs)
        result = self.run_task(definition)
        if self.args.secret_references:
            self.note("ecs-secret-reference-runtime", exit_code=0, execution_role=True, task_role_denied=True,
                      stages=["AWSCURRENT", "AWSPREVIOUS"], task_arn=result["taskArn"])
            for action in ("secretsmanager:GetSecretValue", "kms:Decrypt"):
                error_code = "ValidationException"
                self.deny(self.execution_role, action)
                try:
                    failed = self.run_task(definition, failed=True)
                    require(error_code in failed.get("stoppedReason", ""), "wrong ECS secret authority failure")
                finally:
                    self.undeny(self.execution_role)
                self.note("ecs-secret-reference-denial", action=action, error=error_code, stop_code=failed["stopCode"], task_arn=failed["taskArn"])
            restored = self.run_task(definition)
            self.note("ecs-secret-reference-authority-restored", exit_code=restored["containers"][0]["exitCode"], task_arn=restored["taskArn"])
            return
        self.note("ecs-runtime", exit_code=0, execution_role=True, task_role_denied=True, cross_region=True, batched_parameters=14)
        missing = self.run_task(self.definition([{"name": "TOKEN", "valueFrom": "/" + self.prefix + "/missing"}], "missing"), failed=True)
        require("SSM parameter" in missing.get("stoppedReason", ""), "wrong ECS missing-parameter failure")
        self.note("ecs-missing", stop_code=missing["stopCode"])
        for action in ("ssm:GetParameters", "kms:Decrypt"):
            self.deny(self.execution_role, action)
            try:
                failed = self.run_task(definition, failed=True)
                require("AccessDenied" in failed.get("stoppedReason", ""), "wrong ECS authority failure")
            finally:
                self.undeny(self.execution_role)
            self.note("ecs-authority-denial", action=action, stop_code=failed["stopCode"])
        nonssm = self.definition([{"name": "TOKEN", "valueFrom": "arn:aws:secretsmanager:" + self.args.region + ":" + self.account + ":secret:not-configured"}], "non-ssm")
        try:
            self.run_task(nonssm, failed=True)
        except ClientError as error:
            require(error.response["Error"]["Code"] == "NotImplementedException", "wrong non-SSM dependency error")
        else:
            raise RuntimeError("non-SSM dependency was admitted")
        self.note("ecs-non-ssm", error="NotImplementedException")

    def retained_state(self):
        if self.args.secret_references:
            for page in self.client("ssm").get_paginator("describe_parameters").paginate(
                    ParameterFilters=[{"Key": "Name", "Option": "Contains", "Values": [self.prefix]}]):
                require(not page.get("Parameters"), "secret reference was stored as SSM parameter metadata")
            self.note("secret-reference-metadata", ssm_parameters_absent=True)
        if not self.args.database:
            return
        with sqlite3.connect(Path(self.args.database).resolve().as_uri() + "?mode=ro", uri=True) as db:
            tables = [row[0] for row in db.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND "
                "(name GLOB 'codebuild_*' OR name GLOB 'ecs_*' OR "
                "name IN ('api_call_events', 'kernel_events', 'logs_events')" +
                (" OR name GLOB 'ssm_*'" if self.args.secret_references else "") + ")")]
            needles = [value.encode() for value in self.private_values]
            for table in tables:
                quoted = '"' + table.replace('"', '""') + '"'
                for row in db.execute("SELECT * FROM " + quoted):
                    for value in row:
                        data = value.encode() if isinstance(value, str) else value if isinstance(value, bytes) else b""
                        require(not any(needle in data for needle in needles), "secret value retained in " + table)
                        if self.args.secret_references and table.startswith("ssm_"):
                            require(self.secure.encode() not in data, "secret reference metadata retained in " + table)
        self.note("retained-state", consumer_tables=True, audit_tables=True, log_tables=True,
                  ssm_tables=self.args.secret_references, secrets_absent=True)

    def cleanup(self):
        errors = []
        for task in self.tasks:
            try:
                self.client("ecs").stop_task(cluster=self.cluster, task=task, reason="owned parameter smoke cleanup")
                eventually(lambda: self.client("ecs").describe_tasks(cluster=self.cluster, tasks=[task])["tasks"][0]["lastStatus"] == "STOPPED", "task cleanup", 40)
            except Exception as error:
                errors.append(type(error).__name__ + ": task cleanup")
        for build in self.builds:
            try:
                current = self.client("codebuild").batch_get_builds(ids=[build])["builds"][0]
                if current["buildStatus"] not in TERMINAL:
                    self.client("codebuild").stop_build(id=build)
                    eventually(lambda: self.client("codebuild").batch_get_builds(ids=[build])["builds"][0]["buildStatus"] in TERMINAL, "build cleanup", 40)
            except Exception as error:
                errors.append(type(error).__name__ + ": build cleanup")
        if self.builds:
            try:
                result = self.client("codebuild").batch_delete_builds(ids=self.builds)
                require(not result.get("buildsNotDeleted"), "native build cleanup pending")
            except Exception as error:
                errors.append(type(error).__name__ + ": build deletion")
        for cleanup, arguments in reversed(self.cleanup_actions):
            try:
                cleanup(**arguments)
            except Exception as error:
                errors.append(type(error).__name__ + ": " + cleanup.__name__)
        require(not errors, "owned cleanup failed: " + ", ".join(errors))
        if self.args.secret_references:
            if hasattr(self, "secret_arn"):
                try:
                    self.client("secretsmanager").describe_secret(SecretId=self.secret_arn)
                except ClientError as error:
                    require(error.response["Error"]["Code"] == "ResourceNotFoundException", "unexpected deleted-secret observation")
                else:
                    raise RuntimeError("owned synthetic secret remains after deletion")
            if hasattr(self, "key"):
                state = self.client("kms").describe_key(KeyId=self.key["KeyId"])["KeyMetadata"]["KeyState"]
                require(state == "PendingDeletion", "owned KMS key deletion was not scheduled")
            self.note("secret-reference-cleanup", secret_absent=True,
                      kms_deletion="scheduled-seven-days" if hasattr(self, "key") else "not-created")
        self.note("cleanup", completed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--access-key", default="test")
    parser.add_argument("--secret-key", default="test")
    parser.add_argument("--image", default="busybox:1.38.0")
    parser.add_argument("--consumer", choices=("both", "codebuild", "ecs"), default="both")
    parser.add_argument("--secret-references", action="store_true",
                        help="Run focused Secrets Manager references through ordinary SSM consumers, not the regular-parameter cases")
    parser.add_argument("--database", help="Optional SQLite path for read-only consumer/audit/log secret-absence checks")
    args = parser.parse_args()
    parsed = urlparse(args.endpoint)
    require(parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1"), "smoke endpoint must be an explicit loopback HTTP server, never AWS")
    smoke = Smoke(args)
    try:
        smoke.setup()
        if args.consumer in ("both", "codebuild"):
            smoke.codebuild()
        if args.consumer in ("both", "ecs"):
            smoke.ecs()
        smoke.retained_state()
    finally:
        smoke.cleanup()


if __name__ == "__main__":
    main()
