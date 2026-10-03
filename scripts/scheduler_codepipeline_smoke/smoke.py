#!/usr/bin/env python3
"""Local-only signed Go SDK Scheduler -> real CodePipeline/S3 executable proof."""
import argparse
import base64
from datetime import datetime, timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "aws"))
from stackd_process import StackdProcess


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Workflow:
    def __init__(self, args):
        self.args = args
        self.state = args.state_directory.resolve()
        self.state.mkdir(parents=True, exist_ok=False)
        self.process = StackdProcess(self.state)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.prefix = "sched-cp-" + uuid.uuid4().hex[:10]
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        self.environment["AWS_EC2_METADATA_DISABLED"] = "true"
        self.command = [str(args.binary.resolve()), "-listen", f"127.0.0.1:{self.port}",
                        "-public-endpoint", self.endpoint, "-database", str(self.state / "state.sqlite"),
                        "-clock-start", "2026-10-01T12:00:00Z"]
        self.cleanup = []
        self.report = {"surface": "local executable / signed AWS SDK Go v2", "prefix": self.prefix,
                       "endpoint": self.endpoint, "controllers": self.process.runs, "calls": [],
                       "observations": {}, "cleanup": [], "complete": False, "cleanup_verified": False}

    def save(self):
        (self.state / "report.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def sdk(self, operation, parameters=None, *, expected=None, region="us-east-1", account="test", cleanup=False):
        request = {"Operation": operation, "Parameters": parameters or {}}
        completed = subprocess.run([str(self.args.sdk.resolve()), "-endpoint", self.endpoint,
                                    "-region", region, "-account", account], input=json.dumps(request),
                                   text=True, capture_output=True, timeout=70, env=self.environment)
        row = {"operation": operation, "parameters": parameters or {}, "region": region, "account": account,
               "exit": completed.returncode, "stderr": completed.stderr}
        self.report["cleanup" if cleanup else "calls"].append(row)
        try:
            require(completed.returncode == 0, f"SDK helper failed: {completed.stderr}")
            result = json.loads(completed.stdout)
            row.update(result)
            code = result.get("Error", {}).get("Code", "Success")
            require(code in (expected or ["Success"]), f"{operation}: {json.dumps(result)}")
            return result if code != "Success" else result["Output"]
        finally:
            self.save()

    def control(self, path, payload=None):
        body = json.dumps(payload or {}).encode()
        request = urllib.request.Request(self.endpoint + path, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    def now(self):
        with urllib.request.urlopen(self.endpoint + "/_stackd/clock", timeout=10) as response:
            return datetime.fromisoformat(json.load(response)["time"].replace("Z", "+00:00"))

    def advance(self, seconds):
        self.control("/_stackd/clock", {"advance": f"{seconds}s"})
        return self.control("/_stackd/jobs/drain?limit=4096")

    def start(self):
        self.process.start(self.command, self.endpoint, environment=self.environment)

    def role(self, suffix, principal, actions):
        name = self.prefix + "-" + suffix
        output = self.sdk("iam.CreateRole", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                                                     "Action": "sts:AssumeRole"}]})})
        self.cleanup.append(("role:" + name, lambda: self.remove_role(name)))
        self.policy(name, actions)
        return name, output["Role"]["Arn"]

    def policy(self, name, actions, deny=False):
        statements = [{"Effect": "Allow", "Action": actions, "Resource": "*"}]
        if deny:
            statements.append({"Effect": "Deny", "Action": "codepipeline:StartPipelineExecution", "Resource": "*"})
        self.sdk("iam.PutRolePolicy", {"RoleName": name, "PolicyName": "owned", "PolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": statements})})

    def remove_role(self, name):
        self.sdk("iam.DeleteRolePolicy", {"RoleName": name, "PolicyName": "owned"}, cleanup=True)
        self.sdk("iam.DeleteRole", {"RoleName": name}, cleanup=True)
        self.sdk("iam.GetRole", {"RoleName": name}, expected=["NoSuchEntity"], cleanup=True)

    def bucket(self, suffix):
        name = self.prefix + "-" + suffix
        self.sdk("s3.CreateBucket", {"Bucket": name})
        self.cleanup.append(("bucket:" + name, lambda: self.remove_bucket(name)))
        self.sdk("s3.PutBucketVersioning", {"Bucket": name, "VersioningConfiguration": {"Status": "Enabled"}})
        return name

    def remove_bucket(self, name):
        versions = self.sdk("s3.ListObjectVersions", {"Bucket": name}, cleanup=True)
        require(not versions["IsTruncated"], "owned object versions unexpectedly paginated")
        for row in (versions.get("Versions") or []) + (versions.get("DeleteMarkers") or []):
            self.sdk("s3.DeleteObject", {"Bucket": name, "Key": row["Key"], "VersionId": row["VersionId"]}, cleanup=True)
        remaining = self.sdk("s3.ListObjectVersions", {"Bucket": name}, cleanup=True)
        require(not remaining.get("Versions") and not remaining.get("DeleteMarkers") and not remaining["IsTruncated"], "owned versions remain")
        self.sdk("s3.DeleteBucket", {"Bucket": name}, cleanup=True)
        self.sdk("s3.HeadBucket", {"Bucket": name}, expected=["NotFound", "NoSuchBucket"], cleanup=True)

    def schedule(self, suffix, arn, payload, expected=None):
        name = self.prefix + "-" + suffix
        at = self.now() + timedelta(seconds=120)
        params = {"Name": name, "ScheduleExpression": "at(" + at.strftime("%Y-%m-%dT%H:%M:%S") + ")",
                  "FlexibleTimeWindow": {"Mode": "OFF"}, "Target": {"Arn": arn, "RoleArn": self.scheduler_role,
                  "Input": payload, "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 600},
                  "DeadLetterConfig": {"Arn": self.queue_arn}}}
        output = self.sdk("scheduler.CreateSchedule", params, expected=expected)
        if "Error" not in output:
            self.cleanup.append(("schedule:" + name, lambda: self.remove_schedule(name)))
        return name, output

    def remove_schedule(self, name):
        self.sdk("scheduler.DeleteSchedule", {"Name": name}, cleanup=True)
        self.sdk("scheduler.GetSchedule", {"Name": name}, expected=["ResourceNotFoundException"], cleanup=True)

    def history(self):
        output = self.sdk("codepipeline.ListPipelineExecutions", {"PipelineName": self.prefix})
        require(not output.get("NextToken"), "execution history unexpectedly paginated")
        return output.get("PipelineExecutionSummaries") or []

    def finish_execution(self, identifier):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            self.advance(1)
            execution = self.sdk("codepipeline.GetPipelineExecution", {"PipelineName": self.prefix,
                                "PipelineExecutionId": identifier})["PipelineExecution"]
            if execution["Status"] not in ("InProgress", "Stopping"):
                actions = self.sdk("codepipeline.ListActionExecutions", {"PipelineName": self.prefix,
                                  "Filter": {"PipelineExecutionId": identifier}})
                require(not actions.get("NextToken"), "action history unexpectedly paginated")
                self.report["observations"][identifier] = {"execution": execution, "actions": actions}
                self.save()
                require(execution["Status"] == "Succeeded", "pipeline failed: " + json.dumps(execution))
                return execution
            time.sleep(0.1)
        raise TimeoutError("real pipeline execution did not finish")

    def receive_dlq(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = self.sdk("sqs.ReceiveMessage", {"QueueUrl": self.queue_url, "MaxNumberOfMessages": 10,
                              "MessageAttributeNames": ["All"], "MessageSystemAttributeNames": ["All"]})
            messages = result.get("Messages") or []
            if messages:
                for message in messages:
                    self.sdk("sqs.DeleteMessage", {"QueueUrl": self.queue_url, "ReceiptHandle": message["ReceiptHandle"]})
                return messages
            self.advance(1)
            time.sleep(0.1)
        raise TimeoutError("Scheduler failure did not reach actual SQS DLQ")

    def check_objects(self, bucket, members):
        output = self.sdk("s3.ListObjectsV2", {"Bucket": bucket})
        require(not output["IsTruncated"], "destination unexpectedly paginated")
        require({row["Key"] for row in output.get("Contents") or []} == set(members), "wrong deployed object keys")
        evidence = {}
        for key, expected in members.items():
            result = self.sdk("s3.GetObject", {"Bucket": bucket, "Key": key})
            body = base64.b64decode(result["Body"])
            require(body == expected, "deployed bytes differ from uploaded source ZIP member: " + key)
            evidence[key] = {"base64": result["Body"], "sha256": hashlib.sha256(body).hexdigest(), "length": len(body)}
        return evidence

    def execute(self):
        self.start()
        account = self.sdk("sts.GetCallerIdentity")["Account"]
        _, pipeline_role = self.role("pipeline", "codepipeline.amazonaws.com", ["s3:*"])
        scheduler_name, self.scheduler_role = self.role("scheduler", "scheduler.amazonaws.com", ["codepipeline:StartPipelineExecution", "sqs:SendMessage"])
        source, artifacts, destination = (self.bucket(suffix) for suffix in ("source", "artifacts", "destination"))
        queue_name = self.prefix + "-dlq"
        self.queue_url = self.sdk("sqs.CreateQueue", {"QueueName": queue_name})["QueueUrl"]
        def remove_queue():
            self.sdk("sqs.DeleteQueue", {"QueueUrl": self.queue_url}, cleanup=True)
            self.sdk("sqs.GetQueueUrl", {"QueueName": queue_name}, expected=["AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"], cleanup=True)
        self.cleanup.append(("queue:" + self.queue_url, remove_queue))
        self.queue_arn = self.sdk("sqs.GetQueueAttributes", {"QueueUrl": self.queue_url,
                                 "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        members = {"index.html": b"<html>retained Scheduler deployment</html>\n", "nested/config.json": b'{"scheduler":"real","revision":2}\n',
                   "asset.bin": bytes(range(256)) + b"\x00\xff", "empty.txt": b""}
        revisions = []
        for revision in (1, 2):
            zipped = io.BytesIO()
            with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as archive:
                for key, body in members.items():
                    archive.writestr(zipfile.ZipInfo(key, (2026, 1, 1, 0, 0, 0)), body if revision == 2 else b"old revision\n")
            uploaded = self.sdk("s3.PutObject", {"Bucket": source, "Key": "source.zip", "Body": base64.b64encode(zipped.getvalue()).decode()})
            revisions.append(uploaded["VersionId"])
        declaration = {"Name": self.prefix, "RoleArn": pipeline_role, "PipelineType": "V2", "ExecutionMode": "QUEUED",
                       "ArtifactStore": {"Type": "S3", "Location": artifacts}, "Variables": [{"Name": "Marker", "DefaultValue": "default-marker"}],
                       "Stages": [{"Name": "Source", "Actions": [{"Name": "Source", "ActionTypeId": {"Category": "Source", "Owner": "AWS", "Provider": "S3", "Version": "1"},
                                   "Configuration": {"S3Bucket": source, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, "OutputArtifacts": [{"Name": "SourceZip"}], "RunOrder": 1}]},
                                  {"Name": "Deploy", "Actions": [{"Name": "Deploy", "ActionTypeId": {"Category": "Deploy", "Owner": "AWS", "Provider": "S3", "Version": "1"},
                                   "Configuration": {"BucketName": destination, "Extract": "true", "CacheControl": "#{variables.Marker}"}, "InputArtifacts": [{"Name": "SourceZip"}], "RunOrder": 1}]}]}
        self.sdk("codepipeline.CreatePipeline", {"Pipeline": declaration})
        def remove_pipeline():
            self.sdk("codepipeline.DeletePipeline", {"Name": self.prefix}, cleanup=True)
            self.sdk("codepipeline.GetPipeline", {"Name": self.prefix}, expected=["PipelineNotFoundException"], cleanup=True)
        self.cleanup.append(("pipeline:" + self.prefix, remove_pipeline))
        arn = f"arn:aws:codepipeline:us-east-1:{account}:{self.prefix}"
        payload = json.dumps({"name": self.prefix + "-not-a-pipeline", "variables": [{"name": "Marker", "value": "input-marker"}],
                              "sourceRevisions": [{"actionName": "Source", "revisionType": "S3_OBJECT_VERSION_ID", "revisionValue": revisions[0]}],
                              "clientRequestToken": self.prefix + "-input-token"})
        if self.args.baseline:
            _, result = self.schedule("unsupported", arn, payload, expected=["NotImplementedException"])
            require("not implemented: codepipeline" in result["Error"]["Message"].lower(), "baseline was not explicit unsupported")
            self.report["observations"]["baseline_explicit_unsupported"] = result
            self.report["complete"] = True
            return
        for row in self.history():
            self.finish_execution(row["PipelineExecutionId"])
        direct_request = json.loads(payload)
        direct_request["name"] = self.prefix
        direct = self.sdk("codepipeline.StartPipelineExecution", direct_request)
        direct_execution = self.finish_execution(direct["PipelineExecutionId"])
        require(direct_execution["Variables"] == [{"Name": "Marker", "ResolvedValue": "input-marker"}], "direct CodePipeline variable override did not bind")
        require(any(row.get("RevisionId") == revisions[0] for row in direct_execution.get("ArtifactRevisions") or []), "direct source revision override did not bind")
        self.report["observations"]["direct_override_control"] = {
            "execution": direct_execution, "deployed_members": self.check_objects(destination, {key: b"old revision\n" for key in members})}
        before = {row["PipelineExecutionId"] for row in self.history()}
        name, _ = self.schedule("retained-denial", arn, payload)
        retained = self.sdk("scheduler.GetSchedule", {"Name": name})
        self.process.stop()
        self.start()
        reopened = self.sdk("scheduler.GetSchedule", {"Name": name})
        require(reopened["Target"] == retained["Target"] and reopened["ScheduleExpression"] == retained["ScheduleExpression"], "SQLite restart lost retained target")
        self.report["observations"]["sqlite_restart"] = {"before": retained, "after": reopened}
        self.policy(scheduler_name, ["codepipeline:StartPipelineExecution", "sqs:SendMessage"], deny=True)
        self.advance(180)
        messages = self.receive_dlq()
        self.report["observations"]["current_role_denial_dlq"] = messages
        require(len(messages) == 1 and json.loads(messages[0]["Body"]) == {"Name": self.prefix}, "DLQ differs from native translated CodePipeline request")
        require(messages[0]["MessageAttributes"]["ERROR_CODE"]["StringValue"] == "AccessDeniedException", "DLQ missing native access denial code")
        attributes = messages[0]["MessageAttributes"]
        require(attributes["RETRY_ATTEMPTS"]["StringValue"] == "0", "first denied attempt reported a retry")
        require(attributes["EXECUTION_ID"]["StringValue"] and "EXECUTION_ARN" not in attributes, "DLQ execution identifier key differs from native")
        require({row["PipelineExecutionId"] for row in self.history()} == before, "denied scheduler target started a pipeline")
        self.policy(scheduler_name, ["codepipeline:StartPipelineExecution", "sqs:SendMessage"])
        self.schedule("recovered", arn, payload)
        self.process.stop()
        self.start()
        self.advance(180)
        created = [row for row in self.history() if row["PipelineExecutionId"] not in before]
        require(len(created) == 1, "recovered schedule did not start exactly one execution")
        execution = self.finish_execution(created[0]["PipelineExecutionId"])
        self.report["observations"]["input_diagnostic"] = {"input": json.loads(payload), "execution": execution,
                                                        "uploaded_source_versions": revisions, "native_expectation": self.args.expected_input}
        require(self.args.expected_input == "ignored", "native input calibration must be supplied before asserting local behavior")
        require(execution["PipelineName"] == self.prefix and execution["Trigger"]["TriggerType"] == "StartPipelineExecution", "scheduled execution lost pipeline owner trigger")
        require(execution["Trigger"]["TriggerDetail"].startswith(f"arn:aws:sts::{account}:assumed-role/{scheduler_name}/"), "scheduled execution did not retain execution-role principal")
        require(execution["Variables"] == [{"Name": "Marker", "ResolvedValue": "default-marker"}], "Scheduler Input unexpectedly replaced variable default")
        require(any(row.get("RevisionId") == revisions[1] for row in execution.get("ArtifactRevisions") or []), "Scheduler did not execute latest uploaded source revision")
        self.report["observations"]["deployed_members"] = self.check_objects(destination, members)
        successful = {row["PipelineExecutionId"] for row in self.history()}
        for suffix, target_input in (("repeated-token", payload), ("plaintext", "owned plain text; not JSON")):
            self.schedule(suffix, arn, target_input)
            self.advance(180)
            started = [row for row in self.history() if row["PipelineExecutionId"] not in successful]
            require(len(started) == 1, suffix + " did not create a distinct execution")
            result = self.finish_execution(started[0]["PipelineExecutionId"])
            require(result["Variables"] == [{"Name": "Marker", "ResolvedValue": "default-marker"}], suffix + " changed default variables")
            require(any(row.get("RevisionId") == revisions[1] for row in result.get("ArtifactRevisions") or []), suffix + " changed source revision")
            self.report["observations"][suffix] = {"input": target_input, "execution": result,
                                                  "deployed_members": self.check_objects(destination, members)}
            successful.add(started[0]["PipelineExecutionId"])
        for suffix, foreign in (("foreign-account", arn.replace(account, "111111111111")), ("foreign-region", arn.replace("us-east-1", "us-west-2"))):
            _, result = self.schedule(suffix, foreign, payload, expected=["Success", "ValidationException"])
            observation = {"admission": result}
            if "Error" not in result:
                self.advance(180)
                observation["dlq"] = self.receive_dlq()
            require({row["PipelineExecutionId"] for row in self.history()} == successful, "foreign ARN addressed own pipeline by name")
            self.report["observations"][suffix] = observation
        missing = self.sdk("scheduler.GetSchedule", {"Name": self.prefix + "-missing"}, expected=["ResourceNotFoundException"])
        self.report["observations"]["decoded_scheduler_error"] = missing
        self.report["complete"] = True

    def run(self):
        failure = None
        try:
            self.execute()
        except BaseException as error:
            failure = error
            self.report["failure"] = repr(error)
        finally:
            cleanup_errors = []
            for identity, remove in reversed(self.cleanup):
                try:
                    remove()
                    self.report["cleanup"].append({"owned": identity, "verified_absent": True})
                except BaseException as error:
                    cleanup_errors.append({"owned": identity, "error": repr(error)})
            self.report["cleanup_errors"] = cleanup_errors
            try:
                self.process.stop()
            except BaseException as error:
                cleanup_errors.append({"controller": repr(error)})
            self.report["cleanup_verified"] = not cleanup_errors
            self.save()
        if failure:
            raise failure
        require(not cleanup_errors, "exact-owned cleanup failed: " + json.dumps(cleanup_errors))
        print(json.dumps({"report": str(self.state / "report.json"), "complete": self.report["complete"], "cleanup_verified": self.report["cleanup_verified"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--expected-input", choices=["ignored"], help="measured native templated target Input semantics")
    Workflow(parser.parse_args()).run()


if __name__ == "__main__":
    main()
