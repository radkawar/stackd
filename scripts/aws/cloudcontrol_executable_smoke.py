#!/usr/bin/env python3
"""Local signed Cloud Control/owner workflow against the actual stackd executable."""
import argparse
import json
import os
from pathlib import Path
import socket
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Proof:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        require(not any(self.state.iterdir()), "proof needs an empty owned state directory")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self.prefix = "cc-" + uuid.uuid4().hex[:12]
        self.controller = StackdProcess(self.state)
        self.report = {"prefix": self.prefix, "endpoint": self.endpoint, "observations": {}, "controllers": self.controller.runs, "cleanup": {}}
        self.owned = []
        self.client = {name: self.sdk(name) for name in ("cloudcontrol", "s3", "sqs", "logs", "iam", "ssm", "ecr")}

    def sdk(self, name, region="us-east-1", credentials=None):
        return boto3.client(name, endpoint_url=self.endpoint, region_name=region,
            aws_access_key_id=(credentials or {}).get("AccessKeyId", "test"),
            aws_secret_access_key=(credentials or {}).get("SecretAccessKey", "test"),
            config=Config(retries={"max_attempts": 0}, connect_timeout=3, read_timeout=30,
                s3={"addressing_style": "path"}))

    def save(self):
        (self.state / "report.json").write_text(json.dumps(self.report, indent=2, default=str) + "\n")

    def wait(self, fn, label, timeout=60):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = fn()
            if result:
                return result
            time.sleep(0.1)
        raise TimeoutError(label)

    def start(self):
        command = [str(Path(self.args.binary).resolve()), "-listen", f"127.0.0.1:{self.port}",
            "-public-endpoint", self.endpoint, "-database", str(self.state / "state.sqlite")]
        environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        environment.update(AWS_EC2_METADATA_DISABLED="true")
        self.controller.start(command, self.endpoint, environment=environment)

    def stop(self):
        self.controller.stop()
        self.save()

    def error(self, label, expected, operation, **request):
        try:
            operation(**request)
        except ClientError as error:
            code = error.response["Error"]["Code"]
            require(code == expected, f"{label}: expected {expected}, got {error}")
            self.report["observations"][label] = {"code": code, "status": error.response["ResponseMetadata"]["HTTPStatusCode"]}
            self.save()
            return
        raise AssertionError(label + " unexpectedly succeeded")

    def settle(self, response, status="SUCCESS", error=None):
        token = response["ProgressEvent"]["RequestToken"]
        states = [response["ProgressEvent"]["OperationStatus"]]
        def done():
            current = self.client["cloudcontrol"].get_resource_request_status(RequestToken=token)["ProgressEvent"]
            states.append(current["OperationStatus"])
            if current["OperationStatus"] in ("IN_PROGRESS", "PENDING", "CANCEL_IN_PROGRESS"):
                return None
            require(current["OperationStatus"] == status, f"unexpected terminal progress {current}")
            if error:
                require(current.get("ErrorCode") == error, f"unexpected handler error {current}")
            return current
        result = self.wait(done, "resource " + token)
        self.report["observations"].setdefault("requests", []).append({"token": token, "states": states, "result": result})
        self.save()
        return result

    def create(self, typ, props, **extra):
        response = self.client["cloudcontrol"].create_resource(TypeName=typ, DesiredState=json.dumps(props), **extra)
        require(response["ProgressEvent"]["OperationStatus"] == "IN_PROGRESS", "create did not return real async intent")
        progress = self.settle(response)
        ref = {"TypeName": typ, "Identifier": progress["Identifier"]}
        self.owned.append(ref)
        return ref, progress

    def read(self, ref):
        result = self.client["cloudcontrol"].get_resource(**ref)["ResourceDescription"]
        require(result["Identifier"] == ref["Identifier"], "identifier changed")
        model = json.loads(result["Properties"])
        tags = model.get("Tags", [])
        keys = tags if isinstance(tags, dict) else [row["Key"] for row in tags]
        require(all(not key.startswith("stackd:cloudformation:") for key in keys), "private owner tags leaked")
        return model

    def update(self, ref, patch, **extra):
        return self.settle(self.client["cloudcontrol"].update_resource(**ref, PatchDocument=json.dumps(patch), **extra))

    def exercise(self):
        cc, s3, sqs, logs, iam = (self.client[k] for k in ("cloudcontrol", "s3", "sqs", "logs", "iam"))
        bucket, bucket_progress = self.create("AWS::S3::Bucket", {"BucketName": self.prefix + "-bucket", "Tags": [{"Key": "owner", "Value": self.prefix}]})
        queue, _ = self.create("AWS::SQS::Queue", {"QueueName": self.prefix + "-queue", "VisibilityTimeout": 20})
        group, group_progress = self.create("AWS::Logs::LogGroup", {"LogGroupName": self.prefix + "-logs", "RetentionInDays": 1}, ClientToken=self.prefix)
        parameter, _ = self.create("AWS::SSM::Parameter", {"Name": "/" + self.prefix + "/value", "Type": "String", "Value": "created", "Tags": {"owner": self.prefix}})
        repository, _ = self.create("AWS::ECR::Repository", {"RepositoryName": self.prefix + "-repository", "ImageTagMutability": "MUTABLE", "ImageScanningConfiguration": {"ScanOnPush": False}})
        resources = (bucket, queue, group, parameter, repository)
        listing = {"ResourceRequestStatusFilter": {"Operations": ["CREATE"], "OperationStatuses": ["SUCCESS"]}, "MaxResults": 1}
        listed = set()
        while True:
            page = cc.list_resource_requests(**listing)
            for request in page["ResourceRequestStatusSummaries"]:
                require(request["Operation"] == "CREATE" and request["OperationStatus"] == "SUCCESS", "request filter was ignored")
                require(request["Identifier"] not in listed, "request pagination duplicated an identity")
                listed.add(request["Identifier"])
            if not page.get("NextToken"):
                break
            listing["NextToken"] = page["NextToken"]
        require(listed == {v["Identifier"] for v in resources}, "request pagination lost accepted resources")
        self.report["observations"]["request-listing"] = sorted(listed)
        for ref in resources:
            model = self.read(ref)
            rows = cc.list_resources(TypeName=ref["TypeName"], MaxResults=100)["ResourceDescriptions"]
            require(any(v["Identifier"] == ref["Identifier"] for v in rows), "owner list omitted provisioned resource")
            self.report["observations"][ref["TypeName"]] = model
        name = bucket["Identifier"]
        s3.put_object(Bucket=name, Key="actual", Body=b"cloudcontrol-real-object")
        require(s3.get_object(Bucket=name, Key="actual")["Body"].read() == b"cloudcontrol-real-object", "missing real S3 bytes")
        sqs.send_message(QueueUrl=queue["Identifier"], MessageBody="cloudcontrol-real-message")
        message = self.wait(lambda: sqs.receive_message(QueueUrl=queue["Identifier"], WaitTimeSeconds=1).get("Messages"), "actual queue message")[0]
        require(message["Body"] == "cloudcontrol-real-message", "wrong owner message")
        sqs.delete_message(QueueUrl=queue["Identifier"], ReceiptHandle=message["ReceiptHandle"])
        logs.create_log_stream(logGroupName=group["Identifier"], logStreamName="actual")
        logs.put_log_events(logGroupName=group["Identifier"], logStreamName="actual", logEvents=[{"timestamp": int(time.time() * 1000), "message": "cloudcontrol-real-log"}])
        require(logs.get_log_events(logGroupName=group["Identifier"], logStreamName="actual")["events"][0]["message"] == "cloudcontrol-real-log", "missing owner log event")
        self.update(group, [{"op": "test", "path": "/RetentionInDays", "value": 1}, {"op": "replace", "path": "/RetentionInDays", "value": 3}])
        self.update(queue, [{"op": "replace", "path": "/VisibilityTimeout", "value": 31}])
        self.update(bucket, [{"op": "add", "path": "/VersioningConfiguration", "value": {"Status": "Enabled"}}])
        require(self.read(group)["RetentionInDays"] == 3 and self.read(queue)["VisibilityTimeout"] == 31, "mutable owner update missing")
        self.update(parameter, [{"op": "replace", "path": "/Value", "value": "updated"}])
        require(self.client["ssm"].get_parameter(Name=parameter["Identifier"])["Parameter"]["Value"] == "updated", "SSM owner value did not change")
        self.update(repository, [{"op": "replace", "path": "/ImageTagMutability", "value": "IMMUTABLE"}])
        require(self.client["ecr"].describe_repositories(repositoryNames=[repository["Identifier"]])["repositories"][0]["imageTagMutability"] == "IMMUTABLE", "ECR owner configuration did not change")
        for ref in (parameter, repository):
            self.settle(cc.delete_resource(TypeName=ref["TypeName"], Identifier=self.prefix + "-absent"), "FAILED", "NotFound")
        for label, path, value, expected in [("create-only", "/LogGroupName", "renamed", "NotUpdatableException"), ("readonly", "/Arn", "fake", "ValidationException")]:
            self.error(label, expected, cc.update_resource, **group, PatchDocument=json.dumps([{"op": "replace", "path": path, "value": value}]))
        self.error("failed-test", "ValidationException", cc.update_resource, **group, PatchDocument='[{"op":"test","path":"/RetentionInDays","value":999}]')
        self.settle(cc.create_resource(TypeName=group["TypeName"], DesiredState=json.dumps({"LogGroupName": group["Identifier"]})), "FAILED", "AlreadyExists")
        self.settle(cc.delete_resource(TypeName=group["TypeName"], Identifier=self.prefix + "-missing"), "FAILED", "NotFound")
        # Resources created outside Cloud Control are discovered from owners.
        direct_name = self.prefix + "-direct"
        logs.create_log_group(logGroupName=direct_name)
        direct = {"TypeName": "AWS::Logs::LogGroup", "Identifier": direct_name}
        self.owned.append(direct)
        self.update(direct, [{"op": "add", "path": "/RetentionInDays", "value": 7}])
        require(self.read(direct)["RetentionInDays"] == 7, "direct owner update depended on a Cloud Control resource database")
        # Fresh execution-role authorization governs actual owner commands.
        role_name = self.prefix + "-role"
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "logs:*", "Resource": "*"}]}
        iam.put_role_policy(RoleName=role_name, PolicyName="execution", PolicyDocument=json.dumps(policy))
        self.report["role"] = role_name
        role_group, _ = self.create("AWS::Logs::LogGroup", {"LogGroupName": self.prefix + "-role-logs", "RetentionInDays": 1}, RoleArn=role)
        policy["Statement"].append({"Effect": "Deny", "Action": "logs:PutRetentionPolicy", "Resource": "*"})
        iam.put_role_policy(RoleName=role_name, PolicyName="execution", PolicyDocument=json.dumps(policy))
        self.settle(cc.update_resource(**role_group, RoleArn=role, PatchDocument='[{"op":"replace","path":"/RetentionInDays","value":3}]'), "FAILED", "AccessDenied")
        require(self.read(role_group)["RetentionInDays"] == 1, "denied owner update changed retention")
        policy["Statement"].pop()
        iam.put_role_policy(RoleName=role_name, PolicyName="execution", PolicyDocument=json.dumps(policy))
        self.update(role_group, [{"op": "replace", "path": "/RetentionInDays", "value": 3}], RoleArn=role)
        self.stop()
        self.start()
        retained = cc.get_resource_request_status(RequestToken=group_progress["RequestToken"])["ProgressEvent"]
        require(retained["OperationStatus"] == "SUCCESS" and retained["Identifier"] == group["Identifier"], "progress did not survive restart")
        require(s3.get_object(Bucket=name, Key="actual")["Body"].read() == b"cloudcontrol-real-object", "S3 bytes did not survive restart")
        require(self.read(group)["RetentionInDays"] == 3, "live model reverted to create intent after restart")
        self.report["observations"]["restart"] = {"retained_request": group_progress["RequestToken"], "live_retention": 3, "object_bytes": "cloudcontrol-real-object"}
        self.error("cross-region-request", "RequestTokenNotFoundException", self.sdk("cloudcontrol", region="us-west-2").get_resource_request_status, RequestToken=bucket_progress["RequestToken"])
        # Failed nonempty bucket deletion must preserve the actual data.
        self.settle(cc.delete_resource(**bucket), "FAILED", "InvalidRequest")
        require(s3.get_object(Bucket=name, Key="actual")["Body"].read() == b"cloudcontrol-real-object", "failed deletion lost data")
        s3.delete_object(Bucket=name, Key="actual", VersionId="null")
        for ref in reversed(self.owned):
            self.settle(cc.delete_resource(**ref))
            self.error("deleted-" + ref["Identifier"], "ResourceNotFoundException", cc.get_resource, **ref)
        self.owned.clear()
        iam.delete_role_policy(RoleName=role_name, PolicyName="execution")
        iam.delete_role(RoleName=role_name)
        self.report.pop("role", None)
        self.report["cleanup"] = {"complete": True, "resources_absent": True, "execution_role_absent": True}
        self.save()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    args = parser.parse_args()
    proof = Proof(args)
    try:
        proof.start()
        proof.exercise()
    finally:
        proof.save()
        proof.stop()
    print(json.dumps({"prefix": proof.prefix, "cleanup": proof.report["cleanup"], "controllers": [v["exit"] for v in proof.report["controllers"]]}))


if __name__ == "__main__":
    main()
