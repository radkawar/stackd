#!/usr/bin/env python3
"""Local-only AWS CLI proof over the actual executable and retained SQLite state."""
import argparse
import csv
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
import uuid

from aws_cli import call, observe, run
from scheduler_pipes_executable_smoke import require
from stackd_process import StackdProcess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    args = parser.parse_args()
    state = Path(args.state_directory).resolve()
    state.mkdir(parents=True, exist_ok=True)
    require(not any(state.iterdir()), "requires a fresh owned state directory")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
    environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true", AWS_ENDPOINT_URL=endpoint, AWS_MAX_ATTEMPTS="1")
    controller = StackdProcess(state)
    report = {"endpoint": endpoint, "observations": {}, "controllers": controller.runs, "cleanup": []}
    def save():
        (state / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    def start():
        command = [str(Path(args.binary).resolve()), "-listen", f"127.0.0.1:{port}", "-public-endpoint", endpoint, "-database", str(state / "state.sqlite"), "-clock-start", "2026-09-27T12:00:00Z"]
        controller.start(command, endpoint, environment=environment)
    def invoke(service, action, request):
        return call(service, action, request, environment, paginate=False)
    def control(path, payload=None):
        request = urllib.request.Request(endpoint + path, data=json.dumps(payload or {}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    def advance(seconds):
        control("/_stackd/clock", {"advance": f"{seconds}s"})
        return control("/_stackd/jobs/drain?limit=1024")
    def terminal_report(caller_environment=None):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            control("/_stackd/jobs/drain?limit=1024")
            result = call("resourcegroupstaggingapi", "describe-report-creation", {}, caller_environment or environment, paginate=False)
            if result["Status"] != "RUNNING":
                return result
            time.sleep(0.1)
        raise TimeoutError("report completion")
    name = "tag-cli-" + uuid.uuid4().hex[:10]
    queue = key = None
    parameter = "/" + name
    actor = name + "-actor"
    actor_key = policy_id = root_id = org_id = bucket = wrong_bucket = kms_key = None
    delivered_keys = []
    try:
        start()
        key = invoke("ec2", "create-key-pair", {"KeyName": name, "KeyType": "ed25519", "TagSpecifications": [{"ResourceType": "key-pair", "Tags": [{"Key": "workflow", "Value": name}]}]})
        key.pop("KeyMaterial", None)
        queue = invoke("sqs", "create-queue", {"QueueName": name, "tags": {"workflow": name}})
        invoke("ssm", "put-parameter", {"Name": parameter, "Type": "String", "Value": "owned-local-value", "Tags": [{"Key": "workflow", "Value": name}]})
        arns = [f"arn:aws:ec2:us-east-1:000000000000:key-pair/{key['KeyPairId']}", f"arn:aws:sqs:us-east-1:000000000000:{name}", f"arn:aws:ssm:us-east-1:000000000000:parameter/{name}"]
        discovery = invoke("resourcegroupstaggingapi", "get-resources", {"TagFilters": [{"Key": "workflow", "Values": [name]}]})
        require({r["ResourceARN"] for r in discovery["ResourceTagMappingList"]} == set(arns), "native-to-tagging discovery mismatch")
        report["observations"]["native_to_tagging"] = discovery
        mutation = invoke("resourcegroupstaggingapi", "tag-resources", {"ResourceARNList": arns, "Tags": {"roundtrip": "tagging-owner"}})
        require(not mutation["FailedResourcesMap"], "tagging mutation failed")
        native = {"ec2": invoke("ec2", "describe-key-pairs", {"KeyNames": [name]}), "sqs": invoke("sqs", "list-queue-tags", {"QueueUrl": queue["QueueUrl"]}), "ssm": invoke("ssm", "list-tags-for-resource", {"ResourceType": "Parameter", "ResourceId": parameter})}
        require(native["sqs"]["Tags"]["roundtrip"] == "tagging-owner", "SQS native tags did not change")
        for tags in (native["ec2"]["KeyPairs"][0]["Tags"], native["ssm"]["TagList"]):
            require(any(tag["Key"] == "roundtrip" and tag["Value"] == "tagging-owner" for tag in tags), "native tags did not change")
        report["observations"]["tagging_to_native"] = native
        invoke("iam", "create-user", {"UserName": actor})
        actor_key = invoke("iam", "create-access-key", {"UserName": actor})["AccessKey"]
        actor_environment = dict(environment, AWS_ACCESS_KEY_ID=actor_key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=actor_key["SecretAccessKey"])
        invoke("iam", "put-user-policy", {"UserName": actor, "PolicyName": "tagging-smoke", "PolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "tag:*", "Resource": "*"}, {"Effect": "Allow", "Action": ["sqs:TagQueue", "sqs:UntagQueue"], "Resource": "*"}]})})
        partial = call("resourcegroupstaggingapi", "tag-resources", {"ResourceARNList": [arns[0], arns[1]], "Tags": {"iam-proof": "accepted"}}, actor_environment)
        require(set(partial["FailedResourcesMap"]) == {arns[0]}, "dependent IAM partial failure mismatch")
        require(invoke("sqs", "list-queue-tags", {"QueueUrl": queue["QueueUrl"]})["Tags"]["iam-proof"] == "accepted", "successful partial sibling did not commit")
        invoke("iam", "put-user-policy", {"UserName": actor, "PolicyName": "tagging-smoke", "PolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "Action": "sqs:TagQueue", "Resource": "*"}]})})
        denied = call("resourcegroupstaggingapi", "tag-resources", {"ResourceARNList": [arns[1]], "Tags": {"iam-proof": "forbidden"}}, actor_environment)
        require(set(denied["FailedResourcesMap"]) == {arns[1]}, "current native IAM denial missing")
        require(invoke("sqs", "list-queue-tags", {"QueueUrl": queue["QueueUrl"]})["Tags"]["iam-proof"] == "accepted", "denied update changed native tags")
        report["observations"]["iam_mixed_success"] = partial
        report["observations"]["iam_current_denial"] = denied
        invoke("ssm", "remove-tags-from-resource", {"ResourceType": "Parameter", "ResourceId": parameter, "TagKeys": ["workflow", "roundtrip"]})
        controller.stop()
        start()
        retained = invoke("resourcegroupstaggingapi", "get-resources", {"ResourceARNList": [arns[2]]})
        require(retained["ResourceTagMappingList"] == [{"ResourceARN": arns[2], "Tags": []}], "previously-tagged membership did not survive restart")
        report["observations"]["previously_tagged_after_reopen"] = retained
        invoke("ssm", "delete-parameter", {"Name": parameter})
        invoke("ssm", "put-parameter", {"Name": parameter, "Type": "String", "Value": "new-untagged-incarnation"})
        recreated = invoke("resourcegroupstaggingapi", "get-resources", {"ResourceARNList": [arns[2]]})
        require(recreated["ResourceTagMappingList"] == [], "deleted ARN membership leaked into new untagged resource")
        report["observations"]["recreated_untagged"] = recreated
        organization = invoke("organizations", "create-organization", {"FeatureSet": "ALL"})["Organization"]
        org_id = organization["Id"]
        root_id = invoke("organizations", "list-roots", {})["Roots"][0]["Id"]
        invoke("organizations", "enable-policy-type", {"RootId": root_id, "PolicyType": "TAG_POLICY"})
        invoke("organizations", "enable-aws-service-access", {"ServicePrincipal": "tagpolicies.tag.amazonaws.com"})
        policy = {"tags": {"workflow": {"tag_key": {"@@assign": "workflow"}, "tag_value": {"@@assign": [name]}, "report_required_tag_for": {"@@assign": ["sqs:queue"]}}}}
        policy_id = invoke("organizations", "create-policy", {"Name": name, "Description": "owned tagging smoke", "Type": "TAG_POLICY", "Content": json.dumps(policy)})["Policy"]["PolicySummary"]["Id"]
        invoke("organizations", "attach-policy", {"PolicyId": policy_id, "TargetId": root_id})
        advance(2)
        invoke("resourcegroupstaggingapi", "tag-resources", {"ResourceARNList": [arns[1]], "Tags": {"workflow": "noncompliant"}})
        summary = invoke("resourcegroupstaggingapi", "get-compliance-summary", {"GroupBy": ["TARGET_ID", "REGION", "RESOURCE_TYPE"], "ResourceTypeFilters": ["sqs:queue"]})
        require(sum(row["NonCompliantResources"] for row in summary["SummaryList"]) == 1, "actual organization summary count differs")
        required = invoke("resourcegroupstaggingapi", "list-required-tags", {})
        require(any(row["ResourceType"] == "sqs:queue" and row["ReportingTagKeys"] == ["workflow"] and row["CloudFormationResourceTypes"] == ["AWS::SQS::Queue"] for row in required["RequiredTags"]), "published required-tag mapping missing")
        kms_key = invoke("kms", "create-key", {})["KeyMetadata"]["KeyId"]
        bucket = name + "-reports"
        invoke("s3api", "create-bucket", {"Bucket": bucket})
        invoke("s3api", "put-bucket-encryption", {"Bucket": bucket, "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": kms_key}}]}})
        invoke("resourcegroupstaggingapi", "start-report-creation", {"S3Bucket": bucket})
        completed = terminal_report()
        report["observations"]["compliance_summary"] = summary
        report["observations"]["required_tags"] = required
        report["observations"]["s3_report_status"] = completed
        require(completed["Status"] == "SUCCEEDED", "actual S3 report failed: " + str(completed))
        object_key = completed["S3Location"].removeprefix("s3://" + bucket + "/")
        delivered_keys.append(object_key)
        download = state / "compliance.csv"
        result = run("s3api", "get-object", env=environment, options=("--bucket", bucket, "--key", object_key, str(download)), timeout=30)
        require(result.returncode == 0, "actual report object retrieval failed: " + result.stderr)
        metadata = json.loads(result.stdout)
        require(metadata["ServerSideEncryption"] == "aws:kms", "S3 report bypassed bucket KMS encryption")
        with download.open(newline="") as content:
            csv_rows = list(csv.DictReader(content))
        queue_rows = [row for row in csv_rows if row["ResourceARN"] == arns[1]]
        require(len(queue_rows) == 1 and queue_rows[0]["ComplianceStatus"] == "FALSE", "CSV did not contain actual queue noncompliance")
        report["observations"]["s3_kms_report"] = {"status": completed, "object": metadata, "queue_row": queue_rows[0]}
        invoke("iam", "put-user-policy", {"UserName": actor, "PolicyName": "tagging-smoke", "PolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"}]})})
        call("resourcegroupstaggingapi", "start-report-creation", {"S3Bucket": bucket}, actor_environment)
        failed = terminal_report(actor_environment)
        require(failed["Status"] == "FAILED" and "AccessDenied" in failed["ErrorMessage"], "S3 current denial was not retained as failed report")
        report["observations"]["report_delivery_denied"] = failed
        controller.stop()
        start()
        retained_report = invoke("resourcegroupstaggingapi", "describe-report-creation", {})
        require(retained_report == failed, "failed report status did not survive controller reopen")
        report["observations"]["retained_report_failure"] = retained_report
        wrong_bucket = name + "-wrong-region"
        west = dict(environment, AWS_DEFAULT_REGION="us-west-2")
        call("s3api", "create-bucket", {"Bucket": wrong_bucket, "CreateBucketConfiguration": {"LocationConstraint": "us-west-2"}}, west)
        wrong = observe("resourcegroupstaggingapi", "start-report-creation", {"S3Bucket": wrong_bucket}, environment)
        require(wrong["code"] == "InvalidParameterException", "wrong-region destination admitted")
        report["observations"]["wrong_region_report"] = wrong
        report["cleanup"].append({"service": "s3api", "operation": "delete-bucket", "result": call("s3api", "delete-bucket", {"Bucket": wrong_bucket}, west)})
        wrong_bucket = None
        save()
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        if controller.process is not None and controller.process.poll() is None:
            extra_cleanup = []
            if policy_id:
                extra_cleanup += [("organizations", "detach-policy", {"PolicyId": policy_id, "TargetId": root_id}), ("organizations", "delete-policy", {"PolicyId": policy_id})]
            if org_id:
                extra_cleanup += [("organizations", "disable-aws-service-access", {"ServicePrincipal": "tagpolicies.tag.amazonaws.com"}), ("organizations", "delete-organization", {})]
            for object_key in delivered_keys:
                extra_cleanup.append(("s3api", "delete-object", {"Bucket": bucket, "Key": object_key}))
            for bucket_name in (bucket, wrong_bucket):
                if bucket_name:
                    extra_cleanup.append(("s3api", "delete-bucket", {"Bucket": bucket_name}))
            if kms_key:
                extra_cleanup.append(("kms", "schedule-key-deletion", {"KeyId": kms_key, "PendingWindowInDays": 7}))
            if actor_key:
                extra_cleanup += [("iam", "delete-user-policy", {"UserName": actor, "PolicyName": "tagging-smoke"}), ("iam", "delete-access-key", {"UserName": actor, "AccessKeyId": actor_key["AccessKeyId"]}), ("iam", "delete-user", {"UserName": actor})]
            for service, action, request in extra_cleanup:
                try:
                    report["cleanup"].append({"service": service, "operation": action, "result": invoke(service, action, request)})
                except Exception as error:
                    report["cleanup"].append({"service": service, "operation": action, "error": str(error)})
            for service, action, request in (("ssm", "delete-parameter", {"Name": parameter}), ("sqs", "delete-queue", {"QueueUrl": queue["QueueUrl"]}) if queue else ("sqs", "list-queues", {}), ("ec2", "delete-key-pair", {"KeyName": name})):
                try:
                    result = invoke(service, action, request)
                    report["cleanup"].append({"service": service, "operation": action, "result": result})
                except Exception as error:
                    report["cleanup"].append({"service": service, "error": str(error)})
        try:
            controller.stop()
        finally:
            save()
    require(not any("error" in row for row in report["cleanup"]), "resource cleanup failed")
    print(json.dumps({"report": str(state / "report.json"), "native_to_tagging": True, "tagging_to_native": True, "sqlite_reopen": True, "controllers": report["controllers"]}))


if __name__ == "__main__":
    main()
