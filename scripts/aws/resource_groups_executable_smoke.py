#!/usr/bin/env python3
"""Local-only Resource Groups proof over real owners and a restarted SQLite process."""
import argparse
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from stackd_process import StackdProcess


def require(condition, message):
    if not condition:
        raise AssertionError(message)


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
    environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true")
    process = StackdProcess(state)
    command = [str(Path(args.binary).resolve()), "-listen", f"127.0.0.1:{port}", "-public-endpoint", endpoint, "-database", str(state / "state.sqlite"), "-clock-start", "2026-09-28T12:00:00Z"]
    report = {"endpoint": endpoint, "observations": {}, "controllers": process.runs, "cleanup": []}
    config = Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=30, s3={"addressing_style": "path"})

    def client(service, region="us-east-1", credentials=None):
        c = credentials or {"AccessKeyId": "test", "SecretAccessKey": "test"}
        return boto3.client(service, endpoint_url=endpoint, region_name=region, aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c.get("SessionToken"), config=config)

    rg, s3, sqs, cfn, iam, sts = (client(s) for s in ("resource-groups", "s3", "sqs", "cloudformation", "iam", "sts"))

    def save():
        (state / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")

    def control(path, body=None):
        request = urllib.request.Request(endpoint + path, data=json.dumps(body or {}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    def advance(seconds):
        control("/_stackd/clock", {"advance": f"{seconds}s"})
        control("/_stackd/jobs/drain?limit=1024")

    def rejected(label, codes, fn):
        try:
            fn()
        except ClientError as error:
            require(error.response["Error"]["Code"] in codes, f"{label}: {error}")
            report["observations"][label] = {"code": error.response["Error"]["Code"], "request_id": error.response["ResponseMetadata"].get("RequestId")}
            return
        raise AssertionError(label + " unexpectedly succeeded")

    def query(types, filters):
        return {"Type": "TAG_FILTERS_1_0", "Query": json.dumps({"ResourceTypeFilters": types, "TagFilters": filters})}

    def members(group):
        result, token = [], None
        while True:
            request = {"Group": group, "MaxResults": 1}
            if token:
                request["NextToken"] = token
            out = rg.list_group_resources(**request)
            result.extend(r["ResourceArn"] for r in out["ResourceIdentifiers"])
            token = out.get("NextToken")
            if not token:
                return sorted(result)

    def settle(stack, status):
        for _ in range(60):
            advance(1)
            out = cfn.describe_stacks(StackName=stack)["Stacks"][0]
            if out["StackStatus"] == status:
                return out
            require(not out["StackStatus"].endswith("FAILED"), str(out))
            time.sleep(0.01)
        raise TimeoutError("CloudFormation " + status)

    name = "rg-cli-" + uuid.uuid4().hex[:10]
    bucket, queue_name, role = name + "-bucket", name + "-queue", name + "-reader"
    group = stack_group = stack = queue_url = role_arn = None
    queue_names = {queue_name, name + "-stack-a", name + "-stack-b"}
    bucket_created = False
    try:
        process.start(command, endpoint, environment=environment)
        account = sts.get_caller_identity()["Account"]
        s3.create_bucket(Bucket=bucket)
        bucket_created = True
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "workflow", "Value": name}, {"Key": "stage", "Value": "blue"}]})
        s3.put_object(Bucket=bucket, Key="actual.txt", Body=b"actual Resource Groups owner bytes")
        queue_url = sqs.create_queue(QueueName=queue_name, tags={"workflow": name, "stage": "red"})["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        base = query(["AWS::AllSupported"], [{"Key": "workflow", "Values": [name]}])
        group = rg.create_group(Name=name, ResourceQuery=base, Tags={"workflow": name, "access": "allowed"})["Group"]["GroupArn"]
        expected = sorted([group, queue_arn, "arn:aws:s3:::" + bucket])
        require(members(group) == expected, "self/live owner membership mismatch")
        report["observations"]["self_and_current_owners"] = members(group)
        require(sorted(row["ResourceArn"] for row in rg.search_resources(ResourceQuery=base)["ResourceIdentifiers"]) == expected, "ad hoc discovery differs from group selection")
        rg.tag(Arn=group, Tags={"roundtrip": "present"})
        require(rg.get_tags(Arn=group)["Tags"]["roundtrip"] == "present", "group tag lost")
        rg.untag(Arn=group, Keys=["roundtrip", "absent"])
        tagging = client("resourcegroupstaggingapi")
        tagged = tagging.tag_resources(ResourceARNList=[group], Tags={"external-owner": "tagging-api"})
        require(tagged["FailedResourcesMap"] == {} and rg.get_tags(Arn=group)["Tags"]["external-owner"] == "tagging-api", "shared tagging mutation did not reach group owner")
        require(tagging.get_resources(ResourceARNList=[group])["ResourceTagMappingList"][0]["ResourceARN"] == group, "group missing from current tagging discovery")
        report["observations"]["tagging_owner_roundtrip"] = tagged
        rg.update_group(Group=group, Description="retained description")
        for attribute, value in (("DisplayName", "ordinary"), ("Owner", "owner"), ("Criticality", 1)):
            rejected("ordinary_" + attribute, {"BadRequestException"}, lambda attribute=attribute, value=value: rg.update_group(Group=group, **{attribute: value}))
        require(rg.list_groups(Filters=[{"Name": "resource-type", "Values": ["AWS::SQS::Queue"]}])["Groups"] == [], "definition filter expanded AllSupported")
        rg.update_group_query(Group=group, ResourceQuery=query(["AWS::SQS::Queue"], [{"Key": "workflow", "Values": [name]}, {"Key": "stage", "Values": ["red"]}]))
        require(members(group) == [queue_arn], "query update failed")
        sqs.untag_queue(QueueUrl=queue_url, TagKeys=["stage"])
        require(members(group) == [], "owner untag did not change query")
        sqs.tag_queue(QueueUrl=queue_url, Tags={"stage": "red"})
        sqs.send_message(QueueUrl=queue_url, MessageBody="actual selected queue")
        require(sqs.receive_message(QueueUrl=queue_url)["Messages"][0]["Body"] == "actual selected queue", "SQS data plane mismatch")
        require(s3.get_object(Bucket=bucket, Key="actual.txt")["Body"].read() == b"actual Resource Groups owner bytes", "S3 data plane mismatch")
        role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["resource-groups:ListGroupResources", "resource-groups:GetGroup"], "Resource": group, "Condition": {"StringEquals": {"aws:ResourceTag/access": "allowed"}}}, {"Effect": "Allow", "Action": "tag:GetResources", "Resource": "*"}]}
        iam.put_role_policy(RoleName=role, PolicyName="read-current", PolicyDocument=json.dumps(policy))
        credentials = sts.assume_role(RoleArn=role_arn, RoleSessionName="group-reader")["Credentials"]
        actor = client("resource-groups", credentials=credentials)
        require(actor.list_group_resources(Group=group)["ResourceIdentifiers"][0]["ResourceArn"] == queue_arn, "role current read failed")
        rg.tag(Arn=group, Tags={"access": "denied"})
        rejected("current_resource_tag_denial", {"AccessDenied", "AccessDeniedException", "ForbiddenException"}, lambda: actor.get_group(Group=group))
        rg.tag(Arn=group, Tags={"access": "allowed"})
        iam.delete_role_policy(RoleName=role, PolicyName="read-current")
        rejected("current_role_policy_revocation", {"AccessDenied", "AccessDeniedException", "ForbiddenException"}, lambda: actor.list_group_resources(Group=group))
        rejected("regional_group_isolation", {"NotFoundException"}, lambda: client("resource-groups", "us-west-2").get_group(Group=group))
        template = lambda queue: json.dumps({"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {"QueueName": queue}}}})
        stack = cfn.create_stack(StackName=name + "-stack", TemplateBody=template(name + "-stack-a"))["StackId"]
        settle(stack, "CREATE_COMPLETE")
        stack_query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({"ResourceTypeFilters": ["AWS::AllSupported"], "StackIdentifier": stack})}
        stack_group = rg.create_group(Name=name + "-stack-group", ResourceQuery=stack_query)["Group"]["GroupArn"]
        old_arn = f"arn:aws:sqs:us-east-1:{account}:{name}-stack-a"
        require(members(stack_group) == [old_arn], "untagged CFN owner absent")
        cfn.update_stack(StackName=stack, TemplateBody=template(name + "-stack-b"))
        settle(stack, "UPDATE_COMPLETE")
        current_arn = f"arn:aws:sqs:us-east-1:{account}:{name}-stack-b"
        require(members(stack_group) == [current_arn], "retained old CFN resource leaked")
        current_url = sqs.get_queue_url(QueueName=name + "-stack-b")["QueueUrl"]
        sqs.send_message(QueueUrl=current_url, MessageBody="actual CloudFormation owner")
        require(sqs.receive_message(QueueUrl=current_url)["Messages"][0]["Body"] == "actual CloudFormation owner", "CFN queue data plane failed")
        report["observations"]["cloudformation_replacement"] = {"retained_old": old_arn, "selected_current": members(stack_group)}
        process.stop()
        process.start(command, endpoint, environment=environment)
        require(members(group) == [queue_arn] and members(stack_group) == [current_arn], "SQLite reopen lost queries/current ownership")
        require(rg.get_group(Group=group)["Group"]["Description"] == "retained description", "description not retained")
        report["observations"]["sqlite_restart"] = {"query": rg.get_group_query(Group=group)["GroupQuery"], "members": members(stack_group)}
        sqs.delete_queue(QueueUrl=current_url)
        advance(61)
        sqs.create_queue(QueueName=name + "-stack-b")
        require(members(stack_group) == [], "recreated queue impersonated old stack incarnation")
        report["observations"]["owner_recreation_fenced"] = members(stack_group)
        cfn.delete_stack(StackName=stack)
        settle(stack, "DELETE_COMPLETE")
        deleted = rg.list_group_resources(Group=stack_group)
        require(deleted["ResourceIdentifiers"] == [] and deleted["QueryErrors"][0]["ErrorCode"] == "CLOUDFORMATION_STACK_INACTIVE", "deleted stack query semantics differ")
        report["observations"]["deleted_stack"] = deleted
        for label, action in (
            ("group", lambda: rg.group_resources(Group=group, ResourceArns=[queue_arn])),
            ("ungroup", lambda: rg.ungroup_resources(Group=group, ResourceArns=[queue_arn])),
            ("configuration", lambda: rg.get_group_configuration(Group=group)),
            ("put_configuration", lambda: rg.put_group_configuration(Group=group, Configuration=[{"Type": "AWS::ResourceGroups::Generic"}])),
            ("grouping_statuses", lambda: rg.list_grouping_statuses(Group=group)),
        ):
            rejected("query_group_" + label, {"BadRequestException"}, action)
        task_arn = group + "/" + "a" * 26 + "/tag-sync-task/" + "b" * 26
        rejected("missing_tag_sync", {"NotFoundException"}, lambda: rg.get_tag_sync_task(TaskArn=task_arn))
        rejected("cancel_missing_tag_sync", {"NotFoundException"}, lambda: rg.cancel_tag_sync_task(TaskArn=task_arn))
        require(rg.list_tag_sync_tasks(Filters=[{"GroupArn": group}])["TagSyncTasks"] == [], "phantom task listed")
        rejected("ordinary_group_cannot_sync", {"BadRequestException"}, lambda: rg.start_tag_sync_task(Group=group, RoleArn=role_arn, TagKey="workflow", TagValue=name))
        require(rg.get_account_settings()["AccountSettings"]["GroupLifecycleEventsStatus"] == "INACTIVE", "phantom lifecycle activation")
        rg.update_account_settings(GroupLifecycleEventsDesiredStatus="ACTIVE")
        advance(1)
        require(rg.get_account_settings()["AccountSettings"]["GroupLifecycleEventsStatus"] == "ACTIVE", "lifecycle capture did not activate")
        require(rg.update_account_settings(GroupLifecycleEventsDesiredStatus="INACTIVE")["AccountSettings"]["GroupLifecycleEventsStatus"] == "INACTIVE", "inactive setting changed")
        # Lifecycle's real IAM service sessions expire one hour after issuance.
        advance(3601)
        deletion = iam.delete_service_linked_role(RoleName="AWSServiceRoleForResourceGroups")["DeletionTaskId"]
        advance(10)
        require(iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion)["Status"] == "SUCCEEDED", "disabled lifecycle retained role usage")
        specialized = json.loads((Path(__file__).resolve().parents[2] / "testdata/aws/resourcegroups/native.json").read_text())
        for row in specialized["observations"]:
            if row["case"] in ("capacity-pool", "network-instance"):
                require(row["code"] == "Success", "dependency boundary must use a natively admissible request")
                request = dict(row["input"])
                request["Name"] = name + "-" + row["case"]
                request["Tags"] = {"workflow": name}
                rejected(row["case"] + "_dependency_boundary", {"NotImplementedException"}, lambda: rg.create_group(**request))
                rejected(row["case"] + "_not_persisted", {"NotFoundException"}, lambda: rg.get_group(Group=request["Name"]))
        rg.delete_group(Group=group)
        rejected("deleted_group", {"NotFoundException"}, lambda: rg.get_group(Group=group))
        events, token = [], None
        trail = client("cloudtrail")
        while True:
            request = {"LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": "resource-groups.amazonaws.com"}], "MaxResults": 50}
            if token:
                request["NextToken"] = token
            page = trail.lookup_events(**request)
            events.extend(json.loads(row["CloudTrailEvent"]) for row in page["Events"])
            token = page.get("NextToken")
            if not token:
                break
        expected_actions = {"CreateGroup", "DeleteGroup", "GetGroup", "GetGroupQuery", "UpdateGroup", "UpdateGroupQuery", "ListGroups", "SearchResources", "ListGroupResources", "Tag", "Untag", "GetTags", "GetGroupConfiguration", "PutGroupConfiguration", "GroupResources", "UngroupResources", "ListGroupingStatuses", "GetAccountSettings", "UpdateAccountSettings", "StartTagSyncTask", "GetTagSyncTask", "CancelTagSyncTask", "ListTagSyncTasks"}
        require({event["eventName"] for event in events} == expected_actions, "missing Resource Groups API history")
        for event in events:
            read_only = event["eventName"].startswith(("Get", "List")) or event["eventName"] == "SearchResources"
            require(event["eventSource"] == "resource-groups.amazonaws.com" and event["eventCategory"] == "Management" and event["eventType"] == "AwsApiCall" and event["managementEvent"] and event["readOnly"] == read_only, "native event classification mismatch")
            require("errorMessage" not in event, "native errors omit errorMessage")
            require(event.get("responseElements") is None if read_only else event.get("responseElements") is not None, "native read/write response projection mismatch")
            if event.get("errorCode") and not read_only:
                require(isinstance(event["responseElements"]["Message"], str), "failed mutation omitted native Message")
            if event["eventName"] in ("CreateGroup", "UpdateGroup", "DeleteGroup") and not event.get("errorCode"):
                require(event["responseElements"]["Group"]["OwnerId"] == account, "native group audit owner missing")
            if event["eventName"] in ("GetGroup", "GetGroupQuery", "GetGroupConfiguration", "ListGroupResources"):
                reference = event["requestParameters"]["Group"]
                resource = reference if reference.startswith("arn:") else f"arn:aws:resource-groups:us-east-1:{account}:group/{reference}"
                require(event["resources"][0] == {"accountId": account, "type": "AWS::ResourceGroups::Group", "ARN": resource}, "native group event resource mismatch")
            else:
                require("resources" not in event, "invented native event resources")
            if event["eventName"] in ("Tag", "Untag", "GetTags"):
                require(event["requestParameters"]["Arn"].startswith("arn%3Aaws%3Aresource-groups%3A"), "native tag audit label was not encoded")
        report["observations"]["native_audit_projection"] = {"actions": sorted(expected_actions), "events": len(events), "examples": [{key: event[key] for key in ("eventName", "eventSource", "requestParameters", "responseElements", "resources", "errorCode", "requestID", "eventID") if key in event} for event in events if event["eventName"] in ("CreateGroup", "UpdateGroup", "GetGroup", "GetTags")]}
        group = None
        report["complete"] = True
    finally:
        try:
            if process.process is not None and process.process.poll() is None:
                def cleanup(label, fn):
                    try:
                        fn()
                        report["cleanup"].append({"resource": label, "code": "Success"})
                    except ClientError as error:
                        report["cleanup"].append({"resource": label, "code": error.response["Error"]["Code"]})
                for target in (group, stack_group):
                    if target:
                        cleanup(target, lambda target=target: rg.delete_group(Group=target))
                if stack:
                    cleanup(stack, lambda: cfn.delete_stack(StackName=stack))
                    settle(stack, "DELETE_COMPLETE")
                for q in sorted(queue_names):
                    cleanup(q, lambda q=q: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=q)["QueueUrl"]))
                if bucket_created:
                    cleanup(bucket + "/actual.txt", lambda: s3.delete_object(Bucket=bucket, Key="actual.txt"))
                    cleanup(bucket, lambda: s3.delete_bucket(Bucket=bucket))
                if role_arn:
                    cleanup(role + "/read-current", lambda: iam.delete_role_policy(RoleName=role, PolicyName="read-current"))
                    cleanup(role, lambda: iam.delete_role(RoleName=role))
                require(rg.list_groups()["Groups"] == [], "owned groups retained")
                require(sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", []) == [], "owned queues retained")
                require(not any(b["Name"] == bucket for b in s3.list_buckets().get("Buckets", [])), "owned bucket retained")
                report["cleanup_verified"] = True
        finally:
            process.stop()
            save()
    print(json.dumps({"report": str(state / "report.json"), "complete": report.get("complete", False), "cleanup_verified": report.get("cleanup_verified", False), "controllers": process.runs}))


if __name__ == "__main__":
    main()
