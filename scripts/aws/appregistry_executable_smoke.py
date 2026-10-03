#!/usr/bin/env python3
"""Local-only AppRegistry/owner workflow through signed SDKs and the real CLI.

Positive behavior follows the AWS contracts in testdata/aws/appregistry/
native-contracts.json; native creation was denied by new-customer maintenance
mode. This workflow does not claim successful native AppRegistry parity.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import socket
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from stackd_process import StackdProcess


DENIED = {"AccessDenied", "AccessDeniedException", "ForbiddenException"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
    environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                       AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true")
    process = StackdProcess(state)
    command = [str(Path(args.binary).resolve()), "-listen", f"127.0.0.1:{port}",
               "-public-endpoint", endpoint, "-database", str(state / "state.sqlite"),
               "-clock-start", "2026-09-28T12:00:00Z"]
    report = {"endpoint": endpoint, "controllers": process.runs, "observations": {},
              "cleanup": [], "evidence_scope": "Local documented positive workflow; native fixtures establish errors only, not positive parity."}
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=5,
                    read_timeout=30, s3={"addressing_style": "path"})

    def client(service, credentials=None, region="us-east-1"):
        credentials = credentials or {"AccessKeyId": "test", "SecretAccessKey": "test"}
        return boto3.client(service, endpoint_url=endpoint, region_name=region,
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials.get("SessionToken"), config=config)

    ar, rg, s3, sqs, ssm, cfn, iam, sts, trail = (client(s) for s in
        ("servicecatalog-appregistry", "resource-groups", "s3", "sqs", "ssm",
         "cloudformation", "iam", "sts", "cloudtrail"))

    def control(path, body=None):
        request = urllib.request.Request(endpoint + path, data=json.dumps(body or {}).encode(),
                                         headers={"Content-Type": "application/json"})
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
            observation = {"code": error.response["Error"]["Code"],
                           "request_id": error.response["ResponseMetadata"].get("RequestId")}
            report["observations"][label] = observation
            return observation
        raise AssertionError(label + " unexpectedly succeeded")

    def members(group):
        found, token = [], None
        for _ in range(100):
            request = {"Group": group, "MaxResults": 1}
            if token:
                request["NextToken"] = token
            out = rg.list_group_resources(**request)
            found.extend(row["ResourceArn"] for row in out.get("ResourceIdentifiers", []))
            token = out.get("NextToken")
            if not token:
                return sorted(found)
        raise AssertionError("membership pagination did not terminate")

    def statuses(group):
        found, token = {}, None
        for _ in range(100):
            request = {"Group": group, "MaxResults": 1}
            if token:
                request["NextToken"] = token
            out = rg.list_grouping_statuses(**request)
            for row in out.get("GroupingStatuses", []):
                require(row["ResourceArn"] not in found, "duplicate latest grouping status")
                found[row["ResourceArn"]] = row
            token = out.get("NextToken")
            if not token:
                return found
        raise AssertionError("status pagination did not terminate")

    def settle(stack, wanted):
        for _ in range(60):
            advance(1)
            out = cfn.describe_stacks(StackName=stack)["Stacks"][0]
            if out["StackStatus"] == wanted:
                return out
            require(not out["StackStatus"].endswith("FAILED"), str(out))
        raise TimeoutError("CloudFormation " + wanted)

    def tags(arn):
        if arn.startswith("arn:aws:s3:::"):
            try:
                return {row["Key"]: row["Value"] for row in s3.get_bucket_tagging(Bucket=arn.split(":::", 1)[1])["TagSet"]}
            except ClientError as error:
                if error.response["Error"]["Code"] == "NoSuchTagSet":
                    return {}
                raise
        if ":sqs:" in arn:
            url = sqs.get_queue_url(QueueName=arn.rsplit(":", 1)[1])["QueueUrl"]
            return sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        if ":cloudformation:" in arn:
            return {row["Key"]: row["Value"] for row in cfn.describe_stacks(StackName=arn)["Stacks"][0].get("Tags", [])}
        return {row["Key"]: row["Value"] for row in ssm.list_tags_for_resource(
            ResourceType="Parameter", ResourceId=arn.split(":parameter", 1)[1])["TagList"]}

    def group_result(operation, group, resources):
        out = operation(Group=group, ResourceArns=resources)
        pending = [row["ResourceArn"] for row in out.get("Pending", [])]
        require(sorted(out.get("Succeeded", []) + pending) == sorted(resources) and not out.get("Failed"), str(out))
        for _ in range(60):
            if not pending:
                break
            advance(1)
            current = statuses(group)
            require(all(current[arn]["Status"] in {"SUCCESS", "IN_PROGRESS"} for arn in pending), str(current))
            pending = [arn for arn in pending if current[arn]["Status"] != "SUCCESS"]
        require(not pending, "admitted grouping failed to reach its owner")
        return out

    def delete_application(application_arn):
        # Only enumerate links of this exact application in the fresh local DB.
        # Removing links before deletion is an AWS API precondition.
        for _ in range(100):
            resources = ar.list_associated_resources(application=application_arn).get("resources", [])
            if not resources:
                break
            for resource in resources:
                ar.disassociate_resource(application=application_arn, resourceType=resource["resourceType"], resource=resource["arn"])
                if resource["resourceType"] == "CFN_STACK" and resource.get("options") == ["APPLY_APPLICATION_TAG"]:
                    settle(resource["arn"], "UPDATE_COMPLETE")
        else:
            raise AssertionError("resource associations did not drain during cleanup")
        for _ in range(100):
            links = ar.list_associated_attribute_groups(application=application_arn).get("attributeGroups", [])
            if not links:
                break
            for link in links:
                ar.disassociate_attribute_group(application=application_arn, attributeGroup=link)
        else:
            raise AssertionError("attribute associations did not drain during cleanup")
        group = ar.get_application(application=application_arn)["integrations"]["applicationTagResourceGroup"]["arn"]
        remaining = members(group)
        for offset in range(0, len(remaining), 10):
            group_result(rg.ungroup_resources, group, remaining[offset:offset + 10])
        ar.delete_application(application=application_arn)

    name = "appregistry-cli-" + uuid.uuid4().hex[:10]
    bucket, log_bucket, queue_name, parameter = name + "-bucket", name + "-logs", name + "-queue", "/" + name + "/parameter"
    role_name, trail_name = name + "-role", name + "-trail"
    linked_role = "AWSServiceRoleForAWSServiceCatalogAppRegistry"
    applications, attributes, stacks, managed_groups = [], [], [], []
    buckets, queues, parameters = set(), set(), set()
    role_created = trail_created = False
    app_tag = None
    try:
        process.start(command, endpoint, environment=environment)
        account = sts.get_caller_identity()["Account"]
        for owned_bucket in (bucket, log_bucket):
            s3.create_bucket(Bucket=owned_bucket)
            buckets.add(owned_bucket)
        trail_arn = f"arn:aws:cloudtrail:us-east-1:{account}:trail/{trail_name}"
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::" + log_bucket,
             "Condition": {"StringEquals": {"aws:SourceArn": trail_arn, "aws:SourceAccount": account}}},
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{log_bucket}/AWSLogs/{account}/*",
             "Condition": {"StringEquals": {"aws:SourceArn": trail_arn, "aws:SourceAccount": account,
                                            "s3:x-amz-acl": "bucket-owner-full-control"}}}]}
        s3.put_bucket_policy(Bucket=log_bucket, Policy=json.dumps(policy))
        trail.create_trail(Name=trail_name, S3BucketName=log_bucket)
        trail_created = True
        trail.put_event_selectors(TrailName=trail_name, EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}])
        trail.start_logging(Name=trail_name)

        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "workflow", "Value": name}]})
        s3.put_object(Bucket=bucket, Key="actual.txt", Body=b"AppRegistry actual owner bytes")
        queue_url = sqs.create_queue(QueueName=queue_name, tags={"workflow": name})["QueueUrl"]
        queues.add(queue_name)
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        ssm.put_parameter(Name=parameter, Value="actual owner value", Type="String", Tags=[{"Key": "workflow", "Value": name}])
        parameters.add(parameter)
        direct = ["arn:aws:s3:::" + bucket, queue_arn, f"arn:aws:ssm:us-east-1:{account}:parameter{parameter}"]
        application = ar.create_application(name=name, description="before update", clientToken=uuid.uuid4().hex,
                                            tags={"workflow": name})["application"]
        app = application["arn"]
        applications.append(app)
        attribute = ar.create_attribute_group(name=name + "-attributes", attributes='{"owner":"workflow","revision":1}',
                                              clientToken=uuid.uuid4().hex)["attributeGroup"]
        attr = attribute["arn"]
        attributes.append(attr)
        ar.associate_attribute_group(application=app, attributeGroup=attr)
        require(ar.list_associated_attribute_groups(application=application["id"])["attributeGroups"] == [attribute["id"]], "attribute association missing")
        require(ar.list_attribute_groups_for_application(application=name)["attributeGroupsDetails"][0]["arn"] == attr, "attribute details reference differs")
        ar.update_attribute_group(attributeGroup=attr, attributes='{"owner":"workflow","revision":2}')
        ar.update_application(application=app, description="retained description")
        ar.tag_resource(resourceArn=app, tags={"control": "current"})
        require(ar.list_tags_for_resource(resourceArn=app)["tags"]["control"] == "current", "AppRegistry tags missing")
        ar.untag_resource(resourceArn=app, tagKeys=["control"])
        got = ar.get_application(application=app)
        legacy, modern = (got["integrations"][key]["arn"] for key in ("resourceGroup", "applicationTagResourceGroup"))
        managed_groups.extend([legacy, modern])
        app_tag = got["applicationTag"]
        require(app_tag == {"awsApplication": modern} and legacy != modern and modern != app, "distinct application/group identities were conflated")
        for group in (legacy, modern):
            rejected("managed_configuration_" + ("legacy" if group == legacy else "modern"), {"ForbiddenException"},
                     lambda group=group: rg.put_group_configuration(Group=group, Configuration=[{"Type": "AWS::ResourceGroups::Generic"}]))
        rejected("managed_delete", {"ForbiddenException"}, lambda: rg.delete_group(Group=legacy))
        rejected("managed_update", {"ForbiddenException"}, lambda: rg.update_group(Group=legacy, Description="illegal"))
        rejected("managed_create", {"ForbiddenException"}, lambda: rg.create_group(Name=name + "-forged", Configuration=[{"Type": "AWS::AppRegistry::Application"}]))
        modern_attributes = {"DisplayName": "Owned application", "Owner": "offline-owner", "Criticality": 3}
        updated_group = rg.update_group(Group=modern, **modern_attributes)["Group"]
        require(all(updated_group[key] == expected for key, expected in modern_attributes.items()), "modern application attributes not updated")
        require(any(row["GroupArn"] == modern for row in rg.list_groups(
            Filters=[{"Name": "owner", "Values": ["offline-owner"]}, {"Name": "criticality", "Values": ["3"]}])["GroupIdentifiers"]),
            "application attribute filters ignored current values")
        ar.put_configuration(configuration={"tagQueryConfiguration": {"tagKey": "workflow"}})
        selected = ar.associate_resource(application=app, resourceType="RESOURCE_TAG_VALUE", resource=name,
                                         options=["APPLY_APPLICATION_TAG"])
        collection = selected["resourceArn"]
        managed_groups.append(collection)
        require(members(collection) == sorted(direct), "tag-value association did not select actual configured owners")
        require(all(tags(arn).get("awsApplication") == modern for arn in direct), "tag-value APPLY did not reach owners")
        require(ar.get_associated_resource(application=app, resourceType="RESOURCE_TAG_VALUE", resource=name)
                ["applicationTagResult"]["applicationTagStatus"] == "SUCCESS", "tag-value status not owner-backed")
        ar.disassociate_resource(application=app, resourceType="RESOURCE_TAG_VALUE", resource=name)
        require(all(tags(arn) == {"workflow": name} for arn in direct), "tag-value disassociation damaged unrelated tags")
        rejected("deleted_tag_collection", {"NotFoundException"}, lambda: rg.get_group(Group=collection))
        report["observations"]["configured_tag_value"] = {"tagKey": "workflow", "value": name, "owners": direct, "collection": collection}

        template = {"Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": name + "-stack-bucket"}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": name + "-stack-queue"}},
            "Parameter": {"Type": "AWS::SSM::Parameter", "Properties": {"Name": "/" + name + "/stack", "Type": "String", "Value": "stack-owned"}}}}
        buckets.add(name + "-stack-bucket")
        queues.update([name + "-stack-queue", name + "-skip-queue"])
        parameters.add("/" + name + "/stack")
        stack = cfn.create_stack(StackName=name + "-apply", TemplateBody=json.dumps(template))["StackId"]
        stacks.append(stack)
        settle(stack, "CREATE_COMPLETE")
        stack_owners = ["arn:aws:s3:::" + name + "-stack-bucket", f"arn:aws:sqs:us-east-1:{account}:{name}-stack-queue", f"arn:aws:ssm:us-east-1:{account}:parameter/{name}/stack"]
        skip_stack = cfn.create_stack(StackName=name + "-skip", TemplateBody=json.dumps({"Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": name + "-skip-queue"}}}}))["StackId"]
        stacks.append(skip_stack)
        settle(skip_stack, "CREATE_COMPLETE")
        skip_arn = f"arn:aws:sqs:us-east-1:{account}:{name}-skip-queue"
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        role_created = True
        allow = {"Effect": "Allow", "Action": "*", "Resource": "*"}

        def role_policy(deny=None):
            statements = [allow]
            if deny:
                statements.append({"Effect": "Deny", "Action": deny, "Resource": "*"})
            iam.put_role_policy(RoleName=role_name, PolicyName="current", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))

        role_policy("ssm:AddTagsToResource")
        credentials = sts.assume_role(RoleArn=role, RoleSessionName="appregistry-current")["Credentials"]
        actor, actor_groups = client("servicecatalog-appregistry", credentials), client("resource-groups", credentials)
        rejected("apply_owner_denial", DENIED, lambda: actor.associate_resource(application=app, resourceType="CFN_STACK", resource=stack, options=["APPLY_APPLICATION_TAG"]))
        require(ar.list_associated_resources(application=app).get("resources", []) == [], "failed APPLY persisted association")
        require(all("awsApplication" not in tags(arn) for arn in stack_owners), "failed APPLY partially committed owner tags")
        require(members(legacy) == [], "failed APPLY persisted managed stack group")
        role_policy()
        actor.associate_resource(application=app, resourceType="CFN_STACK", resource=stack, options=["APPLY_APPLICATION_TAG"])
        admitted = ar.get_associated_resource(application=app, resourceType="CFN_STACK", resource=stack)
        require(admitted["applicationTagResult"]["applicationTagStatus"] in {"IN_PROGRESS", "SUCCESS"}, "APPLY did not report actual admitted owner state")
        settle(stack, "UPDATE_COMPLETE")
        require(all(tags(arn).get("awsApplication") == modern for arn in stack_owners), "APPLY did not reach real owners")
        associated = ar.get_associated_resource(application=app, resourceType="CFN_STACK", resource=stack)
        stack_group = associated["resource"]["integrations"]["resourceGroup"]["arn"]
        managed_groups.append(stack_group)
        require(members(stack_group) == sorted(stack_owners), "stack group differs from deployed resources")
        require(associated["options"] == ["APPLY_APPLICATION_TAG"], "APPLY option not retained")
        require(associated["applicationTagResult"]["applicationTagStatus"] == "SUCCESS", "owner tagging never completed")
        ar.associate_resource(application=app, resourceType="CFN_STACK", resource=skip_stack)
        skipped = ar.get_associated_resource(application=app, resourceType="CFN_STACK", resource=skip_stack)
        managed_groups.append(skipped["resource"]["integrations"]["resourceGroup"]["arn"])
        require(skipped["options"] == ["SKIP_APPLICATION_TAG"] and "awsApplication" not in tags(skip_arn), "omitted option applied a tag")
        report["observations"]["stack_apply_skip_atomicity"] = {"apply": stack, "skip": skip_stack, "owners": stack_owners}

        group_result(rg.group_resources, modern, direct)
        require(all(tags(arn).get("awsApplication") == modern for arn in direct), "direct grouping did not tag current owners")
        query = rg.get_group_query(Group=modern)["GroupQuery"]["ResourceQuery"]
        selected = rg.search_resources(ResourceQuery=query)["ResourceIdentifiers"]
        require(set(direct).issubset({row["ResourceArn"] for row in selected}), "application query ignores current tags")
        current = statuses(modern)
        require(all(current[arn]["Action"] == "GROUP" and current[arn]["Status"] == "SUCCESS" for arn in direct), "grouping status not backed by tags")
        group_result(rg.ungroup_resources, modern, direct)
        require(all(tags(arn) == {"workflow": name} for arn in direct), "ungroup changed unrelated owner tags")
        current = statuses(modern)
        require(all(current[arn]["Action"] == "UNGROUP" and current[arn]["Status"] == "SUCCESS" for arn in direct), "ungroup status did not replace last action")
        role_policy("sqs:TagQueue")
        denied = actor_groups.group_resources(Group=modern, ResourceArns=[queue_arn])
        require(not denied.get("Succeeded") and not denied.get("Pending") and len(denied.get("Failed", [])) == 1
                and denied["Failed"][0]["ResourceArn"] == queue_arn, "owner denial must be per-resource failure")
        require("awsApplication" not in tags(queue_arn), "denied direct grouping mutated owner")
        failed_status = statuses(modern)[queue_arn]
        require(failed_status["Action"] == "GROUP" and failed_status["Status"] == "FAILED" and failed_status.get("ErrorCode"),
                "failed latest grouping was hidden by prior success")
        role_policy("servicecatalog:GetApplication")
        rejected("current_role_revocation", DENIED, lambda: actor.get_application(application=app))
        role_policy()
        require(actor.get_application(application=app)["id"] == application["id"], "same-session IAM recovery failed")
        group_result(actor_groups.group_resources, modern, direct)
        require(s3.get_object(Bucket=bucket, Key="actual.txt")["Body"].read() == b"AppRegistry actual owner bytes", "S3 bytes changed")
        sqs.send_message(QueueUrl=queue_url, MessageBody="actual application owner")
        require(sqs.receive_message(QueueUrl=queue_url)["Messages"][0]["Body"] == "actual application owner", "SQS data plane failed")
        require(ssm.get_parameter(Name=parameter)["Parameter"]["Value"] == "actual owner value", "SSM value changed")
        report["observations"]["current_owner_grouping"] = {"resources": direct, "query": query, "statuses": statuses(modern)}

        process.stop()
        process.start(command, endpoint, environment=environment)
        require(ar.get_application(application=name)["description"] == "retained description", "SQLite lost application")
        require(json.loads(ar.get_attribute_group(attributeGroup=attr)["attributes"])["revision"] == 2, "SQLite lost attribute update")
        require(ar.list_associated_attribute_groups(application=app)["attributeGroups"] == [attribute["id"]], "SQLite lost attribute association")
        require({row["arn"] for row in ar.list_associated_resources(application=app)["resources"]} == {stack, skip_stack}, "SQLite lost resource associations")
        require(set(direct).issubset(members(modern)), "SQLite lost current membership")
        require(all(statuses(modern)[arn]["Status"] == "SUCCESS" for arn in direct), "SQLite lost grouping results")
        retained_group = rg.get_group(Group=modern)["Group"]
        require(all(retained_group[key] == expected for key, expected in modern_attributes.items()), "SQLite lost modern application metadata")
        require(ar.get_configuration()["configuration"] == {"tagQueryConfiguration": {"tagKey": "workflow"}}, "SQLite lost tag query configuration")
        report["observations"]["sqlite_restart"] = {"application": app, "members": members(modern)}

        s3.delete_object(Bucket=bucket, Key="actual.txt")
        s3.delete_bucket(Bucket=bucket)
        sqs.delete_queue(QueueUrl=queue_url)
        ssm.delete_parameter(Name=parameter)
        advance(61)
        s3.create_bucket(Bucket=bucket)
        queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        ssm.put_parameter(Name=parameter, Value="replacement", Type="String")
        require(not set(direct).intersection(members(modern)), "recreated owner inherited old membership")
        require(not set(direct).intersection(statuses(modern)), "recreated owner inherited successful old status")
        require(all("awsApplication" not in tags(arn) for arn in direct), "recreated owner inherited old application tag")
        group_result(rg.group_resources, modern, direct)
        rejected("nonempty_application_deletion", {"ConflictException"}, lambda: ar.delete_application(application=app))
        group_result(rg.ungroup_resources, modern, direct)
        ar.disassociate_resource(application=app, resourceType="CFN_STACK", resource=stack)
        settle(stack, "UPDATE_COMPLETE")
        ar.disassociate_resource(application=app, resourceType="CFN_STACK", resource=skip_stack)
        ar.disassociate_attribute_group(application=app, attributeGroup=attr)
        require(all("awsApplication" not in tags(arn) for arn in direct + stack_owners), "explicit disassociation left application tags")
        ar.delete_application(application=app)
        applications.remove(app)
        for owned_group in managed_groups:
            rejected("deleted_group_" + owned_group.rsplit("/", 1)[-1], {"NotFoundException"}, lambda owned_group=owned_group: rg.get_group(Group=owned_group))
        require(ssm.get_parameter(Name=parameter)["Parameter"]["Value"] == "replacement", "empty application deletion removed customer owner")
        replacement = ar.create_application(name=name, clientToken=uuid.uuid4().hex)["application"]
        applications.append(replacement["arn"])
        new_app = ar.get_application(application=name)
        managed_groups.extend([new_app["integrations"][key]["arn"] for key in ("resourceGroup", "applicationTagResourceGroup")])
        require(replacement["id"] != application["id"] and new_app["applicationTag"] != app_tag, "application name reuse inherited identity")
        require(members(new_app["integrations"]["applicationTagResourceGroup"]["arn"]) == [], "new app inherited old membership")
        require(ar.list_associated_attribute_groups(application=replacement["arn"])["attributeGroups"] == [], "new app inherited old attribute links")
        rejected("deleted_application_id", {"ResourceNotFoundException"}, lambda: ar.get_application(application=application["id"]))
        missing_name = name + "-absent"
        missing = rejected("audit_missing_application", {"ResourceNotFoundException"}, lambda: ar.get_application(application=missing_name))
        report["observations"]["identity_fences"] = {"old": app, "new": replacement["arn"], "old_application_tag": app_tag}

        # This exact negative projection is native-calibrated. Successful local
        # mutation delivery is consumed too, but is not called native parity.
        delivered, keys = [], []
        for _ in range(12):
            advance(60)
            delivered, keys = [], []
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=log_bucket):
                for item in page.get("Contents", []):
                    key = item["Key"]
                    if not key.endswith(".json.gz"):
                        continue
                    body = s3.get_object(Bucket=log_bucket, Key=key)["Body"].read()
                    delivered.extend(json.loads(gzip.decompress(body))["Records"])
                    keys.append(key)
            if any(event.get("requestID") == missing["request_id"] for event in delivered):
                break
        matched = [event for event in delivered if event.get("requestID") == missing["request_id"]]
        require(len(matched) == 1, "configured trail did not deliver exact AppRegistry request")
        event = matched[0]
        require(event["eventSource"] == "servicecatalog-appregistry.amazonaws.com" and event["eventName"] == "GetApplication"
                and event["eventCategory"] == "Management" and event["eventType"] == "AwsApiCall"
                and event["managementEvent"] and event["readOnly"], "native error classification differs")
        require(event["requestParameters"] == {"application": missing_name} and event.get("responseElements") is None
                and event["errorCode"] == "ResourceNotFoundException" and "errorMessage" not in event, "native negative projection differs")
        require(event["resources"] == [{"accountId": account, "type": "AWS::ServiceCatalogAppRegistry::Application",
                                      "ARN": f"arn:aws:servicecatalog:us-east-1:{account}:/applications/*"}], "native negative resource projection differs")
        require(any(row.get("eventSource") == event["eventSource"] and row.get("eventName") == "AssociateResource"
                    and not row.get("errorCode") for row in delivered), "local successful association absent from real audit objects")
        report["observations"]["configured_audit_consumer"] = {"keys": keys, "native_negative": event,
                                                                 "positive_scope": "local delivery only"}
        report["complete"] = True
    finally:
        try:
            if process.process is not None and process.process.poll() is None:
                failures = []

                def cleanup(label, fn, absent=()):
                    try:
                        fn()
                        report["cleanup"].append({"resource": label, "code": "Success"})
                    except Exception as error:
                        code = error.response["Error"]["Code"] if isinstance(error, ClientError) else type(error).__name__
                        report["cleanup"].append({"resource": label, "code": code})
                        if code not in absent:
                            failures.append(label + ": " + str(error))

                if trail_created:
                    cleanup(trail_name + " stop", lambda: trail.stop_logging(Name=trail_name))
                    cleanup(trail_name, lambda: trail.delete_trail(Name=trail_name))
                for application_arn in applications:
                    cleanup(application_arn, lambda application_arn=application_arn: delete_application(application_arn), ("ResourceNotFoundException",))
                for attribute_arn in attributes:
                    cleanup(attribute_arn, lambda attribute_arn=attribute_arn: ar.delete_attribute_group(attributeGroup=attribute_arn), ("ResourceNotFoundException",))
                cleanup("tag query configuration", lambda: ar.put_configuration(configuration={"tagQueryConfiguration": {}}))
                def delete_linked_role():
                    # Existing service-role sessions remain real IAM dependencies.
                    # No new application operation can assume the role after cleanup.
                    advance(3601)
                    task = iam.delete_service_linked_role(RoleName=linked_role)["DeletionTaskId"]
                    for _ in range(60):
                        advance(1)
                        status = iam.get_service_linked_role_deletion_status(DeletionTaskId=task)
                        if status["Status"] == "SUCCEEDED":
                            return
                        require(status["Status"] != "FAILED", str(status))
                    raise TimeoutError("AppRegistry service-linked role deletion")
                cleanup(linked_role, delete_linked_role, ("NoSuchEntity",))
                for stack_arn in reversed(stacks):
                    def delete_stack(stack_arn=stack_arn):
                        cfn.delete_stack(StackName=stack_arn)
                        settle(stack_arn, "DELETE_COMPLETE")
                    cleanup(stack_arn, delete_stack)
                for queue in queues:
                    cleanup(queue, lambda queue=queue: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=queue)["QueueUrl"]), ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
                for param in parameters:
                    cleanup(param, lambda param=param: ssm.delete_parameter(Name=param), ("ParameterNotFound",))
                if role_created:
                    cleanup(role_name + " policy", lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="current"), ("NoSuchEntity",))
                    cleanup(role_name, lambda: iam.delete_role(RoleName=role_name))
                for owned_bucket in buckets:
                    def empty_bucket(owned_bucket=owned_bucket):
                        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=owned_bucket):
                            for item in page.get("Contents", []):
                                s3.delete_object(Bucket=owned_bucket, Key=item["Key"])
                        s3.delete_bucket(Bucket=owned_bucket)
                    cleanup(owned_bucket, empty_bucket, ("NoSuchBucket",))
                for application_arn in applications:
                    cleanup(application_arn + " absent", lambda application_arn=application_arn: rejected("cleanup_application", {"ResourceNotFoundException"}, lambda: ar.get_application(application=application_arn)))
                for attribute_arn in attributes:
                    cleanup(attribute_arn + " absent", lambda attribute_arn=attribute_arn: rejected("cleanup_attribute", {"ResourceNotFoundException"}, lambda: ar.get_attribute_group(attributeGroup=attribute_arn)))
                for queue in queues:
                    cleanup(queue + " absent", lambda queue=queue: rejected("cleanup_queue", {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}, lambda: sqs.get_queue_url(QueueName=queue)))
                for param in parameters:
                    cleanup(param + " absent", lambda param=param: rejected("cleanup_parameter", {"ParameterNotFound"}, lambda: ssm.get_parameter(Name=param)))
                for owned_bucket in buckets:
                    cleanup(owned_bucket + " absent", lambda owned_bucket=owned_bucket: rejected("cleanup_bucket", {"404", "NoSuchBucket", "NotFound"}, lambda: s3.head_bucket(Bucket=owned_bucket)))
                if role_created:
                    cleanup(role_name + " absent", lambda: rejected("cleanup_role", {"NoSuchEntity"}, lambda: iam.get_role(RoleName=role_name)))
                cleanup(linked_role + " absent", lambda: rejected("cleanup_linked_role", {"NoSuchEntity"}, lambda: iam.get_role(RoleName=linked_role)))
                if trail_created:
                    cleanup(trail_name + " absent", lambda: rejected("cleanup_trail", {"TrailNotFoundException"}, lambda: trail.get_trail(Name=trail_name)))
                for owned_group in set(managed_groups):
                    cleanup(owned_group + " absent", lambda owned_group=owned_group: rejected("cleanup_group", {"NotFoundException"}, lambda: rg.get_group(Group=owned_group)))
                report["cleanup_verified"] = not failures
                require(not failures, "cleanup failed: " + "; ".join(failures))
        finally:
            try:
                process.stop()
            finally:
                (state / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps({"report": str(state / "report.json"), "complete": report.get("complete", False),
                      "cleanup_verified": report.get("cleanup_verified", False), "controllers": process.runs}))


if __name__ == "__main__":
    main()
