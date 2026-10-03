#!/usr/bin/env python3
"""Local-only retained Resource Groups synchronization and lifecycle smoke.

Uses actual signed SDKs, IAM roles, SQS owners and EventBridge delivery. Native
positive parity is not claimed: the retained AWS account cannot create apps.
"""
import argparse
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


def require(value, message):
    if not value:
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
    report = {"evidence_scope": "Local documented semantics, not successful native parity",
              "controllers": process.runs, "observations": {}, "events": []}
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=30)

    def client(service, credentials=None):
        credentials = credentials or {"AccessKeyId": "test", "SecretAccessKey": "test"}
        return boto3.client(service, endpoint_url=endpoint, region_name="us-east-1",
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials.get("SessionToken"), config=config)

    ar, rg, sqs, iam, sts, events = (client(s) for s in
        ("servicecatalog-appregistry", "resource-groups", "sqs", "iam", "sts", "events"))

    def advance(seconds=1):
        for path, body in (("/_stackd/clock", {"advance": f"{seconds}s"}),
                           ("/_stackd/jobs/drain?limit=1024", {})):
            request = urllib.request.Request(endpoint + path, data=json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=60) as response:
                json.load(response)

    def rejected(label, codes, fn):
        try:
            fn()
        except ClientError as error:
            require(error.response["Error"]["Code"] in codes, f"{label}: {error}")
            report["observations"][label] = error.response["Error"]
            return
        raise AssertionError(label + " unexpectedly succeeded")

    prefix = "rg-sync-" + uuid.uuid4().hex[:10]
    tasks, applications, groups, roles, queues = [], [], [], [], {}
    rule = None
    lifecycle_enabled = False
    all_events = []

    def queue(name, source=True):
        tags = {"keep": "unchanged"}
        if source:
            tags["project"] = ""
        url = sqs.create_queue(QueueName=name, tags=tags)["QueueUrl"]
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        queues[name] = url
        return url, arn

    def tags(url):
        return sqs.list_queue_tags(QueueUrl=url).get("Tags", {})

    def grouped(group, resource):
        out = rg.group_resources(Group=group, ResourceArns=[resource])
        require(out.get("Succeeded") == [resource] and not out.get("Failed"), str(out))

    def task_status(task, wanted):
        out = rg.get_tag_sync_task(TaskArn=task)
        require(out["Status"] == wanted, str(out))
        if wanted == "ERROR":
            require(bool(out.get("ErrorMessage")), "task error has no explanation")
        report["observations"]["task_" + wanted] = out

    def receive_events():
        for _ in range(100):
            messages = sqs.receive_message(QueueUrl=event_url, MaxNumberOfMessages=10).get("Messages", [])
            if not messages:
                break
            for message in messages:
                event = json.loads(message["Body"])
                all_events.append(event)
                sqs.delete_message(QueueUrl=event_url, ReceiptHandle=message["ReceiptHandle"])
        else:
            raise AssertionError("lifecycle event queue did not drain")
        return all_events

    def wait_event(predicate, description):
        for _ in range(10):
            advance()
            for event in receive_events():
                if predicate(event):
                    return event
        raise AssertionError(description)

    try:
        process.start(command, endpoint, environment=environment)
        account = sts.get_caller_identity()["Account"]
        for name in (prefix + "-a", prefix + "-b"):
            app = ar.create_application(name=name, clientToken=uuid.uuid4().hex)["application"]["arn"]
            applications.append(app)
        group, other_group = [ar.get_application(application=a)["integrations"]["applicationTagResourceGroup"]["arn"] for a in applications]
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "resource-groups.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role_name = prefix + "-tagging"
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        roles.append(role_name)
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["resource-groups:GroupResources", "resource-groups:UngroupResources", "tag:GetResources", "tag:TagResources", "tag:UntagResources", "sqs:TagQueue", "sqs:UntagQueue"], "Resource": "*"}]}
        iam.put_role_policy(RoleName=role_name, PolicyName="Tagging", PolicyDocument=json.dumps(policy))
        caller_name = prefix + "-caller"
        caller_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}]}
        caller_role = iam.create_role(RoleName=caller_name, AssumeRolePolicyDocument=json.dumps(caller_trust))["Role"]["Arn"]
        roles.append(caller_name)
        iam.put_role_policy(RoleName=caller_name, PolicyName="Caller", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "resource-groups:*", "Resource": "*"}]}))
        credentials = sts.assume_role(RoleArn=caller_role, RoleSessionName="admission")["Credentials"]
        caller_rg = client("resource-groups", credentials)
        rejected("pass_role_denied", {"AccessDenied", "AccessDeniedException", "ForbiddenException"}, lambda: caller_rg.start_tag_sync_task(Group=group, RoleArn=role, TagKey="project", TagValue=""))
        query = {"Type": "TAG_FILTERS_1_0", "Query": json.dumps({"ResourceTypeFilters": ["AWS::SQS::Queue"], "TagFilters": [{"Key": "project", "Values": [""]}]})}
        rejected("exclusive_selector", {"BadRequestException"}, lambda: rg.start_tag_sync_task(Group=group, RoleArn=role, TagKey="project", TagValue="", ResourceQuery=query))
        rejected("incomplete_pair", {"BadRequestException"}, lambda: rg.start_tag_sync_task(Group=group, RoleArn=role, TagKey="project"))
        q1, arn1 = queue(prefix + "-one")
        task = rg.start_tag_sync_task(Group=group, RoleArn=role, TagKey="project", TagValue="")["TaskArn"]
        tasks.append(task)
        advance()
        require(tags(q1) == {"keep": "unchanged", "project": "", "awsApplication": group}, "source selection did not apply real owner tag")
        sqs.untag_queue(QueueUrl=q1, TagKeys=["project"])
        advance()
        require(tags(q1) == {"keep": "unchanged"}, "source removal did not remove only task-owned tag")
        sqs.tag_queue(QueueUrl=q1, Tags={"project": ""})
        advance()
        denied_policy = dict(policy)
        denied_policy["Statement"] = policy["Statement"] + [{"Effect": "Deny", "Action": "sqs:TagQueue", "Resource": "*"}]
        iam.put_role_policy(RoleName=role_name, PolicyName="Tagging", PolicyDocument=json.dumps(denied_policy))
        q2, arn2 = queue(prefix + "-two")
        advance()
        task_status(task, "ERROR")
        require("awsApplication" not in tags(q2), "denied owner effect committed")
        iam.put_role_policy(RoleName=role_name, PolicyName="Tagging", PolicyDocument=json.dumps(policy))
        advance()
        task_status(task, "ACTIVE")
        require(tags(q2)["awsApplication"] == group, "restored owner rights did not recover")
        bad_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(bad_trust))
        q3, arn3 = queue(prefix + "-three")
        advance()
        task_status(task, "ERROR")
        require("awsApplication" not in tags(q3), "revoked trust reused cached authority")
        iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(trust))
        advance()
        require(tags(q3)["awsApplication"] == group, "restored trust did not recover")
        grouped(group, arn1)
        grouped(other_group, arn2)
        sqs.untag_queue(QueueUrl=q1, TagKeys=["project"])
        sqs.untag_queue(QueueUrl=q2, TagKeys=["project"])
        advance()
        require(tags(q1)["awsApplication"] == group, "task stripped reasserted direct membership")
        require(tags(q2)["awsApplication"] == other_group, "task stripped reassigned membership")
        sqs.delete_queue(QueueUrl=q3)
        queues.pop(prefix + "-three")
        advance(61)
        q3, recreated_arn = queue(prefix + "-three", source=False)
        require(recreated_arn == arn3, "expected ARN reuse")
        advance()
        require("awsApplication" not in tags(q3), "old task ownership resurrected a replacement")
        process.stop()
        process.start(command, endpoint, environment=environment)
        retained = rg.get_tag_sync_task(TaskArn=task)
        require(retained["TagKey"] == "project" and retained["TagValue"] == "", "selector lost across process restart")
        sqs.tag_queue(QueueUrl=q3, Tags={"project": ""})
        advance()
        require(tags(q3)["awsApplication"] == group, "replacement not selected by current source after restart")
        rg.cancel_tag_sync_task(TaskArn=task)
        tasks.remove(task)
        sqs.untag_queue(QueueUrl=q3, TagKeys=["project"])
        advance()
        require(tags(q3)["awsApplication"] == group, "cancel removed tags instead of stopping future effects")
        rejected("cancelled_task_missing", {"NotFoundException"}, lambda: rg.get_tag_sync_task(TaskArn=task))
        require(not rg.list_tag_sync_tasks()["TagSyncTasks"], "cancelled task still listed")
        # Retain the original ResourceQuery spelling and selector form too.
        query_task = rg.start_tag_sync_task(Group=group, RoleArn=role, ResourceQuery=query)["TaskArn"]
        tasks.append(query_task)
        require(rg.get_tag_sync_task(TaskArn=query_task)["ResourceQuery"] == query, "source query was replaced by target application query")
        rg.cancel_tag_sync_task(TaskArn=query_task)
        tasks.remove(query_task)

        event_url, event_arn = queue(prefix + "-events", source=False)
        rule_name = prefix + "-lifecycle"
        rule = events.put_rule(Name=rule_name, EventPattern=json.dumps({"source": ["aws.resource-groups"]}))["RuleArn"]
        sqs.set_queue_attributes(QueueUrl=event_url, Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": event_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule}}}]})})
        require(events.put_targets(Rule=rule_name, Targets=[{"Id": "queue", "Arn": event_arn}])["FailedEntryCount"] == 0, "event target admission failed")
        rg.update_account_settings(GroupLifecycleEventsDesiredStatus="ACTIVE")
        lifecycle_enabled = True
        advance()
        require(rg.get_account_settings()["AccountSettings"]["GroupLifecycleEventsStatus"] == "ACTIVE", "lifecycle scan failed activation")
        iam.get_role(RoleName="AWSServiceRoleForResourceGroups")
        deletion = iam.delete_service_linked_role(RoleName="AWSServiceRoleForResourceGroups")["DeletionTaskId"]
        advance(10)
        refused = iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion)
        report["observations"]["active_lifecycle_role_deletion"] = refused
        require(refused["Status"] == "FAILED", "active lifecycle did not fence SLR deletion")
        sqs.tag_queue(QueueUrl=q3, Tags={"project": ""})
        ordinary = rg.create_group(Name=prefix + "-query", ResourceQuery=query)["Group"]["GroupArn"]
        groups.append(ordinary)
        created = wait_event(lambda e: e["detail-type"] == "ResourceGroups Group State Change" and e["detail"].get("state-change") == "create" and e["detail"]["group"]["arn"] == ordinary, "group create event not delivered to SQS")
        original_id = created["detail"]["group"]["unique-id"]
        require(uuid.UUID(original_id), "group lifecycle identity is not a UUID")
        added = wait_event(lambda e: e["detail-type"] == "ResourceGroups Group Membership Change" and e["detail"]["group"]["arn"] == ordinary and any(r["arn"] == arn3 and r["membership-change"] == "add" for r in e["detail"]["resources"]), "query member add event missing")
        rg.update_group(Group=ordinary, Description="changed")
        wait_event(lambda e: e["detail-type"] == "ResourceGroups Group State Change" and e["detail"].get("new-state", {}).get("description") == "changed", "description update event missing")
        process.stop()
        process.start(command, endpoint, environment=environment)
        sqs.untag_queue(QueueUrl=q3, TagKeys=["project"])
        removed = wait_event(lambda e: e["detail-type"] == "ResourceGroups Group Membership Change" and e["detail"]["group"]["arn"] == ordinary and any(r["arn"] == arn3 and r["membership-change"] == "remove" for r in e["detail"]["resources"]), "retained query membership removal missing after restart")
        require(removed["detail"]["event-sequence"] > added["detail"]["event-sequence"], "event sequence lost across restart")
        rg.delete_group(Group=ordinary)
        groups.remove(ordinary)
        wait_event(lambda e: e["detail-type"] == "ResourceGroups Group State Change" and e["detail"].get("state-change") == "delete" and e["detail"]["group"]["arn"] == ordinary, "group delete event missing")
        replacement = rg.create_group(Name=prefix + "-query", ResourceQuery=query)["Group"]["GroupArn"]
        groups.append(replacement)
        recreated = wait_event(lambda e: e["detail-type"] == "ResourceGroups Group State Change" and e["detail"].get("state-change") == "create" and e["detail"]["group"]["arn"] == ordinary and e["detail"]["group"]["unique-id"] != original_id, "same-name group replacement reused lifecycle identity")
        require(recreated["detail"]["event-sequence"] == 1, "replacement sequence was not reset")
        report["events"] = all_events
        report["complete"] = True
    finally:
        try:
            if process.process is not None and process.process.poll() is None:
                for task in tasks:
                    rg.cancel_tag_sync_task(TaskArn=task)
                if lifecycle_enabled:
                    rg.update_account_settings(GroupLifecycleEventsDesiredStatus="INACTIVE")
                for group in groups:
                    rg.delete_group(Group=group)
                if rule:
                    events.remove_targets(Rule=rule_name, Ids=["queue"])
                    events.delete_rule(Name=rule_name)
                for name, url in queues.items():
                    sqs.delete_queue(QueueUrl=url)
                for application in applications:
                    ar.delete_application(application=application)
                for name in roles:
                    for policy_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
                        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
                    iam.delete_role(RoleName=name)
                # Actual service assumptions last one hour. Disabling the
                # scanner stops new sessions but does not revoke issued ones.
                advance(3601)
                for name in ("AWSServiceRoleForResourceGroups", "AWSServiceRoleForAWSServiceCatalogAppRegistry"):
                    try:
                        deletion = iam.delete_service_linked_role(RoleName=name)["DeletionTaskId"]
                    except ClientError as error:
                        if error.response["Error"]["Code"] == "NoSuchEntity":
                            continue
                        raise
                    advance(10)
                    deleted = iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion)
                    report["observations"]["expired_session_cleanup_" + name] = deleted
                    require(deleted["Status"] == "SUCCEEDED", "unused service role deletion did not finish")
                require(not rg.list_tag_sync_tasks()["TagSyncTasks"], "task cleanup incomplete")
                require(rg.get_account_settings()["AccountSettings"]["GroupLifecycleEventsStatus"] == "INACTIVE", "lifecycle cleanup incomplete")
                report["cleanup_verified"] = True
        finally:
            try:
                process.stop()
            finally:
                (state / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps({"report": str(state / "report.json"), "complete": report.get("complete", False), "cleanup_verified": report.get("cleanup_verified", False)}))


if __name__ == "__main__":
    main()
