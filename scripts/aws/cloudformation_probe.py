#!/usr/bin/env python3
"""Capture native CloudFormation lifecycle over unique free, empty resources.

Uses the shared boto ledger and CloudTrail history collector. Never changes an
existing stack, account controls, trails, or paid compute. --cleanup-only resumes
exact-owned deletion from the persisted inventory after interruption.
Executed change sets retained by AWS are identified as immutable deleted-stack
history, never reported absent. --export-update-only and --subscription-only
extend existing evidence; --schemas-only records 16 public registry schemas
without resource effects and resumes an interrupted partial schema capture.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import time
import uuid

import boto3
from botocore.config import Config

from cloudtrail_events import CollectionError, collect_history
from cloudtrail_service_probe import REGION, Probe, document, now


REFERENCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ExecuteChangeSet.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStackEvents.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStacks.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-changesets-view.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-importvalue.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queue.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-api-logging-cloudtrail.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sns-subscription.html",
]


class CloudFormationProbe(Probe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.session = boto3.Session(region_name=REGION)
        config = Config(retries={"total_max_attempts": 1}, connect_timeout=5,
                        read_timeout=30, ignore_configured_endpoint_urls=True)
        self.clients = {name: self.session.client(name, config=config) for name in
                        ("sts", "cloudformation", "sqs", "sns", "iam", "s3", "cloudtrail")}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != self.account:
            raise RuntimeError("Native writes authorized only for account " + self.account)
        if args.cleanup_only or args.audit_only or args.export_update_only or args.subscription_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.account or self.data["region"] != REGION:
                raise RuntimeError("Capture does not belong to the authorized target")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "service": "cloudformation", "source": "native AWS", "account": self.account,
                "region": REGION, "identity": document(identity), "captured_at": now(),
                "prefix": "stackd-cfn-" + uuid.uuid4().hex[:12],
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "sdk": {"boto3": boto3.__version__}, "documentation": REFERENCES,
                "scope": "Unique owned SQS/SNS/IAM/empty S3 stacks; no standing controls or data traffic",
                "bounds": {"stack_wait_seconds": 900, "poll_seconds": 5, "max_calls": 2400,
                           "cloudtrail_rounds": args.trail_rounds, "cloudtrail_pages_per_round": 20},
                "redaction": "Shared credential/IP redaction only; native IDs, errors, list order and timestamps retained",
                "calls": [], "owned": {"stacks": {}, "changesets": [], "resources": []},
                "event_snapshots": {}, "cleanup": {}, "workflow_complete": False,
            }
        self.data["documentation"] = list(dict.fromkeys(self.data["documentation"] + REFERENCES))
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(document(self.data), indent=2)
        for value in (self.credentials.secret_key, self.credentials.token):
            if value:
                text = text.replace(value, "<redacted-credential>")
        self.args.output.write_text(text + "\n")

    def call(self, label, service, operation, parameters=None, **kwargs):
        if len(self.data["calls"]) >= self.data["bounds"]["max_calls"]:
            raise RuntimeError("Bounded native API call limit reached")
        return super().call(label, service, operation, parameters, **kwargs)

    def cfn(self, label, operation, parameters, **kwargs):
        return self.call(label, "cloudformation", operation, parameters, **kwargs)

    def resource(self, kind, name):
        candidate = {"kind": kind, "name": name}
        if candidate not in self.data["owned"]["resources"]:
            self.data["owned"]["resources"].append(candidate)
            self.save()
        return name

    def wait_stack(self, label, stack, terminal):
        deadline = time.monotonic() + self.data["bounds"]["stack_wait_seconds"]
        for attempt in range(181):
            result = self.cfn(label + "-wait-" + str(attempt), "describe_stacks", {"StackName": stack})
            current = result["Stacks"][0]
            status = current["StackStatus"]
            if status in terminal:
                return current
            if not status.endswith("_IN_PROGRESS"):
                raise RuntimeError(label + ": unexpected terminal status " + status)
            if time.monotonic() >= deadline:
                break
            time.sleep(self.data["bounds"]["poll_seconds"])
        raise RuntimeError(label + ": stack observation deadline expired")

    def snapshot(self, label, stack):
        self.cfn(label + "-describe", "describe_stacks", {"StackName": stack})
        self.cfn(label + "-resources", "describe_stack_resources", {"StackName": stack})
        self.cfn(label + "-resource-list", "list_stack_resources", {"StackName": stack})
        token, events = None, []
        for page in range(20):
            request = {"StackName": stack}
            if token:
                request["NextToken"] = token
            result = self.cfn(label + "-events-" + str(page), "describe_stack_events", request)
            events.extend(result["StackEvents"])
            token = result.get("NextToken")
            if not token:
                break
        if token:
            raise RuntimeError("Owned stack event pagination exceeded bounds")
        self.data["event_snapshots"][label] = {
            "order": "Native reverse chronological response order, retained across pagination",
            "event_ids": [event["EventId"] for event in events],
            "transitions": [{key: event[key] for key in ("EventId", "Timestamp", "LogicalResourceId",
                "PhysicalResourceId", "ResourceType", "ResourceStatus", "ResourceStatusReason",
                "ClientRequestToken") if key in event} for event in events],
        }
        self.save()

    def create(self, key, template, *, parameters=None):
        name = self.data["prefix"] + "-" + key
        self.data["owned"]["stacks"][key] = {"name": name}
        self.save()
        request = {"StackName": name, "TemplateBody": json.dumps(template),
                   "ClientRequestToken": self.data["prefix"] + "-create-" + key,
                   "Capabilities": ["CAPABILITY_NAMED_IAM"],
                   "Tags": [{"Key": "stackd-probe", "Value": self.data["prefix"]}]}
        if parameters is not None:
            request["Parameters"] = parameters
        result = self.cfn("create-" + key, "create_stack", request)
        self.data["owned"]["stacks"][key]["id"] = result["StackId"]
        self.save()
        return result["StackId"], request

    def changeset(self, label, stack, template, *, execute=True):
        name = self.data["prefix"] + "-" + label
        request = {"StackName": stack, "ChangeSetName": name, "ChangeSetType": "UPDATE",
                   "TemplateBody": json.dumps(template), "Capabilities": ["CAPABILITY_NAMED_IAM"],
                   "ClientToken": name + "-create"}
        owned = {"name": name, "stack": stack}
        self.data["owned"]["changesets"].append(owned)
        self.save()
        result = self.cfn(label + "-create-changeset", "create_change_set", request)
        owned["id"] = result["Id"]
        self.save()
        if label == "update":
            self.cfn("changeset-token-repeat", "create_change_set", request, required=False)
            conflict = {**request, "Description": "same-token-different-input"}
            self.cfn("changeset-token-conflict", "create_change_set", conflict, required=False)
        for attempt in range(61):
            current = self.cfn(label + "-changeset-wait-" + str(attempt), "describe_change_set",
                               {"ChangeSetName": owned["id"], "IncludePropertyValues": True})
            if current["Status"] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
                break
            time.sleep(5)
        else:
            raise RuntimeError("Changeset observation deadline expired")
        if execute:
            if current["Status"] != "CREATE_COMPLETE":
                raise RuntimeError(label + ": changeset failed: " + current.get("StatusReason", ""))
            execution = {"ChangeSetName": owned["id"], "ClientRequestToken": name + "-execute"}
            self.cfn(label + "-execute-changeset", "execute_change_set", execution)
            if label == "update":
                self.cfn("execute-token-repeat", "execute_change_set", execution, required=False)
            self.wait_stack(label, stack, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"})
            self.snapshot(label, stack)
        else:
            self.cfn(label + "-execute-rejected", "execute_change_set",
                     {"ChangeSetName": owned["id"]}, required=False)
        return current

    def workflow(self):
        p = self.data["prefix"]
        queue = self.resource("sqs", p + "-q1")
        topic = self.resource("sns", p + "-topic")
        role = self.resource("iam", p + "-role")
        bucket = self.resource("s3", p + "-bucket")
        export = p + "-queue-arn"
        template = {
            "AWSTemplateFormatVersion": "2010-09-09", "Description": "Owned stackd lifecycle probe",
            "Parameters": {"Delay": {"Type": "Number", "Default": 0, "MinValue": 0, "MaxValue": 900}},
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue,
                          "DelaySeconds": {"Ref": "Delay"}}},
                "Topic": {"Type": "AWS::SNS::Topic", "DependsOn": "Queue",
                          "Properties": {"TopicName": topic, "DisplayName": "initial"}},
                "Role": {"Type": "AWS::IAM::Role", "DependsOn": "Topic", "Properties": {
                    "RoleName": role, "AssumeRolePolicyDocument": {"Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                   "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": self.account}}}]}}},
                "Bucket": {"Type": "AWS::S3::Bucket", "DependsOn": "Role", "Properties": {"BucketName": bucket}},
            },
            "Outputs": {"QueueURL": {"Value": {"Ref": "Queue"}},
                        "QueueARN": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}, "Export": {"Name": export}},
                        "TopicARN": {"Value": {"Ref": "Topic"}},
                        "RoleARN": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
                        "BucketName": {"Value": {"Ref": "Bucket"}}},
        }
        self.cfn("validate-template", "validate_template", {"TemplateBody": json.dumps(template)})
        main, request = self.create("main", template)
        self.cfn("create-token-repeat-in-progress", "create_stack", request, required=False)
        changed = copy.deepcopy(template)
        changed["Description"] = "Same token with different template input"
        self.cfn("create-token-conflict", "create_stack", {**request, "TemplateBody": json.dumps(changed)}, required=False)
        self.cfn("create-name-conflict", "create_stack", {**request, "ClientRequestToken": p + "-other-create"}, required=False)
        self.wait_stack("create-main", main, {"CREATE_COMPLETE"})
        self.cfn("create-token-repeat-complete", "create_stack", request, required=False)
        self.snapshot("create", main)
        self.cfn("describe-queue-resource", "describe_stack_resource", {"StackName": main, "LogicalResourceId": "Queue"})
        self.cfn("get-template", "get_template", {"StackName": main})
        updated = copy.deepcopy(template)
        updated["Resources"]["Queue"]["Properties"]["DelaySeconds"] = 5
        updated["Resources"]["Topic"]["Properties"]["DisplayName"] = "updated"
        self.changeset("update", main, updated)
        self.changeset("no-change", main, updated, execute=False)
        self.cfn("update-stack-no-change", "update_stack", {"StackName": main,
                 "TemplateBody": json.dumps(updated), "Capabilities": ["CAPABILITY_NAMED_IAM"]}, required=False)
        replaced = copy.deepcopy(updated)
        replaced["Resources"]["Queue"]["Properties"]["QueueName"] = self.resource("sqs", p + "-q2")
        self.changeset("replacement", main, replaced)
        self.call("replaced-queue-absence", "sqs", "get_queue_url", {"QueueName": queue}, required=False)
        self.call("replacement-queue", "sqs", "get_queue_url", {"QueueName": p + "-q2"})
        failing = copy.deepcopy(replaced)
        failing["Resources"]["Queue"]["Properties"]["DelaySeconds"] = 7
        failing["Resources"]["BadQueue"] = self.bad_queue("bad-update", "Queue")
        self.changeset("update-rollback", main, failing)
        self.cfn("template-after-update-rollback", "get_template", {"StackName": main})
        self.call("queue-after-update-rollback", "sqs", "get_queue_attributes", {
            "QueueUrl": "https://sqs." + REGION + ".amazonaws.com/" + self.account + "/" + p + "-q2",
            "AttributeNames": ["DelaySeconds", "QueueArn"]})
        rollback_template = {"Resources": {
            "GoodQueue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": self.resource("sqs", p + "-rollback-good")}},
            "BadQueue": self.bad_queue("bad-create", "GoodQueue"),
            "BlockedTopic": {"Type": "AWS::SNS::Topic", "DependsOn": "BadQueue",
                             "Properties": {"TopicName": self.resource("sns", p + "-blocked-topic")}},
        }}
        failed, _ = self.create("rollback", rollback_template)
        self.wait_stack("create-rollback", failed, {"ROLLBACK_COMPLETE"})
        self.snapshot("create-rollback", failed)
        importer_template = {"Resources": {"ImportTopic": {"Type": "AWS::SNS::Topic", "Properties": {
            "TopicName": self.resource("sns", p + "-import-topic"), "DisplayName": {"Fn::ImportValue": export}}}},
            "Outputs": {"ImportedARN": {"Value": {"Fn::ImportValue": export}}}}
        importer, _ = self.create("importer", importer_template)
        self.wait_stack("create-importer", importer, {"CREATE_COMPLETE"})
        self.snapshot("importer", importer)
        self.cfn("list-imports", "list_imports", {"ExportName": export})
        self.cfn("delete-export-in-use", "delete_stack", {"StackName": main,
                 "ClientRequestToken": p + "-blocked-delete"}, required=False)
        if self.data["calls"][-1]["code"] == "Success":
            self.wait_delete_cancellation("delete-export-in-use", main,
                p + "-blocked-delete", "UPDATE_ROLLBACK_COMPLETE")
        self.data["workflow_complete"] = True
        self.save()

    def wait_delete_cancellation(self, label, stack, token, previous_status):
        for attempt in range(61):
            result = self.cfn(label + "-cancellation-wait-" + str(attempt),
                "describe_stack_events", {"StackName": stack})
            for event in result["StackEvents"]:
                if (event.get("ClientRequestToken") == token and
                    event["ResourceType"] == "AWS::CloudFormation::Stack" and
                    event.get("ResourceStatusReason", "").startswith("Delete canceled.")):
                    self.data.setdefault("constraint_observations", {})[label] = {
                        "previous_status": previous_status, "final_status": event["ResourceStatus"],
                        "reason": event["ResourceStatusReason"], "event_id": event["EventId"],
                        "client_request_token": token}
                    self.snapshot(label, stack)
                    return
            time.sleep(5)
        raise RuntimeError("Owned export deletion cancellation was not observed within bounds")

    def export_update_constraint(self):
        """Observe whether an in-use export update fails synchronously or rolls back."""
        p = self.data["prefix"]
        export = p + "-export-update"
        topic = self.resource("sns", p + "-export-update-topic")
        producer_template = {"Parameters": {"Secret": {"Type": "String", "NoEcho": True,
            "Default": "synthetic-default"}}, "Resources": {"Topic": {"Type": "AWS::SNS::Topic",
            "Properties": {"TopicName": topic}}}, "Outputs": {"Exported": {
                "Value": "before", "Export": {"Name": export}}}}
        producer, _ = self.create("export-update-producer", producer_template,
            parameters=[{"ParameterKey": "Secret", "ParameterValue": "synthetic-noecho-parameter"}])
        self.wait_stack("create-export-update-producer", producer, {"CREATE_COMPLETE"})
        importer_template = {"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {
            "TopicName": self.resource("sns", p + "-export-update-import-topic"),
            "DisplayName": {"Fn::ImportValue": export}}}}}
        importer, _ = self.create("export-update-importer", importer_template)
        self.wait_stack("create-export-update-importer", importer, {"CREATE_COMPLETE"})
        changed = copy.deepcopy(producer_template)
        changed["Outputs"]["Exported"]["Value"] = "after"
        self.cfn("update-export-in-use", "update_stack", {"StackName": producer,
            "TemplateBody": json.dumps(changed), "ClientRequestToken": p + "-update-export-in-use",
            "Parameters": [{"ParameterKey": "Secret", "UsePreviousValue": True}]}, required=False)
        if self.data["calls"][-1]["code"] == "Success":
            self.wait_stack("update-export-in-use", producer, {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_COMPLETE"})
        self.snapshot("update-export-in-use", producer)
        self.cfn("update-export-in-use-template", "get_template", {"StackName": producer})
        self.cfn("update-export-in-use-imports", "list_imports", {"ExportName": export})
        self.call("update-export-in-use-producer-topic", "sns", "get_topic_attributes",
            {"TopicArn": "arn:aws:sns:" + REGION + ":" + self.account + ":" + topic})
        self.call("update-export-in-use-import-topic", "sns", "get_topic_attributes",
            {"TopicArn": "arn:aws:sns:" + REGION + ":" + self.account + ":" + p + "-export-update-import-topic"})
        previous = self.cfn("supplement-export-before-delete", "describe_stacks",
            {"StackName": producer})["Stacks"][0]["StackStatus"]
        token = p + "-supplement-blocked-delete"
        self.cfn("supplement-delete-export-in-use", "delete_stack",
            {"StackName": producer, "ClientRequestToken": token})
        self.wait_delete_cancellation("supplement-delete-export-in-use", producer, token, previous)
        self.data["export_update_complete"] = True
        self.save()

    def subscription_ref(self):
        p = self.data["prefix"]
        template = {"Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {
                "QueueName": self.resource("sqs", p + "-subscription-queue")}},
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {
                "TopicName": self.resource("sns", p + "-subscription-topic")}},
            "Subscription": {"Type": "AWS::SNS::Subscription", "Properties": {
                "Protocol": "sqs", "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                "TopicArn": {"Ref": "Topic"}}}},
            "Outputs": {"SubscriptionRef": {"Value": {"Ref": "Subscription"}},
                        "SubscriptionArn": {"Value": {"Fn::GetAtt": ["Subscription", "Arn"]}}}}
        stack, _ = self.create("subscription", template)
        final = self.wait_stack("create-subscription", stack, {"CREATE_COMPLETE"})
        outputs = {row["OutputKey"]: row["OutputValue"] for row in final["Outputs"]}
        self.resource("subscription", outputs["SubscriptionArn"])
        self.snapshot("subscription", stack)
        self.call("subscription-attributes", "sns", "get_subscription_attributes",
            {"SubscriptionArn": outputs["SubscriptionArn"]})
        self.data["subscription_complete"] = True
        self.save()

    def bad_queue(self, suffix, dependency):
        p = self.data["prefix"]
        return {"Type": "AWS::SQS::Queue", "DependsOn": dependency, "Properties": {
            "QueueName": self.resource("sqs", p + "-" + suffix),
            "RedrivePolicy": {"deadLetterTargetArn": "arn:aws:sqs:" + REGION + ":" + self.account + ":" + p + "-missing-dlq",
                              "maxReceiveCount": 3}}}

    def cleanup(self):
        cleanup = self.data["cleanup"] = {"started_at": now(), "complete": False, "stacks": [],
                                          "changesets": [], "resources": [], "errors": []}
        for key, owned in reversed(list(self.data["owned"]["stacks"].items())):
            stack = owned.get("id", owned["name"])
            try:
                result = self.cfn("cleanup-inspect-" + key, "describe_stacks", {"StackName": stack}, required=False)
                if result and result["Stacks"][0]["StackStatus"].endswith("_IN_PROGRESS"):
                    self.wait_stack("cleanup-settle-" + key, stack,
                        {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "DELETE_COMPLETE", "DELETE_FAILED"})
                self.cfn("cleanup-delete-" + key, "delete_stack", {"StackName": stack,
                         "ClientRequestToken": self.data["prefix"] + "-cleanup-" + key}, required=False)
                if owned.get("id"):
                    self.wait_stack("cleanup-delete-" + key, stack, {"DELETE_COMPLETE"})
                    self.snapshot("deleted-" + key, stack)
                self.cfn("cleanup-name-absence-" + key, "describe_stacks", {"StackName": owned["name"]}, required=False)
                row = self.data["calls"][-1]
                absent = row["code"] == "ValidationError" and "does not exist" in row.get("error", {}).get("Message", "")
                cleanup["stacks"].append({"name": owned["name"], "id": owned.get("id"), "active_absent": absent,
                                          "deleted_history_retained": bool(owned.get("id"))})
            except Exception as error:
                cleanup["errors"].append({"stack": stack, "error": str(error)})
                self.save()
        for owned in self.data["owned"]["changesets"]:
            try:
                identifier = owned.get("id", owned["name"])
                self.cfn("cleanup-delete-changeset-" + owned["name"], "delete_change_set",
                         {"ChangeSetName": identifier, "StackName": owned["stack"]}, required=False)
                deletion = self.data["calls"][-1]
                self.cfn("cleanup-changeset-absence-" + owned["name"], "describe_change_set",
                         {"ChangeSetName": identifier, "StackName": owned["stack"]}, required=False)
                row = self.data["calls"][-1]
                execution = row.get("output", {}).get("ExecutionStatus")
                deleted_parent = any(item["id"] == owned["stack"] and item["active_absent"]
                                     for item in cleanup["stacks"])
                retained = (deleted_parent and deletion["code"] == "InvalidChangeSetStatus" and
                            execution in ("EXECUTE_COMPLETE", "EXECUTE_FAILED"))
                cleanup["changesets"].append({"id": identifier, "absent": row["code"] == "ChangeSetNotFound",
                    "retained_execution_history": retained, "execution_status": execution,
                    "deletion_error": deletion.get("error")})
            except Exception as error:
                cleanup["errors"].append({"changeset": owned["name"], "error": str(error)})
        for resource in self.data["owned"]["resources"]:
            kind, name = resource["kind"], resource["name"]
            operation, parameters, codes = {
                "sqs": ("get_queue_url", {"QueueName": name}, {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}),
                "sns": ("get_topic_attributes", {"TopicArn": "arn:aws:sns:" + REGION + ":" + self.account + ":" + name}, {"NotFound"}),
                "iam": ("get_role", {"RoleName": name}, {"NoSuchEntity"}),
                "s3": ("head_bucket", {"Bucket": name}, {"404", "NoSuchBucket"}),
                "subscription": ("get_subscription_attributes", {"SubscriptionArn": name}, {"NotFound"}),
            }[kind]
            try:
                self.call("cleanup-resource-absence-" + name, "sns" if kind == "subscription" else kind,
                          operation, parameters, required=False)
                cleanup["resources"].append({**resource, "absent": self.data["calls"][-1]["code"] in codes})
            except Exception as error:
                cleanup["errors"].append({**resource, "error": str(error)})
        cleanup["complete"] = (not cleanup["errors"] and
            all(item["active_absent"] for item in cleanup["stacks"]) and
            all(item["absent"] for item in cleanup["resources"]) and
            all(item["absent"] or item["retained_execution_history"] for item in cleanup["changesets"]))
        cleanup["finished_at"] = now()
        self.save()
        if not cleanup["complete"]:
            raise RuntimeError("Owned cleanup incomplete; inspect exact native evidence")

    def collect_audit(self):
        requests = {row["request_id"]: row["label"] for row in self.data["calls"]
                    if row.get("request_id") and row["service"] == "cloudformation"}
        try:
            result = collect_history(lambda request: self.clients["cloudtrail"].lookup_events(**request),
                requests, start_time=self.data["captured_at"], event_sources=["cloudformation.amazonaws.com"],
                max_pages=20, rounds=self.args.trail_rounds, wait_seconds=30,
                previous=self.data.get("cloudtrail"))
        except CollectionError as error:
            result = error.result
        self.data["cloudtrail"] = result
        self.save()

    def collect_resource_audit(self):
        prefix = self.data["prefix"]
        try:
            result = collect_history(lambda request: self.clients["cloudtrail"].lookup_events(**request),
                {}, start_time=self.data["captured_at"],
                event_sources=["sqs.amazonaws.com", "sns.amazonaws.com", "iam.amazonaws.com", "s3.amazonaws.com"],
                max_pages=10, rounds=self.args.trail_rounds, wait_seconds=30,
                related=lambda event: prefix in json.dumps(event.get("requestParameters", {})) or
                                      prefix in json.dumps(event.get("resources", [])),
                previous=self.data.get("resource_cloudtrail"))
        except CollectionError as error:
            result = error.result
        self.data["resource_cloudtrail"] = result
        self.save()

def capture_schemas(path, account):
    """Read the regional public registry without creating any resource."""
    previous = json.loads(path.read_text()) if path.exists() else None
    if previous and previous.get("complete"):
        raise RuntimeError("Refusing to overwrite complete native schema evidence")
    session = boto3.Session(region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=5,
                    read_timeout=30, ignore_configured_endpoint_urls=True)
    identity = session.client("sts", config=config).get_caller_identity()
    if identity["Account"] != account:
        raise RuntimeError("Native schema capture restricted to the authorized account")
    client = session.client("cloudformation", config=config)
    types = ("AWS::S3::Bucket", "AWS::S3::BucketPolicy", "AWS::SQS::Queue", "AWS::SQS::QueuePolicy",
             "AWS::SNS::Topic", "AWS::SNS::TopicPolicy", "AWS::SNS::Subscription", "AWS::IAM::Role",
             "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::Lambda::Function", "AWS::Lambda::Permission",
             "AWS::Lambda::EventSourceMapping", "AWS::Events::Rule", "AWS::Events::EventBus", "AWS::Logs::LogGroup")
    capture = {"source": "native AWS DescribeType", "account": account, "region": REGION,
               "identity": document(identity), "captured_at": now(), "sdk": {"boto3": boto3.__version__},
               "documentation": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeType.html"],
               "types": {}, "complete": False}
    if previous:
        if previous["account"] != account or previous["region"] != REGION:
            raise RuntimeError("Schema capture target differs from authorized account/region")
        capture = previous
    path.parent.mkdir(parents=True, exist_ok=True)
    for name in types:
        if name in capture["types"]:
            continue
        request = {"Type": "RESOURCE", "TypeName": name}
        result = client.describe_type(**request)
        schema = json.loads(result.pop("Schema"))
        response = result.pop("ResponseMetadata")
        capture["types"][name] = {"input": request, "schema": schema, "metadata": result,
                                 "arn": result.get("Arn", ""), "default_version_id": result.get("DefaultVersionId", ""),
                                 "request_id": response.get("RequestId"), "http_status": response.get("HTTPStatusCode")}
        path.write_text(json.dumps(document(capture), indent=2) + "\n")
        print(name + ": " + str(result.get("DefaultVersionId")), flush=True)
        time.sleep(0.6)
    capture["complete"] = True
    capture["finished_at"] = now()
    path.write_text(json.dumps(document(capture), indent=2) + "\n")
    print(json.dumps({"capture": str(path), "schemas": len(capture["types"]), "complete": True}), flush=True)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lifecycle.json"))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--cleanup-only", action="store_true")
    modes.add_argument("--audit-only", action="store_true")
    modes.add_argument("--export-update-only", action="store_true")
    modes.add_argument("--subscription-only", action="store_true")
    modes.add_argument("--schemas-only", action="store_true")
    parser.add_argument("--schema-output", type=Path, default=Path(".stackd/probes/cloudformation/resource_schemas.json"))
    parser.add_argument("--trail-rounds", type=int, default=3)
    args = parser.parse_args()
    if args.schemas_only:
        capture_schemas(args.schema_output, args.account)
        return
    probe = CloudFormationProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted; entering exact-owned cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if not args.cleanup_only and not args.audit_only:
            try:
                if not args.export_update_only and not args.subscription_only:
                    probe.workflow()
                if not args.subscription_only:
                    probe.export_update_constraint()
                if not args.export_update_only:
                    probe.subscription_ref()
            except Exception as error:
                probe.data["failure"] = {"type": type(error).__name__, "message": str(error)}
                probe.save()
                raise
            finally:
                probe.cleanup()
        elif args.cleanup_only:
            probe.cleanup()
    finally:
        probe.collect_audit()
        probe.collect_resource_audit()
        print(json.dumps({"capture": str(args.output), "prefix": probe.data["prefix"],
                          "workflow_complete": probe.data["workflow_complete"],
                          "cleanup_complete": probe.data["cleanup"].get("complete", False),
                          "cloudtrail_matches": len(probe.data.get("cloudtrail", {}).get("events", [])),
                          "failure": probe.data.get("failure")}), flush=True)


if __name__ == "__main__":
    main()
