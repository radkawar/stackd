#!/usr/bin/env python3
"""Capture native CFN Kinesis mapping defaults, removal and replacement.

All mappings remain disabled. No records or invocations are sent. Evidence is
never overwritten; --cleanup-only resumes the exact-owned durable inventory.
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
import botocore
from botocore.config import Config

from cloudformation_lambda_layer_probe import LayerProbe
from cloudformation_lambda_version_probe import VersionProbe
from cloudtrail_service_probe import REGION, document, now

TYPE = "AWS::Lambda::EventSourceMapping"

SOURCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html",
    "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html",
    "https://docs.aws.amazon.com/lambda/latest/api/API_UpdateEventSourceMapping.html",
    "https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html",
]


class KinesisMappingProbe(LayerProbe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config) for name in
                        ("sts", "iam", "lambda", "cloudformation", "logs", "kinesis", "sqs")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if (self.data["account"], self.data["region"]) != (self.account, REGION):
                raise RuntimeError("Inventory outside approved account/region")
            if not self.data["prefix"].startswith("stackd-cfn-kinesis-"):
                raise RuntimeError("Not a CFN Kinesis mapping inventory")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "source": "Native AWS public endpoints; signed boto3; endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION,
                "prefix": "stackd-cfn-kinesis-" + uuid.uuid4().hex[:12],
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__,
                        "models": {name: {"api_version": client.meta.service_model.api_version,
                                           "endpoint": client.meta.endpoint_url}
                                   for name, client in self.clients.items()}},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "At most two exact-owned provisioned one-shard streams (or one exact-owned SQS queue in SQS mode), one disabled mapping stack, one non-invoked function with optional version/aliases, exact-source/log-scoped role and owned log group; no public grants",
                "mode": "sqs-common-removal" if args.sqs_only else "kinesis-lifecycle",
                "bounds": {"stack_wait_seconds": 420, "resource_wait_seconds": 180, "poll_seconds": 3},
                "owned": {"stacks": {}, "streams": {}, "mappings": []},
                "calls": [], "findings": {}, "templates": {}, "sources": SOURCES,
                "calibration_gaps": [
                    "Control-plane deployment only; no Kinesis records or Lambda invocations are sent.",
                    "Private CloudFormation ownership tokens, restart recovery and local native-engine equivalence are not measured.",
                    "Encrypted filters/KmsKeyArn and failure destinations are not provisioned or calibrated.",
                    "No provisioned pollers, enhanced fan-out consumers, public grants or cross-account sources are created.",
                ],
                "cleanup": {"complete": False}, "workflow_complete": False,
            }
        self.save()
        identity = self.call("identity-before-writes", "sts", "get_caller_identity")
        self.data["identity"] = identity
        self.save()
        if identity["Account"] != self.account or identity["Arn"] != self.actor:
            raise RuntimeError("Native writes require the approved account and IAM user Delegated")

    def documents(self):
        registry = self.call("mapping-public-registry-schema", "cloudformation", "describe_type",
                             {"Type": "RESOURCE", "TypeName": TYPE})
        schema = json.loads(registry["Schema"])
        self.data["schema"] = schema
        self.finding("schema_contract", {key: schema.get(key) for key in
                     ("primaryIdentifier", "readOnlyProperties", "createOnlyProperties", "required", "tagging")})
        if self.args.schema_output:
            path = self.args.schema_output
            capture = json.loads(path.read_text())
            if (capture["account"], capture["region"]) != (self.account, REGION):
                raise RuntimeError("Schema inventory outside approved account/region")
            row = self.data["calls"][-1]
            capture["types"][TYPE] = {
                "input": row["input"], "schema": schema,
                "metadata": {key: value for key, value in registry.items() if key != "Schema"},
                "arn": registry.get("Arn", ""), "default_version_id": registry.get("DefaultVersionId", ""),
                "request_id": row["metadata"].get("RequestId"), "http_status": row["metadata"].get("HTTPStatusCode"),
                "captured_at": row["finished_at"], "capture": str(self.args.output),
            }
            path.write_text(json.dumps(document(capture), indent=2) + "\n")

    def wait_resource(self, label, service, operation, request, predicate):
        deadline = time.monotonic() + self.data["bounds"]["resource_wait_seconds"]
        attempt = 0
        while time.monotonic() < deadline:
            value = self.call(label + "-" + str(attempt), service, operation, request, required=False)
            if predicate(value, self.code()):
                return value
            if self.code() not in ("Success", "ResourceNotFoundException"):
                raise RuntimeError(label + ": unexpected " + self.code())
            attempt += 1
            time.sleep(self.data["bounds"]["poll_seconds"])
        self.finding(label + "-bounded-wait-expired", {"wait_seconds": self.data["bounds"]["resource_wait_seconds"],
                                                    "last_response": self.data["calls"][-1]})
        raise RuntimeError(label + ": bounded wait expired; scenario is not rerun")

    def setup_stream(self, key):
        name = self.data["prefix"] + "-" + key
        arn = "arn:aws:kinesis:" + REGION + ":" + self.account + ":stream/" + name
        self.absent(key + "-stream-name-absent", "kinesis", "describe_stream_summary",
                    {"StreamARN": arn}, "ResourceNotFoundException")
        owned = {"name": name, "arn": arn, "absence_verified": True, "creation_attempted": True}
        self.data["owned"]["streams"][key] = owned
        self.save()
        self.call(key + "-create-stream", "kinesis", "create_stream", {
            "StreamName": name, "ShardCount": 1, "StreamModeDetails": {"StreamMode": "PROVISIONED"},
            "Tags": {"stackd-probe": self.data["prefix"]}})
        owned["creation_confirmed"] = True
        self.save()
        ready = self.wait_resource(key + "-stream-ready", "kinesis", "describe_stream_summary",
                                   {"StreamARN": arn}, lambda value, code:
                                   value.get("StreamDescriptionSummary", {}).get("StreamStatus") == "ACTIVE")
        owned["created_at"] = document(ready["StreamDescriptionSummary"]["StreamCreationTimestamp"])
        self.save()
        return arn

    def setup_queue(self):
        name = self.data["prefix"] + "-queue"
        self.call("queue-name-absent", "sqs", "get_queue_url", {"QueueName": name}, required=False)
        if self.code() not in ("QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"):
            raise RuntimeError("Refusing unverified queue name")
        queue = {"name": name, "absence_verified": True, "creation_attempted": True}
        self.data["owned"]["queue"] = queue
        self.save()
        queue["url"] = self.call("create-owned-queue", "sqs", "create_queue", {
            "QueueName": name, "tags": {"stackd-probe": self.data["prefix"]}})["QueueUrl"]
        self.save()
        queue["arn"] = self.call("owned-queue-identity", "sqs", "get_queue_attributes",
            {"QueueUrl": queue["url"], "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        self.save()
        return queue["arn"]

    def source_arns(self):
        sources = [stream["arn"] for stream in self.data["owned"]["streams"].values()]
        if self.data["owned"].get("queue", {}).get("arn"):
            sources.append(self.data["owned"]["queue"]["arn"])
        return sources

    def source_policy(self):
        owned = self.data["owned"]
        statements = [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                       "Resource": owned["log_group"]["arn"] + ":*"}]
        if owned["streams"]:
            statements.append({"Effect": "Allow", "Action": ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary",
                "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:ListShards"],
                "Resource": [stream["arn"] for stream in owned["streams"].values()]})
        if "queue" in owned:
            statements.append({"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                               "Resource": owned["queue"]["arn"]})
        request = {"RoleName": owned["role"]["name"], "PolicyName": "owned-source-and-logs",
                   "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})}
        owned["role"]["policy"] = request["PolicyName"]
        self.save()
        self.call("put-owned-source-and-log-policy", "iam", "put_role_policy", request)
        self.call("read-owned-source-and-log-policy", "iam", "get_role_policy",
                  {"RoleName": request["RoleName"], "PolicyName": request["PolicyName"]})
        time.sleep(15)

    def setup(self):
        first = self.setup_queue() if self.args.sqs_only else self.setup_stream("first")
        VersionProbe.setup(self)
        name = "/aws/lambda/" + self.data["owned"]["function"]["name"]
        arn = "arn:aws:logs:" + REGION + ":" + self.account + ":log-group:" + name
        self.absent("log-group-absent", "logs", "list_tags_for_resource",
                    {"resourceArn": arn}, "ResourceNotFoundException")
        self.data["owned"]["log_group"] = {"name": name, "arn": arn, "absence_verified": True}
        self.save()
        self.call("create-owned-log-group", "logs", "create_log_group", {
            "logGroupName": name, "tags": {"stackd-probe": self.data["prefix"]}})
        self.source_policy()
        return first

    def template(self, properties):
        if properties.get("Enabled") is not False:
            raise RuntimeError("All native probe mappings must remain disabled")
        if properties["EventSourceArn"] not in self.source_arns():
            raise RuntimeError("Mapping source is outside the exact-owned inventory")
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
            "Mapping": {"Type": TYPE, "Properties": copy.deepcopy(properties)}}, "Outputs": {
                "MappingRef": {"Value": {"Ref": "Mapping"}},
                "MappingId": {"Value": {"Fn::GetAtt": ["Mapping", "Id"]}},
                "MappingArn": {"Value": {"Fn::GetAtt": ["Mapping", "EventSourceMappingArn"]}}}}

    def remember_mappings(self, items):
        for item in items:
            identifier = item.get("PhysicalResourceId")
            if item.get("ResourceType") == TYPE and identifier:
                if identifier not in self.data["owned"]["mappings"]:
                    self.data["owned"]["mappings"].append(identifier)
        self.save()

    def stack(self, label, properties, update=False):
        key = "mapping"
        stacks = self.data["owned"]["stacks"]
        template = self.template(properties)
        self.data["templates"][label] = template
        if not update:
            name = self.data["prefix"] + "-mapping"
            self.absent(label + "-stack-name-absent", "cloudformation", "describe_stacks",
                        {"StackName": name}, "ValidationError")
            stacks[key] = {"name": name, "creation_attempted": True}
        self.save()
        request = {"StackName": stacks[key].get("id", stacks[key]["name"]),
                   "TemplateBody": json.dumps(template), "ClientRequestToken": self.data["prefix"] + "-" + label}
        if not update:
            request["Tags"] = [{"Key": "stackd-probe", "Value": self.data["prefix"]}]
        submitted = self.call(label + "-submit", "cloudformation", "update_stack" if update else "create_stack",
                              request, required=False)
        result = {"submission_code": self.code()}
        if submitted:
            stacks[key]["id"] = submitted["StackId"]
            self.save()
            try:
                current = self.wait_owned_stack(key, label)
            finally:
                for operation, field in (("describe_stack_resources", "StackResources"),
                                         ("describe_stack_events", "StackEvents")):
                    response = self.call(label + "-" + operation, "cloudformation", operation,
                                         {"StackName": submitted["StackId"]}, required=False)
                    self.remember_mappings(response.get(field, []))
                    result[field] = response.get(field, [])
            result.update(stack_status=current["StackStatus"], outputs=current.get("Outputs", []))
            self.call(label + "-get-template", "cloudformation", "get_template", {"StackName": submitted["StackId"]})
            if current["StackStatus"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
                outputs = {item["OutputKey"]: item["OutputValue"] for item in current.get("Outputs", [])}
                identifier = outputs.get("MappingRef")
                if identifier:
                    mapping = self.wait_resource(label + "-mapping-ready", "lambda", "get_event_source_mapping",
                        {"UUID": identifier}, lambda value, code: value.get("State") == "Disabled")
                    result["mapping"] = mapping
                    result["tags"] = self.call(label + "-mapping-tags", "lambda", "list_tags",
                                               {"Resource": mapping["EventSourceMappingArn"]})
        return self.finding(label, result)

    def require_complete(self, result):
        if result.get("stack_status") not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            raise RuntimeError("Native mapping stack did not complete: " + result.get("stack_status", result["submission_code"]))
        return result["mapping"]

    def sqs_workflow(self):
        queue = self.setup()
        base = {"EventSourceArn": queue, "FunctionName": self.data["owned"]["function"]["arn"], "Enabled": False}
        fresh = self.require_complete(self.stack("sqs-fresh-defaults", base))
        settings = {"BatchSize": 17, "MaximumBatchingWindowInSeconds": 2,
                    "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"body": {"probe": [self.data["prefix"]]}})}]},
                    "MetricsConfig": {"Metrics": ["EventCount"]},
                    "FunctionResponseTypes": ["ReportBatchItemFailures"],
                    "ScalingConfig": {"MaximumConcurrency": 2},
                    "Tags": [{"Key": "owned-setting", "Value": self.data["prefix"]}]}
        configured_result = self.stack("sqs-explicit-settings", {**base, **settings}, update=True)
        configured = self.require_complete(configured_result)
        removed_result = self.stack("sqs-remove-settings", base, update=True)
        removed = self.require_complete(removed_result)
        self.finding("sqs-property-removal", {"same_uuid": fresh["UUID"] == configured["UUID"] == removed["UUID"],
            "properties": {key: {"fresh": fresh.get(key), "explicit": configured.get(key), "removed": removed.get(key),
                                   "after_equals_fresh": removed.get(key) == fresh.get(key),
                                   "after_equals_explicit": removed.get(key) == configured.get(key)}
                           for key in settings if key != "Tags"},
            "explicit_tags": configured_result.get("tags"), "removed_tags": removed_result.get("tags")})
        self.require_complete(self.stack("sqs-explicit-empty-filter", {**base, "FilterCriteria": {}}, update=True))
        self.data["workflow_complete"] = True
        self.save()

    def workflow(self):
        self.documents()
        if self.args.sqs_only:
            self.sqs_workflow()
            return
        first = self.setup()
        base = {"EventSourceArn": first, "FunctionName": self.data["owned"]["function"]["arn"],
                "StartingPosition": "LATEST", "Enabled": False}
        fresh = self.require_complete(self.stack("fresh-defaults", base))
        settings = {"BatchSize": 17, "MaximumBatchingWindowInSeconds": 2, "ParallelizationFactor": 2,
                    "MaximumRetryAttempts": 2, "MaximumRecordAgeInSeconds": 120,
                    "BisectBatchOnFunctionError": True,
                    "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"data": {"probe": [self.data["prefix"]]}})}]},
                    "MetricsConfig": {"Metrics": ["EventCount"]},
                    "FunctionResponseTypes": ["ReportBatchItemFailures"],
                    "Tags": [{"Key": "owned-setting", "Value": self.data["prefix"]}]}
        configured_result = self.stack("explicit-settings", {**base, **settings}, update=True)
        configured = self.require_complete(configured_result)
        removed_result = self.stack("remove-settings", base, update=True)
        removed = self.require_complete(removed_result)
        self.finding("property-removal", {"same_uuid": fresh["UUID"] == configured["UUID"] == removed["UUID"],
            "properties": {key: {"fresh": fresh.get(key), "explicit": configured.get(key), "removed": removed.get(key),
                                   "after_equals_fresh": removed.get(key) == fresh.get(key),
                                   "after_equals_explicit": removed.get(key) == configured.get(key)}
                           for key in settings if key != "Tags"},
            "explicit_tags": configured_result.get("tags"), "removed_tags": removed_result.get("tags")})
        # Native rejects non-unit parallelization with a nonzero tumbling window.
        tumbling = self.require_complete(self.stack("explicit-tumbling",
            {**base, "ParallelizationFactor": 1, "TumblingWindowInSeconds": 5}, update=True))
        removed_tumbling = self.require_complete(self.stack("remove-tumbling", base, update=True))
        self.finding("tumbling-removal", {"fresh": fresh.get("TumblingWindowInSeconds"),
            "explicit": tumbling.get("TumblingWindowInSeconds"),
            "removed": removed_tumbling.get("TumblingWindowInSeconds"),
            "same_uuid": tumbling["UUID"] == removed_tumbling["UUID"]})
        function = self.data["owned"]["function"]
        version = self.call("publish-retarget-version", "lambda", "publish_version",
                            {"FunctionName": function["arn"]})["Version"]
        function["versions"].append(version)
        function["aliases"] = []
        self.save()
        for alias in ("first", "second"):
            function["aliases"].append(alias)
            self.save()
            self.call("create-retarget-alias-" + alias, "lambda", "create_alias",
                      {"FunctionName": function["arn"], "Name": alias, "FunctionVersion": version})
        first_target = self.require_complete(self.stack("retarget-first-alias",
            {**base, "FunctionName": function["arn"] + ":first"}, update=True))
        second_target = self.require_complete(self.stack("retarget-second-alias",
            {**base, "FunctionName": function["arn"] + ":second"}, update=True))
        self.finding("function-retarget", {"same_uuid": fresh["UUID"] == first_target["UUID"] == second_target["UUID"],
            "base_function": fresh["FunctionArn"], "first_alias": first_target["FunctionArn"],
            "second_alias": second_target["FunctionArn"], "invocation_exercised": False})
        base["FunctionName"] = function["arn"] + ":second"
        changed_position = self.stack("replace-starting-position", {**base, "StartingPosition": "TRIM_HORIZON"}, update=True)
        if changed_position.get("stack_status") not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError("StartingPosition replacement did not settle")
        if changed_position["stack_status"] == "UPDATE_COMPLETE":
            base["StartingPosition"] = "TRIM_HORIZON"
        timestamp = int(time.time()) - 60
        timestamp_properties = {**base, "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": timestamp}
        changed_timestamp = self.stack("replace-starting-timestamp", timestamp_properties, update=True)
        if changed_timestamp.get("stack_status") not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError("StartingPositionTimestamp replacement did not settle")
        second = self.setup_stream("second")
        self.source_policy()
        second_properties = {**timestamp_properties, "EventSourceArn": second}
        replacement = self.require_complete(self.stack("replace-source-arn", second_properties, update=True))
        self.finding("source-replacement", {"old_uuid": fresh["UUID"], "new_uuid": replacement["UUID"],
                    "old_source": first, "new_source": second, "timestamp_unix_seconds": timestamp,
                    "old_mapping": self.call("source-replacement-old-mapping", "lambda", "get_event_source_mapping",
                                             {"UUID": fresh["UUID"]}, required=False), "old_mapping_code": self.code()})
        changed_timestamp_only = self.stack("replace-timestamp-only",
            {**second_properties, "StartingPositionTimestamp": timestamp + 1}, update=True)
        if changed_timestamp_only.get("stack_status") not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError("Timestamp-only replacement did not settle")
        self.data["workflow_complete"] = True
        self.save()

    def cleanup(self, source_cleanup=None):
        self.cleanup_phase = True
        owned, errors = self.data["owned"], []

        def attempt(label, action):
            try:
                action()
            except Exception as error:
                errors.append(label + ": " + str(error))
                self.save()

        def remove_stack(key):
            stack = owned["stacks"][key]
            if stack.get("id"):
                response = self.call("cleanup-stack-resource-inventory", "cloudformation", "describe_stack_resources",
                                     {"StackName": stack["id"]}, required=False)
                self.remember_mappings(response.get("StackResources", []))
            status = self.delete_stack(key, "cleanup-" + key)
            if status not in ("DELETE_COMPLETE", "ABSENT"):
                raise RuntimeError("Stack " + str(stack) + " ended in " + status)

        def remove_mapping(identifier):
            value = self.call("cleanup-mapping-identity-" + identifier, "lambda", "get_event_source_mapping",
                              {"UUID": identifier}, required=False)
            if not value and self.code() == "ResourceNotFoundException":
                return
            function = owned.get("function", {})
            targets = [function.get("arn")] + [function["arn"] + ":" + alias for alias in function.get("aliases", [])]
            if (value.get("FunctionArn") not in targets or
                    value.get("EventSourceArn") not in self.source_arns()):
                raise RuntimeError("Refusing mapping deletion without exact-owned function/source: " + identifier)
            if value.get("State") != "Deleting":
                self.call("cleanup-delete-mapping-" + identifier, "lambda", "delete_event_source_mapping", {"UUID": identifier})
            self.wait_resource("cleanup-mapping-absent-" + identifier, "lambda", "get_event_source_mapping",
                               {"UUID": identifier}, lambda value, code: code == "ResourceNotFoundException")

        def remove_function():
            function = owned["function"]
            request = {"FunctionName": function["name"]}
            current = self.call("cleanup-function-identity", "lambda", "get_function", request, required=False)
            if current:
                if current.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Refusing function deletion without exact ownership tag")
                self.call("cleanup-delete-function", "lambda", "delete_function", request)
            self.absent("cleanup-function-absent", "lambda", "get_function_configuration", request, "ResourceNotFoundException")
            for alias in function.get("aliases", []):
                self.absent("cleanup-alias-absent-" + alias, "lambda", "get_alias",
                            {**request, "Name": alias}, "ResourceNotFoundException")
            for version in function.get("versions", []):
                self.absent("cleanup-version-absent-" + version, "lambda", "get_function_configuration",
                            {**request, "Qualifier": version}, "ResourceNotFoundException")

        def remove_stream(key):
            stream = owned["streams"][key]
            request = {"StreamARN": stream["arn"]}
            current = self.call("cleanup-stream-identity-" + key, "kinesis", "describe_stream_summary", request, required=False)
            if not current and self.code() == "ResourceNotFoundException":
                return
            summary = current["StreamDescriptionSummary"]
            if summary["StreamARN"] != stream["arn"] or (stream.get("created_at") and
                    document(summary["StreamCreationTimestamp"]) != stream["created_at"]):
                raise RuntimeError("Stream identity changed: " + stream["arn"])
            if summary["StreamStatus"] != "DELETING":
                tags = self.call("cleanup-stream-tags-" + key, "kinesis", "list_tags_for_stream", request)
                if {item["Key"]: item["Value"] for item in tags.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Stream ownership tag changed: " + stream["arn"])
                self.call("cleanup-delete-stream-" + key, "kinesis", "delete_stream", request)
            self.wait_resource("cleanup-stream-absent-" + key, "kinesis", "describe_stream_summary", request,
                               lambda value, code: code == "ResourceNotFoundException")

        def remove_logs():
            group = owned["log_group"]
            result = self.call("cleanup-log-group-tags", "logs", "list_tags_for_resource",
                               {"resourceArn": group["arn"]}, required=False)
            if result or self.code() == "Success":
                if result.get("tags", {}).get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Refusing log-group cleanup without exact ownership tag")
                self.call("cleanup-delete-log-group", "logs", "delete_log_group", {"logGroupName": group["name"]})
            self.absent("cleanup-log-group-absent", "logs", "list_tags_for_resource",
                        {"resourceArn": group["arn"]}, "ResourceNotFoundException")

        def remove_role():
            role = owned["role"]
            result = self.call("cleanup-role-identity", "iam", "get_role", {"RoleName": role["name"]}, required=False)
            if result:
                current = result["Role"]
                if ({item["Key"]: item["Value"] for item in current.get("Tags", [])}.get("stackd-probe") != self.data["prefix"] or
                        current["RoleId"] != role.get("id", current["RoleId"])):
                    raise RuntimeError("Refusing role cleanup without exact ownership identity")
                if role.get("policy"):
                    self.call("cleanup-delete-owned-role-policy", "iam", "delete_role_policy",
                              {"RoleName": role["name"], "PolicyName": role["policy"]}, required=False)
                self.call("cleanup-delete-role", "iam", "delete_role", {"RoleName": role["name"]})
            self.absent("cleanup-role-absent", "iam", "get_role", {"RoleName": role["name"]}, "NoSuchEntity")

        def remove_queue():
            queue = owned["queue"]
            if not queue.get("url"):
                result = self.call("cleanup-owned-queue-url", "sqs", "get_queue_url",
                                   {"QueueName": queue["name"]}, required=False)
                if not result and self.code() in ("QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"):
                    return
                queue["url"] = result["QueueUrl"]
                self.save()
            result = self.call("cleanup-queue-tags", "sqs", "list_queue_tags", {"QueueUrl": queue["url"]}, required=False)
            if not result and self.code() in ("QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"):
                return
            if result.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                raise RuntimeError("Refusing queue cleanup without exact ownership tag")
            self.call("cleanup-delete-queue", "sqs", "delete_queue", {"QueueUrl": queue["url"]})
            self.wait_resource("cleanup-queue-absent", "sqs", "get_queue_attributes",
                {"QueueUrl": queue["url"], "AttributeNames": ["QueueArn"]},
                lambda value, code: code in ("QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"))

        for key in owned["stacks"]:
            attempt("stack " + key, lambda key=key: remove_stack(key))
        for identifier in owned["mappings"]:
            attempt("mapping " + identifier, lambda identifier=identifier: remove_mapping(identifier))
        if source_cleanup is not None:
            source_cleanup(attempt)
        if "function" in owned:
            attempt("function", remove_function)
        for key in owned["streams"]:
            attempt("stream " + key, lambda key=key: remove_stream(key))
        if "queue" in owned:
            attempt("queue", remove_queue)
        if "log_group" in owned:
            attempt("log group", remove_logs)
        if "role" in owned:
            attempt("role", remove_role)
        self.data["cleanup"].update(complete=not errors, errors=errors, finished_at=now(),
            boundary="Exact native IDs verified absent; deleted stack ARN retains DELETE_COMPLETE history")
        self.save()
        if errors:
            raise RuntimeError("Exact-owned cleanup incomplete: " + "; ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_kinesis_mapping.json"))
    parser.add_argument("--schema-output", type=Path)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--sqs-only", action="store_true", help="Calibrate common removal semantics on one exact-owned SQS queue instead of streams")
    args = parser.parse_args()
    probe = KinesisMappingProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            probe.workflow()
    except Exception as error:
        probe.data["failure"] = {"at": now(), "error": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
