#!/usr/bin/env python3
"""Capture native CFN EventBridge rule bus migration and real SQS delivery.

Two custom buses, one queue and one explicitly named rule stack are exact-owned.
Evidence is never overwritten; --cleanup-only resumes only exact-owned cleanup.
The default bus and its policy are never changed or used for event publishing.
--identity-only separately calibrates a disabled targetless rule on default and
one owned custom bus, including equivalent bus-name/ARN representations.
--changeset-only measures unexecuted public replacement planning fields using
one disabled targetless rule on the owned custom bus; default is only proposed.
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
from cloudtrail_service_probe import REGION, document, now

TYPE = "AWS::Events::Rule"

SOURCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-rule.html",
    "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutRule.html",
    "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutTargets.html",
    "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RemoveTargets.html",
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html",
]
QUEUE_MISSING = ("QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue")


class RuleMigrationProbe(LayerProbe):
    # Reuse established recording/redaction, findings, stack polling and deletion.
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config)
                        for name in ("sts", "events", "sqs", "cloudformation")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if (self.data["account"], self.data["region"], self.data.get("mode")) != (
                    self.account, REGION, "eventbridge-rule-migration"):
                raise RuntimeError("Not an approved rule-migration inventory")
            if not self.data["prefix"].startswith("stackd-cfn-rule-"):
                raise RuntimeError("Inventory prefix is outside probe scope")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "mode": "eventbridge-rule-migration", "captured_at": now(),
                "source": "Native public AWS endpoints; signed boto3; endpoint overrides disabled",
                "account": self.account, "region": REGION,
                "prefix": "stackd-cfn-rule-" + uuid.uuid4().hex[:12],
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__,
                        "models": {name: {"api_version": client.meta.service_model.api_version,
                                          "endpoint": client.meta.endpoint_url}
                                   for name, client in self.clients.items()}},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "Two unique custom buses, one scoped queue, one stack containing only an explicitly named rule; same-name collision seed on owned destination only; no default bus mutation or publishing",
                "authorization": {"ethics_review": "allow", "actor_required": self.actor,
                                  "account_required": self.account, "region_required": REGION},
                "bounds": {"stack_wait_seconds": 420, "poll_seconds": 3,
                           "routing_wait_seconds": 30, "cleanup_wait_seconds": 90,
                           "stack_event_pages": 10, "workflow_max_calls": 1200},
                "owned": {"buses": {}, "rules": {}, "stacks": {}},
                "calls": [], "findings": {}, "templates": {}, "sources": SOURCES,
                "calibration_gaps": [
                    "Public stack events and final rule/target states do not expose private CloudFormation API ordering or ownership tokens.",
                    "Absence of an event during a bounded SQS receive window is not proof of permanent non-delivery.",
                    "Only exact probe-owned collision rules are exercised; no unrelated or cross-account resources are touched.",
                    "Reverse custom-bus migration is measured; removal to default is not exercised to avoid sending events through unrelated default-bus rules.",
                ],
                "cleanup": {"complete": False}, "workflow_complete": False,
            }
        self.save()
        identity = self.call("identity-before-writes", "sts", "get_caller_identity")
        self.data["identity"] = identity
        self.save()
        if identity["Account"] != self.account or identity["Arn"] != self.actor:
            raise RuntimeError("Native writes require exact approved account and Delegated actor")
        for name, client in self.clients.items():
            if client.meta.region_name != REGION or not client.meta.endpoint_url.endswith(".amazonaws.com"):
                raise RuntimeError("Unexpected native endpoint for " + name)

    def call(self, label, service, operation, request=None, *, required=True):
        if not self.cleanup_phase and len(self.data["calls"]) >= self.data["bounds"]["workflow_max_calls"]:
            raise RuntimeError("Bounded workflow call limit reached; cleanup only")
        return super().call(label, service, operation, request, required=required)

    def documents(self):
        registry = self.call("rule-public-registry-schema", "cloudformation", "describe_type",
                             {"Type": "RESOURCE", "TypeName": TYPE})
        schema = json.loads(registry["Schema"])
        self.data["schema"] = schema
        self.finding("schema_contract", {key: schema.get(key) for key in
                     ("primaryIdentifier", "readOnlyProperties", "createOnlyProperties", "required", "tagging")})

    def rule_request(self, key, *, describe=False):
        bus = self.data["owned"]["buses"][key]["name"]
        return {"EventBusName": bus, "Name" if describe else "Rule": self.data["prefix"] + "-rule"}

    def setup(self):
        owned = self.data["owned"]
        for key in ("first", "second"):
            name = self.data["prefix"] + "-" + key
            self.absent(key + "-bus-name-absent", "events", "describe_event_bus",
                        {"Name": name}, "ResourceNotFoundException")
            owned["buses"][key] = {"name": name, "absence_verified": True, "creation_attempted": True,
                                   "arn": "arn:aws:events:" + REGION + ":" + self.account + ":event-bus/" + name}
            self.save()
            self.call(key + "-create-bus", "events", "create_event_bus", {
                "Name": name, "Tags": [{"Key": "stackd-probe", "Value": self.data["prefix"]}]})
            self.absent(key + "-rule-name-absent", "events", "describe_rule",
                        self.rule_request(key, describe=True), "ResourceNotFoundException")
            owned["rules"][key] = {"absence_verified": True,
                "arn": "arn:aws:events:" + REGION + ":" + self.account + ":rule/" + name + "/" + self.data["prefix"] + "-rule"}
            self.save()
        missing = self.data["prefix"] + "-missing"
        self.absent("missing-bus-absence", "events", "describe_event_bus", {"Name": missing}, "ResourceNotFoundException")
        self.data["missing_bus"] = missing
        name = self.data["prefix"] + "-queue"
        self.call("queue-name-absent", "sqs", "get_queue_url", {"QueueName": name}, required=False)
        if self.code() not in QUEUE_MISSING:
            raise RuntimeError("Queue name absence not established")
        owned["queue"] = {"name": name, "absence_verified": True, "creation_attempted": True}
        self.save()
        queue = owned["queue"]
        queue["url"] = self.call("create-owned-queue", "sqs", "create_queue", {
            "QueueName": name, "Attributes": {"MessageRetentionPeriod": "600"},
            "tags": {"stackd-probe": self.data["prefix"]}})["QueueUrl"]
        self.save()
        queue["arn"] = self.call("queue-identity", "sqs", "get_queue_attributes", {
            "QueueUrl": queue["url"], "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
        self.save()
        policy = {"Version": "2012-10-17", "Statement": [{
            "Sid": "ExactOwnedEventRulesOnly", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": queue["arn"], "Condition": {
                "ArnEquals": {"aws:SourceArn": [rule["arn"] for rule in owned["rules"].values()]},
                "StringEquals": {"aws:SourceAccount": self.account}}}]}
        self.call("queue-exact-rule-policy", "sqs", "set_queue_attributes", {
            "QueueUrl": queue["url"], "Attributes": {"Policy": json.dumps(policy)}})
        self.call("queue-policy-observed", "sqs", "get_queue_attributes", {
            "QueueUrl": queue["url"], "AttributeNames": ["QueueArn", "Policy"]})

    def template(self, bus):
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Rule": {
            "Type": TYPE, "Properties": {
                "Name": self.data["prefix"] + "-rule", "EventBusName": bus,
                "Description": "Exact owned CloudFormation migration rule", "State": "ENABLED",
                "EventPattern": {"source": [self.data["prefix"]]},
                "Targets": [{"Id": "stack-target", "Arn": self.data["owned"]["queue"]["arn"],
                             "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}]}}},
            "Outputs": {"RuleRef": {"Value": {"Ref": "Rule"}},
                        "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}}}}

    def snapshot(self, label):
        result = {}
        for key in self.data["owned"]["rules"]:
            rule = self.call(label + "-" + key + "-describe", "events", "describe_rule",
                             self.rule_request(key, describe=True), required=False)
            result[key] = {"describe_code": self.code(), "rule": rule}
            if self.code() not in ("Success", "ResourceNotFoundException"):
                raise RuntimeError("Unexpected rule observation failure: " + self.code())
            if rule:
                result[key]["targets"] = self.call(label + "-" + key + "-targets", "events", "list_targets_by_rule",
                                                  self.rule_request(key))
                result[key]["tags"] = self.call(label + "-" + key + "-tags", "events", "list_tags_for_resource",
                                               {"ResourceARN": rule["Arn"]})
        return self.finding(label + "-native-state", result)

    def stack(self, label, bus, update=False):
        stacks = self.data["owned"]["stacks"]
        template = self.template(bus)
        self.data["templates"][label] = copy.deepcopy(template)
        if not update:
            name = self.data["prefix"] + "-stack"
            self.absent(label + "-stack-name-absent", "cloudformation", "describe_stacks", {"StackName": name}, "ValidationError")
            stacks["rule"] = {"name": name, "creation_attempted": True}
        for key, owned_bus in self.data["owned"]["buses"].items():
            if bus in (owned_bus["name"], owned_bus["arn"]) or (bus is None and owned_bus["name"] == "default"):
                self.data["owned"]["rules"][key]["creation_attempted"] = True
        self.save()
        request = {"StackName": stacks["rule"].get("id", stacks["rule"]["name"]),
                   "TemplateBody": json.dumps(template), "ClientRequestToken": self.data["prefix"] + "-" + label}
        if not update:
            request["Tags"] = [{"Key": "stackd-probe", "Value": self.data["prefix"]}]
        submitted = self.call(label + "-submit", "cloudformation", "update_stack" if update else "create_stack", request, required=False)
        result = {"submission_code": self.code()}
        self.data["findings"][label] = result
        self.save()
        if submitted:
            stacks["rule"]["id"] = submitted["StackId"]
            self.save()
            try:
                current = self.wait_owned_stack("rule", label)
                result.update(stack_status=current["StackStatus"], outputs=current.get("Outputs", []))
            finally:
                events, token = [], None
                for page in range(self.data["bounds"]["stack_event_pages"]):
                    event_request = {"StackName": submitted["StackId"]}
                    if token:
                        event_request["NextToken"] = token
                    response = self.call(label + "-events-" + str(page), "cloudformation", "describe_stack_events", event_request)
                    events.extend(response.get("StackEvents", []))
                    token = response.get("NextToken")
                    if not token:
                        break
                result["stack_events"] = events
                result["stack_events_truncated"] = bool(token)
                result["resources"] = self.call(label + "-resources", "cloudformation", "describe_stack_resources",
                                                {"StackName": submitted["StackId"]}).get("StackResources", [])
                self.call(label + "-get-template", "cloudformation", "get_template", {"StackName": submitted["StackId"]})
                self.save()
        result["native_state"] = self.snapshot(label)
        return self.finding(label, result)

    def routing(self, label):
        queue = self.data["owned"]["queue"]
        expected = {}
        for key, bus in self.data["owned"]["buses"].items():
            marker = self.data["prefix"] + ":" + label + ":" + key
            expected[key] = marker
            result = self.call(label + "-publish-" + key, "events", "put_events", {"Entries": [{
                "EventBusName": bus["name"], "Source": self.data["prefix"], "DetailType": "owned-migration-probe",
                "Detail": json.dumps({"marker": marker, "bus": key})}]})
            if result.get("FailedEntryCount"):
                raise RuntimeError("Owned event publication failed")
        received = []
        deadline = time.monotonic() + self.data["bounds"]["routing_wait_seconds"]
        attempt = 0
        while time.monotonic() < deadline:
            response = self.call(label + "-receive-" + str(attempt), "sqs", "receive_message", {
                "QueueUrl": queue["url"], "MaxNumberOfMessages": 10, "WaitTimeSeconds": 5})
            for message in response.get("Messages", []):
                body = json.loads(message["Body"])
                received.append({"message_id": message["MessageId"], "event": body})
                self.call(label + "-delete-message-" + str(len(received)), "sqs", "delete_message", {
                    "QueueUrl": queue["url"], "ReceiptHandle": message["ReceiptHandle"]})
            attempt += 1
        observed = {key: [item for item in received if item["event"].get("detail", {}).get("marker") == marker]
                    for key, marker in expected.items()}
        return self.finding(label + "-routing", {
            "sent_markers": expected, "received": received, "observed": observed,
            "observed_buses": [key for key, items in observed.items() if items],
            "bounded_receive_seconds": self.data["bounds"]["routing_wait_seconds"]})

    def require_success(self, result):
        if result.get("stack_status") not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            raise RuntimeError("Expected successful stack transition: " + json.dumps(document(result)))

    def workflow(self):
        self.documents()
        self.setup()
        buses = self.data["owned"]["buses"]
        self.require_success(self.stack("initial-first", buses["first"]["name"]))
        initial = self.routing("initial-first")
        if "first" not in initial["observed_buses"]:
            raise RuntimeError("Initial actual event delivery was not observed")
        self.require_success(self.stack("migrate-second", buses["second"]["name"], update=True))
        self.routing("migrate-second")
        self.require_success(self.stack("reverse-first", buses["first"]["name"], update=True))
        self.routing("reverse-first")
        missing = self.stack("missing-destination", self.data["missing_bus"], update=True)
        self.routing("missing-destination")
        if missing.get("stack_status") != "UPDATE_ROLLBACK_COMPLETE":
            raise RuntimeError("Missing destination did not return to a bounded stable rollback")
        # If migration leaves an owned copy, remove that exact copy before seeding
        # the collision; preserve before/after observations instead of assuming it.
        self.remove_rule("second", "collision-preparation")
        self.data["owned"]["rules"]["second"]["native_collision_creation_attempted"] = True
        self.save()
        self.call("seed-owned-destination-collision", "events", "put_rule", {
            **self.rule_request("second", describe=True), "State": "DISABLED",
            "Description": "Exact owned native collision sentinel",
            "EventPattern": json.dumps({"source": [self.data["prefix"] + ".collision"]}),
            "Tags": [{"Key": "stackd-probe", "Value": self.data["prefix"]},
                     {"Key": "collision-sentinel", "Value": "native"}]})
        target = self.call("seed-owned-collision-target", "events", "put_targets", {
            **self.rule_request("second"), "Targets": [{"Id": "native-sentinel", "Arn": self.data["owned"]["queue"]["arn"]}]})
        if target.get("FailedEntryCount"):
            raise RuntimeError("Could not seed exact-owned collision target")
        self.snapshot("collision-before-update")
        collision = self.stack("owned-destination-collision", buses["second"]["name"], update=True)
        self.routing("owned-destination-collision")
        if collision.get("stack_status") not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError("Collision did not reach a bounded stable state")
        self.data["workflow_complete"] = True
        self.data["finished_at"] = now()
        self.save()

    def remove_rule(self, key, label):
        owned = self.data["owned"]["rules"][key]
        rule = self.call(label + "-" + key + "-identity", "events", "describe_rule", self.rule_request(key, describe=True), required=False)
        if not rule and self.code() == "ResourceNotFoundException":
            return
        if not owned.get("absence_verified") or rule.get("Arn") != owned["arn"]:
            raise RuntimeError("Rule identity outside exact pre-write inventory")
        tags = self.call(label + "-" + key + "-tags", "events", "list_tags_for_resource", {"ResourceARN": owned["arn"]})
        if {tag["Key"]: tag["Value"] for tag in tags.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
            raise RuntimeError("Rule no longer has exact probe ownership tag")
        targets = self.call(label + "-" + key + "-targets", "events", "list_targets_by_rule", self.rule_request(key))
        if targets.get("NextToken"):
            raise RuntimeError("Unexpected target count outside bounded inventory")
        if targets.get("Targets"):
            for target in targets["Targets"]:
                if target["Id"] not in ("stack-target", "native-sentinel") or target["Arn"] != self.data["owned"]["queue"]["arn"]:
                    raise RuntimeError("Refusing removal of unexpected target")
            removed = self.call(label + "-" + key + "-remove-targets", "events", "remove_targets", {
                **self.rule_request(key), "Ids": [target["Id"] for target in targets["Targets"]]})
            if removed.get("FailedEntryCount"):
                raise RuntimeError("Failed exact-owned target removal")
        self.call(label + "-" + key + "-delete-rule", "events", "delete_rule", self.rule_request(key, describe=True))
        self.absent(label + "-" + key + "-absent", "events", "describe_rule", self.rule_request(key, describe=True), "ResourceNotFoundException")

    def cleanup(self):
        self.cleanup_phase = True
        owned, errors = self.data["owned"], []

        def attempt(label, action):
            try:
                action()
            except Exception as error:
                errors.append(label + ": " + str(error))
                self.save()

        def remove_stack():
            status = self.delete_stack("rule", "cleanup-stack")
            if status not in ("DELETE_COMPLETE", "ABSENT"):
                raise RuntimeError("Stack deletion incomplete: " + status)

        def remove_queue():
            queue = owned["queue"]
            current = self.call("cleanup-queue-url", "sqs", "get_queue_url", {"QueueName": queue["name"]}, required=False)
            if not current and self.code() in QUEUE_MISSING:
                return
            queue["url"] = current["QueueUrl"]
            self.save()
            tags = self.call("cleanup-queue-tags", "sqs", "list_queue_tags", {"QueueUrl": queue["url"]})
            if tags.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                raise RuntimeError("Queue ownership tag changed")
            self.call("cleanup-delete-queue", "sqs", "delete_queue", {"QueueUrl": queue["url"]})
            deadline = time.monotonic() + self.data["bounds"]["cleanup_wait_seconds"]
            while time.monotonic() < deadline:
                self.call("cleanup-queue-absence", "sqs", "get_queue_url", {"QueueName": queue["name"]}, required=False)
                if self.code() in QUEUE_MISSING:
                    return
                if self.code() != "Success":
                    raise RuntimeError("Unexpected queue cleanup observation: " + self.code())
                time.sleep(3)
            raise RuntimeError("Queue deletion observation deadline expired")

        def remove_bus(key):
            bus = owned["buses"][key]
            current = self.call("cleanup-" + key + "-bus-identity", "events", "describe_event_bus", {"Name": bus["name"]}, required=False)
            if not current and self.code() == "ResourceNotFoundException":
                return
            if current.get("Arn") != bus["arn"]:
                raise RuntimeError("Bus identity changed")
            tags = self.call("cleanup-" + key + "-bus-tags", "events", "list_tags_for_resource", {"ResourceARN": bus["arn"]})
            if {tag["Key"]: tag["Value"] for tag in tags.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                raise RuntimeError("Bus ownership tag changed")
            rules = self.call("cleanup-" + key + "-bus-rules", "events", "list_rules", {"EventBusName": bus["name"]})
            if rules.get("Rules") or rules.get("NextToken"):
                raise RuntimeError("Refusing bus deletion while rules remain")
            self.call("cleanup-" + key + "-delete-bus", "events", "delete_event_bus", {"Name": bus["name"]})
            self.absent("cleanup-" + key + "-bus-absent", "events", "describe_event_bus", {"Name": bus["name"]}, "ResourceNotFoundException")

        if "rule" in owned["stacks"]:
            attempt("stack", remove_stack)
        for key in owned["rules"]:
            attempt("rule " + key, lambda key=key: self.remove_rule(key, "cleanup"))
        if "queue" in owned:
            attempt("queue", remove_queue)
        for key in owned["buses"]:
            if owned["buses"][key]["name"] != "default":
                attempt("bus " + key, lambda key=key: remove_bus(key))
        self.data["cleanup"].update(complete=not errors, errors=errors, finished_at=now(),
            boundary="Exact owned names verified absent; deleted stack ARN retains DELETE_COMPLETE history")
        self.save()
        if errors:
            raise RuntimeError("Exact-owned cleanup incomplete: " + "; ".join(errors))


class RuleIdentityProbe(RuleMigrationProbe):
    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only:
            self.data["scenario"] = "identity-only"
            self.data["scope"] = "One unique custom bus and one disabled targetless named rule stack; exact rule name reserved on default and custom bus; no events, queue, targets, schedule or default bus policy changes"
            self.data["calibration_gaps"] = [
                "Control-plane identity only; no events or target delivery are exercised.",
                "Default bus itself is shared and never mutated or deleted; only the exact preverified unique rule is owned.",
                "Public stack events do not expose private CloudFormation API ordering or ownership tokens.",
            ]
            self.save()

    def setup(self):
        owned = self.data["owned"]
        name = self.data["prefix"] + "-custom"
        self.absent("custom-bus-name-absent", "events", "describe_event_bus",
                    {"Name": name}, "ResourceNotFoundException")
        owned["buses"]["custom"] = {
            "name": name, "arn": "arn:aws:events:" + REGION + ":" + self.account + ":event-bus/" + name,
            "absence_verified": True, "creation_attempted": True}
        self.save()
        self.call("create-owned-custom-bus", "events", "create_event_bus", {
            "Name": name, "Tags": [{"Key": "stackd-probe", "Value": self.data["prefix"]}]})
        default = self.call("default-bus-read-only", "events", "describe_event_bus", {"Name": "default"})
        expected = "arn:aws:events:" + REGION + ":" + self.account + ":event-bus/default"
        if default["Arn"] != expected:
            raise RuntimeError("Default bus identity is outside approved account/region")
        owned["buses"]["default"] = {"name": "default", "arn": expected, "shared_read_only": True}
        self.save()
        for key, bus in owned["buses"].items():
            self.absent(key + "-rule-name-absent", "events", "describe_rule",
                        self.rule_request(key, describe=True), "ResourceNotFoundException")
            path = "" if key == "default" else bus["name"] + "/"
            owned["rules"][key] = {
                "absence_verified": True,
                "arn": "arn:aws:events:" + REGION + ":" + self.account + ":rule/" + path + self.data["prefix"] + "-rule"}
            self.save()

    def template(self, bus):
        properties = {
            "Name": self.data["prefix"] + "-rule", "State": "DISABLED",
            "Description": "Exact owned targetless identity calibration",
            "EventPattern": {"source": [self.data["prefix"]]}}
        if bus is not None:
            properties["EventBusName"] = bus
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Rule": {
            "Type": TYPE, "Properties": properties}}, "Outputs": {
                "RuleRef": {"Value": {"Ref": "Rule"}},
                "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}}}}

    def workflow(self):
        self.documents()
        self.setup()
        self.require_success(self.stack("omitted-default", None))
        buses = self.data["owned"]["buses"]
        for label, bus in (
                ("explicit-default-name", "default"),
                ("equivalent-default-arn", buses["default"]["arn"]),
                ("custom-bus-name", buses["custom"]["name"]),
                ("equivalent-custom-arn", buses["custom"]["arn"])):
            result = self.stack(label, bus, update=True)
            if result.get("stack_status") not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
                if result["submission_code"] != "ValidationError":
                    raise RuntimeError("Identity control did not reach a bounded stable state")
                self.finding(label + "-submission-rejected", {
                    "response": next(call for call in self.data["calls"] if call["label"] == label + "-submit")})
        self.data["workflow_complete"] = True
        self.data["finished_at"] = now()
        self.save()


class RuleChangeSetProbe(RuleIdentityProbe):
    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only:
            self.data["scenario"] = "changeset-only"
            self.data["scope"] = "One owned custom bus and disabled targetless rule stack; two unexecuted change sets, no default-bus writes or event publishing"
            self.save()

    def cleanup(self):
        super().cleanup()
        self.data["cleanup"]["complete"] = False
        self.save()
        for index, change_set in enumerate(self.data["owned"].get("change_sets", [])):
            self.call("cleanup-delete-plan-" + str(index), "cloudformation", "delete_change_set",
                      {"ChangeSetName": change_set})
            self.absent("cleanup-plan-absent-" + str(index), "cloudformation", "describe_change_set",
                        {"ChangeSetName": change_set}, "ChangeSetNotFound")
        self.data["cleanup"]["complete"] = True
        self.save()

    def workflow(self):
        self.documents()
        self.setup()
        buses = self.data["owned"]["buses"]
        self.require_success(self.stack("initial-custom", buses["custom"]["name"]))
        stack = self.data["owned"]["stacks"]["rule"]["id"]
        for label, bus in (("equivalent-custom-arn", buses["custom"]["arn"]),
                           ("proposed-default", "default")):
            template = self.template(bus)
            self.data["templates"][label] = template
            self.save()
            created = self.call(label + "-create-plan", "cloudformation", "create_change_set", {
                "StackName": stack, "ChangeSetName": self.data["prefix"] + "-" + label,
                "ChangeSetType": "UPDATE", "TemplateBody": json.dumps(template)})
            self.data["owned"].setdefault("change_sets", []).append(created["Id"])
            self.save()
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                result = self.call(label + "-describe-plan", "cloudformation", "describe_change_set", {
                    "ChangeSetName": created["Id"], "IncludePropertyValues": True})
                if result["Status"] in ("CREATE_COMPLETE", "FAILED"):
                    self.finding(label + "-plan", result)
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Change-set planning deadline expired")
        self.data["workflow_complete"] = True
        self.data["finished_at"] = now()
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/eventbridge_rule_migration.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--identity-only", action="store_true",
                       help="Separate disabled targetless default/custom rule identity control; use a new --output path")
    modes.add_argument("--changeset-only", action="store_true",
                       help="Measure unexecuted rule replacement plans; use a new --output path")
    args = parser.parse_args()
    scenario = "changeset-only" if args.changeset_only else "identity-only" if args.identity_only else "migration"
    if args.cleanup_only:
        scenario = json.loads(args.output.read_text()).get("scenario", "migration")
    probe = {"identity-only": RuleIdentityProbe, "changeset-only": RuleChangeSetProbe,
             "migration": RuleMigrationProbe}[scenario](args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            probe.workflow()
    except Exception as error:
        probe.data.setdefault("failures", []).append({"at": now(), "error": str(error)})
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
