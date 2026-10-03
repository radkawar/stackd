#!/usr/bin/env python3
"""Capture disabled-only native CFN self-managed Kafka admission and lifecycle.

Obtain fresh ethics approval before running, including --cleanup-only recovery.
Only .invalid bootstrap hosts and exact-owned dummy authentication are permitted.
No function is invoked, mapping enabled, broker provisioned or VPC modified.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import time
import urllib.request
import uuid

import boto3
import botocore
from botocore.config import Config

from cloudformation_lambda_kinesis_mapping_probe import KinesisMappingProbe, TYPE
from cloudformation_lambda_version_probe import VersionProbe
from cloudtrail_service_probe import REGION, now


CFN_DOCS = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/"
LAMBDA_DOCS = "https://docs.aws.amazon.com/lambda/latest/"
SOURCES = [CFN_DOCS + "aws-resource-lambda-eventsourcemapping.md"] + [
    CFN_DOCS + "aws-properties-lambda-eventsourcemapping-" + name + ".md"
    for name in ("selfmanagedeventsource", "endpoints", "selfmanagedkafkaeventsourceconfig", "sourceaccessconfiguration")
] + [LAMBDA_DOCS + "api/API_" + name + ".md" for name in
     ("CreateEventSourceMapping", "UpdateEventSourceMapping", "SelfManagedEventSource", "SelfManagedKafkaEventSourceConfig")
] + [LAMBDA_DOCS + "dg/" + name + ".md" for name in
     ("with-kafka-configure", "kafka-cluster-auth", "kafka-esm-create", "kafka-esm-parameters", "kafka-starting-positions")]


class SelfManagedKafkaProbe(KinesisMappingProbe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        approval = json.loads(args.ethics_review.read_text())
        if not approval.get("allowed") or (approval.get("account"), approval.get("region"), approval.get("actor")) != (self.account, REGION, self.actor):
            raise RuntimeError("Fresh approval must name the exact approved account, region and actor")
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config) for name in
                        ("sts", "iam", "lambda", "cloudformation", "secretsmanager")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if ((self.data["account"], self.data["region"]) != (self.account, REGION) or
                    not self.data["prefix"].startswith("stackd-cfn-smk-")):
                raise RuntimeError("Not an approved self-managed Kafka inventory")
            self.data.setdefault("recovery_reviews", []).append(approval)
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "source": "Native AWS public endpoints; signed boto3; endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION,
                "prefix": "stackd-cfn-smk-" + uuid.uuid4().hex[:12], "ethics_review": approval,
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__, "models": {
                    name: {"api_version": client.meta.service_model.api_version, "endpoint": client.meta.endpoint_url}
                    for name, client in self.clients.items()}},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "One non-invoked concurrency-zero function, exact-secret-read role, dummy secret, disabled-only mapping stack and reserved .invalid endpoints; no brokers/VPC/public grants/KMS keys",
                "bounds": {"stack_wait_seconds": 240, "resource_wait_seconds": 120, "poll_seconds": 3,
                           "maximum_stack_updates": 10 if args.contract_only else (8 if args.position_only else 18)},
                "owned": {"stacks": {}, "streams": {}, "mappings": []},
                "calls": [], "findings": {}, "templates": {}, "sources": SOURCES, "documentation": [],
                "calibration_gaps": [
                    "Disabled control-plane lifecycle only; no actual broker connectivity, records or invocations.",
                    "KmsKeyArn, provisioned pollers, destinations, schema registries and qualified function retargeting are not exercised.",
                    "Private CFN ownership tokens and local runtime equivalence are not measured.",
                ], "cleanup": {"complete": False}, "workflow_complete": False,
                "mode": "position-authentication-planning" if args.contract_only else ("position-and-metrics" if args.position_only else "full-lifecycle"),
            }
        for name, client in self.clients.items():
            expected = "https://iam.amazonaws.com" if name == "iam" else "https://" + name + "." + REGION + ".amazonaws.com"
            if client.meta.endpoint_url != expected:
                raise RuntimeError("Unexpected native service endpoint: " + client.meta.endpoint_url)
        self.save()
        identity = self.call("identity-before-writes", "sts", "get_caller_identity")
        self.data["identity"] = identity
        self.save()
        if (identity["Account"], identity["Arn"]) != (self.account, self.actor):
            raise RuntimeError("Native writes require the approved Delegated identity")

    def documents(self):
        for source in SOURCES:
            try:
                with urllib.request.urlopen(source, timeout=30) as response:
                    raw = response.read()
                self.data["documentation"].append({"source": source, "captured_at": now(),
                    "source_sha256": hashlib.sha256(raw).hexdigest(), "content": raw.decode()})
            except Exception as error:
                self.data["calibration_gaps"].append(source + ": " + str(error))
            self.save()
        super().documents()
        model = self.clients["lambda"].meta.service_model
        self.data["sdk"]["mapping_operations"] = {
            name: {"input": {key: shape.type_name for key, shape in model.operation_model(name).input_shape.members.items()},
                   "required": model.operation_model(name).input_shape.required_members}
            for name in ("CreateEventSourceMapping", "UpdateEventSourceMapping")}
        self.save()

    def setup(self):
        owned, prefix = self.data["owned"], self.data["prefix"]
        name = prefix + "-auth"
        self.absent("secret-name-absent", "secretsmanager", "describe_secret", {"SecretId": name}, "ResourceNotFoundException")
        owned["secret"] = {"name": name, "absence_verified": True, "creation_attempted": True}
        self.save()
        secret = self.call("create-owned-dummy-secret", "secretsmanager", "create_secret", {
            "Name": name, "Description": "Disposable disabled-only stackd CFN Kafka calibration; no broker account",
            "SecretString": json.dumps({"username": prefix, "password": "dummy-not-a-real-broker-credential"}),
            "Tags": [{"Key": "stackd-probe", "Value": prefix}]})
        owned["secret"]["arn"] = secret["ARN"]
        self.save()
        VersionProbe.setup(self)
        self.call("disable-function-concurrency", "lambda", "put_function_concurrency", {
            "FunctionName": owned["function"]["arn"], "ReservedConcurrentExecutions": 0})
        self.call("confirm-function-concurrency", "lambda", "get_function_concurrency", {
            "FunctionName": owned["function"]["arn"]})
        owned["role"]["policy"] = "owned-authentication-secret"
        self.save()
        self.call("put-exact-secret-read-policy", "iam", "put_role_policy", {
            "RoleName": owned["role"]["name"], "PolicyName": owned["role"]["policy"],
            "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret["ARN"]}]})})
        self.call("read-exact-secret-policy", "iam", "get_role_policy", {
            "RoleName": owned["role"]["name"], "PolicyName": owned["role"]["policy"]})
        time.sleep(15)

    def endpoints(self):
        return [self.data["prefix"] + ".invalid:9092", self.data["prefix"] + "-replacement.invalid:9092"]

    def template(self, properties):
        if properties.get("Enabled") is not False or properties.get("FunctionName") != self.data["owned"]["function"]["arn"]:
            raise RuntimeError("Only disabled mappings targeting the exact-owned function are allowed")
        endpoints = properties.get("SelfManagedEventSource", {}).get("Endpoints", {}).get("KafkaBootstrapServers", [])
        if len(endpoints) != 1 or endpoints[0] not in self.endpoints() or "EventSourceArn" in properties:
            raise RuntimeError("Only approved .invalid Kafka endpoints are allowed")
        for access in properties.get("SourceAccessConfigurations", []):
            if access["URI"] != self.data["owned"]["secret"]["arn"] or access["Type"] not in ("SASL_SCRAM_512_AUTH", "SASL_SCRAM_256_AUTH"):
                raise RuntimeError("Source authentication must use only the exact-owned dummy secret")
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
            "Mapping": {"Type": TYPE, "Properties": copy.deepcopy(properties)}}, "Outputs": {
                "MappingRef": {"Value": {"Ref": "Mapping"}},
                "MappingId": {"Value": {"Fn::GetAtt": ["Mapping", "Id"]}},
                "MappingArn": {"Value": {"Fn::GetAtt": ["Mapping", "EventSourceMappingArn"]}}}}

    def transition(self, label, current, proposed):
        before = self.data["findings"]["current_mapping"]
        updates = sum(row["operation"] == "UpdateStack" for row in self.data["calls"])
        if updates >= self.data["bounds"]["maximum_stack_updates"]:
            raise RuntimeError("Approved stack update bound exhausted")
        result = self.stack(label, proposed, update=True)
        status = result.get("stack_status")
        if status not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError(label + ": unexpected native transition " + str(result))
        after = result["mapping"]
        self.finding(label + "-transition", {"status": status, "old_uuid": before["UUID"], "new_uuid": after["UUID"],
            "replaced": before["UUID"] != after["UUID"], "before": before, "after": after})
        if before["UUID"] != after["UUID"]:
            self.absent(label + "-old-uuid-absent", "lambda", "get_event_source_mapping", {"UUID": before["UUID"]}, "ResourceNotFoundException")
        self.data["findings"]["current_mapping"] = after
        self.save()
        return copy.deepcopy(proposed if status == "UPDATE_COMPLETE" else current)

    def workflow(self):
        self.documents()
        self.setup()
        prefix, owned = self.data["prefix"], self.data["owned"]
        current = {"FunctionName": owned["function"]["arn"], "Enabled": False,
            "SelfManagedEventSource": {"Endpoints": {"KafkaBootstrapServers": [self.endpoints()[0]]}},
            "Topics": [prefix + "-topic"], "StartingPosition": "LATEST",
            "SelfManagedKafkaEventSourceConfig": {"ConsumerGroupId": prefix + "-group"},
            "SourceAccessConfigurations": [{"Type": "SASL_SCRAM_512_AUTH", "URI": owned["secret"]["arn"]}]}
        initial = self.stack("fresh-defaults", current)
        if initial.get("stack_status") != "CREATE_COMPLETE":
            self.finding("initial-admission-boundary", {"positive_mapping_observed": False,
                "native_result": initial, "boundary": "No lifecycle claims; no widening resources or permissions to satisfy admission"})
            raise RuntimeError("Disabled .invalid Kafka CFN admission did not complete; retained exact native prerequisite/error")
        fresh = initial["mapping"]
        self.finding("current_mapping", fresh)
        if self.args.position_only or self.args.contract_only:
            self.position_workflow(current)
            self.data["workflow_complete"] = True
            self.save()
            return
        settings = {"BatchSize": 17, "MaximumBatchingWindowInSeconds": 2,
            "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"value": {"probe": [prefix]}})}]},
            "Tags": [{"Key": "owned-setting", "Value": prefix}]}
        current = self.transition("explicit-settings", current, {**current, **settings})
        explicit = copy.deepcopy(self.data["findings"]["current_mapping"])
        current = self.transition("remove-settings", current, {key: value for key, value in current.items() if key not in settings})
        removed = self.data["findings"]["current_mapping"]
        self.finding("property-removal", {"same_uuid": fresh["UUID"] == explicit["UUID"] == removed["UUID"],
            "properties": {key: {"fresh": fresh.get(key), "explicit": explicit.get(key), "removed": removed.get(key)} for key in settings},
            "explicit_tags": self.data["findings"]["explicit-settings"].get("tags"),
            "removed_tags": self.data["findings"]["remove-settings"].get("tags")})
        current = self.transition("explicit-empty-filter", current, {**current, "FilterCriteria": {}})
        current = self.transition("change-consumer-group", current, {**current,
            "SelfManagedKafkaEventSourceConfig": {"ConsumerGroupId": prefix + "-other-group"}})
        current = self.transition("remove-consumer-group-config", current,
            {key: value for key, value in current.items() if key != "SelfManagedKafkaEventSourceConfig"})
        current = self.transition("change-topic", current, {**current, "Topics": [prefix + "-other-topic"]})
        current = self.transition("remove-topics", current, {key: value for key, value in current.items() if key != "Topics"})
        current = self.transition("change-source-authentication", current, {**current,
            "SourceAccessConfigurations": [{"Type": "SASL_SCRAM_256_AUTH", "URI": owned["secret"]["arn"]}]})
        current = self.transition("remove-source-access", current,
            {key: value for key, value in current.items() if key != "SourceAccessConfigurations"})
        current = self.transition("restore-source-access", current, {**current,
            "SourceAccessConfigurations": [{"Type": "SASL_SCRAM_512_AUTH", "URI": owned["secret"]["arn"]}]})
        current = self.transition("replace-starting-position", current, {**current, "StartingPosition": "TRIM_HORIZON"})
        timestamp = int(time.time()) - 60
        current = self.transition("replace-starting-timestamp", current, {**current,
            "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": timestamp})
        current = self.transition("replace-source-endpoint", current, {**current,
            "SelfManagedEventSource": {"Endpoints": {"KafkaBootstrapServers": [self.endpoints()[1]]}}})
        if current.get("StartingPosition") == "AT_TIMESTAMP":
            current = self.transition("replace-timestamp-only", current, {**current, "StartingPositionTimestamp": timestamp + 1})
            self.transition("remove-starting-timestamp", current,
                {key: value for key, value in current.items() if key != "StartingPositionTimestamp"})
        self.data["workflow_complete"] = True
        self.save()

    def position_workflow(self, current):
        if self.args.contract_only:
            self.group_change_set(current)
            secret = self.data["owned"]["secret"]["arn"]
            for label, auth in (("authentication-256", "SASL_SCRAM_256_AUTH"),
                                ("authentication-omitted", None),
                                ("authentication-reintroduced-512", "SASL_SCRAM_512_AUTH"),
                                ("authentication-present-256", "SASL_SCRAM_256_AUTH"),
                                ("authentication-present-512", "SASL_SCRAM_512_AUTH")):
                proposed = {key: value for key, value in current.items() if key != "SourceAccessConfigurations"}
                if auth:
                    proposed["SourceAccessConfigurations"] = [{"Type": auth, "URI": secret}]
                current = self.transition(label, current, proposed)
        else:
            current = self.transition("explicit-metrics", current, {**current, "MetricsConfig": {"Metrics": ["EventCount"]}})
            if "MetricsConfig" in current:
                current = self.transition("remove-metrics", current,
                    {key: value for key, value in current.items() if key != "MetricsConfig"})
        current = self.transition("remove-starting-position", current,
            {key: value for key, value in current.items() if key != "StartingPosition"})
        omitted = {key: value for key, value in current.items() if key != "StartingPosition"}
        current = self.transition("replace-source-without-starting-position", current, {**omitted,
            "SelfManagedEventSource": {"Endpoints": {"KafkaBootstrapServers": [self.endpoints()[1]]}}})
        timestamp = int(time.time()) - 60
        old_endpoint = current["SelfManagedEventSource"]["Endpoints"]["KafkaBootstrapServers"][0]
        new_endpoint = next(endpoint for endpoint in self.endpoints() if endpoint != old_endpoint)
        current = self.transition("replace-source-with-starting-timestamp", current, {**current,
            "SelfManagedEventSource": {"Endpoints": {"KafkaBootstrapServers": [new_endpoint]}},
            "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": timestamp})
        if current.get("StartingPosition") == "AT_TIMESTAMP":
            current = self.transition("replace-timestamp-only", current, {**current, "StartingPositionTimestamp": timestamp + 1})
            self.transition("remove-starting-timestamp", current,
                {key: value for key, value in current.items() if key != "StartingPositionTimestamp"})

    def group_change_set(self, current):
        stack = self.data["owned"]["stacks"]["mapping"]
        name = self.data["prefix"] + "-group-plan"
        request = {"StackName": stack["id"], "ChangeSetName": name}
        self.absent("group-change-set-name-absent", "cloudformation", "describe_change_set",
                    request, "ChangeSetNotFound")
        self.data["owned"]["change_set"] = {**request, "absence_verified": True, "creation_attempted": True}
        self.save()
        proposed = {**current, "SelfManagedKafkaEventSourceConfig": {"ConsumerGroupId": self.data["prefix"] + "-planned-group"}}
        template = self.template(proposed)
        self.data["templates"]["group-change-set"] = template
        self.save()
        value = self.call("group-change-set-create", "cloudformation", "create_change_set", {
            **request, "ChangeSetType": "UPDATE", "TemplateBody": json.dumps(template)})
        self.data["owned"]["change_set"]["id"] = value["Id"]
        self.save()
        result = self.wait_resource("group-change-set-ready", "cloudformation", "describe_change_set",
            {"ChangeSetName": value["Id"]}, lambda value, code: value.get("Status") in ("CREATE_COMPLETE", "FAILED"))
        self.finding("group-change-set", {"executed": False, "description": result})
        if result["Status"] != "CREATE_COMPLETE":
            raise RuntimeError("Unexecuted group change set did not complete")
        self.delete_change_set()

    def delete_change_set(self):
        change_set = self.data["owned"].get("change_set")
        if not change_set:
            return
        request = {"ChangeSetName": change_set.get("id", change_set["ChangeSetName"]), "StackName": change_set["StackName"]}
        value = self.call("cleanup-change-set-identity", "cloudformation", "describe_change_set", request, required=False)
        if not value and self.code() == "ChangeSetNotFound":
            return
        if value.get("StackId") != change_set["StackName"] or value.get("ChangeSetName") != change_set["ChangeSetName"]:
            raise RuntimeError("Change set identity changed; refusing deletion")
        self.call("cleanup-delete-change-set", "cloudformation", "delete_change_set", request)
        self.wait_resource("cleanup-change-set-absent", "cloudformation", "describe_change_set", request,
                           lambda value, code: code == "ChangeSetNotFound")
        change_set["deleted"] = True
        self.save()

    def source_arns(self):
        # Self-managed sources have no EventSourceArn. Exact endpoints are fenced
        # below before the inherited cleanup handles the exact observed UUIDs.
        return [None]

    def cleanup(self):
        self.cleanup_phase = True
        owned = self.data["owned"]
        self.delete_change_set()
        if owned.get("function", {}).get("arn"):
            marker = None
            while True:
                request = {"FunctionName": owned["function"]["arn"]}
                if marker:
                    request["Marker"] = marker
                result = self.call("cleanup-function-mapping-inventory", "lambda", "list_event_source_mappings", request)
                for mapping in result.get("EventSourceMappings", []):
                    endpoints = mapping.get("SelfManagedEventSource", {}).get("Endpoints", {}).get("KAFKA_BOOTSTRAP_SERVERS", [])
                    if mapping.get("FunctionArn") != owned["function"]["arn"] or len(endpoints) != 1 or endpoints[0] not in self.endpoints():
                        raise RuntimeError("Unexpected mapping identity on owned function; refusing deletion")
                    if mapping["UUID"] not in owned["mappings"]:
                        owned["mappings"].append(mapping["UUID"])
                    self.save()
                marker = result.get("NextMarker")
                if not marker:
                    break

        def remove_secret():
            secret = owned["secret"]
            request = {"SecretId": secret.get("arn", secret["name"])}
            value = self.call("cleanup-secret-identity", "secretsmanager", "describe_secret", request, required=False)
            if not value and self.code() == "ResourceNotFoundException":
                return
            if ({item["Key"]: item["Value"] for item in value.get("Tags", [])}.get("stackd-probe") != self.data["prefix"] or
                    value.get("Name") != secret["name"] or value.get("ARN") != secret.get("arn", value.get("ARN"))):
                raise RuntimeError("Secret ownership changed; refusing deletion")
            if not value.get("DeletedDate"):
                self.call("cleanup-delete-dummy-secret", "secretsmanager", "delete_secret", {**request, "ForceDeleteWithoutRecovery": True})
            self.wait_resource("cleanup-secret-absent", "secretsmanager", "describe_secret", request,
                               lambda value, code: code == "ResourceNotFoundException")

        def source_cleanup(attempt):
            if "secret" in owned:
                attempt("authentication secret", remove_secret)

        super().cleanup(source_cleanup=source_cleanup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_self_managed_kafka_mapping.json"))
    parser.add_argument("--ethics-review", type=Path, required=True, help="Fresh allowed review covering this run and exact bounded resources")
    parser.add_argument("--cleanup-only", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--position-only", action="store_true", help="Short starting-position, timestamp and metrics follow-up")
    modes.add_argument("--contract-only", action="store_true", help="Starting-position, authentication reintroduction and unexecuted group planning")
    args = parser.parse_args()
    args.schema_output = None
    probe = SelfManagedKafkaProbe(args)

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
