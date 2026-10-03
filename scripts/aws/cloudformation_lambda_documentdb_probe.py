#!/usr/bin/env python3
"""Capture disabled native CFN DocumentDB mappings with exact-owned recovery.

Requires a fresh ethics review. No native delivery or MongoDB equivalence claim.
The default run uses a real DocumentDB cluster without a billable DB instance.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import time
import urllib.request
import uuid

import boto3
from botocore.config import Config

from aws_cli import call as cli_call
from cloudformation_lambda_alias_probe import recorded
from cloudformation_lambda_kinesis_mapping_probe import KinesisMappingProbe
from cloudformation_lambda_self_managed_kafka_probe import SelfManagedKafkaProbe
from cloudformation_lambda_version_probe import VersionProbe
from cloudtrail_service_probe import REGION, now

CFN = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/"
SOURCES = [CFN + "aws-resource-lambda-eventsourcemapping.md",
    CFN + "aws-properties-lambda-eventsourcemapping-documentdbeventsourceconfig.md",
    CFN + "aws-properties-lambda-eventsourcemapping-sourceaccessconfiguration.md",
    "https://docs.aws.amazon.com/lambda/latest/dg/with-documentdb.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_UpdateEventSourceMapping.md"]


class DocumentDBProbe(KinesisMappingProbe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        approval = json.loads(args.ethics_review.read_text())
        if not approval.get("allowed") or (approval.get("account"), approval.get("region"), approval.get("actor")) != (self.account, REGION, self.actor):
            raise RuntimeError("Fresh exact-account/actor review required")
        environment = dict(os.environ, AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
            AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_MAX_ATTEMPTS="1")
        identity = cli_call("sts", "get-caller-identity", {}, environment)
        if (identity["Account"], identity["Arn"]) != (self.account, self.actor):
            raise RuntimeError("Actor outside approved scope")
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
            retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=30)
        self.clients = {name: self.session.client(name, config=config) for name in
            ("sts", "iam", "lambda", "cloudformation", "ec2", "docdb", "secretsmanager")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        for name, client in self.clients.items():
            host = "rds" if name == "docdb" else name
            expected = "https://iam.amazonaws.com" if name == "iam" else "https://" + host + "." + REGION + ".amazonaws.com"
            if client.meta.endpoint_url != expected:
                raise RuntimeError("Unexpected endpoint " + client.meta.endpoint_url)
        self.cleanup_phase = False
        self.end = time.monotonic() + 3600
        if approval.get("deadline"):
            remaining = (datetime.fromisoformat(approval["deadline"]) - datetime.now(timezone.utc)).total_seconds()
            self.end = min(self.end, time.monotonic() + remaining)
        self.workflow_end = self.end - 900
        if args.cleanup_only or args.finish_controls:
            self.data = json.loads(args.output.read_text())
            if (self.data["account"], self.data["region"], self.data["actor"]) != (self.account, REGION, self.actor) or not self.data["prefix"].startswith("stackd-cfn-docdb-"):
                raise RuntimeError("Not an exact-owned DocumentDB inventory")
            self.data.setdefault("recovery_reviews", []).append(approval)
            if args.finish_controls:
                self.data.setdefault("recovery_handoffs", []).append({"at": now(),
                    "reason": "Parent requested direct namespace and nondefault FullDocument removal controls before cleanup; prior exact local writer stopped, durable inventory transferred serially."})
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite evidence")
            self.data = {"source": "Native AWS public endpoints; guarded CLI STS and signed boto3",
                "captured_at": now(), "account": self.account, "region": REGION, "actor": self.actor,
                "prefix": "stackd-cfn-docdb-" + uuid.uuid4().hex[:12], "ethics_review": approval,
                "guard_identity": identity, "bounds": {"stack_wait_seconds": 300,
                    "resource_wait_seconds": 180, "poll_seconds": 3, "total_seconds": 3600,
                    "reserved_cleanup_seconds": 900, "maximum_stack_updates": 24},
                "owned": {"stacks": {}, "streams": {}, "mappings": [], "network": {}},
                "calls": [], "templates": {}, "findings": {}, "documentation": [], "sources": SOURCES,
                "cleanup": {"complete": False}, "workflow_complete": False,
                "calibration_gaps": ["No records, invocation, native delivery, checkpoint, or MongoDB equivalence measured.",
                    "Source ARN replacement to a second cluster is not executed: approved scope contains only one cluster.",
                    "Enabled removal is not executed because every mapping must stay disabled."]}
        self.save()
        native = self.call("identity-before-writes", "sts", "get_caller_identity")
        if (native["Account"], native["Arn"]) != (self.account, self.actor):
            raise RuntimeError("SDK identity differs from approved identity")

    def save(self):
        def scrub(value):
            if isinstance(value, dict):
                return {k: "<redacted-synthetic-credential>" if k in ("SecretString", "MasterUserPassword") else scrub(v) for k, v in value.items()}
            if isinstance(value, list):
                return [scrub(v) for v in value]
            return value
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(scrub(recorded(self.data)), indent=2)
        for credential in (self.credentials.secret_key, self.credentials.token):
            if credential:
                text = text.replace(credential, "<redacted-credential>")
        temporary = self.args.output.with_suffix(".pending")
        temporary.write_text(text + "\n")
        temporary.replace(self.args.output)

    def call(self, label, service, operation, request=None, *, required=True):
        if time.monotonic() >= (self.end if self.cleanup_phase else self.workflow_end):
            raise RuntimeError("Approved bounded capture deadline reached; inventory retained")
        return super().call(label, service, operation, request, required=required)

    def documents(self):
        for source in SOURCES:
            with urllib.request.urlopen(source, timeout=25) as response:
                raw = response.read()
            self.data["documentation"].append({"source": source, "captured_at": now(),
                "sha256": hashlib.sha256(raw).hexdigest(), "content": raw.decode()})
            self.save()
        super().documents()

    def source_arns(self):
        return [self.data["owned"]["cluster"]["arn"]]

    def template(self, properties):
        function = self.data["owned"]["function"]
        targets = [function["arn"]] + [function["arn"] + ":" + value for value in
            function.get("aliases", []) + function.get("versions", [])]
        if properties.get("FunctionName") not in targets:
            raise RuntimeError("Mapping target is not the exact-owned function or qualifier")
        return super().template(properties)

    def setup_source(self):
        owned, prefix = self.data["owned"], self.data["prefix"]
        network = owned["network"]
        tags = [{"Key": "stackd-probe", "Value": prefix}]
        zones = self.call("available-zones", "ec2", "describe_availability_zones", {"Filters": [{"Name": "state", "Values": ["available"]}]})["AvailabilityZones"]
        zones = [z["ZoneName"] for z in zones if z["ZoneType"] == "availability-zone"][:2]
        if len(zones) != 2:
            raise RuntimeError("Two private AZs unavailable")
        for key, operation, request, field, identifier in [
            ("vpc", "create_vpc", {"CidrBlock": "10.219.0.0/24", "TagSpecifications": [{"ResourceType": "vpc", "Tags": tags}]}, "Vpc", "VpcId")]:
            network[key] = {"creation_attempted": True}
            self.save()
            network[key]["id"] = self.call("create-" + key, "ec2", operation, request)[field][identifier]
            self.save()
        for index, zone in enumerate(zones):
            key = "subnet" + str(index)
            network[key] = {"creation_attempted": True}
            self.save()
            network[key]["id"] = self.call("create-" + key, "ec2", "create_subnet", {
                "VpcId": network["vpc"]["id"], "CidrBlock": "10.219.0." + str(index * 128) + "/25",
                "AvailabilityZone": zone, "TagSpecifications": [{"ResourceType": "subnet", "Tags": tags}]})["Subnet"]["SubnetId"]
            self.save()
        network["security_group"] = {"creation_attempted": True}
        self.save()
        network["security_group"]["id"] = self.call("create-private-security-group", "ec2", "create_security_group", {
            "GroupName": prefix, "Description": "Owned disabled DocumentDB calibration; no public ingress",
            "VpcId": network["vpc"]["id"], "TagSpecifications": [{"ResourceType": "security-group", "Tags": tags}]})["GroupId"]
        self.save()
        self.call("private-source-self-ingress", "ec2", "authorize_security_group_ingress", {
            "GroupId": network["security_group"]["id"], "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 27017,
                "ToPort": 27017, "UserIdGroupPairs": [{"GroupId": network["security_group"]["id"]}]}]})
        self.absent("subnet-group-name-absent", "docdb", "describe_db_subnet_groups", {"DBSubnetGroupName": prefix}, "DBSubnetGroupNotFoundFault")
        owned["subnet_group"] = {"name": prefix, "creation_attempted": True, "absence_verified": True}
        self.save()
        self.call("create-subnet-group", "docdb", "create_db_subnet_group", {"DBSubnetGroupName": prefix,
            "DBSubnetGroupDescription": "Exact-owned CFN DocumentDB capture", "SubnetIds": [network["subnet0"]["id"], network["subnet1"]["id"]], "Tags": tags})
        self.absent("cluster-name-absent", "docdb", "describe_db_clusters", {"DBClusterIdentifier": prefix}, "DBClusterNotFoundFault")
        password = "Owned" + uuid.uuid4().hex
        owned["cluster"] = {"name": prefix, "creation_attempted": True, "absence_verified": True}
        self.save()
        cluster = self.call("create-real-documentdb-cluster-no-instance", "docdb", "create_db_cluster", {
            "DBClusterIdentifier": prefix, "Engine": "docdb", "EngineVersion": "5.0.0", "MasterUsername": "ownedprobe",
            "MasterUserPassword": password, "DBSubnetGroupName": prefix, "VpcSecurityGroupIds": [network["security_group"]["id"]],
            "StorageEncrypted": True, "BackupRetentionPeriod": 1, "DeletionProtection": False, "Tags": tags})["DBCluster"]
        owned["cluster"].update(arn=cluster["DBClusterArn"], resource_id=cluster["DbClusterResourceId"])
        self.save()
        self.absent("secret-name-absent", "secretsmanager", "describe_secret", {"SecretId": prefix}, "ResourceNotFoundException")
        owned["secret"] = {"name": prefix, "creation_attempted": True, "absence_verified": True}
        self.save()
        secret = self.call("create-owned-source-secret", "secretsmanager", "create_secret", {
            "Name": prefix, "SecretString": json.dumps({"username": "ownedprobe", "password": password}), "Tags": tags})
        owned["secret"]["arn"] = secret["ARN"]
        self.save()
        deadline = min(self.workflow_end, time.monotonic() + 600)
        while time.monotonic() < deadline:
            value = self.call("cluster-readiness", "docdb", "describe_db_clusters", {"DBClusterIdentifier": prefix})["DBClusters"][0]
            if value["Status"] == "available":
                self.finding("real-cluster-ready-without-instance", value)
                return
            time.sleep(15)
        raise RuntimeError("Real cluster without instance readiness expired; no scope expansion")

    def setup_function(self):
        VersionProbe.setup(self)
        owned = self.data["owned"]
        function = owned["function"]
        self.call("reserve-zero-concurrency", "lambda", "put_function_concurrency", {"FunctionName": function["arn"], "ReservedConcurrentExecutions": 0})
        self.call("confirm-zero-concurrency", "lambda", "get_function_concurrency", {"FunctionName": function["arn"]})
        network = owned["network"]
        root = "arn:aws:ec2:" + REGION + ":" + self.account + ":"
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["rds:DescribeDBClusters", "rds:DescribeDBClusterParameters", "rds:DescribeDBSubnetGroups",
                "ec2:DescribeNetworkInterfaces", "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"], "Resource": "*"},
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": owned["secret"]["arn"]},
            {"Effect": "Allow", "Action": "ec2:CreateNetworkInterface", "Resource": [root + "subnet/" + network[key]["id"] for key in ("subnet0", "subnet1")] + [root + "security-group/" + network["security_group"]["id"]]},
            {"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface"], "Resource": root + "network-interface/*",
                "Condition": {"ArnEquals": {"ec2:Vpc": root + "vpc/" + network["vpc"]["id"]}}}]}
        owned["role"]["policy"] = "owned-documentdb-access"
        self.save()
        self.call("put-owned-source-policy", "iam", "put_role_policy", {"RoleName": owned["role"]["name"], "PolicyName": owned["role"]["policy"], "PolicyDocument": json.dumps(policy)})
        time.sleep(15)
        version = self.call("publish-owned-noninvoked-version", "lambda", "publish_version", {"FunctionName": function["arn"]})["Version"]
        function["versions"].append(version)
        function["aliases"] = ["owned-target"]
        self.save()
        self.call("create-owned-alias", "lambda", "create_alias", {"FunctionName": function["arn"], "Name": "owned-target", "FunctionVersion": version})

    def transition(self, label, current, proposed):
        if current == proposed:
            self.finding(label, {"not_submitted": "Template unchanged after preceding rollback"})
            return current
        return SelfManagedKafkaProbe.transition(self, label, current, proposed)

    def workflow(self):
        self.documents()
        self.setup_source()
        self.setup_function()
        owned = self.data["owned"]
        current = {"FunctionName": owned["function"]["arn"], "EventSourceArn": self.source_arns()[0], "Enabled": False,
            "DocumentDBEventSourceConfig": {"DatabaseName": "owned"},
            "SourceAccessConfigurations": [{"Type": "BASIC_AUTH", "URI": owned["secret"]["arn"]}]}
        if self.args.nondefault_only:
            current.update(FunctionName=owned["function"]["arn"] + ":" + owned["function"]["versions"][0],
                StartingPosition="LATEST", DocumentDBEventSourceConfig={
                    "DatabaseName": "owned", "CollectionName": "events", "FullDocument": "UpdateLookup"})
        initial = self.stack("fresh-nondefault-config" if self.args.nondefault_only else "fresh-omitted-starting-position", current)
        if initial.get("stack_status") != "CREATE_COMPLETE":
            self.finding("initial-admission-boundary", {"positive_mapping_observed": False, "result": initial})
            raise RuntimeError("Real no-instance cluster disabled CFN admission failed; unobserved contracts remain unknown")
        self.finding("current_mapping", initial["mapping"])
        if self.args.nondefault_only:
            self.finish_controls()
            return
        current = self.transition("explicit-batch-window", current, {**current, "BatchSize": 17, "MaximumBatchingWindowInSeconds": 2})
        current = self.transition("remove-batch-window", current, {k: v for k, v in current.items() if k not in ("BatchSize", "MaximumBatchingWindowInSeconds")})
        for label, config in [("explicit-collection-full-document", {"DatabaseName": "owned", "CollectionName": "events", "FullDocument": "UpdateLookup"}),
            ("change-database-collection", {"DatabaseName": "owned_other", "CollectionName": "other_events", "FullDocument": "Default"}),
            ("remove-collection-full-document", {"DatabaseName": "owned_other"}),
            ("remove-database", {"CollectionName": "events"})]:
            current = self.transition(label, current, {**current, "DocumentDBEventSourceConfig": config})
        current = self.transition("remove-documentdb-config", current, {k: v for k, v in current.items() if k != "DocumentDBEventSourceConfig"})
        current = self.transition("restore-documentdb-config", current, {**current, "DocumentDBEventSourceConfig": {"DatabaseName": "owned", "CollectionName": "events", "FullDocument": "Default"}})
        secret = owned["secret"]
        current = self.transition("credential-name-instead-of-arn", current, {**current, "SourceAccessConfigurations": [{"Type": "BASIC_AUTH", "URI": secret["name"]}]})
        current = self.transition("remove-source-credentials", current, {k: v for k, v in current.items() if k != "SourceAccessConfigurations"})
        current = self.transition("restore-source-credentials", current, {**current, "SourceAccessConfigurations": [{"Type": "BASIC_AUTH", "URI": secret["arn"]}]})
        for qualifier in ("owned-target", owned["function"]["versions"][0]):
            current = self.transition("qualified-target-" + qualifier, current, {**current, "FunctionName": owned["function"]["arn"] + ":" + qualifier})
        current = self.transition("explicit-latest-position", current, {**current, "StartingPosition": "LATEST"})
        current = self.transition("replace-trim-horizon", current, {**current, "StartingPosition": "TRIM_HORIZON"})
        current = self.transition("replace-at-timestamp", current, {**current, "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": int(time.time()) - 60})
        current = self.transition("remove-timestamp", current, {k: v for k, v in current.items() if k != "StartingPositionTimestamp"})
        self.transition("remove-position", current, {k: v for k, v in current.items() if k not in ("StartingPosition", "StartingPositionTimestamp")})
        self.finish_controls()

    def finish_controls(self):
        stack = self.data["owned"]["stacks"]["mapping"]
        terminal = self.wait_owned_stack("mapping", "recovery-pending-stack")
        events = self.call("recovery-pending-events", "cloudformation", "describe_stack_events", {"StackName": stack["id"]})
        self.remember_mappings(events.get("StackEvents", []))
        self.finding("recovery-pending-terminal", {"stack": terminal, "events": events})
        if terminal["StackStatus"] not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "CREATE_COMPLETE"):
            raise RuntimeError("Pending stack is not safely mutable")
        template = self.call("recovery-current-template", "cloudformation", "get_template", {"StackName": stack["id"]})["TemplateBody"]
        if isinstance(template, str):
            template = json.loads(template)
        current = template["Resources"]["Mapping"]["Properties"]
        self.template(current)
        identifier = next(output["OutputValue"] for output in terminal["Outputs"] if output["OutputKey"] == "MappingRef")
        before = self.call("direct-namespace-before", "lambda", "get_event_source_mapping", {"UUID": identifier})
        if before["State"] != "Disabled" or before["EventSourceArn"] not in self.source_arns():
            raise RuntimeError("Direct control requires exact-owned disabled mapping")
        controls = [
            ("direct-same-database", {"DatabaseName": before["DocumentDBEventSourceConfig"]["DatabaseName"]}),
            ("direct-collection-only", {"CollectionName": "direct_events"}),
            ("direct-database-only", {"DatabaseName": "direct_other"}),
        ] if self.args.nondefault_only else [
            ("direct-namespace-update", {"DatabaseName": "direct_other", "CollectionName": "direct_events", "FullDocument": "UpdateLookup"})]
        for label, proposed_config in controls:
            changed = self.call(label, "lambda", "update_event_source_mapping", {
                "UUID": identifier, "Enabled": False, "DocumentDBEventSourceConfig": proposed_config},
                required=False)
            update_call = self.data["calls"][-1]
            after = self.wait_resource(label + "-read", "lambda", "get_event_source_mapping",
                {"UUID": identifier}, lambda value, code: value.get("State") == "Disabled")
            self.finding(label + "-owner-control", {"before": before, "update_response": changed,
                "update_code": update_call["code"], "update_error": update_call.get("error"), "after": after})
            self.finding("current_mapping", after)
        config = current.get("DocumentDBEventSourceConfig", {"DatabaseName": "owned"})
        current = self.transition("set-nondefault-full-document", current, {**current,
            "DocumentDBEventSourceConfig": {**config, "FullDocument": "UpdateLookup"}})
        current = self.transition("remove-nondefault-full-document", current, {**current,
            "DocumentDBEventSourceConfig": {k: v for k, v in current["DocumentDBEventSourceConfig"].items() if k != "FullDocument"}})
        current = self.transition("reintroduce-nondefault-full-document", current, {**current,
            "DocumentDBEventSourceConfig": {**current["DocumentDBEventSourceConfig"], "FullDocument": "UpdateLookup"}})
        current = self.transition("remove-nondefault-entire-config", current,
            {k: v for k, v in current.items() if k != "DocumentDBEventSourceConfig"})
        if not self.args.nondefault_only:
            current = self.transition("replace-position-qualified-target", current, {**current,
                "FunctionName": self.data["owned"]["function"]["arn"], "StartingPosition": "TRIM_HORIZON",
                "DocumentDBEventSourceConfig": {"DatabaseName": "owned", "FullDocument": "Default"}})
            self.transition("remove-position-after-qualified-replacement", current,
                {k: v for k, v in current.items() if k not in ("StartingPosition", "StartingPositionTimestamp")})
        self.data["workflow_complete"] = True
        self.save()

    def cleanup_source(self, attempt):
        owned = self.data["owned"]
        def remove_secret():
            item = owned["secret"]
            request = {"SecretId": item.get("arn", item["name"])}
            value = self.call("cleanup-secret-identity", "secretsmanager", "describe_secret", request, required=False)
            if value:
                if {t["Key"]: t["Value"] for t in value.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Secret ownership mismatch")
                self.call("cleanup-delete-secret", "secretsmanager", "delete_secret", {**request, "ForceDeleteWithoutRecovery": True})
            self.wait_resource("cleanup-secret-absent", "secretsmanager", "describe_secret", request, lambda v, c: c == "ResourceNotFoundException")
        def remove_cluster():
            item = owned["cluster"]
            request = {"DBClusterIdentifier": item["name"]}
            value = self.call("cleanup-cluster-identity", "docdb", "describe_db_clusters", request, required=False)
            if value:
                cluster = value["DBClusters"][0]
                tags = self.call("cleanup-cluster-tags", "docdb", "list_tags_for_resource", {"ResourceName": cluster["DBClusterArn"]})
                if {t["Key"]: t["Value"] for t in tags["TagList"]}.get("stackd-probe") != self.data["prefix"] or cluster.get("DbClusterResourceId") != item.get("resource_id", cluster.get("DbClusterResourceId")):
                    raise RuntimeError("Cluster ownership mismatch")
                if cluster["Status"] != "deleting":
                    self.call("cleanup-delete-cluster", "docdb", "delete_db_cluster", {**request, "SkipFinalSnapshot": True})
            deadline = min(self.end, time.monotonic() + 600)
            while time.monotonic() < deadline:
                self.call("cleanup-cluster-absent", "docdb", "describe_db_clusters", request, required=False)
                if self.code() == "DBClusterNotFoundFault":
                    return
                if self.code() != "Success":
                    raise RuntimeError("Unexpected cluster cleanup response")
                time.sleep(10)
            raise RuntimeError("Cluster deletion bounded wait expired")
        def remove_subnet_group():
            item = owned["subnet_group"]
            request = {"DBSubnetGroupName": item["name"]}
            value = self.call("cleanup-subnet-group-identity", "docdb", "describe_db_subnet_groups", request, required=False)
            if value:
                arn = value["DBSubnetGroups"][0]["DBSubnetGroupArn"]
                tags = self.call("cleanup-subnet-group-tags", "docdb", "list_tags_for_resource", {"ResourceName": arn})
                if {t["Key"]: t["Value"] for t in tags["TagList"]}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Subnet group ownership mismatch")
                self.call("cleanup-delete-subnet-group", "docdb", "delete_db_subnet_group", request)
            self.absent("cleanup-subnet-group-absent", "docdb", "describe_db_subnet_groups", request, "DBSubnetGroupNotFoundFault")
        def remove_network(key, describe, field, plural, singular, delete, absent_code):
            item = owned["network"][key]
            if not item.get("id"):
                raise RuntimeError("Unconfirmed creation retained: " + key)
            request = {plural: [item["id"]]}
            value = self.call("cleanup-" + key + "-identity", "ec2", describe, request, required=False)
            if value:
                resource = value[field][0]
                if {t["Key"]: t["Value"] for t in resource.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Network ownership mismatch: " + key)
                self.call("cleanup-delete-" + key, "ec2", delete, {singular: item["id"]})
            self.absent("cleanup-" + key + "-absent", "ec2", describe, request, absent_code)
        if "secret" in owned:
            attempt("secret", remove_secret)
        if "cluster" in owned:
            attempt("cluster", remove_cluster)
        if "subnet_group" in owned:
            attempt("subnet group", remove_subnet_group)
        for key, describe, field, plural, singular, delete, code in [
            ("security_group", "describe_security_groups", "SecurityGroups", "GroupIds", "GroupId", "delete_security_group", "InvalidGroup.NotFound"),
            ("subnet1", "describe_subnets", "Subnets", "SubnetIds", "SubnetId", "delete_subnet", "InvalidSubnetID.NotFound"),
            ("subnet0", "describe_subnets", "Subnets", "SubnetIds", "SubnetId", "delete_subnet", "InvalidSubnetID.NotFound"),
            ("vpc", "describe_vpcs", "Vpcs", "VpcIds", "VpcId", "delete_vpc", "InvalidVpcID.NotFound")]:
            if key in owned["network"]:
                attempt(key, lambda key=key, describe=describe, field=field, plural=plural, singular=singular, delete=delete, code=code:
                    remove_network(key, describe, field, plural, singular, delete, code))

    def cleanup(self):
        super().cleanup(source_cleanup=self.cleanup_source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_documentdb_mapping.json"))
    parser.add_argument("--ethics-review", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--finish-controls", action="store_true",
        help="Serial recovery of an existing inventory: settle pending stack, direct namespace control, nondefault config removal, cleanup")
    parser.add_argument("--nondefault-only", action="store_true",
        help="Focused fresh nondefault config removal and direct namespace negative controls; no repetition of batch/credential/replacement controls")
    args = parser.parse_args()
    args.schema_output = None
    probe = DocumentDBProbe(args)
    def interrupted(signum, frame):
        raise RuntimeError("Interrupted; exact-owned cleanup follows")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    failure = None
    try:
        if args.finish_controls:
            probe.finish_controls()
        elif not args.cleanup_only:
            probe.workflow()
    except Exception as error:
        failure = str(error)
        probe.data.setdefault("failures", []).append({"at": now(), "error": failure})
        probe.save()
    finally:
        probe.cleanup()
    if failure:
        raise RuntimeError(failure)


if __name__ == "__main__":
    main()
