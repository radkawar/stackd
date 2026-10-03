#!/usr/bin/env python3
"""Capture disabled CFN MSK lifecycle on an exact-created private source.

Fresh ethics review and a durable provisioning inventory are required. The
source inventory retains native creation responses and exact role/cluster IDs.
Cleanup retires only those identities and is resumable with --cleanup-only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import time
import urllib.request

import boto3
import botocore
from botocore.config import Config

from aws_cli import call as cli_call
from cloudformation_lambda_kinesis_mapping_probe import KinesisMappingProbe
from cloudformation_lambda_version_probe import VersionProbe
from cloudformation_lambda_self_managed_kafka_probe import SelfManagedKafkaProbe
from cloudtrail_service_probe import REGION, now

CFN_DOCS = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/"
LAMBDA_DOCS = "https://docs.aws.amazon.com/lambda/latest/"
SOURCES = [CFN_DOCS + "aws-resource-lambda-eventsourcemapping.md",
    CFN_DOCS + "aws-properties-lambda-eventsourcemapping-amazonmanagedkafkaeventsourceconfig.md",
    CFN_DOCS + "aws-properties-lambda-eventsourcemapping-sourceaccessconfiguration.md"] + [
    LAMBDA_DOCS + "api/API_" + name + ".md" for name in
    ("CreateEventSourceMapping", "UpdateEventSourceMapping", "AmazonManagedKafkaEventSourceConfig")
] + [LAMBDA_DOCS + "dg/" + name + ".md" for name in
     ("with-msk", "with-msk-permissions", "with-msk-cluster-network", "msk-esm-create",
      "msk-esm-parameters", "kafka-consumer-group-id", "kafka-starting-positions")
] + ["https://docs.aws.amazon.com/msk/latest/developerguide/using-service-linked-roles.md"]


class MSKProbe(KinesisMappingProbe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        approval = json.loads(args.ethics_review.read_text())
        if not approval.get("allowed") or (approval.get("account"), approval.get("region"), approval.get("actor")) != (self.account, REGION, self.actor):
            raise RuntimeError("Fresh approval must identify the exact account, region and actor")
        environment = dict(os.environ, AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
                           AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_MAX_ATTEMPTS="1")
        identity = cli_call("sts", "get-caller-identity", {}, environment)
        if (identity["Account"], identity["Arn"]) != (self.account, self.actor):
            raise RuntimeError("Native writes require the approved Delegated actor")
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config) for name in
                        ("sts", "iam", "lambda", "cloudformation", "kafka", "ec2", "secretsmanager")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        self.prerequisite = json.loads(args.prerequisite_inventory.read_text())
        if ((self.prerequisite["account"], self.prerequisite["region"], self.prerequisite["actor"]) != (self.account, REGION, self.actor) or
                not self.prerequisite.get("ethics_review", {}).get("allowed")):
            raise RuntimeError("Provisioning inventory is not approved")
        for name, client in self.clients.items():
            expected = "https://iam.amazonaws.com" if name == "iam" else "https://" + name + "." + REGION + ".amazonaws.com"
            if client.meta.endpoint_url != expected:
                raise RuntimeError("Unexpected native endpoint: " + client.meta.endpoint_url)
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if ((self.data["account"], self.data["region"]) != (self.account, REGION) or
                    not self.data["prefix"].startswith("stackd-cfn-msk-")):
                raise RuntimeError("Not an approved MSK capture inventory")
            self.data.setdefault("recovery_reviews", []).append(approval)
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            prefix = self.prerequisite["prefix"]
            self.data = {
                "source": "Native public AWS endpoints; guarded aws_cli identity; signed boto3 with endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION, "prefix": prefix,
                "ethics_review": approval, "guard_identity": identity,
                "mode": "private-msk-control-plane-lifecycle",
                "scope": "One exact-created private two-AZ/t3.small source and service-linked role; one non-invoked concurrency-zero function/role, versions/aliases/dummy secret and disabled mapping stack",
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__, "models": {
                    name: {"api_version": client.meta.service_model.api_version, "endpoint": client.meta.endpoint_url}
                    for name, client in self.clients.items()}},
                "bounds": {"stack_wait_seconds": 300, "resource_wait_seconds": 120,
                           "poll_seconds": 3,
                           "maximum_stack_updates": 24, "source_ready_seconds": 1500, "source_cleanup_seconds": 2400},
                "owned": {"stacks": {}, "streams": {}, "mappings": []},
                "calls": [], "findings": {}, "templates": {}, "documentation": [], "sources": SOURCES,
                "calibration_gaps": [
                    "No broker connectivity, records, Lambda invocations or offset behavior measured.",
                    "Only successful native transitions establish lifecycle contracts; failed setup/admission leaves remaining contracts unknown.",
                    "Primary documentation and public schema are recorded separately; neither is treated as observed lifecycle execution.",
                ], "cleanup": {"complete": False}, "workflow_complete": False,
            }
        self.save()
        native_identity = self.call("identity-before-writes", "sts", "get_caller_identity")
        if (native_identity["Account"], native_identity["Arn"]) != (self.account, self.actor):
            raise RuntimeError("SDK actor differs from guarded approved actor")
        self.data["identity"] = native_identity
        self.save()

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

    def source_arns(self):
        return [self.prerequisite["owned"]["cluster"]["arn"]]

    def template(self, properties):
        function = self.data["owned"]["function"]
        targets = [function["arn"]] + [function["arn"] + ":" + value for value in
                                      function.get("aliases", []) + function.get("versions", [])]
        if properties.get("FunctionName") not in targets:
            raise RuntimeError("Mapping target is not the exact-owned function or qualifier")
        return super().template(properties)

    def workflow(self):
        self.documents()
        self.wait_source()
        VersionProbe.setup(self)
        function = self.data["owned"]["function"]
        self.call("zero-reserved-concurrency", "lambda", "put_function_concurrency",
                  {"FunctionName": function["arn"], "ReservedConcurrentExecutions": 0})
        self.call("confirm-zero-concurrency", "lambda", "get_function_concurrency", {"FunctionName": function["arn"]})
        role = self.data["owned"]["role"]
        role["policy"] = "owned-msk-describe-only"
        self.save()
        self.call("put-exact-source-describe-policy", "iam", "put_role_policy", {
            "RoleName": role["name"], "PolicyName": role["policy"],
            "PolicyDocument": json.dumps(self.execution_policy())})
        time.sleep(15)
        version = self.call("publish-noninvoked-version", "lambda", "publish_version", {"FunctionName": function["arn"]})
        function["versions"].append(version["Version"])
        function["aliases"] = ["owned-first", "owned-second"]
        self.save()
        for alias in function["aliases"]:
            self.call("create-" + alias, "lambda", "create_alias", {
                "FunctionName": function["arn"], "Name": alias, "FunctionVersion": version["Version"]})
        base = {"FunctionName": function["arn"], "EventSourceArn": self.source_arns()[0],
                "Enabled": False, "Topics": [self.data["prefix"] + "-topic"]}
        self.lifecycle(base)
        self.data["workflow_complete"] = True
        self.data["lifecycle_complete"] = True
        self.save()

    def execution_policy(self):
        review = json.loads(self.args.permissions_review.read_text())
        if ((review.get("account"), review.get("region"), review.get("actor")) != (self.account, REGION, self.actor) or
                not review.get("ethics_review", {}).get("allowed")):
            raise RuntimeError("Exact-source/network permission amendment is required")
        self.data["permission_review"] = review["ethics_review"]
        self.save()
        source = self.source_arns()[0]
        root = "arn:aws:ec2:" + REGION + ":" + self.account + ":"
        network = self.prerequisite["owned"]["network"]
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["kafka:DescribeCluster", "kafka:DescribeClusterV2",
                "kafka:GetBootstrapBrokers", "kafka:ListScramSecrets", "kafka-cluster:Connect"], "Resource": source},
            {"Effect": "Allow", "Action": ["ec2:DescribeVpcs", "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"], "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:CreateNetworkInterface", "Resource": [
                root + "subnet/" + network["subnet0"]["id"], root + "subnet/" + network["subnet1"]["id"],
                root + "security-group/" + network["security_group"]["id"]]},
            {"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface"],
                "Resource": root + "network-interface/*",
                "Condition": {"ArnEquals": {"ec2:Vpc": root + "vpc/" + network["vpc"]["id"]}}},
            {"Effect": "Allow", "Action": ["kafka-cluster:DescribeTopic", "kafka-cluster:ReadData"],
                "Resource": source.replace(":cluster/", ":topic/") + "/" + self.data["prefix"] + "*"},
            {"Effect": "Allow", "Action": ["kafka-cluster:DescribeGroup", "kafka-cluster:AlterGroup"],
                "Resource": source.replace(":cluster/", ":group/") + "/" + self.data["prefix"] + "*"}]}

    def save_prerequisite(self):
        self.args.prerequisite_inventory.write_text(json.dumps(self.prerequisite, indent=2) + "\n")

    def wait_source(self):
        deadline = time.monotonic() + self.data["bounds"]["source_ready_seconds"]
        while time.monotonic() < deadline:
            cluster = self.call("owned-source-readiness", "kafka", "describe_cluster_v2",
                {"ClusterArn": self.source_arns()[0]})["ClusterInfo"]
            if cluster.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                raise RuntimeError("Source tag does not match exact-owned provisioning inventory")
            if cluster["State"] == "ACTIVE":
                self.finding("source-ready", cluster)
                return
            if cluster["State"] == "FAILED":
                raise RuntimeError("Owned MSK source provisioning failed: " + json.dumps(cluster))
            time.sleep(20)
        raise RuntimeError("Owned MSK readiness bound expired")

    def transition(self, label, current, proposed):
        if current == proposed:
            self.finding(label + "-not-submitted", {
                "reason": "Proposed template already equals the surviving template after earlier rollback",
                "boundary": "No removal lifecycle claim; no redundant native update submitted"})
            return current
        created = self.prerequisite["owned"]["cluster"]["created_at"]
        from datetime import datetime, timezone
        if (datetime.now(timezone.utc) - datetime.fromisoformat(created)).total_seconds() > 4200:
            raise RuntimeError("Approved cluster workflow deadline expired")
        return SelfManagedKafkaProbe.transition(self, label, current, proposed)

    def group_change_set(self, current):
        stack = self.data["owned"]["stacks"]["mapping"]
        request = {"StackName": stack["id"], "ChangeSetName": self.data["prefix"] + "-group-plan"}
        self.absent("group-plan-absent", "cloudformation", "describe_change_set", request, "ChangeSetNotFound")
        self.data["owned"]["change_set"] = {**request, "creation_attempted": True}
        self.save()
        proposed = {**current, "AmazonManagedKafkaEventSourceConfig": {"ConsumerGroupId": self.data["prefix"] + "-other-group"}}
        value = self.call("group-plan-create", "cloudformation", "create_change_set", {
            **request, "ChangeSetType": "UPDATE", "TemplateBody": json.dumps(self.template(proposed))})
        self.data["owned"]["change_set"]["id"] = value["Id"]
        self.save()
        result = self.wait_resource("group-plan-ready", "cloudformation", "describe_change_set",
            {"ChangeSetName": value["Id"]}, lambda value, code: value.get("Status") in ("CREATE_COMPLETE", "FAILED"))
        self.finding("group-public-plan", {"executed": False, "description": result})
        SelfManagedKafkaProbe.delete_change_set(self)
        return proposed

    def lifecycle(self, base):
        prefix = self.data["prefix"]
        current = {**base, "AmazonManagedKafkaEventSourceConfig": {"ConsumerGroupId": prefix + "-group"}}
        result = self.stack("fresh-defaults-omitted-position", current)
        if result.get("stack_status") != "CREATE_COMPLETE":
            self.finding("initial-admission-boundary", {"positive_mapping_observed": False, "native_result": result})
            raise RuntimeError("Real MSK disabled CFN admission failed; remaining lifecycle contracts unknown")
        self.finding("current_mapping", result["mapping"])
        settings = {"BatchSize": 17, "MaximumBatchingWindowInSeconds": 2,
            "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"value": {"probe": [prefix]}})}]}}
        current = self.transition("explicit-settings", current, {**current, **settings})
        current = self.transition("remove-settings", current,
            {key: value for key, value in current.items() if key not in settings})
        planned = self.group_change_set(current)
        current = self.transition("change-consumer-group", current, planned)
        current = self.transition("remove-consumer-group", current,
            {key: value for key, value in current.items() if key != "AmazonManagedKafkaEventSourceConfig"})
        current = self.transition("change-topic", current, {**current, "Topics": [prefix + "-other-topic"]})
        current = self.transition("remove-topics", current,
            {key: value for key, value in current.items() if key != "Topics"})
        function = self.data["owned"]["function"]
        for alias in function["aliases"]:
            current = self.transition("retarget-" + alias, current, {**current, "FunctionName": function["arn"] + ":" + alias})
        current = self.transition("retarget-unqualified", current, {**current, "FunctionName": function["arn"]})
        self.position_and_authentication(current)

    def position_and_authentication(self, current, *, latest_already_observed=False):
        prefix = self.data["prefix"]
        if not latest_already_observed:
            current = self.transition("explicit-latest", current, {**current, "StartingPosition": "LATEST"})
        current = self.transition("explicit-trim", current, {**current, "StartingPosition": "TRIM_HORIZON"})
        timestamp = int(time.time()) - 60
        current = self.transition("timestamp-missing", current, {**current, "StartingPosition": "AT_TIMESTAMP"})
        current = self.transition("timestamp-present", current, {**current,
            "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": timestamp})
        current = self.transition("timestamp-only-change", current, {**current,
            "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": timestamp + 1})
        current = self.transition("replace-position-group-topic", current, {**current,
            "Topics": [prefix + "-replacement-topic"],
            "AmazonManagedKafkaEventSourceConfig": {"ConsumerGroupId": prefix + "-replacement-group"},
            "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": timestamp + 1})
        current = self.transition("timestamp-only-after-replacement", current, {**current,
            "StartingPositionTimestamp": timestamp + 2})
        current = self.transition("remove-position-and-timestamp", current,
            {key: value for key, value in current.items() if key not in ("StartingPosition", "StartingPositionTimestamp")})
        name = prefix + "-dummy"
        self.absent("dummy-secret-name-absent", "secretsmanager", "describe_secret",
            {"SecretId": name}, "ResourceNotFoundException")
        secret = self.data["owned"]["secret"] = {"name": name, "creation_attempted": True}
        self.save()
        secret["arn"] = self.call("create-owned-dummy-secret", "secretsmanager", "create_secret", {
            "Name": name, "SecretString": json.dumps({"username": prefix, "password": "dummy-not-real-credentials"}),
            "Tags": [{"Key": "stackd-probe", "Value": prefix}]})["ARN"]
        self.save()
        role = self.data["owned"]["role"]
        policy = self.call("read-owned-role-policy", "iam", "get_role_policy",
            {"RoleName": role["name"], "PolicyName": role["policy"]})["PolicyDocument"]
        policy["Statement"].append({"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret["arn"]})
        self.call("add-exact-dummy-secret-read", "iam", "put_role_policy", {
            "RoleName": role["name"], "PolicyName": role["policy"], "PolicyDocument": json.dumps(policy)})
        time.sleep(15)
        access = {"Type": "SASL_SCRAM_512_AUTH", "URI": secret["arn"]}
        current = self.transition("add-source-access", current, {**current, "SourceAccessConfigurations": [access]})
        observed_access = self.data["findings"]["current_mapping"].get("SourceAccessConfigurations")
        if not observed_access:
            self.data["calibration_gaps"].append(
                "Adding SCRAM access to an omitted property did not establish observable source credentials; later omission is not proof of credential-removal behavior.")
            self.save()
        if "SourceAccessConfigurations" in current:
            current = self.transition("remove-source-access", current,
                {key: value for key, value in current.items() if key != "SourceAccessConfigurations"})
            current = self.transition("restore-source-access", current, {**current, "SourceAccessConfigurations": [access]})
            current = self.transition("authentication-present-on-replacement", current, {**current,
                "Topics": [prefix + "-authentication-topic"],
                "AmazonManagedKafkaEventSourceConfig": {"ConsumerGroupId": prefix + "-authentication-group"}})
            if self.data["findings"]["current_mapping"].get("SourceAccessConfigurations"):
                self.transition("remove-observed-source-access", current,
                    {key: value for key, value in current.items() if key != "SourceAccessConfigurations"})
            else:
                self.data["calibration_gaps"].append(
                    "Fresh replacement with SCRAM credentials did not establish source access on the IAM cluster; authenticated omission behavior is unknown.")
                self.save()
        else:
            self.data["calibration_gaps"].append("SCRAM source access was not admitted on IAM-only cluster; removal remains unknown.")
            self.save()

    def cleanup_source(self):
        inventory = self.prerequisite["owned"]
        cluster = inventory["cluster"]
        request = {"ClusterArn": cluster["arn"]}
        value = self.call("cleanup-source-identity", "kafka", "describe_cluster_v2", request, required=False)
        if value:
            info = value["ClusterInfo"]
            if info["ClusterArn"] != cluster["arn"] or info.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                raise RuntimeError("Refusing source deletion without exact identity and tag")
            if info["State"] != "DELETING":
                self.call("cleanup-delete-owned-source", "kafka", "delete_cluster", request)
        elif self.code() != "NotFoundException":
            raise RuntimeError("Source absence not proven")
        deadline = time.monotonic() + self.data["bounds"]["source_cleanup_seconds"]
        while time.monotonic() < deadline:
            self.call("cleanup-source-absence", "kafka", "describe_cluster_v2", request, required=False)
            if self.code() == "NotFoundException":
                cluster["deleted"] = True
                self.save_prerequisite()
                break
            time.sleep(20)
        else:
            raise RuntimeError("Source deletion deadline expired; resumable inventory retained")
        network = inventory["network"]
        for key, describe, field, idfield, delete, absent in (
            ("security_group", "describe_security_groups", "SecurityGroups", "GroupId", "delete_security_group", "InvalidGroup.NotFound"),
            ("subnet0", "describe_subnets", "Subnets", "SubnetId", "delete_subnet", "InvalidSubnetID.NotFound"),
            ("subnet1", "describe_subnets", "Subnets", "SubnetId", "delete_subnet", "InvalidSubnetID.NotFound"),
            ("vpc", "describe_vpcs", "Vpcs", "VpcId", "delete_vpc", "InvalidVpcID.NotFound")):
            owned = network[key]
            query = {idfield + "s": [owned["id"]]}
            result = self.call("cleanup-" + key + "-identity", "ec2", describe, query, required=False)
            if result:
                resource = result[field][0]
                if {tag["Key"]: tag["Value"] for tag in resource.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Network ownership tag changed")
                self.call("cleanup-delete-" + key, "ec2", delete, {idfield: owned["id"]})
            elif self.code() != absent:
                raise RuntimeError("Network resource absence not proven")
            self.absent("cleanup-" + key + "-absent", "ec2", describe, query, absent)
            owned["deleted"] = True
            self.save_prerequisite()
        role = inventory["service_linked_role"]
        request = {"RoleName": role["name"]}
        result = self.call("cleanup-owned-service-role-identity", "iam", "get_role", request, required=False)
        if not result and self.code() == "NoSuchEntity":
            role["deleted"] = True
        else:
            if not result or (result["Role"]["Arn"], result["Role"]["RoleId"]) != (role["arn"], role["id"]):
                raise RuntimeError("Service-linked role identity changed; refusing deletion")
            if not role.get("deletion_task"):
                role["deletion_task"] = self.call("cleanup-delete-owned-service-role", "iam",
                    "delete_service_linked_role", request)["DeletionTaskId"]
                self.save_prerequisite()
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                status = self.call("cleanup-service-role-deletion-status", "iam", "get_service_linked_role_deletion_status",
                    {"DeletionTaskId": role["deletion_task"]}, required=False)
                if not status:
                    if self.code() != "NoSuchEntity":
                        raise RuntimeError("Unexpected service-role deletion-status failure")
                    # Native task registration can lag DeleteServiceLinkedRole.
                    # Missing task status is not proof that the role is absent.
                    time.sleep(3)
                    continue
                if status["Status"] == "SUCCEEDED":
                    self.absent("cleanup-service-role-absent", "iam", "get_role", request, "NoSuchEntity")
                    role["deleted"] = True
                    break
                if status["Status"] == "FAILED":
                    role["deletion_failure"] = status
                    role.pop("deletion_task")
                    self.save_prerequisite()
                    raise RuntimeError("Owned service-role deletion failed native dependency checks; no other resources modified")
                time.sleep(3)
            else:
                raise RuntimeError("Service-role deletion bounded wait expired")
        self.prerequisite["cleanup"] = {"complete": True, "finished_at": now()}
        self.save_prerequisite()

    def cleanup(self):
        # Discover mappings whose creation response may have been lost.
        function = self.data["owned"].get("function", {})
        if function.get("arn"):
            self.cleanup_phase = True
            marker = None
            while True:
                request = {"FunctionName": function["arn"]}
                if marker:
                    request["Marker"] = marker
                response = self.call("cleanup-owned-function-mapping-inventory", "lambda", "list_event_source_mappings", request)
                for mapping in response.get("EventSourceMappings", []):
                    targets = [function["arn"]] + [function["arn"] + ":" + alias for alias in function["aliases"]]
                    if mapping.get("FunctionArn") not in targets or mapping.get("EventSourceArn") not in self.source_arns():
                        raise RuntimeError("Unexpected mapping identity; refusing deletion")
                    if mapping["UUID"] not in self.data["owned"]["mappings"]:
                        self.data["owned"]["mappings"].append(mapping["UUID"])
                self.save()
                marker = response.get("NextMarker")
                if not marker:
                    break
        SelfManagedKafkaProbe.delete_change_set(self)

        def source_cleanup(attempt):
            def remove_secret():
                secret = self.data["owned"]["secret"]
                request = {"SecretId": secret.get("arn", secret["name"])}
                value = self.call("cleanup-secret-identity", "secretsmanager", "describe_secret", request, required=False)
                if not value and self.code() == "ResourceNotFoundException":
                    return
                if {tag["Key"]: tag["Value"] for tag in value.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Secret ownership changed")
                if not value.get("DeletedDate"):
                    self.call("cleanup-delete-secret", "secretsmanager", "delete_secret", {**request, "ForceDeleteWithoutRecovery": True})
                self.wait_resource("cleanup-secret-absent", "secretsmanager", "describe_secret", request,
                    lambda value, code: code == "ResourceNotFoundException")
            if "secret" in self.data["owned"]:
                attempt("dummy secret", remove_secret)
            attempt("MSK source/network/service-linked role", self.cleanup_source)

        super().cleanup(source_cleanup=source_cleanup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_msk_mapping.json"))
    parser.add_argument("--ethics-review", type=Path, required=True)
    parser.add_argument("--prerequisite-inventory", type=Path, required=True)
    parser.add_argument("--permissions-review", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    args.schema_output = None
    probe = MSKProbe(args)

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
