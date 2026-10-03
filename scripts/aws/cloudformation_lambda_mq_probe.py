#!/usr/bin/env python3
"""Capture disabled native CFN MQ mappings; fresh exact-scope review required.

Run ActiveMQ first, then RabbitMQ with --previous pointing at the verified
clean ActiveMQ evidence. Both share the original review's 5400-second deadline.
No broker queues, messages, native invocations, or public network are created.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import time
import urllib.error
import urllib.request
import uuid

import boto3
import botocore
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config

from aws_cli import call as cli_call
from cloudformation_lambda_alias_probe import recorded
from cloudformation_lambda_kinesis_mapping_probe import KinesisMappingProbe
from cloudformation_lambda_version_probe import VersionProbe
from cloudtrail_service_probe import REGION, now

CFN = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/"
LAMBDA = "https://docs.aws.amazon.com/lambda/latest/"
SOURCES = [CFN + "aws-resource-lambda-eventsourcemapping.md",
    CFN + "aws-properties-lambda-eventsourcemapping-sourceaccessconfiguration.md"] + [
    LAMBDA + "dg/" + name + ".md" for name in
    ("with-mq", "services-mq-params", "process-mq-messages-with-lambda", "with-mq-filtering")] + [
    LAMBDA + "api/API_" + name + ".md" for name in ("CreateEventSourceMapping", "UpdateEventSourceMapping", "SourceAccessConfiguration")]


class MQProbe(KinesisMappingProbe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        approval = json.loads(args.ethics_review.read_text())
        if not approval.get("allowed") or (approval.get("account"), approval.get("region"), approval.get("actor")) != (self.account, REGION, self.actor):
            raise RuntimeError("Fresh exact-scope mounted review required")
        remaining = (datetime.fromisoformat(approval["deadline"]) - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0 or remaining > 5400:
            raise RuntimeError("Review deadline outside original 5400-second bound")
        self.end = time.monotonic() + remaining
        self.workflow_end = self.end - 1200
        self.cleanup_phase = False
        environment = dict(os.environ, AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
            AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_MAX_ATTEMPTS="1")
        identity = cli_call("sts", "get-caller-identity", {}, environment)
        if (identity["Account"], identity["Arn"]) != (self.account, self.actor):
            raise RuntimeError("Actor outside approved scope")
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
            retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=30)
        self.clients = {name: self.session.client(name, config=config) for name in
            ("sts", "iam", "lambda", "cloudformation", "ec2", "mq", "secretsmanager")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        for name, client in self.clients.items():
            expected = "https://iam.amazonaws.com" if name == "iam" else "https://" + name + "." + REGION + ".amazonaws.com"
            if client.meta.endpoint_url != expected:
                raise RuntimeError("Unexpected endpoint " + client.meta.endpoint_url)
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if (self.data["account"], self.data["region"], self.data["actor"]) != (self.account, REGION, self.actor) or not self.data["prefix"].startswith("stackd-cfn-mq-"):
                raise RuntimeError("Not an exact-owned MQ inventory")
            self.data.setdefault("recovery_reviews", []).append(approval)
            self.data.setdefault("cleanup_attempts", []).append(copy.deepcopy(self.data["cleanup"]))
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite evidence")
            previous = None
            if args.engine == "RABBITMQ":
                if not args.previous:
                    raise RuntimeError("RabbitMQ requires verified first broker cleanup evidence")
                previous = json.loads(args.previous.read_text())
                if (previous["account"], previous["region"], previous["actor"], previous["engine"]) != (self.account, REGION, self.actor, "ACTIVEMQ") or not previous["cleanup"]["complete"] or previous["ethics_review"]["deadline"] != approval["deadline"]:
                    raise RuntimeError("First broker not verified clean under same original review")
            self.data = {"source": "Native AWS public endpoints; guarded CLI STS and signed boto3/raw SigV4 controls",
                "captured_at": now(), "account": self.account, "region": REGION, "actor": self.actor,
                "prefix": "stackd-cfn-mq-" + uuid.uuid4().hex[:12], "engine": args.engine,
                "ethics_review": approval, "guard_identity": identity,
                "previous_capture": str(args.previous) if previous else None,
                "bounds": {"stack_wait_seconds": 300, "resource_wait_seconds": 180,
                    "poll_seconds": 3, "total_seconds": 5400, "reserved_cleanup_seconds": 1200,
                    "maximum_brokers_total": 2, "maximum_concurrent_brokers": 1,
                    "source_ready_seconds": 1200, "maximum_stack_updates": 24},
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
                "owned": {"stacks": {}, "streams": {}, "mappings": [], "network": {}, "secrets": {}},
                "calls": [], "templates": {}, "findings": {}, "documentation": [], "sources": SOURCES,
                "cleanup": {"complete": False}, "workflow_complete": False,
                "calibration_gaps": ["All mappings disabled and functions concurrency zero: no delivery, invocation, queue creation, broker connectivity, or ack/redelivery observation.",
                    "Broker queue existence is not inspected by a protocol client; the harness never creates queues.",
                    "EventSourceArn replacement to another live broker is outside one-concurrent-broker scope.",
                    "Enabled omission is not exercised because all mappings must remain disabled."]}
        self.save()
        native = self.call("identity-before-writes", "sts", "get_caller_identity")
        if (native["Account"], native["Arn"]) != (self.account, self.actor):
            raise RuntimeError("SDK identity differs from guarded actor")

    def save(self):
        def scrub(value):
            if isinstance(value, dict):
                return {k: "<redacted-synthetic-credential>" if k in ("SecretString", "Password") else scrub(v) for k, v in value.items()}
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
            raise RuntimeError("Original approved deadline reached; durable inventory retained")
        if service == "lambda" and operation in ("create_event_source_mapping", "update_event_source_mapping") and (request or {}).get("Enabled") is not False:
            raise RuntimeError("Every direct mapping mutation must explicitly remain disabled")
        if operation in ("invoke", "invoke_async"):
            raise RuntimeError("Native invocation prohibited")
        return super().call(label, service, operation, request, required=required)

    def documents(self):
        for source in SOURCES:
            try:
                with urllib.request.urlopen(source, timeout=25) as response:
                    raw = response.read()
                self.data["documentation"].append({"source": source, "captured_at": now(),
                    "sha256": hashlib.sha256(raw).hexdigest(), "content": raw.decode()})
            except Exception as error:
                self.data["calibration_gaps"].append(source + ": " + str(error))
            self.save()
        super().documents()
        model = self.clients["lambda"].meta.service_model
        self.data["sdk"]["mapping_operations"] = {name: {"input_members": list(model.operation_model(name).input_shape.members),
            "required": model.operation_model(name).input_shape.required_members} for name in ("CreateEventSourceMapping", "UpdateEventSourceMapping")}
        self.save()

    def source_arns(self):
        arn = self.data["owned"].get("broker", {}).get("arn")
        return [arn] if arn else []

    def template(self, properties):
        function = self.data["owned"]["function"]
        targets = [function["arn"]] + [function["arn"] + ":" + q for q in function.get("aliases", []) + function.get("versions", [])]
        if properties.get("FunctionName") not in targets:
            raise RuntimeError("Target outside exact-owned function/qualifiers")
        for access in properties.get("SourceAccessConfigurations", []):
            if access["Type"] == "BASIC_AUTH" and access["URI"] not in [s["arn"] for s in self.data["owned"]["secrets"].values()]:
                raise RuntimeError("Authentication outside owned secrets")
            if access["Type"] not in ("BASIC_AUTH", "VIRTUAL_HOST"):
                raise RuntimeError("Source access outside bounded controls")
        return super().template(properties)

    def setup_source(self):
        owned, prefix, engine = self.data["owned"], self.data["prefix"], self.data["engine"]
        types = self.call("current-engine-versions", "mq", "describe_broker_engine_types", {"MaxResults": 100})
        options = self.call("current-instance-options", "mq", "describe_broker_instance_options", {"EngineType": engine, "MaxResults": 100})
        host = "mq.t3.micro" if engine == "ACTIVEMQ" else "mq.m7g.medium"
        matches = [v for v in options["BrokerInstanceOptions"] if v["HostInstanceType"] == host and "SINGLE_INSTANCE" in v["SupportedDeploymentModes"]]
        if not matches:
            raise RuntimeError("Reviewed smallest instance unavailable; no enlargement permitted")
        option = matches[0]
        versions = next(v["EngineVersions"] for v in types["BrokerEngineTypes"] if v["EngineType"] == engine)
        version = next(v["Name"] for v in versions if v["Name"] in option["SupportedEngineVersions"])
        expected = "5.19" if engine == "ACTIVEMQ" else "4.3"
        if version != expected:
            raise RuntimeError("Current supported version differs from exact fresh review")
        self.finding("smallest-supported-source", {"engine": engine, "host": host, "version": version, "option": option})
        role = self.call("service-linked-role-before", "iam", "get_role", {"RoleName": "AWSServiceRoleForAmazonMQ"}, required=False)
        owned["service_linked_role"] = {"preexisting": bool(role), "before": role}
        self.save()
        if not role:
            if self.code() != "NoSuchEntity":
                raise RuntimeError("Unverified service-linked role state")
            owned["service_linked_role"]["creation_attempted"] = True
            self.save()
            created = self.call("create-owned-service-linked-role", "iam", "create_service_linked_role", {"AWSServiceName": "mq.amazonaws.com"})["Role"]
            owned["service_linked_role"].update(id=created["RoleId"], arn=created["Arn"])
            self.save()
        existing = self.call("broker-name-absent", "mq", "list_brokers", {"MaxResults": 100})
        if existing.get("NextToken") or any(b["BrokerName"] == prefix for b in existing.get("BrokerSummaries", [])):
            raise RuntimeError("Unable to verify exact broker name absence")
        tags = [{"Key": "stackd-probe", "Value": prefix}]
        net = owned["network"]
        net["vpc"] = {"creation_attempted": True}
        self.save()
        net["vpc"]["id"] = self.call("create-private-vpc", "ec2", "create_vpc", {"CidrBlock": "10.218.0.0/24", "TagSpecifications": [{"ResourceType": "vpc", "Tags": tags}]})["Vpc"]["VpcId"]
        self.save()
        self.call("enable-private-vpc-dns", "ec2", "modify_vpc_attribute", {"VpcId": net["vpc"]["id"], "EnableDnsHostnames": {"Value": True}})
        net["subnet"] = {"creation_attempted": True}
        self.save()
        net["subnet"]["id"] = self.call("create-private-subnet", "ec2", "create_subnet", {"VpcId": net["vpc"]["id"], "CidrBlock": "10.218.0.0/24", "AvailabilityZone": option["AvailabilityZones"][0]["Name"], "TagSpecifications": [{"ResourceType": "subnet", "Tags": tags}]})["Subnet"]["SubnetId"]
        self.save()
        net["security_group"] = {"creation_attempted": True}
        self.save()
        net["security_group"]["id"] = self.call("create-private-security-group", "ec2", "create_security_group", {"GroupName": prefix, "Description": "Exact-owned disabled MQ calibration; no public ingress", "VpcId": net["vpc"]["id"], "TagSpecifications": [{"ResourceType": "security-group", "Tags": tags}]})["GroupId"]
        self.save()
        port = 61617 if engine == "ACTIVEMQ" else 5671
        self.call("self-only-broker-ingress", "ec2", "authorize_security_group_ingress", {"GroupId": net["security_group"]["id"], "IpPermissions": [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "UserIdGroupPairs": [{"GroupId": net["security_group"]["id"]}]}]})
        password = "Owned" + uuid.uuid4().hex
        for key in ("first", "second"):
            name = prefix + "-" + key
            self.absent(key + "-secret-name-absent", "secretsmanager", "describe_secret", {"SecretId": name}, "ResourceNotFoundException")
            owned["secrets"][key] = {"name": name, "creation_attempted": True, "absence_verified": True}
            self.save()
            owned["secrets"][key]["arn"] = self.call("create-owned-" + key + "-secret", "secretsmanager", "create_secret", {"Name": name, "SecretString": json.dumps({"username": "ownedprobe", "password": password}), "Tags": tags})["ARN"]
            self.save()
        owned["broker"] = {"name": prefix, "creation_attempted": True, "absence_verified": True}
        self.save()
        user = {"Username": "ownedprobe", "Password": password}
        if engine == "ACTIVEMQ":
            user["ConsoleAccess"] = False
        broker = self.call("create-private-single-broker", "mq", "create_broker", {"BrokerName": prefix, "CreatorRequestId": prefix,
            "EngineType": engine, "EngineVersion": version, "HostInstanceType": host, "DeploymentMode": "SINGLE_INSTANCE",
            "PubliclyAccessible": False, "AutoMinorVersionUpgrade": True, "StorageType": option["StorageType"],
            "SubnetIds": [net["subnet"]["id"]], "SecurityGroups": [net["security_group"]["id"]],
            "Users": [user], "Tags": {"stackd-probe": prefix}})
        owned["broker"].update(id=broker["BrokerId"], arn=broker["BrokerArn"])
        self.save()
        self.setup_function()
        deadline = min(self.workflow_end, time.monotonic() + self.data["bounds"]["source_ready_seconds"])
        while time.monotonic() < deadline:
            value = self.call("broker-readiness", "mq", "describe_broker", {"BrokerId": broker["BrokerId"]})
            self.remember_configuration(value)
            if value["BrokerState"] == "RUNNING":
                self.finding("private-broker-ready", value)
                return
            if value["BrokerState"] in ("CREATION_FAILED", "CRITICAL_ACTION_REQUIRED"):
                raise RuntimeError("Native broker terminal provisioning boundary: " + value["BrokerState"])
            time.sleep(15)
        raise RuntimeError("Broker provisioning bound expired; no scope expansion")

    def remember_configuration(self, broker):
        identifier = broker.get("Configurations", {}).get("Current", {}).get("Id")
        if not identifier or self.data["owned"].get("configuration", {}).get("id") == identifier:
            return
        config = self.call("automatic-configuration-identity", "mq", "describe_configuration", {"ConfigurationId": identifier})
        prefix = self.data["prefix"]
        if config["Name"] != prefix + "-configuration" or config["Created"] < datetime.fromisoformat(self.data["captured_at"]) or not config["LatestRevision"].get("Description", "").startswith("Auto-generated default for " + prefix + "-configuration "):
            raise RuntimeError("Unproven automatic configuration ownership")
        self.data["owned"]["configuration"] = {"id": identifier, "arn": config["Arn"], "name": config["Name"]}
        self.save()

    def setup_function(self):
        VersionProbe.setup(self)
        owned = self.data["owned"]
        function = owned["function"]
        self.call("reserve-zero-concurrency", "lambda", "put_function_concurrency", {"FunctionName": function["arn"], "ReservedConcurrentExecutions": 0})
        self.call("confirm-zero-concurrency", "lambda", "get_function_concurrency", {"FunctionName": function["arn"]})
        net = owned["network"]
        root = "arn:aws:ec2:" + REGION + ":" + self.account + ":"
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "mq:DescribeBroker", "Resource": owned["broker"]["arn"]},
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": [v["arn"] for v in owned["secrets"].values()]},
            {"Effect": "Allow", "Action": ["ec2:DescribeNetworkInterfaces", "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"], "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:CreateNetworkInterface", "Resource": [root + "subnet/" + net["subnet"]["id"], root + "security-group/" + net["security_group"]["id"]]},
            {"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface"], "Resource": root + "network-interface/*", "Condition": {"ArnEquals": {"ec2:Vpc": root + "vpc/" + net["vpc"]["id"]}}}]}
        owned["role"]["policy"] = "owned-mq-access"
        self.save()
        self.call("put-owned-source-policy", "iam", "put_role_policy", {"RoleName": owned["role"]["name"], "PolicyName": owned["role"]["policy"], "PolicyDocument": json.dumps(policy)})
        time.sleep(15)
        version = self.call("publish-owned-noninvoked-version", "lambda", "publish_version", {"FunctionName": function["arn"]})["Version"]
        function["versions"].append(version)
        function["aliases"] = ["owned-target"]
        self.save()
        self.call("create-owned-alias", "lambda", "create_alias", {"FunctionName": function["arn"], "Name": "owned-target", "FunctionVersion": version})

    def transition(self, label, current, proposed):
        if proposed == current:
            self.finding(label, {"not_submitted": "Template unchanged after preceding native rollback"})
            return current
        if sum(row["operation"] == "UpdateStack" for row in self.data["calls"]) >= self.data["bounds"]["maximum_stack_updates"]:
            raise RuntimeError("Approved update bound exhausted")
        before = self.data["findings"]["current_mapping"]
        result = self.stack(label, proposed, update=True)
        status = result.get("stack_status")
        if status is None:
            self.finding(label + "-submission-rejected", result)
            return current
        if status not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError(label + ": nonterminal/failed rollback boundary " + str(status))
        after = result["mapping"]
        self.finding(label + "-transition", {"status": status, "old_uuid": before["UUID"], "new_uuid": after["UUID"],
            "replaced": before["UUID"] != after["UUID"], "before": before, "after": after})
        self.finding("current_mapping", after)
        if before["UUID"] != after["UUID"]:
            self.absent(label + "-old-uuid-absent", "lambda", "get_event_source_mapping", {"UUID": before["UUID"]}, "ResourceNotFoundException")
        return copy.deepcopy(proposed if status == "UPDATE_COMPLETE" else current)

    def direct_update(self, label, fields):
        before = self.data["findings"]["current_mapping"]
        request = {"UUID": before["UUID"], "Enabled": False, **fields}
        result = self.call(label, "lambda", "update_event_source_mapping", request, required=False)
        row = copy.deepcopy(self.data["calls"][-1])
        after = self.wait_resource(label + "-settled", "lambda", "get_event_source_mapping", {"UUID": before["UUID"]}, lambda v, c: v.get("State") == "Disabled")
        self.finding(label + "-owner-control", {"request": request, "code": row["code"], "error": row.get("error"), "result": result, "before": before, "after": after})
        self.finding("current_mapping", after)

    def direct_queue_control(self):
        if time.monotonic() >= self.workflow_end:
            raise RuntimeError("Original workflow deadline reached before raw owner control")
        before = self.data["findings"]["current_mapping"]
        url = self.clients["lambda"].meta.endpoint_url + "/2015-03-31/event-source-mappings/" + before["UUID"]
        body = {"Enabled": False, "Queues": [self.data["prefix"] + "-direct-queue"]}
        row = {"label": "direct-queues-raw-owner-control", "service": "lambda", "operation": "UpdateEventSourceMappingRaw",
            "input": body, "url": url, "started_at": now(), "code": "Pending", "phase": "workflow"}
        self.data["calls"].append(row)
        self.save()
        request = AWSRequest(method="PUT", url=url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        SigV4Auth(self.credentials, "lambda", REGION).add_auth(request)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=request.data, method="PUT", headers=dict(request.headers)), timeout=30) as response:
                row.update(code="Success", http_status=response.status, output=json.loads(response.read()), request_id=response.headers.get("x-amzn-RequestId"))
        except urllib.error.HTTPError as error:
            row.update(code=error.headers.get("x-amzn-ErrorType", str(error.code)), http_status=error.code, output=json.loads(error.read()))
        finally:
            row["finished_at"] = now()
            self.save()
        after = self.wait_resource("direct-queues-raw-settled", "lambda", "get_event_source_mapping", {"UUID": before["UUID"]}, lambda v, c: v.get("State") == "Disabled")
        self.finding("direct-queues-raw-owner-control", {"before": before, "after": after, "request": body, "response": row})
        self.finding("current_mapping", after)

    def virtual_host_controls(self):
        source = json.loads(self.args.source_inventory.read_text())
        if (source["account"], source["region"], source["actor"], source["engine"]) != (self.account, REGION, self.actor, self.args.engine) or source["ethics_review"]["deadline"] != self.data["ethics_review"]["deadline"]:
            raise RuntimeError("Supplement requires the original exact-created engine inventory")
        self.data["mode"] = "independent-disabled-virtual-host-control"
        self.data["referenced_exact_owned"] = {k: source["owned"][k] for k in ("broker", "function", "secrets")}
        self.data["source_capture"] = str(self.args.source_inventory)
        self.save()
        owned = self.data["referenced_exact_owned"]
        function = owned["function"]["arn"]
        if self.call("control-concurrency-zero", "lambda", "get_function_concurrency", {"FunctionName": function}).get("ReservedConcurrentExecutions") != 0:
            raise RuntimeError("Supplement requires zero reserved concurrency")
        deadline = min(self.workflow_end, time.monotonic() + 1200)
        while time.monotonic() < deadline:
            value = self.call("control-source-readiness", "mq", "describe_broker", {"BrokerId": owned["broker"]["id"]})
            if value["BrokerArn"] != owned["broker"]["arn"] or value.get("Tags", {}).get("stackd-probe") != source["prefix"]:
                raise RuntimeError("Supplement broker identity mismatch")
            if value["BrokerState"] == "RUNNING":
                break
            if value["BrokerState"] in ("DELETION_IN_PROGRESS", "CREATION_FAILED"):
                raise RuntimeError("Supplement source unavailable; no recreation")
            time.sleep(15)
        else:
            raise RuntimeError("Supplement bounded source readiness expired")
        auth = [{"Type": "BASIC_AUTH", "URI": owned["secrets"]["first"]["arn"]}]
        host = self.args.virtual_host
        changed_host = "owned-never-created" if host == "/" else "/"
        create = {"FunctionName": function, "EventSourceArn": owned["broker"]["arn"], "Enabled": False,
            "Queues": [self.data["prefix"] + "-never-created"], "SourceAccessConfigurations": auth + [{"Type": "VIRTUAL_HOST", "URI": host}]}
        if self.args.omit_virtual_host:
            create["SourceAccessConfigurations"] = auth
        self.data["control_create_request"] = create
        self.save()
        label = "direct-omitted-virtual-host-create" if self.args.omit_virtual_host else "direct-explicit-virtual-host-create"
        result = self.call(label, "lambda", "create_event_source_mapping", create, required=False)
        if result.get("UUID"):
            self.data["owned"]["mappings"].append(result["UUID"])
            self.save()
            mapping = self.wait_resource("control-disabled", "lambda", "get_event_source_mapping", {"UUID": result["UUID"]}, lambda v, c: v.get("State") == "Disabled")
            self.finding("current_mapping", mapping)
            if not self.args.omit_virtual_host:
                self.direct_update("direct-unchanged-virtual-host", {"SourceAccessConfigurations": auth + [{"Type": "VIRTUAL_HOST", "URI": host}]})
                self.direct_update("direct-changed-virtual-host", {"SourceAccessConfigurations": auth + [{"Type": "VIRTUAL_HOST", "URI": changed_host}]})
                self.direct_update("direct-auth-only-retains-host", {"SourceAccessConfigurations": [{"Type": "BASIC_AUTH", "URI": owned["secrets"]["second"]["arn"]}]})
        self.data["workflow_complete"] = True
        self.save()

    def cleanup_virtual_host_controls(self):
        self.cleanup_phase = True
        expected = self.data.get("control_create_request")
        if expected:
            values = self.call("control-cleanup-recover-mapping", "lambda", "list_event_source_mappings", {"FunctionName": expected["FunctionName"], "EventSourceArn": expected["EventSourceArn"]})
            for value in values.get("EventSourceMappings", []):
                if value.get("Queues") == expected["Queues"] and value["UUID"] not in self.data["owned"]["mappings"]:
                    self.data["owned"]["mappings"].append(value["UUID"])
            self.save()
            for identifier in self.data["owned"]["mappings"]:
                value = self.call("control-cleanup-mapping-identity", "lambda", "get_event_source_mapping", {"UUID": identifier}, required=False)
                if value:
                    if value["FunctionArn"] != expected["FunctionName"] or value["EventSourceArn"] != expected["EventSourceArn"] or value["Queues"] != expected["Queues"]:
                        raise RuntimeError("Supplement mapping identity mismatch")
                    self.call("control-cleanup-delete-mapping", "lambda", "delete_event_source_mapping", {"UUID": identifier})
                self.wait_resource("control-cleanup-mapping-absent", "lambda", "get_event_source_mapping", {"UUID": identifier}, lambda v, c: c == "ResourceNotFoundException")
        self.data["cleanup"].update(complete=True, finished_at=now(), boundary="Only supplement mapping IDs deleted; original capture retains responsibility for referenced exact-created broker/function/network/secrets")
        self.save()

    def workflow(self):
        self.documents()
        self.setup_source()
        owned, prefix = self.data["owned"], self.data["prefix"]
        auth = lambda key: [{"Type": "BASIC_AUTH", "URI": owned["secrets"][key]["arn"]}]
        current = {"FunctionName": owned["function"]["arn"], "EventSourceArn": owned["broker"]["arn"],
            "Enabled": False, "Queues": [prefix + "-never-created"], "SourceAccessConfigurations": auth("first")}
        if self.data["engine"] == "RABBITMQ":
            current["SourceAccessConfigurations"].append({"Type": "VIRTUAL_HOST", "URI": "/"})
        initial = self.stack("initial-omitted-batch-window", current)
        if initial.get("stack_status") != "CREATE_COMPLETE":
            self.finding("initial-admission-boundary", {"positive_mapping_observed": False, "native_result": initial})
            return
        self.finding("current_mapping", initial["mapping"])
        current = self.transition("explicit-batch-window", current, {**current, "BatchSize": 17, "MaximumBatchingWindowInSeconds": 2})
        current = self.transition("remove-batch-window", current, {k: v for k, v in current.items() if k not in ("BatchSize", "MaximumBatchingWindowInSeconds")})
        current = self.transition("add-filter", current, {**current, "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"data": {"probe": [prefix]}})}]}})
        current = self.transition("remove-filter", current, {k: v for k, v in current.items() if k != "FilterCriteria"})
        current = self.transition("change-source-access", current, {**current, "SourceAccessConfigurations": auth("second")})
        current = self.transition("remove-source-access", current, {k: v for k, v in current.items() if k != "SourceAccessConfigurations"})
        current = self.transition("reintroduce-source-access", current, {**current, "SourceAccessConfigurations": auth("first")})
        current = self.transition("change-queues", current, {**current, "Queues": [prefix + "-other-never-created"]})
        current = self.transition("remove-queues", current, {k: v for k, v in current.items() if k != "Queues"})
        current = self.transition("combined-queue-auth-batch", current, {**current, "Queues": [prefix + "-combined-never-created"], "SourceAccessConfigurations": auth("second"), "BatchSize": 23})
        if self.data["engine"] == "RABBITMQ":
            current = self.transition("add-virtual-host", current, {**current, "SourceAccessConfigurations": auth("second") + [{"Type": "VIRTUAL_HOST", "URI": "/"}]})
            current = self.transition("change-virtual-host", current, {**current, "SourceAccessConfigurations": auth("second") + [{"Type": "VIRTUAL_HOST", "URI": "owned-never-created"}]})
            current = self.transition("remove-virtual-host", current, {**current, "SourceAccessConfigurations": auth("second")})
        for qualifier in ("owned-target", owned["function"]["versions"][0]):
            current = self.transition("qualified-target-" + qualifier, current, {**current, "FunctionName": owned["function"]["arn"] + ":" + qualifier})
        actual = self.data["findings"]["current_mapping"]
        duplicate = {"FunctionName": actual["FunctionArn"], "EventSourceArn": actual["EventSourceArn"], "Queues": actual["Queues"],
            "SourceAccessConfigurations": actual["SourceAccessConfigurations"], "Enabled": False}
        value = self.call("direct-disabled-duplicate", "lambda", "create_event_source_mapping", duplicate, required=False)
        if value.get("UUID") and value["UUID"] != actual["UUID"]:
            owned["mappings"].append(value["UUID"])
            self.save()
            self.call("delete-owned-duplicate-control", "lambda", "delete_event_source_mapping", {"UUID": value["UUID"]})
            self.wait_resource("duplicate-control-absent", "lambda", "get_event_source_mapping", {"UUID": value["UUID"]}, lambda v, c: c == "ResourceNotFoundException")
        current = self.transition("replacement-starting-position", current, {**current, "StartingPosition": "LATEST"})
        current = self.transition("remove-starting-position", current, {k: v for k, v in current.items() if k != "StartingPosition"})
        self.direct_update("direct-auth-second", {"SourceAccessConfigurations": auth("second")})
        self.direct_update("direct-auth-empty", {"SourceAccessConfigurations": []})
        self.direct_update("direct-auth-first", {"SourceAccessConfigurations": auth("first")})
        if self.data["engine"] == "RABBITMQ":
            self.direct_update("direct-unchanged-virtual-host", {"SourceAccessConfigurations": auth("first") + [{"Type": "VIRTUAL_HOST", "URI": "/"}]})
            self.direct_update("direct-changed-virtual-host", {"SourceAccessConfigurations": auth("first") + [{"Type": "VIRTUAL_HOST", "URI": "owned-never-created"}]})
            self.direct_update("direct-auth-only-retains-host", {"SourceAccessConfigurations": auth("second")})
        self.direct_queue_control()
        self.data["workflow_complete"] = True
        self.save()

    def cleanup_source(self, attempt):
        owned = self.data["owned"]
        def remove_broker():
            item = owned["broker"]
            if not item.get("id"):
                token = None
                while True:
                    page = self.call("recover-exact-broker", "mq", "list_brokers", {"MaxResults": 100, **({"NextToken": token} if token else {})})
                    for broker in page.get("BrokerSummaries", []):
                        if broker["BrokerName"] == item["name"]:
                            tags = self.call("recovered-broker-tags", "mq", "list_tags", {"ResourceArn": broker["BrokerArn"]})
                            if tags.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                                raise RuntimeError("Recovered broker owner mismatch")
                            item.update(id=broker["BrokerId"], arn=broker["BrokerArn"])
                            self.save()
                    token = page.get("NextToken")
                    if not token:
                        break
                if not item.get("id"):
                    item["absence_verified_after_attempt"] = True
                    self.save()
                    return
            request = {"BrokerId": item["id"]}
            value = self.call("cleanup-broker-identity", "mq", "describe_broker", request, required=False)
            if value:
                if value["BrokerArn"] != item["arn"] or value["BrokerName"] != item["name"] or value.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Broker ownership mismatch")
                self.remember_configuration(value)
            elif self.code() != "NotFoundException":
                raise RuntimeError("Unverified broker identity")
            deadline = min(self.end, time.monotonic() + 900)
            while value and time.monotonic() < deadline:
                if value["BrokerState"] != "DELETION_IN_PROGRESS":
                    self.call("cleanup-delete-broker", "mq", "delete_broker", request, required=False)
                    if self.code() not in ("Success", "BadRequestException", "ConflictException"):
                        raise RuntimeError("Unexpected broker delete result")
                time.sleep(10)
                value = self.call("cleanup-broker-absent", "mq", "describe_broker", request, required=False)
                if not value and self.code() != "NotFoundException":
                    raise RuntimeError("Unverified broker deletion")
            if value:
                raise RuntimeError("Broker deletion bounded wait expired")
            item["deleted"] = True
            self.save()
        def remove_configuration():
            if not owned.get("broker", {}).get("deleted"):
                raise RuntimeError("Broker absence required before configuration removal")
            item = owned["configuration"]
            request = {"ConfigurationId": item["id"]}
            value = self.call("cleanup-configuration-identity", "mq", "describe_configuration", request, required=False)
            if value:
                if value["Arn"] != item["arn"] or value["Name"] != item["name"]:
                    raise RuntimeError("Configuration identity mismatch")
                self.call("cleanup-delete-configuration", "mq", "delete_configuration", request)
            self.absent("cleanup-configuration-absent", "mq", "describe_configuration", request, "NotFoundException")
        def remove_secret(key):
            item = owned["secrets"][key]
            request = {"SecretId": item.get("arn", item["name"])}
            value = self.call("cleanup-" + key + "-secret-identity", "secretsmanager", "describe_secret", request, required=False)
            if value:
                if {t["Key"]: t["Value"] for t in value.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Secret owner mismatch")
                self.call("cleanup-delete-" + key + "-secret", "secretsmanager", "delete_secret", {**request, "ForceDeleteWithoutRecovery": True})
            self.wait_resource("cleanup-" + key + "-secret-absent", "secretsmanager", "describe_secret", request, lambda v, c: c == "ResourceNotFoundException")
        def release_network():
            net = owned["network"]
            deadline = min(self.end, time.monotonic() + 300)
            while time.monotonic() < deadline:
                value = self.call("cleanup-owned-network-release", "ec2", "describe_network_interfaces", {"Filters": [{"Name": "vpc-id", "Values": [net["vpc"]["id"]]}]})
                if not value["NetworkInterfaces"]:
                    return
                time.sleep(10)
            raise RuntimeError("Owned VPC network interfaces not released")
        def remove_network(key, describe, field, plural, singular, delete, code):
            item = owned["network"][key]
            if not item.get("id"):
                raise RuntimeError("Unconfirmed network create; retained ledger: " + key)
            request = {plural: [item["id"]]}
            value = self.call("cleanup-" + key + "-identity", "ec2", describe, request, required=False)
            if value:
                if {t["Key"]: t["Value"] for t in value[field][0].get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Network owner mismatch")
                self.call("cleanup-delete-" + key, "ec2", delete, {singular: item["id"]})
            self.absent("cleanup-" + key + "-absent", "ec2", describe, request, code)
        def remove_service_role():
            item = owned["service_linked_role"]
            request = {"RoleName": "AWSServiceRoleForAmazonMQ"}
            value = self.call("cleanup-service-role-identity", "iam", "get_role", request, required=False)
            if item["preexisting"]:
                if not value or value["Role"]["RoleId"] != item["before"]["Role"]["RoleId"]:
                    raise RuntimeError("Preexisting service-linked role changed")
                item["preserved_verified"] = True
                self.save()
                return
            if value:
                if value["Role"]["RoleId"] != item.get("id"):
                    raise RuntimeError("Unproven service role ownership")
                task = self.call("cleanup-delete-created-service-role", "iam", "delete_service_linked_role", request)
                item["deletion_task"] = task
                self.save()
                deadline = min(self.end, time.monotonic() + self.data["bounds"]["resource_wait_seconds"])
                while time.monotonic() < deadline:
                    result = self.call("cleanup-service-role-deletion", "iam", "get_service_linked_role_deletion_status", task, required=False)
                    if self.code() not in ("Success", "NoSuchEntity"):
                        raise RuntimeError("Unexpected service role deletion status")
                    if result.get("Status") == "FAILED":
                        raise RuntimeError("Service role deletion failed")
                    if result.get("Status") == "SUCCEEDED":
                        break
                    # AWS can return NoSuchEntity for a newly-issued task while
                    # its role still exists. Only role absence proves deletion.
                    current = self.call("cleanup-service-role-pending-identity", "iam", "get_role", request, required=False)
                    if not current and self.code() == "NoSuchEntity":
                        break
                    if not current or current["Role"]["RoleId"] != item["id"]:
                        raise RuntimeError("Created service role identity changed during deletion")
                    time.sleep(self.data["bounds"]["poll_seconds"])
                else:
                    raise RuntimeError("Created service role deletion bounded wait expired")
            self.absent("cleanup-service-role-absent", "iam", "get_role", request, "NoSuchEntity")
        if "broker" in owned:
            attempt("broker", remove_broker)
        if "configuration" in owned:
            attempt("configuration", remove_configuration)
        for key in owned["secrets"]:
            attempt("secret " + key, lambda key=key: remove_secret(key))
        if owned["network"].get("vpc", {}).get("id"):
            attempt("network release", release_network)
        for row in [
            ("security_group", "describe_security_groups", "SecurityGroups", "GroupIds", "GroupId", "delete_security_group", "InvalidGroup.NotFound"),
            ("subnet", "describe_subnets", "Subnets", "SubnetIds", "SubnetId", "delete_subnet", "InvalidSubnetID.NotFound"),
            ("vpc", "describe_vpcs", "Vpcs", "VpcIds", "VpcId", "delete_vpc", "InvalidVpcID.NotFound")]:
            if row[0] in owned["network"]:
                attempt(row[0], lambda row=row: remove_network(*row))
        if "service_linked_role" in owned:
            attempt("service-linked role", remove_service_role)

    def cleanup(self):
        self.cleanup_phase = True
        owned = self.data["owned"]
        # Recover direct-create responses lost after acceptance using exact source
        # and exact-owned function, including qualified targets.
        if owned.get("function", {}).get("arn"):
            marker = None
            while True:
                request = {"FunctionName": owned["function"]["arn"], **({"Marker": marker} if marker else {})}
                page = self.call("cleanup-owned-mapping-inventory", "lambda", "list_event_source_mappings", request)
                for value in page.get("EventSourceMappings", []):
                    if value.get("EventSourceArn") not in self.source_arns():
                        raise RuntimeError("Unexpected source on owned function")
                    if value["UUID"] not in owned["mappings"]:
                        owned["mappings"].append(value["UUID"])
                marker = page.get("NextMarker")
                self.save()
                if not marker:
                    break
        super().cleanup(source_cleanup=self.cleanup_source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ethics-review", type=Path, required=True)
    parser.add_argument("--engine", choices=("ACTIVEMQ", "RABBITMQ"), default="ACTIVEMQ")
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--source-inventory", type=Path,
        help="Fresh-reviewed independent VIRTUAL_HOST controls on this capture's exact-created source")
    parser.add_argument("--virtual-host", choices=("/", "owned-never-created"), default="/")
    parser.add_argument("--omit-virtual-host", action="store_true",
        help="Supplement only: capture BASIC_AUTH-only creation without virtual-host updates")
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    args.schema_output = None
    probe = MQProbe(args)
    def interrupted(signum, frame):
        raise RuntimeError("Interrupted; exact-owned cleanup follows")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    failure = None
    try:
        if not args.cleanup_only:
            if args.source_inventory:
                probe.virtual_host_controls()
            else:
                probe.workflow()
    except Exception as error:
        failure = str(error)
        probe.data.setdefault("failures", []).append({"at": now(), "error": failure})
        probe.save()
    finally:
        if args.source_inventory or probe.data.get("mode") == "independent-disabled-virtual-host-control":
            probe.cleanup_virtual_host_controls()
        else:
            probe.cleanup()
    if failure:
        raise RuntimeError(failure)


if __name__ == "__main__":
    main()
