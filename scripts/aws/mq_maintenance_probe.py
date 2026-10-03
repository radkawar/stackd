#!/usr/bin/env python3
"""Capture one exact-owned native MQ broker's maintenance or create-replay behavior."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import uuid

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import call as cli_call
from mq_create_identity import capture_identity, cleanup_replay_interfaces

REGION = "us-east-1"


def window(when):
    return {"DayOfWeek": when.strftime("%A").upper(), "TimeOfDay": when.strftime("%H:%M"), "TimeZone": "UTC"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=("maintenance", "create-identity"), default="maintenance")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30,
                    ignore_configured_endpoint_urls=True)
    session = boto3.Session(region_name=REGION)
    actor = cli_call("sts", "get-caller-identity", env=dict(os.environ, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_REGION=REGION))
    sdk_actor = session.client("sts", config=config).get_caller_identity()
    if actor["Account"] != args.account or sdk_actor["Arn"] != actor["Arn"]:
        raise RuntimeError("Refusing unexpected probe identity")
    mq = session.client("mq", config=config)
    iam = session.client("iam", config=config)
    ec2 = session.client("ec2", config=config)
    started = time.monotonic()
    deadline = started + 2400
    name = "stackd-mq-" + args.scenario + "-" + uuid.uuid4().hex[:16]
    model = session._session.get_component("data_loader").load_service_model("mq", "service-2")
    evidence = {
        "source": "Native AWS Amazon MQ " + args.scenario + " calibration", "account": args.account,
        "region": REGION, "actor": actor, "prefix": name, "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_urls": ["https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/maintaining-brokers.html"
                        if args.scenario == "maintenance" else "https://docs.aws.amazon.com/amazon-mq/latest/api-reference/brokers.html"],
        "source_model": {"botocore": botocore.__version__, "api_version": model["metadata"]["apiVersion"],
                         "sha256": hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest()},
        "bounds": {"brokers": 1, "vpcs": 1, "subnets": 1, "security_groups": 1, "internet_gateways": 1, "host_instance_type": "mq.t3.micro", "observation_seconds": 2400, "cleanup_seconds": 900},
        "owned": {}, "calls": [], "cleanup": [], "complete": False, "cleanup_verified": False,
        "limitations": ["One ActiveMQ public single-instance broker; not fleet, IAM, or protocol conformance.",
                        "Only the recorded inputs are calibrated; name/token reuse after deletion is not observed."],
    }

    if args.scenario == "maintenance":
        evidence["limitations"].extend([
            "A bounded wait without quota reset does not prove the reset never occurs.",
            "Quota admission after a window does not itself prove a native broker reboot.",
        ])

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    def call(client, method, params, label, cleanup=False):
        if not cleanup and time.monotonic() >= deadline:
            raise TimeoutError("Native observation deadline reached")
        captured = copy.deepcopy(params)
        if "Password" in captured:
            captured["Password"] = "<redacted>"
        for user in captured.get("Users", []):
            if "Password" in user:
                user["Password"] = "<redacted>"
        try:
            output = getattr(client, method)(**params)
            metadata = output.pop("ResponseMetadata", {})
            code = "Success"
        except ClientError as err:
            output = {k: v for k, v in err.response.items() if k != "ResponseMetadata"}
            metadata = err.response.get("ResponseMetadata", {})
            code = err.response["Error"]["Code"]
        row = {"label": label, "operation": client.meta.method_to_api_mapping[method], "parameters": captured,
               "code": code, "output": output, "http_status": metadata.get("HTTPStatusCode"),
               "request_id": metadata.get("RequestId"), "elapsed_seconds": round(time.monotonic() - started, 3)}
        evidence["cleanup" if cleanup else "calls"].append(row)
        save()
        print(label + ": " + code, flush=True)
        return row

    def success(row):
        if row["code"] != "Success":
            raise RuntimeError(row["label"] + ": " + row["code"])
        return row["output"]

    def wait_running(broker, label, require_transition=False):
        transitioned = not require_transition
        while True:
            state = success(call(mq, "describe_broker", {"BrokerId": broker}, label))
            transitioned |= state["BrokerState"] != "RUNNING"
            if state["BrokerState"] == "RUNNING" and transitioned:
                return state
            if state["BrokerState"] in ("CREATION_FAILED", "CRITICAL_ACTION_REQUIRED"):
                raise RuntimeError("Native broker failed: " + state["BrokerState"])
            time.sleep(10)

    role = call(iam, "get_role", {"RoleName": "AWSServiceRoleForAmazonMQ"}, "service-role-before")
    role_missing = role["code"] == "NoSuchEntity"
    broker_id = None
    vpc_id = subnet_id = group_id = gateway_id = route_table_id = None
    try:
        tags = [{"Key": "stackd-probe-owner", "Value": name}]
        vpc = success(call(ec2, "create_vpc", {"CidrBlock": "10.254.0.0/24", "TagSpecifications": [{"ResourceType": "vpc", "Tags": tags}]}, "create-owned-vpc"))
        vpc_id = vpc["Vpc"]["VpcId"]
        evidence["owned"]["vpc_id"] = vpc_id
        success(call(ec2, "modify_vpc_attribute", {"VpcId": vpc_id, "EnableDnsHostnames": {"Value": True}}, "enable-owned-vpc-dns"))
        gateway = success(call(ec2, "create_internet_gateway", {"TagSpecifications": [{"ResourceType": "internet-gateway", "Tags": tags}]}, "create-owned-gateway"))
        gateway_id = gateway["InternetGateway"]["InternetGatewayId"]
        evidence["owned"]["gateway_id"] = gateway_id
        success(call(ec2, "attach_internet_gateway", {"VpcId": vpc_id, "InternetGatewayId": gateway_id}, "attach-owned-gateway"))
        routes = success(call(ec2, "describe_route_tables", {"Filters": [{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "association.main", "Values": ["true"]}]}, "owned-main-route-table"))
        if len(routes["RouteTables"]) != 1:
            raise RuntimeError("Expected exactly one main route table in owned VPC")
        route_table_id = routes["RouteTables"][0]["RouteTableId"]
        evidence["owned"]["route_table_id"] = route_table_id
        success(call(ec2, "create_route", {"RouteTableId": route_table_id, "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": gateway_id}, "create-owned-public-route"))
        subnet = success(call(ec2, "create_subnet", {"VpcId": vpc_id, "CidrBlock": "10.254.0.0/26", "AvailabilityZone": "us-east-1a", "TagSpecifications": [{"ResourceType": "subnet", "Tags": tags}]}, "create-owned-subnet"))
        subnet_id = subnet["Subnet"]["SubnetId"]
        evidence["owned"]["subnet_id"] = subnet_id
        group = success(call(ec2, "create_security_group", {"VpcId": vpc_id, "GroupName": name, "Description": "Exact-owned MQ maintenance capture; no inbound rules", "TagSpecifications": [{"ResourceType": "security-group", "Tags": tags}]}, "create-owned-security-group"))
        group_id = group["GroupId"]
        evidence["owned"]["security_group_id"] = group_id
        initial_window = window(datetime.now(timezone.utc) + timedelta(hours=2))
        create_input = {
            "BrokerName": name, "CreatorRequestId": name, "EngineType": "ACTIVEMQ", "EngineVersion": "5.19",
            "HostInstanceType": "mq.t3.micro", "DeploymentMode": "SINGLE_INSTANCE", "PubliclyAccessible": True,
            "AutoMinorVersionUpgrade": True, "MaintenanceWindowStartTime": initial_window,
            "SubnetIds": [subnet_id], "SecurityGroups": [group_id],
            "Users": [{"Username": "ownedprobe", "Password": secrets.token_urlsafe(24), "ConsoleAccess": False}],
            "Tags": {"stackd-probe-owner": name},
        }
        created = success(call(mq, "create_broker", create_input, "create"))
        broker_id = created["BrokerId"]
        evidence["owned"].update({"broker_id": broker_id, "broker_arn": created["BrokerArn"]})
        save()
        current = wait_running(broker_id, "initial-running")
        if args.scenario == "create-identity":
            capture_identity(mq, call, success, create_input, broker_id, created["BrokerArn"])
            evidence["complete"] = True
            return
        for number in range(2):
            call(mq, "update_broker", {"BrokerId": broker_id, "MaintenanceWindowStartTime": current["MaintenanceWindowStartTime"]}, "unchanged-before-limit-" + str(number))
        call(mq, "update_broker", {"BrokerId": broker_id, "MaintenanceWindowStartTime": {"DayOfWeek": "INVALID", "TimeOfDay": "25:00", "TimeZone": "UTC"}}, "invalid-window")
        base = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        last_window_time = None
        for number in range(5):
            when = base + timedelta(minutes=8 + number)
            row = call(mq, "update_broker", {"BrokerId": broker_id, "MaintenanceWindowStartTime": window(when)}, "changed-window-" + str(number + 1))
            if row["code"] == "Success":
                last_window_time = when
        current = success(call(mq, "describe_broker", {"BrokerId": broker_id}, "at-limit"))
        call(mq, "update_broker", {"BrokerId": broker_id, "MaintenanceWindowStartTime": current["MaintenanceWindowStartTime"]}, "unchanged-at-limit")
        success(call(mq, "reboot_broker", {"BrokerId": broker_id}, "manual-reboot"))
        wait_running(broker_id, "manual-reboot-state", require_transition=True)
        next_window = window(datetime.now(timezone.utc) + timedelta(days=1))
        row = call(mq, "update_broker", {"BrokerId": broker_id, "MaintenanceWindowStartTime": next_window}, "adjust-after-manual-reboot")
        if row["code"] == "Success":
            evidence["limitations"].append("Manual reboot admitted a changed window; the previous near-term window was replaced, so scheduled reset was not measured.")
        elif last_window_time is not None:
            while datetime.now(timezone.utc) < last_window_time + timedelta(minutes=2):
                success(call(mq, "describe_broker", {"BrokerId": broker_id}, "await-scheduled-window"))
                time.sleep(30)
            while True:
                state = success(call(mq, "describe_broker", {"BrokerId": broker_id}, "scheduled-window-state"))
                if state["BrokerState"] == "RUNNING":
                    row = call(mq, "update_broker", {"BrokerId": broker_id, "MaintenanceWindowStartTime": next_window}, "adjust-after-scheduled-window")
                    if row["code"] == "Success":
                        break
                time.sleep(30)
        evidence["complete"] = True
    except Exception as err:
        evidence["failure"] = {"type": type(err).__name__, "message": str(err)}
        raise
    finally:
        cleanup_deadline = time.monotonic() + evidence["bounds"]["cleanup_seconds"]
        cleanup_complete = True
        if broker_id is None:
            # Recover a possibly accepted CreateBroker whose response was lost.
            token = None
            while True:
                params = {"MaxResults": 100}
                if token:
                    params["NextToken"] = token
                page = success(call(mq, "list_brokers", params, "recover-owned-create", cleanup=True))
                for broker in page.get("BrokerSummaries", []):
                    if broker["BrokerName"] == name:
                        tags = success(call(mq, "list_tags", {"ResourceArn": broker["BrokerArn"]}, "verify-recovered-owner", cleanup=True))
                        if tags.get("Tags", {}).get("stackd-probe-owner") != name:
                            raise RuntimeError("Refusing mismatched recovered broker ownership")
                        broker_id = broker["BrokerId"]
                        evidence["owned"].update({"broker_id": broker_id, "broker_arn": broker["BrokerArn"]})
                token = page.get("NextToken")
                if not token:
                    break
        if broker_id:
            broker_deleted = False
            before_delete = success(call(mq, "describe_broker", {"BrokerId": broker_id}, "before-owned-delete", cleanup=True))
            configuration_id = before_delete.get("Configurations", {}).get("Current", {}).get("Id")
            if configuration_id:
                configuration = success(call(mq, "describe_configuration", {"ConfigurationId": configuration_id}, "verify-automatic-configuration-owner", cleanup=True))
                if (configuration["Name"] != name + "-configuration"
                        or configuration["Created"] < datetime.fromisoformat(evidence["observed_at"])
                        or not configuration["LatestRevision"].get("Description", "").startswith("Auto-generated default for " + name + "-configuration ")):
                    raise RuntimeError("Refusing unproven automatic configuration ownership")
                evidence["owned"]["automatic_configuration_id"] = configuration_id
                save()
            success(call(mq, "delete_broker", {"BrokerId": broker_id}, "delete-owned-broker", cleanup=True))
            while time.monotonic() < cleanup_deadline:
                row = call(mq, "describe_broker", {"BrokerId": broker_id}, "verify-broker-deleted", cleanup=True)
                if row["code"] == "NotFoundException":
                    broker_deleted = True
                    break
                success(row)
                time.sleep(10)
            if not broker_deleted:
                save()
                raise RuntimeError("Broker deletion remains pending; preserving owned network dependencies")
            if configuration_id:
                success(call(mq, "delete_configuration", {"ConfigurationId": configuration_id}, "delete-automatic-configuration", cleanup=True))
                row = call(mq, "describe_configuration", {"ConfigurationId": configuration_id}, "verify-automatic-configuration-deleted", cleanup=True)
                if row["code"] != "NotFoundException":
                    save()
                    raise RuntimeError("Automatic configuration deletion not confirmed")
        if args.scenario == "create-identity" and broker_id and vpc_id:
            cleanup_replay_interfaces(mq, ec2, call, success, evidence["owned"], args.account)
        if vpc_id:
            while time.monotonic() < cleanup_deadline:
                interfaces = success(call(ec2, "describe_network_interfaces", {"Filters": [{"Name": "vpc-id", "Values": [vpc_id]}]}, "await-owned-network-release", cleanup=True))
                if not interfaces["NetworkInterfaces"]:
                    break
                time.sleep(5)
            else:
                save()
                raise RuntimeError("Broker network release remains pending; preserving owned network dependencies")
            for method, params, label in [
                ("delete_route", {"RouteTableId": route_table_id, "DestinationCidrBlock": "0.0.0.0/0"}, "delete-owned-public-route"),
                ("detach_internet_gateway", {"InternetGatewayId": gateway_id, "VpcId": vpc_id}, "detach-owned-gateway"),
                ("delete_internet_gateway", {"InternetGatewayId": gateway_id}, "delete-owned-gateway"),
                ("delete_security_group", {"GroupId": group_id}, "delete-owned-security-group"),
                ("delete_subnet", {"SubnetId": subnet_id}, "delete-owned-subnet"),
                ("delete_vpc", {"VpcId": vpc_id}, "delete-owned-vpc"),
            ]:
                if all(params.values()):
                    row = call(ec2, method, params, label, cleanup=True)
                    if row["code"] != "Success":
                        cleanup_complete = False
        if role_missing:
            role_after = call(iam, "get_role", {"RoleName": "AWSServiceRoleForAmazonMQ"}, "service-role-after", cleanup=True)
            if role_after["code"] == "Success":
                deletion = success(call(iam, "delete_service_linked_role", {"RoleName": "AWSServiceRoleForAmazonMQ"}, "delete-created-service-role", cleanup=True))
                while time.monotonic() < cleanup_deadline:
                    status = success(call(iam, "get_service_linked_role_deletion_status", {"DeletionTaskId": deletion["DeletionTaskId"]}, "verify-service-role-deleted", cleanup=True))
                    if status["Status"] == "SUCCEEDED":
                        break
                    if status["Status"] == "FAILED":
                        cleanup_complete = False
                        break
                    time.sleep(5)
                else:
                    cleanup_complete = False
            elif role_after["code"] != "NoSuchEntity":
                cleanup_complete = False
        evidence["cleanup_verified"] = cleanup_complete
        save()
        if not evidence["cleanup_verified"]:
            raise RuntimeError("Native cleanup incomplete; retained exact ownership in evidence")
    print(json.dumps({"output": str(args.output), "complete": evidence["complete"], "cleanup_verified": evidence["cleanup_verified"]}), flush=True)


if __name__ == "__main__":
    main()
