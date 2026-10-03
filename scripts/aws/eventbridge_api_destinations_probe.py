#!/usr/bin/env python3
"""Capture owned, management-only EventBridge API Destination behavior.

Requires boto3 and native credentials matching --account in us-east-1. Never invokes
an endpoint, publishes an event, enables a rule, or changes a standing role.
Use --cleanup-only after interruption and --audit-only for late CloudTrail history.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import uuid

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudtrail_events import CollectionError, collect_history
from cloudtrail_service_probe import document

REGION = "us-east-1"
ROOT = Path(__file__).resolve().parents[2]
CONFIG = Config(region_name=REGION, parameter_validation=False,
                retries={"total_max_attempts": 1}, connect_timeout=10,
                read_timeout=30, ignore_configured_endpoint_urls=True)
LINKED_ROLE = "AWSServiceRoleForAmazonEventBridgeApiDestinations"
DOCS = ["https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_" + name + ".html"
        for name in ("CreateApiDestination", "DescribeApiDestination", "ListApiDestinations",
                     "UpdateApiDestination", "DeleteApiDestination", "CreateConnection",
                     "DeleteConnection", "DeauthorizeConnection", "HttpParameters", "PutTargets")]
DOCS += ["https://docs.aws.amazon.com/eventbridge/latest/userguide/" + name + ".html"
         for name in ("eb-api-destinations", "eb-events-iam-roles", "eb-target-connection")]


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def revision(path):
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


class Probe:
    def __init__(self, args):
        self.args = args
        self.account = args.account
        session = boto3.Session(region_name=REGION)
        self.clients = {service: session.client(service, config=CONFIG)
                        for service in ("sts", "events", "iam", "secretsmanager", "cloudtrail")}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != self.account:
            raise RuntimeError("Caller account differs from --account")
        previous = None
        if args.restart_cleaned:
            previous = json.loads(args.output.read_text())
            if (previous["account"] != self.account or previous["region"] != REGION
                    or not previous["cleanup"].get("finished_at")
                    or any(value is False for value in previous["cleanup"].values())):
                raise RuntimeError("Previous capture ownership/cleanup is not proven")
        if args.audit_only or args.cleanup_only or args.state_followup or args.reauthorization_followup:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.account or self.data["region"] != REGION:
                raise RuntimeError("Capture account/region differs from authorized target")
        else:
            if args.output.exists() and previous is None:
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "account": self.account, "region": REGION, "prefix": "stackd-apid-" + uuid.uuid4().hex[:12],
                "captured_at": now(), "identity": document(identity),
                "scope": "Free owned BASIC/API_KEY connections, API destinations, disabled custom-bus rule and ephemeral target role; management only",
                "boundary": {
                    "native_wire_delivery": False,
                    "reason": "No preexisting legitimate owned reachable HTTPS receiver is configured. No PutEvents, endpoint invocation, local server exposure or credential forwarding occurs.",
                    "documentation_only": "HTTP request merging/headers, timeout, retry status/Retry-After, outbound authentication and rate scheduling are AWS documentation contracts, not wire observations from this fixture.",
                    "role_authority": "PutTargets admission is not proof of delivery-time InvokeApiDestination or service-linked secret authority.",
                    "audit": "Missing bounded CloudTrail observations do not establish event absence.",
                },
                "redaction": "cloudtrail_service_probe.document removes ambient credential secrets, replaces access-key IDs and source IPs. Synthetic owned auth inputs are retained exactly; AWS public response and CloudTrail sensitive projections remain unchanged.",
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__,
                        "credential_method": session.get_credentials().method,
                        "parameter_validation": False, "retry_total_max_attempts": 1},
                "sources": {"repository_revision": revision(ROOT),
                            "aws_sdk_go_v2_revision": revision(ROOT / "clones/aws-sdk-go-v2"),
                            "documentation": DOCS, "documentation_reviewed_at": now(),
                            "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            "cloudtrail_collector_sha256": hashlib.sha256(Path(__file__).with_name("cloudtrail_events.py").read_bytes()).hexdigest()},
                "observations": [], "owned": {"connections": {}, "destinations": {}},
                "cleanup": {}, "audit": {}, "commands": [],
            }
        if previous is not None:
            self.data["prior_captures"] = [*previous.pop("prior_captures", []), previous]
        self.data["commands"].append({"at": now(), "cwd": str(Path.cwd()),
            "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "command": "PYTHONPATH=scripts/aws python3 -B -P " + shlex.join(sys.argv)})
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(document(self.data), indent=2) + "\n")

    def call(self, label, service, method, parameters=None, required=False):
        client = self.clients[service]
        parameters = parameters or {}
        row = {"label": label, "service": service, "operation": method.replace("_", "-"),
               "input": document(parameters), "endpoint": client.meta.endpoint_url,
               "request_started_ms": time.time_ns() // 1_000_000}
        result = {}
        row["result"] = result
        try:
            output = getattr(client, method)(**parameters)
            metadata = output.pop("ResponseMetadata", {})
            result.update(code="Success", output=document(output))
        except ClientError as error:
            metadata = error.response.get("ResponseMetadata", {})
            result.update(code=error.response["Error"]["Code"], error=document(error.response["Error"]),
                          output=document({k: v for k, v in error.response.items() if k not in ("Error", "ResponseMetadata")}))
        except Exception as error:
            result.update(code="ClientFailure", exception_class=type(error).__name__)
            row["request_finished_ms"] = time.time_ns() // 1_000_000
            self.data["observations"].append(row)
            self.save()
            raise
        result.update(request_id=metadata.get("RequestId"), http_status=metadata.get("HTTPStatusCode"),
                      response_metadata=document(metadata))
        row["request_finished_ms"] = time.time_ns() // 1_000_000
        self.data["observations"].append(row)
        self.save()
        print(label + ": " + result["code"], flush=True)
        if required and result["code"] != "Success":
            raise RuntimeError(label + ": " + result["code"])
        return result

    def events(self, label, method, parameters=None, required=False):
        return self.call(label, "events", method, parameters, required)

    def connection(self, suffix, kind, auth):
        name = self.data["prefix"] + "-" + suffix
        absent = self.events("before-" + suffix, "describe_connection", {"Name": name})
        if absent["code"] != "ResourceNotFoundException":
            raise RuntimeError("Cannot prove connection name is unowned and absent")
        # Persist the absent, random exact-name intent before mutation for interrupted cleanup.
        self.data["owned"]["connections"][name] = {}
        self.data["cleanup"].pop(name, None)
        self.data["cleanup"].pop(name + "-secret", None)
        self.save()
        row = self.events("create-" + suffix, "create_connection", {
            "Name": name, "Description": "owned API destination management evidence",
            "AuthorizationType": kind, "AuthParameters": auth}, True)
        owned = self.data["owned"]["connections"][name]
        owned["arn"] = row["output"]["ConnectionArn"]
        self.save()
        described = self.events("describe-" + suffix, "describe_connection", {"Name": name}, True)
        owned["secret_arn"] = described["output"]["SecretArn"]
        self.save()
        self.call("describe-secret-" + suffix, "secretsmanager", "describe_secret", {"SecretId": owned["secret_arn"]}, True)
        return name, owned["arn"]

    def destination(self, suffix, connection, **parameters):
        name = self.data["prefix"] + "-" + suffix
        absent = self.events("before-" + suffix, "describe_api_destination", {"Name": name})
        if absent["code"] != "ResourceNotFoundException":
            raise RuntimeError("Cannot prove destination name is unowned and absent")
        self.data["owned"]["destinations"][name] = {}
        self.data["cleanup"].pop(name, None)
        self.save()
        request = {"Name": name, "ConnectionArn": connection, "InvocationEndpoint": "https://receiver.invalid/events/*",
                   "HttpMethod": "POST", **parameters}
        row = self.events("create-" + suffix, "create_api_destination", request, True)
        self.data["owned"]["destinations"][name]["arn"] = row["output"]["ApiDestinationArn"]
        self.save()
        self.events("describe-" + suffix, "describe_api_destination", {"Name": name}, True)
        return name, row["output"]["ApiDestinationArn"], request

    def controls(self):
        # A connection must not silently create a new standing service-linked role.
        linked = self.call("linked-role-before", "iam", "get_role", {"RoleName": LINKED_ROLE}, True)
        self.data["linked_role_before"] = linked["output"]["Role"]["RoleId"]
        basic, basic_arn = self.connection("basic", "BASIC", {
            "BasicAuthParameters": {"Username": "owned-user", "Password": "owned-inert-password"},
            "InvocationHttpParameters": {
                "HeaderParameters": [{"Key": "x-public", "Value": "visible"},
                                     {"Key": "x-private", "Value": "owned-inert-header", "IsValueSecret": True}],
                "QueryStringParameters": [{"Key": "query", "Value": "connection-query"}],
                "BodyParameters": [{"Key": "body", "Value": "connection-body"}]}})
        api_key, api_key_arn = self.connection("apikey", "API_KEY", {
            "ApiKeyAuthParameters": {"ApiKeyName": "x-owned-key", "ApiKeyValue": "owned-inert-api-key"}})
        self.events("list-connections", "list_connections", {"NamePrefix": self.data["prefix"]}, True)
        self.events("update-apikey", "update_connection", {"Name": api_key, "AuthorizationType": "API_KEY",
            "AuthParameters": {"ApiKeyAuthParameters": {"ApiKeyName": "x-updated-key", "ApiKeyValue": "owned-inert-updated-key"}}}, True)
        self.events("describe-apikey-updated", "describe_connection", {"Name": api_key}, True)
        default, default_arn, request = self.destination("default", basic_arn, Description="owned default rate")
        explicit, explicit_arn, _ = self.destination("explicit", api_key_arn, InvocationRateLimitPerSecond=7)
        self.events("create-duplicate", "create_api_destination", request)
        self.events("list-destinations", "list_api_destinations", {"NamePrefix": self.data["prefix"]}, True)
        self.events("list-combined-filters", "list_api_destinations", {"NamePrefix": self.data["prefix"], "ConnectionArn": basic_arn})
        self.events("list-basic-filter", "list_api_destinations", {"ConnectionArn": basic_arn}, True)
        page = self.events("list-page-one", "list_api_destinations", {"NamePrefix": self.data["prefix"], "Limit": 1}, True)
        for index in range(2, 5):
            token = page["output"].get("NextToken")
            if not token:
                break
            page = self.events("list-page-" + str(index), "list_api_destinations", {
                "NamePrefix": self.data["prefix"], "Limit": 1, "NextToken": token}, True)
        self.events("list-invalid-token", "list_api_destinations", {"NamePrefix": self.data["prefix"], "NextToken": "invalid"})
        for limit in (0, 101):
            self.events("list-limit-" + str(limit), "list_api_destinations", {"NamePrefix": self.data["prefix"], "Limit": limit})
        self.events("update-description-only", "update_api_destination", {"Name": explicit, "Description": "updated explicit"}, True)
        self.events("describe-description-only", "describe_api_destination", {"Name": explicit}, True)
        time.sleep(1.1)  # Native timestamps have whole-second precision.
        self.events("update-name-only", "update_api_destination", {"Name": explicit})
        self.events("describe-name-only", "describe_api_destination", {"Name": explicit}, True)
        for rate in (1, 300, 301, 0, -1):
            self.events("update-rate-" + str(rate), "update_api_destination", {"Name": explicit, "InvocationRateLimitPerSecond": rate})
        for method in ("GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "POST", "post", "TRACE", "CONNECT", ""):
            self.events("update-method-" + (method or "empty"), "update_api_destination", {"Name": explicit, "HttpMethod": method})
        endpoints = {
            "https": "https://receiver.invalid/events/*", "http": "http://receiver.invalid/events",
            "ftp": "ftp://receiver.invalid/events", "no-scheme": "receiver.invalid/events",
            "loopback": "https://127.0.0.1/events", "localhost": "https://localhost/events",
            "ipv6": "https://[::1]/events", "userinfo": "https://owned:inert@receiver.invalid/events",
            "fragment": "https://receiver.invalid/events#fragment", "space": "https://receiver.invalid/a b",
            "query": "https://receiver.invalid/events?key=value&other=two",
            "encoded": "https://receiver.invalid/a%20b", "bad-escape": "https://receiver.invalid/a%xx",
            "empty": "", "no-host": "https://", "wildcard-host": "https://*.invalid/events"}
        for label, endpoint in endpoints.items():
            self.events("update-endpoint-" + label, "update_api_destination", {"Name": explicit, "InvocationEndpoint": endpoint})
        self.events("restore-explicit", "update_api_destination", {"Name": explicit, "HttpMethod": "POST",
            "InvocationEndpoint": "https://receiver.invalid/events/*", "InvocationRateLimitPerSecond": 7, "Description": ""}, True)
        self.events("describe-restored", "describe_api_destination", {"Name": explicit}, True)
        missing_connection = basic_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
        self.events("update-missing-connection", "update_api_destination", {"Name": explicit, "ConnectionArn": missing_connection})
        self.events("update-malformed-connection", "update_api_destination", {"Name": explicit, "ConnectionArn": "not-an-arn"})
        missing = self.data["prefix"] + "-missing"
        self.events("describe-missing", "describe_api_destination", {"Name": missing})
        self.events("update-missing", "update_api_destination", {"Name": missing, "Description": "absent"})
        self.events("delete-missing", "delete_api_destination", {"Name": missing})
        validation_name = self.data["prefix"] + "-validation"
        absent = self.events("before-validation", "describe_api_destination", {"Name": validation_name})
        if absent["code"] != "ResourceNotFoundException":
            raise RuntimeError("Cannot prove validation destination name absent")
        self.data["owned"]["destinations"][validation_name] = {}
        self.save()
        for label, changed in (
                ("invalid-method", {"HttpMethod": "TRACE"}),
                ("http-endpoint", {"InvocationEndpoint": "http://receiver.invalid/events"}),
                ("invalid-endpoint", {"InvocationEndpoint": "https://receiver.invalid/a b"}),
                ("invalid-rate", {"InvocationRateLimitPerSecond": 0}),
                ("missing-connection", {"ConnectionArn": missing_connection})):
            row = self.events("create-" + label, "create_api_destination", {**request, "Name": validation_name, **changed})
            if row["code"] == "Success":
                self.data["owned"]["destinations"][validation_name]["arn"] = row["output"]["ApiDestinationArn"]
                self.save()
                self.events("delete-validation-" + label, "delete_api_destination", {"Name": validation_name}, True)
                if not self.absence("validation-absence-" + label, "events", "describe_api_destination", {"Name": validation_name}, "ResourceNotFoundException"):
                    raise RuntimeError("Validation destination deletion incomplete")
        self.targets(default_arn)
        self.events("deauthorize-basic", "deauthorize_connection", {"Name": basic})
        self.events("describe-basic-deauthorized", "describe_connection", {"Name": basic})
        self.events("describe-destination-deauthorized", "describe_api_destination", {"Name": default})
        self.events("update-basic-reauthorize", "update_connection", {"Name": basic, "AuthorizationType": "BASIC",
            "AuthParameters": {"BasicAuthParameters": {"Username": "updated-user", "Password": "owned-inert-updated-password"}}})
        self.events("describe-basic-reauthorized", "describe_connection", {"Name": basic})
        self.events("describe-destination-reauthorized", "describe_api_destination", {"Name": default})
        self.events("delete-referenced-connection", "delete_connection", {"Name": basic})
        if not self.absence("describe-deleted-basic", "events", "describe_connection", {"Name": basic}, "ResourceNotFoundException"):
            raise RuntimeError("Referenced connection deletion did not complete within bounds")
        self.events("describe-destination-connection-deleted", "describe_api_destination", {"Name": default})
        self.events("list-destinations-connection-deleted", "list_api_destinations", {"NamePrefix": self.data["prefix"]})
        self.events("update-destination-deleted-connection", "update_api_destination", {"Name": default, "ConnectionArn": basic_arn})
        old_secret = self.data["owned"]["connections"][basic]["secret_arn"]
        if not self.absence("deleted-basic-secret-absence", "secretsmanager", "describe_secret", {"SecretId": old_secret}, "ResourceNotFoundException"):
            raise RuntimeError("Deleted connection managed secret absence unproven")
        self.data["cleanup"]["retired_basic_secret_absent"] = True
        self.data["owned"]["connections"][basic] = {}
        self.save()
        recreated = self.events("recreate-basic", "create_connection", {"Name": basic, "AuthorizationType": "BASIC",
            "AuthParameters": {"BasicAuthParameters": {"Username": "recreated-user", "Password": "owned-inert-recreated-password"}}}, True)
        self.data["owned"]["connections"][basic]["arn"] = recreated["output"]["ConnectionArn"]
        self.save()
        described = self.events("describe-recreated-basic", "describe_connection", {"Name": basic}, True)
        self.data["owned"]["connections"][basic]["secret_arn"] = described["output"]["SecretArn"]
        self.save()
        self.events("describe-destination-connection-recreated", "describe_api_destination", {"Name": default})
        self.events("update-destination-stale-incarnation", "update_api_destination", {"Name": default, "ConnectionArn": basic_arn})
        self.events("update-destination-live-connection", "update_api_destination", {"Name": default, "ConnectionArn": api_key_arn})
        self.events("describe-destination-new-connection", "describe_api_destination", {"Name": default})
        self.events("delete-targeted-destination", "delete_api_destination", {"Name": default})
        self.events("list-targets-destination-deleted", "list_targets_by_rule", self.rule_request())
        self.events("describe-deleted-destination", "describe_api_destination", {"Name": default})
        self.events("delete-destination-again", "delete_api_destination", {"Name": default})
        self.data["owned"]["destinations"][default] = {}
        self.save()
        recreated = self.events("recreate-default", "create_api_destination", {**request, "ConnectionArn": api_key_arn}, True)
        self.data["owned"]["destinations"][default]["arn"] = recreated["output"]["ApiDestinationArn"]
        self.save()
        self.events("describe-recreated-default", "describe_api_destination", {"Name": default})
        self.events("list-targets-destination-recreated", "list_targets_by_rule", self.rule_request())

    def state_followup(self):
        self.call("state-linked-role-before", "iam", "get_role", {"RoleName": LINKED_ROLE}, True)
        name, arn = self.connection("state-basic", "BASIC", {
            "BasicAuthParameters": {"Username": "state-user", "Password": "owned-inert-state-password"}})
        primary, _, request = self.destination("state-primary", arn)
        self.events("state-update-schemeless", "update_api_destination", {
            "Name": primary, "InvocationEndpoint": "receiver.invalid/events"}, True)
        self.events("state-describe-schemeless", "describe_api_destination", {"Name": primary}, True)
        self.events("state-restore-https", "update_api_destination", {
            "Name": primary, "InvocationEndpoint": "https://receiver.invalid/events"}, True)
        self.events("state-deauthorize", "deauthorize_connection", {"Name": name}, True)
        self.wait_state("state-deauthorization-poll", "describe_connection", name, "ConnectionState", "DEAUTHORIZED")
        self.events("state-primary-deauthorized", "describe_api_destination", {"Name": primary}, True)
        secondary = self.data["prefix"] + "-state-secondary"
        absent = self.events("state-before-secondary", "describe_api_destination", {"Name": secondary})
        if absent["code"] != "ResourceNotFoundException":
            raise RuntimeError("Cannot prove state followup destination absent")
        self.data["owned"]["destinations"][secondary] = {}
        self.data["cleanup"].pop(secondary, None)
        self.save()
        row = self.events("state-create-with-deauthorized", "create_api_destination", {**request, "Name": secondary})
        if row["code"] == "Success":
            self.data["owned"]["destinations"][secondary]["arn"] = row["output"]["ApiDestinationArn"]
            self.save()
        self.events("state-secondary-deauthorized", "describe_api_destination", {"Name": secondary})
        time.sleep(2)
        self.events("state-primary-deauthorized-settled", "describe_api_destination", {"Name": primary})
        self.events("state-delete-connection", "delete_connection", {"Name": name}, True)
        if not self.absence("state-connection-deletion", "events", "describe_connection", {"Name": name}, "ResourceNotFoundException"):
            raise RuntimeError("State followup connection deletion incomplete")
        self.events("state-primary-connection-deleted", "describe_api_destination", {"Name": primary})
        self.events("state-secondary-connection-deleted", "describe_api_destination", {"Name": secondary})

    def wait_state(self, label, method, name, field, state):
        for attempt in range(1, 31):
            row = self.events(label + "-" + str(attempt), method, {"Name": name}, True)
            if row["output"][field] == state:
                return row["output"]
            time.sleep(2)
        raise RuntimeError(label + ": did not reach " + state + " within observation bounds")

    def reauthorization_followup(self):
        self.call("reauth-linked-role-before", "iam", "get_role", {"RoleName": LINKED_ROLE}, True)
        name, arn = self.connection("reauth-basic", "BASIC", {
            "BasicAuthParameters": {"Username": "reauth-user", "Password": "owned-inert-reauth-password"}})
        destination, _, _ = self.destination("reauth-primary", arn)
        self.destination("reauth-secondary", arn)
        prefix = self.data["prefix"] + "-reauth-"
        page = self.events("reauth-list-page-one", "list_api_destinations", {"NamePrefix": prefix, "Limit": 1}, True)
        token = page["output"].get("NextToken")
        if token:
            self.events("reauth-list-changed-limit", "list_api_destinations", {"NamePrefix": prefix, "Limit": 2, "NextToken": token})
            self.events("reauth-list-changed-prefix", "list_api_destinations", {
                "NamePrefix": self.data["prefix"] + "-reauth-secondary", "Limit": 1, "NextToken": token})
            self.events("reauth-list-changed-connection-filter", "list_api_destinations", {"ConnectionArn": arn, "Limit": 1, "NextToken": token})
        else:
            raise RuntimeError("Two owned destinations did not yield a continuation token")
        old_secret = self.data["owned"]["connections"][name]["secret_arn"]
        self.events("reauth-deauthorize", "deauthorize_connection", {"Name": name}, True)
        self.wait_state("reauth-deauthorized", "describe_connection", name, "ConnectionState", "DEAUTHORIZED")
        self.wait_state("reauth-inactive", "describe_api_destination", destination, "ApiDestinationState", "INACTIVE")
        if not self.absence("reauth-old-secret-absence", "secretsmanager", "describe_secret", {"SecretId": old_secret}, "ResourceNotFoundException"):
            raise RuntimeError("Deauthorized connection secret absence unproven")
        self.data["cleanup"]["retired_reauth_secret_absent"] = True
        self.events("reauth-update-basic", "update_connection", {"Name": name, "AuthorizationType": "BASIC",
            "AuthParameters": {"BasicAuthParameters": {"Username": "reauthorized-user", "Password": "owned-inert-reauthorized-password"}}}, True)
        connection = self.wait_state("reauth-authorized", "describe_connection", name, "ConnectionState", "AUTHORIZED")
        self.data["owned"]["connections"][name]["secret_arn"] = connection["SecretArn"]
        self.save()
        self.wait_state("reauth-active", "describe_api_destination", destination, "ApiDestinationState", "ACTIVE")
        self.events("reauth-delete-active-connection", "delete_connection", {"Name": name}, True)
        if not self.absence("reauth-connection-deletion", "events", "describe_connection", {"Name": name}, "ResourceNotFoundException"):
            raise RuntimeError("Reauthorized connection deletion incomplete")
        self.wait_state("reauth-deleted-inactive", "describe_api_destination", destination, "ApiDestinationState", "INACTIVE")

    def rule_request(self):
        return {"EventBusName": self.data["owned"]["bus"], "Rule": self.data["owned"]["rule"]}

    def targets(self, destination):
        name = self.data["prefix"]
        owned = self.data["owned"]
        before = self.events("before-bus", "describe_event_bus", {"Name": name})
        if before["code"] != "ResourceNotFoundException":
            raise RuntimeError("Cannot prove owned bus name absent")
        owned["bus"] = name
        self.save()
        self.events("create-bus", "create_event_bus", {"Name": name}, True)
        owned["rule"] = name
        self.save()
        rule = self.events("create-disabled-rule", "put_rule", {"Name": name, "EventBusName": name,
            "State": "DISABLED", "EventPattern": json.dumps({"source": [name]})}, True)
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole", "Condition": {"ArnEquals": {"aws:SourceArn": rule["output"]["RuleArn"]},
                                                     "StringEquals": {"aws:SourceAccount": self.account}}}]}
        before = self.call("before-target-role", "iam", "get_role", {"RoleName": name})
        if before["code"] != "NoSuchEntity":
            raise RuntimeError("Cannot prove owned role name absent")
        owned["role"] = {"name": name}
        self.save()
        created = self.call("create-target-role", "iam", "create_role", {"RoleName": name,
            "AssumeRolePolicyDocument": json.dumps(trust), "Tags": [{"Key": "stackd-probe", "Value": name}]}, True)
        owned["role"] = {"name": name, "arn": created["output"]["Role"]["Arn"], "id": created["output"]["Role"]["RoleId"]}
        self.save()
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "events:InvokeApiDestination", "Resource": destination}]}
        self.call("put-target-role-policy", "iam", "put_role_policy", {"RoleName": name, "PolicyName": name,
            "PolicyDocument": json.dumps(policy)}, True)
        target = {"Id": "owned", "Arn": destination}
        cases = [
            ("no-role", target),
            ("missing-role", {**target, "RoleArn": "arn:aws:iam::" + self.account + ":role/" + name + "-missing"}),
            ("malformed-role", {**target, "RoleArn": "not-an-arn"}),
            ("role-only", {**target, "RoleArn": owned["role"]["arn"]}),
        ]
        for label, entry in cases:
            self.events("target-" + label, "put_targets", {**self.rule_request(), "Targets": [entry]})
        target["RoleArn"] = owned["role"]["arn"]
        parameters = {
            "full": {"PathParameterValues": ["path value"], "HeaderParameters": {"x-public": "target", "x-target": "visible"}, "QueryStringParameters": {"query": "target", "extra": "value"}},
            "empty": {}, "path-too-many": {"PathParameterValues": ["one", "two"]},
            "path-empty": {"PathParameterValues": [""]}, "path-whitespace": {"PathParameterValues": [" "]},
            "header-name-space": {"HeaderParameters": {"bad name": "value"}},
            "header-value-newline": {"HeaderParameters": {"x-test": "one\ntwo"}},
            "header-value-empty": {"HeaderParameters": {"x-test": ""}},
            "header-reserved": {"HeaderParameters": {"Host": "receiver.invalid", "User-Agent": "owned", "Authorization": "inert"}},
            "query-empty": {"QueryStringParameters": {"key": ""}},
            "query-newline": {"QueryStringParameters": {"key": "one\ntwo"}},
        }
        for label, params in parameters.items():
            self.events("target-http-" + label, "put_targets", {**self.rule_request(), "Targets": [{**target, "HttpParameters": params}]})
        self.events("target-http-retained", "put_targets", {**self.rule_request(), "Targets": [{**target, "HttpParameters": parameters["full"]}]})
        self.events("list-targets-http-retained", "list_targets_by_rule", self.rule_request())
        self.events("target-update-omit-role", "put_targets", {**self.rule_request(), "Targets": [{"Id": "owned", "Arn": destination}]})
        self.events("list-targets-after-omit-role", "list_targets_by_rule", self.rule_request())

    def absence(self, label, service, method, parameters, missing):
        row = None
        for attempt in range(1, 31):
            row = self.call(label + "-" + str(attempt), service, method, parameters)
            if row["code"] == missing:
                return True
            if row["code"] != "Success":
                return False
            time.sleep(2)
        return False

    def cleanup(self):
        owned = self.data["owned"]
        cleanup = self.data["cleanup"]
        if owned.get("rule") and not cleanup.get("rule_absent"):
            targets = self.events("cleanup-list-targets", "list_targets_by_rule", self.rule_request())
            if targets["code"] == "Success" and targets["output"].get("Targets"):
                self.events("cleanup-remove-targets", "remove_targets", {**self.rule_request(),
                    "Ids": [target["Id"] for target in targets["output"]["Targets"]]})
            self.events("cleanup-delete-rule", "delete_rule", {"Name": owned["rule"], "EventBusName": owned["bus"]})
            cleanup["rule_absent"] = self.absence("cleanup-rule-absence", "events", "describe_rule",
                {"Name": owned["rule"], "EventBusName": owned["bus"]}, "ResourceNotFoundException")
        if owned.get("bus") and not cleanup.get("bus_absent"):
            self.events("cleanup-delete-bus", "delete_event_bus", {"Name": owned["bus"]})
            cleanup["bus_absent"] = self.absence("cleanup-bus-absence", "events", "describe_event_bus", {"Name": owned["bus"]}, "ResourceNotFoundException")
        for name, resource in owned["destinations"].items():
            if cleanup.get(name):
                continue
            row = self.events("cleanup-inspect-destination-" + name, "describe_api_destination", {"Name": name})
            if row["code"] == "Success":
                if resource.get("arn") and row["output"]["ApiDestinationArn"] != resource["arn"]:
                    raise RuntimeError("Destination incarnation changed; refusing cleanup")
                self.events("cleanup-delete-destination-" + name, "delete_api_destination", {"Name": name})
            cleanup[name] = self.absence("cleanup-destination-absence-" + name, "events", "describe_api_destination", {"Name": name}, "ResourceNotFoundException")
        for name, resource in owned["connections"].items():
            if cleanup.get(name) and cleanup.get(name + "-secret"):
                continue
            row = self.events("cleanup-inspect-connection-" + name, "describe_connection", {"Name": name})
            if row["code"] == "Success":
                if resource.get("arn") and row["output"]["ConnectionArn"] != resource["arn"]:
                    raise RuntimeError("Connection incarnation changed; refusing cleanup")
                # DEAUTHORIZED public descriptions omit SecretArn; retain the
                # captured ARN so interrupted cleanup still verifies its absence.
                if row["output"].get("SecretArn"):
                    resource["secret_arn"] = row["output"]["SecretArn"]
                self.save()
                self.events("cleanup-delete-connection-" + name, "delete_connection", {"Name": name})
            cleanup[name] = self.absence("cleanup-connection-absence-" + name, "events", "describe_connection", {"Name": name}, "ResourceNotFoundException")
            if resource.get("secret_arn"):
                cleanup[name + "-secret"] = self.absence("cleanup-secret-absence-" + name, "secretsmanager", "describe_secret", {"SecretId": resource["secret_arn"]}, "ResourceNotFoundException")
        role = owned.get("role")
        if role and not cleanup.get("role_absent"):
            row = self.call("cleanup-inspect-role", "iam", "get_role", {"RoleName": role["name"]})
            if row["code"] == "Success":
                tags = {tag["Key"]: tag["Value"] for tag in row["output"]["Role"].get("Tags", [])}
                if ((role.get("id") and row["output"]["Role"]["RoleId"] != role["id"])
                        or tags.get("stackd-probe") != self.data["prefix"]):
                    raise RuntimeError("Role incarnation changed; refusing cleanup")
                self.call("cleanup-delete-role-policy", "iam", "delete_role_policy", {"RoleName": role["name"], "PolicyName": role["name"]})
                self.call("cleanup-delete-role", "iam", "delete_role", {"RoleName": role["name"]})
            cleanup["role_absent"] = self.absence("cleanup-role-absence", "iam", "get_role", {"RoleName": role["name"]}, "NoSuchEntity")
        if self.data.get("linked_role_before") and not cleanup.get("standing_linked_role_unchanged"):
            row = self.call("linked-role-after", "iam", "get_role", {"RoleName": LINKED_ROLE})
            cleanup["standing_linked_role_unchanged"] = row["code"] == "Success" and row["output"]["Role"]["RoleId"] == self.data["linked_role_before"]
        cleanup["finished_at"] = now()
        self.save()
        if any(value is False for value in cleanup.values()):
            raise RuntimeError("Owned cleanup absence not proven; see fixture cleanup")

    def audit(self):
        captures = [self.data, *self.data.get("prior_captures", [])]
        requests = {}
        for capture in captures:
            prefix = "" if capture is self.data else "prior-" + capture["prefix"] + ":"
            requests.update({row["result"]["request_id"]: prefix + row["label"] for row in capture["observations"]
                             if row["result"].get("request_id")})
        start = min(dt.datetime.fromisoformat(capture["captured_at"]) for capture in captures) - dt.timedelta(minutes=1)
        try:
            self.data["audit"] = collect_history(lambda params: self.clients["cloudtrail"].lookup_events(**params),
                requests, start_time=start, event_sources=("events.amazonaws.com", "secretsmanager.amazonaws.com", "iam.amazonaws.com"),
                max_pages=20, rounds=self.args.audit_rounds, wait_seconds=self.args.audit_wait,
                previous=self.data["audit"] or None)
        except CollectionError as error:
            self.data["audit"] = error.result
            raise
        finally:
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / ".stackd/probes/eventbridge/api-destinations.json")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--audit-only", action="store_true")
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--state-followup", action="store_true",
                      help="Append owned settled-deauthorization and endpoint-normalization controls")
    mode.add_argument("--reauthorization-followup", action="store_true",
                      help="Append successful BASIC reauthorization and active-connection deletion controls")
    mode.add_argument("--restart-cleaned", action="store_true",
                      help="Preserve a fully cleaned earlier capture and capture a new unique run")
    parser.add_argument("--audit-rounds", type=int, default=12)
    parser.add_argument("--audit-wait", type=float, default=30)
    args = parser.parse_args()
    if not 1 <= args.audit_rounds <= 20 or not 0 <= args.audit_wait <= 60:
        parser.error("Audit bounds require 1..20 rounds and 0..60 second intervals")
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    probe = Probe(args)
    if args.cleanup_only:
        probe.cleanup()
    elif args.audit_only:
        probe.audit()
    else:
        try:
            if args.state_followup:
                probe.state_followup()
            elif args.reauthorization_followup:
                probe.reauthorization_followup()
            else:
                probe.controls()
        finally:
            try:
                probe.cleanup()
            finally:
                probe.audit()
    print(json.dumps({"fixture": str(args.output), "observations": len(probe.data["observations"]),
                      "cleanup": probe.data["cleanup"], "audit_events": len(probe.data["audit"].get("events", [])),
                      "audit_missing_calls": probe.data["audit"].get("missing_calls", [])}))


if __name__ == "__main__":
    main()
