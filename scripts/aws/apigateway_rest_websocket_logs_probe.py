#!/usr/bin/env python3
"""Capture owned REST/WebSocket logging; prove empty account-role restoration before enabling it."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shlex
import signal
import sys
import time
import uuid

import botocore
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
import websocket

import apigateway_probe as base
import apigateway_rest_authorizer_probe as helpers
import apigateway_websocket_probe as lifecycle
from apigateway_probe import REGION, now
from apigateway_rest_authorizer_probe import create_function, http, put_route
from apigateway_websocket_probe import LifecycleProbe

HANDLER = '''import json
import os
import platform
import time

def handler(event, context):
    request = event.get("requestContext", {})
    query = event.get("queryStringParameters") or {}
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    try:
        payload = json.loads(event.get("body") or "{}")
    except (ValueError, TypeError):
        payload = {}
    for key in ("headers", "multiValueHeaders"):
        for name in list(event.get(key) or {}):
            if name.lower() in ("authorization", "x-amz-security-token"):
                event[key][name] = "HIDDEN_BY_PROBE"
    mode = query.get("mode") or payload.get("mode", "ok")
    marker = payload.get("marker") or query.get("marker") or headers.get("x-probe")
    record = {"probe_kind": "gateway-logs", "marker": marker,
        "invocation": context.aws_request_id, "mode": mode, "event": event,
        "runtime": platform.python_version(), "execution_environment": os.environ.get("AWS_EXECUTION_ENV")}
    print(json.dumps(record, separators=(",", ":")), flush=True)
    if mode == "raise":
        raise RuntimeError("owned-backend-failure")
    if mode == "malformed":
        return {"statusCode": "invalid", "body": {"not": "a proxy response"}}
    time.sleep(0.025)
    status = 403 if query.get("deny") == "yes" else 503 if mode == "503" else 200
    return {"statusCode": status, "headers": {"Content-Type": "application/json"},
        "body": json.dumps(record, separators=(",", ":"))}
'''

CONTEXT = ("requestId", "extendedRequestId", "apiId", "stage", "httpMethod", "resourcePath",
    "routeKey", "status", "responseLength", "identity.caller", "identity.user", "identity.userArn",
    "authorizer.principalId", "identity.sourceIp", "identity.userAgent", "requestTime", "requestTimeEpoch",
    "responseLatency", "integrationLatency", "integrationStatus", "integration.status",
    "integration.integrationStatus", "integration.latency", "integration.requestId", "integration.error",
    "error.message", "error.responseType", "eventType", "connectionId", "messageId", "connectedAt",
    "domainName", "unsupportedOwnedProbeVariable")
ACCESS_FORMAT = "|".join(key + "=$context." + key for key in CONTEXT)


class LogsProbe(LifecycleProbe):
    def save(self):
        if hasattr(self, "data"):
            actor = {"kind": "capture-owner", "arn": self.data["identity"]["Arn"]}
            for row in self.data["observations"]:
                row.setdefault("actor", actor)
        super().save()

    def cleanup(self):
        for alias in list(self.sockets):
            self.close(alias, "cleanup-socket-" + alias)
        owned = self.data["owned"]
        checks = []
        # Never delete a role while the account still points to it. A concurrent foreign
        # change is not ours to overwrite, including during exceptional cleanup.
        if owned.get("logging_role"):
            owned.setdefault("logging_role_arn", f"arn:aws:iam::{self.data['account']}:role/{owned['logging_role']}")
            account = self.required("cleanup-account-before", "apigateway", "get_account")
            current = account.get("cloudwatchRoleArn")
            if current == owned["logging_role_arn"]:
                self.call("restore-account-empty", "apigateway", "update_account", {
                    "patchOperations": [{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}]}, required=False)
            elif current:
                self.data.setdefault("uncertainties", []).append("Concurrent foreign account role observed during cleanup; no account mutation attempted")
            final = self.required("cleanup-account-after", "apigateway", "get_account")
            restored = not final.get("cloudwatchRoleArn")
            self.data["cleanup"]["account_role"] = {"absent": restored, "account": final}
            checks.append(restored)
            if final.get("cloudwatchRoleArn") != owned["logging_role_arn"]:
                self.call("cleanup-logging-policy", "iam", "delete_role_policy", {
                    "RoleName": owned["logging_role"], "PolicyName": "owned-gateway-logs"}, required=False)
                if owned.get("logging_managed_policy"):
                    self.call("cleanup-logging-managed-policy", "iam", "detach_role_policy", {
                        "RoleName": owned["logging_role"], "PolicyArn": owned["logging_managed_policy"]}, required=False)
                self.call("cleanup-logging-role", "iam", "delete_role", {"RoleName": owned["logging_role"]}, required=False)
                absent = self.call("absence-logging-role", "iam", "get_role", {"RoleName": owned["logging_role"]}, required=False)
                checks.append(absent["code"] == "NoSuchEntity")
                self.data["cleanup"]["logging_role"] = {"absent": checks[-1]}
            else:
                checks.append(False)
                self.data["cleanup"]["logging_role"] = {"absent": False, "retained_reason": "Account still references owned role"}
        try:
            super().cleanup()
        finally:
            for group in owned.get("gateway_log_groups", {}).values():
                self.call("cleanup-group-" + group, "logs", "delete_log_group", {"logGroupName": group}, required=False)
                result = self.required("absence-group-" + group, "logs", "describe_log_groups", {"logGroupNamePrefix": group})
                absent = not any(item["logGroupName"] == group for item in result.get("logGroups", []))
                self.data["cleanup"][group] = {"absent": absent}
                checks.append(absent)
            account = self.required("final-account", "apigateway", "get_account")
            self.data["cleanup"]["final_account"] = account
            if self.data.get("account_initial") is not None:
                checks.append(account == self.data["account_initial"])
                self.data["cleanup"]["account_unchanged"] = checks[-1]
            self.data["cleanup"]["complete"] = self.data["cleanup"].get("complete", False) and all(checks)
            self.save()
        if not self.data["cleanup"]["complete"]:
            raise RuntimeError("Owned logging cleanup remains incomplete; retain role if account restoration failed")


def rest_patch(p, label, operations, required=True):
    return p.call(label, "apigateway", "update_stage", {"restApiId": p.data["owned"]["rest_api"],
        "stageName": "probe", "patchOperations": operations}, required=required)


def ws_patch(p, label, required=True, **settings):
    return p.call(label, "apigatewayv2", "update_stage", {"ApiId": p.data["owned"]["http_api"],
        "StageName": "probe", **settings}, required=required)


def snapshot(p, label):
    rest = p.required(label + "-rest", "apigateway", "get_stage", {
        "restApiId": p.data["owned"]["rest_api"], "stageName": "probe"})
    ws = p.required(label + "-ws", "apigatewayv2", "get_stage", {
        "ApiId": p.data["owned"]["http_api"], "StageName": "probe"})
    p.data["settings"].append({"label": label, "at": now(), "rest": rest, "websocket": ws})
    p.save()


def initialize(p):
    p.data.update(prefix="stackd-restwslogs-" + uuid.uuid4().hex[:10],
        scope="Owned REST/WebSocket access and execution logs, reversible regional account role, one actual Python3.13 Lambda",
        bounds={"apis": 2, "stages": 2, "functions": 1, "roles": 2, "gateway_log_groups": 4,
            "http_requests": 70, "websocket_handshakes": 20, "websocket_messages": 35,
            "readiness_attempts": 8, "logging_role_attempts": 3, "logging_role_interval_seconds": 16, "log_polls": 16,
            "log_pages_per_group_per_poll": 4, "log_poll_interval_seconds": 5},
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        helper_sources={"apigateway_probe.py": Path(base.__file__).read_text(),
            "apigateway_rest_authorizer_probe.py": Path(helpers.__file__).read_text(),
            "apigateway_websocket_probe.py": Path(lifecycle.__file__).read_text()},
        executed_command=shlex.join([sys.executable, *sys.argv]),
        credential_provenance={"method": p.session.get_credentials().method, "actor_arn": p.data["identity"]["Arn"],
            "secrets": "Never persisted; SigV4 authorization and security token redacted"},
        runtime_versions={"python": platform.python_version(), "botocore": botocore.__version__,
            "websocket-client": websocket.__version__, "lambda_requested": "python3.13"},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-logging.html",
            "https://repost.aws/knowledge-center/api-gateway-cloudwatch-logs",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_UpdateAccount.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_MethodSetting.html",
            "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-stages-stagename.html"],
        access_format=ACCESS_FORMAT, cohorts=[], settings=[], raw_logs={}, log_polls=[], uncertainties=[],
        websocket_observations=[], connections={}, scenarios=[], expected_invocation_markers=[],
        log_start_ms=int(time.time() * 1000))
    p.data["modeled_inputs"] = {}
    for service, operations in (("apigateway", ("UpdateAccount", "UpdateStage", "CreateStage")),
            ("apigatewayv2", ("UpdateStage", "CreateStage", "DeleteAccessLogSettings", "DeleteRouteSettings"))):
        model = p.client(service).meta.service_model
        for operation in operations:
            shape = model.operation_model(operation).input_shape
            p.data["modeled_inputs"][service + ":" + operation] = {
                key: {"type": member.type_name, "enum": member.metadata.get("enum")}
                for key, member in shape.members.items()}
    p.save()
    initial = p.required("account-initial", "apigateway", "get_account")
    p.data["account_initial"] = initial
    if initial.get("cloudwatchRoleArn"):
        p.data["uncertainties"].append("Pre-existing nonempty regional role: no account mutations permitted")
        p.save()
        return False
    unchanged = p.required("account-before-empty-proof", "apigateway", "get_account")
    if unchanged != initial:
        raise RuntimeError("Concurrent account change before empty proof; stopped account mutations")
    result = p.call("account-replace-empty-while-absent", "apigateway", "update_account", {
        "patchOperations": [{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}]}, required=False)
    after = p.required("account-after-empty-proof", "apigateway", "get_account")
    safe = result["code"] == "Success" and after == initial and not after.get("cloudwatchRoleArn")
    p.data["empty_role_restoration_proven"] = safe
    if not safe:
        p.data["uncertainties"].append("Empty replacement did not prove reversible absence; logging role will never be installed")
    p.save()
    return safe


def setup_apis(p):
    name, account = p.data["prefix"], p.data["account"]
    function, _ = create_function(p, HANDLER)
    rest = p.required("create-rest", "apigateway", "create_rest_api", {
        "name": name, "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    ws = p.required("create-websocket", "apigatewayv2", "create_api", {
        "Name": name, "ProtocolType": "WEBSOCKET", "RouteSelectionExpression": "$request.body.action"},
        own=("http_api", "ApiId"))
    p.data["owned"].update(rest_endpoint=f"https://{rest}.execute-api.{REGION}.amazonaws.com",
        websocket_endpoint=ws["ApiEndpoint"], routes={}, resources={})
    for kind, api in (("rest", rest), ("websocket", ws["ApiId"])):
        p.required("permission-" + kind, "lambda", "add_permission", {
            "FunctionName": name, "StatementId": kind, "Action": "lambda:InvokeFunction",
            "Principal": "apigateway.amazonaws.com", "SourceAccount": account,
            "SourceArn": f"arn:aws:execute-api:{REGION}:{account}:{api}/*"})
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    root = p.required("rest-resources", "apigateway", "get_resources", {"restApiId": rest})["items"][0]["id"]
    for part in ("sample", "quiet", "guard"):
        resource = p.required("rest-resource-" + part, "apigateway", "create_resource", {
            "restApiId": rest, "parentId": root, "pathPart": part})["id"]
        p.data["owned"]["resources"][part] = resource
        put_route(p, rest, resource, part, "GET", None, uri)
        if part == "guard":
            p.required("rest-guard-iam", "apigateway", "update_method", {
                "restApiId": rest, "resourceId": resource, "httpMethod": "GET", "patchOperations": [
                    {"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"}]})
    p.required("rest-deploy", "apigateway", "create_deployment", {"restApiId": rest, "stageName": "probe"})
    integration = p.required("ws-integration", "apigatewayv2", "create_integration", {
        "ApiId": ws["ApiId"], "IntegrationType": "AWS_PROXY", "IntegrationMethod": "POST", "IntegrationUri": uri})
    for route in ("$connect", "$disconnect", "echo", "quiet"):
        parameters = {"ApiId": ws["ApiId"], "RouteKey": route, "AuthorizationType": "NONE",
            "Target": "integrations/" + integration["IntegrationId"]}
        if not route.startswith("$"):
            parameters["RouteResponseSelectionExpression"] = "$default"
        created = p.required("ws-route-" + route, "apigatewayv2", "create_route", parameters)
        p.data["owned"]["routes"][route] = created["RouteId"]
        if not route.startswith("$"):
            p.required("ws-response-" + route, "apigatewayv2", "create_route_response", {
                "ApiId": ws["ApiId"], "RouteId": created["RouteId"], "RouteResponseKey": "$default"})
    deployment = p.required("ws-deploy", "apigatewayv2", "create_deployment", {"ApiId": ws["ApiId"]})
    p.required("ws-stage", "apigatewayv2", "create_stage", {"ApiId": ws["ApiId"], "StageName": "probe",
        "DeploymentId": deployment["DeploymentId"], "AutoDeploy": False})
    groups = {"rest_access": "/stackd/" + name + "/rest-access", "ws_access": "/stackd/" + name + "/ws-access",
        "rest_execution": "API-Gateway-Execution-Logs_" + rest + "/probe",
        "ws_execution": "/aws/apigateway/" + ws["ApiId"] + "/probe"}
    p.data["owned"]["gateway_log_groups"] = {}
    for kind, group in groups.items():
        p.required("create-group-" + kind, "logs", "create_log_group", {"logGroupName": group})
        p.data["owned"]["gateway_log_groups"][kind] = group
        p.save()
    p.data["destinations"] = {kind: f"arn:aws:logs:{REGION}:{account}:log-group:{group}"
        for kind, group in groups.items()}
    snapshot(p, "initial")


def negative_controls(p, label):
    destination = p.data["destinations"]
    rest_patch(p, label + "-rest-access", [
        {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": destination["rest_access"]},
        {"op": "replace", "path": "/accessLogSettings/format", "value": ACCESS_FORMAT}], required=False)
    rest_patch(p, label + "-rest-info", [{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}], required=False)
    rest_patch(p, label + "-rest-off-trace", [
        {"op": "replace", "path": "/*/*/logging/loglevel", "value": "OFF"},
        {"op": "replace", "path": "/*/*/logging/dataTrace", "value": "true"}], required=False)
    ws_patch(p, label + "-ws-access", required=False, AccessLogSettings={"DestinationArn": destination["ws_access"], "Format": ACCESS_FORMAT})
    ws_patch(p, label + "-ws-info", required=False, DefaultRouteSettings={"LoggingLevel": "INFO"})
    ws_patch(p, label + "-ws-off-trace", required=False, DefaultRouteSettings={"LoggingLevel": "OFF", "DataTraceEnabled": True})
    for case, fmt, dest in (("missing-request-id", "literal-only", None),
            ("multiline", "$context.requestId\n$context.status", None),
            ("extended-only", "$context.extendedRequestId", None),
            ("bad-destination", ACCESS_FORMAT, "not-an-arn")):
        rest_patch(p, label + "-rest-" + case, [
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": dest or destination["rest_access"]},
            {"op": "replace", "path": "/accessLogSettings/format", "value": fmt}], required=False)
        ws_patch(p, label + "-ws-" + case, required=False,
            AccessLogSettings={"DestinationArn": dest or destination["ws_access"], "Format": fmt})
    rest_patch(p, label + "-rest-invalid-level", [{"op": "replace", "path": "/*/*/logging/loglevel", "value": "DEBUG"}], required=False)
    rest_patch(p, label + "-rest-invalid-trace", [{"op": "replace", "path": "/*/*/logging/dataTrace", "value": "invalid"}], required=False)
    ws_patch(p, label + "-ws-invalid-level", required=False, DefaultRouteSettings={"LoggingLevel": "DEBUG"})
    snapshot(p, label + "-retained")


def enable_role(p):
    initial = p.required("account-before-owned-role", "apigateway", "get_account")
    if initial != p.data["account_initial"] or initial.get("cloudwatchRoleArn"):
        raise RuntimeError("Concurrent account change; stopped account mutations")
    name = p.data["prefix"] + "-gateway"
    role = p.required("create-logging-role", "iam", "create_role", {"RoleName": name,
        "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}]})},
        own=("logging_role", "Role.RoleName"))["Role"]
    p.data["owned"]["logging_role_arn"] = role["Arn"]
    resources = [value + ":*" for value in p.data["destinations"].values()]
    p.required("logging-role-policy", "iam", "put_role_policy", {"RoleName": name, "PolicyName": "owned-gateway-logs",
        "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": "*"},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:DescribeLogStreams",
                "logs:PutLogEvents", "logs:GetLogEvents", "logs:FilterLogEvents"], "Resource": resources}]})})
    if try_role(p, role["Arn"], "narrow"):
        return True
    p.data["narrow_role_rejected_within_bound"] = True
    if not p.allow_documented_role_policy:
        p.data["uncertainties"].append("Narrow owned-group role not admitted; documented-policy fallback requires explicit authorization")
        return False
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
    policy = p.required("documented-logging-policy", "iam", "get_policy", {"PolicyArn": policy_arn})["Policy"]
    p.required("documented-logging-policy-version", "iam", "get_policy_version", {
        "PolicyArn": policy_arn, "VersionId": policy["DefaultVersionId"]})
    # Only this newly created role may acquire the documented service policy.
    # Persist the cleanup inventory before attachment, including interruption windows.
    p.data["owned"]["logging_managed_policy"] = policy_arn
    p.save()
    p.required("attach-documented-logging-policy", "iam", "attach_role_policy", {
        "RoleName": name, "PolicyArn": policy_arn})
    admitted = try_role(p, role["Arn"], "documented")
    if not admitted:
        p.data["uncertainties"].append("Documented managed-policy role not admitted within bounded attempts")
    return admitted


def try_role(p, arn, policy_kind):
    for attempt in range(p.data["bounds"]["logging_role_attempts"]):
        label = policy_kind + "-" + str(attempt)
        current = p.required("account-role-guard-" + label, "apigateway", "get_account")
        if current != p.data["account_initial"]:
            raise RuntimeError("Concurrent account change while waiting for role; no replacement attempted")
        result = p.call("account-set-owned-role-" + label, "apigateway", "update_account", {
            "patchOperations": [{"op": "replace", "path": "/cloudwatchRoleArn", "value": arn}]}, required=False)
        after = p.required("account-owned-role-read-" + label, "apigateway", "get_account")
        if result["code"] == "Success" and after.get("cloudwatchRoleArn") == arn:
            p.data["admitted_logging_policy"] = policy_kind
            return True
        if after != p.data["account_initial"]:
            raise RuntimeError("Unexpected account role transition; stopped mutations")
        time.sleep(p.data["bounds"]["logging_role_interval_seconds"])
    return False


def configure(p, label, level, trace, override=False):
    rest_patch(p, label + "-rest-config", [
        {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": p.data["destinations"]["rest_access"]},
        {"op": "replace", "path": "/accessLogSettings/format", "value": ACCESS_FORMAT},
        {"op": "replace", "path": "/*/*/logging/loglevel", "value": level},
        {"op": "replace", "path": "/*/*/logging/dataTrace", "value": str(trace).lower()},
        {"op": "replace", "path": "/~1quiet/GET/logging/loglevel", "value": "INFO" if override else level},
        {"op": "replace", "path": "/~1quiet/GET/logging/dataTrace", "value": str(trace).lower()}])
    ws_patch(p, label + "-ws-config", AccessLogSettings={"DestinationArn": p.data["destinations"]["ws_access"], "Format": ACCESS_FORMAT},
        DefaultRouteSettings={"LoggingLevel": level, "DataTraceEnabled": trace},
        RouteSettings={"quiet": {"LoggingLevel": "INFO" if override else level, "DataTraceEnabled": trace}})
    snapshot(p, label)
    time.sleep(5)


def rest_request(p, label, path, phase, signed=False):
    if len(p.data["http"]) >= p.data["bounds"]["http_requests"]:
        raise RuntimeError("HTTP request bound reached")
    headers = {}
    if signed:
        request = AWSRequest(method="GET", url=p.data["owned"]["rest_endpoint"] + path,
            headers={"User-Agent": "stackd-rest-authorizer-probe", "X-Probe": label})
        credentials = p.session.get_credentials().get_frozen_credentials()
        p.hide(credentials.access_key, "access-key-id")
        if credentials.token:
            p.hide(credentials.token, "session-token")
        SigV4Auth(credentials, "execute-api", REGION).add_auth(request)
        headers = dict(request.headers)
        p.hide(headers["Authorization"], "sigv4-authorization")
    return http(p, label, path, headers=headers, phase=phase)


def ws_message(p, alias, label, action="echo", mode="ok"):
    if sum(row["operation"] == "send" for row in p.data["websocket_observations"]) >= p.data["bounds"]["websocket_messages"]:
        raise RuntimeError("WebSocket message bound reached")
    p.send(alias, label + "-send", json.dumps({"action": action, "mode": mode, "marker": p.marker(label), "payload": "owned-data-trace-body"}))
    return p.receive(alias, label + "-receive", timeout=3)


def cohort(p, name, full=True):
    row = {"name": name, "started_at": now(), "http_start": len(p.data["http"]),
        "websocket_start": len(p.data["websocket_observations"])}
    p.data["cohorts"].append(row)
    cases = [("success", "/sample"), ("quiet", "/quiet"), ("raise", "/sample?mode=raise")]
    if full:
        cases += [("backend503", "/sample?mode=503"), ("malformed", "/sample?mode=malformed"),
            ("iam-denied", "/guard"), ("missing", "/missing")]
    for suffix, path in cases:
        rest_request(p, name + "-rest-" + suffix, "/probe" + path, name)
    if full:
        rest_request(p, name + "-rest-iam-allowed", "/probe/guard", name, signed=True)
    connected = p.connect(name, phase=name)
    if connected.get("status") == 101:
        ws_message(p, name, name + "-ws-success")
        ws_message(p, name, name + "-ws-quiet", action="quiet")
        ws_message(p, name, name + "-ws-raise", mode="raise")
        if full:
            ws_message(p, name, name + "-ws-backend503", mode="503")
            ws_message(p, name, name + "-ws-malformed", mode="malformed")
            ws_message(p, name, name + "-ws-missing", action="missing")
        if name == "info-trace":
            management(p, name)
        p.close(name, name + "-ws-close")
    else:
        p.data["uncertainties"].append(name + ": WebSocket handshake did not succeed")
    row.update(finished_at=now(), http_end=len(p.data["http"]), websocket_end=len(p.data["websocket_observations"]))
    p.save()


def management(p, alias):
    received = [row for row in p.data["websocket_observations"] if row["connection"] == alias and row["operation"] == "receive"]
    record = next((row["result"].get("json") for row in received if row["result"].get("json", {}).get("probe_kind")), None)
    if not record:
        p.data["uncertainties"].append("No two-way Lambda response supplied a connectionId for management callback")
        return
    connection = record["event"]["requestContext"]["connectionId"]
    p.clients["apigatewaymanagementapi"] = p.session.client("apigatewaymanagementapi",
        endpoint_url=p.data["owned"]["websocket_endpoint"].replace("wss://", "https://") + "/probe",
        config=Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=15))
    p.required("management-get", "apigatewaymanagementapi", "get_connection", {"ConnectionId": connection})
    p.required("management-callback", "apigatewaymanagementapi", "post_to_connection", {
        "ConnectionId": connection, "Data": json.dumps({"marker": p.marker("management-callback")}).encode()})
    p.receive(alias, "management-callback-receive", timeout=3)
    p.required("management-delete", "apigatewaymanagementapi", "delete_connection", {"ConnectionId": connection})
    p.receive(alias, "management-delete-receive", timeout=3)
    p.call("management-callback-gone", "apigatewaymanagementapi", "post_to_connection", {
        "ConnectionId": connection, "Data": b"owned-gone-callback"}, required=False)


def remove_settings(p):
    rest_patch(p, "rest-access-remove", [{"op": "remove", "path": "/accessLogSettings"}])
    rest_patch(p, "rest-method-override-remove", [{"op": "remove", "path": "/~1quiet/GET"}], required=False)
    rest_patch(p, "rest-default-off", [{"op": "replace", "path": "/*/*/logging/loglevel", "value": "OFF"},
        {"op": "replace", "path": "/*/*/logging/dataTrace", "value": "false"}])
    p.required("ws-access-remove", "apigatewayv2", "delete_access_log_settings", {
        "ApiId": p.data["owned"]["http_api"], "StageName": "probe"})
    p.call("ws-route-override-remove", "apigatewayv2", "delete_route_settings", {
        "ApiId": p.data["owned"]["http_api"], "StageName": "probe", "RouteKey": "quiet"}, required=False)
    ws_patch(p, "ws-default-off", DefaultRouteSettings={"LoggingLevel": "OFF", "DataTraceEnabled": False})
    snapshot(p, "removed")
    time.sleep(5)


def ws_iam_denial(p):
    api = p.data["owned"]["http_api"]
    p.required("ws-connect-iam", "apigatewayv2", "update_route", {"ApiId": api,
        "RouteId": p.data["owned"]["routes"]["$connect"], "AuthorizationType": "AWS_IAM"})
    deployment = p.required("ws-iam-deploy", "apigatewayv2", "create_deployment", {"ApiId": api})
    ws_patch(p, "ws-iam-stage", DeploymentId=deployment["DeploymentId"])
    time.sleep(5)
    for attempt in range(4):
        alias = "iam-denied-" + str(attempt)
        result = p.connect(alias, phase="iam-denial")
        p.close(alias, alias + "-close")
        if result.get("status") == 403:
            break
        time.sleep(3)


def collect(p):
    groups = {**p.data["owned"]["gateway_log_groups"], "lambda": "/aws/lambda/" + p.data["owned"]["function"]}
    previous, stable = None, 0
    final_marker = p.data["final_marker"]
    for attempt in range(p.data["bounds"]["log_polls"]):
        poll = {"attempt": attempt, "started_at": now(), "groups": {}}
        for kind, group in groups.items():
            events, token = [], None
            for page in range(p.data["bounds"]["log_pages_per_group_per_poll"]):
                parameters = {"logGroupName": group, "startTime": p.data["log_start_ms"], "limit": 1000}
                if token:
                    parameters["nextToken"] = token
                result = p.call(f"logs-{attempt}-{kind}-{page}", "logs", "filter_log_events", parameters, required=False)
                if result["code"] != "Success":
                    break
                events.extend(result["output"].get("events", []))
                token = result["output"].get("nextToken")
                # Keep raw events once, not a growing copy in every successful poll.
                result["output"]["events"] = {"event_ids": [event["eventId"] for event in result["output"].get("events", [])],
                    "raw_records_path": "raw_logs." + kind}
                if not token:
                    break
            if token:
                raise RuntimeError("Log pagination bound reached for " + kind)
            retained = {event["eventId"]: event for event in p.data["raw_logs"].get(kind, [])}
            retained.update({event["eventId"]: event for event in events})
            p.data["raw_logs"][kind] = list(retained.values())
            poll["groups"][kind] = {"events": len(events), "complete_page_chain": token is None}
        ids = {kind: sorted(event["eventId"] for event in events) for kind, events in p.data["raw_logs"].items()}
        final_seen = any(final_marker in event["message"] for event in p.data["raw_logs"].get("lambda", []))
        stable = stable + 1 if ids == previous else 1
        poll.update(finished_at=now(), stable_consecutive_snapshots=stable, final_lambda_marker_seen=final_seen)
        p.data["log_polls"].append(poll)
        p.save()
        if attempt >= 6 and stable >= 3 and final_seen:
            break
        previous = ids
        time.sleep(p.data["bounds"]["log_poll_interval_seconds"])
    p.data["log_collection"] = {"final_lambda_marker_seen": final_seen, "stable_consecutive_snapshots": stable,
        "attempts": attempt + 1, "absence_scope": "Only these bounded paginated owned groups; not proof of permanent silence"}
    if not final_seen:
        p.data["uncertainties"].append("Final Lambda witness not seen within log bound")
    correlate(p)


def correlate(p):
    parsed = {}
    for kind in ("rest_access", "ws_access"):
        parsed[kind] = []
        for event in p.data["raw_logs"].get(kind, []):
            fields = dict(part.split("=", 1) for part in event["message"].strip().split("|") if "=" in part)
            parsed[kind].append({"event_id": event["eventId"], "fields": fields})
    p.data["access_records"] = parsed
    p.data["correlations"] = []
    for row in p.data["http"]:
        headers = {key.lower(): value for key, value in row["result"].get("headers", [])}
        request_id = headers.get("x-amzn-requestid")
        extended = headers.get("x-amz-apigw-id")
        p.data["correlations"].append({"protocol": "REST", "label": row["label"], "status": row["result"].get("status"),
            "request_id": request_id, "extended_request_id": extended,
            "access_event_ids": [record["event_id"] for record in parsed["rest_access"] if record["fields"].get("requestId") == request_id],
            "execution_event_ids": [event["eventId"] for event in p.data["raw_logs"].get("rest_execution", [])
                if request_id and request_id in event["message"]],
            "lambda_event_ids": [event["eventId"] for event in p.data["raw_logs"].get("lambda", []) if row["label"] in event["message"]]})
    for event in p.data["raw_logs"].get("lambda", []):
        try:
            record = json.loads(event["message"])
        except ValueError:
            continue
        context = record.get("event", {}).get("requestContext", {})
        if not context.get("eventType"):
            continue
        request_id = context.get("requestId")
        p.data["correlations"].append({"protocol": "WEBSOCKET", "marker": record.get("marker"),
            "event_type": context["eventType"], "connection_id": context.get("connectionId"), "request_id": request_id,
            "lambda_event_id": event["eventId"],
            "access_event_ids": [item["event_id"] for item in parsed["ws_access"] if item["fields"].get("requestId") == request_id],
            "execution_event_ids": [item["eventId"] for item in p.data["raw_logs"].get("ws_execution", []) if request_id and request_id in item["message"]]})
    p.data["limitations"] = ["Only owned APIs and groups; no Logs resource policy mutations or delivery API mutations",
        "No custom Lambda authorizer was created; principalId substitution sampled absent, signed IAM identity sampled on REST",
        "Fixed five-second settings settling is observational, not a global data-plane convergence guarantee",
        "Unobserved log rows are bounded-capture absence only; raw records and multiple complete polls are retained",
        "WebSocket disconnect is best-effort; management callbacks are signed by the capture owner",
        "Credential-bearing headers are redacted; other owned raw native log messages remain unchanged"]
    p.data["completed_at"] = now()
    p.save()


def run(p):
    reversible = initialize(p)
    setup_apis(p)
    negative_controls(p, "role-absent")
    enabled = reversible and enable_role(p)
    p.data["logging_enabled_safely"] = enabled
    if enabled:
        negative_controls(p, "role-present")
        for name, level, trace, override in (("off-override", "OFF", False, True),
                ("error", "ERROR", False, False), ("info", "INFO", False, False),
                ("info-trace", "INFO", True, False)):
            configure(p, name, level, trace, override)
            cohort(p, name)
        p.connect("lambda-connect-denied", deny=True, phase="info-trace")
        ws_iam_denial(p)
        remove_settings(p)
        cohort(p, "removed", full=False)
    else:
        cohort(p, "no-account-role", full=True)
    p.data["final_marker"] = p.marker("final-lambda-witness")
    rest_request(p, p.data["final_marker"], "/probe/sample", "final-witness")
    collect(p)


def interrupted(signum, frame):
    raise KeyboardInterrupt("Received signal " + str(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/rest_websocket_logs.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--allow-documented-role-policy", action="store_true",
        help="Explicitly permit the AWS documented logging policy on the newly owned role after narrow-policy rejection")
    parser.add_argument("--recapture", action="store_true",
        help="Retain a completed, fully cleaned earlier capture before a new owned runtime capture")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    if args.cleanup_only and args.recapture:
        parser.error("--cleanup-only and --recapture are mutually exclusive")
    p = LogsProbe(args.output, args.account, args.cleanup_only or args.recapture)
    p.allow_documented_role_policy = args.allow_documented_role_policy
    if args.recapture:
        previous = p.data
        if not previous.get("cleanup", {}).get("complete"):
            raise RuntimeError("Previous capture must be fully cleaned before recapture")
        p.data = {"service": "apigateway", "account": args.account, "region": REGION,
            "identity": p.client("sts").get_caller_identity(), "captured_at": now(), "owned": {}, "observations": [],
            "http": [], "tokens": {}, "cleanup": {}, "sdk": {"boto3": base.boto3.__version__},
            "previous_captures": [previous]}
    try:
        if not args.cleanup_only:
            run(p)
    except BaseException as error:
        p.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        p.save()
        raise
    finally:
        try:
            p.cleanup()
        finally:
            for client in p.clients.values():
                client.close()


if __name__ == "__main__":
    main()
