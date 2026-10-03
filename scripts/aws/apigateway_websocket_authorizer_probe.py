#!/usr/bin/env python3
"""Capture owned native WebSocket REQUEST authorizer execution; always clean up."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import time
import urllib.parse
import uuid

import botocore
from botocore.exceptions import BotoCoreError
import websocket

from apigateway_probe import REGION, now
from apigateway_rest_authorizer_probe import create_function
from apigateway_websocket_probe import LifecycleProbe, snapshot

HANDLER = '''import json
import os
import platform


def handler(event, context):
    request = event.get("requestContext", {})
    query = event.get("queryStringParameters") or {}
    headers = {key.lower(): value for key, value in (event.get("headers") or {}).items()}
    marker = query.get("marker") or headers.get("x-probe")
    runtime = {"python": platform.python_version(), "function_version": context.function_version,
               "execution_environment": os.environ.get("AWS_EXECUTION_ENV")}
    record = {"probe_kind": "websocket-authorizer", "invocation": context.aws_request_id,
              "event": event, "runtime": runtime, "marker": marker}
    if event.get("type") == "REQUEST":
        record["kind"] = "authorizer"
        mode = headers.get("x-mode", "allow")
        record["mode"] = mode
        values = {"invocation": context.aws_request_id, "marker": marker,
                  "stageMarker": (event.get("stageVariables") or {}).get("probePhase", ""),
                  "stringValue": "probe-value", "numberValue": 7, "booleanValue": True,
                  "falseValue": False, "emptyValue": ""}
        resource = event["methodArn"]
        if mode == "wrong-resource":
            resource = resource.rsplit("/", 1)[0] + "/not-connect"
        response = {"principalId": "probe-principal", "policyDocument": {
            "Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke",
                "Effect": "Deny" if mode == "deny" else "Allow", "Resource": resource}]},
            "context": values}
        if mode == "unauthorized":
            record["raises"] = {"type": "Exception", "message": "Unauthorized"}
            print(json.dumps(record))
            raise Exception("Unauthorized")
        if mode == "invalid-response":
            response = {"unexpected": "not-an-authorizer-response"}
        elif mode == "malformed-policy":
            response["policyDocument"] = "not-a-policy"
        elif mode == "invalid-effect":
            response["policyDocument"]["Statement"][0]["Effect"] = "NotAnEffect"
        elif mode == "missing-principal":
            del response["principalId"]
        elif mode == "empty-principal":
            response["principalId"] = ""
        elif mode == "null-principal":
            response["principalId"] = None
        elif mode == "number-principal":
            response["principalId"] = 7
        elif mode == "nested-principal":
            response["principalId"] = {"nested": "principal"}
        elif mode == "nested-context":
            values["mapValue"] = {"inner": "value"}
        elif mode == "array-context":
            values["arrayValue"] = ["one", 2, False]
        elif mode == "null-context-value":
            values["nullValue"] = None
        elif mode == "scalar-context":
            response["context"] = "not-a-context-map"
        elif mode == "simple-response":
            response = {"isAuthorized": True, "context": values}
    else:
        record["kind"] = "integration"
        try:
            body = json.loads(event.get("body", ""))
        except (ValueError, TypeError):
            body = {}
        if isinstance(body, dict):
            record["marker"] = body.get("marker") or marker
        response = {"statusCode": 200, "headers": {"content-type": "application/json"},
            "body": json.dumps({"marker": record["marker"], "lambdaRequestId": context.aws_request_id,
                "event": event})}
    record["response"] = response
    print(json.dumps(record))
    return response
'''


class AuthorizerProbe(LifecycleProbe):
    def __init__(self, *args):
        self.envelope = None
        self.envelope_key = None
        super().__init__(*args)

    def save(self):
        if self.envelope is None:
            return super().save()
        capture = self.data
        self.data = {**self.envelope, self.envelope_key: capture}
        try:
            super().save()
        finally:
            self.data = capture

    def connect(self, alias, *, mode="allow", identities=None, tenants=None, phase="semantic", header_name="Authorization", omit_query=False):
        marker = self.marker(alias + "-connect")
        identities = ["probe-shared-identity"] if identities is None else identities
        tenants = ["probe-tenant"] if tenants is None else tenants
        query = [("marker", marker), ("encoded", "a+b space"), ("repeat", "one"), ("repeat", "two")]
        query.extend(("tenant", value) for value in tenants)
        url = self.data["owned"]["websocket_endpoint"] + "/probe"
        if not omit_query:
            url += "?" + urllib.parse.urlencode(query)
        headers = [("X-Probe", marker), ("X-Mode", mode), ("X-Mixed-Header", "ProbeValue"),
                   ("User-Agent", "stackd-native-websocket-authorizer")]
        headers.extend((header_name, value) for value in identities)
        request = {"url": url, "headers": headers, "timeout_seconds": 8, "phase": phase,
                   "mode": mode, "identity_header_values": identities,
                   "identity_query_values": [] if omit_query else tenants,
                   "origin": "https://probe.invalid"}
        started = now()
        sock = websocket.WebSocket()
        try:
            sock.connect(url, header=[key + ": " + value for key, value in headers],
                         timeout=8, origin=request["origin"])
            result = {"status": sock.getstatus(), "headers": sock.getheaders(), "outcome": "connected"}
            self.sockets[alias] = sock
            self.data["expected_integration_markers"].append(marker)
        except websocket.WebSocketBadStatusException as error:
            result = {"status": error.status_code, "headers": error.resp_headers,
                      "body": error.resp_body, "outcome": "handshake_rejected"}
            sock.shutdown()
        except Exception as error:
            result = {"outcome": "transport_error", "error_type": type(error).__name__, "error": str(error)}
            sock.shutdown()
        self.data["connections"][alias] = {"marker": marker, "phase": phase, "mode": mode,
            "handshake_status": result.get("status"), "configuration_phase": self.data.get("configuration_phase")}
        return self.socket_record(alias + "-connect", "connect", alias, started, request, result)

    def application(self, alias, label, *, phase="semantic"):
        marker = self.marker(label)
        sent = self.send(alias, label + "-send", json.dumps({"action": "echo", "marker": marker}))
        if sent["outcome"] == "sent":
            self.data["expected_integration_markers"].append(marker)
        result = self.receive(alias, label + "-receive", timeout=5)
        self.data["scenarios"].append({"label": label, "marker": marker, "connection": alias,
            "phase": phase, "send_label": label + "-send", "receive_label": label + "-receive"})
        self.save()
        return result

    def cleanup(self):
        base_error = None
        try:
            super().cleanup()
        except Exception as error:
            base_error = error
        role = self.data["owned"].get("invocation_role")
        if role:
            self.call("cleanup-invocation-role-policy", "iam", "delete_role_policy",
                      {"RoleName": role, "PolicyName": "probe-invoke"}, required=False)
            self.call("cleanup-invocation-role", "iam", "delete_role", {"RoleName": role}, required=False)
            absent = self.call("absence-invocation-role", "iam", "get_role", {"RoleName": role}, required=False)
            self.data["cleanup"]["invocation_role"] = {"absent": absent["code"] == "NoSuchEntity"}
            self.data["cleanup"]["complete"] = (self.data["cleanup"].get("complete", False)
                                                and absent["code"] == "NoSuchEntity")
            self.save()
        if base_error or not self.data["cleanup"].get("complete"):
            raise RuntimeError("Owned WebSocket authorizer resource cleanup remains incomplete") from base_error


def deploy(p, phase, *, first=False, omit_stage_variables=False):
    api = p.data["owned"]["http_api"]
    deployment = p.required(phase + "-deployment", "apigatewayv2", "create_deployment",
                           {"ApiId": api, "Description": phase})
    stage = {"ApiId": api, "StageName": "probe", "DeploymentId": deployment["DeploymentId"]}
    if not omit_stage_variables:
        stage["StageVariables"] = {"probePhase": phase}
    if first:
        stage["AutoDeploy"] = False
    p.required(phase + "-stage", "apigatewayv2", "create_stage" if first else "update_stage", stage)
    p.data["deployments"][phase] = deployment["DeploymentId"]
    p.data["configuration_phase"] = phase
    snapshot(p, phase)
    p.required(phase + "-authorizer", "apigatewayv2", "get_authorizer",
               {"ApiId": api, "AuthorizerId": p.data["authorizer_id"]})


def ready(p, phase, *, identity=None, omit_query=False, expected_stage_marker=None):
    evidence = {"phase": phase, "started_at": now(), "max_attempts": 24, "interval_seconds": 5,
        "consecutive_successes_required": 3, "attempts": [],
        "requirement": "HTTP 101 plus marker-correlated real echo Lambda response containing matching authorizer handshake marker and stage phase"}
    p.data["readiness"].append(evidence)
    consecutive = 0
    for attempt in range(24):
        alias = phase + "-ready-" + str(attempt)
        handshake = p.connect(alias, phase="readiness", identities=[identity or p.marker(alias)], omit_query=omit_query)
        sample = {"connection": alias, "handshake_status": handshake.get("status")}
        if handshake.get("status") == 101:
            label = alias + "-echo"
            response = p.application(alias, label, phase="readiness")
            body = response.get("json", {})
            auth = body.get("event", {}).get("requestContext", {}).get("authorizer", {})
            sample["application_lambda_request_id"] = body.get("lambdaRequestId")
            sample["authorizer_context"] = auth
            sample["ready"] = (body.get("marker") == p.marker(label)
                and auth.get("marker") == p.marker(alias + "-connect")
                and auth.get("stageMarker") == (p.data["configuration_phase"] if expected_stage_marker is None else expected_stage_marker))
        else:
            sample["ready"] = False
        evidence["attempts"].append(sample)
        p.close(alias, alias + "-close")
        consecutive = consecutive + 1 if sample["ready"] else 0
        if consecutive == 3:
            evidence.update(ready=True, finished_at=now())
            p.save()
            return
        p.save()
        time.sleep(5)
    evidence.update(ready=False, finished_at=now())
    p.save()
    raise RuntimeError("Positive authorizer/integration readiness bound reached: " + phase)


def sample(p, alias, *, keep=False, **kwargs):
    result = p.connect(alias, **kwargs)
    if result.get("status") == 101:
        response = p.application(alias, alias + "-echo")
        if response.get("json", {}).get("marker") != p.marker(alias + "-echo"):
            raise RuntimeError("Accepted socket did not produce real marker-correlated application response: " + alias)
        if not keep:
            p.close(alias, alias + "-close")
    elif result.get("status") is None:
        raise RuntimeError("Transport failure is not authorizer semantics: " + alias)
    return result


def permission(p, label):
    p.required(label, "lambda", "add_permission", {"FunctionName": p.data["owned"]["function"],
        "StatementId": "authorizer", "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
        "SourceAccount": p.data["account"], "SourceArn": p.data["authorizer_source_arn"]})


def credentials_role(p, function):
    role_name = p.data["prefix"] + "-invoke"
    principal = {"Service": "apigateway.amazonaws.com"}
    denied = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny",
        "Principal": principal, "Action": "sts:AssumeRole"}]}
    role = p.required("create-invocation-role-trust-denied", "iam", "create_role",
        {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps(denied)},
        own=("invocation_role", "Role.RoleName"))["Role"]
    p.required("invocation-role-lambda-policy", "iam", "put_role_policy", {"RoleName": role_name,
        "PolicyName": "probe-invoke", "PolicyDocument": json.dumps({"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]}]})})
    p.required("credentials-role-remove-authorizer-permission", "lambda", "remove_permission",
               {"FunctionName": function["FunctionName"], "StatementId": "authorizer"})
    p.required("credentials-role-resource-policy", "lambda", "get_policy", {"FunctionName": function["FunctionName"]})
    p.required("configure-authorizer-invocation-role", "apigatewayv2", "update_authorizer",
        {"ApiId": p.data["owned"]["http_api"], "AuthorizerId": p.data["authorizer_id"],
         "AuthorizerCredentialsArn": role["Arn"]})
    deploy(p, "credentials-trust-denied")
    for attempt in range(3):
        sample(p, "credentials-trust-denied-" + str(attempt), identities=["role-denied-" + str(attempt)])
        if attempt < 2:
            time.sleep(5)
    p.application("allow-held", "held-while-invocation-role-trust-denied")
    restored = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": principal,
        "Action": "sts:AssumeRole", "Condition": {"Null": {"aws:SourceArn": "true", "aws:SourceAccount": "true"},
            "StringEquals": {"aws:PrincipalType": "AssumedRole"}}}]}
    p.required("restore-invocation-role-trust-service-context", "iam", "update_assume_role_policy",
               {"RoleName": role_name, "PolicyDocument": json.dumps(restored)})
    p.required("get-restored-invocation-role", "iam", "get_role", {"RoleName": role_name})
    deploy(p, "credentials-trust-restored")
    ready(p, "credentials-trust-restored")
    sample(p, "credentials-role-positive")
    p.required("credentials-role-resource-policy-still-absent", "lambda", "get_policy",
               {"FunctionName": function["FunctionName"]})
    p.data["credentials_role_evidence"] = {
        "arn": role["Arn"], "explicit_deny_initial_trust": denied, "restored_trust": restored,
        "positive_readiness": True, "authorizer_resource_permission_removed": True,
        "interpretation": "Positive role-backed authorizer invocation under the recorded conditional trust, without authorizer resource permission. Initial rejections are not an STS audit and do not identify the rejection layer.",
        "unsampled": ["STS duration", "STS role session name", "Changing trust after an already successful cached role session"]}
    p.save()


def validation_expression(p):
    api = p.data["owned"]["http_api"]
    p.required("configure-validation-expression", "apigatewayv2", "update_authorizer", {
        "ApiId": api, "AuthorizerId": p.data["authorizer_id"],
        "IdentitySource": ["route.request.header.Authorization"],
        "IdentityValidationExpression": "^probe-regex-allow$"})
    deploy(p, "validation-expression")
    ready(p, "validation-expression", identity="probe-regex-allow")
    for label, identities in (("matching", ["probe-regex-allow"]), ("nonmatching", ["probe-regex-reject"]),
                              ("substring-only", ["prefix-probe-regex-allow-suffix"]),
                              ("missing", []), ("empty", [""])):
        sample(p, "validation-expression-" + label, identities=identities)
    p.data["completed_at"] = now()
    p.save()


def identity_context(p):
    api = p.data["owned"]["http_api"]
    cases = []
    p.data["identity_context_cases"] = cases
    sources = ["context.connectionId", "context.eventType", "context.messageDirection",
               "context.connectedAt", "context.requestTimeEpoch", "context.routeKey",
               "stageVariables.probePhase"]
    p.data["bounds"].update(deployments=16, identity_context_sources=len(sources),
                            missing_stage_variable_samples=12, missing_stage_variable_interval_seconds=5)
    for source in sources:
        phase = "identity-" + source.replace(".", "-")
        result = p.call(phase + "-configure", "apigatewayv2", "update_authorizer", {
            "ApiId": api, "AuthorizerId": p.data["authorizer_id"], "IdentitySource": [source]}, required=False)
        entry = {"source": source, "configuration_result": result, "phase": phase}
        cases.append(entry)
        if result["code"] != "Success":
            continue
        deploy(p, phase)
        try:
            ready(p, phase)
        except RuntimeError as error:
            entry["positive_readiness"] = False
            entry["readiness_error"] = str(error)
            entry["interpretation"] = "Accepted configuration without positive readiness inside the bound; failures alone do not establish identity semantics."
            p.required(phase + "-restore-header", "apigatewayv2", "update_authorizer", {
                "ApiId": api, "AuthorizerId": p.data["authorizer_id"],
                "IdentitySource": ["route.request.header.Authorization"]})
            deploy(p, phase + "-restored")
            ready(p, phase + "-restored")
            continue
        entry["positive_readiness"] = True
        sample(p, phase + "-positive")
    p.data["completed_at"] = now()
    p.save()


def missing_stage_identity(p):
    api = p.data["owned"]["http_api"]
    p.required("configure-missing-stage-identity", "apigatewayv2", "update_authorizer", {
        "ApiId": api, "AuthorizerId": p.data["authorizer_id"], "IdentitySource": ["stageVariables.probePhase"]})
    deploy(p, "missing-stage-identity", omit_stage_variables=True)
    stage = p.data["configuration_snapshots"][-1]["stage"]
    if "probePhase" in stage.get("StageVariables", {}):
        raise RuntimeError("Missing-variable capture requires a stage created without probePhase")
    evidence = {"source": "stageVariables.probePhase", "confirmed_stage": stage,
                "max_samples": 16, "interval_seconds": 5, "consecutive_401_required": 3, "samples": []}
    p.data["missing_stage_identity"] = evidence
    p.data["bounds"].update(missing_stage_variable_samples=16, missing_stage_variable_interval_seconds=5)
    consecutive = 0
    for attempt in range(16):
        alias = "missing-stage-identity-" + str(attempt)
        result = sample(p, alias, phase="transition")
        evidence["samples"].append({"connection": alias, "status": result.get("status")})
        consecutive = consecutive + 1 if result.get("status") == 401 else 0
        if consecutive >= 3:
            break
        if attempt < 15:
            time.sleep(5)
    evidence["observed_consecutive_401"] = consecutive
    deploy(p, "stage-identity-present")
    ready(p, "stage-identity-present")
    sample(p, "stage-identity-present-positive")
    p.data["completed_at"] = now()
    p.save()


def http_route_update(p):
    p.data.update(protocol="HTTP", capture_kind="route_update_status",
        scope="One fresh owned HTTP API route create/update/get/delete status comparison; no integration or Lambda",
        bounds={"apis": 1, "routes": 1, "functions": 0, "roles": 0, "stages": 0,
                "sdk_total_max_attempts": 1, "cleanup_attempts": 3},
        documentation=["https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-routes-routeid.html"],
        probe_source=Path(__file__).read_text(), handler_source=None,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        runtime_versions={"python": platform.python_version(), "botocore": botocore.__version__})
    p.save()
    api = p.required("http-status-create-api", "apigatewayv2", "create_api",
        {"Name": p.data["prefix"], "ProtocolType": "HTTP"}, own=("http_api", "ApiId"))["ApiId"]
    route = p.required("http-status-create-route", "apigatewayv2", "create_route",
        {"ApiId": api, "RouteKey": "GET /before", "AuthorizationType": "NONE"})["RouteId"]
    p.required("http-status-update-route", "apigatewayv2", "update_route",
               {"ApiId": api, "RouteId": route, "RouteKey": "GET /after"})
    current = p.required("http-status-get-route", "apigatewayv2", "get_route", {"ApiId": api, "RouteId": route})
    if current["RouteKey"] != "GET /after":
        raise RuntimeError("Native HTTP route update was not visible in GetRoute")
    p.required("http-status-delete-route", "apigatewayv2", "delete_route", {"ApiId": api, "RouteId": route})
    absent = p.call("http-status-route-absence", "apigatewayv2", "get_route", {"ApiId": api, "RouteId": route}, required=False)
    p.data["route_absent"] = absent["code"] == "NotFoundException"
    if not p.data["route_absent"]:
        raise RuntimeError("Deleted HTTP route was not confirmed absent")
    p.data["completed_at"] = now()
    p.save()


def stage_variable_update(p):
    p.data.update(protocol="WEBSOCKET", capture_kind="stage_variable_update",
        scope="One fresh owned WebSocket API/stage map update comparison; no routes, integration or Lambda",
        bounds={"apis": 1, "stages": 1, "routes": 0, "functions": 0, "roles": 0,
                "sdk_total_max_attempts": 1, "cleanup_attempts": 3},
        documentation=["https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-stages-stagename.html"],
        probe_source=Path(__file__).read_text(), handler_source=None,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        runtime_versions={"python": platform.python_version(), "botocore": botocore.__version__})
    p.save()
    api = p.required("stage-map-create-api", "apigatewayv2", "create_api", {"Name": p.data["prefix"],
        "ProtocolType": "WEBSOCKET", "RouteSelectionExpression": "$request.body.action"},
        own=("http_api", "ApiId"))["ApiId"]
    p.required("stage-map-create-empty", "apigatewayv2", "create_stage",
               {"ApiId": api, "StageName": "probe", "AutoDeploy": False})
    for key, value in (("probeOne", "one"), ("probeTwo", "two")):
        p.required("stage-map-update-" + key, "apigatewayv2", "update_stage",
                   {"ApiId": api, "StageName": "probe", "StageVariables": {key: value}})
        stage = p.required("stage-map-get-" + key, "apigatewayv2", "get_stage",
                           {"ApiId": api, "StageName": "probe"})
    p.data["final_stage_variables"] = stage.get("StageVariables")
    p.required("stage-map-delete-stage", "apigatewayv2", "delete_stage", {"ApiId": api, "StageName": "probe"})
    absent = p.call("stage-map-stage-absence", "apigatewayv2", "get_stage",
                   {"ApiId": api, "StageName": "probe"}, required=False)
    p.data["stage_absent"] = absent["code"] == "NotFoundException"
    if not p.data["stage_absent"]:
        raise RuntimeError("Deleted stage was not confirmed absent")
    p.data["completed_at"] = now()
    p.save()


def run(p, *, validation_expression_only=False, empty_shape_only=False, identity_context_only=False, missing_stage_identity_only=False):
    p.data.update(protocol="WEBSOCKET", scope="One owned REQUEST authorizer and actual WebSocket Lambda integration; no account or organization changes",
        owned_api_slot="http_api is the common Probe cleanup key for API Gateway v2",
        capture_kind="missing_stage_identity" if missing_stage_identity_only else "identity_context" if identity_context_only else "empty_request_shape" if empty_shape_only else "validation_expression" if validation_expression_only else "full_execution",
        bounds={"apis": 1, "functions": 1, "roles": 2, "log_groups": 1, "stages": 1, "authorizers": 1,
            "deployments": 4, "readiness_attempts": 24, "readiness_interval_seconds": 5,
            "readiness_consecutive_successes": 3, "connect_timeout_seconds": 8, "send_timeout_seconds": 8,
            "receive_timeout_seconds": 5, "close_timeout_seconds": 2, "log_attempts": 24,
            "log_pages_per_attempt": 4, "log_interval_seconds": 3, "permission_removal_samples": 3,
            "permission_removal_interval_seconds": 5, "cleanup_attempts": 3, "sdk_total_max_attempts": 1},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-lambda-auth.html"],
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        runtime_versions={"python": platform.python_version(), "websocket-client": websocket.__version__,
            "botocore": botocore.__version__, "lambda_requested": "python3.13"},
        unsampled_boundaries=["Cross-account authorizers; STS duration and session name; role trust changes after cached successful assumption",
            "Policy conditions, NotAction/NotResource, multiple statements, size limits and complex wildcard precedence",
            "Concurrency, multi-stage caching, regional convergence and long idle/lifetime behavior",
            "Absence claims cover the bounded owned log window only; disconnect is best-effort"],
        websocket_observations=[], connections={}, scenarios=[], readiness=[], expected_integration_markers=[],
        configuration_snapshots=[], deployments={}, log_start_ms=int(time.time() * 1000))
    p.save()
    function, _ = create_function(p, handler=HANDLER)
    api = p.required("create-websocket-api", "apigatewayv2", "create_api", {"Name": p.data["prefix"],
        "ProtocolType": "WEBSOCKET", "RouteSelectionExpression": "$request.body.action"}, own=("http_api", "ApiId"))
    p.data["owned"]["websocket_endpoint"] = api["ApiEndpoint"]
    p.data["owned"]["log_group"] = "/aws/lambda/" + function["FunctionName"]
    api_id = api["ApiId"]
    source = f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api_id}"
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    p.required("permission-integration-only", "lambda", "add_permission", {"FunctionName": function["FunctionName"],
        "StatementId": "integration", "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
        "SourceAccount": p.data["account"], "SourceArn": source + "/probe/*"})
    integration = p.required("create-integration", "apigatewayv2", "create_integration", {"ApiId": api_id,
        "IntegrationType": "AWS_PROXY", "IntegrationMethod": "POST", "IntegrationUri": uri})
    authorizer = p.required("create-authorizer", "apigatewayv2", "create_authorizer", {"ApiId": api_id,
        "Name": "request-authorizer", "AuthorizerType": "REQUEST", "AuthorizerUri": uri,
        "IdentitySource": ["route.request.header.Authorization", "route.request.querystring.tenant"]})
    p.data["authorizer_id"] = authorizer["AuthorizerId"]
    p.data["authorizer_source_arn"] = source + "/authorizers/" + authorizer["AuthorizerId"]
    permission(p, "permission-authorizer")
    routes = {}
    for route in ("$connect", "$disconnect", "$default", "echo"):
        parameters = {"ApiId": api_id, "RouteKey": route, "AuthorizationType": "NONE",
                      "Target": "integrations/" + integration["IntegrationId"]}
        if route == "$connect":
            parameters.update(AuthorizationType="CUSTOM", AuthorizerId=authorizer["AuthorizerId"])
        elif route in ("$default", "echo"):
            parameters["RouteResponseSelectionExpression"] = "$default"
        result = p.required("create-route-" + route, "apigatewayv2", "create_route", parameters)
        routes[route] = result["RouteId"]
        if route in ("$default", "echo"):
            p.required("create-response-" + route, "apigatewayv2", "create_route_response",
                {"ApiId": api_id, "RouteId": result["RouteId"], "RouteResponseKey": "$default"})
    p.data["route_ids"] = routes
    if empty_shape_only or missing_stage_identity_only:
        p.required("configure-header-only-identity", "apigatewayv2", "update_authorizer", {
            "ApiId": api_id, "AuthorizerId": p.data["authorizer_id"],
            "IdentitySource": ["route.request.header.Authorization"]})
        deploy(p, "empty-request-shape", first=True, omit_stage_variables=True)
        ready(p, "empty-request-shape", omit_query=True, expected_stage_marker="")
        if missing_stage_identity_only:
            missing_stage_identity(p)
            return
        sample(p, "empty-query-and-stage-variables", omit_query=True)
        p.data["completed_at"] = now()
        p.save()
        return
    deploy(p, "initial", first=True)
    ready(p, "initial")
    if validation_expression_only:
        validation_expression(p)
        return
    if identity_context_only:
        identity_context(p)
        return
    sample(p, "allow-held", keep=True)
    for mode in ("allow", "deny", "wrong-resource", "unauthorized", "invalid-response", "malformed-policy",
                 "invalid-effect", "missing-principal", "empty-principal", "null-principal", "number-principal",
                 "nested-principal", "nested-context", "array-context", "null-context-value", "scalar-context", "simple-response"):
        sample(p, "response-" + mode, mode=mode)
    for label, kwargs in (
            ("missing-header", {"identities": []}), ("empty-header", {"identities": [""]}),
            ("duplicate-header", {"identities": ["header-one", "header-two"]}),
            ("duplicate-header-first-empty", {"identities": ["", "header-two"]}),
            ("duplicate-header-last-empty", {"identities": ["header-one", ""]}),
            ("mixed-case-header", {"header_name": "aUtHoRiZaTiOn"}),
            ("missing-query", {"tenants": []}), ("empty-query", {"tenants": [""]}),
            ("duplicate-query", {"tenants": ["tenant-one", "tenant-two"]}),
            ("duplicate-query-first-empty", {"tenants": ["", "tenant-two"]}),
            ("duplicate-query-last-empty", {"tenants": ["tenant-one", ""]})):
        sample(p, "identity-" + label, **kwargs)
    sample(p, "same-identity-first")
    sample(p, "same-identity-repeat")
    sample(p, "same-identity-new-denied", mode="deny")
    p.application("allow-held", "held-after-denied-new-connections")
    ttl = p.call("update-ttl-60", "apigatewayv2", "update_authorizer", {"ApiId": api_id,
        "AuthorizerId": authorizer["AuthorizerId"], "AuthorizerResultTtlInSeconds": 60}, required=False)
    p.data["ttl_update_accepted"] = ttl["code"] == "Success"
    p.required("get-authorizer-after-ttl-attempt", "apigatewayv2", "get_authorizer",
               {"ApiId": api_id, "AuthorizerId": authorizer["AuthorizerId"]})
    if p.data["ttl_update_accepted"]:
        deploy(p, "ttl-60")
        ready(p, "ttl-60")
        for label, mode in (("first", "allow"), ("repeat", "allow"), ("changed-mode-deny", "deny")):
            sample(p, "ttl-60-same-identity-" + label, mode=mode, identities=["probe-ttl-shared"])
        p.application("allow-held", "held-after-authorizer-ttl-deployment")
    p.required("policy-before-permission-removal", "lambda", "get_policy", {"FunctionName": function["FunctionName"]})
    p.required("remove-authorizer-permission", "lambda", "remove_permission",
               {"FunctionName": function["FunctionName"], "StatementId": "authorizer"})
    p.required("policy-authorizer-permission-removed", "lambda", "get_policy", {"FunctionName": function["FunctionName"]})
    for attempt in range(3):
        sample(p, "permission-removed-" + str(attempt), identities=["permission-removed-" + str(attempt)])
        if attempt < 2:
            time.sleep(5)
    p.application("allow-held", "held-while-authorizer-permission-removed")
    permission(p, "restore-authorizer-permission")
    p.required("policy-authorizer-permission-restored", "lambda", "get_policy", {"FunctionName": function["FunctionName"]})
    ready(p, "permission-restored")
    credentials_role(p, function)
    sample(p, "final-positive")
    p.application("allow-held", "held-final-application")
    p.close("allow-held", "allow-held-final-close")
    p.data["completed_at"] = now()
    p.save()


def collect_logs(p):
    if "function" not in p.data["owned"]:
        return
    collected, previous = {}, None
    for attempt in range(24):
        token = None
        read_succeeded = True
        for page in range(4):
            parameters = {"logGroupName": "/aws/lambda/" + p.data["owned"]["function"],
                          "startTime": p.data["log_start_ms"], "limit": 1000}
            if token:
                parameters["nextToken"] = token
            try:
                result = p.call(f"authorizer-logs-{attempt}-{page}", "logs", "filter_log_events", parameters, required=False)
            except BotoCoreError as error:
                p.data.setdefault("log_collection_attempt_errors", []).append({
                    "attempt": attempt, "page": page, "at": now(), "request": parameters,
                    "error_type": type(error).__name__, "error": str(error)})
                read_succeeded = False
                break
            if result["code"] != "Success":
                read_succeeded = False
                break
            for item in result["output"].get("events", []):
                collected[item["eventId"]] = item
            next_token = result["output"].get("nextToken")
            if not next_token or next_token == token:
                token = None
                break
            token = next_token
        records = []
        for item in sorted(collected.values(), key=lambda value: (value["timestamp"], value["eventId"])):
            try:
                value = json.loads(item["message"])
            except ValueError:
                continue
            if value.get("probe_kind") == "websocket-authorizer":
                records.append({"timestamp": item["timestamp"], "event_id": item["eventId"],
                                "log_stream": item["logStreamName"], "record": value})
        p.data["invocation_logs"] = records
        p.data["runtime_log_records"] = [item for item in collected.values() if item["message"].startswith("INIT_START")]
        integration = [item["record"] for item in records if item["record"]["kind"] == "integration"]
        seen = {item.get("marker") for item in integration}
        missing = sorted(set(p.data.get("expected_integration_markers", [])) - seen)
        connects = {item["event"]["requestContext"]["connectionId"] for item in integration
                    if item["event"]["requestContext"]["eventType"] == "CONNECT"}
        disconnects = {item["event"]["requestContext"]["connectionId"] for item in integration
                       if item["event"]["requestContext"]["eventType"] == "DISCONNECT"}
        current = sorted(collected)
        stable = read_succeeded and current == previous
        p.data["log_collection"] = {"attempts": attempt + 1, "missing_expected_integration_markers": missing,
            "successful_connects_without_observed_disconnect": sorted(connects - disconnects),
            "stable_consecutive_snapshots": 2 if stable else 1, "pagination_bound_hit": bool(token),
            "absence_scope": "Bounded owned function logs; no matching invocation is observed absence, not a global guarantee."}
        p.save()
        if not missing and connects <= disconnects and stable and attempt >= 2 and not token:
            return
        previous = current if read_succeeded and not token else None
        time.sleep(3)
    raise RuntimeError("Owned log capture did not stabilize within 24 attempts")


def summarize(p):
    records = [item["record"] for item in p.data.get("invocation_logs", [])]
    authorizers = [record for record in records if record["kind"] == "authorizer"]
    integrations = [record for record in records if record["kind"] == "integration"]
    rows = []
    for alias, connection in p.data.get("connections", {}).items():
        auth = [record for record in authorizers if record.get("marker") == connection["marker"]]
        backend = [record for record in integrations if record.get("marker") == connection["marker"]]
        ids = {record["event"]["requestContext"]["connectionId"] for record in backend}
        related = [record for record in integrations if record["event"]["requestContext"]["connectionId"] in ids]
        rows.append({"connection": alias, **connection, "authorizer_invocations": [record["invocation"] for record in auth],
            "connect_integration_invocations": [record["invocation"] for record in backend],
            "authorizer_responses": [record.get("response", record.get("raises")) for record in auth],
            "connect_integration_authorizer_contexts": [record["event"]["requestContext"].get("authorizer") for record in backend],
            "related_integration_event_types": [record["event"]["requestContext"]["eventType"] for record in related]})
    accepted = {row["connection"] for row in p.data.get("websocket_observations", [])
                if row["operation"] == "connect" and row["result"].get("status") == 101}
    closed = {row["connection"] for row in p.data.get("websocket_observations", [])
              if row["operation"] == "close" and row["result"].get("local_socket_closed")}
    p.data["summary"] = {"connections": rows, "authorizer_invocation_count": len(authorizers),
        "integration_invocation_count": len(integrations), "accepted_socket_count": len(accepted),
        "closed_socket_count": len(closed), "accepted_sockets_without_local_closure": sorted(accepted - closed),
        "event_top_level_keys": sorted({tuple(sorted(record["event"])) for record in authorizers}),
        "authorization_scope": "Compare marker-correlated REQUEST calls with CONNECT/MESSAGE/DISCONNECT events, not inferred HTTP behavior."}
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/websocket_lambda_authorizers.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--append-capture", action="store_true")
    parser.add_argument("--validation-expression-capture", action="store_true",
                        help="Attach a fresh focused capture to a completely cleaned full execution fixture")
    parser.add_argument("--empty-shape-capture", action="store_true",
                        help="Attach an independent no-query/no-stage-variable event capture")
    parser.add_argument("--identity-context-capture", action="store_true",
                        help="Attach independent WebSocket context and stage-variable identity execution")
    parser.add_argument("--http-route-update-only", action="store_true",
                        help="Capture a separate fresh HTTP API route update status without Lambda")
    parser.add_argument("--missing-stage-identity-capture", action="store_true",
                        help="Attach required stage-variable absence using a stage created without variables")
    parser.add_argument("--stage-variable-update-only", action="store_true",
                        help="Capture separate WebSocket stage variable map updates without a backend")
    args = parser.parse_args()
    if args.cleanup_only and args.append_capture:
        parser.error("--cleanup-only and --append-capture are mutually exclusive")
    if sum((args.validation_expression_capture, args.empty_shape_capture, args.identity_context_capture,
            args.http_route_update_only, args.missing_stage_identity_capture,
            args.stage_variable_update_only, args.append_capture)) > 1:
        parser.error("Only one fresh capture mode may be selected")
    supplement = ("missing_stage_identity_capture" if args.missing_stage_identity_capture else
                  "identity_context_capture" if args.identity_context_capture else
                  "empty_request_shape_capture" if args.empty_shape_capture else
                  "validation_expression_capture" if args.validation_expression_capture else None)
    p = AuthorizerProbe(args.output, args.account, args.cleanup_only or args.append_capture or bool(supplement))
    if supplement and args.cleanup_only:
        p.envelope = p.data
        p.envelope_key = supplement
        p.data = p.data[supplement]
    elif args.append_capture or supplement:
        previous = p.data
        if previous.get("protocol") != "WEBSOCKET" or not previous.get("cleanup", {}).get("complete"):
            raise RuntimeError("Can append only to a completely cleaned WebSocket capture")
        if supplement:
            if supplement in previous:
                raise RuntimeError("Refusing to overwrite " + supplement + " evidence")
            p.envelope_key = supplement
            p.envelope = previous
            earlier = []
        else:
            earlier = previous.pop("prior_captures", [])
        p.data = {"service": "apigateway", "account": args.account, "region": REGION,
            "identity": previous["identity"], "captured_at": now(), "prefix": "stackd-apigw-" + uuid.uuid4().hex[:10],
            "owned": {}, "observations": [], "http": [], "tokens": {}, "cleanup": {},
            "sdk": previous["sdk"]}
        if args.append_capture:
            p.data["prior_captures"] = earlier + [previous]
    try:
        if not args.cleanup_only:
            if args.http_route_update_only:
                http_route_update(p)
            elif args.stage_variable_update_only:
                stage_variable_update(p)
            else:
                run(p, validation_expression_only=args.validation_expression_capture,
                    empty_shape_only=args.empty_shape_capture, identity_context_only=args.identity_context_capture,
                    missing_stage_identity_only=args.missing_stage_identity_capture)
    except BaseException as error:
        p.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        p.save()
        raise
    finally:
        try:
            for alias in list(p.sockets):
                p.close(alias, alias + "-finally-close")
            if not args.cleanup_only:
                try:
                    collect_logs(p)
                except Exception as error:
                    p.data["log_collection_error"] = {"type": type(error).__name__, "message": str(error)}
                summarize(p)
            for attempt in range(3):
                try:
                    p.cleanup()
                    break
                except Exception as error:
                    p.data.setdefault("cleanup_attempt_errors", []).append({"attempt": attempt, "error": str(error)})
                    p.save()
                    if attempt == 2:
                        raise
                    time.sleep(2)
        finally:
            for client in p.clients.values():
                client.close()
    if not args.cleanup_only and (p.data.get("log_collection_error")
            or p.data.get("log_collection", {}).get("missing_expected_integration_markers")
            or p.data.get("summary", {}).get("accepted_sockets_without_local_closure")):
        p.data["failure"] = {"type": "RuntimeError", "message": "Execution evidence incomplete; owned resources were cleaned", "at": now()}
        p.save()
        raise RuntimeError(p.data["failure"]["message"])


if __name__ == "__main__":
    main()
