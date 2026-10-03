#!/usr/bin/env python3
"""Capture owned HTTP/WebSocket Lambda integration credentials against native AWS."""
import argparse
import json
from pathlib import Path
import time
import uuid

import boto3

from apigateway_probe import REGION, now
from apigateway_rest_authorizer_probe import create_function, role_trust
from apigateway_http_authorizer_probe import scoped_role_call
from apigateway_websocket_probe import LifecycleProbe

SENTINEL = "arn:aws:iam::*:user/*"
HANDLER = '''import json

def handler(event, context):
    request = event.get("requestContext", {})
    headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
    body = event.get("body")
    try:
        message = json.loads(body or "{}")
    except ValueError:
        message = {}
    marker = message.get("marker") or headers.get("x-probe") or event.get("queryStringParameters", {}).get("marker")
    result = {"probe_kind": "v2-integration-credentials", "marker": marker,
              "invocation_id": context.aws_request_id, "event": event}
    print(json.dumps(result, separators=(",", ":")))
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"marker": marker, "invocation_id": context.aws_request_id,
                                "route": request.get("routeKey"),
                                "stage_variables": event.get("stageVariables", {})})}
'''


def classify_authority(row):
    """Do not turn independently unsettled API permissions into PassRole evidence."""
    message = row["result"].get("error", {}).get("Message", "")
    if "-passrole-" in row["label"] and "not authorized to perform: apigateway:" in message:
        row["phase"] = "authority-propagation"
        row["interpretation"] = (
            "The error names API Gateway operation authority, not iam:PassRole. "
            "Earlier success on another request does not prove this permission converged.")


class IntegrationProbe(LifecycleProbe):
    def __init__(self, *args):
        self.envelope = None
        super().__init__(*args)
        credentials = self.session.get_credentials().get_frozen_credentials()
        for value, kind in ((credentials.access_key, "accesskeyid"),
                            (credentials.secret_key, "secretaccesskey"),
                            (credentials.token, "sessiontoken")):
            if value:
                self.hide(value, kind)

    def save(self):
        if self.envelope is None:
            return super().save()
        capture = self.data
        self.data = {**self.envelope, "trust_context_capture": capture}
        try:
            super().save()
        finally:
            self.data = capture

    def call(self, *args, **kwargs):
        start = len(self.data["observations"])
        try:
            return super().call(*args, **kwargs)
        finally:
            for row in self.data["observations"][start:]:
                row["phase"] = getattr(self, "phase", "setup")
                row.setdefault("actor", self.data["identity"])
                classify_authority(row)
            self.save()

    def application(self, alias, label, action="active", phase="semantic"):
        marker = self.marker(label)
        self.send(alias, label + "-send", json.dumps({"action": action, "marker": marker}))
        result = self.receive(alias, label + "-receive", timeout=5)
        success = result.get("json", {}).get("marker") == marker
        if success:
            self.data["expected_invocation_markers"].append(marker)
        self.data["scenarios"].append({"label": label, "phase": phase, "protocol": "WEBSOCKET",
            "surface": "held-message", "connection": alias, "route": action,
            "marker": marker, "result": result, "backend_success": success})
        self.save()
        return success if success or result.get("json", {}).get("message") else None

    def request(self, label, route="active", phase="semantic", authorization="none"):
        result = self.http(label, "plain_http", "/probe/" + route, authorization=authorization)
        self.data["http"][-1]["phase"] = phase
        self.data["http"][-1]["actor"] = self.data["identity"] if authorization == "iam" else "anonymous"
        success = bool(result.get("body", {}).get("invocation_id"))
        if success:
            self.data["expected_invocation_markers"].append(label)
        self.data["scenarios"].append({"label": label, "phase": phase, "protocol": "HTTP",
            "surface": "request", "route": route, "marker": label, "result": result,
            "backend_success": success})
        self.save()
        return success if result.get("status") in (200, 500) else None

    def cleanup(self):
        self.phase = "cleanup"
        outcomes = []
        for key in ("plain_http_api", "baseline_websocket_api"):
            api = self.data["owned"].get(key)
            if api:
                self.call("cleanup-" + key, "apigatewayv2", "delete_api", {"ApiId": api}, required=False)
                result = self.call("absence-" + key, "apigatewayv2", "get_api", {"ApiId": api}, required=False)
                outcomes.append(result["code"] == "NotFoundException")
                self.data["cleanup"][key] = {"absent": outcomes[-1]}
        try:
            super().cleanup()
            outcomes.append(True)
        except Exception as error:
            outcomes.append(False)
            self.data["cleanup"]["base_error"] = str(error)
        for key, role in self.data["owned"].items():
            if not key.startswith("credential_role_"):
                continue
            self.call("cleanup-policy-" + key, "iam", "delete_role_policy",
                      {"RoleName": role, "PolicyName": "probe-authority"}, required=False)
            self.call("cleanup-" + key, "iam", "delete_role", {"RoleName": role}, required=False)
            result = self.call("absence-" + key, "iam", "get_role", {"RoleName": role}, required=False)
            outcomes.append(result["code"] == "NoSuchEntity")
            self.data["cleanup"][key] = {"absent": outcomes[-1]}
        self.data["cleanup"]["complete"] = all(outcomes)
        self.save()
        if not all(outcomes):
            raise RuntimeError("Owned v2 integration credentials cleanup incomplete")


def policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def control(p, protocol, label, method, **parameters):
    return p.call(protocol.lower() + "-" + label, "apigatewayv2", method,
                  {"ApiId": p.data["apis"][protocol]["id"], **parameters}, required=False)


def integration_input(p, protocol):
    function = p.data["function_arn"]
    uri = function if protocol == "HTTP" else f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function}/invocations"
    result = {"IntegrationType": "AWS_PROXY", "IntegrationMethod": "POST", "IntegrationUri": uri}
    if protocol == "HTTP":
        result["PayloadFormatVersion"] = "2.0"
    return result


def require(result):
    if result["code"] != "Success":
        raise RuntimeError("Required control failed: " + str(result))
    return result["output"]


def deploy(p, protocol, label, first=False):
    p.phase = "deployment"
    deployment = require(control(p, protocol, label + "-create-deployment", "create_deployment", Description=label))
    values = {"StageName": "probe", "DeploymentId": deployment["DeploymentId"],
              "StageVariables": {"deploymentMarker": label}}
    if first:
        values["AutoDeploy"] = False
    require(control(p, protocol, label + "-stage", "create_stage" if first else "update_stage", **values))
    require(control(p, protocol, label + "-get-stage", "get_stage", StageName="probe"))
    require(control(p, protocol, label + "-get-deployment", "get_deployment", DeploymentId=deployment["DeploymentId"]))
    p.data["apis"][protocol]["deployments"][label] = deployment["DeploymentId"]
    p.save()


def readiness(p, label, probe, expected=True, attempts=24, consecutive=3):
    p.phase = "readiness"
    row = {"label": label, "started_at": now(), "max_attempts": attempts,
           "interval_seconds": 5, "consecutive_required": consecutive, "expected_backend_success": expected,
           "samples": []}
    p.data["readiness"].append(row)
    matches = 0
    for attempt in range(attempts):
        actual = probe("readiness-" + label + "-" + str(attempt))
        row["samples"].append({"at": now(), "backend_success": actual})
        matches = matches + 1 if actual == expected else 0
        if matches >= consecutive:
            row.update(converged=True, finished_at=now())
            p.save()
            return True
        p.save()
        if attempt + 1 < attempts:
            time.sleep(5)
    row.update(converged=False, finished_at=now())
    p.data["uncertainties"].append(label + ": bounded runtime convergence not established")
    p.save()
    return False


def connect_sample(p, label, phase="semantic", keep=False):
    result = p.connect(label, phase=phase)
    p.data["scenarios"].append({"label": label, "phase": phase, "protocol": "WEBSOCKET", "surface": "connect",
        "marker": p.data["connections"][label]["marker"], "result": result,
        "backend_success": result.get("status") == 101})
    if not keep:
        p.close(label, label + "-close")
    p.save()
    return result.get("status") == 101 if result.get("status") in (101, 500) else None


def set_active(p, protocol, label, credentials):
    p.phase = "semantic-control"
    integration = p.data["apis"][protocol]["integrations"]["active"]
    result = control(p, protocol, label + "-update", "update_integration", IntegrationId=integration, CredentialsArn=credentials)
    control(p, protocol, label + "-get", "get_integration", IntegrationId=integration)
    return result


def passrole(p, roles):
    resources = []
    for api in p.data["apis"].values():
        scope = f"arn:aws:apigateway:{REGION}::/apis/{api['id']}/integrations"
        resources.extend((scope, scope + "/*"))
    api_access = {"Effect": "Allow", "Action": ["apigateway:GET", "apigateway:POST", "apigateway:PATCH", "apigateway:DELETE"], "Resource": resources}
    pass_access = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": roles["allow"]["Arn"],
                   "Condition": {"StringEquals": {"iam:PassedToService": "apigateway.amazonaws.com"}}}
    p.required("actor-policy", "iam", "put_role_policy", {"RoleName": roles["actor"]["RoleName"],
        "PolicyName": "probe-authority", "PolicyDocument": policy(api_access, pass_access)})
    for mode in ("missing", "deny", "allow"):
        statements = [api_access]
        if mode != "missing":
            statements.append(pass_access)
        if mode == "deny":
            statements.append({"Effect": "Deny", "Action": "iam:PassRole", "Resource": roles["allow"]["Arn"]})
        assumed = None
        p.phase = "readiness"
        for attempt in range(24):
            result = p.call(f"actor-assume-{mode}-{attempt}", "sts", "assume_role", {
                "RoleArn": roles["actor"]["Arn"], "RoleSessionName": "v2-integration-" + mode,
                "DurationSeconds": 900, "Policy": policy(*statements)}, required=False)
            if result["code"] == "Success":
                assumed = result["output"]
                break
            time.sleep(5)
        if assumed is None:
            p.data["uncertainties"].append("PassRole actor STS bound: " + mode)
            continue
        credentials = assumed["Credentials"]
        session = boto3.Session(region_name=REGION, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        client = session.client("apigatewayv2", config=p.client("apigatewayv2").meta.config)
        actor = assumed["AssumedRoleUser"]
        p.data["actors"][mode] = {"identity": actor, "session_policy": json.loads(policy(*statements))}
        try:
            for protocol, api in p.data["apis"].items():
                common = {"ApiId": api["id"], **integration_input(p, protocol)}
                created = None
                p.phase = "readiness"
                for attempt in range(24):
                    result = scoped_role_call(p, client, actor, f"{protocol}-actor-api-{mode}-{attempt}", "create_integration", common)
                    if result["code"] == "Success":
                        created = result["output"]
                        break
                    time.sleep(5)
                if created is None:
                    p.data["uncertainties"].append(protocol + " PassRole API readiness bound: " + mode)
                    continue
                p.phase = "semantic-control"
                with_role = scoped_role_call(p, client, actor, f"{protocol}-passrole-{mode}-create", "create_integration",
                    {**common, "CredentialsArn": roles["allow"]["Arn"]})
                if with_role["code"] == "Success":
                    scoped_role_call(p, client, actor, f"{protocol}-passrole-{mode}-delete-created", "delete_integration",
                        {"ApiId": api["id"], "IntegrationId": with_role["output"]["IntegrationId"]})
                target = {"ApiId": api["id"], "IntegrationId": created["IntegrationId"]}
                scoped_role_call(p, client, actor, f"{protocol}-passrole-{mode}-update", "update_integration", {**target, "CredentialsArn": roles["allow"]["Arn"]})
                scoped_role_call(p, client, actor, f"{protocol}-passrole-{mode}-get", "get_integration", target)
                p.call(f"{protocol}-passrole-{mode}-owner-get", "apigatewayv2", "get_integration", target)
                scoped_role_call(p, client, actor, f"{protocol}-passrole-{mode}-delete", "delete_integration", target)
        finally:
            client.close()


def run(p):
    p.data.update(scope="Owned HTTP and WebSocket Lambda integration credentials; no authorizers, account settings, or preexisting resources",
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        documentation=["https://docs.aws.amazon.com/apigateway/latest/api/API_PutIntegration.html",
            "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-integrations.html"],
        apis={}, actors={}, readiness=[], scenarios=[], connections={}, websocket_observations=[],
        expected_invocation_markers=[], uncertainties=[], log_start_ms=int(time.time() * 1000),
        bounds={"apis": 2, "functions": 1, "roles": 6, "readiness_attempts": 24, "readiness_interval_seconds": 5,
                "log_attempts": 24, "log_pages_per_attempt": 4, "cleanup_attempts": 3},
        limitations=["No STS audit: session duration/name and hidden service trust context are not inferred from failures.",
            "Three matching runtime samples bound local convergence, not global propagation.",
            "No matching marker in bounded function logs is observed absence, not guaranteed absence.",
            "WebSocket messages use held real sockets; no CUSTOM authorizer is configured."])
    p.save()
    function, _ = create_function(p, HANDLER)
    p.data["function_arn"] = function["FunctionArn"]
    roles = {}
    for key in ("allow", "replacement", "deny", "untrusted", "actor"):
        principal = {"AWS": p.data["identity"]["Arn"]} if key == "actor" else {"Service": "lambda.amazonaws.com" if key == "untrusted" else "apigateway.amazonaws.com"}
        role = p.required("create-" + key + "-role", "iam", "create_role", {
            "RoleName": p.data["prefix"] + "-" + key, "AssumeRolePolicyDocument": role_trust(principal)},
            own=("credential_role_" + key, "Role.RoleName"))["Role"]
        roles[key] = role
        if key != "actor":
            statements = [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]}]
            if key == "deny":
                statements.append({"Effect": "Deny", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]})
            p.required("policy-" + key, "iam", "put_role_policy", {"RoleName": role["RoleName"],
                "PolicyName": "probe-authority", "PolicyDocument": policy(*statements)})
    p.data["roles"] = roles
    p.call("function-policy-initially-absent", "lambda", "get_policy", {"FunctionName": function["FunctionName"]}, required=False)
    for protocol in ("HTTP", "WEBSOCKET"):
        values = {"Name": p.data["prefix"] + "-" + protocol.lower(), "ProtocolType": protocol}
        if protocol == "WEBSOCKET":
            values["RouteSelectionExpression"] = "$request.body.action"
        key = "plain_http_api" if protocol == "HTTP" else "http_api"
        api = p.required("create-" + protocol.lower() + "-api", "apigatewayv2", "create_api", values, own=(key, "ApiId"))
        p.data["owned"]["plain_http_endpoint" if protocol == "HTTP" else "websocket_endpoint"] = api["ApiEndpoint"]
        p.data["apis"][protocol] = {"id": api["ApiId"], "integrations": {}, "routes": {}, "deployments": {}}
        credentials = {"active": roles["allow"]["Arn"], "allow": roles["allow"]["Arn"], "deny": roles["deny"]["Arn"],
            "untrusted": roles["untrusted"]["Arn"], "omitted": None, "empty": "", "sentinel": SENTINEL,
            "malformed": "not-an-arn", "missing-role": f"arn:aws:iam::{p.data['account']}:role/{p.data['prefix']}-not-created"}
        p.phase = "semantic-control"
        for name, value in credentials.items():
            inputs = integration_input(p, protocol)
            if value is not None:
                inputs["CredentialsArn"] = value
            result = control(p, protocol, "create-" + name, "create_integration", **inputs)
            if result["code"] != "Success":
                continue
            integration = result["output"]["IntegrationId"]
            p.data["apis"][protocol]["integrations"][name] = integration
            control(p, protocol, "get-" + name, "get_integration", IntegrationId=integration)
            route = require(control(p, protocol, "route-" + name, "create_route",
                RouteKey="GET /" + name if protocol == "HTTP" else name,
                AuthorizationType="NONE", Target="integrations/" + integration,
                **({"RouteResponseSelectionExpression": "$default"} if protocol == "WEBSOCKET" else {})))
            p.data["apis"][protocol]["routes"][name] = route["RouteId"]
            if protocol == "WEBSOCKET":
                require(control(p, protocol, "response-" + name, "create_route_response", RouteId=route["RouteId"], RouteResponseKey="$default"))
        active = p.data["apis"][protocol]["integrations"]["active"]
        control(p, protocol, "update-omitted-keeps-role", "update_integration", IntegrationId=active, Description="credentials omitted")
        control(p, protocol, "get-after-omitted-update", "get_integration", IntegrationId=active)
        control(p, protocol, "update-malformed", "update_integration", IntegrationId=active, CredentialsArn="not-an-arn")
        control(p, protocol, "get-after-rejected-update", "get_integration", IntegrationId=active)
        admission = p.data["apis"][protocol]["integrations"]["omitted"]
        for label, value in (("sentinel", SENTINEL), ("empty", "")):
            control(p, protocol, "update-admission-" + label, "update_integration",
                    IntegrationId=admission, CredentialsArn=value)
            control(p, protocol, "get-admission-" + label, "get_integration", IntegrationId=admission)
        if protocol == "WEBSOCKET":
            route = require(control(p, protocol, "route-connect", "create_route", RouteKey="$connect", AuthorizationType="NONE", Target="integrations/" + active))
            p.data["apis"][protocol]["routes"]["$connect"] = route["RouteId"]
        deploy(p, protocol, "initial", first=True)
    if not readiness(p, "http-initial", lambda label: p.request(label, phase="readiness")):
        raise RuntimeError("HTTP role invocation did not become ready")
    if not readiness(p, "ws-initial", lambda label: connect_sample(p, label, "readiness")):
        raise RuntimeError("WebSocket role invocation did not become ready")
    if not connect_sample(p, "held", keep=True):
        raise RuntimeError("Could not retain initial positive socket")
    p.phase = "semantic-execution"
    for route in p.data["apis"]["HTTP"]["integrations"]:
        p.request("http-initial-" + route, route)
    for route in p.data["apis"]["WEBSOCKET"]["integrations"]:
        p.application("held", "ws-initial-" + route, route)
    if "sentinel" in p.data["apis"]["HTTP"]["integrations"]:
        p.request("http-sentinel-signed-no-resource-policy", "sentinel", authorization="iam")
    p.call("function-policy-after-role-success-absent", "lambda", "get_policy", {"FunctionName": function["FunctionName"]}, required=False)

    for protocol in p.data["apis"]:
        require(set_active(p, protocol, "replace-with-deny", roles["deny"]["Arn"]))
    p.request("http-deny-control-not-deployed")
    p.application("held", "ws-deny-control-not-deployed")
    connect_sample(p, "ws-deny-control-not-deployed-connect")
    for protocol in p.data["apis"]:
        deploy(p, protocol, "deny-deployed")
    readiness(p, "http-deny-deployed", lambda label: p.request(label, phase="readiness"), expected=False)
    readiness(p, "ws-deny-deployed-connect", lambda label: connect_sample(p, label, "readiness"), expected=False)
    readiness(p, "ws-deny-deployed-held", lambda label: p.application("held", label, phase="readiness"), expected=False)
    p.request("http-deny-deployed-semantic")
    p.application("held", "ws-deny-deployed-held-semantic")
    connect_sample(p, "ws-deny-deployed-connect-semantic")
    p.application("held", "ws-other-allow-route-still-works", "allow")

    for protocol in p.data["apis"]:
        require(set_active(p, protocol, "replace-with-allow", roles["replacement"]["Arn"]))
    p.request("http-recovery-control-not-deployed")
    p.application("held", "ws-recovery-control-not-deployed")
    for protocol in p.data["apis"]:
        deploy(p, protocol, "replacement-deployed")
    readiness(p, "http-replacement", lambda label: p.request(label, phase="readiness"))
    readiness(p, "ws-replacement-connect", lambda label: connect_sample(p, label, "readiness"))
    readiness(p, "ws-replacement-held", lambda label: p.application("held", label, phase="readiness"))

    for protocol in p.data["apis"]:
        require(set_active(p, protocol, "remove-with-empty", ""))
    p.request("http-removal-control-not-deployed")
    p.application("held", "ws-removal-control-not-deployed")
    for protocol in p.data["apis"]:
        deploy(p, protocol, "removed-deployed")
    readiness(p, "http-removed-no-policy", lambda label: p.request(label, phase="readiness"), expected=False)
    readiness(p, "ws-removed-no-policy-connect", lambda label: connect_sample(p, label, "readiness"), expected=False)
    readiness(p, "ws-removed-no-policy-held", lambda label: p.application("held", label, phase="readiness"), expected=False)

    p.phase = "semantic-control"
    p.required("recover-untrusted-role", "iam", "update_assume_role_policy", {"RoleName": roles["untrusted"]["RoleName"],
        "PolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"})})
    p.required("get-recovered-role", "iam", "get_role", {"RoleName": roles["untrusted"]["RoleName"]})
    readiness(p, "http-untrusted-recovery", lambda label: p.request(label, "untrusted", phase="readiness"))
    readiness(p, "ws-untrusted-recovery", lambda label: p.application("held", label, "untrusted", phase="readiness"))
    p.request("http-untrusted-recovered", "untrusted")
    p.application("held", "ws-untrusted-recovered", "untrusted")

    for protocol, api in p.data["apis"].items():
        p.required("add-resource-permission-" + protocol, "lambda", "add_permission", {
            "FunctionName": function["FunctionName"], "StatementId": protocol.lower(), "Action": "lambda:InvokeFunction",
            "Principal": "apigateway.amazonaws.com", "SourceAccount": p.data["account"],
            "SourceArn": f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api['id']}/*"})
    p.required("function-resource-policy", "lambda", "get_policy", {"FunctionName": function["FunctionName"]})
    readiness(p, "http-resource-policy-recovery", lambda label: p.request(label, phase="readiness"))
    readiness(p, "ws-resource-policy-connect", lambda label: connect_sample(p, label, "readiness"))
    readiness(p, "ws-resource-policy-held", lambda label: p.application("held", label, phase="readiness"))
    for route in ("active", "omitted", "empty", "deny", "sentinel"):
        if route in p.data["apis"]["HTTP"]["integrations"]:
            p.request("http-resource-policy-" + route, route)
        if route in p.data["apis"]["WEBSOCKET"]["integrations"]:
            p.application("held", "ws-resource-policy-" + route, route)
    if "sentinel" in p.data["apis"]["HTTP"]["integrations"]:
        p.request("http-sentinel-signed-with-resource-policy", "sentinel", authorization="iam")
    passrole(p, roles)
    p.data["completed_at"] = now()
    p.save()


def run_trust_context(p):
    condition = {"Null": {"aws:SourceArn": "true", "aws:SourceAccount": "true"},
                 "StringEquals": {"aws:PrincipalType": "AssumedRole"}}
    p.data.update(scope="Fresh v2 integration trust-context comparison; independent HTTP, WebSocket connect and message roles",
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        documentation=["https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-integrations.html"],
        apis={}, actors={}, readiness=[], scenarios=[], connections={}, websocket_observations=[],
        expected_invocation_markers=[], uncertainties=[], log_start_ms=int(time.time() * 1000),
        bounds={"apis": 3, "functions": 1, "roles": 5, "readiness_attempts": 24,
                "readiness_interval_seconds": 5, "cleanup_attempts": 3},
        trust_condition=condition, context_results={},
        limitations=["A positive conjunction establishes these three tested conditions, not other STS context values.",
                     "A failed conjunction alone cannot identify which condition failed; unconditional repair is a control.",
                     "Fresh distinct roles avoid HTTP or connect priming another execution surface's role session."])
    p.save()
    function, _ = create_function(p, HANDLER)
    p.data["function_arn"] = function["FunctionArn"]
    roles = {}
    for key in ("baseline", "http-context", "ws-connect-context", "ws-message-context"):
        role = p.required("create-" + key + "-role", "iam", "create_role", {
            "RoleName": p.data["prefix"] + "-" + key,
            "AssumeRolePolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"},
                                                  None if key == "baseline" else condition)},
            own=("credential_role_" + key, "Role.RoleName"))["Role"]
        roles[key] = role
        p.required("invoke-policy-" + key, "iam", "put_role_policy", {"RoleName": role["RoleName"],
            "PolicyName": "probe-authority", "PolicyDocument": policy({
                "Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]})})
    p.data["roles"] = roles
    p.call("context-function-policy-absent-before", "lambda", "get_policy",
           {"FunctionName": function["FunctionName"]}, required=False)
    for protocol in ("HTTP", "WEBSOCKET", "WEBSOCKET_BASELINE"):
        wire_protocol = "HTTP" if protocol == "HTTP" else "WEBSOCKET"
        values = {"Name": p.data["prefix"] + "-" + protocol.lower(), "ProtocolType": wire_protocol}
        if wire_protocol == "WEBSOCKET":
            values["RouteSelectionExpression"] = "$request.body.action"
        api_key, endpoint_key = {
            "HTTP": ("plain_http_api", "plain_http_endpoint"),
            "WEBSOCKET": ("http_api", "websocket_endpoint"),
            "WEBSOCKET_BASELINE": ("baseline_websocket_api", "baseline_websocket_endpoint")}[protocol]
        api = p.required("create-context-" + protocol.lower(), "apigatewayv2", "create_api", values,
                         own=(api_key, "ApiId"))
        p.data["owned"][endpoint_key] = api["ApiEndpoint"]
        p.data["apis"][protocol] = {"id": api["ApiId"], "integrations": {}, "routes": {}, "deployments": {}}
        choices = {"allow": "baseline"}
        if protocol == "HTTP":
            choices["context"] = "http-context"
        elif protocol == "WEBSOCKET":
            choices.update({"context": "ws-message-context", "connect-context": "ws-connect-context"})
        for name, role_key in choices.items():
            integration = require(control(p, protocol, "context-integration-" + name, "create_integration",
                **integration_input(p, protocol), CredentialsArn=roles[role_key]["Arn"]))["IntegrationId"]
            p.data["apis"][protocol]["integrations"][name] = integration
            if name == "connect-context":
                continue
            route = require(control(p, protocol, "context-route-" + name, "create_route",
                RouteKey="GET /" + name if protocol == "HTTP" else name,
                AuthorizationType="NONE", Target="integrations/" + integration,
                **({"RouteResponseSelectionExpression": "$default"} if wire_protocol == "WEBSOCKET" else {})))
            p.data["apis"][protocol]["routes"][name] = route["RouteId"]
            if wire_protocol == "WEBSOCKET":
                require(control(p, protocol, "context-response-" + name, "create_route_response",
                                RouteId=route["RouteId"], RouteResponseKey="$default"))
        if wire_protocol == "WEBSOCKET":
            connect_key = "connect-context" if protocol == "WEBSOCKET" else "allow"
            route = require(control(p, protocol, "context-connect-route", "create_route",
                RouteKey="$connect", AuthorizationType="NONE",
                Target="integrations/" + p.data["apis"][protocol]["integrations"][connect_key]))
            p.data["apis"][protocol]["routes"]["$connect"] = route["RouteId"]
        deploy(p, protocol, "context-initial", first=True)
    if not readiness(p, "context-http-baseline", lambda label: p.request(label, "allow", phase="readiness")):
        raise RuntimeError("Unconditional HTTP comparison did not become ready")
    def baseline_connect(label):
        endpoint = p.data["owned"]["websocket_endpoint"]
        p.data["owned"]["websocket_endpoint"] = p.data["owned"]["baseline_websocket_endpoint"]
        try:
            return connect_sample(p, label, "readiness")
        finally:
            p.data["owned"]["websocket_endpoint"] = endpoint

    if not readiness(p, "context-ws-baseline-connect", baseline_connect):
        raise RuntimeError("Unconditional WebSocket comparison did not become ready")
    checks = [
        ("http-context", lambda label: p.request(label, "context", phase="readiness")),
        ("ws-connect-context", lambda label: connect_sample(p, label, "readiness"))]
    for role_key, callback in checks:
        positive = readiness(p, role_key, callback)
        p.data["context_results"][role_key] = {"conditional_positive": positive}
        if not positive:
            p.required("repair-" + role_key, "iam", "update_assume_role_policy", {
                "RoleName": roles[role_key]["RoleName"],
                "PolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"})})
            p.data["context_results"][role_key]["unconditional_repair_positive"] = readiness(p, role_key + "-repair", callback)
    if not connect_sample(p, "context-held", keep=True):
        raise RuntimeError("Could not retain context comparison socket after conditional trust or repair")
    p.request("context-http-baseline-semantic", "allow")
    p.application("context-held", "context-ws-baseline-message", "allow")
    callback = lambda label: p.application("context-held", label, "context", phase="readiness")
    positive = readiness(p, "ws-message-context", callback)
    p.data["context_results"]["ws-message-context"] = {"conditional_positive": positive}
    if not positive:
        p.required("repair-ws-message-context", "iam", "update_assume_role_policy", {
            "RoleName": roles["ws-message-context"]["RoleName"],
            "PolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"})})
        p.data["context_results"]["ws-message-context"]["unconditional_repair_positive"] = readiness(
            p, "ws-message-context-repair", callback)
    p.request("context-http-conditional-semantic", "context")
    p.application("context-held", "context-ws-message-conditional-semantic", "context")
    connect_sample(p, "context-ws-fresh-conditional-semantic")
    p.call("context-function-policy-absent-after", "lambda", "get_policy",
           {"FunctionName": function["FunctionName"]}, required=False)
    p.data["completed_at"] = now()
    p.save()


def collect_logs(p):
    if "function" not in p.data["owned"]:
        return
    collected, previous = {}, None
    for attempt in range(24):
        token = None
        complete = True
        for page in range(4):
            parameters = {"logGroupName": "/aws/lambda/" + p.data["owned"]["function"], "startTime": p.data["log_start_ms"], "limit": 1000}
            if token:
                parameters["nextToken"] = token
            result = p.call(f"logs-{attempt}-{page}", "logs", "filter_log_events", parameters, required=False)
            if result["code"] != "Success":
                complete = False
                break
            for event in result["output"].get("events", []):
                collected[event["eventId"]] = event
            next_token = result["output"].get("nextToken")
            if not next_token or next_token == token:
                token = None
                break
            token = next_token
        records = []
        for event in sorted(collected.values(), key=lambda item: (item["timestamp"], item["eventId"])):
            try:
                value = json.loads(event["message"])
            except ValueError:
                continue
            if value.get("probe_kind") == "v2-integration-credentials":
                records.append({"timestamp": event["timestamp"], "event_id": event["eventId"], "log_stream": event["logStreamName"], "record": value})
        p.data["invocation_logs"] = records
        seen = {item["record"].get("marker") for item in records}
        missing = sorted(set(p.data["expected_invocation_markers"]) - seen)
        current = sorted(collected)
        stable = complete and not token and current == previous
        p.data["log_collection"] = {"attempts": attempt + 1, "missing_expected_markers": missing,
            "stable": stable, "pagination_bound_hit": bool(token), "finished_at": now()}
        for scenario in p.data["scenarios"]:
            matches = [item for item in records if item["record"].get("marker") == scenario["marker"]]
            scenario["invocation_ids"] = [item["record"]["invocation_id"] for item in matches]
            scenario["observed_backend_invocations"] = len(matches)
        p.data["summary"] = {
            "protocols": list(p.data["apis"]),
            "correlated_lambda_invocations": len(records),
            "semantic_cases": [
                {"label": item["label"], "protocol": item["protocol"], "surface": item["surface"],
                 "status": item["result"].get("status"), "backend_success": item["backend_success"],
                 "observed_backend_invocations": item["observed_backend_invocations"]}
                for item in p.data["scenarios"] if item["phase"] == "semantic"],
            "caller_sentinel_admission": [
                {"label": item["label"], "result": item["result"]}
                for item in p.data["observations"]
                if item["label"].endswith(("create-sentinel", "update-admission-sentinel"))],
            "bounded_readiness": [
                {"label": item["label"], "converged": item["converged"],
                 "samples": len(item["samples"])}
                for item in p.data["readiness"]],
            "no_claims": ["STS role session identity/duration and hidden trust context were not measured.",
                          "Caller-identity forwarding is not executable when the sentinel is rejected.",
                          "Readiness samples are propagation evidence, not additional semantic cases."]}
        p.save()
        if stable and not missing and attempt >= 2:
            return
        previous = current if complete and not token else None
        time.sleep(3)
    raise RuntimeError("Owned Lambda log evidence did not stabilize within bound")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/v2_integration_credentials.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--append-capture", action="store_true",
                        help="Preserve a completely cleaned run and execute a fresh owned capture")
    parser.add_argument("--trust-context-capture", action="store_true",
                        help="Attach a fresh role trust-context comparison to a cleaned primary capture")
    args = parser.parse_args()
    if args.append_capture and (args.cleanup_only or args.trust_context_capture):
        parser.error("--append-capture cannot combine with cleanup or a trust context capture")
    p = IntegrationProbe(args.output, args.account,
                         args.cleanup_only or args.append_capture or args.trust_context_capture)
    if args.append_capture or args.trust_context_capture:
        previous = p.data
        if args.trust_context_capture and args.cleanup_only:
            p.envelope = previous
            p.data = previous["trust_context_capture"]
        else:
            if not previous.get("cleanup", {}).get("complete"):
                raise RuntimeError("Cannot append before all previously owned resources are absent")
            if args.trust_context_capture and "trust_context_capture" in previous:
                raise RuntimeError("Refusing to overwrite trust context evidence")
            p.data = {"service": "apigateway", "account": args.account, "region": REGION,
                "identity": previous["identity"], "captured_at": now(),
                "prefix": "stackd-apigw-" + uuid.uuid4().hex[:10], "owned": {}, "observations": [],
                "http": [], "tokens": {}, "cleanup": {}, "sdk": previous["sdk"]}
            if args.trust_context_capture:
                p.envelope = previous
            else:
                earlier = previous.pop("prior_captures", [])
                p.data["prior_captures"] = earlier + [previous]
    try:
        if not args.cleanup_only:
            if args.trust_context_capture:
                run_trust_context(p)
            else:
                run(p)
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
                    p.phase = "log-collection"
                    collect_logs(p)
                except Exception as error:
                    p.data["log_collection_error"] = {"type": type(error).__name__, "message": str(error)}
                    p.save()
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
    if p.data.get("log_collection_error"):
        raise RuntimeError("Native log evidence incomplete; owned resources cleaned")


if __name__ == "__main__":
    main()
