#!/usr/bin/env python3
"""Capture one owned native HTTP API's real REQUEST Lambda authorizers and remove it."""
import argparse
import base64
import io
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
import zipfile

from botocore.config import Config

import apigateway_probe
from apigateway_probe import Probe, REGION, now

HANDLER = '''import json
import uuid


def handler(event, context):
    if event.get("type") != "REQUEST":
        print(json.dumps({"probe_kind": "backend", "event": event}))
        return {"statusCode": 200, "headers": {"content-type": "application/json"},
                "body": json.dumps({"event": event})}
    headers = {key.lower(): value for key, value in event.get("headers", {}).items()}
    mode = headers.get("x-mode", "policy-allow")
    invocation = str(uuid.uuid4())
    values = {"invocationUUID": invocation, "lambdaRequestId": context.aws_request_id,
              "eventJSON": json.dumps(event, separators=(",", ":")),
              "stringValue": "probe-value", "numberValue": 7, "booleanValue": True,
              "emptyValue": ""}
    if "nested" in mode:
        values.update(arrayValue=["one", 2, False], mapValue={"inner": "value"}, nullValue=None)
    if "claims" in mode:
        values["claims"] = {"sub": "probe-subject"}
    if mode == "unauthorized-raise":
        print(json.dumps({"probe_kind": "authorizer", "invocationUUID": invocation,
                          "event": event, "raises": "Unauthorized"}))
        raise Exception("Unauthorized")
    if mode == "unauthorized-return":
        response = {"errorMessage": "Unauthorized"}
    elif mode == "invalid":
        response = {"unexpected": "not-an-authorizer-response", "context": values}
    elif mode == "simple-string":
        response = {"isAuthorized": "true", "context": values}
    elif mode.startswith("simple"):
        allowed = "deny" not in mode
        if mode == "simple-route-a":
            allowed = event.get("rawPath", "").endswith("/a")
        response = {"isAuthorized": allowed, "context": values}
    else:
        resource = event.get("routeArn", event.get("methodArn"))
        response = {"principalId": "probe-principal", "policyDocument": {
            "Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke",
                "Effect": "Deny" if "deny" in mode else "Allow", "Resource": resource}]},
            "context": values}
    print(json.dumps({"probe_kind": "authorizer", "invocationUUID": invocation,
                      "event": event, "response": response}))
    return response
'''


def request(p, label, path, *, token="probe-literal", mode="policy-allow", headers=None):
    sent = {"User-Agent": "stackd-native-http-authorizer-probe", "X-Probe": label, "X-Mode": mode}
    if token is not None:
        sent["Authorization"] = token
    sent.update(headers or {})
    started = now()
    req = urllib.request.Request(p.data["owned"]["http_endpoint"] + path, headers=sent, method="GET")
    try:
        response = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    except urllib.error.URLError as error:
        result = {"transport_error": str(error.reason)}
        response = None
    if response is not None:
        with response:
            body = response.read(1 << 20)
            result = {"status": response.status, "headers": list(response.headers.items())}
            try:
                result["body"] = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                result["body_base64"] = base64.b64encode(body).decode()
    p.data["http"].append({"label": label, "api": "http", "path": path, "method": "GET",
        "request_headers": sent, "started_at": started, "finished_at": now(), "result": result})
    if p.data.get("mode") in ("credentials-roles", "service-context", "principal-types"):
        p.data["http"][-1]["phase"] = "readiness" if label.startswith(("ready-", "iam-ready-")) else "semantic"
        p.data["http"][-1]["actor"] = "unsigned HTTP caller; literal probe Authorization header"
    p.save()
    print(label + ": " + str(result.get("status", "transport error")), flush=True)
    return result


def deploy(p, phase, integration):
    api = p.data["owned"]["http_api"]
    path = "/ready-" + phase
    p.required("ready-route-" + phase, "apigatewayv2", "create_route", {"ApiId": api,
        "RouteKey": "GET " + path, "AuthorizationType": "NONE", "Target": "integrations/" + integration})
    deployment = p.required("deploy-" + phase, "apigatewayv2", "create_deployment", {"ApiId": api})
    p.required("select-deployment-" + phase, "apigatewayv2", "update_stage", {"ApiId": api,
        "StageName": "$default", "DeploymentId": deployment["DeploymentId"]})
    for attempt in range(15):
        result = request(p, "ready-" + phase + "-" + str(attempt), path, token=None)
        if result.get("status") == 200:
            return
        time.sleep(2)
    raise RuntimeError("Owned deployment did not become ready within 15 attempts")


def create_function(p, role):
    name = p.data["prefix"]
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        output.writestr("index.py", HANDLER)
    for attempt in range(15):
        result = p.call("create-function-" + str(attempt), "lambda", "create_function", {
            "FunctionName": name, "Role": role, "Runtime": "python3.13", "Handler": "index.handler",
            "MemorySize": 128, "Timeout": 5, "Code": {"ZipFile": archive.getvalue()}},
            own=("function", "FunctionName"), required=False)
        if result["code"] == "Success":
            function = result["output"]
            break
        if result["code"] != "InvalidParameterValueException" or result["error"]["Message"] != "The role defined for the function cannot be assumed by Lambda.":
            raise RuntimeError("Native Lambda creation failed: " + result["code"])
        time.sleep(2)
    else:
        raise RuntimeError("Native Lambda role propagation bound reached")
    for attempt in range(15):
        current = p.required("function-ready-" + str(attempt), "lambda", "get_function_configuration", {"FunctionName": name})
        if current["State"] == "Active":
            return function["FunctionArn"]
        if current["State"] == "Failed":
            raise RuntimeError("Native Lambda activation failed")
        time.sleep(2)
    raise RuntimeError("Native Lambda activation bound reached")


def collect_logs(p):
    if "function" not in p.data["owned"]:
        return
    group = "/aws/lambda/" + p.data["owned"]["function"]
    events = {}
    # The final uncached request is a positive marker, not an assertion of synchronous logging.
    for attempt in range(12):
        token = None
        for page in range(10):
            parameters = {"logGroupName": group, "filterPattern": '"probe_kind"', "limit": 1000}
            if token:
                parameters["nextToken"] = token
            result = p.call("lambda-logs-" + str(attempt) + "-" + str(page), "logs", "filter_log_events", parameters, required=False)
            if result["code"] != "Success":
                break
            for item in result["output"]["events"]:
                events[item["eventId"]] = item
            following = result["output"].get("nextToken")
            if not following or following == token:
                break
            token = following
        decoded = []
        for item in sorted(events.values(), key=lambda value: (value["timestamp"], value["eventId"])):
            try:
                value = json.loads(item["message"])
            except ValueError:
                continue
            if value.get("probe_kind") == "authorizer":
                decoded.append({"timestamp": item["timestamp"], "event_id": item["eventId"], **value})
        p.data["authorizer_invocations"] = decoded
        p.data["log_evidence"] = {"attempts": attempt + 1, "events": len(events),
            "complete_marker_seen": any(item["event"].get("headers", {}).get("x-probe") == "logs-final-marker" for item in decoded),
            "absence_caveat": "No matching invocation means absent in this bounded log collection, not an account-wide audit."}
        p.save()
        if p.data["log_evidence"]["complete_marker_seen"] and attempt >= 2:
            return
        time.sleep(3)


def run(p):
    name, account = p.data["prefix"], p.data["account"]
    p.data.update(scope="One owned HTTP API with REQUEST Lambda authorizers; no account-level settings",
        bounds={"apis": 1, "functions": 1, "roles": 1, "function_log_groups": 1,
            "readiness_attempts": 15, "readiness_interval_seconds": 2, "sdk_total_max_attempts": 1,
            "http_timeout_seconds": 30, "log_attempts": 12, "log_pages_per_attempt": 10,
            "log_interval_seconds": 3, "cleanup_attempts": 3, "cache_ttl_seconds": [0, 2, 60]},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html",
            "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-authorizers.html",
            "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-stages-stagename-cache-authorizers.html"],
        probe_source=Path(__file__).read_text(), base_helper_source=Path(apigateway_probe.__file__).read_text(),
        handler_source=HANDLER, authorizers={}, unsampled_boundaries=[
            "WebSocket protocol (one HTTP API only)", "AuthorizerCredentialsArn role assumption",
            "Cross-account Lambda authorizers", "Concurrent cache fills and regional cache convergence",
            "Stage-variable identities and multiple stages", "Custom domains and client certificates",
            "Policy wildcards, NotAction/NotResource, conditions, multiple statements, and size limits"])
    # Let native HTTP API validation, rather than botocore's min-value check, answer rejection probes.
    original = p.client("apigatewayv2")
    config = original.meta.config.merge(Config(parameter_validation=False))
    original.close()
    p.clients["apigatewayv2"] = p.session.client("apigatewayv2", config=config)
    p.data["sdk"]["apigatewayv2_parameter_validation"] = False
    model = p.client("apigatewayv2").meta.service_model
    p.data["modeled_inputs"] = {operation: {"required": model.operation_model(operation).input_shape.required_members,
        "members": {key: {"type": shape.type_name, "metadata": shape.metadata}
                    for key, shape in model.operation_model(operation).input_shape.members.items()}}
        for operation in ("CreateAuthorizer", "UpdateAuthorizer", "CreateRoute", "ResetAuthorizersCache")}
    p.save()
    role = p.required("create-role", "iam", "create_role", {"RoleName": name,
        "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}, own=("role", "Role.RoleName"))["Role"]
    p.required("role-logs", "iam", "put_role_policy", {"RoleName": name, "PolicyName": "probe-logs",
        "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"arn:aws:logs:{REGION}:{account}:log-group:/aws/lambda/{name}:*"}]})})
    function = create_function(p, role["Arn"])
    api = p.required("create-http", "apigatewayv2", "create_api", {"Name": name, "ProtocolType": "HTTP"}, own=("http_api", "ApiId"))
    p.data["owned"]["http_endpoint"] = api["ApiEndpoint"]
    api = api["ApiId"]
    source = f"arn:aws:execute-api:{REGION}:{account}:{api}"
    p.required("permission-integration-only", "lambda", "add_permission", {"FunctionName": name, "StatementId": "integration",
        "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com", "SourceAccount": account,
        "SourceArn": source + "/*/GET/*"})
    integration = p.required("integration", "apigatewayv2", "create_integration", {"ApiId": api,
        "IntegrationType": "AWS_PROXY", "IntegrationUri": function, "PayloadFormatVersion": "2.0"})["IntegrationId"]
    common = {"ApiId": api, "AuthorizerType": "REQUEST",
        "AuthorizerUri": f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function}/invocations",
        "AuthorizerPayloadFormatVersion": "2.0", "IdentitySource": ["$request.header.Authorization"],
        "AuthorizerResultTtlInSeconds": 0, "EnableSimpleResponses": False}
    invalid = [("missing-payload", {"AuthorizerPayloadFormatVersion": None}),
        ("unsupported-payload", {"AuthorizerPayloadFormatVersion": "3.0"}),
        ("v1-simple-enabled", {"AuthorizerPayloadFormatVersion": "1.0", "EnableSimpleResponses": True}),
        ("ttl-negative", {"AuthorizerResultTtlInSeconds": -1}),
        ("ttl-too-high", {"AuthorizerResultTtlInSeconds": 3601}),
        ("cache-no-identity", {"AuthorizerResultTtlInSeconds": 60, "IdentitySource": []}),
        ("rest-identity-expression", {"IdentitySource": ["method.request.header.Authorization"]}),
        ("token-authorizer-type", {"AuthorizerType": "TOKEN"})]
    for label, overrides in invalid:
        parameters = {**common, "Name": label, **overrides}
        parameters = {key: value for key, value in parameters.items() if value is not None}
        result = p.call("protocol-" + label, "apigatewayv2", "create_authorizer", parameters, required=False)
        if result["code"] == "Success":
            p.required("remove-protocol-" + label, "apigatewayv2", "delete_authorizer", {"ApiId": api, "AuthorizerId": result["output"]["AuthorizerId"]})
    definitions = [("v1", "1.0", False, 0, ["$request.header.Authorization"]),
        ("v2policy", "2.0", False, 0, ["$request.header.Authorization"]),
        ("v2simple", "2.0", True, 0, ["$request.header.Authorization"]),
        ("noidentity", "2.0", True, 0, []),
        ("cachedsimple", "2.0", True, 60, ["$request.header.Authorization"]),
        ("cachedpolicy", "2.0", False, 60, ["$request.header.Authorization"]),
        ("cachedroute", "2.0", True, 60, ["$request.header.Authorization", "$request.querystring.tenant", "$context.routeKey"]),
        ("shortcache", "2.0", True, 2, ["$request.header.Authorization"])]
    for label, version, simple, ttl, identities in definitions:
        authorizer = p.required("create-" + label, "apigatewayv2", "create_authorizer", {**common, "Name": label,
            "AuthorizerPayloadFormatVersion": version, "EnableSimpleResponses": simple,
            "AuthorizerResultTtlInSeconds": ttl, "IdentitySource": identities})
        ident = authorizer["AuthorizerId"]
        p.data["authorizers"][label] = authorizer
        if label != "v2simple":
            p.required("permission-authorizer-" + label, "lambda", "add_permission", {"FunctionName": name,
                "StatementId": "authorizer-" + label, "Action": "lambda:InvokeFunction",
                "Principal": "apigateway.amazonaws.com", "SourceAccount": account,
                "SourceArn": source + "/authorizers/" + ident})
        for suffix in ("a", "b"):
            p.required("route-" + label + "-" + suffix, "apigatewayv2", "create_route", {"ApiId": api,
                "RouteKey": "GET /" + label + "/" + suffix, "AuthorizationType": "CUSTOM",
                "AuthorizerId": ident, "Target": "integrations/" + integration})
    p.required("path-parameter-route", "apigatewayv2", "create_route", {"ApiId": api, "RouteKey": "GET /v1/item/{item}",
        "AuthorizationType": "CUSTOM", "AuthorizerId": p.data["authorizers"]["v1"]["AuthorizerId"], "Target": "integrations/" + integration})
    p.required("stage", "apigatewayv2", "create_stage", {"ApiId": api, "StageName": "$default", "AutoDeploy": False,
        "StageVariables": {"probeStage": "owned-stage-value"}})
    deploy(p, "initial", integration)
    request(p, "v2simple-missing-invoke-permission", "/v2simple/a", mode="simple-allow")
    p.required("repair-authorizer-permission", "lambda", "add_permission", {"FunctionName": name, "StatementId": "authorizer-v2simple",
        "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com", "SourceAccount": account,
        "SourceArn": source + "/authorizers/" + p.data["authorizers"]["v2simple"]["AuthorizerId"]})
    for attempt in range(15):
        if request(p, "permission-repaired-" + str(attempt), "/v2simple/a", mode="simple-allow").get("status") == 200:
            break
        time.sleep(2)
    else:
        raise RuntimeError("Authorizer permission repair did not propagate")
    p.required("function-policy", "lambda", "get_policy", {"FunctionName": name})
    for label, allow, deny in (("v1", "policy-allow", "policy-deny"), ("v2policy", "policy-allow", "policy-deny"),
                               ("v2simple", "simple-allow", "simple-deny")):
        path = "/" + label + "/a"
        for case, mode in (("allow", allow), ("allow-repeat", allow), ("nested", allow + "-nested"),
                           ("claims", allow + "-claims"), ("deny", deny), ("unauthorized-return", "unauthorized-return"),
                           ("unauthorized-raise", "unauthorized-raise"), ("invalid", "invalid"),
                           ("simple-string", "simple-string"), ("opposite-format", "policy-allow" if label == "v2simple" else "simple-allow")):
            request(p, label + "-" + case, path, mode=mode)
        request(p, label + "-missing-header", path, token=None, mode=allow)
        request(p, label + "-empty-header", path, token="", mode=allow)
    for label, path, mode in (("v1", "/v1/item/value%20space", "policy-allow"), ("v2", "/v2simple/a", "simple-allow")):
        request(p, label + "-event-shape", path + "?dup=one&dup=two&empty=&encoded=a%2Bb", mode=mode,
                headers={"Cookie": "one=1; two=2", "X-Mixed-Header": "ProbeValue", "Authorization": "probe-shape-token"})
    for mode in ("simple-allow", "unauthorized-return", "unauthorized-raise", "invalid"):
        request(p, "noidentity-" + mode, "/noidentity/a", token=None, mode=mode)
    request(p, "cache-simple-first", "/cachedsimple/a", token="probe-cache-shared", mode="simple-route-a")
    request(p, "cache-simple-repeat", "/cachedsimple/a", token="probe-cache-shared", mode="simple-route-a")
    request(p, "cache-simple-other-route", "/cachedsimple/b", token="probe-cache-shared", mode="simple-route-a")
    request(p, "cache-simple-different-token", "/cachedsimple/b", token="probe-cache-other", mode="simple-route-a")
    request(p, "cache-deny-first", "/cachedsimple/a", token="probe-cache-deny", mode="simple-deny")
    request(p, "cache-deny-mode-changed", "/cachedsimple/a", token="probe-cache-deny", mode="simple-allow")
    for label, suffix in (("first", "a"), ("other-route", "b"), ("repeat", "a")):
        request(p, "cache-policy-" + label, "/cachedpolicy/" + suffix, token="probe-policy-shared")
    for label, path in (("first", "/cachedroute/a?tenant=one"), ("repeat", "/cachedroute/a?tenant=one"),
                        ("other-route", "/cachedroute/b?tenant=one"), ("other-query", "/cachedroute/a?tenant=two"),
                        ("missing-query", "/cachedroute/a"), ("empty-query", "/cachedroute/a?tenant="),
                        ("wrong-query-case", "/cachedroute/a?Tenant=one"), ("duplicate-query", "/cachedroute/a?tenant=one&tenant=two")):
        request(p, "cache-route-" + label, path, token="probe-route-shared", mode="simple-allow")
    request(p, "cache-route-header-case", "/cachedroute/a?tenant=one", token=None, mode="simple-allow",
            headers={"aUtHoRiZaTiOn": "probe-route-shared"})
    request(p, "cache-short-first", "/shortcache/a", mode="simple-allow")
    request(p, "cache-short-repeat", "/shortcache/a", mode="simple-allow")
    time.sleep(3)
    request(p, "cache-short-after-expiry", "/shortcache/a", mode="simple-allow")
    p.required("reset-authorizers-cache", "apigatewayv2", "reset_authorizers_cache", {"ApiId": api, "StageName": "$default"})
    request(p, "cache-simple-after-reset", "/cachedsimple/a", token="probe-cache-shared", mode="simple-allow")
    request(p, "cache-deny-after-reset", "/cachedsimple/a", token="probe-cache-deny", mode="simple-allow")
    request(p, "cache-policy-after-reset", "/cachedpolicy/b", token="probe-policy-shared")
    request(p, "cache-route-after-reset", "/cachedroute/a?tenant=one", token="probe-route-shared", mode="simple-allow")
    p.call("reset-missing-stage", "apigatewayv2", "reset_authorizers_cache", {"ApiId": api, "StageName": "not-created"}, required=False)
    cached = p.data["authorizers"]["cachedsimple"]["AuthorizerId"]
    request(p, "update-before", "/cachedsimple/a", token="probe-update", mode="simple-allow")
    p.required("update-authorizer-ttl-zero", "apigatewayv2", "update_authorizer", {"ApiId": api, "AuthorizerId": cached, "AuthorizerResultTtlInSeconds": 0})
    p.required("get-updated-authorizer", "apigatewayv2", "get_authorizer", {"ApiId": api, "AuthorizerId": cached})
    request(p, "update-without-deployment", "/cachedsimple/a", token="probe-update", mode="simple-deny")
    deploy(p, "ttlzero", integration)
    request(p, "update-after-deployment-deny", "/cachedsimple/a", token="probe-update", mode="simple-deny")
    request(p, "update-after-deployment-allow", "/cachedsimple/a", token="probe-update", mode="simple-allow")
    request(p, "update-after-deployment-repeat", "/cachedsimple/a", token="probe-update", mode="simple-allow")
    request(p, "logs-final-marker", "/v2simple/a", mode="simple-allow")
    p.data["completed_at"] = now()
    p.save()


def role_policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def role_trust(principal, condition=None):
    statement = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if condition is not None:
        statement["Condition"] = condition
    return role_policy(statement)


def invocation_ready(p, label, path, mode, attempts=24):
    """A successful real invocation is readiness; a negative is never readiness."""
    evidence = {"label": label, "path": path, "mode": mode, "started_at": now(),
        "max_attempts": attempts, "interval_seconds": 5, "requests": []}
    p.data["readiness"].append(evidence)
    for attempt in range(attempts):
        request_label = "iam-ready-" + label + "-" + str(attempt)
        result = request(p, request_label, path, mode=mode)
        evidence["requests"].append({"label": request_label, "status": result.get("status")})
        if result.get("status") == 200:
            evidence.update(ready=True, finished_at=now())
            p.save()
            return True
        if attempt + 1 < attempts:
            time.sleep(5)
    evidence.update(ready=False, finished_at=now(),
        conclusion="Inconclusive: bounded runtime readiness did not reach a successful invocation.")
    p.save()
    return False


def scoped_role_call(p, client, actor, label, method, parameters):
    """Keep Probe's SDK evidence convention while recording the non-default actor."""
    previous = p.clients["apigatewayv2"]
    p.clients["apigatewayv2"] = client
    try:
        result = p.call(label, "apigatewayv2", method, parameters, required=False)
        p.data["observations"][-1]["actor"] = actor
        p.save()
        return result
    finally:
        p.clients["apigatewayv2"] = previous


def passrole_cases(p, api, common, invoke_role, caller_role):
    resources = [f"arn:aws:apigateway:{REGION}::/apis/{api}/authorizers",
        f"arn:aws:apigateway:{REGION}::/apis/{api}/authorizers/*"]
    api_access = {"Effect": "Allow", "Action": ["apigateway:GET", "apigateway:POST",
        "apigateway:PATCH", "apigateway:DELETE"], "Resource": resources}
    pass_access = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": invoke_role,
        "Condition": {"StringEquals": {"iam:PassedToService": "apigateway.amazonaws.com"}}}
    p.required("caller-policy", "iam", "put_role_policy", {"RoleName": caller_role["RoleName"],
        "PolicyName": "probe-owned", "PolicyDocument": role_policy(api_access, pass_access)})
    sts = p.client("sts")

    def hide_credentials(parsed, **kwargs):
        for key, value in parsed.get("Credentials", {}).items():
            if key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                p.hide(value, key.lower())

    # Probe.call saves immediately; hide STS secrets in the SDK response event before it can save.
    sts.meta.events.register("after-call.sts.AssumeRole", hide_credentials)
    try:
        for label, statements in (
                ("missing-passrole", (api_access,)),
                ("deny-passrole", (api_access, pass_access,
                    {"Effect": "Deny", "Action": "iam:PassRole", "Resource": invoke_role})),
                ("allow-passrole", (api_access, pass_access))):
            assumed = None
            evidence = {"label": "sts-" + label, "started_at": now(),
                "max_attempts": 24, "interval_seconds": 5, "observations": []}
            p.data["readiness"].append(evidence)
            for attempt in range(24):
                call_label = "sts-ready-" + label + "-" + str(attempt)
                result = p.call(call_label, "sts", "assume_role", {"RoleArn": caller_role["Arn"],
                    "RoleSessionName": label, "DurationSeconds": 900, "Policy": role_policy(*statements)},
                    required=False)
                evidence["observations"].append({"label": call_label, "code": result["code"]})
                if result["code"] == "Success":
                    assumed = result["output"]
                    break
                if result["code"] != "AccessDenied":
                    break
                if attempt < 23:
                    time.sleep(5)
            evidence.update(ready=assumed is not None, finished_at=now())
            p.save()
            if assumed is None:
                p.data["uncertainties"].append(label + ": STS readiness bound failed; no PassRole conclusion.")
                continue
            credentials = assumed["Credentials"]
            session = apigateway_probe.boto3.Session(region_name=REGION,
                aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"])
            actor_sts = session.client("sts", config=sts.meta.config)
            client = session.client("apigatewayv2", config=p.client("apigatewayv2").meta.config)
            try:
                actor = actor_sts.get_caller_identity()
                p.data["actors"][label] = {"identity": actor, "session_policy": json.loads(role_policy(*statements)),
                    "credential_fields": {key: p.sanitize(value) for key, value in credentials.items()}}
                evidence = {"label": "caller-api-" + label, "started_at": now(),
                    "max_attempts": 24, "interval_seconds": 5, "observations": []}
                p.data["readiness"].append(evidence)
                created = None
                for attempt in range(24):
                    call_label = "caller-api-ready-" + label + "-" + str(attempt)
                    result = scoped_role_call(p, client, actor, call_label, "create_authorizer",
                        {**common, "Name": label + "-without-credentials"})
                    evidence["observations"].append({"label": call_label, "code": result["code"]})
                    if result["code"] == "Success":
                        created = result["output"]
                        break
                    if attempt < 23:
                        time.sleep(5)
                evidence.update(ready=created is not None, finished_at=now())
                p.save()
                if created is None:
                    p.data["uncertainties"].append(label + ": API authorization never became ready; PassRole unproven.")
                    continue
                with_credentials = scoped_role_call(p, client, actor, label + "-create", "create_authorizer",
                    {**common, "Name": label + "-with-credentials", "AuthorizerCredentialsArn": invoke_role})
                if with_credentials["code"] == "Success":
                    scoped_role_call(p, client, actor, label + "-delete-created", "delete_authorizer",
                        {"ApiId": api, "AuthorizerId": with_credentials["output"]["AuthorizerId"]})
                target = {"ApiId": api, "AuthorizerId": created["AuthorizerId"]}
                result = scoped_role_call(p, client, actor, label + "-update", "update_authorizer",
                    {**target, "AuthorizerCredentialsArn": invoke_role})
                scoped_role_call(p, client, actor, label + "-get", "get_authorizer", target)
                if label == "allow-passrole" and result["code"] != "Success":
                    p.data["uncertainties"].append(
                        "Scoped allow-passrole update failed despite API readiness; separate PassRole propagation is not proven.")
                scoped_role_call(p, client, actor, label + "-delete-updated", "delete_authorizer", target)
            finally:
                client.close()
                actor_sts.close()
    finally:
        sts.meta.events.unregister("after-call.sts.AssumeRole", hide_credentials)


def run_credentials_roles(p):
    name, account = p.data["prefix"], p.data["account"]
    p.data.update(mode="credentials-roles",
        scope="One owned HTTP API: REQUEST authorizer service-role invocation and scoped caller PassRole authority",
        bounds={"apis": 1, "functions": 1, "roles": 6, "function_log_groups": 1, "simultaneous_authorizers": 10,
            "readiness_attempts": 24, "readiness_interval_seconds": 5,
            "deployment_readiness_attempts": 15, "deployment_readiness_interval_seconds": 2,
            "sdk_total_max_attempts": 1, "http_timeout_seconds": 30, "cache_ttl_seconds": 0,
            "negative_rounds": 3, "negative_interval_seconds": 10, "cleanup_attempts": 3,
            "log_attempts": 12, "log_pages_per_attempt": 10, "log_interval_seconds": 3},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html",
            "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-authorizers.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"],
        probe_source=Path(__file__).read_text(), base_helper_source=Path(apigateway_probe.__file__).read_text(),
        handler_source=HANDLER, authorizers={}, readiness=[], actors={}, uncertainties=[],
        source_context_discriminator={"role": "allow",
            "initial_trust_condition": {"Null": {"aws:SourceAccount": "true", "aws:SourceArn": "true"}},
            "interpretation": "A successful invocation uses a fresh role whose only trust version requires both source keys absent."},
        actor_context={"default_sdk_actor": p.data["identity"],
            "overrides": "Per-observation actor identifies scoped STS callers; unsigned HTTP caller is recorded separately."},
        unsampled_boundaries=["Cross-account roles and functions", "Role permissions boundaries and organization SCPs",
            "Authorizer result cache (TTL zero throughout)", "CloudTrail and service-internal STS event inspection",
            "IAM/STS cache lifetime after a previously successful role assumption"])
    p.data["sdk"]["apigatewayv2_parameter_validation"] = True
    execution = p.required("create-role", "iam", "create_role", {"RoleName": name,
        "AssumeRolePolicyDocument": role_trust({"Service": "lambda.amazonaws.com"})},
        own=("role", "Role.RoleName"))["Role"]
    p.required("role-logs", "iam", "put_role_policy", {"RoleName": name, "PolicyName": "probe-logs",
        "PolicyDocument": role_policy({"Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"arn:aws:logs:{REGION}:{account}:log-group:/aws/lambda/{name}:*"})})
    function = create_function(p, execution["Arn"])
    api_output = p.required("create-http", "apigatewayv2", "create_api",
        {"Name": name, "ProtocolType": "HTTP"}, own=("http_api", "ApiId"))
    api = api_output["ApiId"]
    p.data["owned"]["http_endpoint"] = api_output["ApiEndpoint"]
    source = f"arn:aws:execute-api:{REGION}:{account}:{api}"
    p.data["owned"]["log_group"] = "/aws/lambda/" + name
    p.required("permission-backend-only", "lambda", "add_permission", {"FunctionName": name,
        "StatementId": "integration", "Action": "lambda:InvokeFunction",
        "Principal": "apigateway.amazonaws.com", "SourceAccount": account,
        "SourceArn": source + "/$default/GET/*"})
    p.required("function-policy-before", "lambda", "get_policy", {"FunctionName": name})
    integration = p.required("integration", "apigatewayv2", "create_integration", {"ApiId": api,
        "IntegrationType": "AWS_PROXY", "IntegrationUri": function, "PayloadFormatVersion": "2.0"})["IntegrationId"]
    roles = {}
    invocation_allow = {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function}
    for label in ("allow", "missing", "deny", "wrong-trust", "caller"):
        principal = ({"AWS": f"arn:aws:iam::{account}:root"} if label == "caller" else
            {"Service": "lambda.amazonaws.com" if label == "wrong-trust" else "apigateway.amazonaws.com"})
        condition = {"Null": {"aws:SourceAccount": "true", "aws:SourceArn": "true"}} if label == "allow" else None
        role = p.required("create-credentials-role-" + label, "iam", "create_role",
            {"RoleName": name + "-" + label, "AssumeRolePolicyDocument": role_trust(principal, condition)},
            own=("credentials_role_" + label, "Role.RoleName"))["Role"]
        roles[label] = role
        if label not in ("missing", "caller"):
            statements = [invocation_allow]
            if label == "deny":
                statements.append({**invocation_allow, "Effect": "Deny"})
            p.required("credentials-policy-" + label, "iam", "put_role_policy",
                {"RoleName": role["RoleName"], "PolicyName": "probe-owned",
                    "PolicyDocument": role_policy(*statements)})
    p.data["roles"] = roles
    common = {"ApiId": api, "AuthorizerType": "REQUEST",
        "AuthorizerUri": f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function}/invocations",
        "AuthorizerPayloadFormatVersion": "2.0", "IdentitySource": ["$request.header.Authorization"],
        "AuthorizerResultTtlInSeconds": 0, "EnableSimpleResponses": False}
    for label in ("allow", "missing", "deny", "wrong-trust", "no-credentials"):
        for kind, simple in (("policy", False), ("simple", True)):
            parameters = {**common, "Name": label + "-" + kind, "EnableSimpleResponses": simple}
            if label != "no-credentials":
                parameters["AuthorizerCredentialsArn"] = roles[label]["Arn"]
            authorizer = p.required("create-authorizer-" + label + "-" + kind,
                "apigatewayv2", "create_authorizer", parameters)
            p.data["authorizers"][label + "-" + kind] = authorizer
            p.required("get-authorizer-" + label + "-" + kind, "apigatewayv2", "get_authorizer",
                {"ApiId": api, "AuthorizerId": authorizer["AuthorizerId"]})
            p.required("route-" + label + "-" + kind, "apigatewayv2", "create_route",
                {"ApiId": api, "RouteKey": "GET /" + label + "/" + kind, "AuthorizationType": "CUSTOM",
                    "AuthorizerId": authorizer["AuthorizerId"], "Target": "integrations/" + integration})
    p.required("stage", "apigatewayv2", "create_stage", {"ApiId": api, "StageName": "$default", "AutoDeploy": False})
    deploy(p, "credentials", integration)
    if not invocation_ready(p, "allowed-role", "/allow/policy", "policy-allow"):
        p.data["uncertainties"].append("Positive service-role control did not become ready; negative invocation cases are inconclusive.")
    for kind in ("policy", "simple"):
        request(p, "role-allow-" + kind, "/allow/" + kind, mode=kind + "-allow")
        request(p, "role-response-deny-" + kind, "/allow/" + kind, mode=kind + "-deny")
    for attempt in range(3):
        request(p, "negative-guard-" + str(attempt), "/allow/policy")
        for label in ("missing", "deny", "wrong-trust", "no-credentials"):
            for kind in ("policy", "simple"):
                request(p, label + "-" + kind + "-round-" + str(attempt), "/" + label + "/" + kind,
                    mode=kind + "-allow")
        if attempt < 2:
            time.sleep(10)
    # Repair the missing permission and explicit deny without modifying any authorizer or deployment.
    for label in ("missing", "deny"):
        p.required("repair-policy-" + label, "iam", "put_role_policy",
            {"RoleName": roles[label]["RoleName"], "PolicyName": "probe-owned",
                "PolicyDocument": role_policy(invocation_allow)})
        if invocation_ready(p, "repaired-" + label, "/" + label + "/policy", "policy-allow"):
            for kind in ("policy", "simple"):
                request(p, "repaired-" + label + "-" + kind, "/" + label + "/" + kind, mode=kind + "-allow")
    # This role has not successfully been used by API Gateway: avoid old successful STS sessions
    # masking the source-condition experiment. Successful invocation, not GetRole, is positive proof.
    wrong = roles["wrong-trust"]["RoleName"]
    conditions = (
        ("source-match", {"StringEquals": {"aws:SourceAccount": account},
            "ArnLike": {"aws:SourceArn": source + "/authorizers/*"}}),
        ("source-absent", {"Null": {"aws:SourceAccount": "true", "aws:SourceArn": "true"}}))
    for label, condition in conditions:
        p.required("trust-" + label, "iam", "update_assume_role_policy", {"RoleName": wrong,
            "PolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"}, condition)})
        p.required("get-trust-" + label, "iam", "get_role", {"RoleName": wrong})
        ready = invocation_ready(p, label, "/wrong-trust/policy", "policy-allow",
            attempts=12 if label == "source-match" else 24)
        for kind in ("policy", "simple"):
            request(p, label + "-" + kind, "/wrong-trust/" + kind, mode=kind + "-allow")
        if label == "source-match" and ready:
            p.data["uncertainties"].append(
                "Source-match succeeded before source-absent: later Null-condition success may reuse an earlier STS session.")
    # HTTP APIs permit ten authorizers by default. Retire completed runtime cases before controls.
    routes = p.required("routes-before-control", "apigatewayv2", "get_routes", {"ApiId": api, "MaxResults": "100"})
    for label, authorizer in p.data["authorizers"].items():
        if label.startswith("allow-"):
            continue
        ident = authorizer["AuthorizerId"]
        for route in routes.get("Items", []):
            if route.get("AuthorizerId") == ident:
                p.required("retire-route-" + label, "apigatewayv2", "delete_route",
                    {"ApiId": api, "RouteId": route["RouteId"]})
        p.required("retire-authorizer-" + label, "apigatewayv2", "delete_authorizer",
            {"ApiId": api, "AuthorizerId": ident})
    control = p.required("credentials-control-create", "apigatewayv2", "create_authorizer",
        {**common, "Name": "credentials-control", "AuthorizerCredentialsArn": roles["allow"]["Arn"]})
    target = {"ApiId": api, "AuthorizerId": control["AuthorizerId"]}
    for label, value in (("malformed", "not-an-arn"),
            ("nonexistent", f"arn:aws:iam::{account}:role/{name}-not-created"),
            ("wrong-service", function), ("empty", "")):
        result = p.call("credentials-create-" + label, "apigatewayv2", "create_authorizer",
            {**common, "Name": "credentials-" + label, "AuthorizerCredentialsArn": value}, required=False)
        if result["code"] == "Success":
            p.required("credentials-get-created-" + label, "apigatewayv2", "get_authorizer",
                {"ApiId": api, "AuthorizerId": result["output"]["AuthorizerId"]})
            p.required("credentials-delete-created-" + label, "apigatewayv2", "delete_authorizer",
                {"ApiId": api, "AuthorizerId": result["output"]["AuthorizerId"]})
        p.call("credentials-update-" + label, "apigatewayv2", "update_authorizer",
            {**target, "AuthorizerCredentialsArn": value}, required=False)
        p.required("credentials-get-updated-" + label, "apigatewayv2", "get_authorizer", target)
    p.required("credentials-update-set", "apigatewayv2", "update_authorizer",
        {**target, "AuthorizerCredentialsArn": roles["allow"]["Arn"]})
    p.required("credentials-update-omitted", "apigatewayv2", "update_authorizer",
        {**target, "Name": "credentials-control-renamed"})
    p.required("credentials-get-omitted", "apigatewayv2", "get_authorizer", target)
    passrole_cases(p, api, common, roles["allow"]["Arn"], roles["caller"])
    p.required("function-policy-after", "lambda", "get_policy", {"FunctionName": name})
    request(p, "logs-final-marker", "/allow/simple", mode="simple-allow")
    p.data["completed_at"] = now()
    p.save()


def run_service_context(p, *, principal_types=False):
    name, account = p.data["prefix"], p.data["account"]
    cases = {
        "control": None,
        "principal-absent": {"Null": {"aws:PrincipalType": "true"}},
        "principal-account": {"StringEquals": {"aws:PrincipalType": "Account"}},
        "principal-assumedrole": {"StringEquals": {"aws:PrincipalType": "AssumedRole"}},
        "principal-anonymous": {"StringEquals": {"aws:PrincipalType": "Anonymous"}},
    } if principal_types else {
        "control": None,
        "principal-service": {"StringEquals": {"aws:PrincipalType": "Service"}},
        "principal-awsservice": {"StringEquals": {"aws:PrincipalType": "AWSService"}},
        "source-org-id-absent": {"Null": {"aws:SourceOrgID": "true"}},
        "source-org-paths-absent": {"Null": {"aws:SourceOrgPaths": "true"}},
    }
    p.data.update(mode="principal-types" if principal_types else "service-context",
        scope="One owned HTTP API: fresh immutable service trusts discriminate native IAM service context",
        bounds={"apis": 1, "functions": 1, "roles": 6, "function_log_groups": 1,
            "simultaneous_authorizers": 10, "cache_ttl_seconds": 0,
            "readiness_attempts": 24, "readiness_interval_seconds": 5,
            "deployment_readiness_attempts": 15, "deployment_readiness_interval_seconds": 2,
            "semantic_rounds": 3, "semantic_interval_seconds": 10, "cleanup_attempts": 3,
            "sdk_total_max_attempts": 1, "http_timeout_seconds": 30,
            "log_attempts": 12, "log_pages_per_attempt": 10, "log_interval_seconds": 3},
        probe_source=Path(__file__).read_text(), base_helper_source=Path(apigateway_probe.__file__).read_text(),
        handler_source=HANDLER, trust_cases=cases, authorizers={}, readiness=[], uncertainties=[],
        documentation=["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html"],
        interpretation={
            "positive": "Actual authorizer execution through an unchanged fresh role establishes its initial trust condition admitted invocation.",
            "negative": "Repeated denial with healthy controls is bounded non-admission, not proof that independent role propagation completed.",
            "identity": "No IAM condition value is inferred from a CloudTrail identity type.",
            "source_keys": "Null=true success establishes absence for this native invocation, not universal absence across AWS services."})
    p.data["sdk"]["apigatewayv2_parameter_validation"] = True
    organizations = p.client("organizations")

    def membership_only(parsed, **kwargs):
        organization = parsed.get("Organization")
        if organization:
            parsed["Organization"] = {key: organization[key] for key in
                ("Id", "Arn", "FeatureSet", "MasterAccountId") if key in organization}

    organizations.meta.events.register("after-call.organizations.DescribeOrganization", membership_only)
    try:
        membership = p.call("organization-membership", "organizations", "describe_organization", required=False)
    finally:
        organizations.meta.events.unregister("after-call.organizations.DescribeOrganization", membership_only)
    if membership["code"] == "Success":
        p.data["organization_membership"] = {"member": True, **membership["output"]["Organization"]}
        ancestry = []
        child = account
        for depth in range(10):
            parents = p.call("organization-parent-" + str(depth), "organizations", "list_parents",
                {"ChildId": child}, required=False)
            if parents["code"] != "Success" or len(parents["output"].get("Parents", [])) != 1:
                p.data["uncertainties"].append("Organization ancestry lookup did not establish a complete path.")
                break
            parent = parents["output"]["Parents"][0]
            ancestry.append(parent)
            if parent["Type"] == "ROOT":
                p.data["organization_membership"]["account_path"] = (
                    membership["output"]["Organization"]["Id"] + "/" +
                    "/".join(item["Id"] for item in reversed(ancestry)) + "/")
                break
            child = parent["Id"]
        p.data["organization_membership"]["parents_nearest_first"] = ancestry
    elif membership["code"] == "AWSOrganizationsNotInUseException":
        p.data["organization_membership"] = {"member": False}
    else:
        p.data["organization_membership"] = {"member": None, "lookup_code": membership["code"]}
        p.data["uncertainties"].append("Organization membership lookup did not establish membership.")
    p.save()
    execution = p.required("create-role", "iam", "create_role", {"RoleName": name,
        "AssumeRolePolicyDocument": role_trust({"Service": "lambda.amazonaws.com"})},
        own=("role", "Role.RoleName"))["Role"]
    p.required("role-logs", "iam", "put_role_policy", {"RoleName": name, "PolicyName": "probe-logs",
        "PolicyDocument": role_policy({"Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"arn:aws:logs:{REGION}:{account}:log-group:/aws/lambda/{name}:*"})})
    function = create_function(p, execution["Arn"])
    api_output = p.required("create-http", "apigatewayv2", "create_api",
        {"Name": name, "ProtocolType": "HTTP"}, own=("http_api", "ApiId"))
    api = api_output["ApiId"]
    p.data["owned"]["http_endpoint"] = api_output["ApiEndpoint"]
    p.data["owned"]["log_group"] = "/aws/lambda/" + name
    p.required("permission-backend-only", "lambda", "add_permission", {"FunctionName": name,
        "StatementId": "integration", "Action": "lambda:InvokeFunction",
        "Principal": "apigateway.amazonaws.com", "SourceAccount": account,
        "SourceArn": f"arn:aws:execute-api:{REGION}:{account}:{api}/$default/GET/*"})
    p.required("function-policy-before", "lambda", "get_policy", {"FunctionName": name})
    integration = p.required("integration", "apigatewayv2", "create_integration", {"ApiId": api,
        "IntegrationType": "AWS_PROXY", "IntegrationUri": function, "PayloadFormatVersion": "2.0"})["IntegrationId"]
    p.data["roles"] = {}
    for label, condition in cases.items():
        role = p.required("create-credentials-role-" + label, "iam", "create_role",
            {"RoleName": name + "-" + label,
                "AssumeRolePolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"}, condition)},
            own=("credentials_role_" + label, "Role.RoleName"))["Role"]
        p.data["roles"][label] = role
        p.required("credentials-policy-" + label, "iam", "put_role_policy",
            {"RoleName": role["RoleName"], "PolicyName": "probe-owned",
                "PolicyDocument": role_policy({"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function})})
        for kind, simple in (("policy", False), ("simple", True)):
            authorizer = p.required("create-authorizer-" + label + "-" + kind,
                "apigatewayv2", "create_authorizer", {"ApiId": api, "Name": label + "-" + kind,
                    "AuthorizerType": "REQUEST",
                    "AuthorizerUri": f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function}/invocations",
                    "AuthorizerCredentialsArn": role["Arn"], "AuthorizerPayloadFormatVersion": "2.0",
                    "IdentitySource": ["$request.header.Authorization"],
                    "AuthorizerResultTtlInSeconds": 0, "EnableSimpleResponses": simple})
            p.data["authorizers"][label + "-" + kind] = authorizer
            p.required("route-" + label + "-" + kind, "apigatewayv2", "create_route",
                {"ApiId": api, "RouteKey": "GET /" + label + "/" + kind, "AuthorizationType": "CUSTOM",
                    "AuthorizerId": authorizer["AuthorizerId"], "Target": "integrations/" + integration})
    p.required("stage", "apigatewayv2", "create_stage", {"ApiId": api, "StageName": "$default", "AutoDeploy": False})
    deploy(p, "service-context", integration)
    controls_ready = {}
    for kind in ("policy", "simple"):
        controls_ready[kind] = invocation_ready(p, "control-" + kind, "/control/" + kind, kind + "-allow")
    if not all(controls_ready.values()):
        p.data["uncertainties"].append("Unconditioned controls did not both become ready; negative samples are inconclusive.")
    # A single bounded window preserves every candidate failure without treating it as a semantic denial.
    pending = {(label, kind) for label in cases if label != "control" for kind in ("policy", "simple")}
    readiness = {"label": "conditioned-role-window", "started_at": now(), "max_attempts": 24,
        "interval_seconds": 5, "requests": []}
    p.data["readiness"].append(readiness)
    for attempt in range(24):
        request(p, "iam-ready-window-control-" + str(attempt), "/control/policy")
        for label, kind in sorted(pending):
            sample = "iam-ready-" + label + "-" + kind + "-" + str(attempt)
            result = request(p, sample, "/" + label + "/" + kind, mode=kind + "-allow")
            readiness["requests"].append({"label": sample, "status": result.get("status")})
            if result.get("status") == 200:
                pending.remove((label, kind))
        if not pending:
            break
        if attempt < 23:
            time.sleep(5)
    readiness.update(finished_at=now(), ready=not pending,
        unresolved=[label + "-" + kind for label, kind in sorted(pending)],
        conclusion="Never-successful conditions remain bounded non-admission; independent role propagation is not proven.")
    p.data["semantic_results"] = {label: {kind: [] for kind in ("policy", "simple")} for label in cases}
    for attempt in range(3):
        for label in cases:
            for kind in ("policy", "simple"):
                result = request(p, "service-context-" + label + "-" + kind + "-round-" + str(attempt),
                    "/" + label + "/" + kind, mode=kind + "-allow")
                p.data["semantic_results"][label][kind].append(result.get("status"))
        if attempt < 2:
            time.sleep(10)
    p.required("function-policy-after", "lambda", "get_policy", {"FunctionName": name})
    request(p, "logs-final-marker", "/control/simple", mode="simple-allow")
    p.data["completed_at"] = now()
    p.save()


def cleanup_credentials_roles(p):
    # Always attempt every extra role even if one of the common deletions failed.
    base_error = None
    try:
        p.cleanup()
    except Exception as error:
        base_error = error
    absent = []
    for key, name in p.data["owned"].items():
        if not key.startswith("credentials_role_"):
            continue
        p.call("cleanup-policy-" + key, "iam", "delete_role_policy",
            {"RoleName": name, "PolicyName": "probe-owned"}, required=False)
        deleted = p.call("cleanup-" + key, "iam", "delete_role", {"RoleName": name}, required=False)
        result = p.call("absence-" + key, "iam", "get_role", {"RoleName": name}, required=False)
        absent.append(result["code"] == "NoSuchEntity")
        p.data["cleanup"][key] = {"delete_code": deleted["code"], "absent": absent[-1]}
    p.data["cleanup"]["complete"] = base_error is None and all(absent)
    p.save()
    if base_error is not None or not all(absent):
        raise RuntimeError("Owned credentials-role cleanup remains incomplete") from base_error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--service-context", action="store_true",
        help="Capture fresh immutable service-role trust conditions for principal type and source organization keys")
    modes.add_argument("--principal-types", action="store_true",
        help="Capture fresh PrincipalType absent, Account, AssumedRole, and Anonymous trust discriminators")
    modes.add_argument("--credentials-roles", action="store_true",
        help="Capture uncached service-role and scoped PassRole authority instead of the canonical authorizer matrix")
    parser.add_argument("--append-capture", action="store_true",
        help="Preserve a fully cleaned credentials-role capture in prior_captures and execute a fresh owned run")
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    if args.append_capture and (not args.credentials_roles or args.cleanup_only):
        parser.error("--append-capture requires --credentials-roles and cannot accompany --cleanup-only")
    if args.output is None:
        args.output = Path(".stackd/probes/apigateway/http_authorizer_principal_type.json" if args.principal_types
            else ".stackd/probes/apigateway/http_authorizer_service_context.json" if args.service_context
            else ".stackd/probes/apigateway/http_authorizer_roles.json" if args.credentials_roles
            else ".stackd/probes/apigateway/http_lambda_authorizers.json")
    probe = Probe(args.output, args.account, args.cleanup_only or args.append_capture)
    if args.append_capture:
        previous = probe.data
        if previous.get("mode") != "credentials-roles" or not previous.get("cleanup", {}).get("complete"):
            raise RuntimeError("Can append only to a fully cleaned credentials-role capture")
        earlier = previous.pop("prior_captures", [])
        probe.data = {"service": "apigateway", "account": args.account, "region": REGION,
            "identity": probe.client("sts").get_caller_identity(), "captured_at": now(),
            "prefix": "stackd-apigw-" + apigateway_probe.uuid.uuid4().hex[:10],
            "owned": {}, "observations": [], "http": [], "tokens": {}, "cleanup": {},
            "sdk": {"boto3": apigateway_probe.boto3.__version__}, "prior_captures": earlier + [previous]}
    try:
        if not args.cleanup_only:
            if args.principal_types or args.service_context:
                run_service_context(probe, principal_types=args.principal_types)
            else:
                (run_credentials_roles if args.credentials_roles else run)(probe)
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        try:
            if not args.cleanup_only:
                try:
                    collect_logs(probe)
                except Exception as error:
                    probe.data["log_collection_error"] = str(error)
                    probe.save()
            for attempt in range(3):
                try:
                    (cleanup_credentials_roles if probe.data.get("mode") in ("credentials-roles", "service-context", "principal-types") else Probe.cleanup)(probe)
                    break
                except Exception as error:
                    probe.data.setdefault("cleanup_attempt_errors", []).append({"attempt": attempt, "error": str(error)})
                    probe.save()
                    if attempt == 2:
                        raise
                    time.sleep(2)
        finally:
            for client in probe.clients.values():
                client.close()


if __name__ == "__main__":
    main()
