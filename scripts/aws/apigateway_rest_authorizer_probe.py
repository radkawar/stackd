#!/usr/bin/env python3
"""Capture owned native REST authorizers, optionally --credentials-roles or --service-context; cleanup is resumable."""
import argparse
import base64
import io
import json
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

import apigateway_probe as base
from apigateway_probe import Probe, REGION, now


HANDLER = '''import json
import uuid


def handler(event, context):
    invocation = str(uuid.uuid4())
    if event.get("type") in ("TOKEN", "REQUEST"):
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        token = event.get("authorizationToken", headers.get("x-auth", "allow-missing"))
        mode = token.split("-", 1)[0]
        print(json.dumps({"probe_kind": "authorizer", "invocation": invocation,
                          "lambdaRequestId": context.aws_request_id, "token": token, "event": event}))
        if mode == "unauthorized":
            raise Exception("Unauthorized")
        if mode == "invalid" and token != "invalid-context":
            return {"principalId": "probe-user", "context": {"invocation": invocation}}
        resource = event["methodArn"]
        if "narrow" not in token:
            resource = "/".join(resource.split("/")[:2]) + "/*/*"
        values = {"invocation": invocation, "event": json.dumps(event, separators=(",", ":")),
                  "stringValue": "scalar-text", "integerValue": 123, "floatValue": 1.5,
                  "trueValue": True, "falseValue": False, "zeroValue": 0}
        if token == "invalid-context":
            values["nested"] = {"not": "scalar"}
        return {"principalId": "probe-user", "policyDocument": {"Version": "2012-10-17",
                "Statement": [{"Action": "execute-api:Invoke", "Effect": "Deny" if mode == "deny" else "Allow",
                               "Resource": resource}]}, "context": values}
    print(json.dumps({"probe_kind": "backend", "invocation": invocation,
                      "lambdaRequestId": context.aws_request_id, "probe": (event.get("headers") or {}).get("X-Probe")}))
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"backendInvocationId": invocation, "event": event})}
'''


def http(p, label, path, *, method="GET", headers=None, phase="semantic"):
    sent = {"User-Agent": "stackd-rest-authorizer-probe", "X-Probe": label, **(headers or {})}
    started = now()
    request = urllib.request.Request(p.data["owned"]["rest_endpoint"] + path, headers=sent, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    except urllib.error.URLError as error:
        result = {"transport_error": str(error.reason)}
    if "response" in locals():
        with response:
            body = response.read(1 << 20)
            result = {"status": response.status, "headers": list(response.headers.items())}
            try:
                result["body"] = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                result["body_base64"] = base64.b64encode(body).decode()
    p.data["http"].append({"label": label, "api": "rest", "path": path, "method": method,
        "request_headers": sent, "identity_headers": {k: v for k, v in sent.items() if k.lower() == "x-auth"},
        "phase": phase, "started_at": started, "finished_at": now(), "result": result})
    p.save()
    print(label + ": " + str(result.get("status", "transport error")), flush=True)
    return result


def ready(p, label, path, headers=None):
    for attempt in range(20):
        result = http(p, label + "-" + str(attempt), path, headers=headers, phase="readiness")
        if result.get("status") == 200 and "backendInvocationId" in result.get("body", {}):
            return result
        time.sleep(3)
    raise RuntimeError(label + " exceeded 20 attempts; semantic requests were not retried")


def authorizer_uuid(result):
    return result.get("body", {}).get("event", {}).get("requestContext", {}).get("authorizer", {}).get("invocation")


def wait_for_flush(p, label, path, token, previous):
    for attempt in range(30):
        result = http(p, label + "-" + str(attempt), path, headers={"X-Auth": token}, phase="cache-flush-propagation")
        current = authorizer_uuid(result)
        if current and current != previous:
            return current
        time.sleep(3)
    raise RuntimeError(label + " exceeded 30 attempts without a changed authorizer invocation UUID")


def add_permission(p, label, source):
    p.required(label, "lambda", "add_permission", {"FunctionName": p.data["owned"]["function"],
        "StatementId": label, "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
        "SourceArn": source, "SourceAccount": p.data["account"]})


def collect_logs(p, final_invocation):
    previous = None
    for attempt in range(12):
        events, token = [], None
        for page in range(4):
            parameters = {"logGroupName": "/aws/lambda/" + p.data["owned"]["function"],
                          "startTime": p.data["log_start_ms"], "limit": 1000}
            if token:
                parameters["nextToken"] = token
            output = p.required(f"authorizer-logs-{attempt}-{page}", "logs", "filter_log_events", parameters)
            events.extend(output.get("events", []))
            token = output.get("nextToken")
            if not token:
                break
        if token:
            raise RuntimeError("Owned log collection exceeded four pages")
        records = []
        for event in events:
            try:
                value = json.loads(event["message"])
            except ValueError:
                continue
            if value.get("probe_kind"):
                records.append({"timestamp": event["timestamp"], "event_id": event["eventId"], "record": value})
        p.data["invocation_logs"] = records
        ids = sorted(item["event_id"] for item in records)
        final_seen = any(item["record"]["invocation"] == final_invocation for item in records)
        if final_seen and ids == previous:
            p.data["log_collection"] = {"final_backend_seen": True, "stable_consecutive_snapshots": 2,
                "poll_interval_seconds": 5, "attempts": attempt + 1,
                "absence_scope": "No matching invocation in the bounded, stable owned-function log capture; not an account-wide claim"}
            p.save()
            return
        previous = ids
        p.save()
        time.sleep(5)
    raise RuntimeError("Owned invocation log collection did not stabilize with final backend marker")


def summarize(p):
    rows = {row["label"]: row for row in p.data["http"] if row["phase"] == "semantic"}
    p.data["semantic_summary"] = {}
    for label, row in rows.items():
        result = row["result"]
        authorizer = result.get("body", {}).get("event", {}).get("requestContext", {}).get("authorizer")
        p.data["semantic_summary"][label] = {"status": result.get("status"), "backend_authorizer": authorizer}
    by_token = {}
    for entry in p.data["invocation_logs"]:
        record = entry["record"]
        if record["probe_kind"] == "authorizer":
            by_token.setdefault(record["token"], []).append(record["invocation"])
    p.data["authorizer_invocations_by_token"] = by_token
    p.save()


def create_function(p, handler=HANDLER):
    name, account = p.data["prefix"], p.data["account"]
    role = p.required("create-role", "iam", "create_role", {"RoleName": name,
        "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})},
        own=("role", "Role.RoleName"))["Role"]
    p.required("role-logs", "iam", "put_role_policy", {"RoleName": name, "PolicyName": "probe-logs",
        "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"arn:aws:logs:{REGION}:{account}:log-group:/aws/lambda/{name}:*"}]})})
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        output.writestr("index.py", handler)
    for attempt in range(15):
        result = p.call("create-function-" + str(attempt), "lambda", "create_function", {"FunctionName": name,
            "Role": role["Arn"], "Runtime": "python3.13", "Handler": "index.handler", "MemorySize": 128,
            "Timeout": 3, "Code": {"ZipFile": archive.getvalue()}}, own=("function", "FunctionName"), required=False)
        if result["code"] == "Success":
            function = result["output"]
            break
        if result["code"] != "InvalidParameterValueException" or result["error"]["Message"] != "The role defined for the function cannot be assumed by Lambda.":
            raise RuntimeError("Native Lambda creation failed: " + result["code"])
        time.sleep(2)
    else:
        raise RuntimeError("Native Lambda role propagation bound reached")
    p.required("create-function-log-group", "logs", "create_log_group", {"logGroupName": "/aws/lambda/" + name})
    for attempt in range(15):
        current = p.required("function-ready-" + str(attempt), "lambda", "get_function_configuration", {"FunctionName": name})
        if current["State"] == "Active":
            break
        if current["State"] == "Failed":
            raise RuntimeError("Native Lambda activation failed")
        time.sleep(2)
    else:
        raise RuntimeError("Native Lambda activation bound reached")
    return function, role


def put_route(p, api, resource, part, verb, auth, uri):
    parameters = {"restApiId": api, "resourceId": resource, "httpMethod": verb,
                  "authorizationType": "CUSTOM" if auth else "NONE"}
    if auth:
        parameters["authorizerId"] = auth
    p.required("put-method-" + part + "-" + verb, "apigateway", "put_method", parameters)
    p.required("put-integration-" + part + "-" + verb, "apigateway", "put_integration",
        {"restApiId": api, "resourceId": resource, "httpMethod": verb, "type": "AWS_PROXY",
         "integrationHttpMethod": "POST", "uri": uri})


def deploy(p, label, variables):
    return p.required(label, "apigateway", "create_deployment",
        {"restApiId": p.data["owned"]["rest_api"], "stageName": "dev", "variables": variables},
        own=("deployment", "id"))


def run(p):
    name, account = p.data["prefix"], p.data["account"]
    p.data.update(scope="Owned REST TOKEN/REQUEST Lambda authorizers, cache and identity behavior; no global logging changes",
        bounds={"apis": 1, "functions": 1, "roles": 1, "function_log_groups": 1, "authorizers": 5,
                "role_propagation_attempts": 15, "lambda_activation_attempts": 15, "readiness_attempts": 20,
                "readiness_delay_seconds": 3, "semantic_http_attempts": 1,
                "cache_flush_attempts": 30, "cache_flush_delay_seconds": 3,
                "log_poll_attempts": 12, "log_poll_delay_seconds": 5, "log_pages_per_poll": 4},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-input.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_CreateAuthorizer.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_FlushStageAuthorizersCache.html"],
        probe_source=Path(__file__).read_text(), base_helper_source=Path(base.__file__).read_text(),
        handler_source=HANDLER, log_start_ms=int(time.time() * 1000),
        retry_contract="Only exact IAM role propagation failure, Lambda activation, explicit readiness routes, cache-flush UUID transition and log delivery are polled; semantic HTTP calls are single-shot.",
        unsampled_boundaries=["TTL expiration by elapsed wall clock", "Cache identity-source order reversal",
            "Authorizer IAM assume-role credentials", "Cross-stage cache isolation", "Custom gateway response mappings",
            "Policy size and ARN length limits", "Null context values", "Non-exact Unauthorized exception text"])
    model = p.client("apigateway").meta.service_model
    p.data["modeled_inputs"] = {operation: {key: member.type_name for key, member in model.operation_model(operation).input_shape.members.items()}
        for operation in ("CreateAuthorizer", "FlushStageAuthorizersCache", "CreateDeployment")}
    p.save()
    function, _ = create_function(p)
    api = p.required("create-rest", "apigateway", "create_rest_api", {"name": name,
        "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    p.data["owned"]["rest_endpoint"] = f"https://{api}.execute-api.{REGION}.amazonaws.com"
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    source = f"arn:aws:execute-api:{REGION}:{account}:{api}"
    add_permission(p, "permission-integration", source + "/dev/*/*")
    authorizers = {}
    for key, kind, ttl in (("token0", "TOKEN", 0), ("token300", "TOKEN", 300),
                           ("request0", "REQUEST", 0), ("request300", "REQUEST", 300),
                           ("requestnone0", "REQUEST", 0)):
        parameters = {"restApiId": api, "name": key, "type": kind, "authorizerUri": uri,
            "authorizerResultTtlInSeconds": ttl, "identitySource": "method.request.header.X-Auth"}
        if kind == "TOKEN":
            parameters["identityValidationExpression"] = "^(allow|deny|unauthorized|invalid)(-[a-z0-9]+)*$"
        elif key == "requestnone0":
            parameters.pop("identitySource")
        else:
            parameters["identitySource"] += ",method.request.querystring.tenant"
        authorizers[key] = p.required("create-authorizer-" + key, "apigateway", "create_authorizer", parameters)["id"]
        if key != "token0":
            add_permission(p, "permission-" + key, source + "/authorizers/" + authorizers[key])
    p.data["authorizers"] = authorizers
    p.save()
    root = p.required("rest-resources", "apigateway", "get_resources", {"restApiId": api})["items"][0]["id"]
    for part, auth, verbs in (("ready", None, ["GET"]), ("token0", "token0", ["GET"]),
            ("token300", "token300", ["GET", "POST"]), ("other300", "token300", ["GET"]),
            ("request0", "request0", ["GET"]), ("request300", "request300", ["GET", "POST"]),
            ("requestnone0", "requestnone0", ["GET"])):
        resource = p.required("create-resource-" + part, "apigateway", "create_resource",
            {"restApiId": api, "parentId": root, "pathPart": part})["id"]
        if part.startswith("request"):
            resource = p.required("create-resource-" + part + "-item", "apigateway", "create_resource",
                {"restApiId": api, "parentId": resource, "pathPart": "{item}"})["id"]
        for verb in verbs:
            put_route(p, api, resource, part, verb, authorizers.get(auth), uri)
    deploy(p, "deploy", {"ProbeVar": "authorizer-probe"})
    ready(p, "ready-deployment", "/dev/ready")
    p.required("policy-before-authorizer-repair", "lambda", "get_policy", {"FunctionName": name})
    http(p, "token0-permission-missing", "/dev/token0", headers={"X-Auth": "allow-permission-negative"})
    add_permission(p, "permission-token0", source + "/authorizers/" + authorizers["token0"])
    p.required("policy-after-authorizer-repair", "lambda", "get_policy", {"FunctionName": name})
    for key in authorizers:
        path = "/dev/" + key + ("/ready?tenant=ready" if key.startswith("request") else "")
        ready(p, "ready-" + key, path, {"X-Auth": "allow-ready-" + key})
    http(p, "token0-permission-repaired", "/dev/token0", headers={"X-Auth": "allow-permission-negative"})
    for key in ("token0", "token300"):
        path = "/dev/" + key
        for label, token in (("allow-first", "allow-repeat-" + key), ("allow-repeat", "allow-repeat-" + key),
                ("deny-first", "deny-repeat-" + key), ("deny-repeat", "deny-repeat-" + key),
                ("unauthorized-first", "unauthorized-repeat-" + key), ("unauthorized-repeat", "unauthorized-repeat-" + key),
                ("invalid-response-first", "invalid-repeat-" + key), ("invalid-response-repeat", "invalid-repeat-" + key),
                ("regex-reject", "reject-" + key), ("empty", ""), ("missing", None)):
            http(p, key + "-" + label, path, headers={"X-Auth": token} if token is not None else {})
    http(p, "token0-invalid-context", "/dev/token0", headers={"X-Auth": "invalid-context"})
    for policy in ("narrow", "wide"):
        token = "allow-" + policy + "-scope"
        for label, path, method in (("first", "/dev/token300", "GET"), ("same", "/dev/token300", "GET"),
                ("other-method", "/dev/token300", "POST"), ("other-route", "/dev/other300", "GET")):
            http(p, "token300-" + policy + "-" + label, path, method=method, headers={"X-Auth": token})
    for key in ("request0", "request300", "requestnone0"):
        prefix = "/dev/" + key + "/item"
        token = "allow-repeat-" + key
        for label, suffix, header in (("allow-first", "?tenant=one&extra=first&extra=second&empty=", token),
                ("allow-repeat", "?tenant=one&extra=changed", token), ("query-key-change", "?tenant=two", token),
                ("header-key-change", "?tenant=one", "allow-other-" + key),
                ("missing-header", "?tenant=one", None), ("empty-header", "?tenant=one", ""),
                ("missing-query", "", token), ("empty-query", "?tenant=", token)):
            http(p, key + "-" + label, prefix + suffix, headers={"X-Auth": header} if header is not None else {})
        for mode in ("deny", "unauthorized", "invalid"):
            http(p, key + "-" + mode, prefix + "?tenant=one", headers={"X-Auth": mode + "-" + key})
    for label, path, method in (("same", "/dev/request300/item?tenant=one", "GET"),
            ("other-method", "/dev/request300/item?tenant=one", "POST"),
            ("other-path", "/dev/request300/other?tenant=one", "GET")):
        http(p, "request300-cache-" + label, path, method=method, headers={"X-Auth": "allow-repeat-request300"})
    before = {row["label"]: authorizer_uuid(row["result"]) for row in p.data["http"]}
    p.required("flush-stage-authorizers", "apigateway", "flush_stage_authorizers_cache", {"restApiId": api, "stageName": "dev"})
    http(p, "token300-immediate-after-flush", "/dev/token300", headers={"X-Auth": "allow-wide-scope"})
    http(p, "request300-immediate-after-flush", "/dev/request300/item?tenant=one", headers={"X-Auth": "allow-repeat-request300"})
    wait_for_flush(p, "flush-token300", "/dev/token300", "allow-wide-scope", before["token300-wide-first"])
    wait_for_flush(p, "flush-request300", "/dev/request300/item?tenant=one", "allow-repeat-request300",
                   before["request300-allow-first"])
    http(p, "token300-after-flush", "/dev/token300", headers={"X-Auth": "allow-wide-scope"})
    http(p, "request300-after-flush", "/dev/request300/item?tenant=one", headers={"X-Auth": "allow-repeat-request300"})
    # Sample the narrow policy's method scope only after both UUID readiness barriers observed invalidation.
    http(p, "token300-narrow-post-after-flush", "/dev/token300", method="POST", headers={"X-Auth": "allow-narrow-scope"})
    http(p, "token300-narrow-get-after-flush", "/dev/token300", headers={"X-Auth": "allow-narrow-scope"})
    final = http(p, "final-backend-log-marker", "/dev/ready")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)
    p.data["completed_at"] = now()
    p.save()


ROLES_HANDLER = HANDLER + '''

original_handler = handler


def handler(event, context):
    print(json.dumps({"probe_kind": "lambda-context", "invocation": context.aws_request_id,
                      "event": event, "context": {
                          "aws_request_id": context.aws_request_id,
                          "invoked_function_arn": context.invoked_function_arn,
                          "function_name": context.function_name,
                          "function_version": context.function_version,
                          "memory_limit_in_mb": context.memory_limit_in_mb,
                          "log_group_name": context.log_group_name,
                          "log_stream_name": context.log_stream_name,
                          "identity": None if context.identity is None else {
                              "cognito_identity_id": context.identity.cognito_identity_id,
                              "cognito_identity_pool_id": context.identity.cognito_identity_pool_id},
                          "client_context_present": context.client_context is not None}}))
    return original_handler(event, context)
'''


class CredentialsProbe(Probe):
    """Extend the common ledger only for temporary STS secrets and extra owned roles."""

    def sanitize(self, value):
        if isinstance(value, dict):
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                if isinstance(value.get(key), str) and not value[key].startswith("<redacted-"):
                    self.hide(value[key], key.lower())
            if self.data.get("mode") in ("service-context", "principal-types"):
                value = {key: "<redacted-email>" if key.lower().endswith("email") else child
                         for key, child in value.items()}
        return super().sanitize(value)

    def save(self):
        if not hasattr(self, "envelope"):
            return super().save()
        self.envelope["fresh_null_capture"] = self.sanitize(self.data)
        self.path.write_text(json.dumps(self.envelope, indent=2) + "\n")

    def call(self, *args, **kwargs):
        index = len(self.data["observations"])
        try:
            return super().call(*args, **kwargs)
        finally:
            for row in self.data["observations"][index:]:
                row["actor"] = getattr(self, "actor", self.data["identity"])
                row["phase"] = getattr(self, "phase", "setup")
            self.save()

    def cleanup(self):
        self.phase = "cleanup"
        base_error = None
        # The execution role doubles as the wrong-trust case, with invoke permission.
        if "role" in self.data["owned"]:
            self.call("cleanup-execution-invoke", "iam", "delete_role_policy",
                {"RoleName": self.data["owned"]["role"], "PolicyName": "probe-authority"}, required=False)
        try:
            super().cleanup()
        except Exception as error:
            base_error = str(error)
        items = [self.data["cleanup"].get("complete", False) and base_error is None]
        for key, role in self.data["owned"].items():
            if not key.startswith("credential_role_"):
                continue
            self.call("cleanup-policy-" + key, "iam", "delete_role_policy",
                {"RoleName": role, "PolicyName": "probe-authority"}, required=False)
            result = self.call("cleanup-" + key, "iam", "delete_role", {"RoleName": role}, required=False)
            absent = self.call("absence-" + key, "iam", "get_role", {"RoleName": role}, required=False)
            items.append(absent["code"] == "NoSuchEntity")
            self.data["cleanup"][key] = {"delete_code": result["code"], "absent": items[-1]}
        self.data["cleanup"]["complete"] = all(items)
        if base_error:
            self.data["cleanup"]["base_error"] = base_error
        self.save()
        if not all(items):
            raise RuntimeError("Owned credentials-role resource cleanup remains incomplete")


def role_trust(principal, condition=None):
    statement = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if condition is not None:
        statement["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


def role_policy(p, role, statements):
    p.required("policy-" + role["RoleName"], "iam", "put_role_policy", {
        "RoleName": role["RoleName"], "PolicyName": "probe-authority",
        "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})


def credentials_ready(p, label, path, *, marker=None):
    started = now()
    for attempt in range(30):
        result = http(p, label + "-" + str(attempt), path,
            headers={"X-Auth": "allow-" + label + "-" + str(attempt)}, phase="readiness")
        body = result.get("body", {})
        if (result.get("status") == 200 and "backendInvocationId" in body
                and (marker is None or body["event"].get("stageVariables", {}).get("Transition") == marker)):
            observed = True
            break
        time.sleep(3)
    else:
        observed = False
    p.data.setdefault("readiness", {})[label] = {"started_at": started, "finished_at": now(),
        "observed": observed, "attempts": attempt + 1, "limit": 30, "delay_seconds": 3,
        "expected": {"status": 200, "stage_variable_Transition": marker}}
    p.save()
    return observed


def credentials_deploy(p, label):
    result = deploy(p, label, {"Transition": label})
    p.data["owned"].setdefault("deployments", []).append(result["id"])
    p.required(label + "-stage", "apigateway", "get_stage",
        {"restApiId": p.data["owned"]["rest_api"], "stageName": "dev"})
    if not credentials_ready(p, label + "-ready", "/dev/ready", marker=label):
        raise RuntimeError("Deployment marker did not become visible: " + label)


def passrole_cases(p, actor_role, parameters, allowed_role):
    api = p.data["owned"]["rest_api"]
    scope = f"arn:aws:apigateway:{REGION}::/restapis/{api}/authorizers"
    allow = [{"Effect": "Allow", "Action": ["apigateway:GET", "apigateway:POST", "apigateway:PATCH"],
              "Resource": [scope, scope + "/*"]},
             {"Effect": "Allow", "Action": "iam:PassRole", "Resource": allowed_role["Arn"],
              "Condition": {"StringEquals": {"iam:PassedToService": "apigateway.amazonaws.com"}}}]
    role_policy(p, actor_role, allow)
    original = {service: p.client(service) for service in ("apigateway", "sts")}
    for mode in ("deny", "admit"):
        statements = allow + ([{"Effect": "Deny", "Action": "iam:PassRole", "Resource": allowed_role["Arn"]}]
                              if mode == "deny" else [])
        p.phase = "readiness"
        for attempt in range(20):
            result = p.call(f"assume-actor-{mode}-{attempt}", "sts", "assume_role",
                {"RoleArn": actor_role["Arn"], "RoleSessionName": "rest-passrole-" + mode,
                 "DurationSeconds": 900, "Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})},
                required=False)
            if result["code"] == "Success":
                break
            if result["code"] != "AccessDenied":
                break
            time.sleep(3)
        if result["code"] != "Success":
            p.data.setdefault("inconclusive", []).append("Scoped actor STS assumption failed for " + mode)
            continue
        credentials = result["output"]["Credentials"]
        session = base.boto3.Session(region_name=REGION, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        clients = {service: session.client(service, config=base.Config(
            retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)) for service in original}
        try:
            p.clients.update(clients)
            p.actor = result["output"]["AssumedRoleUser"]
            p.actor = p.required("actor-identity-" + mode, "sts", "get_caller_identity")
            for attempt in range(20):
                admitted = p.call(f"actor-ready-{mode}-{attempt}", "apigateway", "get_authorizers",
                    {"restApiId": api}, required=False)
                if admitted["code"] == "Success":
                    break
                time.sleep(3)
            if admitted["code"] != "Success":
                p.data.setdefault("inconclusive", []).append("Scoped actor API permission did not converge: " + mode)
                continue
            p.phase = "semantic"
            for with_role in (False, True):
                label = "passrole-" + mode + ("-role" if with_role else "-no-role")
                values = {**parameters, "name": label}
                if with_role:
                    values["authorizerCredentials"] = allowed_role["Arn"]
                result = p.call(label + "-create", "apigateway", "create_authorizer", values, required=False)
                if result["code"] != "Success":
                    continue
                identifier = result["output"]["id"]
                p.data["owned"]["authorizers"].append(identifier)
                p.call(label + "-update", "apigateway", "update_authorizer", {
                    "restApiId": api, "authorizerId": identifier, "patchOperations": [
                        {"op": "replace", "path": "/authorizerCredentials", "value": allowed_role["Arn"]}]},
                    required=False)
                followup = p.call(label + "-get", "apigateway", "get_authorizer",
                    {"restApiId": api, "authorizerId": identifier}, required=False)
                if followup["code"] != "Success":
                    p.data.setdefault("inconclusive", []).append(
                        label + ": scoped follow-up read failed; post-update state not established by that read")
                # Delete with the original actor: the scoped actor deliberately has no DELETE.
                p.clients["apigateway"] = original["apigateway"]
                saved_actor, p.actor = p.actor, p.data["identity"]
                p.required(label + "-delete", "apigateway", "delete_authorizer",
                    {"restApiId": api, "authorizerId": identifier})
                p.actor = saved_actor
                p.clients["apigateway"] = clients["apigateway"]
        finally:
            p.clients.update(original)
            p.actor = p.data["identity"]
            for client in clients.values():
                client.close()
    p.phase = "semantic"
    p.save()


def run_credentials(p):
    name, account = p.data["prefix"], p.data["account"]
    p.data.update(mode="credentials-roles", scope="Owned REST credentials-role control plane and real TOKEN/REQUEST execution",
        bounds={"apis": 1, "functions": 1, "roles": 6, "function_log_groups": 1,
                "concurrent_authorizers": 8, "lambda_activation_attempts": 15, "role_propagation_attempts": 15,
                "readiness_attempts": 30, "readiness_delay_seconds": 3, "semantic_http_attempts": 1,
                "actor_readiness_attempts": 20, "log_poll_attempts": 12, "log_pages_per_poll": 4},
        probe_source=Path(__file__).read_text(), base_helper_source=Path(base.__file__).read_text(),
        handler_source=ROLES_HANDLER, log_start_ms=int(time.time() * 1000),
        documentation=["https://docs.aws.amazon.com/apigateway/latest/api/API_CreateAuthorizer.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_UpdateAuthorizer.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html"],
        retry_contract="Bounded IAM/STS, deployment markers and positive authority readiness are separate from single-shot semantic requests; negative observations alone do not establish propagation.",
        unsampled_boundaries=["Cross-account roles and functions", "CloudTrail service-assumption events",
            "Cached STS credentials expiration and regional convergence", "Caller-identity passthrough runtime"],
        inconclusive=[], owned={})
    p.save()
    function, execution = create_function(p, ROLES_HANDLER)
    api = p.required("create-rest", "apigateway", "create_rest_api",
        {"name": name, "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    p.data["owned"].update(rest_endpoint=f"https://{api}.execute-api.{REGION}.amazonaws.com",
        authorizers=[], deployments=[], log_group="/aws/lambda/" + name)
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    source = f"arn:aws:execute-api:{REGION}:{account}:{api}"
    add_permission(p, "permission-integration", source + "/dev/*/*")
    p.required("policy-no-authorizer-grant", "lambda", "get_policy", {"FunctionName": name})
    roles = {}
    condition = {"ArnLike": {"aws:SourceArn": source + "/authorizers/*"},
                 "StringEquals": {"aws:SourceAccount": account}}
    for key in ("allow", "missing", "deny", "condition", "actor"):
        principal = {"AWS": p.data["identity"]["Arn"]} if key == "actor" else {"Service": "apigateway.amazonaws.com"}
        roles[key] = p.required("create-role-" + key, "iam", "create_role",
            {"RoleName": name + "-" + key, "AssumeRolePolicyDocument": role_trust(
                principal, condition if key == "condition" else None)},
            own=("credential_role_" + key, "Role.RoleName"))["Role"]
    invoke = {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]}
    for key in ("allow", "deny", "condition"):
        role_policy(p, roles[key], [invoke] + ([{**invoke, "Effect": "Deny"}] if key == "deny" else []))
    role_policy(p, execution, [invoke])
    parameters = {"restApiId": api, "name": "scratch", "type": "TOKEN", "authorizerUri": uri,
        "identitySource": "method.request.header.X-Auth", "authorizerResultTtlInSeconds": 0}
    authorizers = {}
    for key, kind, role in (("token", "TOKEN", roles["allow"]), ("request", "REQUEST", roles["allow"]),
            ("missing", "TOKEN", roles["missing"]), ("deny", "TOKEN", roles["deny"]),
            ("wrong", "TOKEN", execution), ("condition", "TOKEN", roles["condition"]), ("none", "TOKEN", None)):
        values = {**parameters, "name": key, "type": kind}
        if role:
            values["authorizerCredentials"] = role["Arn"]
        created = p.required("create-authorizer-" + key, "apigateway", "create_authorizer", values)
        authorizers[key] = created["id"]
        p.data["owned"]["authorizers"].append(created["id"])
        p.required("get-authorizer-" + key, "apigateway", "get_authorizer",
            {"restApiId": api, "authorizerId": created["id"]})
    p.data["authorizers"] = authorizers
    root = p.required("rest-resources", "apigateway", "get_resources", {"restApiId": api})["items"][0]["id"]
    for part in ("ready", *authorizers):
        resource = p.required("create-resource-" + part, "apigateway", "create_resource",
            {"restApiId": api, "parentId": root, "pathPart": part})["id"]
        put_route(p, api, resource, part, "GET", authorizers.get(part), uri)
    credentials_deploy(p, "initial")
    for key in ("token", "request"):
        if not credentials_ready(p, "role-" + key, "/dev/" + key):
            p.data["inconclusive"].append("Positive role invocation did not converge for " + key)
    p.phase = "semantic"
    for key in authorizers:
        http(p, key + "-initial", "/dev/" + key, headers={"X-Auth": "allow-" + key + "-initial"})
    # Test the absence of both context keys, rather than guessing the SourceArn shape.
    p.required("condition-trust-null", "iam", "update_assume_role_policy",
        {"RoleName": roles["condition"]["RoleName"], "PolicyDocument": role_trust(
            {"Service": "apigateway.amazonaws.com"}, {"Null": {"aws:SourceArn": "true", "aws:SourceAccount": "true"}})})
    null_ready = credentials_ready(p, "condition-null", "/dev/condition")
    http(p, "condition-null-semantic", "/dev/condition", headers={"X-Auth": "allow-condition-null"})
    if not null_ready:
        p.data["inconclusive"].append("Null SourceArn/SourceAccount trust did not converge; failure does not establish presence")
    p.required("condition-trust-unconditional", "iam", "update_assume_role_policy",
        {"RoleName": roles["condition"]["RoleName"],
         "PolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"})})
    if not credentials_ready(p, "condition-unconditional", "/dev/condition"):
        p.data["inconclusive"].append("Condition role unconditional repair did not converge")
    http(p, "condition-unconditional-semantic", "/dev/condition", headers={"X-Auth": "allow-condition-unconditional"})
    for key in ("missing", "deny", "wrong", "none"):
        http(p, key + "-after-readiness", "/dev/" + key, headers={"X-Auth": "allow-" + key + "-late"})
    for label, role in (("missing", roles["missing"]), ("restored", roles["allow"])):
        p.required("token-update-" + label, "apigateway", "update_authorizer",
            {"restApiId": api, "authorizerId": authorizers["token"], "patchOperations": [
                {"op": "replace", "path": "/authorizerCredentials", "value": role["Arn"]}]})
        p.required("token-get-" + label, "apigateway", "get_authorizer",
            {"restApiId": api, "authorizerId": authorizers["token"]})
        http(p, "token-" + label + "-before-deployment", "/dev/token",
            headers={"X-Auth": "allow-" + label + "-before-deployment"})
        credentials_deploy(p, "credentials-" + label)
        if label == "restored":
            credentials_ready(p, "token-restored", "/dev/token")
        http(p, "token-" + label + "-after-deployment", "/dev/token",
            headers={"X-Auth": "allow-" + label + "-after-deployment"})
    # Strings reach native API validation; no botocore-only type failures are used.
    for label, value in (("malformed", "not-an-arn"), ("empty", ""),
            ("user-arn", f"arn:aws:iam::{account}:user/does-not-exist"),
            ("missing-role", f"arn:aws:iam::{account}:role/{name}-never-created")):
        result = p.call("credentials-create-" + label, "apigateway", "create_authorizer",
            {**parameters, "name": "validation-" + label, "authorizerCredentials": value}, required=False)
        if result["code"] == "Success":
            identifier = result["output"]["id"]
            p.data["owned"]["authorizers"].append(identifier)
            p.required("credentials-get-" + label, "apigateway", "get_authorizer",
                {"restApiId": api, "authorizerId": identifier})
            p.required("credentials-delete-" + label, "apigateway", "delete_authorizer",
                {"restApiId": api, "authorizerId": identifier})
    for label, patch in (("malformed", {"op": "replace", "path": "/authorizerCredentials", "value": "not-an-arn"}),
            ("empty", {"op": "replace", "path": "/authorizerCredentials", "value": ""}),
            ("set", {"op": "replace", "path": "/authorizerCredentials", "value": roles["allow"]["Arn"]}),
            ("remove", {"op": "remove", "path": "/authorizerCredentials"})):
        p.call("credentials-update-" + label, "apigateway", "update_authorizer",
            {"restApiId": api, "authorizerId": authorizers["none"], "patchOperations": [patch]}, required=False)
        p.required("credentials-update-get-" + label, "apigateway", "get_authorizer",
            {"restApiId": api, "authorizerId": authorizers["none"]})
    passrole_cases(p, roles["actor"], parameters, roles["allow"])
    final = http(p, "final-backend-log-marker", "/dev/ready")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)
    p.data["condition_interpretation"] = (
        "Invocation succeeded after both Null=true conditions were installed, consistent with absent source context keys. Reuse of STS credentials issued under the earlier matching trust cannot be excluded without fresh-assumption evidence; initial matching-condition failure alone is not proof."
        if null_ready else "Source context remains inconclusive; consult bounded condition and unconditional readiness outcomes.")
    if null_ready:
        p.data["inconclusive"].append(
            "Mutable Null-trust success is consistent with absent source context keys, but does not independently exclude previously issued STS credentials")
    p.data["completed_at"] = now()
    p.save()


def run_fresh_null(p):
    name, account = p.data["prefix"], p.data["account"]
    p.data.update(mode="credentials-roles-fresh-null",
        scope="Fresh, never-before-assumable REST authorizer role with initial Null SourceArn/SourceAccount trust",
        bounds={"apis": 1, "functions": 1, "roles": 2, "function_log_groups": 1, "authorizers": 2,
                "readiness_attempts": 30, "readiness_delay_seconds": 3, "semantic_http_attempts": 1,
                "role_propagation_attempts": 15, "lambda_activation_attempts": 15,
                "log_poll_attempts": 12, "log_pages_per_poll": 4},
        probe_source=Path(__file__).read_text(), base_helper_source=Path(base.__file__).read_text(),
        handler_source=ROLES_HANDLER, log_start_ms=int(time.time() * 1000), inconclusive=[],
        retry_contract="Only bounded positive readiness and log delivery are polled. The role trust is never updated.",
        documentation=["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Null"])
    p.save()
    function, _ = create_function(p, ROLES_HANDLER)
    api = p.required("create-rest", "apigateway", "create_rest_api",
        {"name": name, "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    p.data["owned"].update(rest_endpoint=f"https://{api}.execute-api.{REGION}.amazonaws.com",
        authorizers=[], deployments=[], log_group="/aws/lambda/" + name)
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    source = f"arn:aws:execute-api:{REGION}:{account}:{api}"
    add_permission(p, "permission-integration", source + "/dev/*/*")
    p.required("policy-no-authorizer-grant", "lambda", "get_policy", {"FunctionName": name})
    role = p.required("create-role-initial-null", "iam", "create_role", {
        "RoleName": name + "-null", "AssumeRolePolicyDocument": role_trust(
            {"Service": "apigateway.amazonaws.com"}, {"Null": {"aws:SourceArn": "true", "aws:SourceAccount": "true"}})},
        own=("credential_role_null", "Role.RoleName"))["Role"]
    role_policy(p, role, [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]}])
    p.required("get-role-initial-null", "iam", "get_role", {"RoleName": role["RoleName"]})
    root = p.required("rest-resources", "apigateway", "get_resources", {"restApiId": api})["items"][0]["id"]
    for part in ("ready", "token", "request"):
        auth = None
        if part != "ready":
            auth = p.required("create-authorizer-" + part, "apigateway", "create_authorizer", {
                "restApiId": api, "name": part, "type": part.upper(), "authorizerUri": uri,
                "identitySource": "method.request.header.X-Auth", "authorizerResultTtlInSeconds": 0,
                "authorizerCredentials": role["Arn"]})["id"]
            p.data["owned"]["authorizers"].append(auth)
        resource = p.required("create-resource-" + part, "apigateway", "create_resource",
            {"restApiId": api, "parentId": root, "pathPart": part})["id"]
        put_route(p, api, resource, part, "GET", auth, uri)
    credentials_deploy(p, "fresh-null")
    successes = []
    p.phase = "semantic"
    for part in ("token", "request"):
        converged = credentials_ready(p, "initial-null-" + part, "/dev/" + part)
        result = http(p, "initial-null-" + part + "-semantic", "/dev/" + part,
            headers={"X-Auth": "allow-initial-null-" + part})
        successes.append(converged and result.get("status") == 200 and authorizer_uuid(result) is not None)
    p.required("get-role-unchanged-null", "iam", "get_role", {"RoleName": role["RoleName"]})
    final = http(p, "final-backend-log-marker", "/dev/ready")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)
    if all(successes):
        p.data["condition_interpretation"] = (
            "Observed TOKEN and REQUEST invocation through a newly created role whose only trust statement has always required both aws:SourceArn and aws:SourceAccount to be Null=true. No earlier permissive trust or credentials existed for this role. Both keys were absent in an accepted native API Gateway service assumption in this account/region.")
    else:
        p.data["condition_interpretation"] = "Fresh initial-Null trust did not establish both successful runtime cases within the bound."
        p.data["inconclusive"].append("Negative bounded results cannot establish source-key presence or rule out propagation.")
    p.data["completed_at"] = now()
    p.save()


def service_context_organization(p):
    result = p.call("organization-membership", "organizations", "describe_organization", required=False)
    metadata = {"describe_code": result["code"], "account_id": p.data["account"],
        "read_only": True}
    p.data["organization_membership"] = metadata
    if result["code"] == "AWSOrganizationsNotInUseException":
        metadata["membership"] = "none"
    elif result["code"] != "Success":
        metadata["membership"] = "unknown"
        p.data["inconclusive"].append("Organization membership lookup returned " + result["code"])
    else:
        organization = result["output"]["Organization"]
        metadata.update(membership="member", organization_id=organization["Id"],
            organization_arn=organization["Arn"], feature_set=organization["FeatureSet"],
            management_account_id=organization.get("ManagementAccountId", organization.get("MasterAccountId")))
        child, ancestors = p.data["account"], []
        for depth in range(10):
            parent = p.call("organization-parent-" + str(depth), "organizations", "list_parents",
                {"ChildId": child}, required=False)
            if parent["code"] != "Success" or len(parent["output"].get("Parents", [])) != 1:
                p.data["inconclusive"].append("Organization ancestry was not fully observable")
                break
            ancestor = parent["output"]["Parents"][0]
            ancestors.append(ancestor)
            if ancestor["Type"] == "ROOT":
                metadata["organization_path"] = organization["Id"] + "/" + "/".join(
                    item["Id"] for item in reversed(ancestors)) + "/"
                break
            child = ancestor["Id"]
        else:
            p.data["inconclusive"].append("Organization ancestry exceeded ten read-only lookups")
        metadata["ancestors_nearest_first"] = ancestors
    p.save()


def run_service_context(p, *, principal_types=False):
    name, account = p.data["prefix"], p.data["account"]
    mode = "principal-types" if principal_types else "service-context"
    cases = {
        "control": None,
        "principal-service": {"StringEquals": {"aws:PrincipalType": "Service"}},
        "principal-awsservice": {"StringEquals": {"aws:PrincipalType": "AWSService"}},
        "source-org-id-absent": {"Null": {"aws:SourceOrgID": "true"}},
        "source-org-paths-absent": {"Null": {"aws:SourceOrgPaths": "true"}},
    } if not principal_types else {
        "control": None,
        "principal-absent": {"Null": {"aws:PrincipalType": "true"}},
        "principal-account": {"StringEquals": {"aws:PrincipalType": "Account"}},
        "principal-assumedrole": {"StringEquals": {"aws:PrincipalType": "AssumedRole"}},
        "principal-anonymous": {"StringEquals": {"aws:PrincipalType": "Anonymous"}},
    }
    p.data.update(mode=mode,
        scope="Fresh immutable API Gateway service trust roles, both REST TOKEN and REQUEST authorizers",
        bounds={"apis": 1, "functions": 1, "roles": 6, "function_log_groups": 1, "authorizers": 10,
                "readiness_attempts": 30, "readiness_delay_seconds": 3, "semantic_rounds": 3,
                "semantic_round_delay_seconds": 5, "role_propagation_attempts": 15,
                "lambda_activation_attempts": 15, "log_poll_attempts": 12, "log_pages_per_poll": 4,
                "organization_ancestor_lookups": 10},
        probe_source=Path(__file__).read_text(), base_helper_source=Path(base.__file__).read_text(),
        handler_source=ROLES_HANDLER, log_start_ms=int(time.time() * 1000), inconclusive=[],
        trust_cases=cases,
        retry_contract="Immutable initial trust. Positive control readiness precedes interleaved candidate readiness; all attempts are retained separately from three semantic rounds. Persistent failures alone cannot exclude role-specific propagation.",
        documentation=["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Null"])
    p.save()
    service_context_organization(p)
    function, _ = create_function(p, ROLES_HANDLER)
    api = p.required("create-rest", "apigateway", "create_rest_api",
        {"name": name, "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    p.data["owned"].update(rest_endpoint=f"https://{api}.execute-api.{REGION}.amazonaws.com",
        authorizers=[], deployments=[], log_group="/aws/lambda/" + name)
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    source = f"arn:aws:execute-api:{REGION}:{account}:{api}"
    add_permission(p, "permission-integration", source + "/dev/*/*")
    p.required("policy-no-authorizer-grant", "lambda", "get_policy", {"FunctionName": name})
    roles = {}
    invoke = {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]}
    for case, condition in cases.items():
        roles[case] = p.required("create-role-" + case, "iam", "create_role", {
            "RoleName": name + "-" + case,
            "AssumeRolePolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"}, condition)},
            own=("credential_role_" + case, "Role.RoleName"))["Role"]
        role_policy(p, roles[case], [invoke])
        p.required("get-role-initial-" + case, "iam", "get_role", {"RoleName": roles[case]["RoleName"]})
    root = p.required("rest-resources", "apigateway", "get_resources", {"restApiId": api})["items"][0]["id"]
    routes = {}
    for case in cases:
        for kind in ("token", "request"):
            part = case + "-" + kind
            auth = p.required("create-authorizer-" + part, "apigateway", "create_authorizer", {
                "restApiId": api, "name": part, "type": kind.upper(), "authorizerUri": uri,
                "identitySource": "method.request.header.X-Auth", "authorizerResultTtlInSeconds": 0,
                "authorizerCredentials": roles[case]["Arn"]})["id"]
            p.data["owned"]["authorizers"].append(auth)
            routes[part] = {"case": case, "type": kind.upper(), "authorizer_id": auth}
            p.required("get-authorizer-" + part, "apigateway", "get_authorizer",
                {"restApiId": api, "authorizerId": auth})
    p.data["service_context_routes"] = routes
    for part in ("ready", *routes):
        resource = p.required("create-resource-" + part, "apigateway", "create_resource",
            {"restApiId": api, "parentId": root, "pathPart": part})["id"]
        put_route(p, api, resource, part, "GET", routes.get(part, {}).get("authorizer_id"), uri)
    credentials_deploy(p, mode)
    p.phase = "readiness"
    for kind in ("token", "request"):
        part = "control-" + kind
        if not credentials_ready(p, part, "/dev/" + part):
            p.data["inconclusive"].append("Unconditional baseline did not converge for " + kind)
            raise RuntimeError("Cannot interpret conditions without a successful unconditioned baseline")
    pending = [part for part, route in routes.items() if route["case"] != "control"]
    started = now()
    for attempt in range(30):
        for part in pending[:]:
            result = http(p, part + "-readiness-" + str(attempt), "/dev/" + part,
                headers={"X-Auth": "allow-" + part + "-readiness-" + str(attempt)}, phase="readiness")
            observed = result.get("status") == 200 and authorizer_uuid(result) is not None
            p.data["readiness"][part] = {"started_at": started, "finished_at": now(),
                "observed": observed, "attempts": attempt + 1, "limit": 30, "delay_seconds": 3,
                "expected": {"status": 200, "authorizer_invocation": "present"}}
            if observed:
                pending.remove(part)
        p.save()
        if not pending:
            break
        if attempt != 29:
            time.sleep(3)
    p.phase = "semantic"
    for round_number in range(1, 4):
        for part in routes:
            label = part + "-round-" + str(round_number)
            http(p, label, "/dev/" + part, headers={"X-Auth": "allow-" + label})
        if round_number != 3:
            time.sleep(5)
    for case, role in roles.items():
        p.required("get-role-unchanged-" + case, "iam", "get_role", {"RoleName": role["RoleName"]})
    p.required("policy-still-no-authorizer-grant", "lambda", "get_policy", {"FunctionName": name})
    final = http(p, "final-backend-log-marker", "/dev/ready")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)
    outcomes = {}
    for part, route in routes.items():
        rows = [row for row in p.data["http"] if row["phase"] == "semantic"
                and row["path"] == "/dev/" + part]
        invocations = [authorizer_uuid(row["result"]) for row in rows]
        log_matches = [invocation is not None and invocation in p.data["authorizer_invocations_by_token"].get(
            row["request_headers"]["X-Auth"], []) for row, invocation in zip(rows, invocations)]
        proven = all(row["result"].get("status") == 200 for row in rows) and all(log_matches)
        outcomes[part] = {**route, "readiness_observed": p.data["readiness"][part]["observed"],
            "semantic_statuses": [row["result"].get("status") for row in rows],
            "authorizer_invocation_ids": invocations, "matching_authorizer_logs": log_matches,
            "successful_all_semantic_rounds": proven,
            "observation": "Immutable initial trust admitted actual authorizer invocation" if proven else
                "No repeatable successful invocation established; negative observations alone cannot exclude propagation"}
        if not proven:
            p.data["inconclusive"].append(part + ": bounded negative observations do not independently exclude role-specific propagation")
    p.data["service_context_results"] = outcomes
    admitted = {case for case in cases
                if all(outcomes[case + "-" + kind]["successful_all_semantic_rounds"] for kind in ("token", "request"))}
    p.data["condition_interpretation"] = {
        "principal_type_values_admitted": [condition["StringEquals"]["aws:PrincipalType"]
            for case, condition in cases.items() if case in admitted and condition
            and "aws:PrincipalType" in condition.get("StringEquals", {})],
        "principal_type_proven_absent": any(case in admitted and condition
            and condition.get("Null", {}).get("aws:PrincipalType") == "true" for case, condition in cases.items()),
        "source_keys_proven_absent": [key for case, condition in cases.items() if case in admitted and condition
            for key, value in condition.get("Null", {}).items() if key.startswith("aws:Source") and value == "true"],
        "scope": "Accepted fresh immutable service trust, both authorizer types, this account/region only. No context value is inferred from a CloudTrail identity label."}
    p.data["completed_at"] = now()
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--credentials-roles", action="store_true")
    parser.add_argument("--fresh-null-trust", action="store_true",
        help="Append a second bounded fresh-role discriminator to the completed credentials fixture")
    parser.add_argument("--service-context", action="store_true",
        help="Capture fresh immutable service PrincipalType and source-organization trust conditions")
    parser.add_argument("--principal-types", action="store_true",
        help="Capture fresh immutable PrincipalType Null/Account/AssumedRole/Anonymous conditions")
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    if sum((args.service_context, args.principal_types, args.credentials_roles or args.fresh_null_trust)) > 1:
        parser.error("--service-context, --principal-types and --credentials-roles are separate capture modes")
    path = args.output or Path(".stackd/probes/apigateway/" + (
        "rest_authorizer_principal_type.json" if args.principal_types else
        "rest_authorizer_service_context.json" if args.service_context else
        "rest_authorizer_roles.json" if args.credentials_roles else "rest_lambda_authorizers.json"))
    envelope = json.loads(path.read_text()) if args.fresh_null_trust or args.cleanup_only else None
    principal_types = args.principal_types or bool(args.cleanup_only and envelope.get("mode") == "principal-types")
    service_context = principal_types or args.service_context or bool(
        args.cleanup_only and envelope.get("mode") == "service-context")
    credentials_mode = service_context or args.credentials_roles or (
        args.cleanup_only and envelope.get("mode") == "credentials-roles")
    fresh_null = args.fresh_null_trust or bool(args.cleanup_only and envelope.get("fresh_null_capture")
        and not envelope["fresh_null_capture"].get("cleanup", {}).get("complete", False))
    if fresh_null:
        if not credentials_mode or envelope.get("mode") != "credentials-roles":
            parser.error("--fresh-null-trust requires an existing --credentials-roles capture")
        if args.cleanup_only:
            probe = CredentialsProbe(path, args.account, True)
            probe.envelope, probe.data = envelope, envelope["fresh_null_capture"]
        else:
            if not envelope["cleanup"].get("complete") or "fresh_null_capture" in envelope:
                parser.error("The first capture must be cleaned, with no existing fresh-null capture")
            # Initialize using the common Probe contract before any AWS resource is created.
            with tempfile.TemporaryDirectory(prefix="stackd-rest-authorizer-") as directory:
                probe = CredentialsProbe(Path(directory) / "capture.json", args.account, False)
            probe.path, probe.envelope = path, envelope
            probe.save()
    else:
        probe = (CredentialsProbe if credentials_mode else Probe)(path, args.account, args.cleanup_only)
    try:
        if not args.cleanup_only:
            if service_context:
                run_service_context(probe, principal_types=principal_types)
            else:
                (run_fresh_null if fresh_null else run_credentials if credentials_mode else run)(probe)
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            for client in probe.clients.values():
                client.close()


if __name__ == "__main__":
    main()
