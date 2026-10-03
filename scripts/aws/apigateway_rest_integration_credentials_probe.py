#!/usr/bin/env python3
"""Capture owned native REST Lambda integration credentials; always clean up resources."""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import time

import apigateway_probe as base
import apigateway_rest_authorizer_probe as shared
from apigateway_probe import REGION, now
from apigateway_rest_authorizer_probe import CredentialsProbe, collect_logs, create_function, role_policy, role_trust

SENTINEL = "arn:aws:iam::*:user/*"
HANDLER = '''import json
import uuid


def handler(event, context):
    invocation = str(uuid.uuid4())
    headers = {key.lower(): value for key, value in (event.get("headers") or {}).items()}
    print(json.dumps({"probe_kind": "backend", "invocation": invocation,
                      "lambdaRequestId": context.aws_request_id, "probe": headers.get("x-probe"),
                      "event": event, "invoked_function_arn": context.invoked_function_arn}))
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"backendInvocationId": invocation, "event": event})}
'''


def request(p, label, part, *, signed=False, phase="semantic"):
    headers = {"User-Agent": "stackd-rest-authorizer-probe", "X-Probe": label}
    path = "/dev/" + part
    if signed:
        credentials = p.session.get_credentials().get_frozen_credentials()
        for key in (credentials.access_key, credentials.secret_key, credentials.token):
            if key:
                p.hide(key, "signing-credential")
        wire = base.AWSRequest(method="GET", url=p.data["owned"]["rest_endpoint"] + path, headers=headers)
        base.SigV4Auth(credentials, "execute-api", REGION).add_auth(wire)
        headers = dict(wire.headers)
        p.hide(headers["Authorization"], "authorization")
        p.hide(headers["Authorization"].split("Signature=", 1)[1], "signature")
    result = shared.http(p, label, path, headers=headers, phase=phase)
    row = p.data["http"][-1]
    row.update(actor=getattr(p, "actor", p.data["identity"]) if signed else {"type": "anonymous"},
               authorization="iam" if signed else "none", url=p.data["owned"]["rest_endpoint"] + path)
    p.save()
    return result


def ready(p, label, part, *, signed=False, limit=30):
    started, streak = now(), 0
    for attempt in range(limit):
        result = request(p, label + "-" + str(attempt), part, signed=signed, phase="readiness")
        positive = result.get("status") == 200 and result.get("body", {}).get("backendInvocationId")
        streak = streak + 1 if positive else 0
        if streak == 3:
            observed = True
            break
        time.sleep(3)
    else:
        observed = False
    p.data.setdefault("readiness", {})[label] = {"started_at": started, "finished_at": now(),
        "attempts": attempt + 1, "limit": limit, "delay_seconds": 3,
        "three_consecutive_positive_backend_samples": observed, "final_positive_streak": streak}
    if not observed:
        p.data["inconclusive"].append(label + ": positive backend readiness did not converge within bound")
    p.save()
    return observed


def parameters(p, part):
    return {"restApiId": p.data["owned"]["rest_api"], "resourceId": p.data["resources"][part], "httpMethod": "GET"}


def integration(p, label, part, *, method="get_integration", values=None):
    result = p.call(label, "apigateway", method, {**parameters(p, part), **(values or {})}, required=False)
    output = result.get("output", {})
    p.data.setdefault("integration_fields", []).append({"label": label, "part": part,
        "code": result["code"], "http_status": result.get("http_status"),
        "credentials_present": "credentials" in output, "credentials": output.get("credentials"),
        "output_fields": sorted(output)})
    p.save()
    return result


def put(p, label, part, credentials=..., *, required=True):
    values = {"type": "AWS_PROXY", "integrationHttpMethod": "POST", "uri": p.data["integration_uri"]}
    if credentials is not ...:
        values["credentials"] = credentials
    # RestJSONSerializer skips top-level Python None even with validation disabled.
    # Inject and record the literal JSON null after serialization, before SDK signing.
    def explicit_null(params, **kwargs):
        body = json.loads(params["body"])
        body["credentials"] = None
        params["body"] = json.dumps(body).encode()
        p.data.setdefault("explicit_null_wire_requests", []).append(
            {"label": label, "method": params["method"], "url": params["url"], "body": body})

    events = p.client("apigateway").meta.events
    if credentials is None:
        events.register("before-call.*.PutIntegration", explicit_null)
    try:
        result = integration(p, label, part, method="put_integration", values=values)
    finally:
        if credentials is None:
            events.unregister("before-call.*.PutIntegration", explicit_null)
    if required and result["code"] != "Success":
        raise RuntimeError(label + ": " + result["code"])
    return result


def patch(p, label, part, operations):
    result = integration(p, label, part, method="update_integration", values={"patchOperations": operations})
    integration(p, label + "-get", part)
    return result


def route(p, part, credentials=..., *, auth="NONE"):
    resource = p.required("create-resource-" + part, "apigateway", "create_resource",
        {"restApiId": p.data["owned"]["rest_api"], "parentId": p.data["root"], "pathPart": part})["id"]
    p.data["resources"][part] = resource
    p.required("put-method-" + part, "apigateway", "put_method",
        {**parameters(p, part), "authorizationType": auth})
    put(p, "put-integration-" + part, part, credentials)
    integration(p, "get-integration-" + part, part)


def deploy(p, label, *, required=True):
    # A new successfully invoked resource proves the deployed route tree advanced;
    # stage variables alone are mutable stage state, not sufficient snapshot evidence.
    p.phase = "readiness"
    marker = "marker-" + str(len(p.data["owned"]["deployments"]))
    route(p, marker, p.data["roles"]["allow"]["Arn"])
    result = p.call("deploy-" + label, "apigateway", "create_deployment",
        {"restApiId": p.data["owned"]["rest_api"], "stageName": "dev", "variables": {"Transition": label}},
        required=required)
    if result["code"] != "Success":
        p.phase = "semantic"
        return False
    p.data["owned"]["deployments"].append(result["output"]["id"])
    p.required("stage-" + label, "apigateway", "get_stage",
        {"restApiId": p.data["owned"]["rest_api"], "stageName": "dev"})
    if not ready(p, "deploy-" + label, marker):
        raise RuntimeError("New deployment marker did not execute: " + label)
    p.phase = "semantic"
    return True


def sample_snapshot(p, label, expected):
    started, clock, streak = now(), time.monotonic(), 0
    for attempt in range(24):
        target = request(p, label + "-target-" + str(attempt), "snapshot", phase="propagation")
        control = request(p, label + "-control-" + str(attempt), "ready", phase="propagation")
        denied = request(p, label + "-denied-witness-" + str(attempt), "deny", phase="propagation")
        matches = (target.get("status") == expected and control.get("status") == 200
                   and denied.get("status") == 500
                   and (expected != 200 or target.get("body", {}).get("backendInvocationId")))
        streak = streak + 1 if matches else 0
        if streak >= 4 and time.monotonic() - clock >= 30:
            break
        time.sleep(5)
    observed = streak >= 4 and time.monotonic() - clock >= 30
    p.data.setdefault("deployment_sampling", {})[label] = {"started_at": started, "finished_at": now(),
        "attempts": attempt + 1, "limit": 24, "delay_seconds": 5, "minimum_elapsed_seconds": 30,
        "consecutive_matching_samples": streak, "observed": observed, "expected_snapshot_status": expected,
        "scope": "Bounded route samples paired with successful backend and immutable explicit-deny controls; not global regional convergence or STS-cache evidence."}
    if not observed:
        p.data["inconclusive"].append(label + ": bounded paired deployment samples did not establish the requested transition")
    p.save()


def actor_statements(p):
    api = p.data["owned"]["rest_api"]
    scope = f"arn:aws:apigateway:{REGION}::/restapis/{api}/resources/{p.data['resources']['actor']}/methods/GET/integration"
    return [{"Effect": "Allow", "Action": ["apigateway:GET", "apigateway:PUT", "apigateway:PATCH"], "Resource": scope},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": p.data["roles"]["allow"]["Arn"],
         "Condition": {"StringEquals": {"iam:PassedToService": "apigateway.amazonaws.com"}}},
        {"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api}/dev/GET/*"},
        p.data["invoke_statement"]]


@contextmanager
def actor(p, label, deny_action=None, *, lambda_condition=None, deny_resource=None):
    statements = actor_statements(p)
    if lambda_condition is not None:
        statements[-1] = {**statements[-1], "Condition": lambda_condition}
    if deny_action:
        statements.append({"Effect": "Deny", "Action": deny_action,
            "Resource": deny_resource or (p.data["roles"]["allow"]["Arn"]
                if deny_action == "iam:PassRole" else p.data["function_arn"])})
    p.phase = "readiness"
    for attempt in range(20):
        result = p.call(f"assume-actor-{label}-{attempt}", "sts", "assume_role",
            {"RoleArn": p.data["roles"]["actor"]["Arn"], "RoleSessionName": "rest-integration-" + label,
             "DurationSeconds": 900, "Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}, required=False)
        if result["code"] == "Success":
            break
        time.sleep(3)
    if result["code"] != "Success":
        raise RuntimeError("Scoped actor did not become assumable: " + label)
    credentials = result["output"]["Credentials"]
    session = base.boto3.Session(region_name=REGION, aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
    original_session, original_clients = p.session, p.clients
    p.session, p.clients = session, {}
    try:
        p.actor = result["output"]["AssumedRoleUser"]
        p.actor = p.required("actor-identity-" + label, "sts", "get_caller_identity")
        for attempt in range(20):
            result = integration(p, f"actor-ready-{label}-{attempt}", "actor")
            if result["code"] == "Success":
                break
            time.sleep(3)
        if result["code"] != "Success":
            raise RuntimeError("Scoped actor API permission did not converge: " + label)
        p.phase = "semantic"
        yield
    finally:
        for client in p.clients.values():
            client.close()
        p.session, p.clients, p.actor = original_session, original_clients, p.data["identity"]
        p.phase = "semantic"


def caller_context_cases(p):
    cases = [
        ("context-plain-before", None),
        ("context-via-true", {"Bool": {"aws:ViaAWSService": "true"}}),
        ("context-via-false", {"Bool": {"aws:ViaAWSService": "false"}}),
        ("context-via-absent", {"Null": {"aws:ViaAWSService": "true"}}),
        ("context-calledvia-gateway", {"ForAnyValue:StringEquals": {"aws:CalledVia": "apigateway.amazonaws.com"}}),
        ("context-calledvia-absent", {"Null": {"aws:CalledVia": "true"}}),
        ("context-plain-after", None),
    ]
    p.data["caller_context_contract"] = (
        "Immutable STS session policies keep execute-api:Invoke and API read authority unconditional; "
        "only lambda:InvokeFunction Allow is conditioned. Each sentinel request is paired with a signed "
        "IAM route whose integration assumes the allowed role, plus plain sentinel controls before/after.")
    for label, condition in cases:
        with actor(p, label, lambda_condition=condition):
            if label == "context-plain-before":
                ready(p, label + "-ready", "sentinel-iam", signed=True)
            request(p, label + "-role-control", "iam-role", signed=True)
            request(p, label + "-sentinel", "sentinel-iam", signed=True)
    p.required("scoped-control-method-iam", "apigateway", "update_method",
        {**parameters(p, "actor"), "patchOperations": [
            {"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"}]})
    with actor(p, "context-passrole-deny-all", "iam:PassRole", deny_resource="*"):
        put(p, "scoped-sentinel-put-passrole-denied", "actor", SENTINEL, required=False)
        patch(p, "scoped-sentinel-update-passrole-denied", "actor",
            [{"op": "replace", "path": "/credentials", "value": SENTINEL}])
        for kind in ("role", "user"):
            put(p, "scoped-absent-" + kind + "-passrole-denied", "actor",
                f"arn:aws:iam::{p.data['account']}:{kind}/{p.data['prefix']}-never-created", required=False)
            integration(p, "scoped-absent-" + kind + "-followup", "actor")


def run(p, *, caller_context_only=False):
    name, account = p.data["prefix"], p.data["account"]
    source = Path(__file__).read_text()
    p.data.update(mode="rest-integration-credentials", scope="Owned regional REST Lambda AWS_PROXY integration credentials only; no authorizers or account settings",
        bounds={"apis": 1, "functions": 1, "roles": 9, "log_groups": 1, "resources": 24,
            "sdk_total_max_attempts": 1, "readiness_attempts": 30, "readiness_interval_seconds": 3,
            "actor_readiness_attempts": 20, "semantic_http_attempts": 1,
            "snapshot_propagation_attempts": 24, "snapshot_propagation_interval_seconds": 5,
            "log_poll_attempts": 12, "log_pages_per_poll": 4, "cleanup_attempts": 3},
        probe_source=source, source_sha256=hashlib.sha256(source.encode()).hexdigest(), handler_source=HANDLER,
        helper_sources={Path(module.__file__).name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                        for module in (base, shared)}, log_start_ms=int(time.time() * 1000),
        documentation=["https://docs.aws.amazon.com/apigateway/latest/api/API_PutIntegration.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_GetIntegration.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/API_UpdateIntegration.html"],
        retry_contract="Positive backend/actor/deployment readiness and explicitly labeled bounded paired deployment-propagation samples are separate from single-shot semantic requests. A policy acknowledgement, single positive marker or repeated failure is not global convergence proof.",
        limitations=["Single account and region, Lambda AWS_PROXY GET methods only; not non-proxy or other service integrations.",
            "No claim about STS caching, session names, duration or regional convergence without direct service-assumption evidence.",
            "Fresh immutable trust conditions compare source-key absence/presence and AssumedRole PrincipalType; negative samples alone cannot prove a missing context key.",
            "Primary signed samples use the native SDK caller identity recorded in the fixture; narrowly scoped caller-authority comparisons use assumed-role sessions."],
        owned={}, resources={}, roles={}, inconclusive=[])
    p.data["capture_focus"] = "caller-context-only" if caller_context_only else "complete"
    # Permit Python None as probe input; put() records its literal-null wire injection.
    original = p.client("apigateway")
    config = original.meta.config.merge(base.Config(parameter_validation=False))
    original.close()
    p.clients["apigateway"] = p.session.client("apigateway", config=config)
    p.data["sdk"]["apigateway_parameter_validation"] = False
    p.save()
    function, execution = create_function(p, HANDLER)
    p.data["function_arn"] = function["FunctionArn"]
    api = p.required("create-rest", "apigateway", "create_rest_api",
        {"name": name, "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    p.data["owned"].update(rest_endpoint=f"https://{api}.execute-api.{REGION}.amazonaws.com", deployments=[])
    p.data["root"] = p.required("rest-resources", "apigateway", "get_resources", {"restApiId": api})["items"][0]["id"]
    p.data["integration_uri"] = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    p.data["invoke_statement"] = {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function["FunctionArn"]}
    conditions = {"nullsource": {"Null": {"aws:SourceArn": "true", "aws:SourceAccount": "true"}},
        "presentsource": {"Null": {"aws:SourceArn": "false", "aws:SourceAccount": "false"}},
        "assumed": {"StringEquals": {"aws:PrincipalType": "AssumedRole"}}}
    for key in ("allow", "missing", "deny", "wrong", "nullsource", "presentsource", "assumed", "actor"):
        principal = ({"AWS": p.data["identity"]["Arn"]} if key == "actor" else
                     {"Service": "lambda.amazonaws.com" if key == "wrong" else "apigateway.amazonaws.com"})
        role = p.required("create-role-" + key, "iam", "create_role",
            {"RoleName": name + "-" + key, "AssumeRolePolicyDocument": role_trust(principal, conditions.get(key))},
            own=("credential_role_" + key, "Role.RoleName"))["Role"]
        p.data["roles"][key] = role
        if key not in ("missing", "actor"):
            role_policy(p, role, [p.data["invoke_statement"]] +
                ([{**p.data["invoke_statement"], "Effect": "Deny"}] if key == "deny" else []))
    p.call("function-resource-policy-initially-absent", "lambda", "get_policy", {"FunctionName": name}, required=False)
    for part, role in (("ready", "allow"), ("snapshot", "allow"), ("missing", "missing"), ("deny", "deny"),
                       ("wrong", "wrong"), ("nullsource", "nullsource"), ("presentsource", "presentsource"), ("assumed", "assumed")):
        route(p, part, p.data["roles"][role]["Arn"])
    route(p, "absentrole", f"arn:aws:iam::{account}:role/{name}-never-created")
    for part in ("omitted", "scratch", "actor"):
        route(p, part)
    route(p, "sentinel-none")
    p.phase = "semantic"
    put(p, "sentinel-with-none-auth-admission", "sentinel-none", SENTINEL, required=False)
    integration(p, "sentinel-with-none-auth-followup", "sentinel-none")
    route(p, "sentinel-iam", SENTINEL, auth="AWS_IAM")
    route(p, "iam-role", p.data["roles"]["allow"]["Arn"], auth="AWS_IAM")
    role_policy(p, p.data["roles"]["actor"], actor_statements(p))
    if caller_context_only:
        put(p, "admission-literal-null-wire", "scratch", None)
        integration(p, "admission-literal-null-wire-get", "scratch")
        deploy(p, "caller-context")
        caller_context_cases(p)
        finish(p)
        return
    p.phase = "semantic"
    for label, value in (("omitted", ...), ("empty", ""), ("null", None), ("malformed", "not-an-arn"),
            ("user", f"arn:aws:iam::{account}:user/{name}-never-created"),
            ("absent-role", f"arn:aws:iam::{account}:role/{name}-never-created"), ("sentinel", SENTINEL),
            ("allow", p.data["roles"]["allow"]["Arn"])):
        put(p, "admission-put-" + label, "scratch", value, required=False)
        integration(p, "admission-get-" + label, "scratch")
    for label, operation in (("malformed", {"op": "replace", "path": "/credentials", "value": "not-an-arn"}),
            ("empty", {"op": "replace", "path": "/credentials", "value": ""}),
            ("allow", {"op": "replace", "path": "/credentials", "value": p.data["roles"]["allow"]["Arn"]}),
            ("sentinel", {"op": "replace", "path": "/credentials", "value": SENTINEL}),
            ("remove", {"op": "remove", "path": "/credentials"}),
            ("remove-again", {"op": "remove", "path": "/credentials"}),
            ("add", {"op": "add", "path": "/credentials", "value": p.data["roles"]["allow"]["Arn"]})):
        patch(p, "admission-update-" + label, "scratch", [operation])
    deploy(p, "initial")
    for part in ("ready", "snapshot", "missing", "deny", "wrong", "absentrole", "omitted", "nullsource", "presentsource", "assumed"):
        request(p, part + "-initial", part)
    for part in ("nullsource", "assumed"):
        ready(p, part + "-fresh-role", part)
        request(p, part + "-after-readiness", part)
    for part in ("missing", "deny", "wrong", "presentsource", "absentrole"):
        request(p, part + "-late-before-repair", part)
    # Authority/trust repairs on existing deployed integrations, without redeployment.
    role_policy(p, p.data["roles"]["missing"], [p.data["invoke_statement"]])
    ready(p, "missing-authority-repaired", "missing")
    request(p, "missing-authority-repaired-semantic", "missing")
    p.required("wrong-trust-repair", "iam", "update_assume_role_policy",
        {"RoleName": p.data["roles"]["wrong"]["RoleName"], "PolicyDocument": role_trust({"Service": "apigateway.amazonaws.com"})})
    ready(p, "wrong-trust-repaired", "wrong")
    request(p, "wrong-trust-repaired-semantic", "wrong")
    # This deny role remains immutable until all replacement/removal samples finish.
    for label, value in (("denied", p.data["roles"]["deny"]["Arn"]), ("restored", p.data["roles"]["allow"]["Arn"]), ("removed", "")):
        result = patch(p, "snapshot-update-" + label, "snapshot",
            [{"op": "replace", "path": "/credentials", "value": value}])
        if result["code"] != "Success":
            raise RuntimeError("Snapshot credentials update was not admitted: " + label)
        request(p, "snapshot-" + label + "-before-deployment", "snapshot")
        deploy(p, "snapshot-" + label)
        sample_snapshot(p, "snapshot-" + label, 200 if label == "restored" else 500)
        request(p, "snapshot-" + label + "-after-deployment", "snapshot")
        request(p, "deny-witness-" + label, "deny")
    role_policy(p, p.data["roles"]["deny"], [p.data["invoke_statement"]])
    ready(p, "deny-authority-repaired", "deny")
    request(p, "deny-authority-repaired-semantic", "deny")
    for part in ("omitted", "snapshot"):
        p.required("resource-permission-" + part, "lambda", "add_permission",
            {"FunctionName": name, "StatementId": "resource-" + part, "Action": "lambda:InvokeFunction",
             "Principal": "apigateway.amazonaws.com", "SourceArn": f"arn:aws:execute-api:{REGION}:{account}:{api}/dev/GET/{part}", "SourceAccount": account})
        ready(p, "resource-policy-" + part, part)
        request(p, part + "-resource-policy-semantic", part)
    p.required("function-resource-policy-scoped", "lambda", "get_policy", {"FunctionName": name})
    for part in ("sentinel-iam", "iam-role"):
        request(p, part + "-unsigned", part)
        request(p, part + "-primary-signed", part, signed=True)
    for mode, deny_action in (("passrole-deny", "iam:PassRole"), ("allow", None), ("lambda-deny", "lambda:InvokeFunction")):
        with actor(p, mode, deny_action):
            if mode != "lambda-deny":
                put(p, mode + "-put-omitted", "actor", required=False)
                put(p, mode + "-put-role", "actor", p.data["roles"]["allow"]["Arn"], required=False)
                integration(p, mode + "-get-after-put", "actor")
                patch(p, mode + "-update-role", "actor", [{"op": "replace", "path": "/credentials", "value": p.data["roles"]["allow"]["Arn"]}])
            if mode != "passrole-deny":
                ready(p, mode + "-execute-api-control", "iam-role", signed=True)
                for part in ("iam-role", "sentinel-iam"):
                    request(p, mode + "-" + part, part, signed=True)
    caller_context_cases(p)
    mutation = p.call("sentinel-method-auth-none", "apigateway", "update_method",
        {**parameters(p, "sentinel-iam"), "patchOperations": [
            {"op": "replace", "path": "/authorizationType", "value": "NONE"}]}, required=False)
    p.required("sentinel-method-after-auth-update", "apigateway", "get_method", parameters(p, "sentinel-iam"))
    if mutation["code"] == "Success" and deploy(p, "sentinel-auth-none", required=False):
        for attempt in range(6):
            request(p, "sentinel-auth-none-unsigned-propagation-" + str(attempt), "sentinel-iam", phase="propagation")
            request(p, "sentinel-auth-none-signed-propagation-" + str(attempt), "sentinel-iam", signed=True, phase="propagation")
            time.sleep(5)
    request(p, "sentinel-after-auth-mutation-unsigned", "sentinel-iam")
    request(p, "sentinel-after-auth-mutation-signed", "sentinel-iam", signed=True)
    finish(p)


def finish(p):
    final = request(p, "final-backend-log-marker", "ready")
    collect_logs(p, final["body"]["backendInvocationId"])
    by_label = {}
    for entry in p.data["invocation_logs"]:
        by_label.setdefault(entry["record"].get("probe"), []).append(entry["record"]["invocation"])
    p.data["semantic_summary"] = {row["label"]: {"status": row["result"].get("status"),
        "backend_invocation": row["result"].get("body", {}).get("backendInvocationId"),
        "correlated_log_invocations": by_label.get(row["label"], [])}
        for row in p.data["http"] if row["phase"] == "semantic"}
    p.data["completed_at"] = now()
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/rest_integration_credentials.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--caller-context-only", action="store_true",
        help="Run only the scoped caller-condition comparisons with fresh owned prerequisites")
    args = parser.parse_args()
    probe = CredentialsProbe(args.output, args.account, args.cleanup_only)
    try:
        if not args.cleanup_only:
            run(probe, caller_context_only=args.caller_context_only)
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        try:
            for attempt in range(3):
                try:
                    probe.cleanup()
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(3)
        finally:
            for client in probe.clients.values():
                client.close()


if __name__ == "__main__":
    main()
