#!/usr/bin/env python3
"""Capture bounded owned REST API-key enforcement with real Lambda and invocation logs."""
import argparse
import datetime
import json
from pathlib import Path
import tempfile
import time
import uuid

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from apigateway_probe import Probe, REGION, now
from apigateway_rest_authorizer_probe import create_function, http, authorizer_uuid


HANDLER = '''import json
import uuid


def handler(event, context):
    invocation = str(uuid.uuid4())
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if event.get("type") == "REQUEST":
        token = headers.get("x-auth", "missing")
        key = headers.get("x-usage-key")
        result = {"principalId": "api-key-probe-user", "policyDocument": {
            "Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke",
            "Effect": "Deny" if token.startswith("deny") else "Allow",
            "Resource": "/".join(event["methodArn"].split("/")[:2]) + "/*/*"}]},
            "context": {"invocation": invocation, "token": token}}
        if key is not None:
            result["usageIdentifierKey"] = key
        print(json.dumps({"probe_kind": "authorizer", "invocation": invocation,
            "lambdaRequestId": context.aws_request_id, "probe": headers.get("x-probe"),
            "token": token, "event": event, "response": result}))
        if token.startswith("unauthorized"):
            raise Exception("Unauthorized")
        return result
    print(json.dumps({"probe_kind": "backend", "invocation": invocation,
        "lambdaRequestId": context.aws_request_id, "probe": headers.get("x-probe"),
        "requestContext": event.get("requestContext")}))
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"backendInvocationId": invocation, "event": event})}
'''


class RuntimeProbe(Probe):
    def save(self):
        if hasattr(self, "envelope"):
            self.path.write_text(json.dumps(self.sanitize(self.envelope), indent=2) + "\n")
        else:
            super().save()

    def cleanup(self):
        owned = self.data["owned"]
        # Remove attached API stages before deleting their usage plans.
        super().cleanup()
        checks = []
        for kind, delete, lookup, parameter in (
                ("plan", "delete_usage_plan", "get_usage_plan", "usagePlanId"),
                ("key", "delete_api_key", "get_api_key", "apiKey")):
            for name, value in list(owned.items()):
                if not name.startswith(kind + "_"):
                    continue
                result = self.call("cleanup-" + name, "apigateway", delete,
                    {parameter: value}, required=False)
                absent = self.call("absence-" + name, "apigateway", lookup,
                    {parameter: value}, required=False)
                checks.append(absent["code"] == "NotFoundException")
                self.data["cleanup"][name] = {"delete_code": result["code"], "absent": checks[-1]}
                self.save()
        self.data["cleanup"]["complete"] = self.data["cleanup"]["complete"] and all(checks)
        self.save()
        if not self.data["cleanup"]["complete"]:
            raise RuntimeError("Owned API keys or usage plans remain after cleanup")


def request(p, label, path="/dev/required", *, headers=None, signed=False, phase="semantic"):
    if len(p.data["http"]) >= p.data["bounds"]["http_requests"]:
        raise RuntimeError("Hard probe HTTP request budget exhausted")
    sent = {"X-Probe": label, **(headers or {})}
    if signed:
        credentials = p.session.get_credentials().get_frozen_credentials()
        for secret, kind in ((credentials.access_key, "access-key"),
                (credentials.secret_key, "secret-key"), (credentials.token, "session-token")):
            if secret:
                p.hide(secret, kind)
        wire = AWSRequest(method="GET", url=p.data["owned"]["rest_endpoint"] + path, headers=sent)
        SigV4Auth(credentials, "execute-api", REGION).add_auth(wire)
        sent = dict(wire.headers)
        p.hide(sent["Authorization"], "sigv4-authorization")
    result = http(p, label, path, headers=sent, phase=phase)
    p.data["http"][-1]["authorization"] = "iam" if signed else "none"
    p.data["http"][-1]["rest_api_id"] = p.data["owned"]["rest_api"]
    p.data["http"][-1]["configured_api_key_source"] = p.data["configured_api_key_source"]
    p.save()
    return result


def stable(p, label, status, path="/dev/required", *, headers=None, signed=False, marker=None):
    started = now()
    samples = []
    def matches(result, expected):
        visible = result.get("body", {}).get("event", {}).get("stageVariables", {}).get("Revision")
        return (expected in (200, 401, 403, 429) and result.get("status") == expected
                and (marker is None or visible == marker))

    for attempt in range(30):
        result = request(p, f"ready-{label}-{attempt}", path, headers=headers, signed=signed, phase="readiness")
        samples.append(result.get("status"))
        expected = status
        if expected is None and len(samples) >= 3 and len(set(samples[-3:])) == 1:
            expected = samples[-1]
        if matches(result, expected):
            selected = request(p, label, path, headers=headers, signed=signed)
            if matches(selected, expected):
                p.data["convergence"].append({"label": label, "started_at": started,
                    "finished_at": now(), "samples": samples, "selected_status": expected,
                    "deployment_marker": marker, "timing_is_not_a_guarantee": True})
                p.save()
                return selected
            p.data["http"][-1]["phase"] = "readiness"
        time.sleep(10)
    raise RuntimeError("Bounded propagation did not converge: " + label)


def expect(p, label, status, path="/dev/required", *, headers=None, signed=False):
    result = request(p, label, path, headers=headers, signed=signed)
    if result.get("status") != status:
        raise RuntimeError(f"Stable scenario {label}: expected {status}, observed {result}")
    return result


def control(p, label, method, parameters, **kwargs):
    if method == "update_usage_plan":
        # Account-level control quota, unrelated to deployed usage-plan enforcement.
        time.sleep(21)
    result = p.required(label, "apigateway", method, parameters, **kwargs)
    if method == "update_rest_api":
        for patch in parameters.get("patchOperations", []):
            if patch["path"] == "/apiKeySource":
                p.data["configured_api_key_source"] = patch["value"]
    p.data["control_timeline"].append({"label": label, "at": now(), "operation": method,
        "observation_index": len(p.data["observations"]) - 1})
    p.save()
    return result


def deploy(p, label, stage="dev"):
    # Pace the low-rate deployment control; this is not a data-plane propagation claim.
    time.sleep(6)
    result = control(p, label, "create_deployment", {"restApiId": p.data["owned"]["rest_api"],
        "stageName": stage, "variables": {"Revision": label}})
    stable(p, label + "-visible", 200, "/" + stage + "/optional", marker=label)
    return result


def key(p, name, enabled=True):
    result = control(p, "create-key-" + name, "create_api_key",
        {"name": p.data["prefix"] + "-" + name, "enabled": enabled}, own=("key_" + name, "id"))
    p.data["keys"][name] = result
    p.save()
    return {"X-API-Key": result["value"]}


def assign(p, name, plan="primary"):
    return control(p, "assign-" + name + "-" + plan, "create_usage_plan_key", {
        "usagePlanId": p.data["owned"]["plan_" + plan], "keyId": p.data["owned"]["key_" + name], "keyType": "API_KEY"})


def plan_patch(p, label, patches):
    return control(p, label, "update_usage_plan", {
        "usagePlanId": p.data["owned"]["plan_primary"], "patchOperations": patches})


def collect_logs(p, final_invocation):
    """Use the existing paginated/stable snapshot protocol with a larger page bound."""
    previous = None
    for attempt in range(12):
        events, token = [], None
        for page in range(16):
            parameters = {"logGroupName": "/aws/lambda/" + p.data["owned"]["function"],
                "startTime": p.data["log_start_ms"], "limit": 1000}
            if token:
                parameters["nextToken"] = token
            output = p.required(f"authorizer-logs-{attempt}-{page}", "logs", "filter_log_events", parameters)
            events.extend(output.get("events", []))
            token = output.get("nextToken")
            if not token:
                break
        records = []
        for event in events:
            try:
                value = json.loads(event["message"])
            except ValueError:
                continue
            if value.get("probe_kind"):
                records.append({"timestamp": event["timestamp"], "event_id": event["eventId"], "record": value})
        p.data["invocation_logs"] = records
        p.save()
        if token:
            raise RuntimeError("Owned log collection exceeded sixteen pages")
        ids = sorted(item["event_id"] for item in records)
        final_seen = any(item["record"]["invocation"] == final_invocation for item in records)
        if final_seen and ids == previous:
            p.data["log_collection"] = {"final_backend_seen": True, "stable_consecutive_snapshots": 2,
                "poll_interval_seconds": 5, "attempts": attempt + 1, "page_bound": 16,
                "complete_paginated_scan": True,
                "absence_scope": "No matching invocation in the bounded, stable owned-function log capture; not an account-wide claim"}
            p.save()
            return
        previous = ids
        time.sleep(5)
    raise RuntimeError("Owned invocation logs did not stabilize with final backend marker")


def policy_samples(p, label, paths, headers, rounds=5, *, override=None):
    """Bounded traffic observes best-effort admission, never a precise token-bucket contract."""
    all_rows = []
    for round_number in range(rounds):
        time.sleep(p.data["bounds"].get("policy_observation_interval_seconds", 45))
        rows = []
        for index in range(8):
            path = paths[index % len(paths)]
            result = request(p, f"{label}-{round_number}-{index}", path,
                headers=headers, phase="readiness")
            rows.append({"label": p.data["http"][-1]["label"], "path": path, "status": result.get("status")})
        all_rows.extend(rows)
        throttled = any(row["status"] == 429 for row in rows)
        limited = [row["status"] for row in rows if row["path"] == "/dev/limited"]
        sibling = [row["status"] for row in rows if row["path"] == "/dev/required"]
        discriminated = True
        if override == "strict":
            discriminated = 429 in limited and all(status == 200 for status in sibling)
        elif override == "loose":
            discriminated = 429 in sibling and 429 in limited and any(row["status"] == 200 for row in rows)
        if throttled and discriminated:
            for sample in p.data["http"][-8:]:
                sample["phase"] = "policy-observation"
            break
    p.data["policy_samples"][label] = {"requests": all_rows,
        "throttled": [row["label"] for row in all_rows if row["status"] == 429],
        "accepted": [row["label"] for row in all_rows if row["status"] == 200],
        "best_effort_only": True,
        "selected_round": round_number if throttled and discriminated else None,
        "override_mode": override, "overridden_method_throttled": 429 in limited if override else None}
    p.save()
    if not p.data["policy_samples"][label]["throttled"] or not discriminated:
        raise RuntimeError("No discriminating throttling within bounded policy experiment: " + label)


def setup(p, *, fresh_authorizer=False, policies_only=False, initial_loose=False, recovery_only=False):
    p.data.update({"prefix": "stackd-keyrun-" + uuid.uuid4().hex[:10],
        "scope": "Owned deployed REST API keys, usage plans and real Lambda authorization/backend",
        "bounds": {"apis": 1, "stages": 3, "functions": 1, "roles": 1, "keys": 5,
            "plans": 2, "http_requests": 300, "convergence_attempts_per_transition": 30,
            "convergence_interval_seconds": 10, "policy_rounds": 5, "requests_per_policy_round": 8,
            "lambda_memory_mb": 128, "lambda_timeout_seconds": 3,
            "account_logging_mutations": 0, "paid_extras": 0},
        "documentation": ["https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html"],
        "probe_source": Path(__file__).read_text(), "handler_source": HANDLER,
        "keys": {}, "control_timeline": [], "convergence": [], "policy_samples": {},
        "log_start_ms": int(time.time() * 1000), "inconclusive": []})
    p.data["configured_api_key_source"] = "AUTHORIZER" if fresh_authorizer else "HEADER"
    if fresh_authorizer:
        p.data["bounds"].update({"stages": 3, "plans": 2, "keys": 4, "http_requests": 170,
            "policy_observation_interval_seconds": 45})
        p.data["scope"] = "Fresh initial AUTHORIZER source, followed by independent HEADER legacy-stage-key controls"
    if policies_only:
        p.data["bounds"].update({"stages": 2, "plans": 1, "keys": 3, "http_requests": 140,
            "policy_observation_interval_seconds": 45})
        p.data["scope"] = "Narrow method-override, quota and key-deletion recovery capture"
    if initial_loose:
        p.data["bounds"].update({"http_requests": 75, "policy_settle_pause_seconds": 120})
        p.data["scope"] = "Fresh initial looser method override, strict override, quota and deletion"
    if recovery_only:
        p.data["bounds"].update({"stages": 1, "plans": 1, "keys": 3, "http_requests": 20,
            "policy_settle_pause_seconds": 180})
        p.data["scope"] = "Quota removal, deletion and optional key authority versus identity; no repeated throttles"
    p.save()
    function, role = create_function(p, HANDLER)
    api = control(p, "create-rest-api", "create_rest_api", {"name": p.data["prefix"],
        "apiKeySource": p.data["configured_api_key_source"],
        "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))["id"]
    p.data["owned"]["rest_endpoint"] = f"https://{api}.execute-api.{REGION}.amazonaws.com"
    p.save()
    permission = p.required("allow-owned-api", "lambda", "add_permission", {
        "FunctionName": function["FunctionName"], "StatementId": "owned-api",
        "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
        "SourceArn": f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api}/*",
        "SourceAccount": p.data["account"]})
    p.data["permission_context"] = {"actor": p.data["identity"], "execution_role": role,
        "lambda_resource_permission": permission, "account_logging_role_changed": False,
        "authorizer_and_backend": "Distinct real invocations of one tiny owned function"}
    p.save()
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    auth = control(p, "create-authorizer", "create_authorizer", {"restApiId": api,
        "name": "key-authorizer", "type": "REQUEST", "authorizerUri": uri,
        "identitySource": "method.request.header.X-Auth", "authorizerResultTtlInSeconds": 300})["id"]
    root = p.required("root-resource", "apigateway", "get_resources", {"restApiId": api})["items"][0]["id"]
    resources = {}
    routes = ("required", "second", "limited", "optional", "custom") if fresh_authorizer else (
        "required", "second", "limited", "optional", "draft", "iam", "custom")
    if policies_only:
        routes = ("required", "second", "limited", "optional")
    if recovery_only:
        routes = ("required", "optional")
    for name in routes:
        resource = control(p, "resource-" + name, "create_resource", {
            "restApiId": api, "parentId": root, "pathPart": name})["id"]
        resources[name] = resource
        parameters = {"restApiId": api, "resourceId": resource, "httpMethod": "GET",
            "authorizationType": "AWS_IAM" if name == "iam" else "CUSTOM" if name == "custom" else "NONE",
            "apiKeyRequired": name not in ("optional", "draft")}
        if name == "custom":
            parameters["authorizerId"] = auth
        control(p, "method-" + name, "put_method", parameters)
        control(p, "integration-" + name, "put_integration", {"restApiId": api,
            "resourceId": resource, "httpMethod": "GET", "type": "AWS_PROXY",
            "integrationHttpMethod": "POST", "uri": uri})
    p.data["resources"] = resources
    p.save()
    stages = ("dev", "other") if policies_only else (("dev",) if fresh_authorizer else ("dev", "other", "isolated"))
    if recovery_only:
        stages = ("dev",)
    for stage in stages:
        deploy(p, "initial-" + stage, stage)
    plans = (("primary", ["dev"]),) if fresh_authorizer else (
        ("primary", ["dev", "other"]), ("isolated", ["isolated"]))
    if policies_only:
        plans = (("primary", ["dev", "other"]),)
    if recovery_only:
        plans = (("primary", ["dev"]),)
    for name, stages in plans:
        parameters = {"name": p.data["prefix"] + "-" + name,
            "apiStages": [{"apiId": api, "stage": stage} for stage in stages]}
        if initial_loose:
            parameters["throttle"] = {"rateLimit": 1.0, "burstLimit": 1}
            parameters["apiStages"][0]["throttle"] = {"/limited/GET": {"rateLimit": 100.0, "burstLimit": 100}}
        if recovery_only:
            parameters["quota"] = {"limit": 1, "period": "DAY", "offset": 0}
        control(p, "create-plan-" + name, "create_usage_plan", parameters, own=("plan_" + name, "id"))
    return api


def run(p):
    api = setup(p)
    primary = key(p, "primary")
    independent = key(p, "independent")
    disabled = key(p, "disabled", False)
    unassigned = key(p, "unassigned")
    quota_fresh = key(p, "quota_fresh")
    for name in ("primary", "independent", "disabled", "quota_fresh"):
        assign(p, name)
    stable(p, "header-valid", 200, headers=primary)
    expect(p, "header-missing", 403)
    expect(p, "header-wrong", 403, headers={"X-API-Key": "wrong000000000000000000000000000"})
    expect(p, "header-disabled", 403, headers=disabled)
    expect(p, "header-unassigned", 403, headers=unassigned)
    expect(p, "optional-missing", 200, "/dev/optional")
    expect(p, "optional-wrong", 200, "/dev/optional", headers={"X-API-Key": "wrong"})
    expect(p, "optional-valid", 200, "/dev/optional", headers=primary)
    expect(p, "same-plan-other-stage", 200, "/other/required", headers=primary)
    expect(p, "unassigned-stage", 403, "/isolated/required", headers=primary)
    assign(p, "primary", "isolated")
    stable(p, "distinct-plan-stage", 200, "/isolated/required", headers=primary)
    expect(p, "iam-unsigned-valid-key", 403, "/dev/iam", headers=primary)
    expect(p, "iam-signed-missing-key", 403, "/dev/iam", signed=True)
    expect(p, "iam-signed-valid-key", 200, "/dev/iam", headers=primary, signed=True)
    expect(p, "header-authorizer-missing-identity", 401, "/dev/custom", headers=primary)
    expect(p, "header-authorizer-deny-valid-key", 403, "/dev/custom", headers={**primary, "X-Auth": "deny-header"})
    expect(p, "header-authorizer-deny-missing-key", 403, "/dev/custom", headers={"X-Auth": "deny-no-key"})
    expect(p, "header-authorizer-allow-missing-key", 403, "/dev/custom", headers={"X-Auth": "allow-no-key"})
    expect(p, "header-authorizer-allow-valid-key", 200, "/dev/custom",
        headers={**primary, "X-Auth": "allow-header", "X-Usage-Key": "wrong-ignored"})
    for enabled, label, status in ((False, "key-disabled-live", 403), (True, "key-reenabled-live", 200)):
        control(p, label + "-control", "update_api_key", {"apiKey": p.data["owned"]["key_primary"],
            "patchOperations": [{"op": "replace", "path": "/enabled", "value": str(enabled).lower()}]})
        stable(p, label, status, headers=primary)
    control(p, "unassign-primary", "delete_usage_plan_key", {
        "usagePlanId": p.data["owned"]["plan_primary"], "keyId": p.data["owned"]["key_primary"]})
    stable(p, "key-unassigned-live", 403, headers=primary)
    expect(p, "other-plan-unaffected-by-unassign", 200, "/isolated/required", headers=primary)
    assign(p, "primary")
    stable(p, "key-reassigned-live", 200, headers=primary)
    control(p, "draft-require-key", "update_method", {"restApiId": api,
        "resourceId": p.data["resources"]["draft"], "httpMethod": "GET",
        "patchOperations": [{"op": "replace", "path": "/apiKeyRequired", "value": "true"}]})
    expect(p, "draft-change-not-deployed", 200, "/dev/draft")
    deploy(p, "require-draft-key")
    stable(p, "draft-now-required", 403, "/dev/draft")
    expect(p, "draft-valid-key", 200, "/dev/draft", headers=primary)
    expect(p, "other-stage-keeps-optional-draft", 200, "/other/draft")
    control(p, "source-authorizer", "update_rest_api", {"restApiId": api,
        "patchOperations": [{"op": "replace", "path": "/apiKeySource", "value": "AUTHORIZER"}]})
    request(p, "source-authorizer-before-deployment", "/dev/custom",
        headers={"X-Auth": "source-predeploy", "X-Usage-Key": primary["X-API-Key"]}, phase="configuration-observation")
    deploy(p, "authorizer-source")
    valid = {"X-Auth": "usage-valid", "X-Usage-Key": primary["X-API-Key"]}
    stable(p, "authorizer-usage-valid", 200, "/dev/custom", headers=valid)
    expect(p, "authorizer-usage-missing", 403, "/dev/custom", headers={"X-Auth": "usage-missing"})
    expect(p, "authorizer-usage-wrong", 403, "/dev/custom", headers={"X-Auth": "usage-wrong", "X-Usage-Key": "wrong"})
    # Measure conflicting sources rather than assuming that apiKeySource precludes header fallback.
    stable(p, "authorizer-missing-usage-valid-header", None, "/dev/custom",
        headers={**primary, "X-Auth": "usage-missing-header"})
    stable(p, "authorizer-wrong-usage-valid-header", None, "/dev/custom",
        headers={**primary, "X-Auth": "usage-wrong-header", "X-Usage-Key": "wrong"})
    stable(p, "authorizer-valid-usage-wrong-header", None, "/dev/custom",
        headers={**valid, "X-Auth": "usage-valid-header-wrong", "X-API-Key": "wrong"})
    expect(p, "authorizer-usage-disabled", 403, "/dev/custom", headers={"X-Auth": "usage-disabled", "X-Usage-Key": disabled["X-API-Key"]})
    expect(p, "authorizer-deny-valid-usage", 403, "/dev/custom", headers={**valid, "X-Auth": "deny-usage"})
    expect(p, "authorizer-unauthorized-valid-usage", 401, "/dev/custom", headers={**valid, "X-Auth": "unauthorized-usage"})
    stable(p, "authorizer-source-no-authorizer-route", None, headers=primary)
    cache_headers = {**valid, "X-Auth": "cache-key"}
    cached = expect(p, "cache-usage-valid", 200, "/dev/custom", headers=cache_headers)
    cache_wrong = {"X-Auth": "cache-key", "X-Usage-Key": "wrong"}
    reused = expect(p, "cache-retains-usage-key", 200, "/dev/custom", headers=cache_wrong)
    if authorizer_uuid(cached) != authorizer_uuid(reused):
        raise RuntimeError("Identical authorizer identity unexpectedly missed the cache")
    control(p, "flush-valid-key-cache", "flush_stage_authorizers_cache", {"restApiId": api, "stageName": "dev"})
    stable(p, "cache-flushed-wrong-usage", 403, "/dev/custom", headers=cache_wrong)
    expect(p, "cache-retains-wrong-usage", 403, "/dev/custom", headers=cache_headers)
    control(p, "flush-wrong-key-cache", "flush_stage_authorizers_cache", {"restApiId": api, "stageName": "dev"})
    stable(p, "cache-flushed-valid-usage", 200, "/dev/custom", headers=cache_headers)
    control(p, "source-header", "update_rest_api", {"restApiId": api,
        "patchOperations": [{"op": "replace", "path": "/apiKeySource", "value": "HEADER"}]})
    request(p, "source-header-before-deployment", headers=primary, phase="configuration-observation")
    deploy(p, "header-restored")
    stable(p, "header-source-restored", 200, headers=primary)
    run_policies(p, primary, independent, quota_fresh)
    final = expect(p, "final-backend-marker", 200, "/dev/optional")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)


def run_policies(p, primary, independent, quota_fresh):
    plan_patch(p, "aggregate-throttle-on", [
        {"op": "add", "path": "/throttle/rateLimit", "value": "1"},
        {"op": "add", "path": "/throttle/burstLimit", "value": "1"}])
    policy_samples(p, "aggregate-throttle", ["/dev/required", "/other/second"], primary)
    expect(p, "aggregate-throttle-independent-key", 200, headers=independent)
    expect(p, "aggregate-throttle-other-plan", 200, "/isolated/required", headers=primary)
    request(p, "aggregate-throttle-optional-known-key", "/dev/optional", headers=primary,
        phase="policy-observation")
    time.sleep(12)
    request(p, "aggregate-throttle-time-recovery", headers=primary, phase="policy-observation")
    plan_patch(p, "aggregate-throttle-remove", [{"op": "remove", "path": "/throttle"}])
    stable(p, "aggregate-throttle-removed-recovery", 200, headers=primary)
    run_method_limits(p, primary, independent)
    run_quota(p, primary, quota_fresh)


def run_method_limits(p, primary, independent, *, include_loose=True):
    api = p.data["owned"]["rest_api"]
    throttle_path = f"/apiStages/{api}:dev/throttle/limited/GET"
    plan_patch(p, "method-throttle-on", [
        {"op": "add", "path": "/throttle/rateLimit", "value": "100"},
        {"op": "add", "path": "/throttle/burstLimit", "value": "100"},
        {"op": "add", "path": throttle_path + "/rateLimit", "value": "1"},
        {"op": "add", "path": throttle_path + "/burstLimit", "value": "1"}])
    policy_samples(p, "method-override", ["/dev/limited", "/dev/required"], primary, override="strict")
    expect(p, "method-throttle-independent-key", 200, "/dev/limited", headers=independent)
    if include_loose:
        plan_patch(p, "loose-method-override-on", [
            {"op": "replace", "path": "/throttle/rateLimit", "value": "1"},
            {"op": "replace", "path": "/throttle/burstLimit", "value": "1"},
            {"op": "replace", "path": throttle_path + "/rateLimit", "value": "100"},
            {"op": "replace", "path": throttle_path + "/burstLimit", "value": "100"}])
        policy_samples(p, "loose-method-override", ["/dev/required", "/dev/limited"], primary,
            override="loose")
    plan_patch(p, "method-throttle-remove", [
        {"op": "remove", "path": f"/apiStages/{api}:dev/throttle"}])
    plan_patch(p, "default-throttle-remove", [{"op": "remove", "path": "/throttle"}])
    time.sleep(p.data["bounds"].get("policy_settle_pause_seconds", 0))
    stable(p, "method-throttle-removed-recovery", 200, "/dev/limited", headers=primary)


def run_quota(p, primary, quota_fresh):
    time.sleep(p.data["bounds"].get("policy_settle_pause_seconds", 0))
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    p.call("documentary-usage-before-quota", "apigateway", "get_usage", {
        "usagePlanId": p.data["owned"]["plan_primary"], "startDate": today, "endDate": today}, required=False)
    plan_patch(p, "quota-on", [{"op": "add", "path": "/quota/limit", "value": "1"},
        {"op": "add", "path": "/quota/period", "value": "DAY"},
        {"op": "add", "path": "/quota/offset", "value": "0"}])
    time.sleep(p.data["bounds"].get("policy_settle_pause_seconds", 0))
    stable(p, "quota-exceeded-primary", 429, headers=primary)
    stable(p, "quota-aggregate-other-stage", 429, "/other/required", headers=primary)
    expect(p, "quota-independent-key-first-call", 200, headers=quota_fresh)
    request(p, "quota-independent-key-other-stage", "/other/required", headers=quota_fresh,
        phase="policy-observation")
    if "plan_isolated" in p.data["owned"]:
        expect(p, "quota-other-plan-unaffected", 200, "/isolated/required", headers=primary)
    request(p, "quota-optional-known-key", "/dev/optional", headers=primary)
    p.call("documentary-usage-after-quota", "apigateway", "get_usage", {
        "usagePlanId": p.data["owned"]["plan_primary"], "startDate": today, "endDate": today}, required=False)
    plan_patch(p, "quota-remove", [{"op": "remove", "path": "/quota"}])
    time.sleep(p.data["bounds"].get("policy_settle_pause_seconds", 0))
    stable(p, "quota-removed-recovery", 200, headers=primary)
    control(p, "delete-primary-key", "delete_api_key", {"apiKey": p.data["owned"]["key_primary"]})
    time.sleep(p.data["bounds"].get("policy_settle_pause_seconds", 0))
    stable(p, "key-deleted-live", 403, headers=primary)
    if "plan_isolated" in p.data["owned"]:
        stable(p, "key-deleted-other-plan", 403, "/isolated/required", headers=primary)
    else:
        stable(p, "key-deleted-other-stage", 403, "/other/required", headers=primary)


def summarize(p):
    logs = p.data["invocation_logs"]
    by_request = {}
    for entry in logs:
        record = entry["record"]
        context = record.get("requestContext", record.get("event", {}).get("requestContext", {}))
        if context.get("requestId"):
            by_request.setdefault(context["requestId"], []).append(record)
    summary = {}
    missing = []
    denied_invoked = []
    for row in p.data["http"]:
        if row["phase"] not in ("semantic", "policy-observation"):
            continue
        result = row["result"]
        request_id = next((value for name, value in result.get("headers", [])
            if name.lower() == "x-amzn-requestid"), None)
        records = by_request.get(request_id, [])
        backend = [r for r in records if r["probe_kind"] == "backend"]
        authorizers = [r for r in records if r["probe_kind"] == "authorizer"]
        identity = result.get("body", {}).get("event", {}).get("requestContext", {}).get("identity", {})
        summary[row["label"]] = {"status": result.get("status"), "phase": row["phase"],
            "gateway_request_id": request_id,
            "backend_invocations": [r["invocation"] for r in backend],
            "authorizer_invocations": [r["invocation"] for r in authorizers],
            "backend_authorizer_invocation": authorizer_uuid(result),
            "identity_key_fields": {name: {"present": name in identity, "value": identity.get(name)}
                for name in ("apiKey", "apiKeyId")},
            "denied_backend_absent": not backend if result.get("status") != 200 else None}
        if result.get("status") == 200 and not any(r["invocation"] == result["body"]["backendInvocationId"] for r in backend):
            missing.append(row["label"])
        if result.get("status") in (401, 403, 429) and backend:
            denied_invoked.append(row["label"])
    p.data["semantic_summary"] = summary
    p.data["invocation_correlation"] = {"accepted_missing_logs": missing,
        "denied_with_backend_logs": denied_invoked,
        "readiness_excluded_from_selected_scenarios": True,
        "absence_scope": p.data["log_collection"]["absence_scope"]}
    p.data["observed_http_requests"] = len(p.data["http"])
    p.data["completed_at"] = now()
    p.save()
    if missing or denied_invoked:
        raise RuntimeError("Actual invocation-log correlation failed")


def run_fresh_authorizer(p, *, policy_gate=False):
    api = setup(p, fresh_authorizer=True)
    primary = key(p, "primary")
    alternate = key(p, "alternate")
    assign(p, "primary")
    assign(p, "alternate")
    quota_fresh = key(p, "quota_fresh")
    assign(p, "quota_fresh")
    legacy = control(p, "create-legacy-stage-key", "create_api_key", {
        "name": p.data["prefix"] + "-legacy", "enabled": True,
        "stageKeys": [{"restApiId": api, "stageName": "dev"}]}, own=("key_legacy", "id"))
    p.data["keys"]["legacy"] = legacy
    p.save()
    legacy_headers = {"X-API-Key": legacy["value"]}
    p.required("fresh-source-control-read", "apigateway", "get_rest_api", {"restApiId": api})
    valid = {"X-Auth": "fresh-valid", "X-Usage-Key": primary["X-API-Key"]}
    stable(p, "fresh-authorizer-valid-usage", 200, "/dev/custom", headers=valid)
    expect(p, "fresh-authorizer-missing-usage", 403, "/dev/custom", headers={"X-Auth": "fresh-missing"})
    expect(p, "fresh-authorizer-wrong-usage", 403, "/dev/custom",
        headers={"X-Auth": "fresh-wrong", "X-Usage-Key": "wrong"})
    stable(p, "fresh-missing-usage-valid-header", None, "/dev/custom",
        headers={**primary, "X-Auth": "fresh-missing-header"})
    stable(p, "fresh-wrong-usage-valid-header", None, "/dev/custom",
        headers={**primary, "X-Auth": "fresh-wrong-header", "X-Usage-Key": "wrong"})
    stable(p, "fresh-valid-usage-wrong-header", None, "/dev/custom",
        headers={**valid, "X-Auth": "fresh-valid-wrong-header", "X-API-Key": "wrong"})
    stable(p, "fresh-distinct-valid-header-and-usage", None, "/dev/custom",
        headers={**valid, **alternate, "X-Auth": "fresh-distinct-keys"})
    stable(p, "fresh-no-authorizer-route-valid-header", None, headers=primary)
    expect(p, "fresh-deny-with-valid-usage-and-header", 403, "/dev/custom",
        headers={**valid, **primary, "X-Auth": "deny-fresh"})
    expect(p, "fresh-optional-valid-header", 200, "/dev/optional", headers=primary)
    control(p, "fresh-switch-header", "update_rest_api", {"restApiId": api,
        "patchOperations": [{"op": "replace", "path": "/apiKeySource", "value": "HEADER"}]})
    deploy(p, "fresh-header-source")
    stable(p, "fresh-header-usage-only-rejected", 403, "/dev/custom",
        headers={"X-Auth": "fresh-header-usage-only", "X-Usage-Key": primary["X-API-Key"]})
    stable(p, "fresh-header-plan-positive", 200, headers=primary)
    deploy(p, "fresh-other-stage", "other")
    expect(p, "fresh-other-stage-plan-negative", 403, "/other/required", headers=primary)
    p.required("legacy-plans-before-assignment", "apigateway", "get_usage_plans", {"keyId": legacy["id"]})
    stable(p, "legacy-stage-key-without-plan-named-stage", None, headers=legacy_headers)
    stable(p, "legacy-stage-key-without-plan-other-stage", None, "/other/required", headers=legacy_headers)
    assign(p, "legacy")
    stable(p, "legacy-key-with-plan-positive", 200, headers=legacy_headers)
    control(p, "unassign-legacy-plan", "delete_usage_plan_key", {
        "usagePlanId": p.data["owned"]["plan_primary"], "keyId": legacy["id"]})
    p.required("legacy-plans-after-unassignment", "apigateway", "get_usage_plans", {"keyId": legacy["id"]})
    stable(p, "legacy-stage-key-after-plan-removal", 403, headers=legacy_headers)
    if policy_gate:
        print("Awaiting owned usage-plan policy gate", flush=True)
        input()
    deploy(p, "fresh-isolated-stage", "isolated")
    control(p, "create-plan-isolated", "create_usage_plan", {"name": p.data["prefix"] + "-isolated",
        "apiStages": [{"apiId": api, "stage": "isolated"}]}, own=("plan_isolated", "id"))
    assign(p, "primary", "isolated")
    stable(p, "fresh-isolated-plan-ready", 200, "/isolated/required", headers=primary)
    plan_patch(p, "add-other-stage-to-primary", [{"op": "add", "path": "/apiStages", "value": api + ":other"}])
    stable(p, "fresh-primary-other-stage-ready", 200, "/other/required", headers=primary)
    run_policies(p, primary, alternate, quota_fresh)
    final = expect(p, "fresh-final-backend-marker", 200, "/dev/optional")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)


def run_policy_recovery(p):
    setup(p, policies_only=True)
    primary = key(p, "primary")
    independent = key(p, "independent")
    quota_fresh = key(p, "quota_fresh")
    for name in ("primary", "independent", "quota_fresh"):
        assign(p, name)
    stable(p, "policy-baseline-primary", 200, headers=primary)
    expect(p, "policy-baseline-other-stage", 200, "/other/required", headers=primary)
    run_method_limits(p, primary, independent)
    run_quota(p, primary, quota_fresh)
    final = expect(p, "policy-final-backend-marker", 200, "/dev/optional")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)


def run_method_quota(p):
    setup(p, policies_only=True, initial_loose=True)
    primary = key(p, "primary")
    independent = key(p, "independent")
    quota_fresh = key(p, "quota_fresh")
    for name in ("primary", "independent", "quota_fresh"):
        assign(p, name)
    time.sleep(p.data["bounds"]["policy_settle_pause_seconds"])
    policy_samples(p, "fresh-loose-method-override", ["/dev/required", "/dev/limited"], primary,
        override="loose")
    expect(p, "fresh-loose-independent-key", 200, headers=independent)
    run_method_limits(p, primary, independent, include_loose=False)
    run_quota(p, primary, quota_fresh)
    final = expect(p, "method-quota-final-backend-marker", 200, "/dev/optional")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)


def run_quota_only(p):
    setup(p, policies_only=True)
    p.data["bounds"].update({"keys": 4, "http_requests": 40, "policy_settle_pause_seconds": 180})
    p.data["scope"] = "Quota/prior-traffic, deletion, and bounded optional HEADER identity controls"
    p.save()
    primary = key(p, "primary")
    quota_fresh = key(p, "quota_fresh")
    disabled = key(p, "disabled", False)
    unassigned = key(p, "unassigned")
    for name in ("primary", "quota_fresh", "disabled"):
        assign(p, name)
    time.sleep(p.data["bounds"]["policy_settle_pause_seconds"])
    stable(p, "quota-baseline-primary", 200, headers=primary)
    expect(p, "quota-baseline-other-stage", 200, "/other/required", headers=primary)
    expect(p, "optional-disabled-known-key", 200, "/dev/optional", headers=disabled)
    expect(p, "optional-unassigned-known-key", 200, "/dev/optional", headers=unassigned)
    run_quota(p, primary, quota_fresh)
    final = expect(p, "quota-final-backend-marker", 200, "/dev/optional")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)


def run_quota_recovery(p):
    setup(p, policies_only=True, recovery_only=True)
    primary = key(p, "primary")
    disabled = key(p, "disabled")
    unassigned = key(p, "unassigned")
    for name in ("primary", "disabled"):
        assign(p, name)
    time.sleep(p.data["bounds"]["policy_settle_pause_seconds"])
    expect(p, "quota-fresh-plan-first-request", 200, headers=primary)
    stable(p, "quota-fresh-plan-exceeded", 429, headers=primary)
    request(p, "quota-optional-known-key", "/dev/optional", headers=primary)
    expect(p, "quota-before-disable-first-request", 200, headers=disabled)
    control(p, "disable-exhausted-key", "update_api_key", {
        "apiKey": p.data["owned"]["key_disabled"],
        "patchOperations": [{"op": "replace", "path": "/enabled", "value": "false"}]})
    time.sleep(p.data["bounds"]["policy_settle_pause_seconds"])
    request(p, "quota-required-disabled-known-key", headers=disabled)
    request(p, "quota-optional-disabled-known-key", "/dev/optional", headers=disabled)
    request(p, "quota-optional-unassigned-known-key", "/dev/optional", headers=unassigned)
    expect(p, "quota-optional-no-key", 200, "/dev/optional")
    expect(p, "quota-optional-unknown-key", 200, "/dev/optional", headers={"X-API-Key": "wrong"})
    time.sleep(p.data["bounds"]["policy_settle_pause_seconds"])
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    p.call("documentary-usage-after-quota", "apigateway", "get_usage", {
        "usagePlanId": p.data["owned"]["plan_primary"], "startDate": today, "endDate": today}, required=False)
    plan_patch(p, "quota-remove", [{"op": "remove", "path": "/quota"}])
    time.sleep(p.data["bounds"]["policy_settle_pause_seconds"])
    stable(p, "quota-removed-recovery", 200, headers=primary)
    control(p, "delete-primary-key", "delete_api_key", {"apiKey": p.data["owned"]["key_primary"]})
    time.sleep(p.data["bounds"]["policy_settle_pause_seconds"])
    stable(p, "key-deleted-live", 403, headers=primary)
    final = expect(p, "quota-recovery-final-backend-marker", 200, "/dev/optional")
    collect_logs(p, final["body"]["backendInvocationId"])
    summarize(p)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/api_key_runtime.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--retry-cleaned", action="store_true",
        help="Retain a failed, fully cleaned capture and run a new owned attempt")
    parser.add_argument("--fresh-authorizer", action="store_true",
        help="Append an independent initial-AUTHORIZER discriminator to a cleaned capture")
    parser.add_argument("--policies-only", action="store_true",
        help="Append a narrow method-override and quota capture without repeating lifecycle traffic")
    parser.add_argument("--method-quota", action="store_true",
        help="Append a fresh-at-creation override and quota discriminator")
    parser.add_argument("--quota-only", action="store_true",
        help="Append quota/prior-traffic evidence without repeating throttle controls")
    parser.add_argument("--quota-recovery", action="store_true",
        help="Append minimal quota removal and key deletion recovery")
    parser.add_argument("--policy-gate", action="store_true",
        help="Wait on stdin before supplemental usage-plan mutations to coordinate account control quotas")
    args = parser.parse_args()
    if sum((args.fresh_authorizer, args.policies_only, args.method_quota, args.quota_only, args.quota_recovery)) > 1:
        parser.error("Choose one supplemental capture mode")
    if args.fresh_authorizer or args.policies_only or args.method_quota or args.quota_only or args.quota_recovery:
        capture_name = ("quota_recovery_capture" if args.quota_recovery else
            "quota_capture" if args.quota_only else "method_quota_capture" if args.method_quota else
            "fresh_authorizer_capture" if args.fresh_authorizer else "policy_recovery_capture")
        envelope = json.loads(args.output.read_text())
        if args.retry_cleaned or not envelope.get("cleanup", {}).get("complete"):
            parser.error("Supplemental capture requires an independently cleaned main capture")
        if args.cleanup_only:
            probe = RuntimeProbe(args.output, args.account, True)
            probe.data = envelope[capture_name]
        else:
            if capture_name in envelope:
                parser.error("Refusing to overwrite the supplemental capture")
            with tempfile.TemporaryDirectory(prefix="stackd-keyrun-fresh-") as directory:
                probe = RuntimeProbe(Path(directory) / "capture.json", args.account, False)
            envelope[capture_name] = probe.data
        probe.path, probe.envelope = args.output, envelope
        probe.save()
    elif args.retry_cleaned:
        previous = json.loads(args.output.read_text())
        if args.cleanup_only or not previous.get("cleanup", {}).get("complete") or not previous.get("failure"):
            parser.error("--retry-cleaned requires a failed, completely cleaned capture")
        with tempfile.TemporaryDirectory(prefix="stackd-keyrun-") as directory:
            probe = RuntimeProbe(Path(directory) / "capture.json", args.account, False)
        probe.path = args.output
        attempts = previous.pop("previous_attempts", [])
        probe.data["previous_attempts"] = attempts + [previous]
        probe.save()
    else:
        probe = RuntimeProbe(args.output, args.account, args.cleanup_only)
        if args.cleanup_only:
            probe.data.setdefault("cleanup_repair_sources", []).append(Path(__file__).read_text())
            probe.save()
    try:
        if not args.cleanup_only:
            if args.fresh_authorizer:
                run_fresh_authorizer(probe, policy_gate=args.policy_gate)
            elif args.policies_only:
                run_policy_recovery(probe)
            elif args.method_quota:
                run_method_quota(probe)
            elif args.quota_only:
                run_quota_only(probe)
            elif args.quota_recovery:
                run_quota_recovery(probe)
            else:
                run(probe)
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        successful = [row["result"]["body"]["backendInvocationId"] for row in probe.data["http"]
            if row["result"].get("status") == 200 and "backendInvocationId" in row["result"].get("body", {})]
        if successful and not probe.data.get("invocation_logs"):
            try:
                collect_logs(probe, successful[-1])
            except Exception as log_error:
                probe.data["failure_log_collection"] = str(log_error)
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
