#!/usr/bin/env python3
"""Capture owned native HTTP access logs; --cleanup resumes ownership-safe deletion.

Requires boto3 and the existing gateway probe dependencies. No API Gateway
account logging-role mutation. Retains exact source, policy inventories, real
Lambda observations, access-log polls, and native cleanup absence witnesses.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import platform
import shlex
import sys
import time
from botocore.config import Config

from apigateway_probe import REGION, now
from apigateway_rest_authorizer_probe import create_function
from apigateway_websocket_probe import LifecycleProbe

HANDLER = '''import json
import os
import platform


def handler(event, context):
    route = event["requestContext"]["routeKey"]
    status = {"GET /client": 400, "GET /bad": 503}.get(route, 200)
    for key in list((event.get("headers") or {})):
        if key.lower() in ("authorization", "x-amz-security-token"):
            event["headers"][key] = "HIDDEN_BY_PROBE"
    body = {"marker": (event.get("headers") or {}).get("x-probe"),
        "request_id": event["requestContext"]["requestId"],
        "lambda_request_id": context.aws_request_id, "status": status}
    response = {"statusCode": status, "headers": {"content-type": "application/json"},
        "body": json.dumps(body)}
    print(json.dumps({"probe_kind": "http-access-logs", "event": event,
        "invocation_id": context.aws_request_id, "response": response,
        "runtime": {"python": platform.python_version(),
            "execution_environment": os.environ.get("AWS_EXECUTION_ENV")}}), flush=True)
    if route == "GET /raise":
        raise RuntimeError("owned HTTP access log integration failure")
    return response
'''

FIELDS = ["requestId", "extendedRequestId", "accountId", "apiId", "stage", "routeKey", "path",
    "httpMethod", "protocol", "status", "responseLength", "requestTime", "requestTimeEpoch",
    "responseLatency", "dataProcessed", "domainName", "domainPrefix", "identity.sourceIp",
    "identity.userAgent", "identity.accountId", "identity.caller", "identity.user", "identity.userArn",
    "integration.status", "integration.integrationStatus", "integrationStatus", "integration.latency",
    "integrationLatency", "integration.requestId", "awsEndpointRequestId", "awsEndpointRequestId2",
    "integration.error", "integrationErrorMessage", "error.message", "error.responseType",
    "authorizer.error", "authorizer.missing", "authorizer.claims", "customDomain.basePathMatched",
    "resourcePath"]
FORMAT = json.dumps({key: "$context." + key for key in FIELDS}, separators=(",", ":"))
FORMAT_UPDATED = 'updated | $context.requestId | ${context.requestId} | $context.extendedRequestId | $stageVariables.probe | $context.status | $context.error.messageString | $$context.requestId'


class LogsProbe(LifecycleProbe):
    def call(self, *args, **kwargs):
        offset = len(self.data["observations"])
        try:
            return super().call(*args, **kwargs)
        finally:
            for row in self.data["observations"][offset:]:
                row["actor"] = self.data.get("current_actor", self.data["identity"])
            self.save()

    def inventory(self, label):
        snapshot = {"label": label, "at": now(), "policies": [], "deliveries": []}
        for key, operation, member, params in (
                ("policies", "describe_resource_policies", "resourcePolicies", {"limit": 50}),
                ("deliveries", "describe_deliveries", "deliveries", {"limit": 50})):
            for page in range(6):
                name = f"inventory-{label}-{key}-{page}"
                result = self.required(name, "logs", operation, params)
                snapshot[key].extend(result.get(member, []))
                token = result.get("nextToken")
                if not token:
                    break
                params = {**params, "nextToken": token}
            else:
                raise RuntimeError("Inventory exceeded six pages: " + key)
        # RESOURCE policies are not necessarily returned by the unfiltered account inventory.
        for group in self.data["owned"].get("access_groups", []):
            params = {"resourceArn": group["arn"], "policyScope": "RESOURCE", "limit": 50}
            for page in range(6):
                result = self.required(f"inventory-{label}-{group['alias']}-scoped-{page}", "logs", "describe_resource_policies", params)
                for policy in result.get("resourcePolicies", []):
                    if policy not in snapshot["policies"]:
                        snapshot["policies"].append(policy)
                token = result.get("nextToken")
                if not token:
                    break
                params = {**params, "nextToken": token}
            else:
                raise RuntimeError("Scoped policy inventory exceeded six pages")
        self.data["delivery_inventories"].append(snapshot)
        self.save()
        return snapshot

    def http(self, *args, **kwargs):
        if len(self.data["http"]) >= 40:
            raise RuntimeError("Forty HTTP requests exhausted")
        return super().http(*args, **kwargs)

    def cleanup(self):
        problems = []
        owned = self.data["owned"]
        if owned.get("http_api"):
            self.call("cleanup-http-api", "apigatewayv2", "delete_api", {"ApiId": owned["http_api"]}, required=False)
            absent = self.call("absence-http-api", "apigatewayv2", "get_api", {"ApiId": owned["http_api"]}, required=False)
            self.data["cleanup"]["http_api"] = {"absent": absent["code"] == "NotFoundException"}
            if absent["code"] != "NotFoundException":
                problems.append("HTTP API not absent")
        if self.data.get("delivery_inventories"):
            baseline = self.data["delivery_inventories"][0]
            current = self.inventory("cleanup-before")
            for row in current["deliveries"]:
                if is_owned_delivery(self, row) and not any(x.get("id") == row.get("id") for x in baseline["deliveries"]):
                    self.required("cleanup-v2-delivery-" + row["id"], "logs", "delete_delivery", {"id": row["id"]})
            # Compare current non-owned policy contents to baseline. Never restore a stale snapshot.
            for policy in current["policies"]:
                original = next((x for x in baseline["policies"] if policy_key(x) == policy_key(policy)), None)
                document = json.loads(policy["policyDocument"])
                stripped, removed = remove_owned_resources(self, document)
                if not removed:
                    continue
                if original is not None and normalized_document(stripped) != normalized_document(json.loads(original["policyDocument"])):
                    problems.append("Concurrent baseline policy change; retained owned additions in " + repr(policy_key(policy)))
                    continue
                if original is None and stripped.get("Statement"):
                    problems.append("New policy contains unrelated contents; retained " + repr(policy_key(policy)))
                    continue
                fresh = self.inventory("cleanup-policy-guard")
                latest = next((x for x in fresh["policies"] if policy_key(x) == policy_key(policy)), None)
                if latest != policy:
                    problems.append("Policy changed during cleanup guard: " + repr(policy_key(policy)))
                    continue
                params = {"policyName": policy["policyName"]} if policy.get("policyName") else {}
                if policy.get("resourceArn"):
                    params["resourceArn"] = policy["resourceArn"]
                if policy.get("revisionId"):
                    params["expectedRevisionId"] = policy["revisionId"]
                if stripped.get("Statement"):
                    params["policyDocument"] = json.dumps(stripped)
                    self.required("cleanup-policy-owned-entries", "logs", "put_resource_policy", params)
                else:
                    self.required("cleanup-owned-policy", "logs", "delete_resource_policy", params)
            final = self.inventory("cleanup-after-policy")
            remaining = [x for x in final["deliveries"] if is_owned_delivery(self, x)]
            policies = [policy_key(x) for x in final["policies"] if remove_owned_resources(self, json.loads(x["policyDocument"]))[1]]
            self.data["cleanup"]["delivery_and_policy"] = {"owned_deliveries_remaining": remaining,
                "owned_policy_entries_remaining": policies, "problems": problems}
            if remaining or policies:
                problems.append("Owned delivery/policy remains")
        for group in owned.get("access_groups", []):
            self.call("cleanup-group-" + group["alias"], "logs", "delete_log_group", {"logGroupName": group["name"]}, required=False)
            result = self.required("absence-group-" + group["alias"], "logs", "describe_log_groups", {"logGroupNamePrefix": group["name"]})
            absent = not any(x["logGroupName"] == group["name"] for x in result["logGroups"])
            self.data["cleanup"][group["alias"]] = {"absent": absent}
            if not absent:
                problems.append("Group remains: " + group["name"])
        if owned.get("role") and owned.get("actor_policy"):
            self.call("cleanup-actor-policy", "iam", "delete_role_policy", {"RoleName": owned["role"], "PolicyName": "probe-http-control"}, required=False)
        try:
            super().cleanup()
        finally:
            self.data["cleanup"]["problems"] = problems
            self.data["cleanup"]["complete"] = self.data["cleanup"].get("complete", False) and not problems
            self.save()
        if problems:
            raise RuntimeError("Owned cleanup requires inspection: " + "; ".join(problems))


def policy_key(policy):
    return policy.get("resourceArn", ""), policy.get("policyName", "")


def normalized_document(document):
    value = copy.deepcopy(document)
    for statement in value.get("Statement", []):
        if isinstance(statement.get("Resource"), str):
            statement["Resource"] = [statement["Resource"]]
    return value


def remove_owned_resources(p, document):
    result = copy.deepcopy(document)
    owned = {group["arn"] + suffix for group in p.data["owned"].get("access_groups", [])
             for suffix in ("", ":*", ":log-stream:*")}
    statements, removed = [], []
    for statement in result.get("Statement", []):
        resources = statement.get("Resource", [])
        values = [resources] if isinstance(resources, str) else resources
        dropped = [value for value in values if value in owned]
        removed.extend(dropped)
        if not dropped:
            statements.append(statement)
        elif len(dropped) != len(values):
            statement["Resource"] = [value for value in values if value not in owned]
            statements.append(statement)
    result["Statement"] = statements
    return result, removed


def is_owned_delivery(p, row):
    arn_values = {group["arn"] + suffix for group in p.data["owned"].get("access_groups", []) for suffix in ("", ":*")}
    return any(row.get(key) in arn_values for key in ("deliveryDestinationArn", "destinationResourceArn", "resourceArn"))


def stage(p, label, method="update_stage", name="probe", required=True, **values):
    return p.call(label, "apigatewayv2", method, {"ApiId": p.data["owned"]["http_api"], "StageName": name, **values}, required=required)


def poll_logs(p, label, expected=(), attempts=8):
    expected = set(expected)
    snapshots = []
    p.data["log_polls"].append({"label": label, "expected_request_ids": sorted(expected), "snapshots": snapshots})
    for attempt in range(attempts):
        snapshot = {"at": now(), "attempt": attempt, "groups": {}, "seen_expected_ids": []}
        seen = set()
        for group in p.data["owned"]["access_groups"] + [{"alias": "lambda", "name": "/aws/lambda/" + p.data["owned"]["function"]}]:
            events = []
            params = {"logGroupName": group["name"], "startTime": p.data["log_start_ms"], "limit": 1000}
            for page in range(3):
                output = p.required(f"logs-{label}-{attempt}-{group['alias']}-{page}", "logs", "filter_log_events", params)
                events.extend(output.get("events", []))
                token = output.get("nextToken")
                if not token:
                    break
                params = {**params, "nextToken": token}
            else:
                raise RuntimeError("Log poll exceeded three pages")
            # Keep raw event bodies once, referencing stable IDs in subsequent snapshots.
            for event in events:
                key = group["alias"] + ":" + event["eventId"]
                p.data["log_events"].setdefault(key, {"group": group["name"], **event})
                if group["alias"] != "lambda":
                    seen.update(request_id for request_id in expected if request_id in event["message"])
            snapshot["groups"][group["alias"]] = [event["eventId"] for event in events]
        snapshot["seen_expected_ids"] = sorted(seen)
        snapshots.append(snapshot)
        p.save()
        if expected and seen == expected:
            return True
        if attempt + 1 < attempts:
            time.sleep(15)
    return not expected


def request(p, label, path, **kwargs):
    result = p.http(label, "http", "/probe/" + path, **kwargs)
    headers = {key.lower(): value for key, value in result.get("headers", [])}
    request_id = headers.get("apigw-requestid") or headers.get("x-amzn-requestid")
    p.data["request_correlations"][label] = {"request_id": request_id, "status": result.get("status")}
    p.save()
    return request_id


def setup(p):
    p.data.update(scope="One owned HTTP API/Lambda/execution role, two access-log groups and one Lambda group; no regional API Gateway account mutations",
        probe_source=Path(__file__).read_text(), handler_source=HANDLER,
        executed_command="env PYTHONPATH=" + shlex.quote(os.environ.get("PYTHONPATH", "")) + " " + shlex.join([sys.executable, *sys.argv]),
        credential_provenance={"method": p.session.get_credentials().method, "local_python": platform.python_version(),
            "actor": p.data["identity"], "credential_values": "Never retained"},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging-variables.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutResourcePolicy.html"],
        bounds={"http_requests": 40, "sdk_total_max_attempts": 1, "connect_timeout_seconds": 10,
            "read_timeout_seconds": 30, "inventory_pages": 6, "log_pages": 3,
            "log_poll_attempts": 8, "log_poll_interval_seconds": 15,
            "function_create_attempts": 15, "function_ready_attempts": 15, "readiness_attempts": 15},
        delivery_inventories=[], log_polls=[], log_events={}, request_correlations={},
        log_start_ms=int(time.time() * 1000), formats={"full": FORMAT, "updated": FORMAT_UPDATED},
        limitations=["One native account/region/run; bounded absence is not proof of permanent non-delivery.",
            "Account resource policies have no atomic revision guard: immediately reread and stop if any snapshot differs before subtraction.",
            "Inventory reads account policy/delivery metadata only, never unrelated log records.",
            "V1 CreateLogDelivery is an IAM permission, not a public SDK command; DescribeDeliveries inventories public V2 deliveries only.",
            "No regional Gateway account role is changed; REST/WebSocket sibling may independently change that account setting."])
    p.data["owned"]["access_groups"] = []
    p.save()
    p.inventory("baseline-before-any-activation")
    function, role = create_function(p, HANDLER)
    for alias in ("access", "alternate"):
        group = {"alias": alias, "name": "/stackd/http-logs/" + p.data["prefix"] + "/" + alias}
        group["arn"] = f"arn:aws:logs:{REGION}:{p.data['account']}:log-group:{group['name']}"
        p.required("create-" + alias + "-group", "logs", "create_log_group", {"logGroupName": group["name"]})
        p.data["owned"]["access_groups"].append(group)
        p.save()
    api = p.required("create-http-api", "apigatewayv2", "create_api", {"Name": p.data["prefix"], "ProtocolType": "HTTP"}, own=("http_api", "ApiId"))
    p.data["owned"]["http_endpoint"] = api["ApiEndpoint"]
    p.required("lambda-permission", "lambda", "add_permission", {"FunctionName": function["FunctionName"],
        "StatementId": "owned-http-logs", "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
        "SourceAccount": p.data["account"], "SourceArn": f"arn:aws:execute-api:{REGION}:{p.data['account']}:{api['ApiId']}/*"})
    integration = p.required("create-integration", "apigatewayv2", "create_integration", {"ApiId": api["ApiId"],
        "IntegrationType": "AWS_PROXY", "IntegrationMethod": "POST", "IntegrationUri": function["FunctionArn"], "PayloadFormatVersion": "2.0"})
    for path in ("ok", "client", "bad", "raise", "iam"):
        p.required("route-" + path, "apigatewayv2", "create_route", {"ApiId": api["ApiId"], "RouteKey": "GET /" + path,
            "Target": "integrations/" + integration["IntegrationId"], "AuthorizationType": "AWS_IAM" if path == "iam" else "NONE"})
    deployment = p.required("deploy", "apigatewayv2", "create_deployment", {"ApiId": api["ApiId"]})
    for name in ("probe", "admission"):
        stage(p, "create-stage-" + name, "create_stage", name, DeploymentId=deployment["DeploymentId"], AutoDeploy=False,
            StageVariables={"probe": "owned-stage-value"})
    p.ready("http", "/probe/ok", 200)
    p.data["owned"]["role_arn"] = role["Arn"]
    p.save()


def actor_deny(p, destination):
    role = p.data["owned"]["role"]
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": p.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}]}
    p.required("actor-trust", "iam", "update_assume_role_policy", {"RoleName": role, "PolicyDocument": json.dumps(trust)})
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["apigateway:PATCH", "apigateway:GET"],
            "Resource": f"arn:aws:apigateway:{REGION}::/apis/{p.data['owned']['http_api']}/stages/admission"},
        {"Effect": "Deny", "Action": "logs:CreateLogDelivery", "Resource": "*"}]}
    p.required("actor-deny-policy", "iam", "put_role_policy", {"RoleName": role, "PolicyName": "probe-http-control", "PolicyDocument": json.dumps(policy)})
    p.data["owned"]["actor_policy"] = True
    p.save()
    time.sleep(10)
    assumed = p.required("assume-owned-deny-role", "sts", "assume_role", {"RoleArn": p.data["owned"]["role_arn"],
        "RoleSessionName": "owned-http-log-deny", "DurationSeconds": 900})
    credentials = assumed["Credentials"]
    client = p.session.client("apigatewayv2", aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"],
        config=Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30))
    original = p.client("apigatewayv2")
    p.clients["apigatewayv2"] = client
    p.data["current_actor"] = assumed["AssumedRoleUser"]
    try:
        stage(p, "actor-deny-readable-stage", "get_stage", "admission")
        stage(p, "actor-deny-create-log-delivery", name="admission", required=False,
            AccessLogSettings={"DestinationArn": destination, "Format": "$context.requestId"})
    finally:
        p.clients["apigatewayv2"] = original
        p.data.pop("current_actor", None)
        p.save()


def admission(p):
    first, second = p.data["owned"]["access_groups"]
    for label, values in (
            ("logging-info", {"DefaultRouteSettings": {"LoggingLevel": "INFO"}}),
            ("logging-off", {"DefaultRouteSettings": {"LoggingLevel": "OFF"}}),
            ("data-trace-true", {"DefaultRouteSettings": {"DataTraceEnabled": True}}),
            ("data-trace-false", {"DefaultRouteSettings": {"DataTraceEnabled": False}}),
            ("route-execution-logging", {"RouteSettings": {"GET /ok": {"LoggingLevel": "ERROR", "DataTraceEnabled": True}}})):
        stage(p, "admission-" + label, name="admission", required=False, **values)
    for label, settings in (
            ("empty-object", {}), ("destination-only", {"DestinationArn": first["arn"]}),
            ("format-only", {"Format": "$context.requestId"}),
            ("missing-request-id", {"DestinationArn": first["arn"], "Format": "$context.status"}),
            ("extended-id-only", {"DestinationArn": first["arn"], "Format": "$context.extendedRequestId"}),
            ("unsupported-context", {"DestinationArn": first["arn"], "Format": "$context.requestId $context.unknown $context.resourceId"}),
            ("unsupported-pipe-delimiter", {"DestinationArn": first["arn"], "Format": "$context.requestId|$context.status|"}),
            ("missing-group", {"DestinationArn": first["arn"] + "-missing", "Format": "$context.requestId"}),
            ("wrong-service", {"DestinationArn": f"arn:aws:s3:::{p.data['prefix']}", "Format": "$context.requestId"}),
            ("empty-format", {"DestinationArn": first["arn"], "Format": ""}),
            ("newline-format", {"DestinationArn": first["arn"], "Format": "$context.requestId\n$context.status"})):
        stage(p, "admission-" + label, name="admission", required=False, AccessLogSettings=settings)
        stage(p, "after-admission-" + label, "get_stage", "admission")
    p.inventory("after-admission")
    stage(p, "disable-admission", "delete_access_log_settings", "admission", required=False)
    actor_deny(p, second["arn"])
    p.inventory("after-actor-deny")


def execute(p, settings_only=False):
    first, second = p.data["owned"]["access_groups"]
    p.data["capture_mode"] = "settings-supplement" if settings_only else "full"
    if not settings_only:
        admission(p)
    stage(p, "enable-full-format", AccessLogSettings={"DestinationArn": first["arn"], "Format": FORMAT})
    stage(p, "get-full-format", "get_stage")
    p.inventory("after-enable")
    time.sleep(15)
    if settings_only:
        ids = [request(p, "settings-baseline", "ok")]
    else:
        ids = [request(p, "full-" + path, path) for path in ("ok", "client", "bad", "raise", "iam", "unmatched")]
        ids.append(request(p, "full-iam-signed", "iam", authorization="iam"))
    p.data["full_cohort_logs_seen"] = poll_logs(p, "full-cohort", [value for value in ids if value])
    stage(p, "update-format-only", AccessLogSettings={"Format": FORMAT_UPDATED}, required=False)
    stage(p, "get-after-format-only", "get_stage")
    stage(p, "update-empty-settings", AccessLogSettings={}, required=False)
    stage(p, "get-after-empty-settings", "get_stage")
    stage(p, "update-format-complete", AccessLogSettings={"DestinationArn": first["arn"], "Format": FORMAT_UPDATED})
    stage(p, "get-updated-format", "get_stage")
    time.sleep(10)
    updated = request(p, "updated-format", "ok")
    poll_logs(p, "updated-format", [updated] if updated else [])
    stage(p, "update-destination-only", AccessLogSettings={"DestinationArn": second["arn"] + ":*"}, required=False)
    stage(p, "get-after-destination-only", "get_stage")
    stage(p, "update-destination-complete", AccessLogSettings={"DestinationArn": second["arn"] + ":*", "Format": FORMAT_UPDATED})
    stage(p, "get-updated-destination", "get_stage")
    p.inventory("after-destination-update")
    time.sleep(10)
    moved = request(p, "updated-destination", "client")
    poll_logs(p, "updated-destination", [moved] if moved else [])
    stage(p, "remove-access-settings", "delete_access_log_settings")
    stage(p, "get-removed-settings", "get_stage")
    time.sleep(10)
    request(p, "removed-settings", "ok")
    poll_logs(p, "removed-settings-bounded", attempts=2)
    stage(p, "reenable-access-settings", AccessLogSettings={"DestinationArn": second["arn"], "Format": FORMAT})
    stage(p, "get-reenabled-settings", "get_stage")
    p.inventory("after-reenable")
    time.sleep(10)
    reenabled = request(p, "reenabled-settings", "ok")
    poll_logs(p, "reenabled-settings", [reenabled] if reenabled else [])
    for group in p.data["owned"]["access_groups"]:
        p.required("final-streams-" + group["alias"], "logs", "describe_log_streams", {"logGroupName": group["name"], "limit": 50})
    for label, row in p.data["request_correlations"].items():
        row["access_event_keys"] = [key for key, event in p.data["log_events"].items()
            if not key.startswith("lambda:") and row["request_id"] and row["request_id"] in event["message"]]
        row["lambda_event_keys"] = [key for key, event in p.data["log_events"].items()
            if key.startswith("lambda:") and row["request_id"] and row["request_id"] in event["message"]]
    p.data["capture_complete"] = True
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--settings-only", action="store_true",
        help="Capture only setting transitions with fresh owned resources, without repeating admission/error cohorts")
    args = parser.parse_args()
    p = LogsProbe(args.output, args.account, args.cleanup)
    if args.cleanup:
        p.data.setdefault("recovery_sources", []).append({"at": now(), "source": Path(__file__).read_text()})
        p.save()
        p.cleanup()
        return
    try:
        setup(p)
        execute(p, settings_only=args.settings_only)
    except Exception as error:
        p.data["failure"] = {"at": now(), "type": type(error).__name__, "message": str(error)}
        p.save()
        raise
    finally:
        p.cleanup()


if __name__ == "__main__":
    main()
