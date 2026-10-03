#!/usr/bin/env python3
"""Capture owned native WebSocket REQUEST authorizer admission; always remove resources."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import time
import uuid

import botocore
from botocore.config import Config

import apigateway_probe
import apigateway_rest_authorizer_probe
from apigateway_probe import Probe, REGION, now
from apigateway_rest_authorizer_probe import create_function

HANDLER = '''def handler(event, context):
    return {"principalId": "admission-probe", "policyDocument": {"Version": "2012-10-17",
        "Statement": [{"Action": "execute-api:Invoke", "Effect": "Allow", "Resource": event["methodArn"]}]}}
'''


def authorizer_get(p, label, ident):
    return p.call(label, "apigatewayv2", "get_authorizer",
        {"ApiId": p.data["owned"]["http_api"], "AuthorizerId": ident}, required=False)


def authorizer_list(p, label):
    return p.required(label, "apigatewayv2", "get_authorizers",
        {"ApiId": p.data["owned"]["http_api"]})


def delete_authorizer(p, label, ident):
    parameters = {"ApiId": p.data["owned"]["http_api"], "AuthorizerId": ident}
    p.required(label, "apigatewayv2", "delete_authorizer", parameters)
    absent = authorizer_get(p, label + "-absence", ident)
    p.data.setdefault("temporary_authorizer_absence", {})[ident] = absent["code"] == "NotFoundException"
    p.save()
    if absent["code"] != "NotFoundException":
        raise RuntimeError(label + " did not establish authorizer absence")


def create_case(p, common, label, overrides):
    parameters = {key: value for key, value in {**common, "Name": label, **overrides}.items()
                  if value is not None}
    result = p.call("create-" + label, "apigatewayv2", "create_authorizer", parameters, required=False)
    row = {"label": label, "input_overrides": overrides, "code": result["code"]}
    if result["code"] == "Success":
        ident = result["output"]["AuthorizerId"]
        row["output"] = result["output"]
        row["get"] = authorizer_get(p, "get-" + label, ident)
        row["list"] = authorizer_list(p, "list-" + label)
        delete_authorizer(p, "delete-" + label, ident)
    else:
        row["error"] = result["error"]
    p.data["create_matrix"].append(row)
    p.save()


def update_case(p, ident, label, changes):
    before = authorizer_get(p, "before-update-" + label, ident)
    result = p.call("update-" + label, "apigatewayv2", "update_authorizer",
        {"ApiId": p.data["owned"]["http_api"], "AuthorizerId": ident, **changes}, required=False)
    after = authorizer_get(p, "after-update-" + label, ident)
    row = {"label": label, "input_changes": changes, "result": result,
           "before": before, "after": after,
           "state_preserved": before.get("output") == after.get("output")}
    p.data["update_matrix"].append(row)
    p.save()
    return result


def route_cases(p, ident):
    api = p.data["owned"]["http_api"]
    for route_key, label in (("$connect", "connect"), ("message", "message"),
                             ("$disconnect", "disconnect"), ("$default", "default")):
        parameters = {"ApiId": api, "RouteKey": route_key,
                      "AuthorizationType": "CUSTOM", "AuthorizerId": ident}
        result = p.call("create-custom-" + label, "apigatewayv2", "create_route", parameters, required=False)
        row = {"route_key": route_key, "create_custom": result}
        if result["code"] == "Success":
            route = result["output"]
        else:
            route = p.required("create-none-" + label, "apigatewayv2", "create_route",
                {"ApiId": api, "RouteKey": route_key, "AuthorizationType": "NONE"})
        route_id = route["RouteId"]
        p.data["owned"]["routes"][route_key] = route_id
        before = p.required("before-custom-update-" + label, "apigatewayv2", "get_route",
            {"ApiId": api, "RouteId": route_id})
        changed = p.call("update-custom-" + label, "apigatewayv2", "update_route",
            {"ApiId": api, "RouteId": route_id, "AuthorizationType": "CUSTOM", "AuthorizerId": ident},
            required=False)
        after = p.required("after-custom-update-" + label, "apigatewayv2", "get_route",
            {"ApiId": api, "RouteId": route_id})
        row.update(update_custom=changed, before=before, after=after, state_preserved=before == after)
        p.data["route_matrix"].append(row)
        p.save()
    p.required("list-custom-routes", "apigatewayv2", "get_routes", {"ApiId": api})
    before = authorizer_get(p, "before-referenced-delete", ident)
    result = p.call("delete-referenced-authorizer", "apigatewayv2", "delete_authorizer",
        {"ApiId": api, "AuthorizerId": ident}, required=False)
    after = authorizer_get(p, "after-referenced-delete", ident)
    routes = p.required("routes-after-referenced-delete", "apigatewayv2", "get_routes", {"ApiId": api})
    p.data["referenced_deletion"] = {"before": before, "result": result, "after": after, "routes": routes,
                                     "state_preserved": before.get("output") == after.get("output")}
    p.save()
    for route_key, route_id in p.data["owned"]["routes"].items():
        label = route_key.replace("$", "")
        p.required("delete-route-" + label, "apigatewayv2", "delete_route", {"ApiId": api, "RouteId": route_id})
        absent = p.call("absence-route-" + label, "apigatewayv2", "get_route",
            {"ApiId": api, "RouteId": route_id}, required=False)
        p.data.setdefault("route_absence", {})[route_key] = absent["code"] == "NotFoundException"
        p.save()
        if absent["code"] != "NotFoundException":
            raise RuntimeError("Route deletion did not establish absence: " + route_key)
    if result["code"] != "Success":
        delete_authorizer(p, "delete-unreferenced-authorizer", ident)
    else:
        p.data.setdefault("temporary_authorizer_absence", {})[ident] = after["code"] == "NotFoundException"
    p.required("list-authorizers-after-deletion", "apigatewayv2", "get_authorizers", {"ApiId": api})
    p.call("update-deleted-authorizer", "apigatewayv2", "update_authorizer",
        {"ApiId": api, "AuthorizerId": ident, "Name": "deleted-update"}, required=False)
    p.call("delete-authorizer-again", "apigatewayv2", "delete_authorizer",
        {"ApiId": api, "AuthorizerId": ident}, required=False)


def run(p):
    source = Path(__file__).read_bytes()
    p.data.update(scope="One owned WEBSOCKET API: native Lambda REQUEST authorizer admission and CRUD only; no account settings or deployment",
        mode="websocket-authorizer-admission", protocol="WEBSOCKET",
        owned_api_slot="http_api is Probe's cleanup slot for any API Gateway v2 API",
        bounds={"apis": 1, "functions": 1, "roles": 1, "log_groups": 1, "concurrent_authorizers": 2,
            "routes": 4, "stages": 0, "deployments": 0, "function_invocations": 0,
            "function_create_attempts": 15, "function_ready_attempts": 15,
            "function_readiness_interval_seconds": 2, "cleanup_attempts": 3,
            "cleanup_interval_seconds": 2, "sdk_total_max_attempts": 1,
            "sdk_connect_timeout_seconds": 10, "sdk_read_timeout_seconds": 30},
        probe_source=source.decode(), source_sha256=hashlib.sha256(source).hexdigest(), handler_source=HANDLER,
        helper_sources={Path(module.__file__).name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                        for module in (apigateway_probe, apigateway_rest_authorizer_probe)},
        runtime_versions={"python": platform.python_version(), "botocore": botocore.__version__,
                          "lambda_requested": "python3.13"},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-lambda-auth.html",
            "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-authorizers.html",
            "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-authorizers-authorizerid.html"],
        limitations=["Control-plane acceptance, storage and response-field presence only; no inference about authorizer invocation, caching or identity enforcement.",
            "The owned Lambda execution role is used solely to sample credentials-ARN admission; it trusts Lambda, not API Gateway. No role-assumption/trust conclusions.",
            "No WebSocket connection is attempted and the Lambda is never invoked; websocket_observations and invocation_logs are intentionally empty.",
            "Single region, one account, one fresh API; no quotas, pagination, cross-account roles, custom domains or concurrent mutation sampled."],
        create_matrix=[], update_matrix=[], route_matrix=[], websocket_observations=[], invocation_logs=[])
    original = p.client("apigatewayv2")
    config = original.meta.config.merge(Config(parameter_validation=False))
    original.close()
    p.clients["apigatewayv2"] = p.session.client("apigatewayv2", config=config)
    p.data["sdk"]["apigatewayv2_parameter_validation"] = False
    model = p.client("apigatewayv2").meta.service_model
    p.data["modeled_inputs"] = {operation: {"required": model.operation_model(operation).input_shape.required_members,
        "members": {key: {"type": shape.type_name, "metadata": shape.metadata}
                    for key, shape in model.operation_model(operation).input_shape.members.items()}}
        for operation in ("CreateAuthorizer", "UpdateAuthorizer", "CreateRoute", "UpdateRoute")}
    p.save()
    function, role = create_function(p, handler=HANDLER)
    api = p.required("create-websocket-api", "apigatewayv2", "create_api",
        {"Name": p.data["prefix"], "ProtocolType": "WEBSOCKET", "RouteSelectionExpression": "$request.body.action"},
        own=("http_api", "ApiId"))["ApiId"]
    p.data["owned"].update(log_group="/aws/lambda/" + function["FunctionName"], routes={})
    common = {"ApiId": api, "AuthorizerType": "REQUEST",
        "AuthorizerUri": f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations",
        "IdentitySource": ["route.request.header.Authorization"]}
    authorizer = p.required("create-request-defaults", "apigatewayv2", "create_authorizer",
        {**common, "Name": "request-defaults"})
    ident = authorizer["AuthorizerId"]
    p.data["owned"]["baseline_authorizer"] = ident
    authorizer_get(p, "get-request-defaults", ident)
    authorizer_list(p, "list-request-defaults")
    cases = [
        ("type-jwt", {"AuthorizerType": "JWT"}),
        ("type-jwt-configured", {"AuthorizerType": "JWT", "AuthorizerUri": None,
            "IdentitySource": ["$request.header.Authorization"],
            "JwtConfiguration": {"Issuer": "https://example.com", "Audience": ["probe"]}}),
        ("type-token", {"AuthorizerType": "TOKEN"}),
        ("payload-empty", {"AuthorizerPayloadFormatVersion": ""}),
        ("payload-v1", {"AuthorizerPayloadFormatVersion": "1.0"}),
        ("payload-v2", {"AuthorizerPayloadFormatVersion": "2.0"}),
        ("payload-v3", {"AuthorizerPayloadFormatVersion": "3.0"}),
        ("ttl-zero", {"AuthorizerResultTtlInSeconds": 0}),
        ("ttl-one", {"AuthorizerResultTtlInSeconds": 1}),
        ("ttl-sixty", {"AuthorizerResultTtlInSeconds": 60}),
        ("ttl-max", {"AuthorizerResultTtlInSeconds": 3600}),
        ("ttl-negative", {"AuthorizerResultTtlInSeconds": -1}),
        ("ttl-over-max", {"AuthorizerResultTtlInSeconds": 3601}),
        ("simple-false", {"EnableSimpleResponses": False}),
        ("simple-true", {"EnableSimpleResponses": True}),
        ("payload-v2-simple-false", {"AuthorizerPayloadFormatVersion": "2.0", "EnableSimpleResponses": False}),
        ("payload-v2-simple-true", {"AuthorizerPayloadFormatVersion": "2.0", "EnableSimpleResponses": True}),
        ("identity-omitted", {"IdentitySource": None}),
        ("identity-empty-list", {"IdentitySource": []}),
        ("identity-empty-string", {"IdentitySource": [""]}),
        ("identity-empty-header", {"IdentitySource": ["route.request.header."]}),
        ("identity-invalid-literal", {"IdentitySource": ["invalid"]}),
        ("identity-route-query", {"IdentitySource": ["route.request.querystring.tenant"]}),
        ("identity-route-header-query", {"IdentitySource": ["route.request.header.Authorization", "route.request.querystring.tenant"]}),
        ("identity-dollar-header", {"IdentitySource": ["$request.header.Authorization"]}),
        ("identity-dollar-query", {"IdentitySource": ["$request.querystring.tenant"]}),
        ("identity-dollar-context", {"IdentitySource": ["$context.routeKey"]}),
        ("identity-dollar-stage-variable", {"IdentitySource": ["$stageVariables.tenant"]}),
        ("identity-context", {"IdentitySource": ["context.routeKey"]}),
        ("identity-stage-variable", {"IdentitySource": ["stageVariables.tenant"]}),
        ("identity-route-context", {"IdentitySource": ["route.request.context.routeKey"]}),
        ("identity-route-stage-variable", {"IdentitySource": ["route.request.stageVariables.tenant"]}),
        ("identity-rest-header", {"IdentitySource": ["method.request.header.Authorization"]}),
        ("identity-route-body", {"IdentitySource": ["route.request.body.action"]}),
        ("identity-whitespace", {"IdentitySource": ["route.request.header.Invalid Name"]}),
        ("identity-empty-ttl-positive", {"IdentitySource": [], "AuthorizerResultTtlInSeconds": 60}),
        ("identity-empty-ttl-zero", {"IdentitySource": [], "AuthorizerResultTtlInSeconds": 0}),
        ("validation-expression", {"IdentityValidationExpression": "^probe-.*$"}),
        ("validation-expression-empty", {"IdentityValidationExpression": ""}),
        ("validation-expression-invalid-regex", {"IdentityValidationExpression": "["}),
        ("credentials-owned-role", {"AuthorizerCredentialsArn": role["Arn"]}),
        ("credentials-empty", {"AuthorizerCredentialsArn": ""}),
        ("credentials-invalid", {"AuthorizerCredentialsArn": "not-an-arn"}),
    ]
    p.data["bounds"]["create_admission_cases"] = len(cases) + 1
    p.save()
    for label, overrides in cases:
        create_case(p, common, label, overrides)
    changes = [
        ("rename", {"Name": "renamed-request"}),
        ("identity-query", {"IdentitySource": ["route.request.querystring.tenant"]}),
        ("reject-invalid-source-atomic", {"Name": "rejected-source-name", "IdentitySource": ["invalid"]}),
        ("reject-token-atomic", {"Name": "rejected-token-name", "AuthorizerType": "TOKEN"}),
        ("payload-v2", {"AuthorizerPayloadFormatVersion": "2.0"}),
        ("payload-empty", {"AuthorizerPayloadFormatVersion": ""}),
        ("ttl-zero", {"AuthorizerResultTtlInSeconds": 0}),
        ("ttl-sixty", {"AuthorizerResultTtlInSeconds": 60}),
        ("ttl-negative-atomic", {"Name": "rejected-ttl-name", "AuthorizerResultTtlInSeconds": -1}),
        ("simple-false", {"EnableSimpleResponses": False}),
        ("simple-true", {"EnableSimpleResponses": True}),
        ("validation-expression", {"IdentityValidationExpression": "^probe-.*$"}),
        ("validation-expression-empty", {"IdentityValidationExpression": ""}),
        ("credentials-owned-role", {"AuthorizerCredentialsArn": role["Arn"]}),
        ("credentials-omitted", {"Name": "credentials-retained"}),
        ("credentials-invalid-atomic", {"Name": "rejected-credentials-name", "AuthorizerCredentialsArn": "not-an-arn"}),
        ("credentials-clear", {"AuthorizerCredentialsArn": ""}),
        ("identity-clear", {"IdentitySource": []}),
        ("restore-header", {"IdentitySource": ["route.request.header.Authorization"]}),
    ]
    p.data["bounds"]["update_admission_cases"] = len(changes)
    p.save()
    for label, fields in changes:
        update_case(p, ident, label, fields)
    authorizer_list(p, "list-after-updates")
    route_cases(p, ident)
    p.data["completed_at"] = now()
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/websocket_authorizer_admission.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--append-capture", action="store_true",
        help="Preserve a completely cleaned prior capture and run with fresh owned infrastructure")
    args = parser.parse_args()
    if args.cleanup_only and args.append_capture:
        parser.error("--cleanup-only and --append-capture are mutually exclusive")
    p = Probe(args.output, args.account, args.cleanup_only or args.append_capture)
    if args.append_capture:
        previous = p.data
        if previous.get("mode") != "websocket-authorizer-admission" or not previous.get("cleanup", {}).get("complete"):
            raise RuntimeError("Can append only to a fully cleaned WebSocket admission capture")
        earlier = previous.pop("prior_captures", [])
        p.data = {"service": "apigateway", "account": args.account, "region": REGION,
            "identity": p.client("sts").get_caller_identity(), "captured_at": now(),
            "prefix": "stackd-apigw-" + uuid.uuid4().hex[:10], "owned": {}, "observations": [],
            "http": [], "tokens": {}, "cleanup": {}, "sdk": previous["sdk"], "prior_captures": earlier + [previous]}
    try:
        if not args.cleanup_only:
            run(p)
    except BaseException as error:
        p.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        p.save()
        raise
    finally:
        try:
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


if __name__ == "__main__":
    main()
