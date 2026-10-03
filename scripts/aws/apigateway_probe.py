#!/usr/bin/env python3
"""Capture owned REST/HTTP API Lambda and Cognito workflows; never change GetAccount settings.

Requires boto3 and the existing Cognito probe dependencies. Creates two APIs, one
Lambda execution role/function, one Lite Cognito pool and one synthetic user.
--cleanup resumes deletion from the persisted owned-resource inventory.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import time
import urllib.error
import urllib.request
import uuid
import zipfile

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.exceptions import ClientError
from cognito_login_probe import jwt_projection

REGION = "us-east-1"
HANDLER = '''import json

def handler(event, context):
    # Do not copy bearer credentials into the response or customer logs.
    for name in ("headers", "multiValueHeaders"):
        for key in list((event.get(name) or {})):
            if key.lower() in ("authorization", "x-amz-security-token"):
                event[name][key] = "HIDDEN_BY_PROBE"
    return {"statusCode": 200, "headers": {"content-type": "application/json", "x-probe": "actual-lambda"},
            "body": json.dumps({"event": event, "function": context.function_name})}
'''


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Probe:
    def __init__(self, path, account, cleanup):
        self.path = path
        self.session = boto3.Session(region_name=REGION)
        self.clients = {}
        self.hidden = {}
        identity = self.client("sts").get_caller_identity()
        if identity["Account"] != account:
            raise RuntimeError("Native account does not match --account")
        if cleanup:
            self.data = json.loads(path.read_text())
            if self.data["account"] != account or self.data["region"] != REGION:
                raise RuntimeError("Capture ownership does not match native account/region")
        else:
            if path.exists():
                raise RuntimeError("Refusing to overwrite evidence")
            self.data = {"service": "apigateway", "account": account, "region": REGION,
                "identity": identity, "captured_at": now(), "prefix": "stackd-apigw-" + uuid.uuid4().hex[:10],
                "scope": "Owned REST/HTTP deployed Lambda routes, Cognito/JWT and IAM authorization; no account-level logging changes",
                "bounds": {"apis": 2, "functions": 1, "roles": 1, "pools": 1, "users": 1, "readiness_attempts": 15},
                "owned": {}, "observations": [], "http": [], "tokens": {}, "cleanup": {},
                "documentation": [
                    "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html",
                    "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html",
                    "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html"],
                "probe_source": Path(__file__).read_text(), "handler_source": HANDLER,
                "sdk": {"boto3": boto3.__version__}}
            self.save()

    def client(self, service):
        if service not in self.clients:
            self.clients[service] = self.session.client(service, config=Config(
                retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30))
        return self.clients[service]

    def sanitize(self, value):
        if isinstance(value, dict):
            return {key: self.sanitize(child) for key, child in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.sanitize(child) for child in value]
        if isinstance(value, bytes):
            return {"base64": base64.b64encode(value).decode()}
        if isinstance(value, datetime.datetime):
            return value.isoformat()
        if isinstance(value, str):
            # CloudWatch execution/access messages can contain credentials issued
            # to AWS services, not just credentials this probe created or signed.
            for match in re.finditer(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", value):
                self.hide(match.group(), "accesskeyid")
            for match in re.finditer(r"(?i)\bX-Amz-Security-Token[=:]\s*([^,\s}]+)", value):
                token = match.group(1)
                if not token.startswith("<redacted-"):
                    self.hide(token, "sessiontoken")
            for secret, marker in self.hidden.items():
                value = value.replace(secret, marker)
        return value

    def hide(self, value, kind):
        self.hidden[value] = "<redacted-" + kind + "-sha256:" + hashlib.sha256(value.encode()).hexdigest() + ">"
        return value

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.sanitize(self.data), indent=2) + "\n")

    def call(self, label, service, method, parameters=None, *, own=None, required=True):
        client = self.client(service)
        started = now()
        try:
            output = getattr(client, method)(**(parameters or {}))
            metadata = output.pop("ResponseMetadata", {})
            result = {"code": "Success", "http_status": metadata.get("HTTPStatusCode"),
                "request_id": metadata.get("RequestId"), "output": output}
        except ClientError as error:
            metadata = error.response.get("ResponseMetadata", {})
            result = {"code": error.response["Error"]["Code"], "error": error.response["Error"],
                "http_status": metadata.get("HTTPStatusCode"), "request_id": metadata.get("RequestId")}
        if own and result["code"] == "Success":
            key, field = own
            value = result["output"]
            for part in field.split("."):
                value = value[part]
            self.data["owned"][key] = value
        # Capture secrets before serializing any successful authentication result.
        authentication = result.get("output", {}).get("AuthenticationResult", {})
        for key in ("AccessToken", "IdToken", "RefreshToken"):
            if key in authentication:
                self.hide(authentication[key], key.lower())
        self.data["observations"].append({"label": label, "service": service,
            "operation": client.meta.method_to_api_mapping[method], "input": parameters or {},
            "started_at": started, "finished_at": now(), "result": result})
        self.save()
        print(label + ": " + result["code"], flush=True)
        if required and result["code"] != "Success":
            raise RuntimeError(label + ": " + result["code"])
        return result

    def required(self, label, service, method, parameters=None, **kwargs):
        return self.call(label, service, method, parameters, **kwargs)["output"]

    def http(self, label, api, path, *, authorization="none", token=None):
        endpoint = self.data["owned"][api + "_endpoint"]
        headers = {"User-Agent": "stackd-native-gateway-probe", "X-Probe": label}
        if token:
            headers["Authorization"] = "Bearer " + token
        url = endpoint + path
        if authorization == "iam":
            request = AWSRequest(method="GET", url=url, headers=headers)
            SigV4Auth(self.session.get_credentials().get_frozen_credentials(), "execute-api", REGION).add_auth(request)
            headers = dict(request.headers)
        started = now()
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except urllib.error.URLError as error:
            result = {"transport_error": str(error.reason)}
        else:
            result = None
        if "response" in locals():
            with response:
                body = response.read(1 << 20)
                result = {"status": response.status, "headers": list(response.headers.items())}
                try:
                    result["body"] = json.loads(body)
                except (ValueError, UnicodeDecodeError):
                    result["body_base64"] = base64.b64encode(body).decode()
        self.data["http"].append({"label": label, "api": api, "path": path,
            "method": "GET", "authorization": authorization, "started_at": started,
            "finished_at": now(), "result": result})
        self.save()
        print(label + ": " + str(result.get("status", "transport error")), flush=True)
        return result

    def ready(self, api, path, expected):
        for attempt in range(self.data["bounds"]["readiness_attempts"]):
            result = self.http("ready-" + api + "-" + str(attempt), api, path)
            if result.get("status") == expected:
                return
            time.sleep(2)
        raise RuntimeError("Owned " + api + " deployment did not become ready")

    def cleanup(self):
        owned = self.data["owned"]
        items = []
        for key, service, deletion, lookup, parameter in (
                ("http_api", "apigatewayv2", "delete_api", "get_api", "ApiId"),
                ("rest_api", "apigateway", "delete_rest_api", "get_rest_api", "restApiId"),
                ("pool", "cognito-idp", "delete_user_pool", "describe_user_pool", "UserPoolId"),
                ("function", "lambda", "delete_function", "get_function", "FunctionName")):
            if key in owned:
                result = self.call("cleanup-" + key, service, deletion, {parameter: owned[key]}, required=False)
                absent = self.call("absence-" + key, service, lookup, {parameter: owned[key]}, required=False)
                items.append(absent["code"] in ("NotFoundException", "ResourceNotFoundException"))
                self.data["cleanup"][key] = {"delete_code": result["code"], "absent": items[-1]}
        if "role" in owned:
            role = owned["role"]
            self.call("cleanup-role-policy", "iam", "delete_role_policy", {"RoleName": role, "PolicyName": "probe-logs"}, required=False)
            self.call("cleanup-role", "iam", "delete_role", {"RoleName": role}, required=False)
            absent = self.call("absence-role", "iam", "get_role", {"RoleName": role}, required=False)
            items.append(absent["code"] == "NoSuchEntity")
            self.data["cleanup"]["role"] = {"absent": items[-1]}
        if "function" in owned:
            group = "/aws/lambda/" + owned["function"]
            self.call("cleanup-log-group", "logs", "delete_log_group", {"logGroupName": group}, required=False)
            groups = self.required("absence-log-group", "logs", "describe_log_groups", {"logGroupNamePrefix": group})
            items.append(not any(item["logGroupName"] == group for item in groups["logGroups"]))
            self.data["cleanup"]["log_group"] = {"absent": items[-1]}
        self.data["cleanup"]["complete"] = all(items)
        self.save()
        if not all(items):
            raise RuntimeError("Owned resource cleanup remains incomplete")


def run(p):
    name, account = p.data["prefix"], p.data["account"]
    p.required("account-before", "apigateway", "get_account")
    role = p.required("create-role", "iam", "create_role", {"RoleName": name,
        "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}, own=("role", "Role.RoleName"))["Role"]
    p.required("role-logs", "iam", "put_role_policy", {"RoleName": name, "PolicyName": "probe-logs",
        "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:{REGION}:{account}:log-group:/aws/lambda/{name}:*"}]})})
    rest = p.required("create-rest", "apigateway", "create_rest_api", {"name": name,
        "endpointConfiguration": {"types": ["REGIONAL"]}}, own=("rest_api", "id"))
    http = p.required("create-http", "apigatewayv2", "create_api", {"Name": name, "ProtocolType": "HTTP"}, own=("http_api", "ApiId"))
    p.data["owned"].update(rest_endpoint=f"https://{rest['id']}.execute-api.{REGION}.amazonaws.com", http_endpoint=http["ApiEndpoint"])
    pool = p.required("create-pool", "cognito-idp", "create_user_pool", {"PoolName": name, "UserPoolTier": "LITE"}, own=("pool", "UserPool.Id"))["UserPool"]
    client = p.required("create-client", "cognito-idp", "create_user_pool_client", {"UserPoolId": pool["Id"], "ClientName": name,
        "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]})["UserPoolClient"]
    password = p.hide("GatewayA1!" + secrets.token_hex(12), "password")
    p.required("create-user", "cognito-idp", "admin_create_user", {"UserPoolId": pool["Id"], "Username": "gateway-user", "TemporaryPassword": password, "MessageAction": "SUPPRESS"})
    p.required("set-password", "cognito-idp", "admin_set_user_password", {"UserPoolId": pool["Id"], "Username": "gateway-user", "Password": password, "Permanent": True})
    tokens = p.required("login", "cognito-idp", "initiate_auth", {"ClientId": client["ClientId"], "AuthFlow": "USER_PASSWORD_AUTH",
        "AuthParameters": {"USERNAME": "gateway-user", "PASSWORD": password}})["AuthenticationResult"]
    issuer = f"https://cognito-idp.{REGION}.amazonaws.com/{pool['Id']}"
    with urllib.request.urlopen(issuer + "/.well-known/jwks.json", timeout=30) as response:
        jwks = json.load(response)
    p.data["jwks"] = jwks
    for member, use in (("IdToken", "id"), ("AccessToken", "access")):
        p.data["tokens"][use] = jwt_projection(tokens[member], jwks, issuer, client["ClientId"], use)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        output.writestr("index.py", HANDLER)
    for attempt in range(15):
        result = p.call("create-function-" + str(attempt), "lambda", "create_function", {"FunctionName": name, "Role": role["Arn"],
            "Runtime": "python3.13", "Handler": "index.handler", "MemorySize": 128, "Timeout": 3,
            "Code": {"ZipFile": archive.getvalue()}}, own=("function", "FunctionName"), required=False)
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
            break
        if current["State"] == "Failed":
            raise RuntimeError("Native Lambda activation failed")
        time.sleep(2)
    else:
        raise RuntimeError("Native Lambda readiness bound reached")
    for kind, api_id in (("rest", rest["id"]), ("http", http["ApiId"])):
        p.required("permission-" + kind, "lambda", "add_permission", {"FunctionName": name, "StatementId": kind,
            "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
            "SourceArn": f"arn:aws:execute-api:{REGION}:{account}:{api_id}/*"})
    integration = p.required("http-integration", "apigatewayv2", "create_integration", {"ApiId": http["ApiId"],
        "IntegrationType": "AWS_PROXY", "IntegrationUri": function["FunctionArn"], "PayloadFormatVersion": "2.0"})
    jwt = p.required("http-authorizer", "apigatewayv2", "create_authorizer", {"ApiId": http["ApiId"], "Name": "jwt", "AuthorizerType": "JWT",
        "IdentitySource": ["$request.header.Authorization"], "JwtConfiguration": {"Issuer": issuer, "Audience": [client["ClientId"]]}})
    for route, auth, scopes in (("ANY /echo", "NONE", None), ("GET /iam", "AWS_IAM", None), ("GET /jwt", "JWT", None),
                               ("GET /scope", "JWT", ["aws.cognito.signin.user.admin"])):
        parameters = {"ApiId": http["ApiId"], "RouteKey": route, "Target": "integrations/" + integration["IntegrationId"], "AuthorizationType": auth}
        if auth == "JWT":
            parameters["AuthorizerId"] = jwt["AuthorizerId"]
        if scopes is not None:
            parameters["AuthorizationScopes"] = scopes
        p.required("http-route-" + route, "apigatewayv2", "create_route", parameters)
    p.call("http-invalid-literal-management-route", "apigatewayv2", "create_route",
        {"ApiId": http["ApiId"], "RouteKey": "GET /@connections/{id}",
         "Target": "integrations/" + integration["IntegrationId"], "AuthorizationType": "NONE"}, required=False)
    p.required("http-stage", "apigatewayv2", "create_stage", {"ApiId": http["ApiId"], "StageName": "$default", "AutoDeploy": False})
    p.http("http-before-deployment", "http", "/echo")
    deployment = p.required("http-deploy", "apigatewayv2", "create_deployment", {"ApiId": http["ApiId"]})
    p.required("http-select-deployment", "apigatewayv2", "update_stage", {"ApiId": http["ApiId"], "StageName": "$default", "DeploymentId": deployment["DeploymentId"]})
    root = p.required("rest-resources", "apigateway", "get_resources", {"restApiId": rest["id"]})["items"][0]["id"]
    authorizer = p.required("rest-authorizer", "apigateway", "create_authorizer", {"restApiId": rest["id"], "name": "cognito", "type": "COGNITO_USER_POOLS",
        "providerARNs": [pool["Arn"]], "identitySource": "method.request.header.Authorization"})
    uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function['FunctionArn']}/invocations"
    for part, auth, scopes in (("echo", "NONE", None), ("iam", "AWS_IAM", None), ("jwt", "COGNITO_USER_POOLS", None),
                               ("scope", "COGNITO_USER_POOLS", ["aws.cognito.signin.user.admin"])):
        resource = p.required("rest-resource-" + part, "apigateway", "create_resource", {"restApiId": rest["id"], "parentId": root, "pathPart": part})
        parameters = {"restApiId": rest["id"], "resourceId": resource["id"], "httpMethod": "GET", "authorizationType": auth}
        if auth == "COGNITO_USER_POOLS":
            parameters["authorizerId"] = authorizer["id"]
        if scopes is not None:
            parameters["authorizationScopes"] = scopes
        p.required("rest-method-" + part, "apigateway", "put_method", parameters)
        p.required("rest-integration-" + part, "apigateway", "put_integration", {"restApiId": rest["id"], "resourceId": resource["id"], "httpMethod": "GET",
            "type": "AWS_PROXY", "integrationHttpMethod": "POST", "uri": uri})
    p.http("rest-before-deployment", "rest", "/dev/echo")
    p.required("rest-deploy", "apigateway", "create_deployment", {"restApiId": rest["id"], "stageName": "dev"})
    for kind, prefix in (("http", ""), ("rest", "/dev")):
        p.ready(kind, prefix + "/echo", 200)
        p.http(kind + "-query", kind, prefix + "/echo?dup=one&dup=two&empty=&encoded=a%2Bb")
        p.http(kind + "-missing", kind, prefix + "/not-present")
        p.http(kind + "-iam-unsigned", kind, prefix + "/iam")
        p.http(kind + "-iam-signed", kind, prefix + "/iam", authorization="iam")
        p.http(kind + "-jwt-missing", kind, prefix + "/jwt")
        p.http(kind + "-jwt-invalid", kind, prefix + "/jwt", token="invalid-jwt", authorization="invalid")
        for member, use in (("IdToken", "id"), ("AccessToken", "access")):
            p.http(kind + "-jwt-" + use, kind, prefix + "/jwt", token=tokens[member], authorization=use)
            p.http(kind + "-scope-" + use, kind, prefix + "/scope", token=tokens[member], authorization=use)
    p.http("http-literal-management-path", "http", "/@connections/not-a-websocket")
    p.required("revoke-refresh", "cognito-idp", "revoke_token", {"ClientId": client["ClientId"], "Token": tokens["RefreshToken"]})
    p.call("cognito-revoked-access", "cognito-idp", "get_user", {"AccessToken": tokens["AccessToken"]}, required=False)
    for kind, prefix in (("http", ""), ("rest", "/dev")):
        p.http(kind + "-jwt-after-revocation", kind, prefix + "/jwt", token=tokens["IdToken"], authorization="id")
        p.http(kind + "-scope-after-revocation", kind, prefix + "/scope", token=tokens["AccessToken"], authorization="access")
    p.required("account-after", "apigateway", "get_account")
    p.data["completed_at"] = now()
    p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/deployed_lambda_authorization.json"))
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    probe = Probe(args.output, args.account, args.cleanup)
    try:
        if not args.cleanup:
            run(probe)
    finally:
        probe.cleanup()
        for client in probe.clients.values():
            client.close()


if __name__ == "__main__":
    main()
