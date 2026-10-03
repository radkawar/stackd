#!/usr/bin/env python3
"""Capture owned REST API key/usage-plan controls; always clean up, never change GetAccount."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import time
import uuid

import boto3
import botocore
from botocore.exceptions import ParamValidationError

import apigateway_probe as base
from apigateway_probe import Probe, REGION, now

TARGETS = ["CreateApiKey", "DeleteApiKey", "GetApiKey", "GetApiKeys", "UpdateApiKey", "ImportApiKeys",
           "CreateUsagePlan", "DeleteUsagePlan", "GetUsagePlan", "GetUsagePlans", "UpdateUsagePlan",
           "CreateUsagePlanKey", "DeleteUsagePlanKey", "GetUsagePlanKey", "GetUsagePlanKeys"]


class KeysProbe(Probe):
    """Use the shared SDK ledger, projecting lists before any serialization."""

    def sanitize(self, value):
        if isinstance(value, dict):
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
                if isinstance(value.get(key), str) and not value[key].startswith("<redacted-"):
                    self.hide(value[key], key.lower())
        return super().sanitize(value)

    def save(self):
        if not hasattr(self, "envelope"):
            return super().save()
        self.envelope["distinct_id_capture"] = self.sanitize(self.data)
        self.path.write_text(json.dumps(self.envelope, indent=2) + "\n")

    def call(self, label, service, method, parameters=None, **kwargs):
        parameters = parameters or {}
        index = len(self.data["observations"])
        client = self.client(service)
        operation = client.meta.method_to_api_mapping[method]
        evidence = {}
        # Respect documented account-level control rates, not data-plane quotas.
        intervals = {"update_usage_plan": 21, "delete_rest_api": 31}
        if not hasattr(self, "last_calls"):
            self.last_calls = {}
        interval = intervals.get(method, 0.45)
        delay = max(0.45, interval - (time.monotonic() - self.last_calls.get(method, 0)))
        time.sleep(delay)
        self.last_calls[method] = time.monotonic()
        if method.startswith(("create_", "import_")):
            self.data.setdefault("mutation_intents", []).append({"label": label, "operation": operation,
                "input": parameters, "at": now()})
            if method == "create_role":
                self.data["owned"]["role"] = parameters["RoleName"]
            elif method == "create_stage":
                stages = self.data["owned"].setdefault("stages", [])
                if parameters["stageName"] not in stages:
                    stages.append(parameters["stageName"])
            self.save()

        def before_call(params, **unused):
            evidence["request"] = {key: params[key] for key in ("method", "url_path", "query_string", "body") if key in params}

        def after_call(parsed, **unused):
            evidence["response_metadata"] = parsed.get("ResponseMetadata", {})
            owned = self.data["owned"]
            if operation in ("GetApiKeys", "GetUsagePlans", "GetUsagePlanKeys", "GetRestApis") and "items" in parsed:
                family = {"GetUsagePlans": "plans", "GetRestApis": "apis"}.get(operation, "keys")
                known = owned.get(family, [])
                items = parsed["items"]
                parsed["items"] = [item for item in items if item.get("id") in known
                    or (item.get("name") or "").startswith(self.data["prefix"])
                    or item.get("tags", {}).get("Capture") == self.data["prefix"]
                    or (operation == "GetUsagePlans" and owned.get("rest_api") and any(
                        stage.get("apiId") == owned["rest_api"] for stage in item.get("apiStages", [])))]
                evidence["projection"] = {"scope": "owned IDs, unique name/tag marker, or owned API stage only",
                    "omitted_unowned_count": len(items) - len(parsed["items"]),
                    "position": "opaque service token retained; account-wide ordering not inferred"}
                if operation in ("GetApiKeys", "GetUsagePlans"):
                    for item in parsed["items"]:
                        if item["id"] not in owned.setdefault(family, []):
                            owned[family].append(item["id"])
                elif operation == "GetRestApis":
                    if len(parsed["items"]) > 1:
                        raise RuntimeError("Ambiguous owned API discovery")
                    if parsed["items"]:
                        owned["rest_api"] = parsed["items"][0]["id"]
                elif operation == "GetUsagePlanKeys":
                    for item in parsed["items"]:
                        pair = {"usagePlanId": parameters["usagePlanId"], "keyId": item["id"]}
                        if pair not in owned.setdefault("associations", []):
                            owned["associations"].append(pair)
            if "Error" not in parsed:
                if operation in ("CreateApiKey", "CreateUsagePlan"):
                    family = "keys" if operation == "CreateApiKey" else "plans"
                    if parsed["id"] not in owned.setdefault(family, []):
                        owned[family].append(parsed["id"])
                elif operation == "ImportApiKeys":
                    for ident in parsed.get("ids", []):
                        if ident not in owned.setdefault("keys", []):
                            owned["keys"].append(ident)
                elif operation == "CreateRestApi":
                    owned["rest_api"] = parsed["id"]
                elif operation == "CreateRole":
                    owned["role"] = parsed["Role"]["RoleName"]
                elif operation == "CreateStage":
                    if parameters["stageName"] not in owned.setdefault("stages", []):
                        owned["stages"].append(parameters["stageName"])
                elif operation == "CreateUsagePlanKey":
                    pair = {"usagePlanId": parameters["usagePlanId"], "keyId": parameters["keyId"]}
                    if pair not in owned.setdefault("associations", []):
                        owned["associations"].append(pair)
            self.save()

        event = client.meta.service_model.service_id.hyphenize()
        client.meta.events.register("before-call." + event + "." + operation, before_call)
        client.meta.events.register("after-call." + event + "." + operation, after_call)
        try:
            try:
                return super().call(label, service, method, parameters, **kwargs)
            except ParamValidationError as error:
                result = {"code": "ParamValidationError", "error": {"Message": str(error)},
                          "http_status": None, "boundary": "SDK; no service request"}
                self.data["observations"].append({"label": label, "service": service, "operation": operation,
                    "input": parameters, "started_at": now(), "finished_at": now(), "result": result})
                if kwargs.get("required", True):
                    raise
                return result
        finally:
            client.meta.events.unregister("before-call." + event + "." + operation, before_call)
            client.meta.events.unregister("after-call." + event + "." + operation, after_call)
            for row in self.data["observations"][index:]:
                row.update(evidence, actor=getattr(self, "actor", self.data["identity"]),
                           phase=getattr(self, "phase", "semantic"))
            self.save()

    def cleanup(self):
        self.phase = "cleanup"
        self.actor = self.data["identity"]
        owned = self.data["owned"]
        # A CSV operation can mutate keys even when it returns an error. Rediscover
        # only the persisted unique prefix, including after an interrupted run.
        pages(self, "cleanup-discover-keys", "get_api_keys", {"nameQuery": self.data["prefix"], "limit": 100})
        unnamed = any(row["operation"] == "CreateApiKey" and "name" not in row["input"]
                      for row in self.data.get("mutation_intents", []))
        if unnamed:
            pages(self, "cleanup-discover-unnamed-key", "get_api_keys", {"limit": 100})
        # These APIs have no name filter. The after-call projection runs before
        # Probe saves anything; discover only this run's unique names.
        pages(self, "cleanup-discover-plans", "get_usage_plans", {"limit": 100})
        pages(self, "cleanup-discover-api", "get_rest_apis", {"limit": 100})
        checks = {}
        for stage in owned.get("stages", []):
            target = {"restApiId": owned["rest_api"], "stageName": stage}
            self.call("cleanup-stage-" + stage, "apigateway", "delete_stage", target, required=False)
            absent = self.call("absence-stage-" + stage, "apigateway", "get_stage", target, required=False)
            checks["stage/" + stage] = {"absent": absent["code"] == "NotFoundException"}
        if "rest_api" in owned:
            target = {"restApiId": owned["rest_api"]}
            self.call("cleanup-api", "apigateway", "delete_rest_api", target, required=False)
            absent = self.call("absence-api", "apigateway", "get_rest_api", target, required=False)
            checks["api"] = {"absent": absent["code"] == "NotFoundException"}
        for family, delete, get, parameter in (("plans", "delete_usage_plan", "get_usage_plan", "usagePlanId"),
                                               ("keys", "delete_api_key", "get_api_key", "apiKey")):
            for ident in owned.get(family, []):
                deletion = self.call("cleanup-" + family + "-" + ident, "apigateway", delete, {parameter: ident}, required=False)
                absent = self.call("absence-" + family + "-" + ident, "apigateway", get, {parameter: ident}, required=False)
                checks[family + "/" + ident] = {"delete_code": deletion["code"], "absent": absent["code"] == "NotFoundException"}
        if "role" in owned:
            target = {"RoleName": owned["role"]}
            self.call("cleanup-role-policy", "iam", "delete_role_policy", {**target, "PolicyName": "probe-authority"}, required=False)
            self.call("cleanup-role", "iam", "delete_role", target, required=False)
            absent = self.call("absence-role", "iam", "get_role", target, required=False)
            checks["role"] = {"absent": absent["code"] == "NoSuchEntity"}
        remaining = pages(self, "absence-prefix-keys", "get_api_keys", {"nameQuery": self.data["prefix"], "limit": 100})
        checks["prefix-keys"] = {"absent": not remaining}
        if unnamed:
            checks["marker-keys"] = {"absent": not pages(self, "absence-marker-keys", "get_api_keys", {"limit": 100})}
        checks["prefix-plans"] = {"absent": not pages(self, "absence-prefix-plans", "get_usage_plans", {"limit": 100})}
        checks["prefix-api"] = {"absent": not pages(self, "absence-prefix-api", "get_rest_apis", {"limit": 100})}
        for pair in owned.get("associations", []):
            absent = self.call("absence-association-" + pair["usagePlanId"] + "-" + pair["keyId"],
                               "apigateway", "get_usage_plan_key", pair, required=False)
            checks["association/" + pair["usagePlanId"] + "/" + pair["keyId"]] = {"absent": absent["code"] == "NotFoundException"}
        self.data["cleanup"] = {"resources": checks, "complete": all(row["absent"] for row in checks.values()), "verified_at": now()}
        self.save()
        if not self.data["cleanup"]["complete"]:
            raise RuntimeError("Owned key/plan cleanup incomplete")


def control(p, label, method, parameters=None, required=True):
    return p.call(label, "apigateway", method, parameters, required=required)


def output(p, label, method, parameters=None):
    return control(p, label, method, parameters)["output"]


def pages(p, label, method, parameters):
    found, position = [], None
    for number in range(20):
        request = dict(parameters)
        if position:
            request["position"] = position
        result = output(p, label + "-page-" + str(number), method, request)
        found.extend(result.get("items", []))
        position = result.get("position")
        if not position:
            return found
    raise RuntimeError(label + ": exceeded bounded owned pagination")


def patch(p, label, family, ident, operations, required=True):
    method, parameter = ("update_api_key", "apiKey") if family == "key" else ("update_usage_plan", "usagePlanId")
    result = control(p, label, method, {parameter: ident, "patchOperations": operations}, required=required)
    control(p, label + "-retained", "get_api_key" if family == "key" else "get_usage_plan",
            {parameter: ident, **({"includeValue": True} if family == "key" else {})})
    return result


def replace(path, value):
    return {"op": "replace", "path": path, "value": value}


def associate(p, label, plan, key, required=True, key_type="API_KEY"):
    return control(p, label, "create_usage_plan_key", {"usagePlanId": plan, "keyId": key, "keyType": key_type}, required)


def imports(p, plan):
    prefix = p.data["prefix"]
    values = [uuid.uuid4().hex for unused in range(4)]
    good = "kEy,NaMe,Description,Enabled,UsagePlanIds,Ignored\n" + values[0] + "," + prefix + "-csv-good,quoted import,true," + plan + ",ignored\n"
    for label, text, fail in (
            ("csv-valid-mixed-case-columns", good, False),
            ("csv-overwrite-existing-value", "Key,Name,Enabled\n" + values[0] + "," + prefix + "-csv-renamed,false\n", False),
            ("csv-partial-keep-valid", "Name,Key\n" + prefix + "-csv-partial," + values[1] + "\n" + prefix + "-csv-short,short\n", False),
            ("csv-rollback-on-warning", "Name,Key\n" + prefix + "-csv-rollback," + values[2] + "\n" + prefix + "-csv-rollback-short,short\n", True),
            ("csv-invalid-plan-partial", "Name,Key,UsagePlanIds\n" + prefix + "-csv-missing-plan," + values[3] + ",zzzzzz\n", False),
            ("csv-missing-key-column", "Name,Description\n" + prefix + "-csv-missing,missing key column\n", False)):
        if fail:
            output(p, "csv-fail-on-warning-fresh-name-absent", "get_api_keys",
                   {"nameQuery": prefix + "-csv-rollback", "includeValues": True})
        control(p, label, "import_api_keys", {"body": text.encode(), "format": "csv", "failOnWarnings": fail}, False)
        # A separate state read records partial effects and discovers IDs even on errors.
        pages(p, label + "-retained", "get_api_keys", {"nameQuery": prefix + "-csv", "includeValues": True, "limit": 100})
    pages(p, "csv-plan-members", "get_usage_plan_keys", {"usagePlanId": plan, "nameQuery": prefix})


def tags(p, family, ident):
    arn = "arn:aws:apigateway:" + REGION + "::/" + family + "/" + ident
    output(p, family + "-tags-created", "get_tags", {"resourceArn": arn})
    output(p, family + "-tags-merge", "tag_resource", {"resourceArn": arn, "tags": {"Owner": "control", "Mutable": "added", "Empty": ""}})
    output(p, family + "-tags-merged", "get_tags", {"resourceArn": arn})
    output(p, family + "-tags-remove", "untag_resource", {"resourceArn": arn, "tagKeys": ["Mutable", "Absent"]})
    output(p, family + "-tags-retained", "get_tags", {"resourceArn": arn})


def iam_cases(p, key, other_key, plan, other_plan):
    arn = "arn:aws:apigateway:" + REGION + "::/"
    key_arn, plan_arn = arn + "apikeys/" + key, arn + "usageplans/" + plan
    principal = {"AWS": p.data["identity"]["Arn"]}
    role = p.required("create-scoped-role", "iam", "create_role", {"RoleName": p.data["prefix"] + "-actor",
        "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": principal, "Action": "sts:AssumeRole"}]})})["Role"]
    allow = {"Effect": "Allow", "Action": ["apigateway:GET", "apigateway:PATCH", "apigateway:POST", "apigateway:DELETE"],
             "Resource": [key_arn, plan_arn, plan_arn + "/keys", plan_arn + "/keys/*"]}
    p.required("scoped-role-policy", "iam", "put_role_policy", {"RoleName": role["RoleName"], "PolicyName": "probe-authority",
        "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [allow]})})
    original = {service: p.client(service) for service in ("apigateway", "sts")}
    for mode in ("allow", "deny"):
        statements = [allow]
        if mode == "deny":
            statements += [{"Effect": "Deny", "Action": ["apigateway:PATCH", "apigateway:DELETE"],
                            "Resource": [key_arn, plan_arn, plan_arn + "/keys/*"]}]
        policy = json.dumps({"Version": "2012-10-17", "Statement": statements})
        p.phase = "readiness"
        for attempt in range(20):
            assumed = p.call("assume-" + mode + "-" + str(attempt), "sts", "assume_role", {
                "RoleArn": role["Arn"], "RoleSessionName": "key-controls-" + mode, "DurationSeconds": 900, "Policy": policy}, required=False)
            if assumed["code"] == "Success":
                break
            if assumed["code"] != "AccessDenied":
                raise RuntimeError("Unexpected STS failure: " + assumed["code"])
            time.sleep(3)
        else:
            raise RuntimeError("Scoped role assumption did not converge")
        credentials = assumed["output"]["Credentials"]
        session = boto3.Session(region_name=REGION, aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        clients = {service: session.client(service, config=original[service].meta.config) for service in original}
        try:
            p.clients.update(clients)
            p.actor = assumed["output"]["AssumedRoleUser"]
            p.actor = p.required("identity-" + mode, "sts", "get_caller_identity")
            p.data["actors"][mode] = {"identity": p.actor, "session_policy": json.loads(policy)}
            for attempt in range(20):
                reads = [control(p, "iam-ready-" + mode + "-" + family + "-" + str(attempt), method, parameters, False)
                    for family, method, parameters in (("key", "get_api_key", {"apiKey": key}),
                        ("plan", "get_usage_plan", {"usagePlanId": plan}),
                        ("association", "get_usage_plan_key", {"usagePlanId": plan, "keyId": key}))]
                if all(row["code"] == "Success" for row in reads):
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Scoped API read authority did not converge")
            p.phase = "semantic"
            patch(p, "iam-" + mode + "-key-patch", "key", key, [replace("/description", "iam-" + mode)], mode == "allow")
            patch(p, "iam-" + mode + "-plan-patch", "plan", plan, [replace("/description", "iam-" + mode)], mode == "allow")
            control(p, "iam-" + mode + "-outside-key", "get_api_key", {"apiKey": other_key}, False)
            control(p, "iam-" + mode + "-outside-plan", "get_usage_plan", {"usagePlanId": other_plan}, False)
            if mode == "allow":
                associate(p, "iam-allow-association-create", plan, other_key)
                control(p, "iam-allow-association-read", "get_usage_plan_key", {"usagePlanId": plan, "keyId": other_key})
                control(p, "iam-allow-association-delete", "delete_usage_plan_key", {"usagePlanId": plan, "keyId": other_key})
            else:
                control(p, "iam-deny-association-delete", "delete_usage_plan_key", {"usagePlanId": plan, "keyId": key}, False)
                control(p, "iam-deny-association-retained", "get_usage_plan_key", {"usagePlanId": plan, "keyId": key})
        finally:
            p.clients.update(original)
            p.actor = p.data["identity"]
            for client in clients.values():
                client.close()
    p.phase = "semantic"


def run(p):
    source = Path(__file__).read_bytes()
    p.data.update(mode="api-keys-control", prefix="stackd-keyctl-" + uuid.uuid4().hex[:10],
        scope="Owned REST API key, usage-plan and association controls; no invocation or GetAccount mutation",
        probe_source=source.decode(), source_sha256=hashlib.sha256(source).hexdigest(), handler_source=None,
        base_helper_source=Path(base.__file__).read_text(),
        runtime_versions={"python": platform.python_version(), "boto3": boto3.__version__, "botocore": botocore.__version__},
        bounds={"apis": 1, "stages": 2, "roles": 1, "planned_keys_maximum": 16, "planned_plans_maximum": 8,
            "sdk_total_max_attempts": 1, "call_delay_seconds": 0.45, "pagination_pages": 20,
            "operation_minimum_intervals_seconds": {"UpdateUsagePlan": 21, "DeleteRestApi": 31},
            "sts_attempts": 20, "authority_read_attempts": 20, "readiness_delay_seconds": 3,
            "cleanup_attempts": 4, "cleanup_delay_seconds": 5, "data_plane_requests": 0},
        target_operations=TARGETS, actors={}, pagination={}, inconclusive=[],
        documentation=["https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-key-file-format.html",
            "https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-tagging-supported-resources.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html",
            *["https://docs.aws.amazon.com/apigateway/latest/api/API_" + op + ".html" for op in TARGETS]],
        references=[{"path": "clones/aws-sdk-go-v2/codegen/sdk-codegen/aws-models/api-gateway.json", "revision": "14444d5e84c592efe294222ac87eb3fd0a869188"}],
        limitations=["Lists use owned nameQuery/keyId/usagePlanId filters and an owned-ID/name projection before serialization. No account-wide resource payloads retained.",
            "Restart cleanup scans plans/APIs and an unnamed-key case without name filters; owned IDs/name/tag/API-stage projections discard unrelated rows before persistence and record only an omitted count.",
            "Opaque native pagination tokens and observed stable order are not portable sorting or consistency guarantees.",
            "No requests invoke APIs; throttle/quota fields and associations here do not prove deployed enforcement or exact propagation timing.",
            "One region/account, no marketplace integration, quota exhaustion, account setting changes or cross-account tests.",
            "SDK validation errors are explicitly separate from service errors. No raw signed requests are needed for the sampled boundaries.",
            "API key values are disposable owned controls retained for replay; STS credentials are redacted before persistence."])
    p.save()
    prefix = p.data["prefix"]
    generated = output(p, "key-generated-defaults", "create_api_key", {"name": prefix + "-generated"})
    supplied = output(p, "key-supplied-enabled", "create_api_key", {"name": prefix + "-supplied", "enabled": True,
        "value": uuid.uuid4().hex, "description": "supplied", "customerId": prefix + "-customer", "tags": {"Owner": "initial"}})
    disabled = output(p, "key-generated-disabled", "create_api_key", {"name": prefix + "-disabled", "enabled": False})
    control(p, "key-duplicate-value", "create_api_key", {"name": prefix + "-duplicate-value", "value": supplied["value"]}, False)
    control(p, "key-short-value", "create_api_key", {"name": prefix + "-short", "value": "short"}, False)
    output(p, "key-duplicate-name", "create_api_key", {"name": prefix + "-generated"})
    unnamed = output(p, "key-omitted-name", "create_api_key", {"description": prefix + "-unnamed", "tags": {"Capture": prefix}})
    output(p, "key-omitted-name-retained", "get_api_key", {"apiKey": unnamed["id"], "includeValue": True})
    for label, extra in (("omitted", {}), ("false", {"includeValue": False}), ("true", {"includeValue": True})):
        output(p, "key-get-value-" + label, "get_api_key", {"apiKey": supplied["id"], **extra})
    for label, extra in (("omitted", {}), ("false", {"includeValues": False}), ("true", {"includeValues": True})):
        pages(p, "keys-list-values-" + label, "get_api_keys", {"nameQuery": prefix, **extra})
    pages(p, "keys-customer-filter", "get_api_keys", {"nameQuery": prefix, "customerId": prefix + "-customer"})
    pages(p, "keys-customer-mismatch", "get_api_keys", {"nameQuery": prefix, "customerId": prefix + "-absent"})
    pages(p, "keys-name-substring", "get_api_keys", {"nameQuery": "keyctl-" + prefix.split("-")[-1]})
    for iteration in range(2):
        rows = pages(p, "keys-pagination-" + str(iteration), "get_api_keys", {"nameQuery": prefix, "limit": 1})
        p.data["pagination"]["keys-" + str(iteration)] = [row["id"] for row in rows]
    patch(p, "key-update-untagged", "key", generated["id"], [replace("/description", "untagged update")])
    patch(p, "key-update-fields", "key", supplied["id"], [replace("/name", prefix + "-renamed"),
        replace("/description", "changed"), replace("/customerId", prefix + "-customer-updated"), replace("/enabled", "false")])
    patch(p, "key-immutable-value-retains-earlier-field", "key", supplied["id"],
          [replace("/description", "must-not-stick"), replace("/value", uuid.uuid4().hex)], False)
    patch(p, "key-empty-customer-retains-description", "key", supplied["id"], [replace("/description", ""), replace("/customerId", "")], False)
    patch(p, "key-empty-description", "key", supplied["id"], [replace("/description", "")], False)
    patch(p, "key-invalid-enabled", "key", supplied["id"], [replace("/enabled", "not-a-boolean")], False)
    patch(p, "key-remove-description", "key", supplied["id"], [{"op": "remove", "path": "/description"}], False)
    tags(p, "apikeys", supplied["id"])

    p.phase = "setup"
    api = output(p, "create-control-api", "create_rest_api", {"name": prefix, "endpointConfiguration": {"types": ["REGIONAL"]}})["id"]
    root = output(p, "get-control-root", "get_resources", {"restApiId": api})["items"][0]["id"]
    resource = output(p, "create-control-resource", "create_resource", {"restApiId": api, "parentId": root, "pathPart": "probe"})["id"]
    target = {"restApiId": api, "resourceId": resource, "httpMethod": "GET"}
    output(p, "create-control-method", "put_method", {**target, "authorizationType": "NONE", "apiKeyRequired": True})
    function_arn = "arn:aws:lambda:" + REGION + ":" + p.data["account"] + ":function:" + prefix + "-uninvoked"
    p.data["setup_integration"] = {"function_arn": function_arn, "function_created": False,
        "invocations": 0, "purpose": "Syntactically valid AWS_PROXY deployment prerequisite; control-only capture"}
    output(p, "create-control-integration", "put_integration", {**target, "type": "AWS_PROXY",
        "integrationHttpMethod": "POST",
        "uri": "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/" + function_arn + "/invocations"})
    deployment = output(p, "create-control-deployment", "create_deployment", {"restApiId": api})["id"]
    for stage in ("alpha", "beta"):
        output(p, "create-stage-" + stage, "create_stage", {"restApiId": api, "stageName": stage, "deploymentId": deployment})
    p.phase = "semantic"
    legacy = control(p, "key-legacy-stage-keys", "create_api_key", {"name": prefix + "-legacy",
        "stageKeys": [{"restApiId": api, "stageName": "alpha"}]}, False)
    if legacy["code"] == "Success":
        output(p, "key-legacy-stage-keys-retained", "get_api_key", {"apiKey": legacy["output"]["id"], "includeValue": True})
        pages(p, "key-legacy-plans", "get_usage_plans", {"keyId": legacy["output"]["id"]})
    a = output(p, "plan-all-fields", "create_usage_plan", {"name": prefix + "-plan-a", "description": "initial",
        "throttle": {"burstLimit": 7, "rateLimit": 3.5}, "quota": {"limit": 25, "offset": 0, "period": "DAY"},
        "apiStages": [{"apiId": api, "stage": "alpha", "throttle": {"/probe/GET": {"burstLimit": 4, "rateLimit": 1.5}}}],
        "tags": {"Owner": "initial"}})["id"]
    b = output(p, "plan-defaults", "create_usage_plan", {"name": prefix + "-plan-b"})["id"]
    c = output(p, "plan-conflicting-stage", "create_usage_plan", {"name": prefix + "-plan-c", "apiStages": [{"apiId": api, "stage": "alpha"}]})["id"]
    partial = control(p, "plan-partial-settings", "create_usage_plan", {"name": prefix + "-partial-settings",
        "throttle": {"rateLimit": 0.5}, "quota": {"limit": 10, "period": "MONTH"}}, False)
    if partial["code"] == "Success":
        output(p, "plan-partial-settings-retained", "get_usage_plan", {"usagePlanId": partial["output"]["id"]})
    control(p, "plan-partial-throttle-missing-rate", "create_usage_plan",
        {"name": prefix + "-missing-rate", "throttle": {"burstLimit": 3}}, False)
    control(p, "plan-partial-quota-missing-limit", "create_usage_plan",
        {"name": prefix + "-missing-limit", "quota": {"period": "DAY"}}, False)
    control(p, "plan-partial-quota-missing-period", "create_usage_plan",
        {"name": prefix + "-missing-period", "quota": {"limit": 10}}, False)
    control(p, "plan-missing-name-sdk", "create_usage_plan", {}, False)
    control(p, "plan-invalid-period", "create_usage_plan", {"name": prefix + "-invalid-period", "quota": {"limit": 1, "period": "YEAR"}}, False)
    control(p, "plan-day-offset-rejected", "create_usage_plan", {"name": prefix + "-day-offset", "quota": {"limit": 25, "offset": 2, "period": "DAY"}}, False)
    control(p, "plan-missing-stage", "create_usage_plan", {"name": prefix + "-missing-stage", "apiStages": [{"apiId": api, "stage": "missing"}]}, False)
    patch(p, "plan-update-fields", "plan", a, [replace("/name", prefix + "-plan-renamed"), replace("/description", "changed"),
        replace("/throttle/rateLimit", "4.25"), replace("/throttle/burstLimit", "9"),
        replace("/quota/period", "WEEK"), replace("/quota/limit", "40"), replace("/quota/offset", "3")])
    method_patch = patch(p, "plan-method-throttle", "plan", a,
        [replace("/apiStages/" + api + ":alpha/throttle/probe/GET/rateLimit", "2.25")], False)
    if method_patch["code"] != "Success":
        p.data["inconclusive"].append("Method rate patch was not accepted; create-time method throttle was retained.")
    patch(p, "plan-invalid-patch-retains-state", "plan", a, [replace("/description", "must-not-stick"), replace("/quota/period", "YEAR")], False)
    patch(p, "plan-negative-throttle", "plan", a, [replace("/throttle/burstLimit", "-2")], False)
    patch(p, "plan-add-beta", "plan", b, [{"op": "add", "path": "/apiStages", "value": api + ":beta"}])
    associate(p, "association-a", a, supplied["id"])
    associate(p, "association-b-different-stage", b, supplied["id"])
    associate(p, "association-duplicate", a, supplied["id"], False)
    associate(p, "association-conflicting-stage", c, supplied["id"], False)
    associate(p, "association-invalid-type", c, disabled["id"], False, "OTHER")
    associate(p, "association-missing-key", c, "zzzzzzzzzz", False)
    associate(p, "association-disabled-key", a, disabled["id"])
    output(p, "association-get", "get_usage_plan_key", {"usagePlanId": a, "keyId": supplied["id"]})
    output(p, "association-name-filter", "get_usage_plan_keys", {"usagePlanId": a, "nameQuery": prefix + "-renamed"})
    output(p, "association-name-no-match", "get_usage_plan_keys", {"usagePlanId": a, "nameQuery": prefix + "-absent"})
    for iteration in range(2):
        for name, method, parameters in (("plans", "get_usage_plans", {"keyId": supplied["id"], "limit": 1}),
                ("associations", "get_usage_plan_keys", {"usagePlanId": a, "nameQuery": prefix, "limit": 1})):
            rows = pages(p, name + "-pagination-" + str(iteration), method, parameters)
            p.data["pagination"][name + "-" + str(iteration)] = [row["id"] for row in rows]
    patch(p, "plan-conflict-introduced-by-update", "plan", b, [{"op": "add", "path": "/apiStages", "value": api + ":alpha"}], False)
    patch(p, "plan-remove-beta", "plan", b, [{"op": "remove", "path": "/apiStages", "value": api + ":beta"}])
    patch(p, "plan-restore-beta", "plan", b, [{"op": "add", "path": "/apiStages", "value": api + ":beta"}])
    tags(p, "usageplans", a)
    imports(p, b)
    iam_cases(p, supplied["id"], generated["id"], a, b)

    control(p, "association-delete", "delete_usage_plan_key", {"usagePlanId": a, "keyId": disabled["id"]})
    control(p, "association-deleted-get", "get_usage_plan_key", {"usagePlanId": a, "keyId": disabled["id"]}, False)
    control(p, "association-delete-again", "delete_usage_plan_key", {"usagePlanId": a, "keyId": disabled["id"]}, False)
    output(p, "association-delete-key-survives", "get_api_key", {"apiKey": disabled["id"]})
    associate(p, "association-before-key-delete", a, disabled["id"])
    control(p, "delete-associated-key", "delete_api_key", {"apiKey": disabled["id"]})
    control(p, "deleted-key-get", "get_api_key", {"apiKey": disabled["id"]}, False)
    control(p, "deleted-key-association-get", "get_usage_plan_key", {"usagePlanId": a, "keyId": disabled["id"]}, False)
    output(p, "deleted-key-plan-survives", "get_usage_plan", {"usagePlanId": a})
    control(p, "delete-key-again", "delete_api_key", {"apiKey": disabled["id"]}, False)
    patch(p, "plan-remove-throttle-with-method-settings-rejected", "plan", a,
          [{"op": "remove", "path": "/quota"}, {"op": "remove", "path": "/throttle"}], False)
    patch(p, "plan-remove-method-throttle", "plan", a,
          [{"op": "remove", "path": "/apiStages/" + api + ":alpha/throttle"}], False)
    patch(p, "plan-remove-quota-throttle", "plan", a, [{"op": "remove", "path": "/quota"}, {"op": "remove", "path": "/throttle"}], False)
    control(p, "delete-plan-with-stage-rejected", "delete_usage_plan", {"usagePlanId": a}, False)
    output(p, "delete-plan-with-stage-retained", "get_usage_plan", {"usagePlanId": a})
    control(p, "delete-associated-stage", "delete_stage", {"restApiId": api, "stageName": "alpha"})
    output(p, "stage-delete-plan-retained", "get_usage_plan", {"usagePlanId": a})
    output(p, "stage-delete-key-retained", "get_api_key", {"apiKey": supplied["id"], "includeValue": True})
    output(p, "stage-delete-association-retained", "get_usage_plan_key", {"usagePlanId": a, "keyId": supplied["id"]})
    if legacy["code"] == "Success":
        output(p, "stage-delete-legacy-key-retained", "get_api_key", {"apiKey": legacy["output"]["id"], "includeValue": True})
    control(p, "delete-associated-api", "delete_rest_api", {"restApiId": api})
    output(p, "api-delete-plan-retained", "get_usage_plan", {"usagePlanId": b})
    control(p, "delete-associated-plan", "delete_usage_plan", {"usagePlanId": a})
    control(p, "deleted-plan-get", "get_usage_plan", {"usagePlanId": a}, False)
    control(p, "deleted-plan-association-get", "get_usage_plan_key", {"usagePlanId": a, "keyId": supplied["id"]}, False)
    output(p, "plan-delete-key-survives", "get_api_key", {"apiKey": supplied["id"]})
    output(p, "plan-delete-other-association-survives", "get_usage_plan_key", {"usagePlanId": b, "keyId": supplied["id"]})
    control(p, "delete-plan-again", "delete_usage_plan", {"usagePlanId": a}, False)
    p.data["operation_coverage"] = {op: sorted({row["result"]["code"] for row in p.data["observations"]
        if row["operation"] == op and row["phase"] != "cleanup"}) for op in TARGETS}
    p.save()


def distinct_ids(p):
    source = Path(__file__).read_bytes()
    p.data.update(mode="api-key-distinct-id", scope="Two owned generated-distinct-ID admission cases; no APIs, plans or invocation",
        probe_source=source.decode(), source_sha256=hashlib.sha256(source).hexdigest(),
        base_helper_source=Path(base.__file__).read_text(), handler_source=None,
        runtime_versions={"python": platform.python_version(), "boto3": boto3.__version__, "botocore": botocore.__version__},
        bounds={"keys": 2, "apis": 0, "plans": 0, "roles": 0, "data_plane_requests": 0},
        documentation=["https://docs.aws.amazon.com/apigateway/latest/api/API_CreateApiKey.html"],
        identity_observations=[])
    p.save()
    for flag in (False, True):
        label = "distinct-id-" + str(flag).lower()
        value = uuid.uuid4().hex
        result = control(p, label, "create_api_key", {"name": p.data["prefix"] + "-" + str(flag).lower(),
            "value": value, "generateDistinctId": flag, "enabled": False}, False)
        if result["code"] == "Success":
            key = output(p, label + "-retained", "get_api_key", {"apiKey": result["output"]["id"], "includeValue": True})
            p.data["identity_observations"].append({"label": label, "id_equals_value": key["id"] == key["value"],
                "supplied_value_retained": key["value"] == value})
            p.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/api_keys.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--append-capture", action="store_true")
    parser.add_argument("--distinct-id-supplement", action="store_true")
    args = parser.parse_args()
    if sum((args.cleanup_only, args.append_capture, args.distinct_id_supplement)) > 1:
        parser.error("cleanup-only, append-capture and distinct-id-supplement are mutually exclusive")
    p = KeysProbe(args.output, args.account, args.cleanup_only or args.append_capture or args.distinct_id_supplement)
    supplement = p.data.get("distinct_id_capture")
    if supplement and not supplement.get("cleanup", {}).get("complete"):
        if not args.cleanup_only:
            raise RuntimeError("Run cleanup-only for the unfinished distinct-ID capture first")
        p.envelope, p.data = p.data, supplement
    if args.distinct_id_supplement:
        if not p.data.get("cleanup", {}).get("complete") or supplement:
            raise RuntimeError("Distinct-ID supplement requires a cleaned primary capture and cannot overwrite evidence")
        p.envelope = p.data
        p.data = {"service": "apigateway", "account": args.account, "region": REGION,
            "identity": p.client("sts").get_caller_identity(), "captured_at": now(),
            "prefix": "stackd-keyctl-distinct-" + uuid.uuid4().hex[:10], "owned": {}, "observations": [],
            "http": [], "tokens": {}, "cleanup": {}, "sdk": p.envelope["sdk"]}
    if args.append_capture:
        previous = p.data
        if previous.get("mode") != "api-keys-control" or not previous.get("cleanup", {}).get("complete"):
            raise RuntimeError("Can append only after verified owned cleanup")
        earlier = previous.pop("prior_captures", [])
        p.data = {"service": "apigateway", "account": args.account, "region": REGION,
            "identity": p.client("sts").get_caller_identity(), "captured_at": now(),
            "prefix": "stackd-keyctl-" + uuid.uuid4().hex[:10], "owned": {}, "observations": [],
            "http": [], "tokens": {}, "cleanup": {}, "sdk": previous["sdk"], "prior_captures": earlier + [previous]}
    if args.cleanup_only:
        p.data.setdefault("restart_cleanup_runs", []).append({"started_at": now(),
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
        p.save()
    try:
        if args.distinct_id_supplement:
            distinct_ids(p)
        elif not args.cleanup_only:
            run(p)
    except BaseException as error:
        p.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        p.save()
        raise
    finally:
        try:
            for attempt in range(4):
                try:
                    p.cleanup()
                    break
                except Exception as error:
                    p.data.setdefault("cleanup_attempt_errors", []).append({"attempt": attempt, "error": str(error)})
                    p.save()
                    if attempt == 3:
                        raise
                    time.sleep(5)
        finally:
            for client in p.clients.values():
                client.close()


if __name__ == "__main__":
    main()
