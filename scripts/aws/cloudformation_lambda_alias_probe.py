#!/usr/bin/env python3
"""Capture an exact-owned native CloudFormation Lambda alias lifecycle.

Uses prepublished real function versions, one permissionless execution role and
at most one provisioned execution. --cleanup-only resumes the persisted owned
inventory. Never overwrites evidence or mutates preexisting resources.
"""
import argparse
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudtrail_service_probe import REGION, document, now


SOURCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-alias.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-alias-provisionedconcurrencyconfiguration.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_CreateAlias.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_GetProvisionedConcurrencyConfig.md",
    "https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.md",
]
HANDLER = '''import os

def handler(event, context):
    return {"version": context.function_version,
            "invoked_arn": context.invoked_function_arn,
            "initialization_type": os.environ.get("AWS_LAMBDA_INITIALIZATION_TYPE"),
            "marker": os.environ.get("PROBE_MARKER")}
'''


def recorded(value):
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode(), "bytes": len(value)}
    if isinstance(value, dict):
        return {key: recorded(item) for key, item in document(value).items()}
    if isinstance(value, list):
        return [recorded(item) for item in value]
    return document(value)


class AliasProbe:
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config) for name in
                        ("sts", "iam", "lambda", "cloudformation", "resource-groups")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.account or self.data["region"] != REGION:
                raise RuntimeError("Capture target does not match authorized account/region")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            prefix = "stackd-cfn-alias-" + uuid.uuid4().hex[:12]
            self.data = {
                "source": "Native AWS public endpoints; boto3; configured endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION, "prefix": prefix,
                "sdk": {"boto3": boto3.__version__},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "Only newly created probe resources; no function/version CFN provider; one provisioned execution briefly; no logging policy or standing account changes",
                "bounds": {"stack_wait_seconds": 420, "poll_seconds": 3,
                           "resource_group_wait_seconds": 90, "weighted_invocations": 16},
                "sources": SOURCES, "documentation": [], "calls": [], "owned": {},
                "findings": {}, "calibration_gaps": [
                    "Native private CloudFormation ownership tokens and restart/foreign-replacement fencing are not exposed or inferred.",
                    "Bounded invocation samples do not establish an exact traffic distribution.",
                    "A bounded Resource Groups membership miss is not permanent exclusion.",
                    "Provisioned-concurrency retarget evidence covers primary-version changes, not weight-only changes or FAILED-pool recovery.",
                ], "cleanup": {"complete": False}, "workflow_complete": False,
                "redaction": "Shared credential redaction; exact native account, IDs, timestamps, request/response metadata retained",
            }
        self.save()
        identity = self.call("identity", "sts", "get_caller_identity")
        if identity["Account"] != self.account:
            raise RuntimeError("Native writes authorized only for account " + self.account)
        self.data["identity"] = identity
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(recorded(self.data), indent=2)
        for value in (self.credentials.secret_key, self.credentials.token):
            if value:
                text = text.replace(value, "<redacted-credential>")
        self.args.output.write_text(text + "\n")

    def call(self, label, service, operation, request=None, *, required=True):
        client = self.clients[service]
        row = {"label": label, "service": service,
               "operation": client.meta.method_to_api_mapping[operation],
               "input": recorded(request or {}), "started_at": now(),
               "phase": "cleanup" if self.cleanup_phase else "workflow", "code": "Pending"}
        self.data["calls"].append(row)
        self.save()
        try:
            output = getattr(client, operation)(**(request or {}))
            metadata = output.pop("ResponseMetadata", {})
            payload = output.get("Payload")
            if hasattr(payload, "read"):
                try:
                    output["Payload"] = json.loads(payload.read())
                finally:
                    payload.close()
            row.update(code="Success", output=recorded(output), metadata=document(metadata))
        except ClientError as error:
            output = {}
            row.update(code=error.response["Error"]["Code"], error=error.response["Error"],
                       metadata=document(error.response.get("ResponseMetadata", {})))
        except Exception as error:
            row.update(code=type(error).__name__, error=str(error), finished_at=now())
            self.save()
            raise
        row["finished_at"] = now()
        self.save()
        print(label + ": " + row["code"], flush=True)
        if required and row["code"] != "Success":
            raise RuntimeError(label + ": " + json.dumps(row["error"]))
        return output

    def code(self):
        return self.data["calls"][-1]["code"]

    def absent(self, label, service, operation, request, code):
        self.call(label, service, operation, request, required=False)
        if self.code() != code:
            raise RuntimeError(label + ": expected " + code + ", observed " + self.code())
        if code == "ValidationError" and "does not exist" not in self.data["calls"][-1]["error"]["Message"]:
            raise RuntimeError(label + ": not a missing-stack response")

    def documents(self):
        for source in SOURCES:
            try:
                with urllib.request.urlopen(source, timeout=30) as response:
                    raw = response.read()
                text = raw.decode()
                if source.endswith("supported-resources.md"):
                    text = "\n".join(line for line in text.splitlines() if "AWS::Lambda::Alias" in line)
                self.data["documentation"].append({"source": source, "captured_at": now(),
                    "source_sha256": hashlib.sha256(raw).hexdigest(), "content": text})
            except Exception as error:
                self.data["calibration_gaps"].append(source + ": " + str(error))
            self.save()
        registry = self.call("alias-public-registry-schema", "cloudformation", "describe_type",
                             {"Type": "RESOURCE", "TypeName": "AWS::Lambda::Alias"}, required=False)
        if registry:
            schema = json.loads(registry["Schema"])
            self.data["schema"] = schema
            self.data["findings"]["schema_contract"] = {
                key: schema.get(key) for key in ("primaryIdentifier", "readOnlyProperties",
                                                "createOnlyProperties", "required", "tagging")}
            if self.args.schema_output:
                path = self.args.schema_output
                capture = json.loads(path.read_text())
                if capture["account"] != self.account or capture["region"] != REGION:
                    raise RuntimeError("Schema inventory target differs from authorized account/region")
                if "AWS::Lambda::Alias" not in capture["types"]:
                    row = self.data["calls"][-1]
                    metadata = {key: value for key, value in registry.items() if key != "Schema"}
                    capture["types"]["AWS::Lambda::Alias"] = {
                        "input": row["input"], "schema": schema, "metadata": metadata,
                        "arn": registry.get("Arn", ""), "default_version_id": registry.get("DefaultVersionId", ""),
                        "request_id": row["metadata"].get("RequestId"),
                        "http_status": row["metadata"].get("HTTPStatusCode"),
                        "captured_at": row["finished_at"], "capture": str(self.args.output),
                    }
                    path.write_text(json.dumps(document(capture), indent=2) + "\n")
        else:
            self.data["calibration_gaps"].append("Native DescribeType unavailable: " + self.code())
        self.save()

    def ready_function(self, label):
        for attempt in range(80):
            value = self.call(label + "-" + str(attempt), "lambda", "get_function_configuration",
                              {"FunctionName": self.data["owned"]["function"]["name"]})
            if value.get("State") == "Active" and value.get("LastUpdateStatus", "Successful") == "Successful":
                return value
            if value.get("State") == "Failed" or value.get("LastUpdateStatus") == "Failed":
                raise RuntimeError("Owned function failed to initialize")
            time.sleep(2)
        raise RuntimeError("Owned function readiness deadline expired")

    def setup(self):
        prefix, owned = self.data["prefix"], self.data["owned"]
        role_name, function_name = prefix + "-role", prefix + "-fn"
        self.absent("role-name-absent", "iam", "get_role", {"RoleName": role_name}, "NoSuchEntity")
        owned["role"] = {"name": role_name, "creation_attempted": True}
        self.save()
        role = self.call("create-role", "iam", "create_role", {
            "RoleName": role_name, "Tags": [{"Key": "stackd-probe", "Value": prefix}],
            "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                 "Action": "sts:AssumeRole"}]})})["Role"]
        owned["role"].update(arn=role["Arn"], id=role["RoleId"])
        self.absent("function-name-absent", "lambda", "get_function_configuration",
                    {"FunctionName": function_name}, "ResourceNotFoundException")
        owned["function"] = {"name": function_name, "creation_attempted": True, "versions": []}
        owned["aliases"] = []
        self.save()
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("entry.py", HANDLER)
        self.data["runtime_source"] = HANDLER
        request = {"FunctionName": function_name, "Role": role["Arn"], "Runtime": "python3.12",
                   "Handler": "entry.handler", "Timeout": 3, "MemorySize": 128,
                   "Code": {"ZipFile": package.getvalue()}, "Environment": {"Variables": {"PROBE_MARKER": "one"}},
                   "Tags": {"stackd-probe": prefix}}
        for attempt in range(30):
            value = self.call("create-function-" + str(attempt), "lambda", "create_function", request, required=False)
            if value:
                owned["function"]["arn"] = value["FunctionArn"]
                self.save()
                break
            if self.code() != "InvalidParameterValueException" or "cannot be assumed" not in self.data["calls"][-1]["error"]["Message"]:
                raise RuntimeError("Owned function creation failed: " + self.code())
            time.sleep(3)
        else:
            raise RuntimeError("Owned execution role propagation expired")
        self.ready_function("function-ready")
        for marker in ("one", "two"):
            if marker == "two":
                self.call("change-function-marker", "lambda", "update_function_configuration", {
                    "FunctionName": function_name, "Environment": {"Variables": {"PROBE_MARKER": marker}}})
                self.ready_function("function-update-ready")
            value = self.call("publish-version-" + marker, "lambda", "publish_version",
                              {"FunctionName": function_name, "Description": "owned probe " + marker})
            owned["function"]["versions"].append({"version": value["Version"], "arn": value["FunctionArn"]})
            self.save()

    def alias_request(self, name="live"):
        return {"FunctionName": self.data["owned"]["function"]["name"], "Name": name}

    def concurrency_request(self):
        return {"FunctionName": self.data["owned"]["function"]["name"], "Qualifier": "live"}

    def invoke(self, label, qualifier):
        value = self.call(label, "lambda", "invoke", {
            "FunctionName": self.data["owned"]["function"]["name"], "Qualifier": qualifier,
            "InvocationType": "RequestResponse", "Payload": b"{}"})
        if "FunctionError" in value:
            raise RuntimeError("Owned version-returning handler failed")
        return value

    def wait_stack(self, label, *, concurrency=False):
        stack = self.data["owned"]["stack"]["id"]
        deadline = time.monotonic() + self.data["bounds"]["stack_wait_seconds"]
        attempt = 0
        while time.monotonic() < deadline:
            value = self.call(label + "-stack-" + str(attempt), "cloudformation", "describe_stacks", {"StackName": stack})
            current = value["Stacks"][0]
            if concurrency:
                self.call(label + "-alias-" + str(attempt), "lambda", "get_alias",
                          self.alias_request(), required=False)
                self.call(label + "-concurrency-" + str(attempt), "lambda", "get_provisioned_concurrency_config",
                          self.concurrency_request(), required=False)
            status = current["StackStatus"]
            if not status.endswith("_IN_PROGRESS"):
                return current
            attempt += 1
            time.sleep(self.data["bounds"]["poll_seconds"])
        raise RuntimeError(label + ": stack observation deadline expired")

    def snapshot(self, label):
        stack = self.data["owned"]["stack"]["id"]
        for operation in ("describe_stack_resources", "describe_stack_events", "get_template"):
            self.call(label + "-" + operation, "cloudformation", operation, {"StackName": stack})
        return self.call(label + "-alias", "lambda", "get_alias", self.alias_request())

    def update(self, label, template, *, concurrency=False):
        self.data.setdefault("templates", {})[label] = copy.deepcopy(template)
        self.save()
        self.call(label + "-update", "cloudformation", "update_stack", {
            "StackName": self.data["owned"]["stack"]["id"], "TemplateBody": json.dumps(template),
            "ClientRequestToken": self.data["prefix"] + "-" + label})
        stack = self.wait_stack(label, concurrency=concurrency)
        alias = self.snapshot(label)
        self.data["findings"][label] = {"stack_status": stack["StackStatus"], "alias": alias,
                                         "outputs": stack.get("Outputs", [])}
        self.save()
        if stack["StackStatus"] != "UPDATE_COMPLETE":
            raise RuntimeError(label + ": " + stack["StackStatus"])
        return alias

    def resource_group(self):
        owned = self.data["owned"]
        name = self.data["prefix"] + "-group"
        self.absent("group-name-absent", "resource-groups", "get_group", {"Group": name}, "NotFoundException")
        query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
            "ResourceTypeFilters": ["AWS::Lambda::Alias"], "StackIdentifier": owned["stack"]["id"]})}
        owned["group"] = {"name": name, "creation_attempted": True}
        self.save()
        value = self.call("create-stack-alias-group", "resource-groups", "create_group", {
            "Name": name, "ResourceQuery": query, "Tags": {"stackd-probe": self.data["prefix"]}}, required=False)
        if not value:
            self.data["calibration_gaps"].append("Stack-scoped alias Resource Group admission: " + self.code())
            self.save()
            return
        owned["group"]["arn"] = value["Group"]["GroupArn"]
        self.save()
        start = time.monotonic()
        attempt, member = 0, False
        while True:
            value = self.call("stack-group-members-" + str(attempt), "resource-groups", "list_group_resources",
                              {"Group": owned["group"]["arn"]}, required=False)
            member = any(item.get("ResourceType") == "AWS::Lambda::Alias"
                         and item.get("ResourceArn") == self.data["findings"]["remove-provisioned"]["alias"]["AliasArn"]
                         for item in value.get("ResourceIdentifiers", []))
            if member or time.monotonic() - start >= self.data["bounds"]["resource_group_wait_seconds"]:
                break
            attempt += 1
            time.sleep(5)
        self.data["findings"]["resource_group"] = {"query_admitted": True, "membership_observed": member,
            "observation_seconds": time.monotonic() - start,
            "boundary": "A bounded miss does not establish permanent nonmembership"}
        self.save()

    def workflow(self):
        self.documents()
        self.setup()
        owned = self.data["owned"]
        function = owned["function"]["name"]
        versions = [item["version"] for item in owned["function"]["versions"]]
        owned["aliases"].append("latest-check")
        self.save()
        latest = self.call("native-create-alias-latest", "lambda", "create_alias", {
            **self.alias_request("latest-check"), "FunctionVersion": "$LATEST"}, required=False)
        self.data["findings"]["native_latest"] = {"code": self.code(), "output": latest}
        if latest:
            self.data["findings"]["native_latest"]["invocation"] = self.invoke("invoke-native-latest", "latest-check")
            self.call("delete-native-latest", "lambda", "delete_alias", self.alias_request("latest-check"))
        self.save()
        self.absent("native-latest-absent", "lambda", "get_alias", self.alias_request("latest-check"), "ResourceNotFoundException")
        name = self.data["prefix"] + "-stack"
        self.absent("stack-name-absent", "cloudformation", "describe_stacks", {"StackName": name}, "ValidationError")
        owned["stack"] = {"name": name, "creation_attempted": True}
        owned["aliases"].append("live")
        template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Alias": {
            "Type": "AWS::Lambda::Alias", "Properties": {"FunctionName": function,
                "FunctionVersion": versions[0], "Name": "live", "Description": "initial description"}}},
            "Outputs": {"AliasRef": {"Value": {"Ref": "Alias"}},
                        "AliasArn": {"Value": {"Fn::GetAtt": ["Alias", "AliasArn"]}}}}
        self.data["templates"] = {"create": copy.deepcopy(template)}
        self.save()
        self.call("validate-alias-template", "cloudformation", "validate_template", {"TemplateBody": json.dumps(template)})
        value = self.call("create-alias-stack", "cloudformation", "create_stack", {
            "StackName": name, "TemplateBody": json.dumps(template), "ClientRequestToken": self.data["prefix"] + "-create",
            "Tags": [{"Key": "stackd-probe", "Value": self.data["prefix"]}]})
        owned["stack"]["id"] = value["StackId"]
        self.save()
        stack = self.wait_stack("create")
        alias = self.snapshot("create")
        self.data["findings"]["create"] = {"stack_status": stack["StackStatus"], "alias": alias, "outputs": stack.get("Outputs", [])}
        if stack["StackStatus"] != "CREATE_COMPLETE":
            raise RuntimeError("Native alias stack creation failed")
        self.invoke("invoke-initial", "live")
        props = template["Resources"]["Alias"]["Properties"]
        props["Description"] = "weighted description"
        props["RoutingConfig"] = {"AdditionalVersionWeights": [{"FunctionVersion": versions[1], "FunctionWeight": 0.5}]}
        self.update("weighted", template)
        counts = {}
        for attempt in range(self.data["bounds"]["weighted_invocations"]):
            invocation = self.invoke("invoke-weighted-" + str(attempt), "live")
            version = invocation["Payload"]["version"]
            counts[version] = counts.get(version, 0) + 1
        self.data["findings"]["weighted"]["sample_counts"] = counts
        del props["RoutingConfig"]
        del props["Description"]
        self.update("remove-routing-description", template)
        self.invoke("invoke-routing-removed", "live")
        self.call("native-provisioned-zero-admission", "lambda", "put_provisioned_concurrency_config", {
            **self.concurrency_request(), "ProvisionedConcurrentExecutions": 0}, required=False)
        props["ProvisionedConcurrencyConfig"] = {"ProvisionedConcurrentExecutions": 1}
        self.update("add-provisioned", template, concurrency=True)
        self.data["findings"]["provisioned_at_update_complete"] = self.call("provisioned-ready", "lambda",
            "get_provisioned_concurrency_config", self.concurrency_request())
        self.data["findings"]["provisioned_invocation"] = self.invoke("invoke-provisioned", "live")
        props["FunctionVersion"] = versions[1]
        self.update("retarget-with-provisioned", template, concurrency=True)
        self.call("native-retarget-with-provisioned", "lambda", "update_alias", {
            **self.alias_request(), "FunctionVersion": versions[0]})
        self.data["findings"]["provisioned_immediately_after_native_retarget"] = self.call(
            "provisioned-immediately-after-native-retarget", "lambda",
            "get_provisioned_concurrency_config", self.concurrency_request())
        props["FunctionVersion"] = versions[0]
        self.update("reconcile-native-retarget", template, concurrency=True)
        del props["ProvisionedConcurrencyConfig"]
        self.update("remove-provisioned", template, concurrency=True)
        self.call("provisioned-after-removal", "lambda", "get_provisioned_concurrency_config",
                  self.concurrency_request(), required=False)
        self.data["findings"]["provisioned_after_removal_code"] = self.code()
        self.resource_group()
        self.data["workflow_complete"] = True
        self.data["finished_at"] = now()
        self.save()

    def cleanup(self):
        self.cleanup_phase = True
        owned, errors = self.data["owned"], []

        def attempt(label, action):
            try:
                action()
            except Exception as error:
                errors.append(label + ": " + str(error))
                self.save()

        def remove_group():
            group = owned["group"]
            self.call("cleanup-delete-group", "resource-groups", "delete_group", {"Group": group.get("arn", group["name"])}, required=False)
            self.absent("cleanup-group-absent", "resource-groups", "get_group", {"Group": group["name"]}, "NotFoundException")

        def remove_stack():
            stack = owned["stack"]
            identifier = stack.get("id", stack["name"])
            current = self.call("cleanup-stack-current", "cloudformation", "describe_stacks", {"StackName": identifier}, required=False)
            if current and current["Stacks"][0]["StackStatus"].endswith("_IN_PROGRESS"):
                self.wait_stack("cleanup-wait-current", concurrency=True)
            self.call("cleanup-delete-stack", "cloudformation", "delete_stack", {
                "StackName": identifier, "ClientRequestToken": self.data["prefix"] + "-delete"}, required=False)
            if "id" in stack:
                result = self.wait_stack("cleanup-delete")
                if result["StackStatus"] != "DELETE_COMPLETE":
                    raise RuntimeError("Stack deletion did not complete")
                self.data["cleanup"]["deleted_stack_history"] = {
                    "id": stack["id"], "status": "DELETE_COMPLETE",
                    "boundary": "AWS retains deleted-stack history; absence is verified by stack name, not ARN"}
            self.absent("cleanup-stack-name-absent", "cloudformation", "describe_stacks", {"StackName": stack["name"]}, "ValidationError")

        def remove_alias(name):
            self.call("cleanup-delete-alias-" + name, "lambda", "delete_alias", self.alias_request(name), required=False)
            self.absent("cleanup-alias-absent-" + name, "lambda", "get_alias", self.alias_request(name), "ResourceNotFoundException")

        def remove_function():
            function = owned["function"]
            self.call("cleanup-delete-function", "lambda", "delete_function", {"FunctionName": function["name"]}, required=False)
            self.absent("cleanup-function-absent", "lambda", "get_function_configuration", {"FunctionName": function["name"]}, "ResourceNotFoundException")
            for version in function["versions"]:
                self.absent("cleanup-version-absent-" + version["version"], "lambda", "get_function_configuration",
                            {"FunctionName": function["name"], "Qualifier": version["version"]}, "ResourceNotFoundException")
            self.absent("cleanup-provisioned-absent", "lambda", "get_provisioned_concurrency_config", self.concurrency_request(), "ResourceNotFoundException")

        def remove_role():
            self.call("cleanup-delete-role", "iam", "delete_role", {"RoleName": owned["role"]["name"]}, required=False)
            self.absent("cleanup-role-absent", "iam", "get_role", {"RoleName": owned["role"]["name"]}, "NoSuchEntity")

        if "group" in owned:
            attempt("group", remove_group)
        if "stack" in owned:
            attempt("stack", remove_stack)
        if "function" in owned:
            # Bound paid capacity even if a stack operation or deletion failed.
            attempt("provisioned", lambda: self.call("cleanup-delete-provisioned", "lambda",
                "delete_provisioned_concurrency_config", self.concurrency_request(), required=False))
            for name in owned.get("aliases", []):
                attempt("alias " + name, lambda name=name: remove_alias(name))
            attempt("function", remove_function)
        if "role" in owned:
            attempt("role", remove_role)
        self.data["cleanup"].update(complete=not errors, errors=errors, finished_at=now())
        self.save()
        if errors:
            raise RuntimeError("Exact-owned cleanup incomplete: " + "; ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path,
                        default=Path(".stackd/probes/cloudformation/lambda_alias.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--schema-output", type=Path,
                        help="Add only the captured Alias entry to an existing native schema inventory")
    args = parser.parse_args()
    probe = AliasProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            probe.workflow()
    except Exception as error:
        probe.data["failure"] = {"at": now(), "error": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
