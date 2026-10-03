#!/usr/bin/env python3
"""Capture exact-owned CloudFormation Lambda Version behavior; cleanup is resumable.

Never overwrites existing evidence. Uses one permissionless execution role and
at most one provisioned execution; no Managed Instances capacity is created.
"""
import argparse
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
import botocore
from botocore.config import Config

from cloudformation_lambda_alias_probe import AliasProbe, HANDLER
from cloudtrail_service_probe import REGION, document, now

SOURCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-version.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-version-runtimepolicy.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-version-functionscalingconfig.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-version-provisionedconcurrencyconfiguration.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_PublishVersion.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_DeleteFunction.md",
    "https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.md",
]


class VersionProbe(AliasProbe):
    # Share the established durable call recorder, credential redaction, readiness
    # polling and actual handler invocation, not the Alias-specific lifecycle.
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
                raise RuntimeError("Capture target differs from authorized account/region")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "source": "Native AWS public endpoints; configured endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION,
                "prefix": "stackd-cfn-version-" + uuid.uuid4().hex[:12],
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "Exact-owned temporary function, permissionless role, stacks, aliases and Resource Group; at most one provisioned execution; no Managed Instances capacity",
                "bounds": {"stack_wait_seconds": 420, "poll_seconds": 3, "resource_group_wait_seconds": 90},
                "sources": SOURCES, "documentation": [], "calls": [],
                "owned": {"stacks": {}, "aliases": []}, "findings": {}, "templates": {},
                "calibration_gaps": [
                    "Private CloudFormation request tokens and restart/foreign-replacement fencing are not publicly observable.",
                    "Managed Instances scaling is not exercised on capacity resources; admission on an ordinary on-demand function is captured instead.",
                    "A bounded Resource Groups membership miss is not permanent exclusion.",
                ], "cleanup": {"complete": False}, "workflow_complete": False,
                "redaction": "Shared credential redaction; native account, IDs, timestamps and request metadata retained",
            }
        self.save()
        identity = self.call("identity", "sts", "get_caller_identity")
        if identity["Account"] != self.account:
            raise RuntimeError("Native writes authorized only for account " + self.account)
        self.data["identity"] = identity
        self.save()

    def documents(self):
        for source in SOURCES:
            try:
                with urllib.request.urlopen(source, timeout=30) as response:
                    raw = response.read()
                text = raw.decode()
                if source.endswith("supported-resources.md"):
                    text = "\n".join(line for line in text.splitlines() if "AWS::Lambda::Version" in line)
                self.data["documentation"].append({"source": source, "captured_at": now(),
                    "source_sha256": hashlib.sha256(raw).hexdigest(), "content": text})
            except Exception as error:
                self.data["calibration_gaps"].append(source + ": " + str(error))
            self.save()
        registry = self.call("version-public-registry-schema", "cloudformation", "describe_type",
                             {"Type": "RESOURCE", "TypeName": "AWS::Lambda::Version"})
        schema = json.loads(registry["Schema"])
        self.data["schema"] = schema
        self.data["findings"]["schema_contract"] = {key: schema.get(key) for key in
            ("primaryIdentifier", "readOnlyProperties", "createOnlyProperties", "required", "tagging")}
        self.save()
        if self.args.schema_output:
            path = self.args.schema_output
            capture = json.loads(path.read_text())
            if capture["account"] != self.account or capture["region"] != REGION:
                raise RuntimeError("Schema inventory target differs from authorized account/region")
            if "AWS::Lambda::Version" not in capture["types"]:
                row = self.data["calls"][-1]
                capture["types"]["AWS::Lambda::Version"] = {
                    "input": row["input"], "schema": schema,
                    "metadata": {key: value for key, value in registry.items() if key != "Schema"},
                    "arn": registry.get("Arn", ""), "default_version_id": registry.get("DefaultVersionId", ""),
                    "request_id": row["metadata"].get("RequestId"), "http_status": row["metadata"].get("HTTPStatusCode"),
                    "captured_at": row["finished_at"], "capture": str(self.args.output),
                }
                path.write_text(json.dumps(document(capture), indent=2) + "\n")

    def setup(self):
        owned, prefix = self.data["owned"], self.data["prefix"]
        role_name, function_name = prefix + "-role", prefix + "-fn"
        self.absent("role-name-absent", "iam", "get_role", {"RoleName": role_name}, "NoSuchEntity")
        owned["role"] = {"name": role_name, "creation_attempted": True}
        self.save()
        role = self.call("create-role", "iam", "create_role", {
            "RoleName": role_name, "Tags": [{"Key": "stackd-probe", "Value": prefix}],
            "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})})["Role"]
        owned["role"].update(arn=role["Arn"], id=role["RoleId"])
        self.save()
        self.absent("function-name-absent", "lambda", "get_function_configuration",
                    {"FunctionName": function_name}, "ResourceNotFoundException")
        owned["function"] = {"name": function_name, "creation_attempted": True, "versions": []}
        self.save()
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("entry.py", HANDLER)
        self.data["runtime_source"] = HANDLER
        request = {"FunctionName": function_name, "Role": role["Arn"], "Runtime": "python3.12",
                   "Handler": "entry.handler", "Timeout": 3, "MemorySize": 128,
                   "Code": {"ZipFile": package.getvalue()}, "Environment": {"Variables": {"PROBE_MARKER": "native"}},
                   "Tags": {"stackd-probe": prefix}}
        for attempt in range(30):
            value = self.call("create-function-" + str(attempt), "lambda", "create_function", request, required=False)
            if value:
                owned["function"].update(arn=value["FunctionArn"], revision=value["RevisionId"])
                self.save()
                break
            if self.code() != "InvalidParameterValueException" or "cannot be assumed" not in self.data["calls"][-1]["error"]["Message"]:
                raise RuntimeError("Owned function creation failed: " + self.code())
            time.sleep(3)
        else:
            raise RuntimeError("Owned role propagation expired")
        self.ready_function("function-ready")

    def inventory(self, label):
        result = self.call(label, "lambda", "list_versions_by_function", self.function_request())
        self.data["owned"]["function"]["versions"] = sorted(set(
            self.data["owned"]["function"]["versions"] +
            [item["Version"] for item in result["Versions"] if item["Version"] != "$LATEST"]), key=int)
        self.save()
        return result

    def function_request(self, version=None):
        request = {"FunctionName": self.data["owned"]["function"]["name"]}
        if version is not None:
            request["Qualifier"] = version
        return request

    def change(self, marker):
        self.call("change-" + marker, "lambda", "update_function_configuration", {
            **self.function_request(), "Environment": {"Variables": {"PROBE_MARKER": marker}}})
        return self.ready_function(marker + "-ready")

    def template(self, **props):
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Version": {
            "Type": "AWS::Lambda::Version", "Properties": {**self.function_request(), **props}}},
            "Outputs": {"VersionRef": {"Value": {"Ref": "Version"}},
                        "FunctionArn": {"Value": {"Fn::GetAtt": ["Version", "FunctionArn"]}},
                        "VersionNumber": {"Value": {"Fn::GetAtt": ["Version", "Version"]}}}}

    def wait_owned_stack(self, key, label, *, bounded_observation=False):
        stack = self.data["owned"]["stacks"][key]
        deadline = time.monotonic() + self.data["bounds"]["stack_wait_seconds"]
        attempt = 0
        while time.monotonic() < deadline:
            value = self.call(label + "-poll-" + str(attempt), "cloudformation", "describe_stacks",
                              {"StackName": stack.get("id", stack["name"])})["Stacks"][0]
            if not value["StackStatus"].endswith("_IN_PROGRESS"):
                return value
            attempt += 1
            time.sleep(self.data["bounds"]["poll_seconds"])
        if bounded_observation:
            self.data["findings"][label + "_observation_boundary"] = {
                "stack_status": value["StackStatus"],
                "wait_seconds": self.data["bounds"]["stack_wait_seconds"],
                "boundary": "Deletion remained nonterminal while an owned alias referenced the version; cleanup removes the alias before waiting again.",
            }
            self.save()
            return value
        raise RuntimeError(label + ": stack observation deadline expired")

    def stack(self, key, label, template, update=False):
        stacks = self.data["owned"]["stacks"]
        self.data["templates"][label] = copy.deepcopy(template)
        if not update:
            name = self.data["prefix"] + "-" + key
            self.absent(label + "-name-absent", "cloudformation", "describe_stacks", {"StackName": name}, "ValidationError")
            stacks[key] = {"name": name, "creation_attempted": True}
        self.save()
        request = {"StackName": stacks[key].get("id", stacks[key]["name"]), "TemplateBody": json.dumps(template),
                   "ClientRequestToken": self.data["prefix"] + "-" + label}
        if not update:
            request["Tags"] = [{"Key": "stackd-probe", "Value": self.data["prefix"]}]
        value = self.call(label + "-submit", "cloudformation", "update_stack" if update else "create_stack", request, required=False)
        finding = {"submission_code": self.code()}
        self.data["findings"][label] = finding
        if not value:
            self.save()
            return finding
        stacks[key]["id"] = value["StackId"]
        self.save()
        current = self.wait_owned_stack(key, label)
        finding.update(stack_status=current["StackStatus"], outputs=current.get("Outputs", []))
        for operation in ("describe_stack_resources", "describe_stack_events", "get_template"):
            result = self.call(label + "-" + operation, "cloudformation", operation, {"StackName": value["StackId"]})
            if operation == "describe_stack_resources":
                finding["resources"] = result["StackResources"]
        self.inventory(label + "-versions")
        outputs = {item["OutputKey"]: item["OutputValue"] for item in current.get("Outputs", [])}
        if current["StackStatus"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE") and "VersionNumber" in outputs:
            version = outputs["VersionNumber"]
            finding["configuration"] = self.call(label + "-configuration", "lambda", "get_function_configuration", self.function_request(version), required=False)
            finding["runtime"] = self.call(label + "-runtime", "lambda", "get_runtime_management_config", self.function_request(version), required=False)
            if finding["configuration"]:
                finding["invocation"] = self.invoke(label + "-invoke", version)
        self.save()
        print("FINDING " + label + ": " + json.dumps(document(finding)), flush=True)
        return finding

    def delete_stack(self, key, label, *, bounded_observation=False):
        stack = self.data["owned"]["stacks"][key]
        identifier = stack.get("id", stack["name"])
        current = self.call(label + "-current", "cloudformation", "describe_stacks", {"StackName": identifier}, required=False)
        if not current:
            self.absent(label + "-name-absent", "cloudformation", "describe_stacks", {"StackName": stack["name"]}, "ValidationError")
            return "ABSENT"
        value = current["Stacks"][0]
        if value.get("Tags") != [{"Key": "stackd-probe", "Value": self.data["prefix"]}]:
            raise RuntimeError("Refusing deletion without exact stack ownership tag")
        if value["StackStatus"].endswith("_IN_PROGRESS"):
            value = self.wait_owned_stack(key, label + "-settle")
        if value["StackStatus"] != "DELETE_COMPLETE":
            self.call(label + "-delete", "cloudformation", "delete_stack", {"StackName": identifier})
            value = self.wait_owned_stack(key, label, bounded_observation=bounded_observation)
        self.call(label + "-events", "cloudformation", "describe_stack_events", {"StackName": identifier})
        if value["StackStatus"] == "DELETE_COMPLETE":
            self.absent(label + "-name-absent", "cloudformation", "describe_stacks", {"StackName": stack["name"]}, "ValidationError")
            stack["deleted"] = True
            self.save()
        return value["StackStatus"]

    def resource_group(self, key, arn):
        name = self.data["prefix"] + "-group"
        self.absent("group-name-absent", "resource-groups", "get_group", {"Group": name}, "NotFoundException")
        self.data["owned"]["group"] = {"name": name, "creation_attempted": True}
        self.save()
        query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
            "ResourceTypeFilters": ["AWS::Lambda::Version"], "StackIdentifier": self.data["owned"]["stacks"][key]["id"]})}
        value = self.call("create-version-group", "resource-groups", "create_group", {
            "Name": name, "ResourceQuery": query, "Tags": {"stackd-probe": self.data["prefix"]}}, required=False)
        finding = {"admission_code": self.code(), "expected_version_arn": arn}
        self.data["findings"]["resource_group"] = finding
        if value:
            self.data["owned"]["group"]["arn"] = value["Group"]["GroupArn"]
            self.save()
            start, attempt = time.monotonic(), 0
            while True:
                members = self.call("version-group-members-" + str(attempt), "resource-groups", "list_group_resources", {"Group": value["Group"]["GroupArn"]}, required=False)
                member = any(item.get("ResourceType") == "AWS::Lambda::Version" and item.get("ResourceArn") == arn
                             for item in members.get("ResourceIdentifiers", []))
                if member or time.monotonic() - start >= self.data["bounds"]["resource_group_wait_seconds"]:
                    finding.update(membership_observed=member, observation_seconds=time.monotonic() - start)
                    break
                attempt += 1
                time.sleep(5)
        self.save()

    def workflow(self):
        self.documents()
        self.setup()
        native = self.call("native-first-publication", "lambda", "publish_version", self.function_request())
        self.inventory("native-first-inventory")
        repeated = self.call("native-unchanged-publication", "lambda", "publish_version", self.function_request(), required=False)
        self.data["findings"]["native_unchanged"] = {"first": native, "repeated": repeated, "code": self.code()}
        self.save()
        self.stack("adopt", "already-native-published", self.template())
        self.data["findings"]["native_after_adoption_rejection"] = self.call("native-after-adoption-rejection", "lambda", "get_function_configuration", self.function_request(native["Version"]), required=False)
        self.data["findings"]["delete_adopted_publication"] = {"status": self.delete_stack("adopt", "delete-adopted")}
        self.save()
        config = self.change("main")
        template = self.template(CodeSha256=config["CodeSha256"], Description="initial version")
        initial = self.stack("main", "initial", template)
        if initial.get("stack_status") != "CREATE_COMPLETE":
            raise RuntimeError("Initial Version stack did not complete")
        outputs = {item["OutputKey"]: item["OutputValue"] for item in initial["outputs"]}
        self.stack("shared", "second-stack-same-publication", copy.deepcopy(template))
        self.data["findings"]["delete_shared_publication"] = {"status": self.delete_stack("shared", "delete-shared")}
        self.data["findings"]["publication_after_shared_delete"] = self.call("publication-after-shared-delete", "lambda", "get_function_configuration", self.function_request(outputs["VersionNumber"]), required=False)
        self.resource_group("main", outputs["VersionRef"])
        template["Resources"]["Version"]["Properties"]["Description"] = "description-only replacement"
        description = self.stack("main", "description-only", template, update=True)
        if description.get("stack_status") != "UPDATE_COMPLETE":
            template["Resources"]["Version"]["Properties"]["Description"] = "initial version"
        template["Resources"]["Version"]["Properties"]["ProvisionedConcurrencyConfig"] = {"ProvisionedConcurrentExecutions": 1}
        pc = self.stack("main", "provisioned-only", template, update=True)
        for item in pc.get("outputs", []):
            if item["OutputKey"] == "VersionNumber":
                self.data["findings"]["provisioned_state"] = self.call("provisioned-state", "lambda", "get_provisioned_concurrency_config", self.function_request(item["OutputValue"]), required=False)
        # End the bounded capacity interval immediately; stack deletion follows.
        for version in self.data["owned"]["function"]["versions"]:
            self.call("end-provisioned-" + version, "lambda", "delete_provisioned_concurrency_config", self.function_request(version), required=False)
        self.data["findings"]["delete_main"] = {"status": self.delete_stack("main", "delete-main")}
        self.save()
        self.change("hash-mismatch")
        foreign = self.call("native-before-hash-mismatch", "lambda", "publish_version", self.function_request())
        self.inventory("before-hash-mismatch")
        self.stack("mismatch", "hash-mismatch", self.template(CodeSha256="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
        self.data["findings"]["foreign_after_hash_mismatch"] = self.call("foreign-after-hash-mismatch", "lambda", "get_function_configuration", self.function_request(foreign["Version"]))
        self.save()
        for mode in ("FunctionUpdate", "Auto"):
            self.change("runtime-" + mode.lower())
            self.stack(mode.lower(), "runtime-" + mode.lower(), self.template(RuntimePolicy={"UpdateRuntimeOn": mode}))
        self.change("scaling")
        self.stack("scaling", "on-demand-scaling-boundary", self.template(FunctionScalingConfig={"MinExecutionEnvironments": 0, "MaxExecutionEnvironments": 1}))
        self.change("referenced")
        reference = self.stack("referenced", "referenced-version", self.template())
        outputs = {item["OutputKey"]: item["OutputValue"] for item in reference.get("outputs", [])}
        if "VersionNumber" in outputs:
            self.data["owned"]["aliases"].append("referenced")
            self.save()
            self.call("create-referencing-alias", "lambda", "create_alias", {
                **self.function_request(), "Name": "referenced", "FunctionVersion": outputs["VersionNumber"]})
            self.data["findings"]["delete_alias_referenced_version"] = {
                "stack_status": self.delete_stack("referenced", "delete-alias-referenced-version", bounded_observation=True)}
            self.call("alias-after-version-delete", "lambda", "get_alias", {**self.function_request(), "Name": "referenced"}, required=False)
            self.call("version-after-alias-referenced-delete", "lambda", "get_function_configuration", self.function_request(outputs["VersionNumber"]), required=False)
        self.data["workflow_complete"] = True
        self.data["finished_at"] = now()
        self.save()

    def provisioned_alias_workflow(self):
        self.documents()
        self.setup()
        result = self.stack("provisioned", "fresh-provisioned-version", self.template(
            ProvisionedConcurrencyConfig={"ProvisionedConcurrentExecutions": 1}))
        if result.get("stack_status") != "CREATE_COMPLETE":
            raise RuntimeError("Fresh provisioned Version stack did not complete")
        outputs = {item["OutputKey"]: item["OutputValue"] for item in result["outputs"]}
        version = outputs["VersionNumber"]
        self.data["findings"]["numeric_provisioned_state"] = self.call(
            "numeric-provisioned-state", "lambda", "get_provisioned_concurrency_config",
            self.function_request(version))
        self.data["owned"]["aliases"].append("pool-check")
        self.save()
        self.call("create-pool-check-alias", "lambda", "create_alias", {
            **self.function_request(), "Name": "pool-check", "FunctionVersion": version})
        self.data["findings"]["numeric_pool_invocation"] = self.invoke("invoke-numeric-pool", version)
        self.data["findings"]["alias_pool_invocation"] = self.invoke("invoke-alias-numeric-pool", "pool-check")
        self.data["findings"]["alias_provisioned_state"] = self.call(
            "alias-provisioned-state", "lambda", "get_provisioned_concurrency_config",
            self.function_request("pool-check"), required=False)
        self.data["findings"]["alias_provisioned_code"] = self.code()
        self.save()
        self.call("end-numeric-pool", "lambda", "delete_provisioned_concurrency_config",
                  self.function_request(version))
        self.data["findings"]["delete_alias_referenced_version"] = {
            "stack_status": self.delete_stack("provisioned", "delete-provisioned-referenced-version", bounded_observation=True)}
        self.call("alias-after-provisioned-version-delete", "lambda", "get_alias",
                  {**self.function_request(), "Name": "pool-check"}, required=False)
        self.call("provisioned-version-after-referenced-delete", "lambda", "get_function_configuration",
                  self.function_request(version), required=False)
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

        def function_owned():
            current = self.call("cleanup-function-identity", "lambda", "get_function", self.function_request(), required=False)
            if not current and self.code() == "ResourceNotFoundException":
                return False
            if current.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                raise RuntimeError("Refusing function cleanup without exact ownership tag")
            if owned["function"].get("arn", current["Configuration"]["FunctionArn"]) != current["Configuration"]["FunctionArn"]:
                raise RuntimeError("Owned function ARN changed")
            return True

        def remove_function_children():
            if not function_owned():
                return
            self.inventory("cleanup-version-inventory")
            for version in owned["function"]["versions"]:
                self.call("cleanup-delete-provisioned-" + version, "lambda", "delete_provisioned_concurrency_config", self.function_request(version), required=False)
            for name in owned.get("aliases", []):
                request = {**self.function_request(), "Name": name}
                self.call("cleanup-delete-alias-" + name, "lambda", "delete_alias", request, required=False)
                self.absent("cleanup-alias-absent-" + name, "lambda", "get_alias", request, "ResourceNotFoundException")

        def remove_function():
            if function_owned():
                self.call("cleanup-delete-function", "lambda", "delete_function", self.function_request())
            self.absent("cleanup-function-absent", "lambda", "get_function_configuration", self.function_request(), "ResourceNotFoundException")
            for version in owned["function"]["versions"]:
                self.absent("cleanup-version-absent-" + version, "lambda", "get_function_configuration", self.function_request(version), "ResourceNotFoundException")
                self.absent("cleanup-provisioned-absent-" + version, "lambda", "get_provisioned_concurrency_config", self.function_request(version), "ResourceNotFoundException")

        def remove_role():
            role = self.call("cleanup-role-identity", "iam", "get_role", {"RoleName": owned["role"]["name"]}, required=False)
            if role:
                current = role["Role"]
                tags = {item["Key"]: item["Value"] for item in current.get("Tags", [])}
                if tags.get("stackd-probe") != self.data["prefix"] or current["RoleId"] != owned["role"].get("id", current["RoleId"]):
                    raise RuntimeError("Refusing role cleanup without exact ownership identity")
                self.call("cleanup-delete-role", "iam", "delete_role", {"RoleName": owned["role"]["name"]})
            self.absent("cleanup-role-absent", "iam", "get_role", {"RoleName": owned["role"]["name"]}, "NoSuchEntity")

        def remove_group():
            group = owned["group"]
            current = self.call("cleanup-group-identity", "resource-groups", "get_group", {"Group": group.get("arn", group["name"])}, required=False)
            if current:
                arn = current["Group"]["GroupArn"]
                tags = self.call("cleanup-group-tags", "resource-groups", "get_tags", {"Arn": arn})
                if tags.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Refusing group cleanup without exact ownership tag")
                self.call("cleanup-delete-group", "resource-groups", "delete_group", {"Group": arn})
            self.absent("cleanup-group-absent", "resource-groups", "get_group", {"Group": group["name"]}, "NotFoundException")

        def remove_stack(key):
            status = self.delete_stack(key, "cleanup-" + key)
            if status not in ("DELETE_COMPLETE", "ABSENT"):
                raise RuntimeError("Stack deletion ended in " + status)

        if "group" in owned:
            attempt("group", remove_group)
        if "function" in owned:
            attempt("function children", remove_function_children)
        for key in reversed(list(owned["stacks"])):
            attempt("stack " + key, lambda key=key: remove_stack(key))
        if "function" in owned:
            attempt("function", remove_function)
        if "role" in owned:
            attempt("role", remove_role)
        self.data["cleanup"].update(complete=not errors, errors=errors, finished_at=now(),
            boundary="Deleted stack ARNs retain DELETE_COMPLETE history; stack names and native resources verified absent")
        self.save()
        if errors:
            raise RuntimeError("Exact-owned cleanup incomplete: " + "; ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_version.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--provisioned-alias-only", action="store_true",
                        help="Capture one fresh Version pool and invocation through its alias")
    parser.add_argument("--schema-output", type=Path, help="Add only the Version entry to existing schema inventory")
    args = parser.parse_args()
    probe = VersionProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            if args.provisioned_alias_only:
                probe.provisioned_alias_workflow()
            else:
                probe.workflow()
    except Exception as error:
        probe.data["failure"] = {"at": now(), "error": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
