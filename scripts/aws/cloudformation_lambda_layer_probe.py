#!/usr/bin/env python3
"""Capture native CloudFormation LayerVersion publication and runtime behavior.

Only exact-owned temporary resources are mutated. Evidence is never overwritten;
--cleanup-only resumes the durable inventory. No provisioned capacity is used.
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
import botocore
from botocore.config import Config

from cloudformation_lambda_version_probe import VersionProbe
from cloudtrail_service_probe import REGION, document, now

SOURCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-layerversion.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-layerversion-content.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_DeleteLayerVersion.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_LayerVersionContentInput.md",
    "https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.md",
    "https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.md",
]
HANDLER = '''import shared

def handler(event, context):
    return {"marker": shared.VALUE, "module_path": shared.__file__,
            "invoked_arn": context.invoked_function_arn}
'''


def archive_bytes(path, source):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        entry = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, source)
    return output.getvalue()


class LayerProbe(VersionProbe):
    # Reuse durable recording, identity checks, function readiness and exact-owned
    # stack deletion from the Version/Alias probes, not their publication workflow.
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config) for name in
                        ("sts", "iam", "s3", "lambda", "cloudformation", "resource-groups", "logs")}
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
                "prefix": "stackd-cfn-layer-" + uuid.uuid4().hex[:12],
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "Exact-owned versioned S3 bucket/object, layer versions, stacks, one permissionless role/function and Resource Group; no provisioned capacity",
                "bounds": {"stack_wait_seconds": 420, "poll_seconds": 3, "resource_group_wait_seconds": 90},
                "sources": SOURCES, "documentation": [], "calls": [], "templates": {},
                "owned": {"stacks": {}, "layers": {}}, "findings": {},
                "calibration_gaps": [
                    "Private CloudFormation ownership tokens and restart/foreign-replacement fencing are not publicly observable.",
                    "A bounded Resource Groups membership miss is not permanent exclusion.",
                    "Layer content uses default COPY storage; current documented REFERENCE storage mode is not exercised.",
                    "One Python runtime, x86_64 architecture and tiny archive are exercised; cross-account sharing and signing are not.",
                ], "cleanup": {"complete": False}, "workflow_complete": False,
                "redaction": "Shared credential redaction; native account, IDs, timestamps, SDK inputs and decoded results retained",
            }
        self.save()
        identity = self.call("identity", "sts", "get_caller_identity")
        if identity["Account"] != self.account:
            raise RuntimeError("Native writes authorized only for account " + self.account)
        self.data["identity"] = identity
        self.save()

    def finding(self, name, value):
        self.data["findings"][name] = value
        self.save()
        print("FINDING " + name + ": " + json.dumps(document(value)), flush=True)
        return value

    def documents(self):
        for source in SOURCES:
            try:
                with urllib.request.urlopen(source, timeout=30) as response:
                    raw = response.read()
                text = raw.decode()
                if source.endswith("supported-resources.md"):
                    text = "\n".join(line for line in text.splitlines() if "AWS::Lambda::LayerVersion" in line)
                self.data["documentation"].append({"source": source, "captured_at": now(),
                    "source_sha256": hashlib.sha256(raw).hexdigest(), "content": text})
            except Exception as error:
                self.data["calibration_gaps"].append(source + ": " + str(error))
            self.save()
        registry = self.call("layer-public-registry-schema", "cloudformation", "describe_type",
                             {"Type": "RESOURCE", "TypeName": "AWS::Lambda::LayerVersion"})
        schema = json.loads(registry["Schema"])
        self.data["schema"] = schema
        self.finding("schema_contract", {key: schema.get(key) for key in
            ("primaryIdentifier", "readOnlyProperties", "createOnlyProperties", "required", "tagging")})
        if self.args.schema_output:
            path = self.args.schema_output
            capture = json.loads(path.read_text())
            if capture["account"] != self.account or capture["region"] != REGION:
                raise RuntimeError("Schema inventory target differs from authorized account/region")
            if "AWS::Lambda::LayerVersion" not in capture["types"]:
                row = self.data["calls"][-1]
                capture["types"]["AWS::Lambda::LayerVersion"] = {
                    "input": row["input"], "schema": schema,
                    "metadata": {key: value for key, value in registry.items() if key != "Schema"},
                    "arn": registry.get("Arn", ""), "default_version_id": registry.get("DefaultVersionId", ""),
                    "request_id": row["metadata"].get("RequestId"), "http_status": row["metadata"].get("HTTPStatusCode"),
                    "captured_at": row["finished_at"], "capture": str(self.args.output),
                }
                path.write_text(json.dumps(document(capture), indent=2) + "\n")

    def setup_bucket(self):
        name = self.data["prefix"] + "-data"
        self.absent("bucket-name-absent", "s3", "head_bucket", {"Bucket": name}, "404")
        self.data["owned"]["bucket"] = {"name": name, "creation_attempted": True,
                                        "key": "layer.zip", "versions": []}
        self.save()
        self.call("create-bucket", "s3", "create_bucket", {"Bucket": name})
        self.data["owned"]["bucket"]["creation_confirmed"] = True
        self.save()
        self.call("tag-bucket", "s3", "put_bucket_tagging", {"Bucket": name, "ExpectedBucketOwner": self.account,
            "Tagging": {"TagSet": [{"Key": "stackd-probe", "Value": self.data["prefix"]}]}})
        self.call("enable-object-versioning", "s3", "put_bucket_versioning", {"Bucket": name,
            "ExpectedBucketOwner": self.account, "VersioningConfiguration": {"Status": "Enabled"}})
        self.call("versioning-state", "s3", "get_bucket_versioning", {"Bucket": name, "ExpectedBucketOwner": self.account})
        return self.upload("one")

    def upload(self, marker):
        bucket = self.data["owned"]["bucket"]
        source = "VALUE = " + repr(marker) + "\n"
        payload = archive_bytes("python/shared.py", source)
        self.data.setdefault("archives", {})[marker] = {
            "path": "python/shared.py", "source": source, "bytes": len(payload),
            "sha256_base64": base64.b64encode(hashlib.sha256(payload).digest()).decode()}
        bucket["upload_attempted"] = True
        self.save()
        result = self.call("upload-" + marker, "s3", "put_object", {"Bucket": bucket["name"],
            "Key": bucket["key"], "Body": payload, "ExpectedBucketOwner": self.account})
        version = result.get("VersionId")
        if not version or version == "null":
            raise RuntimeError("Owned versioned upload did not return an immutable version ID")
        bucket["versions"].append(version)
        self.save()
        return {"S3Bucket": bucket["name"], "S3Key": bucket["key"], "S3ObjectVersion": version}

    def reserve_layer(self, suffix):
        name = self.data["prefix"] + "-" + suffix
        result = self.call("layer-name-absent-" + suffix, "lambda", "list_layer_versions", {"LayerName": name})
        if result.get("LayerVersions") or result.get("NextMarker"):
            raise RuntimeError("Refusing existing layer name")
        self.data["owned"]["layers"][name] = {"absence_verified": True, "versions": []}
        self.save()
        return name

    def remember_layer(self, arn, *, stack=None):
        prefix = "arn:aws:lambda:" + REGION + ":" + self.account + ":layer:"
        if not arn.startswith(prefix):
            raise RuntimeError("Layer ARN outside exact authorized account/region")
        name, version = arn[len(prefix):].rsplit(":", 1)
        layers = self.data["owned"]["layers"]
        if name not in layers:
            if not stack or not self.data["owned"]["stacks"].get(stack, {}).get("id"):
                raise RuntimeError("Layer ARN lacks a verified exact-owned stack")
            layers[name] = {"stack": stack, "versions": []}
        if version not in layers[name]["versions"]:
            layers[name]["versions"].append(version)
            self.save()

    def inventory(self, label):
        for name, owned in self.data["owned"]["layers"].items():
            # Omitted LayerName can use the logical ID, not a unique stack name.
            # Only CFN-returned physical IDs establish ownership in that namespace.
            if not owned.get("absence_verified"):
                continue
            marker, page = None, 0
            while True:
                request = {"LayerName": name}
                if marker:
                    request["Marker"] = marker
                result = self.call(label + "-" + name + "-" + str(page), "lambda", "list_layer_versions", request)
                for item in result.get("LayerVersions", []):
                    self.remember_layer(item["LayerVersionArn"])
                marker = result.get("NextMarker")
                if not marker:
                    break
                page += 1
        self.save()

    def properties(self, content, name=None):
        properties = {"Content": content, "Description": "initial layer", "LicenseInfo": "MIT",
                      "CompatibleRuntimes": ["python3.12"], "CompatibleArchitectures": ["x86_64"]}
        if name:
            properties["LayerName"] = name
        return properties

    def template(self, properties):
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
            "Layer": {"Type": "AWS::Lambda::LayerVersion", "Properties": properties}},
            "Outputs": {"LayerRef": {"Value": {"Ref": "Layer"}},
                        "LayerVersionArn": {"Value": {"Fn::GetAtt": ["Layer", "LayerVersionArn"]}}}}

    def stack(self, key, label, properties, update=False):
        stacks = self.data["owned"]["stacks"]
        template = self.template(copy.deepcopy(properties))
        self.data["templates"][label] = template
        if not update:
            name = self.data["prefix"] + "-" + key
            self.absent(label + "-name-absent", "cloudformation", "describe_stacks", {"StackName": name}, "ValidationError")
            stacks[key] = {"name": name, "creation_attempted": True}
        self.save()
        request = {"StackName": stacks[key].get("id", stacks[key]["name"]), "TemplateBody": json.dumps(template),
                   "ClientRequestToken": self.data["prefix"] + "-" + label}
        if not update:
            request["Tags"] = [{"Key": "stackd-probe", "Value": self.data["prefix"]}]
        result = self.call(label + "-submit", "cloudformation", "update_stack" if update else "create_stack", request, required=False)
        finding = {"submission_code": self.code()}
        if not result:
            return self.finding(label, finding)
        stacks[key]["id"] = result["StackId"]
        self.save()
        current = self.wait_owned_stack(key, label)
        finding.update(stack_status=current["StackStatus"], outputs=current.get("Outputs", []))
        self.collect_stack_layers(key, label)
        self.call(label + "-template", "cloudformation", "get_template", {"StackName": result["StackId"]})
        outputs = {item["OutputKey"]: item["OutputValue"] for item in current.get("Outputs", [])}
        if "LayerVersionArn" in outputs:
            finding["arn"] = outputs["LayerVersionArn"]
            finding["ref_equals_getatt"] = outputs["LayerRef"] == outputs["LayerVersionArn"]
            finding["layer"] = self.get_layer(label + "-layer", finding["arn"])
        self.inventory(label + "-inventory")
        return self.finding(label, finding)

    def collect_stack_layers(self, key, label):
        owned = self.data["owned"]["stacks"][key]
        identifier = owned.get("id", owned["name"])
        result = self.call(label + "-identity", "cloudformation", "describe_stacks", {"StackName": identifier}, required=False)
        if not result:
            if self.code() == "ValidationError" and "does not exist" in self.data["calls"][-1]["error"]["Message"]:
                return
            raise RuntimeError("Cannot verify owned stack identity")
        current = result["Stacks"][0]
        if {item["Key"]: item["Value"] for item in current.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
            raise RuntimeError("Refusing stack discovery without exact ownership tag")
        owned["id"] = current["StackId"]
        self.save()
        for operation, field in (("describe_stack_resources", "StackResources"), ("describe_stack_events", "StackEvents")):
            request = {"StackName": owned["id"]}
            page = 0
            while True:
                result = self.call(label + "-" + operation + "-" + str(page), "cloudformation", operation, request)
                for item in result.get(field, []):
                    arn = item.get("PhysicalResourceId", "")
                    if item.get("ResourceType") == "AWS::Lambda::LayerVersion" and arn.startswith("arn:"):
                        self.remember_layer(arn, stack=key)
                if not result.get("NextToken"):
                    break
                request["NextToken"] = result["NextToken"]
                page += 1

    def get_layer(self, label, arn):
        result = self.call(label, "lambda", "get_layer_version_by_arn", {"Arn": arn}, required=False)
        return {"code": self.code(), "result": result}

    def setup_function(self, layer):
        prefix, owned = self.data["prefix"], self.data["owned"]
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
        self.absent("function-name-absent", "lambda", "get_function_configuration", {"FunctionName": function_name}, "ResourceNotFoundException")
        log_name = "/aws/lambda/" + function_name
        logs = self.call("log-name-absent", "logs", "describe_log_groups", {"logGroupNamePrefix": log_name})
        if any(item["logGroupName"] == log_name for item in logs.get("logGroups", [])):
            raise RuntimeError("Owned function log name already exists")
        owned["function"] = {"name": function_name, "creation_attempted": True}
        owned["log_group"] = {"name": log_name, "absence_verified": True}
        self.data["runtime_source"] = HANDLER
        self.save()
        request = {"FunctionName": function_name, "Role": role["Arn"], "Runtime": "python3.12",
                   "Handler": "entry.handler", "Timeout": 3, "MemorySize": 128,
                   "Code": {"ZipFile": archive_bytes("entry.py", HANDLER)}, "Layers": [layer],
                   "Architectures": ["x86_64"], "Tags": {"stackd-probe": prefix}}
        for attempt in range(30):
            result = self.call("create-function-" + str(attempt), "lambda", "create_function", request, required=False)
            if result:
                owned["function"]["arn"] = result["FunctionArn"]
                self.save()
                break
            if self.code() != "InvalidParameterValueException" or "cannot be assumed" not in self.data["calls"][-1]["error"]["Message"]:
                raise RuntimeError("Owned function creation failed: " + self.code())
            time.sleep(3)
        else:
            raise RuntimeError("Owned execution role propagation expired")
        self.ready_function("function-ready")

    def invoke(self, label, marker):
        result = self.call(label, "lambda", "invoke", {"FunctionName": self.data["owned"]["function"]["name"],
            "InvocationType": "RequestResponse", "Payload": b"{}"})
        self.finding(label, result)
        if "FunctionError" in result or result.get("Payload", {}).get("marker") != marker:
            raise RuntimeError("Layer handler did not execute expected archive bytes: " + label)
        return result

    def attach(self, label, arn, marker):
        self.call(label + "-update", "lambda", "update_function_configuration", {
            "FunctionName": self.data["owned"]["function"]["name"], "Layers": [arn]})
        self.ready_function(label + "-ready")
        return self.invoke(label + "-invoke", marker)

    def resource_group(self, key, arn):
        name = self.data["prefix"] + "-group"
        self.absent("group-name-absent", "resource-groups", "get_group", {"Group": name}, "NotFoundException")
        self.data["owned"]["group"] = {"name": name, "creation_attempted": True}
        self.save()
        query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
            "ResourceTypeFilters": ["AWS::Lambda::LayerVersion"], "StackIdentifier": self.data["owned"]["stacks"][key]["id"]})}
        result = self.call("create-layer-group", "resource-groups", "create_group", {
            "Name": name, "ResourceQuery": query, "Tags": {"stackd-probe": self.data["prefix"]}}, required=False)
        finding = {"admission_code": self.code(), "expected_layer_arn": arn}
        if result:
            self.data["owned"]["group"]["arn"] = result["Group"]["GroupArn"]
            self.save()
            start, attempt = time.monotonic(), 0
            while True:
                members = self.call("layer-group-members-" + str(attempt), "resource-groups", "list_group_resources",
                                    {"Group": result["Group"]["GroupArn"]}, required=False)
                member = any(item.get("ResourceType") == "AWS::Lambda::LayerVersion" and item.get("ResourceArn") == arn
                             for item in members.get("ResourceIdentifiers", []))
                if member or time.monotonic() - start >= self.data["bounds"]["resource_group_wait_seconds"]:
                    finding.update(membership_observed=member, observation_seconds=time.monotonic() - start,
                                   final_members=members, final_code=self.code())
                    break
                attempt += 1
                time.sleep(5)
        self.finding("resource_group", finding)

    def workflow(self):
        self.documents()
        first_content = self.setup_bucket()
        name = self.reserve_layer("shared")
        properties = self.properties(first_content, name)
        native = []
        for label in ("native-first", "native-same-content"):
            result = self.call(label, "lambda", "publish_layer_version", copy.deepcopy(properties))
            self.remember_layer(result["LayerVersionArn"])
            native.append(result)
        self.finding("same_content_native_publication", {"first_arn": native[0]["LayerVersionArn"],
            "second_arn": native[1]["LayerVersionArn"], "distinct_versions": native[0]["Version"] != native[1]["Version"],
            "same_hash": native[0]["Content"]["CodeSha256"] == native[1]["Content"]["CodeSha256"]})
        initial = self.stack("main", "initial", properties)
        shared = self.stack("shared", "same-content-second-stack", properties)
        if initial.get("stack_status") != "CREATE_COMPLETE" or shared.get("stack_status") != "CREATE_COMPLETE":
            raise RuntimeError("Same-content layer stacks did not both complete")
        self.finding("same_content_stack_publication", {"initial_arn": initial["arn"], "second_arn": shared["arn"],
            "distinct_versions": initial["arn"] != shared["arn"], "native_arns": [item["LayerVersionArn"] for item in native]})
        self.setup_function(initial["arn"])
        self.invoke("before-layer-retirement", "one")
        properties["Description"] = "description-only replacement"
        description = self.stack("main", "description-only", properties, update=True)
        if description.get("stack_status") != "UPDATE_COMPLETE":
            raise RuntimeError("Description-only layer replacement did not complete")
        self.finding("description_retired_visibility", self.get_layer("description-retired-get", initial["arn"]))
        self.invoke("after-layer-retirement-attached", "one")
        self.finding("delete_shared_stack", {"status": self.delete_stack("shared", "delete-shared"),
            "deleted_layer": self.get_layer("shared-after-delete", shared["arn"]),
            "main_layer": self.get_layer("main-after-shared-delete", description["arn"])})
        self.attach("attach-description-replacement", description["arn"], "one")
        second_content = self.upload("two")
        pinned_name = self.reserve_layer("pinned")
        pinned = self.stack("pinned", "pinned-old-object-version", self.properties(first_content, pinned_name))
        if pinned.get("stack_status") != "CREATE_COMPLETE":
            raise RuntimeError("Pinned layer stack did not complete")
        self.attach("pinned-old-version-after-overwrite", pinned["arn"], "one")
        properties["Content"] = second_content
        changed = self.stack("main", "content-only", properties, update=True)
        if changed.get("stack_status") != "UPDATE_COMPLETE":
            raise RuntimeError("Content-only layer replacement did not complete")
        self.finding("content_retired_visibility", self.get_layer("content-retired-get", description["arn"]))
        self.attach("attach-content-replacement", changed["arn"], "two")
        self.resource_group("main", changed["arn"])
        self.finding("delete_attached_stack", {"status": self.delete_stack("main", "delete-attached"),
            "layer": self.get_layer("deleted-attached-layer-get", changed["arn"]),
            "function": self.call("function-after-attached-delete", "lambda", "get_function_configuration",
                {"FunctionName": self.data["owned"]["function"]["name"]})})
        self.invoke("after-stack-delete-attached", "two")
        self.generated_names(first_content)

    def generated_names(self, first_content):
        generated_properties = self.properties(first_content)
        generated = self.stack("generated", "generated-name", generated_properties)
        if generated.get("stack_status") == "CREATE_COMPLETE":
            generated_properties["Description"] = "generated-name description replacement"
            replaced = self.stack("generated", "generated-name-replacement", generated_properties, update=True)
            self.finding("generated_name_behavior", {"initial_arn": generated["arn"], "replacement_arn": replaced.get("arn"),
                "initial_retired": self.get_layer("generated-retired-get", generated["arn"]),
                "replacement_status": replaced.get("stack_status")})
        else:
            self.data["calibration_gaps"].append("Generated LayerName omission did not produce a successful stack")
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

        def remove_stack(key):
            self.collect_stack_layers(key, "cleanup-discover-" + key)
            status = self.delete_stack(key, "cleanup-" + key)
            if status not in ("DELETE_COMPLETE", "ABSENT"):
                raise RuntimeError("Stack deletion ended in " + status)

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

        def remove_function():
            request = {"FunctionName": owned["function"]["name"]}
            result = self.call("cleanup-function-identity", "lambda", "get_function", request, required=False)
            if result:
                if result.get("Tags", {}).get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Refusing function cleanup without exact ownership tag")
                if result["Configuration"]["FunctionArn"] != owned["function"].get("arn", result["Configuration"]["FunctionArn"]):
                    raise RuntimeError("Owned function ARN changed")
                self.call("cleanup-delete-function", "lambda", "delete_function", request)
            self.absent("cleanup-function-absent", "lambda", "get_function_configuration", request, "ResourceNotFoundException")

        def remove_layers():
            self.inventory("cleanup-layer-inventory")
            for name, layer in owned["layers"].items():
                for version in layer["versions"]:
                    request = {"LayerName": name, "VersionNumber": int(version)}
                    self.call("cleanup-delete-layer-" + name + "-" + version, "lambda", "delete_layer_version", request)
                    self.absent("cleanup-layer-absent-" + name + "-" + version, "lambda", "get_layer_version", request, "ResourceNotFoundException")
                if layer.get("absence_verified"):
                    result = self.call("cleanup-layer-name-empty-" + name, "lambda", "list_layer_versions", {"LayerName": name})
                    if result.get("LayerVersions") or result.get("NextMarker"):
                        raise RuntimeError("Owned layer versions remain")

        def remove_role():
            request = {"RoleName": owned["role"]["name"]}
            result = self.call("cleanup-role-identity", "iam", "get_role", request, required=False)
            if result:
                role = result["Role"]
                tags = {item["Key"]: item["Value"] for item in role.get("Tags", [])}
                if tags.get("stackd-probe") != self.data["prefix"] or role["RoleId"] != owned["role"].get("id", role["RoleId"]):
                    raise RuntimeError("Refusing role cleanup without exact ownership identity")
                inline = self.call("cleanup-role-inline-policies", "iam", "list_role_policies", request)
                attached = self.call("cleanup-role-attached-policies", "iam", "list_attached_role_policies", request)
                if inline.get("PolicyNames") or attached.get("AttachedPolicies"):
                    raise RuntimeError("Permissionless role unexpectedly has policies; refusing unrelated policy deletion")
                self.call("cleanup-delete-role", "iam", "delete_role", request)
            self.absent("cleanup-role-absent", "iam", "get_role", request, "NoSuchEntity")

        def remove_logs():
            name = owned["log_group"]["name"]
            result = self.call("cleanup-log-inventory", "logs", "describe_log_groups", {"logGroupNamePrefix": name})
            if any(item["logGroupName"] == name for item in result.get("logGroups", [])):
                self.call("cleanup-delete-log-group", "logs", "delete_log_group", {"logGroupName": name})
            result = self.call("cleanup-log-absent", "logs", "describe_log_groups", {"logGroupNamePrefix": name})
            if any(item["logGroupName"] == name for item in result.get("logGroups", [])):
                raise RuntimeError("Owned log group remains")

        def remove_bucket():
            bucket = owned["bucket"]
            request = {"Bucket": bucket["name"], "ExpectedBucketOwner": self.account}
            self.call("cleanup-bucket-identity", "s3", "head_bucket", request, required=False)
            if self.code() == "404":
                return
            if self.code() != "Success":
                raise RuntimeError("Cannot verify owned bucket account")
            tags = self.call("cleanup-bucket-tags", "s3", "get_bucket_tagging", request, required=False)
            matched = {item["Key"]: item["Value"] for item in tags.get("TagSet", [])}.get("stackd-probe") == self.data["prefix"]
            if not matched and not (self.code() == "NoSuchTagSet" and bucket.get("creation_confirmed")):
                raise RuntimeError("Refusing bucket cleanup without exact creation identity")
            page_request = dict(request)
            while True:
                result = self.call("cleanup-object-version-inventory", "s3", "list_object_versions", page_request)
                items = result.get("Versions", []) + result.get("DeleteMarkers", [])
                if any(item["Key"] != bucket["key"] for item in items):
                    raise RuntimeError("Unexpected object in exact-owned bucket")
                for item in items:
                    self.call("cleanup-delete-object-version-" + item["VersionId"], "s3", "delete_object",
                              {**request, "Key": item["Key"], "VersionId": item["VersionId"]})
                if not result.get("IsTruncated"):
                    break
                page_request.update(KeyMarker=result["NextKeyMarker"], VersionIdMarker=result["NextVersionIdMarker"])
            result = self.call("cleanup-object-versions-empty", "s3", "list_object_versions", request)
            if result.get("Versions") or result.get("DeleteMarkers"):
                raise RuntimeError("Owned S3 object versions remain")
            self.call("cleanup-delete-bucket", "s3", "delete_bucket", request)
            self.absent("cleanup-bucket-absent", "s3", "head_bucket", request, "404")

        if "group" in owned:
            attempt("group", remove_group)
        for key in reversed(list(owned["stacks"])):
            attempt("stack " + key, lambda key=key: remove_stack(key))
        if "function" in owned:
            attempt("function", remove_function)
        attempt("layers", remove_layers)
        if "role" in owned:
            attempt("role", remove_role)
        if "log_group" in owned:
            attempt("logs", remove_logs)
        if "bucket" in owned:
            attempt("bucket", remove_bucket)
        self.data["cleanup"].update(complete=not errors, errors=errors, finished_at=now(),
            boundary="Stack ARNs retain DELETE_COMPLETE history; stack names, functions, layer versions, object versions, bucket, role and group checked absent")
        self.save()
        if errors:
            raise RuntimeError("Exact-owned cleanup incomplete: " + "; ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_layer.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--generated-only", action="store_true",
                        help="Capture omitted LayerName replacement using only a bucket and one stack")
    parser.add_argument("--schema-output", type=Path, help="Add only the LayerVersion entry to existing schema inventory")
    args = parser.parse_args()
    probe = LayerProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            if args.generated_only:
                probe.data["scope"] = "Exact-owned versioned S3 bucket/object and one LayerVersion stack; only CFN-returned physical versions are owned when LayerName is omitted"
                probe.save()
                probe.documents()
                probe.generated_names(probe.setup_bucket())
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
