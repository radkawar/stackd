#!/usr/bin/env python3
"""Capture exact-owned native CloudFormation LayerVersionPermission behavior.

Only unique temporary layers, stacks and own-account permissions are created.
Evidence is never overwritten; --cleanup-only resumes the durable inventory.
No IAM resources, functions, public permissions or cross-account fixtures are used.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import urllib.request
import uuid

import boto3
import botocore
from botocore.config import Config

from cloudformation_lambda_layer_probe import LayerProbe, archive_bytes
from cloudtrail_service_probe import REGION, document, now

TYPE_NAME = "AWS::Lambda::LayerVersionPermission"

SOURCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-layerversionpermission.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_AddLayerVersionPermission.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_RemoveLayerVersionPermission.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_GetLayerVersionPolicy.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatereplacepolicy.md",
]


class LayerPermissionProbe(LayerProbe):
    # Reuse exact-owned layer inventory, signed SDK recording/redaction and
    # tagged stack cleanup, without running the layer/function probe workflow.
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.root = "arn:aws:iam::" + self.account + ":root"
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config)
                        for name in ("sts", "lambda", "cloudformation")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.account or self.data["region"] != REGION:
                raise RuntimeError("Capture target differs from authorized account/region")
            if not self.data["prefix"].startswith("stackd-cfn-layer-permission-"):
                raise RuntimeError("Capture is not a layer-permission inventory")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "source": "Native AWS public endpoints; signed boto3; configured endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION,
                "prefix": "stackd-cfn-layer-permission-" + uuid.uuid4().hex[:12],
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "Exact-owned temporary layer versions, stacks and statements granting only own account ID/root; no IAM resources or compute",
                "bounds": {"stack_wait_seconds": 420, "poll_seconds": 3},
                "sources": SOURCES, "documentation": [], "calls": [], "templates": {},
                "owned": {"stacks": {}, "layers": {}, "statements": []}, "findings": {},
                "calibration_gaps": [
                    "Private deployment ownership tokens, exact-owned retry recovery, foreign-replacement fencing and SQLite restart persistence are local invariants, not observable native contracts.",
                    "Cross-account attachment is unmeasured: no explicitly authorized cross-account fixture is available; only own-account ID/root principals are exercised.",
                    "OrganizationId and wildcard-principal behavior are not exercised; this probe never grants public or organization-wide access.",
                ], "cleanup": {"complete": False}, "workflow_complete": False,
                "redaction": "Shared credential redaction; native account, IDs, timestamps, SDK inputs and decoded results retained",
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
                self.data["documentation"].append({"source": source, "captured_at": now(),
                    "source_sha256": hashlib.sha256(raw).hexdigest(), "content": raw.decode()})
            except Exception as error:
                self.data["calibration_gaps"].append(source + ": " + str(error))
            self.save()
        registry = self.call("permission-public-registry-schema", "cloudformation", "describe_type",
                             {"Type": "RESOURCE", "TypeName": TYPE_NAME})
        schema = json.loads(registry["Schema"])
        self.data["schema"] = schema
        self.finding("schema_contract", {key: schema.get(key) for key in
            ("primaryIdentifier", "readOnlyProperties", "createOnlyProperties", "required", "tagging")})
        if self.args.schema_output:
            path = self.args.schema_output
            capture = json.loads(path.read_text())
            if capture["account"] != self.account or capture["region"] != REGION:
                raise RuntimeError("Schema inventory target differs from authorized account/region")
            if TYPE_NAME not in capture["types"]:
                row = self.data["calls"][-1]
                capture["types"][TYPE_NAME] = {
                    "input": row["input"], "schema": schema,
                    "metadata": {key: value for key, value in registry.items() if key != "Schema"},
                    "arn": registry.get("Arn", ""), "default_version_id": registry.get("DefaultVersionId", ""),
                    "request_id": row["metadata"].get("RequestId"), "http_status": row["metadata"].get("HTTPStatusCode"),
                    "captured_at": row["finished_at"], "capture": str(self.args.output),
                }
                path.write_text(json.dumps(document(capture), indent=2) + "\n")

    def publish(self, name, marker):
        if name not in self.data["owned"]["layers"]:
            raise RuntimeError("Layer publication requires an absence-verified owned name")
        result = self.call("publish-layer-" + marker, "lambda", "publish_layer_version", {
            "LayerName": name, "Description": self.data["prefix"],
            "Content": {"ZipFile": archive_bytes("python/permission_probe.py", "VALUE = " + repr(marker) + "\n")},
            "CompatibleRuntimes": ["python3.12"]})
        self.remember_layer(result["LayerVersionArn"])
        return result["LayerVersionArn"]

    def layer_request(self, arn):
        prefix = "arn:aws:lambda:" + REGION + ":" + self.account + ":layer:"
        if not arn.startswith(prefix):
            raise RuntimeError("Layer ARN outside authorized account/region")
        name, version = arn[len(prefix):].rsplit(":", 1)
        layer = self.data["owned"]["layers"].get(name, {})
        if version not in layer.get("versions", []):
            raise RuntimeError("Layer version lacks exact-created inventory ownership")
        return {"LayerName": name, "VersionNumber": int(version)}

    def remember_statement(self, physical):
        arn, sid = physical.rsplit("#", 1)
        self.layer_request(arn)
        statement = {"layer_arn": arn, "statement_id": sid, "physical_id": physical}
        if statement not in self.data["owned"]["statements"]:
            self.data["owned"]["statements"].append(statement)
            self.save()
        return statement

    def policy(self, label, arn):
        result = self.call(label, "lambda", "get_layer_version_policy", self.layer_request(arn), required=False)
        return {"code": self.code(), **result,
                **({"document": json.loads(result["Policy"])} if result.get("Policy") else {})}

    def template(self, arn, principal, retain=False, include_getatt=False):
        self.layer_request(arn)
        if principal not in (self.account, self.root):
            raise RuntimeError("Only own-account ID/root permissions are authorized")
        resource = {"Type": TYPE_NAME, "Properties": {
            "Action": "lambda:GetLayerVersion", "LayerVersionArn": arn, "Principal": principal}}
        if retain:
            resource.update(DeletionPolicy="Retain", UpdateReplacePolicy="Retain")
        outputs = {"PermissionRef": {"Value": {"Ref": "Permission"}}}
        if include_getatt:
            outputs["PermissionId"] = {"Value": {"Fn::GetAtt": ["Permission", "Id"]}}
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Permission": resource},
                "Outputs": outputs}

    def collect_statements(self, key, label):
        stack = self.data["owned"]["stacks"][key]
        if not stack.get("id"):
            return []
        result = self.call(label + "-resources", "cloudformation", "describe_stack_resources",
                           {"StackName": stack["id"]}, required=False)
        resources = result.get("StackResources", [])
        for resource in resources:
            physical = resource.get("PhysicalResourceId", "")
            if resource.get("ResourceType") == TYPE_NAME and "#" in physical:
                self.remember_statement(physical)
        self.call(label + "-events", "cloudformation", "describe_stack_events", {"StackName": stack["id"]})
        return resources

    def stack(self, key, label, arn, principal=None, *, update=False, retain=False, include_getatt=False):
        if principal is None:
            principal = self.account
        template = self.template(arn, principal, retain, include_getatt)
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
        result = self.call(label + "-submit", "cloudformation", "update_stack" if update else "create_stack", request)
        stacks[key]["id"] = result["StackId"]
        self.save()
        current = self.wait_owned_stack(key, label)
        resources = self.collect_statements(key, label)
        self.call(label + "-template", "cloudformation", "get_template", {"StackName": result["StackId"]})
        finding = {"stack_status": current["StackStatus"], "outputs": current.get("Outputs", []), "resources": resources,
                   "policy": self.policy(label + "-policy", arn)}
        outputs = {item["OutputKey"]: item["OutputValue"] for item in current.get("Outputs", [])}
        if "PermissionRef" in outputs:
            finding.update(self.remember_statement(outputs["PermissionRef"]))
            finding["ref_equals_physical_id"] = any(resource.get("PhysicalResourceId") == outputs["PermissionRef"] for resource in resources)
        self.finding(label, finding)
        if current["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            raise RuntimeError(label + ": unexpected stack status " + current["StackStatus"])
        return finding

    def remove_statement(self, label, statement, *, required=True):
        if not any(item["physical_id"] == statement["physical_id"] for item in self.data["owned"]["statements"]):
            raise RuntimeError("Statement lacks exact-owned physical identity")
        self.call(label, "lambda", "remove_layer_version_permission", {
            **self.layer_request(statement["layer_arn"]), "StatementId": statement["statement_id"]}, required=required)
        return self.code()

    def getatt_workflow(self):
        self.documents()
        name = self.reserve_layer("getatt")
        arn = self.publish(name, "getatt")
        created = self.stack("getatt", "getatt-create", arn, include_getatt=True)
        outputs = {item["OutputKey"]: item["OutputValue"] for item in created["outputs"]}
        self.finding("getatt_id", {"ref": outputs["PermissionRef"], "id": outputs["PermissionId"],
            "ref_equals_id": outputs["PermissionRef"] == outputs["PermissionId"],
            "id_equals_physical_id": outputs["PermissionId"] == created["physical_id"]})
        self.data["workflow_complete"] = True
        self.save()

    def workflow(self):
        self.documents()
        name = self.reserve_layer("data")
        first, second = self.publish(name, "one"), self.publish(name, "two")
        self.finding("initial_policy", self.policy("initial-policy", first))
        created = self.stack("lifecycle", "create", first)
        self.call("native-duplicate-add", "lambda", "add_layer_version_permission", {
            **self.layer_request(first), "StatementId": created["statement_id"],
            "Action": "lambda:GetLayerVersion", "Principal": self.account}, required=False)
        self.finding("native_duplicate_add", {"code": self.code(), "policy": self.policy("duplicate-add-policy", first)})
        replaced = self.stack("lifecycle", "principal-replacement", first, self.root, update=True)
        self.finding("principal_replacement_identity", {
            "before": created["physical_id"], "after": replaced["physical_id"],
            "sid_changed": created["statement_id"] != replaced["statement_id"],
            "old_sid_present": any(item["Sid"] == created["statement_id"] for item in replaced["policy"].get("document", {}).get("Statement", []))})
        retargeted = self.stack("lifecycle", "layer-replacement", second, self.root, update=True)
        self.finding("layer_replacement_identity", {
            "before": replaced["physical_id"], "after": retargeted["physical_id"],
            "old_layer_policy": self.policy("old-layer-policy-after-replacement", first)})
        status = self.delete_stack("lifecycle", "normal-delete")
        self.finding("normal_delete", {"stack_status": status, "policy": self.policy("policy-after-normal-delete", second)})

        missing = self.stack("missing", "missing-create", first)
        self.remove_statement("native-remove-owned-statement", missing)
        self.finding("missing_statement", {
            "policy": self.policy("policy-after-native-remove", first),
            "second_remove_code": self.remove_statement("native-remove-already-deleted-statement", missing, required=False)})
        status = self.delete_stack("missing", "missing-statement-delete")
        self.finding("missing_statement_stack_delete", {"stack_status": status,
            "policy": self.policy("policy-after-missing-statement-stack-delete", first)})

        self.stack("deleted-layer", "deleted-layer-create", second)
        self.call("native-delete-owned-layer", "lambda", "delete_layer_version", self.layer_request(second))
        self.absent("deleted-layer-absent", "lambda", "get_layer_version", self.layer_request(second), "ResourceNotFoundException")
        status = self.delete_stack("deleted-layer", "deleted-layer-stack-delete")
        self.finding("deleted_layer_stack_delete", {"stack_status": status,
            "policy": self.policy("policy-after-deleted-layer-stack-delete", second)})

        retained = self.stack("retained", "retained-create", first, retain=True)
        retained_new = self.stack("retained", "retained-replacement", first, self.root, update=True, retain=True)
        status = self.delete_stack("retained", "retained-delete")
        self.finding("retention", {"stack_status": status,
            "original_physical_id": retained["physical_id"], "replacement_physical_id": retained_new["physical_id"],
            "policy_after_stack_delete": self.policy("policy-after-retained-stack-delete", first)})
        self.data["workflow_complete"] = True
        self.save()

    def cleanup(self):
        self.cleanup_phase = True
        errors = []

        def attempt(label, operation):
            try:
                operation()
            except Exception as error:
                errors.append(label + ": " + str(error))
                self.data["cleanup"]["errors"] = errors
                self.save()

        def remove_stack(key):
            self.collect_statements(key, "cleanup-discover-" + key)
            status = self.delete_stack(key, "cleanup-" + key)
            if status not in ("DELETE_COMPLETE", "ABSENT"):
                raise RuntimeError("Stack deletion ended in " + status)

        def remove_permission(statement):
            code = self.remove_statement("cleanup-remove-statement-" + statement["statement_id"], statement, required=False)
            if code not in ("Success", "ResourceNotFoundException"):
                raise RuntimeError("Statement cleanup failed: " + code)
            policy = self.policy("cleanup-check-statement-" + statement["statement_id"], statement["layer_arn"])
            if policy["code"] not in ("Success", "ResourceNotFoundException"):
                raise RuntimeError("Cannot verify statement absence: " + policy["code"])
            if any(item["Sid"] == statement["statement_id"] for item in policy.get("document", {}).get("Statement", [])):
                raise RuntimeError("Exact-owned statement remains")

        def remove_layers():
            self.inventory("cleanup-layer-inventory")
            for name, layer in self.data["owned"]["layers"].items():
                if not name.startswith(self.data["prefix"] + "-") or not layer.get("absence_verified"):
                    raise RuntimeError("Layer name lacks exact-owned absence verification")
                for version in layer["versions"]:
                    request = {"LayerName": name, "VersionNumber": int(version)}
                    self.call("cleanup-delete-layer-" + version, "lambda", "delete_layer_version", request)
                    self.absent("cleanup-layer-absent-" + version, "lambda", "get_layer_version", request, "ResourceNotFoundException")
                    self.absent("cleanup-policy-absent-" + version, "lambda", "get_layer_version_policy", request, "ResourceNotFoundException")
                result = self.call("cleanup-layer-name-empty-" + name, "lambda", "list_layer_versions", {"LayerName": name})
                if result.get("LayerVersions") or result.get("NextMarker"):
                    raise RuntimeError("Owned layer versions remain")

        for key in reversed(list(self.data["owned"]["stacks"])):
            attempt("stack " + key, lambda key=key: remove_stack(key))
        for statement in self.data["owned"]["statements"]:
            attempt("statement " + statement["physical_id"], lambda statement=statement: remove_permission(statement))
        attempt("layers", remove_layers)
        self.data["cleanup"].update(complete=not errors, errors=errors, finished_at=now(),
            boundary="Stack ARNs retain DELETE_COMPLETE history; exact-created stack names, permission statements, layer versions and policies checked absent")
        self.save()
        if errors:
            raise RuntimeError("Exact-owned cleanup incomplete: " + "; ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_layer_permission.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--getatt-only", action="store_true",
                        help="Capture only Ref and GetAtt Id using one layer and one stack")
    parser.add_argument("--schema-output", type=Path, help="Add only the LayerVersionPermission entry to existing schema inventory")
    args = parser.parse_args()
    probe = LayerPermissionProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            if args.getatt_only:
                probe.getatt_workflow()
            else:
                probe.workflow()
    except Exception as error:
        probe.data.setdefault("failures", []).append({"at": now(), "error": str(error)})
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
