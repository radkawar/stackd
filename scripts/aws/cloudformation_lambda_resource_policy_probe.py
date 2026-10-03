#!/usr/bin/env python3
"""Capture exact-owned native CFN function policies and stale-Sid deletion.

Evidence is never overwritten; --cleanup-only resumes its durable inventory.
Only own-account grants are used. Functions are never invoked.
"""
import argparse
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
from cloudformation_lambda_version_probe import VersionProbe
from cloudtrail_service_probe import REGION, document, now

TYPE = "AWS::Lambda::ResourcePolicy"

SOURCES = [
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-resourcepolicy.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-permission.md",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-layerversionpermission.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_PutResourcePolicy.md",
    "https://docs.aws.amazon.com/lambda/latest/api/API_DeleteResourcePolicy.md",
]


class ResourcePolicyProbe(LayerProbe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.root = "arn:aws:iam::" + self.account + ":root"
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config)
                        for name in ("sts", "iam", "lambda", "cloudformation", "logs")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if (self.data["account"], self.data["region"]) != (self.account, REGION):
                raise RuntimeError("Inventory outside approved account/region")
            if not self.data["prefix"].startswith("stackd-cfn-fpolicy-"):
                raise RuntimeError("Not a function-policy inventory")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "source": "Native AWS public endpoints; signed boto3; endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION,
                "prefix": "stackd-cfn-fpolicy-" + uuid.uuid4().hex[:12],
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "Exact-owned non-invoked function, permissionless role, layer, stacks; own-account/root grants only",
                "bounds": {"stack_wait_seconds": 420, "poll_seconds": 3},
                "owned": {"stacks": {}, "layers": {}, "statements": [], "aliases": []},
                "calls": [], "findings": {}, "templates": {}, "schemas": {},
                "sources": SOURCES, "documentation": [],
                "calibration_gaps": [
                    "Cross-account authorization and invocation are unmeasured; own-account grants only.",
                    "Public, wildcard, organization and function-URL grants are unmeasured and never created.",
                    "Private CloudFormation ownership tokens, restart recovery and local SQLite persistence are not native measurements.",
                ],
                "cleanup": {"complete": False}, "workflow_complete": False,
            }
        self.save()
        identity = self.call("identity", "sts", "get_caller_identity")
        if identity["Account"] != self.account:
            raise RuntimeError("Unauthorized native account")
        self.data["identity"] = identity
        self.finding("authorized_identity", identity)

    def documents(self):
        for name in (TYPE, "AWS::Lambda::Permission"):
            registry = self.call("schema-" + name.split("::")[-1], "cloudformation", "describe_type",
                                 {"Type": "RESOURCE", "TypeName": name}, required=False)
            if not registry:
                self.data["calibration_gaps"].append(name + " DescribeType unavailable: " + self.code())
                continue
            schema = json.loads(registry["Schema"])
            self.data["schemas"][name] = schema
            self.finding("schema_" + name.split("::")[-1], {key: schema.get(key) for key in
                         ("properties", "primaryIdentifier", "readOnlyProperties", "createOnlyProperties", "required")})
            if self.args.schema_output:
                path = self.args.schema_output
                capture = json.loads(path.read_text())
                if (capture["account"], capture["region"]) != (self.account, REGION):
                    raise RuntimeError("Unauthorized schema inventory")
                row = self.data["calls"][-1]
                capture["types"][name] = {
                    "input": row["input"], "schema": schema,
                    "metadata": {key: value for key, value in registry.items() if key != "Schema"},
                    "arn": registry.get("Arn", ""), "default_version_id": registry.get("DefaultVersionId", ""),
                    "request_id": row["metadata"].get("RequestId"), "http_status": row["metadata"].get("HTTPStatusCode"),
                    "captured_at": row["finished_at"], "capture": str(self.args.output),
                }
                path.write_text(json.dumps(document(capture), indent=2) + "\n")
        for source in SOURCES:
            try:
                with urllib.request.urlopen(source, timeout=30) as response:
                    raw = response.read()
                self.data["documentation"].append({"source": source, "captured_at": now(),
                    "sha256": hashlib.sha256(raw).hexdigest(), "content": raw.decode()})
            except Exception as error:
                self.data["calibration_gaps"].append(source + ": " + str(error))
            self.save()
        schema = self.data["schemas"].get(TYPE, {})
        self.finding("documentation_schema_contradiction", {
            "documentation_property": "FunctionResourceArn",
            "registry_properties": sorted(schema.get("properties", {})),
            "registry_primary_identifier": schema.get("primaryIdentifier"),
            "boundary": "Template syntax/property documentation says FunctionResourceArn; native registry and documentation example use ResourceArn."})

    def stack(self, key, label, template, update=False):
        result = VersionProbe.stack(self, key, label, template, update)
        owned = self.data["owned"]["stacks"][key]
        if owned.get("id") and result.get("stack_status") not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            self.call(label + "-validation-details", "cloudformation", "describe_events",
                      {"StackName": owned["id"]}, required=False)
        return result

    def resource_template(self, kind, properties):
        outputs = {"ResourceRef": {"Value": {"Ref": "Resource"}}}
        for pointer in self.data["schemas"].get(kind, {}).get("readOnlyProperties", []):
            if pointer.count("/") == 2:
                name = pointer.split("/")[-1]
                outputs["Attribute" + name] = {"Value": {"Fn::GetAtt": ["Resource", name]}}
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
            "Resource": {"Type": kind, "Properties": properties}}, "Outputs": outputs}

    def policy(self, label, arn, layer=False):
        if layer:
            name, version = arn.rsplit(":", 1)
            request = {"LayerName": name, "VersionNumber": int(version)}
            operation = "get_layer_version_policy"
        else:
            self.assert_function_arn(arn)
            request, operation = {"ResourceArn": arn}, "get_resource_policy"
        result = self.call(label, "lambda", operation, request, required=False)
        return {"code": self.code(), **result,
                **({"document": json.loads(result["Policy"])} if result.get("Policy") else {})}

    def assert_function_arn(self, arn):
        base = self.data["owned"]["function"]["arn"]
        allowed = [base] + [base + ":" + v for v in self.data["owned"]["function"]["versions"]]
        allowed += [base + ":" + alias for alias in self.data["owned"]["aliases"]]
        if arn not in allowed:
            raise RuntimeError("Function ARN lacks exact-created inventory")

    def stale_permission(self, changed=False, layer=False):
        label = ("layer" if layer else "function") + ("-changed" if changed else "-identical")
        if layer:
            name = self.reserve_layer(label)
            result = self.call(label + "-publish", "lambda", "publish_layer_version", {
                "LayerName": name, "Description": self.data["prefix"],
                "Content": {"ZipFile": archive_bytes("python/probe.py", "VALUE = 1\n")}})
            arn = result["LayerVersionArn"]
            self.remember_layer(arn)
            request = {"LayerName": name, "VersionNumber": result["Version"]}
            kind, action, field = "AWS::Lambda::LayerVersionPermission", "lambda:GetLayerVersion", "LayerVersionArn"
            remove, add = "remove_layer_version_permission", "add_layer_version_permission"
        else:
            arn = self.data["owned"]["function"]["arn"]
            request = {"FunctionName": arn}
            kind, action, field = "AWS::Lambda::Permission", "lambda:InvokeFunction", "FunctionName"
            remove, add = "remove_permission", "add_permission"
        template = self.resource_template(kind, {field: arn, "Action": action, "Principal": self.account})
        created = self.stack(label, label + "-create", template)
        if created.get("stack_status") != "CREATE_COMPLETE":
            raise RuntimeError(label + " permission creation failed")
        before = self.policy(label + "-before", arn, layer)
        statements = before["document"]["Statement"]
        if len(statements) != 1:
            raise RuntimeError("Expected exactly one exact-created statement")
        sid = statements[0]["Sid"]
        self.data["owned"]["statements"].append({"arn": arn, "sid": sid, "stack": label})
        self.save()
        self.call(label + "-native-remove", "lambda", remove, {**request, "StatementId": sid})
        grant = {**request, "StatementId": sid, "Action": action, "Principal": self.account}
        if changed:
            if layer:
                # Root is normalized by Lambda; layer statement's only other mutable
                # grant field is OrganizationId, intentionally outside this probe.
                raise RuntimeError("Changed layer statement is outside authorized probe")
            grant["SourceAccount"] = self.account
        self.call(label + "-native-readd", "lambda", add, grant)
        replacement = self.policy(label + "-replacement", arn, layer)
        status = self.delete_stack(label, label + "-delete")
        after = self.policy(label + "-after-delete", arn, layer)
        self.finding(label + "-stale-delete", {"before": before, "replacement": replacement,
            "replacement_statement_equal": before["document"]["Statement"] == replacement["document"]["Statement"],
            "delete_status": status, "after": after,
            "replacement_survives": any(item.get("Sid") == sid for item in after.get("document", {}).get("Statement", []))})

    def policy_document(self, arn, *sids):
        self.assert_function_arn(arn)
        return {"Version": "2012-10-17", "Statement": [{"Sid": sid, "Effect": "Allow",
            "Principal": {"AWS": self.root}, "Action": "lambda:InvokeFunction", "Resource": arn} for sid in sids]}

    def policy_stack(self, label, arn, sids, update=False, *, key="policy", allow_failure=False):
        schema = self.data["schemas"][TYPE]
        properties = schema["properties"]
        arn_fields = [name for name in properties if name.endswith("Arn") and name not in
                      [path.split("/")[-1] for path in schema.get("readOnlyProperties", [])]]
        if len(arn_fields) != 1:
            raise RuntimeError("Cannot derive canonical ARN property from native schema")
        self.finding("canonical_arn_property", arn_fields[0])
        template = self.resource_template(TYPE, {arn_fields[0]: arn, "PolicyDocument": self.policy_document(arn, *sids)})
        result = self.stack(key, label, template, update)
        self.finding(label + "-policy", self.policy(label + "-read", arn))
        if not allow_failure and result.get("stack_status") not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            raise RuntimeError(label + " failed")
        return result

    def workflow(self):
        self.documents()
        VersionProbe.setup(self)
        function = self.data["owned"]["function"]
        log_name = "/aws/lambda/" + function["name"]
        logs = self.call("log-name-absent", "logs", "describe_log_groups", {"logGroupNamePrefix": log_name})
        if any(item["logGroupName"] == log_name for item in logs.get("logGroups", [])):
            raise RuntimeError("Unexpected existing function log group")
        self.data["owned"]["log_group"] = {"name": log_name, "absence_verified": True}
        self.save()
        if not self.args.policy_only:
            self.stale_permission()
            self.stale_permission(changed=True)
            self.stale_permission(layer=True)
        if TYPE not in self.data["schemas"]:
            raise RuntimeError("Native ResourcePolicy schema unavailable")
        arn = function["arn"]
        if not self.args.policy_only:
            self.call("preexisting-owned-policy", "lambda", "put_resource_policy", {
                "ResourceArn": arn, "Policy": json.dumps(self.policy_document(arn, "PreexistingOwned"))})
            self.policy_stack("policy-existing-create", arn, ["First"], key="conflict", allow_failure=True)
            self.delete_stack("conflict", "policy-existing-delete-stack")
            self.call("policy-existing-delete-native", "lambda", "delete_resource_policy", {"ResourceArn": arn}, required=False)
        self.policy_stack("policy-create", arn, ["First"])
        self.call("policy-native-extra", "lambda", "add_permission", {
            "FunctionName": arn, "StatementId": "NativeExtra", "Action": "lambda:InvokeFunction", "Principal": self.account})
        self.finding("policy-before-update", self.policy("policy-before-update-read", arn))
        self.policy_stack("policy-full-update", arn, ["Second", "Third"], update=True)
        published = self.call("publish-owned-version", "lambda", "publish_version", {"FunctionName": arn})
        function["versions"].append(published["Version"])
        self.save()
        version_arn = published["FunctionArn"]
        self.policy_stack("policy-version-replacement", version_arn, ["VersionGrant"], update=True)
        self.finding("policy-old-base-after-replacement", self.policy("policy-old-base-read", arn))
        alias = "owned"
        self.data["owned"]["aliases"].append(alias)
        self.save()
        alias_result = self.call("create-owned-alias", "lambda", "create_alias", {
            "FunctionName": arn, "Name": alias, "FunctionVersion": published["Version"]})
        alias_arn = alias_result["AliasArn"]
        self.policy_stack("policy-alias-replacement", alias_arn, ["AliasGrant"], update=True)
        self.finding("policy-old-version-after-replacement", self.policy("policy-old-version-read", version_arn))
        overwritten = self.policy_document(alias_arn, "NativeOverwrite")
        self.call("policy-native-overwrite", "lambda", "put_resource_policy", {
            "ResourceArn": alias_arn, "Policy": json.dumps(overwritten)})
        self.finding("policy-overwrite-before-delete", self.policy("policy-overwrite-read", alias_arn))
        status = self.delete_stack("policy", "policy-delete-overwrite")
        self.finding("policy-overwrite-delete", {"delete_status": status,
            "after": self.policy("policy-after-delete", alias_arn)})
        self.policy_stack("policy-normal-create", arn, ["Normal"])
        status = self.delete_stack("policy", "policy-normal-delete")
        self.finding("policy-normal-delete", {"delete_status": status,
            "after": self.policy("policy-normal-after-delete", arn)})
        self.data["workflow_complete"] = True
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/function_resource_policy.json"))
    parser.add_argument("--schema-output", type=Path)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--policy-only", action="store_true", help="Skip previously captured stale-Sid and existing-policy scenarios")
    args = parser.parse_args()
    probe = ResourcePolicyProbe(args)

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
