#!/usr/bin/env python3
"""Capture AWS role templates and probe acquisition with owned temporary roles.

Does not enable Role Manager or change account-wide settings. Every created role
uses this run's unique prefix and is removed with its policy attachments.
"""

import argparse
import datetime
import json
import pathlib
import re
import uuid

from aws_cli import call


TEMPLATES = {
    "power": "iam.amazonaws.com/PowerUserRoleTemplate",
    "backup": "backup.amazonaws.com/AWSBackupDefaultServiceRoleTemplate",
    "studio_admin": "datazone.amazonaws.com/AmazonSageMakerAdminIAMPermissiveExecutionRoleTemplate",
    "studio_user": "datazone.amazonaws.com/AmazonSageMakerUserIAMPermissiveExecutionRoleTemplate",
    "rotation": "secretsmanager.amazonaws.com/AWSSecretsManagerRotationRoleTemplate",
    "scheduled_query": "logs.amazonaws.com/AmazonCloudWatchLogsScheduledQueryExecutionRoleTemplate",
    "metric_stream": "streams.metrics.cloudwatch.amazonaws.com/AmazonCloudWatchMetricStreamsFirehosePutRecordsRoleTemplate",
    "firehose": "firehose.amazonaws.com/AmazonCloudWatchMetricStreamsFirehoseToS3RoleTemplate",
    "rum": "rum.amazonaws.com/AmazonCloudWatchRUMPutEventsRoleTemplate",
    "synthetics": "synthetics.amazonaws.com/AmazonCloudWatchSyntheticsExecutionRoleTemplate",
    "synthetics_kms": "synthetics.amazonaws.com/AmazonCloudWatchSyntheticsKmsExecutionRoleTemplate",
    "synthetics_vpc": "synthetics.amazonaws.com/AmazonCloudWatchSyntheticsVpcExecutionRoleTemplate",
}


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue-only", action="store_true", help="Read published templates without creating roles")
    parser.add_argument("--account", required=True)
    options = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    owner = require_account(options.account)["Account"]
    prefix = "stackd-template-" + uuid.uuid4().hex[:12]
    names = set()
    observations = {}
    captured = []

    def observe(label, operation, parameters=None):
        try:
            result = call("iam", operation, parameters)
            observations[label] = {"result": result}
            print(label + ": success", flush=True)
            return result
        except RuntimeError as error:
            message = str(error)
            code = re.search(r"\(([^)]+)\) when calling", message)
            if code is None:
                raise
            observations[label] = {"error": {"code": code[1], "message": message}}
            print(label + ": " + code[1], flush=True)
            return None

    def acquire(label, kind, values, suffix=None, minor=None):
        name = prefix + "-" + (suffix or label)
        names.add(name)
        replacements = {key: {"Values": value if isinstance(value, list) else [value]} for key, value in values.items()}
        replacements["RoleName"] = {"Values": [name]}
        parameters = {"TemplateArn": "arn:aws:iam::aws:role-template/" + TEMPLATES[kind] + ":1", "ReplacementValues": replacements}
        if minor is not None:
            parameters["TemplateMinorVersion"] = minor
        return observe(label, "acquire-role", parameters)

    def inspect(label, name):
        role = call("iam", "get-role", {"RoleName": name})["Role"]
        attached = call("iam", "list-attached-role-policies", {"RoleName": name})["AttachedPolicies"]
        inline = {}
        for policy in call("iam", "list-role-policies", {"RoleName": name})["PolicyNames"]:
            inline[policy] = call("iam", "get-role-policy", {"RoleName": name, "PolicyName": policy})["PolicyDocument"]
        observations[label] = {"role": role, "attached": attached, "inline": inline}

    try:
        observe("account_properties", "get-account-properties")
        for kind, name in TEMPLATES.items():
            arn = "arn:aws:iam::aws:role-template/" + name + ":1"
            response = observe("template_" + kind, "get-role-template-version", {"TemplateArn": arn})
            if response:
                captured.append(response["RoleTemplateVersion"])
        if options.catalogue_only:
            write_capture(root, owner, prefix, observations, captured, "role_template_catalogue.json")
            return
        power = {"AWSServiceName": "lambda.amazonaws.com"}
        first = acquire("create", "power", power, suffix="power")
        if first is None:
            raise RuntimeError("The baseline role acquisition failed")
        acquire("reuse", "power", power, suffix="power")
        inspect("created_role", prefix + "-power")
        call("iam", "update-role-description", {"RoleName": prefix + "-power", "Description": "customer description"})
        acquire("description_changed", "power", power, suffix="power")
        call("iam", "attach-role-policy", {"RoleName": prefix + "-power", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"})
        acquire("extra_attachment", "power", power, suffix="power")
        call("iam", "detach-role-policy", {"RoleName": prefix + "-power", "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"})
        acquire("required_attachment_removed", "power", power, suffix="power")
        acquire("missing_required", "power", {})
        acquire("multiple_string_values", "power", {"AWSServiceName": ["lambda.amazonaws.com", "ec2.amazonaws.com"]})
        acquire("extra_parameter", "power", {**power, "Unused": "ignored"})
        acquire("invalid_service", "power", {"AWSServiceName": "not-a-service"})
        acquire("unknown_minor", "power", power, minor=999)
        acquire("negative_minor", "power", power, minor=-1)
        backup = acquire("backup", "backup", {"accountId": owner})
        if backup:
            inspect("backup_role", prefix + "-backup")
        rotation = {"accountId": owner, "region": "us-east-1", "resourceType": "probe"}
        acquire("rotation_inactive_missing", "rotation", rotation)
        rotation.update(adminType="admin-probe", kmsKeyArn=[f"arn:aws:kms:us-east-1:{owner}:key/11111111-1111-1111-1111-111111111111", f"arn:aws:kms:us-east-1:{owner}:key/22222222-2222-2222-2222-222222222222"])
        if acquire("rotation_disabled", "rotation", rotation):
            inspect("rotation_disabled_role", prefix + "-rotation_disabled")
        if acquire("rotation_enabled", "rotation", {**rotation, "ADMIN_RESOURCE_ENABLED": "True", "CMK_ENABLED": "True"}):
            inspect("rotation_enabled_role", prefix + "-rotation_enabled")
        if acquire("rotation_lowercase", "rotation", {**rotation, "ADMIN_RESOURCE_ENABLED": "true", "CMK_ENABLED": "true"}):
            inspect("rotation_lowercase_role", prefix + "-rotation_lowercase")
        admin = {"accountId": owner, "keyAccountId": owner, "keyRegion": "us-east-1", "kmsKeyId": "11111111-1111-1111-1111-111111111111"}
        if acquire("studio_admin_disabled", "studio_admin", admin):
            inspect("studio_admin_disabled_role", prefix + "-studio_admin_disabled")
        if acquire("studio_admin_enabled", "studio_admin", {**admin, "CMK_ENABLED": "True"}):
            inspect("studio_admin_enabled_role", prefix + "-studio_admin_enabled")
        if acquire("studio_user", "studio_user", {"accountId": owner}):
            inspect("studio_user_role", prefix + "-studio_user")
    finally:
        for name in sorted(names):
            try:
                attached = call("iam", "list-attached-role-policies", {"RoleName": name})["AttachedPolicies"]
            except RuntimeError as error:
                if "NoSuchEntity" in str(error):
                    continue
                raise
            for policy in attached:
                call("iam", "detach-role-policy", {"RoleName": name, "PolicyArn": policy["PolicyArn"]})
            for policy in call("iam", "list-role-policies", {"RoleName": name})["PolicyNames"]:
                call("iam", "delete-role-policy", {"RoleName": name, "PolicyName": policy})
            call("iam", "delete-role", {"RoleName": name})
        if names:
            remaining = call("iam", "list-roles")["Roles"]
            if any(role["RoleName"].startswith(prefix) for role in remaining):
                raise RuntimeError("An owned probe role remains after cleanup")
            print("Owned roles removed", flush=True)
    write_capture(root, owner, prefix, observations, captured, "role_templates.json")


def write_capture(root, owner, prefix, observations, captured, fixture_name):
    observed = datetime.datetime.now(datetime.timezone.utc).isoformat()
    fixture = {"observed_at": observed, "source": "AWS IAM role-template APIs with owned commercial-account roles; account properties read without modification", "observations": observations, "cleanup": "All owned roles and attachments removed; account settings unchanged."}
    if fixture_name == "role_template_catalogue.json":
        fixture["source"] = "AWS IAM GetRoleTemplateVersion and GetAccountProperties in a commercial account; read-only capture"
        fixture["cleanup"] = "No resources created or settings changed."
    text = json.dumps(fixture, indent=2).replace(owner, "111111111111").replace(prefix, "OWNED_ROLE")
    (root / '.stackd/probes/iam' / fixture_name).parent.mkdir(parents=True, exist_ok=True)
    (root / '.stackd/probes/iam' / fixture_name).write_text(text + "\n")
    destination = root / "internal/iam/roletemplates/data/aws.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Restore policy strings to the generated API type. The behavior fixture
    # retains the CLI's decoded policy trees for semantic comparisons.
    for template in captured:
        template["AssumeRolePolicyDocumentTemplate"] = json.dumps(template["AssumeRolePolicyDocumentTemplate"], separators=(",", ":"))
        for policy in template.get("InlinePolicyTemplates", []):
            policy["PolicyDocument"] = json.dumps(policy["PolicyDocument"], separators=(",", ":"))
    destination.write_text(json.dumps({"observed_at": observed, "source": "AWS IAM GetRoleTemplateVersion; template ARNs from the IAM User Guide role template directory", "templates": captured}, indent=2) + "\n")
    print("Wrote role-template catalogue and behavior fixture", flush=True)


if __name__ == "__main__":
    main()
