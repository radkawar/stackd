#!/usr/bin/env python3
"""Capture owned Lambda architecture transitions and executable version identity."""
import argparse
import base64
import datetime
import io
import json
import os
import pathlib
import secrets
import tempfile
import time
import zipfile

from aws_cli import observe, result, run


HANDLER = '''import platform

def invoke(event, context):
    return {"machine": platform.machine(), "version": context.function_version,
            "invoked_arn": context.invoked_function_arn, "event": event}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/lambda/architectures.json"))
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION=args.region, AWS_DEFAULT_REGION=args.region, AWS_MAX_ATTEMPTS="2")
    prefix = "stackd-lambda-arch-" + secrets.token_hex(6)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(zipfile.ZipInfo("entry.py", (2026, 1, 1, 0, 0, 0)), HANDLER)
    encoded = base64.b64encode(archive.getvalue()).decode()
    capture = {
        "source": "Native AWS Lambda HTTPS calls through the shared AWS CLI transport",
        "region": args.region, "prefix": prefix,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "documentation": [
            "https://docs.aws.amazon.com/lambda/latest/dg/foundation-arch.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html",
            "https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html",
        ],
        "artifact": {"source_utf8": HANDLER, "zip_base64": encoded},
        "observations": [], "cleanup": [],
    }

    def record(label, service, operation, parameters, cleanup=False):
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        observed = observe(service, operation, parameters, env)
        capture["cleanup" if cleanup else "observations"].append({
            "label": label, "service": service, "operation": operation,
            "input": parameters, "started_at": started, "result": observed,
        })
        print(label + ": " + observed["code"], flush=True)
        return observed

    def require(observed):
        if observed["code"] != "Success":
            raise RuntimeError(json.dumps(observed))
        return observed["output"]

    def ready(name, label):
        for attempt in range(60):
            output = require(record(label + "_" + str(attempt), "lambda", "get-function-configuration", {"FunctionName": name}))
            if output["State"] == "Active" and output.get("LastUpdateStatus", "Successful") == "Successful":
                return
            if output["State"] == "Failed" or output.get("LastUpdateStatus") == "Failed":
                raise RuntimeError("Lambda deployment failed: " + json.dumps(output))
            time.sleep(2)
        raise RuntimeError("Lambda deployment did not settle in 120 seconds")

    def invoke(name, qualifier, label, directory):
        parameters = {"FunctionName": name, "Payload": json.dumps({"case": label})}
        if qualifier:
            parameters["Qualifier"] = qualifier
        output_file = directory / (label + ".json")
        options = ["--function-name", name, "--payload", parameters["Payload"],
                   "--cli-binary-format", "raw-in-base64-out", str(output_file)]
        if qualifier:
            options += ["--qualifier", qualifier]
        observed = result(run("lambda", "invoke", env=env, options=options, timeout=40),
                          cli_message=None)
        if observed["code"] == "Success":
            payload = output_file.read_bytes()
            observed["payload_base64"] = base64.b64encode(payload).decode()
            observed["output"]["Payload"] = json.loads(payload)
        capture["observations"].append({"label": label, "service": "lambda", "operation": "invoke", "input": parameters, "result": observed})
        output = require(observed)
        if "FunctionError" in output:
            raise RuntimeError("Native handler failed: " + json.dumps(output))
        print(label + ": " + json.dumps(output["Payload"]), flush=True)

    functions = []
    role_created = False
    policy_created = False
    identity = require(record("identity", "sts", "get-caller-identity", {}))
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside the selected account")
    capture["account"] = identity["Account"]
    role_name = prefix + "-role"
    name, explicit = prefix + "-default", prefix + "-arm"
    try:
        role = require(record("create_role", "iam", "create-role", {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
        }))["Role"]["Arn"]
        role_created = True
        require(record("put_logs_policy", "iam", "put-role-policy", {
            "RoleName": role_name, "PolicyName": "owned-logs",
            "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": [f"arn:aws:logs:{args.region}:{identity['Account']}:log-group:/aws/lambda/{function}:*" for function in (name, explicit)]}]}),
        }))
        policy_created = True
        for function, architecture in ((name, None), (explicit, "arm64")):
            parameters = {"FunctionName": function, "Role": role, "Runtime": "python3.12", "Handler": "entry.invoke", "Code": {"ZipFile": encoded}, "Timeout": 10, "MemorySize": 128}
            if architecture:
                parameters["Architectures"] = [architecture]
            functions.append(function)
            for attempt in range(20):
                observed = record(("create_default" if architecture is None else "create_arm") + "_" + str(attempt), "lambda", "create-function", parameters)
                if observed["code"] == "Success":
                    break
                if observed["code"] != "InvalidParameterValueException" or "cannot be assumed" not in json.dumps(observed):
                    require(observed)
                time.sleep(3)
            else:
                raise RuntimeError("Execution role trust did not propagate in 60 seconds")
            ready(function, "ready_" + ("default" if architecture is None else "explicit_arm"))
        with tempfile.TemporaryDirectory(prefix=prefix) as temp:
            directory = pathlib.Path(temp)
            invoke(name, "", "invoke_default", directory)
            invoke(explicit, "", "invoke_explicit_arm", directory)
            first = require(record("publish_x86", "lambda", "publish-version", {"FunctionName": name}))["Version"]
            require(record("migrate_arm", "lambda", "update-function-code", {"FunctionName": name, "ZipFile": encoded, "Architectures": ["arm64"]}))
            ready(name, "ready_migrated_arm")
            second = require(record("publish_arm", "lambda", "publish-version", {"FunctionName": name}))["Version"]
            invoke(name, "", "invoke_migrated_arm", directory)
            record("architecture_only_update", "lambda", "update-function-code", {"FunctionName": name, "Architectures": ["x86_64"]})
            ready(name, "after_architecture_only")
            require(record("migrate_back_x86", "lambda", "update-function-code", {"FunctionName": name, "ZipFile": encoded, "Architectures": ["x86_64"]}))
            ready(name, "ready_migrated_back")
            invoke(name, "", "invoke_migrated_back", directory)
            require(record("list_retained_versions", "lambda", "list-versions-by-function", {"FunctionName": name}))
            for version, architecture in ((first, "x86"), (second, "arm")):
                require(record("retained_" + architecture, "lambda", "get-function-configuration", {"FunctionName": name, "Qualifier": version}))
                invoke(name, version, "invoke_retained_" + architecture, directory)
            require(record("create_alias_x86", "lambda", "create-alias", {"FunctionName": name, "Name": "selected", "FunctionVersion": first}))
            invoke(name, "selected", "invoke_alias_x86", directory)
            require(record("retarget_alias_arm", "lambda", "update-alias", {"FunctionName": name, "Name": "selected", "FunctionVersion": second}))
            invoke(name, "selected", "invoke_alias_arm", directory)
            require(record("retarget_alias_x86", "lambda", "update-alias", {"FunctionName": name, "Name": "selected", "FunctionVersion": first}))
            invoke(name, "selected", "invoke_alias_back_x86", directory)
        capture["workflow_complete"] = True
    finally:
        cleanup_errors = []
        def clean(label, service, operation, parameters, allowed=("Success",)):
            try:
                observed = record(label, service, operation, parameters, cleanup=True)
                if observed["code"] not in allowed:
                    cleanup_errors.append(observed)
                return observed
            except Exception as error:
                cleanup_errors.append(str(error))
                return None
        for function in functions:
            clean("delete_" + function, "lambda", "delete-function", {"FunctionName": function}, ("Success", "ResourceNotFoundException"))
            clean("absent_" + function, "lambda", "get-function-configuration", {"FunctionName": function}, ("ResourceNotFoundException",))
            clean("delete_logs_" + function, "logs", "delete-log-group", {"logGroupName": "/aws/lambda/" + function}, ("Success", "ResourceNotFoundException"))
            checked = clean("absent_logs_" + function, "logs", "describe-log-groups", {"logGroupNamePrefix": "/aws/lambda/" + function})
            if checked and checked.get("output", {}).get("logGroups"):
                cleanup_errors.append("Log group remains for " + function)
        if policy_created:
            clean("delete_logs_policy", "iam", "delete-role-policy", {"RoleName": role_name, "PolicyName": "owned-logs"})
        if role_created:
            clean("delete_role", "iam", "delete-role", {"RoleName": role_name})
            clean("absent_role", "iam", "get-role", {"RoleName": role_name}, ("NoSuchEntity",))
        capture["cleanup_verified"] = not cleanup_errors
        capture["cleanup_errors"] = cleanup_errors
        capture["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")
        if cleanup_errors:
            raise RuntimeError("Owned AWS resource cleanup failed: " + json.dumps(cleanup_errors))


if __name__ == "__main__":
    main()
