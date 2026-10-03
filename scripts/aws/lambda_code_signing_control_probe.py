#!/usr/bin/env python3
"""Probe signed ZIP admission and CSC controls using exact-owned resources."""
import argparse
import base64
import io
import json
from pathlib import Path
import time
import uuid
import zipfile
import boto3
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    captured = json.loads(Path(args.fixture).read_text())
    session = boto3.Session(region_name="us-east-1")
    if session.client("sts").get_caller_identity()["Account"] != args.account:
        raise RuntimeError("Unauthorized account")
    iam, lam, logs = (session.client(x) for x in ("iam", "lambda", "logs"))
    name = "stackd-next-lambda-signing-" + uuid.uuid4().hex[:12]
    result = {"name": name, "cases": [], "cleanup": []}
    config = role = None
    function_created = False
    layers = []

    def call(label, client, operation, **kwargs):
        try:
            out = getattr(client, operation)(**kwargs)
            result["cases"].append({"label": label, "operation": operation, "requestId": out.get("ResponseMetadata", {}).get("RequestId"), "output": {k: v for k, v in out.items() if k not in ("ResponseMetadata", "Payload")}})
            content = result["cases"][-1]["output"].get("Content")
            if isinstance(content, dict):
                content.pop("Location", None)
            if "Payload" in out:
                result["cases"][-1]["payload"] = out["Payload"].read().decode()
            return out
        except ClientError as e:
            result["cases"].append({"label": label, "operation": operation, "requestId": e.response.get("ResponseMetadata", {}).get("RequestId"), "error": e.response["Error"]})
            return None

    def settle():
        lam.get_waiter("function_updated_v2").wait(FunctionName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    try:
        config = call("create-enforce", lam, "create_code_signing_config", AllowedPublishers={"SigningProfileVersionArns": [captured["profileVersionArn"]]}, CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"}, Tags={"stackd-probe": name})["CodeSigningConfig"]["CodeSigningConfigArn"]
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        time.sleep(10)
        signed = base64.b64decode(captured["signedZipBase64"])
        unsigned = base64.b64decode(captured["unsignedZipBase64"])
        created = call("create-signed", lam, "create_function", FunctionName=name, Runtime="python3.12", Handler="handler.handler", Role=role, Code={"ZipFile": signed}, CodeSigningConfigArn=config)
        if created is None:
            raise RuntimeError("Native signed function failed; inspect fixture")
        function_created = True
        lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 60})
        call("invoke-signed", lam, "invoke", FunctionName=name, Payload=b"{}")
        call("get-attachment", lam, "get_function_code_signing_config", FunctionName=name)
        call("list-functions", lam, "list_functions_by_code_signing_config", CodeSigningConfigArn=config, MaxItems=1)
        call("delete-in-use", lam, "delete_code_signing_config", CodeSigningConfigArn=config)
        call("unsigned-enforce", lam, "update_function_code", FunctionName=name, ZipFile=unsigned)
        original = zipfile.ZipFile(io.BytesIO(signed))
        cases = {}
        for label in ("recompressed", "retimed", "renamed", "tampered", "reordered"):
            target = io.BytesIO()
            with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as z:
                entries = original.infolist()
                if label == "reordered": entries = entries[::-1]
                for entry in entries:
                    data = original.read(entry)
                    filename = entry.filename
                    if label == "renamed" and filename == "handler.py": filename = "other.py"
                    if label == "tampered" and filename == "handler.py": data += b"# changed\n"
                    info = zipfile.ZipInfo(filename, (2020, 1, 1, 0, 0, 0) if label == "retimed" else entry.date_time)
                    z.writestr(info, data)
            cases[label] = target.getvalue()
        for label, code in cases.items():
            if call(label+"-enforce", lam, "update_function_code", FunctionName=name, ZipFile=code): settle()
        call("warn", lam, "update_code_signing_config", CodeSigningConfigArn=config, CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"})
        if call("unsigned-warn", lam, "update_function_code", FunctionName=name, ZipFile=unsigned): settle()
        call("tampered-warn", lam, "update_function_code", FunctionName=name, ZipFile=cases["tampered"])
        for label, code in (("unsigned", unsigned), ("signed", signed), ("tampered", cases["tampered"])):
            out = call("publish-layer-"+label, lam, "publish_layer_version", LayerName=name, Content={"ZipFile": code})
            if out: layers.append(out["Version"])
        call("list-tags", lam, "list_tags", Resource=config)
        call("detach", lam, "delete_function_code_signing_config", FunctionName=name)
        call("get-detached", lam, "get_function_code_signing_config", FunctionName=name)
    finally:
        if function_created:
            lam.delete_function(FunctionName=name)
            result["cleanup"].append("function-deleted")
        for version in layers:
            lam.delete_layer_version(LayerName=name, VersionNumber=version)
            result["cleanup"].append("layer-"+str(version)+"-deleted")
        if config:
            lam.delete_code_signing_config(CodeSigningConfigArn=config)
            result["cleanup"].append("config-deleted")
        if role:
            iam.delete_role(RoleName=name)
            result["cleanup"].append("role-deleted")
        try:
            logs.delete_log_group(logGroupName="/aws/lambda/"+name)
            result["cleanup"].append("log-group-deleted")
        except logs.exceptions.ResourceNotFoundException:
            result["cleanup"].append("log-group-absent")
        Path(args.output).write_text(json.dumps(result, indent=2, default=str)+"\n")
        print(json.dumps({"output": args.output, "cleanup": result["cleanup"], "cases": [{"label": c["label"], "error": c.get("error")} for c in result["cases"]]}))


if __name__ == "__main__": main()
