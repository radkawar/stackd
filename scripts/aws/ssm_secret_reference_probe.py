#!/usr/bin/env python3
"""Capture synthetic SSM Secrets Manager references, including raw wire responses.

Native: env PYTHONPATH=scripts/aws python3 -B -P scripts/aws/ssm_secret_reference_probe.py --account ACCOUNT_ID --output .stackd/probes/ssm/secret_references.json
Local: same command with --account LOCAL_ACCOUNT_ID --endpoint http://127.0.0.1:4566 --output /tmp/secret-references-local.json
Local mode repeats the owned-resource scenarios using test credentials; it does
not claim automatic differential comparison. Native credentials never go local.
Local setup omits explicit KmsKeyId on the first CreateSecret to initialize the
same real managed default key owner; native requests retain the explicit alias.
Use --selector-edges-only for the independent compact-version/stage ambiguity probe.
Use --stage-conditions-only for owned-role PutSecretValue condition-key evidence.
Use --validation-authority-only for malformed secret-write admission precedence.
Use --missing-authorization-only for absent-secret resource authorization evidence.
Only three synthetic secrets, one standard parameter and one role can be created.
No customer KMS key, standing policy, service setting or existing secret is changed.
"""
import argparse
import ast
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlparse
import uuid

import aws_cli
from signed_requests import signed_post

REGION = "us-east-1"
REFERENCE = "/aws/reference/secretsmanager/"
REFERENCES = [
    "https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
    "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html",
    "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameters.html",
    "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html",
    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html",
    "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html",
    "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_secretsmanager.html",
]
CREDENTIAL_FIELDS = {"accesskeyid", "secretaccesskey", "sessiontoken", "securitytoken", "authorization", "signature"}


def now():
    return datetime.now(timezone.utc).isoformat()


def sanitize(value):
    if isinstance(value, dict):
        return {key: "<redacted>" if key.lower().replace("-", "") in CREDENTIAL_FIELDS else sanitize(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "<redacted-access-key>", value)
    return value


def require(result):
    if result["code"] != "Success":
        raise RuntimeError("Required request failed: " + json.dumps(sanitize(result)))
    return result["output"]


class Probe:
    def __init__(self, args):
        self.args = args
        self.path = Path(args.output)
        if self.path.exists():
            raise ValueError("Refusing to overwrite evidence: " + str(self.path))
        self.env = dict(os.environ, AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION,
                        AWS_MAX_ATTEMPTS="1", AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off",
                        AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
        if args.endpoint:
            if urlparse(args.endpoint).hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("Local endpoint must be loopback")
            for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
                self.env.pop(key, None)
            self.env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_EC2_METADATA_DISABLED="true")
        self.prefix = "stackd-ssm-secret-" + uuid.uuid4().hex[:16]
        self.secrets = []
        self.parameter = None
        self.role = None
        self.phase = "setup"
        self.data = {
            "schema_version": 1, "captured_at": now(), "endpoint": args.endpoint or "native AWS",
            "region": REGION, "prefix": self.prefix, "calls": [], "ownership": [], "constraints": [],
            "cleanup": {"confirmed": False, "remaining": [], "errors": []},
            "sources": {"references": REFERENCES,
                        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
            "safety": {"account_required": self.args.account, "region_required": REGION,
                       "fixture_values_only": True, "max_owned_secrets": 3, "max_owned_parameters": 1,
                       "max_owned_roles": 1, "kms_key": "alias/aws/secretsmanager (no key mutations)",
                       "standing_settings_mutated": False, "credentials_retained": False},
            "evidence_boundary": "Raw SSM/Secrets Manager JSON and request IDs are retained. All values are public synthetic fixtures. No CloudTrail absence claim. IAM unavailability is captured, never inferred as reference behavior.",
        }
        if args.endpoint:
            self.data["local_setup_adaptations"] = [
                "First owned CreateSecret omits explicit KmsKeyId to initialize the real default managed alias."]
        self.save()

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(sanitize(self.data), indent=2, sort_keys=True) + "\n")

    def call(self, label, service, operation, request, env=None):
        row = {"label": label, "phase": self.phase, "at": now(), "service": service,
               "operation": operation, "request": request}
        self.data["calls"].append(row)
        self.save()
        environment = self.env if env is None else env
        try:
            if service in ("ssm", "secretsmanager"):
                target = ("AmazonSSM." if service == "ssm" else "secretsmanager.") + operation
                if self.args.endpoint:
                    auth = environment["AWS_ACCESS_KEY_ID"] + ":" + environment["AWS_SECRET_ACCESS_KEY"]
                    command = ["curl", "--silent", "--show-error", "--include", "--connect-timeout", "10", "--max-time", "30",
                               "--aws-sigv4", "aws:amz:" + REGION + ":" + service, "--user", auth,
                               "--header", "content-type: application/x-amz-json-1.1", "--header", "x-amz-target: " + target]
                    if environment.get("AWS_SESSION_TOKEN"):
                        command += ["--header", "x-amz-security-token: " + environment["AWS_SESSION_TOKEN"]]
                    command += ["--data-binary", json.dumps(request), self.args.endpoint]
                    process = subprocess.run(command, capture_output=True, text=True, env=environment, timeout=35)
                    if process.returncode:
                        raise RuntimeError("Local HTTP transport failed; diagnostics discarded")
                    headers, separator, body = process.stdout.partition("\n\n")
                    if not separator:
                        raise RuntimeError("Missing HTTP response header boundary")
                    status = int(headers.splitlines()[0].split()[1])
                    request_id = next((line.split(":", 1)[1].strip() for line in headers.splitlines()[1:]
                                      if line.lower().startswith(("x-amzn-requestid:", "x-amzn-request-id:", "x-amz-request-id:"))), None)
                else:
                    response = signed_post(service + "." + REGION + ".amazonaws.com", service,
                                           json.dumps(request).encode(), {"content-type": "application/x-amz-json-1.1", "x-amz-target": target}, environment)
                    status, request_id, body = response.status, response.request_id, response.body.decode("utf-8")
                row["raw_response"] = {"status": status, "request_id": request_id, "body": body}
                output = json.loads(body)
                result = {"code": "Success", "output": output} if 200 <= status < 300 else {
                    "code": output["__type"].split("#")[-1], "error": output}
                result.update(http_status=status, request_id=request_id)
            else:
                options = ["--debug", "--region", REGION, "--no-paginate", "--cli-connect-timeout", "10", "--cli-read-timeout", "30"]
                if self.args.endpoint:
                    options += ["--endpoint-url", self.args.endpoint]
                process = aws_cli.run(service, operation, request, environment, options=options, timeout=50)
                result = aws_cli.result(process, debug=True)
                for line in process.stderr.splitlines():
                    if "Response headers:" in line:
                        headers = ast.literal_eval(line.split("Response headers:", 1)[1].strip())
                        for key, value in headers.items():
                            if key.lower() in ("x-amzn-requestid", "x-amzn-request-id", "x-amz-request-id"):
                                result["request_id"] = value
                raw = aws_cli.raw_xml(process)
                if raw is not None:
                    match = re.search(rb"<(?:\w+:)?RequestId>([^<]+)</", raw)
                    if match:
                        result["request_id"] = match[1].decode()
                if result["code"] == "CLIError":
                    raise RuntimeError("CLI transport failure; raw diagnostics discarded")
            row["result"] = sanitize(result)
            self.save()
            return result
        except Exception as error:
            row["failure"] = {"type": type(error).__name__, "message": str(error)}
            self.save()
            raise

    def create_secret(self, leaf, **value):
        name = self.prefix + "/" + leaf
        if self.call("preflight-" + leaf, "secretsmanager", "DescribeSecret", {"SecretId": name})["code"] != "ResourceNotFoundException":
            raise RuntimeError("Refusing existing or ambiguous secret: " + name)
        ownership = {"kind": "secret", "name": name, "status": "create-attempted"}
        self.data["ownership"].append(ownership)
        self.save()
        request = {"Name": name, "ClientRequestToken": str(uuid.uuid4()),
                   "Tags": [{"Key": "stackd-probe", "Value": self.prefix}], **value}
        if not self.args.endpoint or self.secrets:
            request["KmsKeyId"] = "alias/aws/secretsmanager"
        output = require(self.call("create-" + leaf, "secretsmanager", "CreateSecret", request))
        self.secrets.append(output["ARN"])
        ownership.update(status="created", arn=output["ARN"])
        self.save()
        return output

    def get(self, label, name, decrypt=None, env=None):
        request = {"Name": name}
        if decrypt is not None:
            request["WithDecryption"] = decrypt
        return self.call(label, "ssm", "GetParameter", request, env)

    def batch(self, label, names, decrypt=None, env=None):
        request = {"Names": names}
        if decrypt is not None:
            request["WithDecryption"] = decrypt
        return self.call(label, "ssm", "GetParameters", request, env)

    def identify(self):
        identity = require(self.call("identity", "sts", "get-caller-identity", {}))
        self.data["identity"] = identity
        self.save()
        if identity["Account"] != self.args.account:
            raise RuntimeError("Refusing unexpected native account")
        return identity

    def scenario(self):
        identity = self.identify()
        initial = self.create_secret("string", SecretString='{"fixture":"public-first","unicode":"λ"}')
        binary = self.create_secret("binary", SecretBinary=base64.b64encode(b"stackd-public-binary\x00\xff\n").decode())
        special = self.create_secret("nested+/@/=", SecretString="public-special-name")
        name, arn = initial["Name"], initial["ARN"]
        stage32 = "fixture-stage-" + "x" * 18
        uuidstage = "abcdefab-abcd-abcd-abcd-abcdefabcdef"
        current = require(self.call("put-current", "secretsmanager", "PutSecretValue", {
            "SecretId": arn, "ClientRequestToken": str(uuid.uuid4()),
            "SecretString": '{"fixture":"public-current","unicode":"λ"}',
            "VersionStages": ["AWSCURRENT", "stable._-", stage32, uuidstage, "1", "bad/stage", "bad:stage"]}))
        parameter = "/" + self.prefix + "/ordinary"
        if self.get("preflight-ordinary", parameter)["code"] != "ParameterNotFound":
            raise RuntimeError("Refusing existing or ambiguous parameter")
        self.data["ownership"].append({"kind": "parameter", "name": parameter, "status": "create-attempted"})
        self.save()
        require(self.call("create-ordinary", "ssm", "PutParameter", {
            "Name": parameter, "Type": "String", "Value": "public-ordinary", "Overwrite": False,
            "Tags": [{"Key": "stackd-probe", "Value": self.prefix}]}))
        self.parameter = parameter
        self.data["ownership"][-1]["status"] = "created"
        self.save()
        ref, binary_ref = REFERENCE + name, REFERENCE + binary["Name"]
        missing = REFERENCE + self.prefix + "/absent"
        self.phase = "observe"
        self.call("direct-string", "secretsmanager", "GetSecretValue", {"SecretId": arn})
        self.call("direct-binary", "secretsmanager", "GetSecretValue", {"SecretId": binary["ARN"]})
        self.get("special-secret-name", REFERENCE + special["Name"], True)
        for flag in (None, False, True):
            suffix = "omitted" if flag is None else str(flag).lower()
            self.get("string-decryption-" + suffix, ref, flag)
            self.get("binary-decryption-" + suffix, binary_ref, flag)
            self.batch("batch-decryption-" + suffix, [binary_ref, ref, parameter], flag)
        selectors = {
            "current-stage": ":AWSCURRENT", "previous-stage": ":AWSPREVIOUS", "custom-stage": ":stable._-",
            "stage32": ":" + stage32, "uuid-stage": ":" + uuidstage,
            "initial-version-id": ":" + initial["VersionId"], "current-version-id": ":" + current["VersionId"],
            "numeric-stage": ":1", "numeric-leading-zero": ":01", "missing-stage": ":absent",
            "missing-version-id": ":00000000-0000-0000-0000-000000000000",
            "slash-stage": "/AWSPREVIOUS", "colon-slash-stage": ":bad/stage", "colon-colon-stage": ":bad:stage",
            "stage-version": ":AWSCURRENT:" + current["VersionId"], "empty-selector": ":",
            "json-key-syntax": ":fixture:AWSCURRENT:", "stage-space": ":bad stage",
        }
        for label, selector in selectors.items():
            self.get(label, ref + selector, True)
        for label, identifier in {
            "full-secret-arn": arn, "partial-secret-arn": arn.rsplit("-", 1)[0],
            "full-secret-arn-stage": arn + ":AWSPREVIOUS", "double-slash-name": "/" + name,
            "missing-slash-prefix": "NO_PREFIX", "empty-secret": "",
        }.items():
            self.get(label, ref.removeprefix("/") if identifier == "NO_PREFIX" else REFERENCE + identifier, True)
        self.get("bare-secret-arn", arn, True)
        self.get("missing-secret", missing, False)
        self.get("missing-secret-stage", missing + ":AWSCURRENT", True)
        self.batch("batch-missing", [missing, ref, parameter], True)
        self.batch("batch-missing-stage", [ref + ":absent", ref, parameter], True)
        self.batch("batch-invalid-arn", [REFERENCE + arn, ref, parameter], True)
        self.batch("batch-invalid-selector", [ref + ":bad/stage", ref, parameter], True)
        self.batch("batch-duplicates-stages", [ref + ":AWSPREVIOUS", ref, ref, ref + ":AWSCURRENT"], True)
        self.authorization(identity, ref, binary_ref, missing, arn, binary["ARN"])

    def selector_edges(self):
        self.identify()
        compact = uuid.uuid4().hex
        initial = self.create_secret("compact", ClientRequestToken=compact, SecretString="public-compact-version")
        current = require(self.call("compact-put-current", "secretsmanager", "PutSecretValue", {
            "SecretId": initial["ARN"], "ClientRequestToken": str(uuid.uuid4()),
            "SecretString": "public-compact-stage",
            "VersionStages": ["AWSCURRENT", compact, "a" * 36, "1-1-1-1-1"]}))
        ref = REFERENCE + initial["Name"]
        self.phase = "observe"
        self.call("compact-direct-version", "secretsmanager", "GetSecretValue", {
            "SecretId": initial["ARN"], "VersionId": compact})
        self.call("compact-direct-stage", "secretsmanager", "GetSecretValue", {
            "SecretId": initial["ARN"], "VersionStage": compact})
        self.get("compact-version-stage-ambiguity", ref + ":" + compact, True)
        self.get("non-uuid-36-stage", ref + ":" + "a" * 36, True)
        self.get("short-hyphen-stage", ref + ":1-1-1-1-1", True)
        self.get("canonical-current-version", ref + ":" + current["VersionId"], True)

    def create_role(self, identity, statements):
        principal = identity["Arn"]
        if ":assumed-role/" in principal:
            principal = principal.replace(":sts:", ":iam:").split(":assumed-role/", 1)[0] + ":role/" + principal.split(":assumed-role/", 1)[1].rsplit("/", 1)[0]
        role_name = self.prefix
        if self.call("preflight-role", "iam", "get-role", {"RoleName": role_name})["code"] != "NoSuchEntity":
            self.data["constraints"].append("Role preflight did not establish absence; IAM scenarios unavailable")
            self.save()
            return
        self.data["ownership"].append({"kind": "role", "name": role_name, "status": "create-attempted"})
        self.save()
        result = self.call("create-role", "iam", "create-role", {
            "RoleName": role_name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}]}),
            "Tags": [{"Key": "stackd-probe", "Value": self.prefix}]})
        if result["code"] != "Success":
            self.data["constraints"].append("Role creation unavailable: " + result["code"] + "; no IAM/KMS read behavior inferred")
            self.save()
            return
        self.role = role_name
        self.data["ownership"][-1].update(status="created", arn=result["output"]["Role"]["Arn"])
        self.save()
        role_arn = result["output"]["Role"]["Arn"]
        self.role_policy = "owned-probe"
        result = self.call("role-policy", "iam", "put-role-policy", {
            "RoleName": role_name, "PolicyName": self.role_policy, "PolicyDocument": json.dumps({
                "Version": "2012-10-17", "Statement": statements})})
        if result["code"] != "Success":
            self.data["constraints"].append("Owned-role policy unavailable: " + result["code"])
            self.save()
            return
        if not self.args.endpoint:
            time.sleep(self.args.iam_settle_seconds)
        return role_arn

    def authorization(self, identity, ref, binary_ref, missing, arn, binary_arn):
        self.phase = "authorization"
        ssm = {"Effect": "Allow", "Action": ["ssm:GetParameter", "ssm:GetParameters"], "Resource": "*"}
        secret = {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": [arn, binary_arn]}
        role_arn = self.create_role(identity, [ssm, secret])
        if not role_arn:
            return
        variants = {
            "both": [ssm, secret], "ssm-only": [ssm], "secrets-only": [secret],
            "deny-ssm": [ssm, secret, {"Effect": "Deny", "Action": "ssm:*", "Resource": "*"}],
            "deny-binary-secret": [ssm, secret, {"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": binary_arn}],
            "deny-kms": [ssm, secret, {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*"}],
        }
        for label, statements in variants.items():
            result = self.call("assume-" + label, "sts", "assume-role", {
                "RoleArn": role_arn, "RoleSessionName": label, "DurationSeconds": 900,
                "Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})})
            if result["code"] != "Success":
                self.data["constraints"].append(label + " session unavailable: " + result["code"])
                self.save()
                continue
            credentials = result["output"]["Credentials"]
            environment = dict(self.env, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                               AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"], AWS_SESSION_TOKEN=credentials["SessionToken"])
            for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SECURITY_TOKEN"):
                environment.pop(key, None)
            self.call(label + "-identity", "sts", "get-caller-identity", {}, environment)
            self.call(label + "-direct", "secretsmanager", "GetSecretValue", {"SecretId": arn}, environment)
            self.get(label + "-string-false", ref, False, environment)
            self.get(label + "-string-true", ref, True, environment)
            self.get(label + "-binary", binary_ref, True, environment)
            self.get(label + "-ordinary", self.parameter, False, environment)
            self.batch(label + "-batch", [ref, binary_ref, self.parameter], True, environment)
            self.batch(label + "-batch-missing", [ref, missing, binary_ref], True, environment)

    def stage_conditions(self, validation=False):
        identity = self.identify()
        secret = self.create_secret("stage-conditions", SecretString="public-stage-conditions-initial")
        self.phase = "authorization"
        allow = {"Effect": "Allow", "Action": "secretsmanager:PutSecretValue", "Resource": secret["ARN"]}
        role_arn = self.create_role(identity, [allow])
        if not role_arn:
            return
        key = "secretsmanager:VersionStage"
        variants = {
            "equals": {"StringEquals": {key: "allowed"}},
            "not-equals": {"StringNotEquals": {key: "forbidden"}},
            "for-all": {"ForAllValues:StringEquals": {key: ["allowed", "other"]}},
            "present": {"Null": {key: "false"}},
        }
        cases = {"omitted": None, "empty": [], "allowed": ["allowed"],
                 "allowed-other": ["allowed", "other"], "allowed-forbidden": ["allowed", "forbidden"]}
        if validation:
            cases = {
                "valid": {},
                "empty-stages": {"VersionStages": []},
                "empty-stage": {"VersionStages": [""]},
                "short-token": {"ClientRequestToken": "short"},
                "null-secret-id": {"SecretId": None},
                "wrong-stages-type": {"VersionStages": {}},
                "wrong-stage-type": {"VersionStages": [{}]},
                "empty-value": {"SecretString": ""},
                "null-value": {"SecretString": None},
            }
        self.data["condition_matrix"] = {"variants": variants, "cases": cases, "observations": []}
        self.save()
        for variant, condition in variants.items():
            result = self.call("stage-assume-" + variant, "sts", "assume-role", {
                "RoleArn": role_arn, "RoleSessionName": variant, "DurationSeconds": 900,
                "Policy": json.dumps({"Version": "2012-10-17", "Statement": [dict(allow, Condition=condition)]})})
            if result["code"] != "Success":
                self.data["constraints"].append(variant + " session unavailable: " + result["code"])
                self.save()
                continue
            credentials = result["output"]["Credentials"]
            environment = dict(self.env, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                               AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"], AWS_SESSION_TOKEN=credentials["SessionToken"])
            for env_key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SECURITY_TOKEN"):
                environment.pop(env_key, None)
            self.call("stage-identity-" + variant, "sts", "get-caller-identity", {}, environment)
            for case, overrides in cases.items():
                label = "stage-" + variant + "-" + case
                token = str(uuid.uuid4())
                request = {"SecretId": secret["ARN"], "ClientRequestToken": token,
                           "SecretString": "public-" + label}
                if validation:
                    request.update(overrides)
                elif overrides is not None:
                    request["VersionStages"] = overrides
                result = self.call(label, "secretsmanager", "PutSecretValue", request, environment)
                readback = self.call(label + "-readback", "secretsmanager", "GetSecretValue", {
                    "SecretId": secret["ARN"], "VersionId": request["ClientRequestToken"]})
                self.data["condition_matrix"]["observations"].append({
                    "variant": variant, "case": case, "code": result["code"],
                    "returned_stages": result.get("output", {}).get("VersionStages"),
                    "readback_code": readback["code"],
                    "readback_stages": readback.get("output", {}).get("VersionStages")})
                self.save()

    def missing_authorization(self, suffix_only=False):
        identity = self.identify()
        name = self.prefix + "/missing"
        partial_arn = "arn:aws:secretsmanager:" + REGION + ":" + identity["Account"] + ":secret:" + name
        preflight = self.call("missing-preflight", "secretsmanager", "GetSecretValue", {"SecretId": name})
        if preflight["code"] != "ResourceNotFoundException":
            raise RuntimeError("Missing-secret scenario requires a proven absent unique name")
        self.phase = "authorization"
        ssm = {"Effect": "Allow", "Action": ["ssm:GetParameter", "ssm:GetParameters"], "Resource": "*"}
        secret = {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
        role_arn = self.create_role(identity, [secret] if suffix_only else [ssm, secret])
        if not role_arn:
            return
        resources = {
            "all": "*",
            "unrelated": partial_arn.removesuffix("/missing") + "/unrelated-AbCdEf",
            "suffix-wildcard": partial_arn + "-*",
            "exact-partial": partial_arn,
        }
        if suffix_only:
            resources = {
                "fixed-suffix": partial_arn + "-ABC123",
                "six-wildcards": partial_arn + "-??????",
                "restricted-suffix": partial_arn + "-A*",
            }
        self.data["missing_authorization_matrix"] = {"name": name, "resources": resources, "observations": []}
        self.save()
        for variant, resource in resources.items():
            statements = [dict(secret, Resource=resource)]
            if not suffix_only:
                statements.append(ssm)
            result = self.call("missing-assume-" + variant, "sts", "assume-role", {
                "RoleArn": role_arn, "RoleSessionName": variant, "DurationSeconds": 900,
                "Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})})
            if result["code"] != "Success":
                self.data["constraints"].append(variant + " session unavailable: " + result["code"])
                self.save()
                continue
            credentials = result["output"]["Credentials"]
            environment = dict(self.env, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                               AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"], AWS_SESSION_TOKEN=credentials["SessionToken"])
            for env_key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SECURITY_TOKEN"):
                environment.pop(env_key, None)
            self.call("missing-identity-" + variant, "sts", "get-caller-identity", {}, environment)
            direct = self.call("missing-direct-" + variant, "secretsmanager", "GetSecretValue", {"SecretId": name}, environment)
            observation = {"variant": variant, "direct": direct}
            if not suffix_only:
                observation["ssm_single"] = self.get("missing-ssm-single-" + variant, REFERENCE + name, True, environment)
                observation["ssm_batch"] = self.batch("missing-ssm-batch-" + variant, [REFERENCE + name], True, environment)
            self.data["missing_authorization_matrix"]["observations"].append(observation)
            self.save()

    def cleanup(self):
        self.phase = "cleanup"
        errors, remaining = [], []
        # Resolve an interrupted create by its recorded name and unique owner tag.
        # Never delete an ambiguous resource, or report unverified cleanup as success.
        for ownership in self.data["ownership"]:
            if ownership["status"] != "create-attempted":
                continue
            kind, name = ownership["kind"], ownership["name"]
            try:
                if kind == "secret":
                    result = self.call("recover-secret-ownership", "secretsmanager", "DescribeSecret", {"SecretId": name})
                    absent, tag_key = "ResourceNotFoundException", "Tags"
                    output = result.get("output", {})
                elif kind == "role":
                    result = self.call("recover-role-ownership", "iam", "get-role", {"RoleName": name})
                    absent, tag_key = "NoSuchEntity", "Tags"
                    output = result.get("output", {}).get("Role", {})
                else:
                    result = self.call("recover-parameter-ownership", "ssm", "ListTagsForResource", {
                        "ResourceType": "Parameter", "ResourceId": name})
                    absent, tag_key = "InvalidResourceId", "TagList"
                    output = result.get("output", {})
                if result["code"] == absent:
                    ownership["status"] = "not-created"
                    continue
                tags = {tag["Key"]: tag["Value"] for tag in output.get(tag_key, [])}
                if result["code"] != "Success" or tags.get("stackd-probe") != self.prefix:
                    remaining.append(name)
                    errors.append({"resource": name, "error": "Create outcome has no verified owner tag; not deleted"})
                    continue
                ownership["status"] = "created-recovered"
                if kind == "secret":
                    self.secrets.append(output["ARN"])
                    ownership["arn"] = output["ARN"]
                elif kind == "role":
                    self.role = name
                else:
                    self.parameter = name
            except Exception as error:
                errors.append({"resource": name, "error": str(error)})
                remaining.append(name)
        if self.role:
            for operation, request in (("delete-role-policy", {"RoleName": self.role, "PolicyName": getattr(self, "role_policy", "owned-probe")}),
                                       ("delete-role", {"RoleName": self.role})):
                try:
                    result = self.call("cleanup-" + operation, "iam", operation, request)
                    if result["code"] not in ("Success", "NoSuchEntity"):
                        errors.append({"resource": self.role, "operation": operation, "code": result["code"]})
                except Exception as error:
                    errors.append({"resource": self.role, "operation": operation, "error": str(error)})
            try:
                if self.call("verify-role-deleted", "iam", "get-role", {"RoleName": self.role})["code"] != "NoSuchEntity":
                    remaining.append(self.role)
            except Exception as error:
                errors.append({"resource": self.role, "error": str(error)})
                remaining.append(self.role)
        if self.parameter:
            try:
                result = self.call("cleanup-parameter", "ssm", "DeleteParameter", {"Name": self.parameter})
                if result["code"] not in ("Success", "ParameterNotFound"):
                    errors.append({"resource": self.parameter, "code": result["code"]})
                if self.get("verify-parameter-deleted", self.parameter)["code"] != "ParameterNotFound":
                    remaining.append(self.parameter)
            except Exception as error:
                errors.append({"resource": self.parameter, "error": str(error)})
                remaining.append(self.parameter)
        for arn in self.secrets:
            try:
                result = self.call("cleanup-secret-" + arn.rsplit("/", 1)[-1], "secretsmanager", "DeleteSecret", {
                    "SecretId": arn, "ForceDeleteWithoutRecovery": True})
                if result["code"] not in ("Success", "ResourceNotFoundException"):
                    errors.append({"resource": arn, "code": result["code"]})
                deleted = False
                for attempt in range(20):
                    result = self.call("verify-secret-deleted-" + str(attempt), "secretsmanager", "DescribeSecret", {"SecretId": arn})
                    if result["code"] == "ResourceNotFoundException":
                        deleted = True
                        break
                    if result["code"] != "Success":
                        break
                    time.sleep(3)
                if not deleted:
                    remaining.append(arn)
            except Exception as error:
                errors.append({"resource": arn, "error": str(error)})
                remaining.append(arn)
        self.data["cleanup"] = {"confirmed": not remaining and not errors, "remaining": remaining, "errors": errors, "finished_at": now()}
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--endpoint")
    parser.add_argument("--iam-settle-seconds", type=int, default=15)
    scenarios = parser.add_mutually_exclusive_group()
    scenarios.add_argument("--selector-edges-only", action="store_true")
    scenarios.add_argument("--stage-conditions-only", action="store_true")
    scenarios.add_argument("--validation-authority-only", action="store_true")
    scenarios.add_argument("--missing-authorization-only", action="store_true")
    scenarios.add_argument("--missing-suffix-only", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    probe = Probe(args)
    failed = False
    try:
        if args.selector_edges_only:
            probe.selector_edges()
        elif args.stage_conditions_only:
            probe.stage_conditions()
        elif args.validation_authority_only:
            probe.stage_conditions(validation=True)
        elif args.missing_authorization_only:
            probe.missing_authorization()
        elif args.missing_suffix_only:
            probe.missing_authorization(suffix_only=True)
        else:
            probe.scenario()
    except Exception as error:
        failed = True
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error)}
        probe.save()
    finally:
        probe.cleanup()
    summary = {"output": str(probe.path), "calls": len(probe.data["calls"]), "constraints": probe.data["constraints"],
               "cleanup": probe.data["cleanup"], "failure": probe.data.get("failure")}
    print(json.dumps(summary, indent=2))
    return 1 if failed or not probe.data["cleanup"]["confirmed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
