#!/usr/bin/env python3
"""Capture outbound identity behavior with owned IAM observers.

Default mode keeps account configuration unchanged. --issuance temporarily enables
the initially disabled feature and restores disabled state during cleanup. Tokens
stay in memory; captures contain decoded claims and public verification keys only.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
from iam_organizations_access_probe import Probe, ROOT, call, operation, policy, allow, stamp

DESTINATION = ROOT / '.stackd/probes/iam/outbound_identity.json'
DOCS = [
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_" + action + ".html"
    for action in ["EnableOutboundWebIdentityFederation", "DisableOutboundWebIdentityFederation", "GetOutboundWebIdentityFederationInfo"]
] + [
    "https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_token_claims.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_policies.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_sts.html",
]


class OutboundProbe(Probe):
    def __init__(self, output):
        super().__init__(output)
        self.prefix = "stackd-outbound-" + uuid.uuid4().hex[:10]
        self.normalized_prefix = "stackd-outbound-fixture"
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")
        self.signing_credentials = None
        self.probe_name = "scripts/aws/iam_outbound_identity_probe.py"
        self.documentation = DOCS
        self.issuance = False
        self.limitations = [
            "Existing account-wide outbound federation configuration is read only; no enable or disable request is sent.",
            "The live account has federation disabled. Successful issuance, JWT claim encoding, JWKS/key details, rotation, enable/disable transitions and numeric payload limits are not observed by this capture.",
            "Authorization and input errors are observed on actual signed Query requests; invalid inputs bypass only CLI client-side validation.",
            "Temporary sessions have only owned observer permissions and their returned credentials stay in memory; bearer tokens and signing material are never retained.",
        ]

    def normalize(self, value):
        if isinstance(value, dict):
            value = {k: v for k, v in value.items() if k not in ("WebIdentityToken", "SecretAccessKey", "SessionToken", "Credentials")}
        return super().normalize(value)

    def write(self, cleaned=False):
        data = {"schema_version": 1, "source": "Real AWS IAM and STS APIs, commercial partition",
                "probe": self.probe_name, "aws_cli_version": self.cli_version,
                "started_at": self.started, "finished_at": stamp(), "documentation": self.documentation,
                "model_source": "clones/aws-sdk-go-v2/codegen/sdk-codegen/aws-models/{iam,sts}.json",
                "eligibility": self.eligibility, "setup": self.normalize(self.setup), "observations": self.observations,
                "cleanup": self.normalize(self.cleanup), "capture_complete": self.complete, "cleanup_verified": cleaned,
                "sanitization": "Owned names/IDs/account normalized; original caller identity redacted; no bearer tokens, credential secrets or debug logs retained.",
                "limitations": self.limitations}
        self.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(data, indent=2) + "\n")
        temporary.replace(self.output)

    def finish(self):
        super().finish()
        if self.issuance:
            result = call("iam", "get-outbound-web-identity-federation-info")
            self.cleanup.append({"service": "iam", "operation": "GetOutboundWebIdentityFederationInfo", "code": result["code"]})
            self.write(result["code"] == "FeatureDisabled")
            if result["code"] != "FeatureDisabled":
                raise RuntimeError("Final outbound federation state is not verified disabled")

    def request(self, case, service, action, parameters=None, environment=None, credential="original", region="us-east-1", global_endpoint=False):
        if (service, action) not in (("sts", "get-web-identity-token"), ("iam", "get-outbound-web-identity-federation-info")) and not (self.issuance and service == "iam" and action in ("enable-outbound-web-identity-federation", "disable-outbound-web-identity-federation")):
            raise ValueError("Outbound capture may only read configuration or request a token")
        endpoint = "https://iam.amazonaws.com" if service == "iam" else ("https://sts.amazonaws.com" if global_endpoint else "https://sts." + region + ".amazonaws.com")
        result = self.query(service, action, parameters or {}, environment, region, endpoint)
        output = result.get("output", {})
        if "IssuerIdentifier" in output:
            self.identifiers[output["IssuerIdentifier"]] = "https://fixture.tokens.sts.global.api.aws"
        token = output.get("WebIdentityToken")
        if token:
            if not self.issuance:
                raise RuntimeError("Account federation state changed; unexpected bearer token discarded")
            header, body, signature = token.split(".")
            decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            claims = json.loads(decode(body))
            custom = claims.get("https://sts.amazonaws.com/", {})
            if custom.get("org_id"):
                self.identifiers[custom["org_id"]] = "o-fixture"
            output.update(jwt_header=json.loads(decode(header)), jwt_claims=claims, payload_bytes=len(decode(body)), token_bytes=len(token), signature_bytes=len(decode(signature)))
        row = {"case": case, "service": service, "operation": operation(action), "input": parameters or {}, "credential": credential,
               "region": region, "endpoint": endpoint, "observed_at": stamp(), **result}
        if self.changes:
            row["state_changes_before"], self.changes = self.changes, []
        self.observations.append(self.normalize(row))
        self.write()
        print(case, result["code"], flush=True)
        return result

    def query(self, service, action, parameters, environment, region, endpoint):
        if environment is not None:
            credentials = {"AccessKeyId": environment["AWS_ACCESS_KEY_ID"], "SecretAccessKey": environment["AWS_SECRET_ACCESS_KEY"], "SessionToken": environment.get("AWS_SESSION_TOKEN")}
        else:
            if self.signing_credentials is None:
                response = subprocess.run(["aws", "configure", "export-credentials", "--format", "process"], capture_output=True, text=True, timeout=30)
                if response.returncode:
                    raise RuntimeError("Unable to load signing credentials; diagnostics discarded")
                self.signing_credentials = json.loads(response.stdout)
            credentials = self.signing_credentials
        fields = {"Action": operation(action), "Version": "2010-05-08" if service == "iam" else "2011-06-15"}
        def encode(name, value):
            if isinstance(value, list):
                for index, item in enumerate(value, 1):
                    encode(name + ".member." + str(index), item)
            elif isinstance(value, dict):
                for key, item in value.items():
                    encode(name + "." + key, item)
            else:
                fields[name] = str(value).lower() if isinstance(value, bool) else str(value)
        for name, value in parameters.items():
            encode(name, value)
        body = urllib.parse.urlencode(fields).encode()
        now = datetime.datetime.now(datetime.timezone.utc)
        date, instant = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
        headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8", "host": urllib.parse.urlsplit(endpoint).netloc, "x-amz-date": instant}
        if credentials.get("SessionToken"):
            headers["x-amz-security-token"] = credentials["SessionToken"]
        names = ";".join(sorted(headers))
        canonical = "POST\n/\n\n" + "".join(name + ":" + headers[name] + "\n" for name in sorted(headers)) + "\n" + names + "\n" + hashlib.sha256(body).hexdigest()
        scope = date + "/" + region + "/" + service + "/aws4_request"
        signing_key = ("AWS4" + credentials["SecretAccessKey"]).encode()
        for part in (date, region, service, "aws4_request"):
            signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(signing_key, ("AWS4-HMAC-SHA256\n" + instant + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()).encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + credentials["AccessKeyId"] + "/" + scope + ", SignedHeaders=" + names + ", Signature=" + signature
        request = urllib.request.Request(endpoint + "/", data=body, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, xml = response.status, ET.fromstring(response.read())
        for element in xml.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        error = xml.find("Error")
        if error is not None:
            return {"code": error.findtext("Code"), "message": error.findtext("Message"), "http_status": status}
        output = xml.find(operation(action) + "Result")
        output = {item.tag: (item.text == "true" if item.tag == "JwtVendingEnabled" else item.text) for item in output} if output is not None else {}
        return {"code": "Success", "output": output, "http_status": status}


def session_environment(output):
    c = output["Credentials"]
    env = os.environ.copy()
    env.update(AWS_ACCESS_KEY_ID=c["AccessKeyId"], AWS_SECRET_ACCESS_KEY=c["SecretAccessKey"], AWS_SESSION_TOKEN=c["SessionToken"], AWS_EC2_METADATA_DISABLED="true")
    env.pop("AWS_PROFILE", None)
    return env


def run(p):
    identity = call("sts", "get-caller-identity")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    caller = identity["output"]
    p.account = caller["Account"]
    p.identifiers.update({caller["Arn"]: "<original-caller-arn>", caller["UserId"]: "<original-caller-id>"})
    p.eligibility = {"caller_is_root": caller["Arn"].endswith(":root"), "caller_is_role": ":assumed-role/" in caller["Arn"]}
    state = p.request("info_initial", "iam", "get-outbound-web-identity-federation-info")
    p.eligibility["initial_feature_code"] = state["code"]
    if state["code"] != "FeatureDisabled":
        raise RuntimeError("This probe requires the observed disabled account state")
    base = {"Audience": ["https://stackd-outbound.example.invalid"], "SigningAlgorithm": "RS256"}
    for case, input in [
        ("default", base), ("es384", {**base, "SigningAlgorithm": "ES384"}),
        *[("algorithm_" + value, {**base, "SigningAlgorithm": value}) for value in ["RS384", "ES256", "HS256", "rs256", "", "none", "RS256x"]],
        ("missing_algorithm", {"Audience": base["Audience"]}),
        ("missing_audience", {"SigningAlgorithm": "RS256"}), ("audience_empty_list", {**base, "Audience": []}),
        *[("audience_" + label, {**base, "Audience": value}) for label, value in [
            ("empty", [""]), ("space", [" "]), ("plain", ["not-a-url"]), ("duplicate", base["Audience"] * 2),
            ("eleven", [str(i) for i in range(11)]), ("long", ["a" * 1001]), ("unicode", ["https://例.example.invalid"])]],
        *[("duration_" + str(value), {**base, "DurationSeconds": value}) for value in [0, 59, 60, 3600, 3601]],
        *[("tags_" + label, {**base, "Tags": value}) for label, value in [
            ("plain", [{"Key": "team", "Value": "test"}]), ("empty", []),
            ("duplicate", [{"Key": "team", "Value": "one"}, {"Key": "team", "Value": "two"}]),
            ("case_duplicate", [{"Key": "team", "Value": "one"}, {"Key": "Team", "Value": "two"}]),
            ("reserved", [{"Key": "aws:team", "Value": "test"}]), ("empty_key", [{"Key": "", "Value": "test"}]),
            ("invalid_key", [{"Key": "<team>", "Value": "test"}]), ("long_key", [{"Key": "k" * 129, "Value": "test"}]),
            ("long_value", [{"Key": "team", "Value": "v" * 257}]),
            ("fifty_one", [{"Key": str(i), "Value": "test"} for i in range(51)])]],
    ]:
        p.request("original_" + case, "sts", "get-web-identity-token", input)
    p.request("original_other_region", "sts", "get-web-identity-token", base, region="eu-west-2")
    p.request("original_global_endpoint", "sts", "get-web-identity-token", base, global_endpoint=True)
    observers = {}
    configs = [
        ("no_grants", None),
        ("plain", lambda u: policy(allow(["iam:GetOutboundWebIdentityFederationInfo", "sts:GetWebIdentityToken"]))),
        ("tagged", lambda u: policy(allow(["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken", "sts:GetFederationToken"]))),
        ("denied", lambda u: policy(allow("sts:*"), {"Effect": "Deny", "Action": "sts:GetWebIdentityToken", "Resource": "*"})),
        ("scoped_user", lambda u: policy(allow(["sts:GetWebIdentityToken", "iam:GetOutboundWebIdentityFederationInfo"], u["Arn"]))),
        ("scoped_self", lambda u: policy(allow(["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken"], "arn:aws:sts::" + p.account + ":self"))),
        ("condition", lambda u: policy(allow("sts:GetWebIdentityToken", Condition={"ForAllValues:StringEquals": {"sts:IdentityTokenAudience": base["Audience"]}, "StringEquals": {"sts:SigningAlgorithm": "RS256"}, "NumericEquals": {"sts:DurationSeconds": "300"}}))),
        ("tag_condition", lambda u: policy(allow("sts:GetWebIdentityToken"), allow("sts:TagGetWebIdentityToken", Condition={"StringEquals": {"aws:RequestTag/team": "test"}, "ForAllValues:StringEquals": {"aws:TagKeys": ["team"]}}))),
        ("boundary", lambda u: policy(allow(["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken"]))),
    ]
    for name, make_document in configs:
        user = p.user(name)
        if make_document:
            p.inline(user, make_document(user))
        observers[name] = (user, p.key(user, name))
    user = observers["boundary"][0]
    boundary = p.require("iam", "create-policy", {"PolicyName": p.prefix + "-boundary", "PolicyDocument": policy(allow("iam:GetUser"))})["Policy"]
    p.identifiers[boundary["PolicyId"]] = "<policy-id:boundary>"
    p.own("iam", "delete-policy", {"PolicyArn": boundary["Arn"]}, {"service": "iam", "action": "get-policy", "input": {"PolicyArn": boundary["Arn"]}})
    p.require("iam", "put-user-permissions-boundary", {"UserName": user["UserName"], "PermissionsBoundary": boundary["Arn"]})
    p.own("iam", "delete-user-permissions-boundary", {"UserName": user["UserName"]})
    role = p.require("iam", "create-role", {"RoleName": p.prefix + "-role", "Path": "/outbound/", "AssumeRolePolicyDocument": policy({"Effect": "Allow", "Principal": {"AWS": caller["Arn"]}, "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"]})})["Role"]
    p.identifiers[role["RoleId"]] = "<role-id:observer>"
    p.own("iam", "delete-role", {"RoleName": role["RoleName"]}, {"service": "iam", "action": "get-role", "input": {"RoleName": role["RoleName"]}})
    p.require("iam", "put-role-policy", {"RoleName": role["RoleName"], "PolicyName": "Outbound", "PolicyDocument": policy(allow(["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken"]))})
    p.own("iam", "delete-role-policy", {"RoleName": role["RoleName"], "PolicyName": "Outbound"})
    # Every observer receives its policy once. Allow IAM's documented propagation
    # before observations, avoiding repeated changes to cached permission graphs.
    time.sleep(40)
    tagged = {**base, "Tags": [{"Key": "team", "Value": "test"}]}
    for name in ["no_grants", "plain", "scoped_user"]:
        p.request(name + "_info", "iam", "get-outbound-web-identity-federation-info", environment=observers[name][1], credential=name)
    for name in observers:
        p.request(name + "_token", "sts", "get-web-identity-token", base, observers[name][1], name)
    for name in ["plain", "tagged", "scoped_self", "tag_condition"]:
        p.request(name + "_with_tags", "sts", "get-web-identity-token", tagged, observers[name][1], name)
    for label, input in [("matching_explicit", {**base, "DurationSeconds": 300}),
                         ("audience_denied", {**base, "Audience": ["other"]}), ("algorithm_denied", {**base, "SigningAlgorithm": "ES384"}),
                         ("duration_denied", {**base, "DurationSeconds": 301})]:
        p.request("condition_" + label, "sts", "get-web-identity-token", input, observers["condition"][1], "condition")
    for label, tags in [("wrong_value", [{"Key": "team", "Value": "other"}]), ("wrong_key", [{"Key": "extra", "Value": "test"}])]:
        p.request("tag_condition_" + label, "sts", "get-web-identity-token", {**base, "Tags": tags}, observers["tag_condition"][1], "tag_condition")
    env = observers["tagged"][1]
    session = call("sts", "get-session-token", {"DurationSeconds": 900}, env)
    if session["code"] != "Success":
        raise RuntimeError("Owned observer session creation failed: " + session["code"])
    p.changes.append({"service": "sts", "operation": "GetSessionToken", "input": {"DurationSeconds": 900}, "credential": "tagged", "code": "Success"})
    p.request("get_session_token_caller", "sts", "get-web-identity-token", base, session_environment(session["output"]), "observer_session")
    parameters = {"Name": "outbound-probe", "DurationSeconds": 900, "Policy": policy(allow("sts:GetWebIdentityToken"))}
    session = call("sts", "get-federation-token", parameters, env)
    if session["code"] != "Success":
        raise RuntimeError("Owned observer federation creation failed: " + session["code"])
    p.changes.append({"service": "sts", "operation": "GetFederationToken", "input": parameters, "credential": "tagged", "code": "Success"})
    p.request("federation_token_caller", "sts", "get-web-identity-token", base, session_environment(session["output"]), "observer_federated")
    for label, extra in [("role", {}), ("role_session_denied", {"Policy": policy({"Effect": "Deny", "Action": "sts:GetWebIdentityToken", "Resource": "*"})})]:
        parameters = {"RoleArn": role["Arn"], "RoleSessionName": label, "SourceIdentity": "outbound-observer", "DurationSeconds": 900, **extra}
        result = call("sts", "assume-role", parameters)
        if result["code"] != "Success":
            raise RuntimeError("Owned role assumption failed: " + result["code"])
        p.changes.append({"service": "sts", "operation": "AssumeRole", "input": parameters, "code": "Success", "output": {"Expiration": result["output"]["Credentials"]["Expiration"]}})
        role_env = session_environment(result["output"])
        p.request(label + "_default", "sts", "get-web-identity-token", base, role_env, label)
        if label == "role":
            p.request("role_exceeds_remaining_duration", "sts", "get-web-identity-token", {**base, "DurationSeconds": 3600}, role_env, label)
    p.request("info_final", "iam", "get-outbound-web-identity-federation-info")


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DESTINATION)
    parser.add_argument("--issuance", action="store_true", help="temporarily enable the initially disabled account feature, then restore disabled state")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    probe = OutboundProbe(args.output)
    probe.issuance = args.issuance
    try:
        if args.issuance:
            run_issuance(probe)
        else:
            run(probe)
        probe.complete = True
    finally:
        probe.finish()


def run_issuance(p):
    caller = call("sts", "get-caller-identity")["output"]
    p.account = caller["Account"]
    p.identifiers.update({caller["Arn"]: "<original-caller-arn>", caller["UserId"]: "<original-caller-id>"})
    p.limitations = ["The initially disabled account feature is temporarily enabled, then disabled during cleanup; its AWS-assigned issuer may remain allocated.",
                     "Tokens and credentials are held only in memory. Claims, sizes and public discovery documents are retained.",
                     "Key rotation and other partitions are not observed by this bounded capture."]
    state = p.request("info_initial", "iam", "get-outbound-web-identity-federation-info")
    if state["code"] != "FeatureDisabled":
        raise RuntimeError("Issuance capture requires initially disabled account state")
    enabled = p.request("enable", "iam", "enable-outbound-web-identity-federation")
    if enabled["code"] != "Success":
        raise RuntimeError("Unable to enable outbound federation: " + enabled["code"])
    p.own("iam", "disable-outbound-web-identity-federation", {})
    issuer = enabled["output"]["IssuerIdentifier"]
    p.request("enable_again", "iam", "enable-outbound-web-identity-federation")
    p.request("info_enabled", "iam", "get-outbound-web-identity-federation-info")
    user = p.user("issuer")
    p.inline(user, policy(allow(["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken"])))
    p.require("iam", "tag-user", {"UserName": user["UserName"], "Tags": [{"Key": "Team", "Value": "platform"}]})
    env = p.key(user, "issuer")
    role = p.require("iam", "create-role", {"RoleName": p.prefix + "-role", "Path": "/outbound/", "Tags": [{"Key": "Team", "Value": "role"}, {"Key": "untouched", "Value": "retained"}], "AssumeRolePolicyDocument": policy({"Effect": "Allow", "Principal": {"AWS": caller["Arn"]}, "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]})})["Role"]
    p.own("iam", "delete-role", {"RoleName": role["RoleName"]}, {"service": "iam", "action": "get-role", "input": {"RoleName": role["RoleName"]}})
    p.require("iam", "put-role-policy", {"RoleName": role["RoleName"], "PolicyName": "Outbound", "PolicyDocument": policy(allow(["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken"]))})
    p.own("iam", "delete-role-policy", {"RoleName": role["RoleName"], "PolicyName": "Outbound"})
    time.sleep(40)
    base = {"Audience": ["https://stackd-outbound.example.invalid"], "SigningAlgorithm": "RS256", "DurationSeconds": 60}
    for label, extra in [("user_rs256", {}), ("user_es384", {"SigningAlgorithm": "ES384"}),
                         ("multiple_audience", {"Audience": ["one", "two"]}), ("duplicate_audience", {"Audience": ["one", "one"]}),
                         ("request_tags", {"Tags": [{"Key": "Team", "Value": "request"}, {"Key": "aws:test", "Value": "reserved"}]}),
                         ("max_payload", {"Audience": ["a" * 999 + str(i) for i in range(10)], "Tags": [{"Key": str(i) + "k" * 126, "Value": "v" * 256} for i in range(50)]})]:
        p.request(label, "sts", "get-web-identity-token", {**base, **extra}, env, "issuer")
    def padded(size):
        audiences, tags = [], []
        for _ in range(10):
            length = min(size, 999)
            audiences.append("a" * (1 + length))
            size -= length
        for index in range(50):
            length = min(size, 256)
            tags.append({"Key": str(index), "Value": "v" * length})
            size -= length
        return {**base, "Audience": audiences, "Tags": tags}
    low, high = 0, 22790
    while low + 1 < high:
        middle = (low + high) // 2
        result = p.request("payload_padding_" + str(middle), "sts", "get-web-identity-token", padded(middle), env, "issuer")
        if result["code"] == "Success":
            low = middle
        elif result["code"] == "JWTPayloadSizeExceededException":
            high = middle
        else:
            raise RuntimeError("Unexpected payload boundary result: " + result["code"])
    p.request("payload_boundary_es384", "sts", "get-web-identity-token", {**padded(low), "SigningAlgorithm": "ES384"}, env, "issuer")
    p.request("payload_over_boundary_es384", "sts", "get-web-identity-token", {**padded(high), "SigningAlgorithm": "ES384"}, env, "issuer")
    for label, replacement in [("slash", "/"), ("unicode", "é"), ("quote", '"')]:
        parameters = padded(low)
        parameters["Audience"][0] = replacement + parameters["Audience"][0][1:]
        p.request("payload_boundary_" + label, "sts", "get-web-identity-token", parameters, env, "issuer")
    session = call("sts", "get-session-token", {"DurationSeconds": 900}, env)
    if session["code"] == "Success":
        p.request("user_session", "sts", "get-web-identity-token", base, session_environment(session["output"]), "user_session")
    assumed = call("sts", "assume-role", {"RoleArn": role["Arn"], "RoleSessionName": "outbound", "SourceIdentity": "probe-source", "DurationSeconds": 900, "Tags": [{"Key": "team", "Value": "session"}]})
    if assumed["code"] == "Success":
        role_env = session_environment(assumed["output"])
        p.request("role_session", "sts", "get-web-identity-token", base, role_env, "role_session")
        role_low, role_high = low - 1024, low
        while role_low + 1 < role_high:
            middle = (role_low + role_high) // 2
            result = p.request("role_payload_padding_" + str(middle), "sts", "get-web-identity-token", padded(middle), role_env, "role_session")
            if result["code"] == "Success":
                role_low = middle
            elif result["code"] == "JWTPayloadSizeExceededException":
                role_high = middle
            else:
                raise RuntimeError("Unexpected role payload boundary result: " + result["code"])
    else:
        raise RuntimeError("Role assumption failed: " + assumed["code"])
    for document in ["openid-configuration", "jwks.json"]:
        with urllib.request.urlopen(issuer + "/.well-known/" + document, timeout=30) as response:
            p.observations.append(p.normalize({"case": document, "http_status": response.status, "output": json.load(response)}))
    p.request("disable", "iam", "disable-outbound-web-identity-federation")
    p.request("info_disabled", "iam", "get-outbound-web-identity-federation-info")
    p.request("disable_again", "iam", "disable-outbound-web-identity-federation")
    p.request("token_disabled", "sts", "get-web-identity-token", base, env, "issuer")
    with urllib.request.urlopen(issuer + "/.well-known/jwks.json", timeout=30) as response:
        p.observations.append(p.normalize({"case": "jwks_after_disable", "http_status": response.status, "output": json.load(response)}))
    again = p.request("reenable", "iam", "enable-outbound-web-identity-federation")
    p.eligibility["issuer_stable_after_reenable"] = again.get("output", {}).get("IssuerIdentifier") == issuer
    p.request("info_reenabled", "iam", "get-outbound-web-identity-federation-info")


if __name__ == "__main__":
    main()
