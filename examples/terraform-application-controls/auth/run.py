"""Terraform / AWS 6.68.0 lifecycle with signed Cognito, Identity and MIME consumers.

Run: python examples/terraform-application-controls/auth/run.py --port 14783
Optional: --provider-mirror /absolute/provider/mirror
Requires boto3 and cryptography. No AWS requests, SMTP, or simulated MFA.
"""

import base64
from contextlib import ExitStack
from email import policy
from email.parser import BytesParser
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

import boto3
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local import (ACCOUNT, REGION, arguments, client, controller, environment,
                   expect_missing, require, workspace)


def decode64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def rejects(call, codes, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response["Error"]["Code"] in codes, str(error))
    else:
        raise RuntimeError("Unauthorized request succeeded")


def http_get(endpoint, path):
    authority = urlsplit(endpoint)
    connection = http.client.HTTPConnection(authority.hostname, authority.port, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        data = response.read()
        require(response.status == 200, f"Local HTTP status {response.status}")
        return data
    finally:
        connection.close()


def verify_jwt(token, keys, endpoint, outputs, use):
    header64, claims64, signature64 = token.split(".")
    header, claims = json.loads(decode64(header64)), json.loads(decode64(claims64))
    require(header.get("alg") == "RS256" and header.get("typ") == "JWT", "Unexpected JWT algorithm")
    matches = [key for key in keys["keys"] if key["kid"] == header["kid"]]
    require(len(matches) == 1 and matches[0]["kty"] == "RSA" and matches[0]["use"] == "sig", "Missing signing key")
    key = matches[0]
    public = rsa.RSAPublicNumbers(int.from_bytes(decode64(key["e"]), "big"),
                                 int.from_bytes(decode64(key["n"]), "big")).public_key()
    signed = (header64 + "." + claims64).encode("ascii")
    signature = decode64(signature64)
    public.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    try:
        public.verify(bytes([signature[0] ^ 1]) + signature[1:], signed,
                      padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        pass
    else:
        raise RuntimeError("Forged JWT signature verified")
    require(claims["iss"] == endpoint + "/" + outputs["pool_id"]
            and claims["sub"] == outputs["user_sub"] and claims["token_use"] == use
            and claims["exp"] > time.time() and claims["iat"] <= time.time(), "Invalid JWT claims")
    audience = "aud" if use == "id" else "client_id"
    require(claims[audience] == outputs["client_id"] and "readers" in claims["cognito:groups"],
            "JWT audience/group claims do not consume Terraform resources")
    return claims


def captured(directory, predicate):
    deadline = time.monotonic() + 15
    while True:
        for path in sorted(directory.rglob("*.eml")):
            message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
            part = message.get_body(preferencelist=("plain",)) if message.is_multipart() else message
            text = part.get_content() if part is not None else ""
            if predicate(path, message, text):
                require(not message.defects, f"Malformed captured MIME: {path}")
                return path, message, text
        require(time.monotonic() < deadline, "Expected actual captured MIME was not written")
        time.sleep(0.1)


def main():
    parser = arguments(__doc__, 14783)
    parser.add_argument("--provider-mirror", type=Path, help="Prepared filesystem provider mirror; disables direct downloads")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform 1.15.9 or newer, below 2.0.0")
    os.umask(0o077)
    root = workspace(args, "terraform-auth")
    root.chmod(0o700)  # Terraform state, password, codes and MIME are private.
    shutil.copyfile(Path(__file__).with_name("main.tf"), root / "main.tf")
    env = environment()
    config = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror does not exist")
        config += ("provider_installation {\n  filesystem_mirror {\n    path = "
                   + json.dumps(str(args.provider_mirror.resolve()))
                   + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    (root / "terraform.rc").write_text(config)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")

    evidence = {"provider": "hashicorp/aws 6.68.0",
                "controller": str(args.stackd.resolve()), "endpoint": f"http://127.0.0.1:{args.port}",
                "workspace": str(root), "stages": [], "commands": [], "consumers": [],
                "assertion_failures": [],
                "cleanup": {"status": "not attempted"}, "status": "running",
                "scope": "Only the declared fixture settings and actual consumers; not service parity."}

    def persist_evidence():
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")

    def stage(name):
        evidence["stages"].append(name)
        persist_evidence()
        print("Completed stage:", name, flush=True)

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        result = subprocess.run(["terraform", *command], cwd=root, env=env,
                                check=False, text=True, capture_output=capture)
        evidence["commands"].append({"command": ["terraform", *command], "exit_code": result.returncode})
        persist_evidence()
        if check and result.returncode:
            if capture:
                print(result.stdout, result.stderr, file=sys.stderr, flush=True)
            result.check_returncode()
        return result

    version = json.loads(terraform("version", "-json", capture=True).stdout)
    evidence["terraform"] = version["terraform_version"]
    password = "Aa1!" + secrets.token_urlsafe(28)
    name = "stackd-auth-" + uuid.uuid4().hex[:12]
    capture_directory = root / "mail"
    with ExitStack() as controllers:
        endpoint = controllers.enter_context(controller(
            args, root, extra=("-ses-email-directory", str(capture_directory))))
        variables = {"endpoint": endpoint, "name": name, "password": password, "revision": "initial"}
        def save_variables():
            (root / "local.auto.tfvars.json").write_text(json.dumps(variables))
        save_variables()
        terraform("init", "-input=false")
        idp, identity, ses, sesv2 = (client(service, endpoint) for service in
                                    ("cognito-idp", "cognito-identity", "ses", "sesv2"))
        outputs = None

        def read_outputs():
            result = json.loads(terraform("output", "-json", "application", capture=True).stdout)
            (root / "outputs.json").write_text(json.dumps(result, indent=2) + "\n")
            return result


        def recover_password(label):
            existing = set(capture_directory.rglob("*.eml"))
            idp.forgot_password(ClientId=outputs["client_id"], Username="alice")
            path, _, reset_text = captured(capture_directory, lambda path, msg, text:
                                          path not in existing
                                          and str(msg["Subject"]) == "Your password reset code"
                                          and outputs["sender"] in str(msg["To"]))
            code = re.search(r"\b[0-9]{6}\b", reset_text)
            require(code is not None, "Recovery code missing from actual MIME")
            idp.confirm_forgot_password(ClientId=outputs["client_id"], Username="alice",
                                       ConfirmationCode=code.group(0), Password=password)
            evidence["consumers"].append({"stage": label, "password_reset_mime": str(path)})
            stage(label + "/actual MIME password reset")

        refresh_failures = []

        def noop(label):
            # Consumers can change computed state; reconcile it before requiring clean plans.
            # Terraform 1.15.9 can also apply state-only refresh changes without public drift.
            terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
            stage(label + "/post-consumer refresh-only state reconciliation")
            for mode in (("-refresh-only",), ()):
                kind = "refresh" if mode else "ordinary"
                plan_file = f"{label}-{kind}-noop.tfplan"
                plan = terraform("plan", *mode, "-input=false", "-detailed-exitcode",
                                 "-out=" + plan_file, check=False)
                try:
                    require(plan.returncode == 0, f"Expected no-op plan {mode}: exit {plan.returncode}")
                except RuntimeError as error:
                    # Retain this evidenced Terraform failure without skipping independent
                    # reopen/consumer checks. It is re-raised after the ordinary teardown.
                    if mode != ("-refresh-only",) or plan.returncode != 2:
                        raise
                    actual = json.loads(terraform("show", "-json", plan_file, capture=True).stdout)
                    require(not actual.get("resource_drift")
                            and not actual.get("resource_changes")
                            and all(change["actions"] == ["no-op"]
                                    for change in actual.get("output_changes", {}).values()),
                            "Refresh failure included actual resource/output drift")
                    summary = {key: actual.get(key) for key in
                               ("terraform_version", "applyable", "complete", "errored",
                                "resource_changes", "resource_drift")}
                    summary["output_actions"] = {key: change["actions"] for key, change in
                                                  actual.get("output_changes", {}).items()}
                    (root / (plan_file + ".summary.json")).write_text(json.dumps(summary, indent=2) + "\n")
                    refresh_failures.append(error)
                    evidence["assertion_failures"].append({
                        "stage": label + "/strict refresh-only no-op", "error": str(error),
                        "plan": str(root / plan_file), "summary": str(root / (plan_file + ".summary.json"))})
                    persist_evidence()
                    print(f"FAILED strict {label} refresh-only no-op: {error}", flush=True)
                    continue
                terraform("apply", "-input=false", "-auto-approve", plan_file)
                stage(label + "/" + kind + " no-op")
        def consume(revision, label=None):
            label = label or revision
            require(outputs["data_pool_id"] == outputs["pool_id"]
                    and outputs["data_client_id"] == outputs["client_id"]
                    and outputs["data_identity"] == outputs["identity_pool"]
                    and outputs["data_group"] == "readers", "Terraform data source identity mismatch")
            pool = idp.describe_user_pool(UserPoolId=outputs["pool_id"])["UserPool"]
            mfa = idp.get_user_pool_mfa_config(UserPoolId=outputs["pool_id"])
            require(pool["MfaConfiguration"] == "OFF"
                    and mfa["SoftwareTokenMfaConfiguration"]["Enabled"] is False,
                    "Declared disabled MFA configuration was not retained")
            user = idp.admin_get_user(UserPoolId=outputs["pool_id"], Username="alice")
            attrs = {attribute["Name"]: attribute["Value"] for attribute in user["UserAttributes"]}
            require(pool["UserPoolTags"]["Revision"] == revision and attrs["name"] == revision,
                    "Pool/user update was not retained")
            group = idp.get_group(UserPoolId=outputs["pool_id"], GroupName="readers")["Group"]
            require(group["Description"] == revision, "Group update was not retained")
            auth_args = {"ClientId": outputs["client_id"], "AuthFlow": "USER_PASSWORD_AUTH",
                         "AuthParameters": {"USERNAME": "alice", "PASSWORD": password}}
            rejects(idp.initiate_auth, {"NotAuthorizedException"}, **{
                **auth_args, "AuthParameters": {"USERNAME": "alice", "PASSWORD": password + "wrong"}})
            tokens = idp.initiate_auth(**auth_args)["AuthenticationResult"]
            keys = json.loads(http_get(endpoint, "/" + outputs["pool_id"] + "/.well-known/jwks.json"))
            for token, use in ((tokens["IdToken"], "id"), (tokens["AccessToken"], "access")):
                verify_jwt(token, keys, endpoint, outputs, use)
            require(idp.get_user(AccessToken=tokens["AccessToken"])["Username"] == "alice", "Access token did not authorize GetUser")
            header, claims, signature = tokens["AccessToken"].split(".")
            forged_signature = decode64(signature)
            forged_signature = bytes([forged_signature[0] ^ 1]) + forged_signature[1:]
            forged = header + "." + claims + "." + base64.urlsafe_b64encode(forged_signature).decode().rstrip("=")
            rejects(idp.get_user, {"NotAuthorizedException"}, AccessToken=forged)
            refreshed = idp.initiate_auth(ClientId=outputs["client_id"], AuthFlow="REFRESH_TOKEN_AUTH",
                                         AuthParameters={"REFRESH_TOKEN": tokens["RefreshToken"]})["AuthenticationResult"]
            for key, use in (("IdToken", "id"), ("AccessToken", "access")):
                verify_jwt(refreshed[key], keys, endpoint, outputs, use)
                require(refreshed[key] != tokens[key], "Refresh did not issue fresh tokens")
            provider = "cognito-idp." + REGION + ".amazonaws.com/" + outputs["pool_id"]
            logins = {provider: refreshed["IdToken"]}
            identity_id = identity.get_id(IdentityPoolId=outputs["identity_pool"], Logins=logins)["IdentityId"]
            rejects(identity.get_credentials_for_identity, {"NotAuthorizedException"}, IdentityId=identity_id)
            credentials = identity.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)["Credentials"]
            require(credentials["Expiration"].timestamp() > time.time(), "Identity credentials expired")
            session = boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                                    aws_secret_access_key=credentials["SecretKey"],
                                    aws_session_token=credentials["SessionToken"], region_name=REGION)
            def authenticated(service):
                return session.client(service, endpoint_url=endpoint, config=client(service, endpoint).meta.config)
            caller = authenticated("sts").get_caller_identity()
            require(caller["Account"] == ACCOUNT and ":assumed-role/" + outputs["role_name"] + "/" in caller["Arn"],
                    "Identity credentials did not authenticate as configured IAM role")
            # These sends use actual role credentials, current IAM and shared SES identities.
            subject = "Signed Identity " + revision
            sent = authenticated("sesv2").send_email(
                FromEmailAddress=outputs["sender"], ConfigurationSetName=outputs["configuration"],
                Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
                Content={"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": "Actual " + revision + " body"}}}})
            v2_path, message, text = captured(capture_directory, lambda path, msg, text: path.stem == sent["MessageId"])
            require(str(message["Subject"]) == subject and "Actual " + revision + " body" in text,
                    "SES MIME did not retain signed application content")
            classic_sent = authenticated("ses").send_templated_email(
                Source=outputs["sender"], ConfigurationSetName=outputs["classic_config"],
                Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
                Template=outputs["template"], TemplateData=json.dumps({"name": "alice"}))
            classic_path, message, text = captured(capture_directory, lambda path, msg, text: path.stem == classic_sent["MessageId"])
            require(str(message["Subject"]) == "Lifecycle " + revision + " alice"
                    and "Captured " + revision + " email for alice." in text, "Stored template was not rendered into real MIME")
            rejects(authenticated("sesv2").delete_email_identity, {"AccessDeniedException"}, EmailIdentity=outputs["sender"])
            evidence["consumers"].append({
                "stage": label, "pool": outputs["pool_id"], "identity": identity_id,
                "role_arn": caller["Arn"], "jwks_key_ids": [key["kid"] for key in keys["keys"]],
                "sesv2_mime": str(v2_path), "classic_mime": str(classic_path),
                "checks": ["signed pool/user/group reads", "wrong-password denial", "RS256 JWT/JWKS",
                           "forged signature rejection locally and by GetUser", "refresh JWTs",
                           "authenticated Identity role credentials", "mail-only IAM denial",
                           "actual classic/v2 MIME and stored template rendering"]})
            stage(label + "/signed authentication and MIME consumers")
            print(f"Consumed {label}: password denial, RS256 JWT/JWKS, refresh, Identity role credentials, classic/v2 MIME", flush=True)

        try:
            terraform("apply", "-input=false", "-auto-approve")
            outputs = read_outputs()
            verification_path, _, text = captured(capture_directory, lambda path, msg, text:
                                  str(msg["Subject"]) == "Amazon SES Email Address Verification Request"
                                  and outputs["sender"] in str(msg["To"]))
            link = re.search(r"http://[^\s<>]+", text)
            require(link is not None, "Verification link missing from actual MIME")
            target = urlsplit(link.group(0))
            require(target.scheme == "http" and target.netloc == urlsplit(endpoint).netloc
                    and target.path == "/_stackd/ses/verify-email-identity", "Refusing external verification link")
            http_get(endpoint, target.path + "?" + target.query)
            require(sesv2.get_email_identity(EmailIdentity=outputs["sender"])["VerifiedForSendingStatus"], "Verification did not commit")
            evidence["consumers"].append({"stage": "initial", "verification_mime": str(verification_path),
                                          "check": "One-use local verification link consumed from actual private MIME"})
            stage("create/read and actual MIME SES verification")
            # Capture Cognito's real managed recovery mail; never synthesize a code.
            recover_password("initial")
            # Reconcile computed verification state and user count before no-op checks.
            terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
            outputs = read_outputs()
            consume("initial")
            state = json.loads(terraform("show", "-json", capture=True).stdout)
            resources = [resource for resource in state["values"]["root_module"]["resources"] if resource["mode"] == "managed"]
            imports = {}
            for resource in resources:
                identifier = resource["values"]["id"]
                if resource["type"] == "aws_cognito_user_pool_client":
                    identifier = outputs["pool_id"] + "/" + identifier
                imports[resource["address"]] = identifier
            (root / "imports.json").write_text(json.dumps(imports, indent=2) + "\n")
            for address, identifier in imports.items():
                terraform("state", "rm", address)
                terraform("import", "-input=false", address, identifier)
            # Passwords are write-only; restore their desired Terraform state after import.
            terraform("apply", "-input=false", "-auto-approve")
            outputs = read_outputs()
            stage("import every managed resource and reconcile write-only password")
            variables["revision"] = "updated"
            save_variables()
            terraform("apply", "-input=false", "-auto-approve")
            outputs = read_outputs()
            consume("updated")
            stage("update")
            noop("updated")
            controllers.close()  # Stop the real controller and close its SQLite database.
            shutil.copyfile(root / "stackd.log", root / "stackd.before-reopen.log")
            endpoint = controllers.enter_context(controller(
                args, root, extra=("-ses-email-directory", str(capture_directory))))
            stage("SQLite controller stop/reopen")
            outputs = read_outputs()
            require(sesv2.get_email_identity(EmailIdentity=outputs["sender"])["VerifiedForSendingStatus"],
                    "SQLite reopen lost the actual email verification")
            recover_password("reopened")
            consume("updated", "reopened")
            noop("reopened")
            if refresh_failures:
                raise refresh_failures[0]
            evidence["status"] = "passed"
        except BaseException as error:
            evidence["status"] = "failed"
            evidence["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            try:
                # Keep ordinary Terraform teardown and signed absence checks on failure too.
                terraform("destroy", "-input=false", "-auto-approve")
                evidence["cleanup"]["destroy"] = "passed"
                if outputs is not None:
                    expect_missing(idp.describe_user_pool, {"ResourceNotFoundException"}, UserPoolId=outputs["pool_id"])
                    expect_missing(identity.describe_identity_pool, {"ResourceNotFoundException"}, IdentityPoolId=outputs["identity_pool"])
                    expect_missing(sesv2.get_email_identity, {"NotFoundException"}, EmailIdentity=outputs["sender"])
                    expect_missing(sesv2.get_configuration_set, {"NotFoundException"}, ConfigurationSetName=outputs["configuration"])
                    expect_missing(ses.describe_configuration_set, {"ConfigurationSetDoesNotExist"}, ConfigurationSetName=outputs["classic_config"])
                    expect_missing(ses.get_template, {"TemplateDoesNotExist"}, TemplateName=outputs["template"])
                    expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"}, RoleName=outputs["role_name"])
                    evidence["cleanup"]["signed_absence"] = "passed"
                state = json.loads(terraform("show", "-json", capture=True).stdout)
                retained = state.get("values", {}).get("root_module", {}).get("resources", [])
                evidence["cleanup"]["retained_state_addresses"] = [resource["address"] for resource in retained]
                require(not retained, "State retained resources after destroy")
                evidence["cleanup"]["status"] = "passed"
                stage("ordinary destroy/signed absence/empty state")
            except BaseException as error:
                evidence["cleanup"]["status"] = "failed"
                evidence["cleanup"]["error"] = f"{type(error).__name__}: {error}"
                evidence["status"] = "failed"
                raise
            finally:
                persist_evidence()
    print(f"Auth lifecycle complete; private owned artifacts retained at {root}")


if __name__ == "__main__":
    main()
