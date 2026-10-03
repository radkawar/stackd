#!/usr/bin/env python3
"""Exercise unmodified aws sso login against the actual retained stackd process.

Waits for a real browser at the printed verification URL. The browser automation
reads private login.json; no tokens, passwords or role keys enter the report.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pty
import select
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--aws-cli", default="aws", help="Actual AWS CLI executable; avoid HOME-dependent version-manager shims.")
    parser.add_argument("--pkce", action="store_true", help="Exercise the unmodified AWS CLI default authorization-code/S256 flow.")
    args = parser.parse_args()
    state = Path(args.state_directory).resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = str(Path(args.binary).resolve())
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    endpoint = f"https://127.0.0.1:{port}"
    certificate = state / "certificate.pem"
    private_key = state / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost", "-keyout", str(private_key), "-out", str(certificate)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    private_key.chmod(0o600)
    tls_context = ssl.create_default_context(cafile=str(certificate))
    account = "123456789012"
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update(HOME=str(state), AWS_CONFIG_FILE=str(state / "config"), AWS_SHARED_CREDENTIALS_FILE=str(state / "credentials"), AWS_ENDPOINT_URL=endpoint, AWS_CA_BUNDLE=str(certificate), AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off")
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=3, read_timeout=15, s3={"addressing_style": "path"})
    process = None
    server_log = None
    client_id = ""
    observations = []
    exits = []

    def client(service, owner=account, credential=None):
        credential = credential or {"AccessKeyId": owner, "SecretAccessKey": "test", "SessionToken": ""}
        return boto3.client(service, endpoint_url=endpoint, verify=str(certificate), region_name="us-east-1", aws_access_key_id=credential["AccessKeyId"], aws_secret_access_key=credential["SecretAccessKey"], aws_session_token=credential["SessionToken"], config=config)

    def control(path, body):
        request = urllib.request.Request(endpoint + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=20, context=tls_context) as response:
            return response.read()

    def advance(duration):
        control("/_stackd/clock", {"advance": duration})

    def start():
        nonlocal process, server_log
        server_log = (state / f"controller-{len(exits)}.log").open("wb")
        command = [binary, "-listen", f"127.0.0.1:{port}", "-public-endpoint", endpoint, "-tls-cert", str(certificate), "-tls-key", str(private_key), "-account-id", account, "-database", str(state / "state.sqlite"), "-clock-start", datetime.now(timezone.utc).isoformat()]
        if client_id:
            command += ["-sso-user-pool-client-id", client_id]
        process = subprocess.Popen(command, env=env, stdout=server_log, stderr=server_log)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("controller exited; inspect private controller log")
            try:
                with urllib.request.urlopen(endpoint + "/_stackd/health", timeout=1, context=tls_context) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("controller did not become ready")

    def stop():
        nonlocal process, server_log
        if process is not None:
            process.terminate()
            code = process.wait(timeout=30)
            exits.append(code)
            process = None
            if code != 0:
                raise RuntimeError("controller shutdown failed")
        if server_log:
            server_log.close()
            server_log = None

    def cli(profile, *command, denied=False):
        result = subprocess.run([args.aws_cli, "--profile", profile, "--endpoint-url", endpoint, "--no-cli-pager", *command], env=env, text=True, capture_output=True, timeout=60)
        if denied:
            if result.returncode == 0 or "AccessDenied" not in result.stderr:
                raise AssertionError("expected current IAM AccessDenied from actual CLI: " + result.stderr)
            return None
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def rejects(code, fn):
        try:
            fn()
        except ClientError as error:
            if error.response["Error"]["Code"] != code:
                raise
        else:
            raise AssertionError("expected " + code)

    try:
        start()
        idp, admin, directory, iam, org = (client(v) for v in ("cognito-idp", "sso-admin", "identitystore", "iam", "organizations"))
        pool = idp.create_user_pool(PoolName="identity-center-login", UserPoolTier="LITE")["UserPool"]["Id"]
        client_id = idp.create_user_pool_client(UserPoolId=pool, ClientName="identity-center-browser", ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])["UserPoolClient"]["ClientId"]
        username = "alice"
        password = secrets.token_urlsafe(24) + "Aa1!"
        idp.admin_create_user(UserPoolId=pool, Username=username, MessageAction="SUPPRESS")
        idp.admin_set_user_password(UserPoolId=pool, Username=username, Password=password, Permanent=True)
        instance = admin.create_instance(Name="identity-center-proof")["InstanceArn"]
        store = admin.describe_instance(InstanceArn=instance)["IdentityStoreId"]
        user = directory.create_user(IdentityStoreId=store, UserName=username, DisplayName="Alice", Name={"GivenName": "Alice", "FamilyName": "Proof"})["UserId"]
        group = directory.create_group(IdentityStoreId=store, DisplayName="Developers")["GroupId"]
        membership = directory.create_group_membership(IdentityStoreId=store, GroupId=group, MemberId={"UserId": user})["MembershipId"]
        org.create_organization(FeatureSet="ALL")
        org.enable_aws_service_access(ServicePrincipal="sso.amazonaws.com")
        request = org.create_account(AccountName="sso-member", Email="sso-member@example.invalid")["CreateAccountStatus"]["Id"]
        for _ in range(30):
            control("/_stackd/jobs/drain?limit=1024", {})
            status = org.describe_create_account_status(CreateAccountRequestId=request)["CreateAccountStatus"]
            if status["State"] == "SUCCEEDED":
                break
            if status["State"] == "FAILED":
                raise AssertionError("local account provisioning failed: " + status.get("FailureReason", ""))
            advance("1s")
        else:
            raise AssertionError("local account provisioning did not finish")
        member = status["AccountId"]
        permission = admin.create_permission_set(InstanceArn=instance, Name="Developer", SessionDuration="PT1H")["PermissionSet"]["PermissionSetArn"]
        allow = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": "*"}]}
        admin.put_inline_policy_to_permission_set(InstanceArn=instance, PermissionSetArn=permission, InlinePolicy=json.dumps(allow))
        assignment = dict(InstanceArn=instance, PermissionSetArn=permission, TargetType="AWS_ACCOUNT")
        first = admin.create_account_assignment(**assignment, TargetId=account, PrincipalType="GROUP", PrincipalId=group)["AccountAssignmentCreationStatus"]
        second = admin.create_account_assignment(**assignment, TargetId=member, PrincipalType="USER", PrincipalId=user)["AccountAssignmentCreationStatus"]
        assert first["Status"] == second["Status"] == "SUCCEEDED"
        old_role = next(v for v in iam.list_roles()["Roles"] if v["RoleName"].startswith("AWSReservedSSO_Developer_"))
        buckets = {account: "identity-center-owner-proof", member: "identity-center-member-proof"}
        for owner, bucket in buckets.items():
            client("s3", owner).create_bucket(Bucket=bucket)
        start_url = "https://identitycenter.amazonaws.com/" + instance.rsplit("/", 1)[1]
        text = f"[sso-session local]\nsso_start_url = {start_url}\nsso_region = us-east-1\nsso_registration_scopes = sso:account:access\n"
        for name, owner in (("identity-owner", account), ("identity-member", member)):
            text += f"\n[profile {name}]\nsso_session = local\nsso_account_id = {owner}\nsso_role_name = Developer\nregion = us-east-1\n"
        (state / "config").write_text(text)
        (state / "body").write_bytes(b"real aws sso role credentials")
        (state / "login.json").write_text(json.dumps({"username": username, "password": password}))
        (state / "login.json").chmod(0o600)
        stop()
        start()
        master, terminal = pty.openpty()
        login_command = [args.aws_cli, "--endpoint-url", endpoint, "--no-cli-pager", "sso", "login", "--profile", "identity-owner", "--no-browser"]
        if not args.pkce:
            login_command.append("--use-device-code")
        login = subprocess.Popen(login_command, env=env, stdin=subprocess.DEVNULL, stdout=terminal, stderr=terminal)
        os.close(terminal)
        prompt = ""
        verification = None
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                try:
                    data = os.read(master, 8192)
                except OSError:
                    break
                prompt += data.decode()
                pattern = r"https?://[^\s]+/authorize\?[^\s]+" if args.pkce else r"https?://[^\s]+/_stackd/sso/device\?user_code=[A-Z0-9-]+"
                match = re.search(pattern, prompt)
                if match:
                    verification = match.group(0)
                    break
            if login.poll() is not None:
                break
        if not verification:
            failed_status = login.poll()
            login.terminate()
            login.wait(timeout=10)
            os.close(master)
            raise RuntimeError(f"actual aws sso login did not expose a verification URL (status {failed_status}): " + prompt)
        # Registered clients (and device requests in device mode) survive restart.
        stop()
        start()
        (state / "browser.json").write_text(json.dumps({"url": verification}))
        print("BROWSER_URL=" + verification, flush=True)
        ticking = threading.Event()
        def tick():
            while not ticking.wait(1):
                advance("1s")
        ticker = threading.Thread(target=tick, daemon=True)
        ticker.start()
        login.wait(timeout=600)
        remaining = ""
        while True:
            try:
                data = os.read(master, 8192)
            except OSError:
                break
            if not data:
                break
            remaining += data.decode()
        os.close(master)
        ticking.set()
        ticker.join()
        if login.returncode != 0 or "Successfully logged into Start URL" not in remaining:
            raise RuntimeError("actual aws sso login failed: " + remaining)
        observations.append("unmodified aws sso login default PKCE completed through real browser Cognito password authorization and the CLI loopback receiver; registration survived process restart" if args.pkce else "unmodified aws sso login --use-device-code completed through real browser Cognito password authorization; pending device survived process restart")
        for profile, owner in (("identity-owner", account), ("identity-member", member)):
            identity = cli(profile, "sts", "get-caller-identity")
            assert identity["Account"] == owner and ":assumed-role/AWSReservedSSO_Developer_" in identity["Arn"]
            cli(profile, "s3api", "put-object", "--bucket", buckets[owner], "--key", "cli", "--body", str(state / "body"))
            assert client("s3", owner).get_object(Bucket=buckets[owner], Key="cli")["Body"].read() == b"real aws sso role credentials"
        observations.append("real CLI resolved permission-set roles in owner and organization-member accounts and signed actual S3 writes")
        exported = cli("identity-member", "configure", "export-credentials", "--format", "process")
        cached = next(json.loads(p.read_text()) for p in (state / ".aws/sso/cache").glob("*.json") if "accessToken" in json.loads(p.read_text()))
        access = cached["accessToken"]
        portal, oidc = client("sso"), client("sso-oidc")
        assert {v["accountId"] for v in portal.list_accounts(accessToken=access)["accountList"]} == {account, member}
        stop()
        start()
        assert len(portal.list_accounts(accessToken=access)["accountList"]) == 2
        cli("identity-member", "s3api", "put-object", "--bucket", buckets[member], "--key", "restart", "--body", str(state / "body"))
        observations.append("SQLite restart retained actual access/role credentials, assignments, directory and IAM role incarnation")
        allow["Statement"][0]["Effect"] = "Deny"
        admin.put_inline_policy_to_permission_set(InstanceArn=instance, PermissionSetArn=permission, InlinePolicy=json.dumps(allow))
        # Pending policy edits do not silently alter the provisioned IAM role.
        cli("identity-member", "s3api", "put-object", "--bucket", buckets[member], "--key", "pending", "--body", str(state / "body"))
        admin.provision_permission_set(InstanceArn=instance, PermissionSetArn=permission, TargetType="ALL_PROVISIONED_ACCOUNTS")
        cli("identity-owner", "s3api", "put-object", "--bucket", buckets[account], "--key", "denied", "--body", str(state / "body"), denied=True)
        cli("identity-member", "s3api", "put-object", "--bucket", buckets[member], "--key", "denied", "--body", str(state / "body"), denied=True)
        allow["Statement"][0]["Effect"] = "Allow"
        admin.put_inline_policy_to_permission_set(InstanceArn=instance, PermissionSetArn=permission, InlinePolicy=json.dumps(allow))
        admin.provision_permission_set(InstanceArn=instance, PermissionSetArn=permission, TargetType="ALL_PROVISIONED_ACCOUNTS")
        observations.append("explicit permission-set provisioning updated current policies for already-issued real CLI credentials in both accounts")
        directory.delete_group_membership(IdentityStoreId=store, MembershipId=membership)
        rejects("UnauthorizedException", lambda: portal.get_role_credentials(accessToken=access, accountId=account, roleName="Developer"))
        assert len(portal.list_accounts(accessToken=access)["accountList"]) == 1
        rejects("ResourceNotFoundException", lambda: client("identitystore", member).describe_user(IdentityStoreId=store, UserId=user))
        observations.append("current group membership revokes new owner-role exchange without removing independent member-account access; foreign directory scope rejected")
        admin.delete_account_assignment(**assignment, TargetId=account, PrincipalType="GROUP", PrincipalId=group)
        admin.create_account_assignment(**assignment, TargetId=account, PrincipalType="USER", PrincipalId=user)
        new_role = next(v for v in iam.list_roles()["Roles"] if v["RoleName"].startswith("AWSReservedSSO_Developer_"))
        assert new_role["RoleId"] != old_role["RoleId"] and new_role["RoleName"] != old_role["RoleName"]
        observations.append("last assignment retired actual reserved role; re-assignment created a distinct retained role incarnation")
        cli("identity-owner", "sso", "logout")
        rejects("UnauthorizedException", lambda: portal.list_accounts(accessToken=access))
        if cached.get("refreshToken"):
            rejects("InvalidGrantException", lambda: oidc.create_token(clientId=cached["clientId"], clientSecret=cached["clientSecret"], grantType="refresh_token", refreshToken=cached["refreshToken"]))
        client("s3", credential=exported).put_object(Bucket=buckets[member], Key="after-logout", Body=b"IAM role session remains live")
        observations.append("actual aws sso logout invalidated server-side sign-in and refresh; already-issued IAM role session remained usable as documented")
        registration = oidc.register_client(clientName="expiry-proof", clientType="public", scopes=["sso:account:access"])
        authorization = oidc.start_device_authorization(clientId=registration["clientId"], clientSecret=registration["clientSecret"], startUrl=start_url)
        token_args = dict(clientId=registration["clientId"], clientSecret=registration["clientSecret"], grantType="urn:ietf:params:oauth:grant-type:device_code", deviceCode=authorization["deviceCode"])
        rejects("AuthorizationPendingException", lambda: oidc.create_token(**token_args))
        rejects("SlowDownException", lambda: oidc.create_token(**token_args))
        advance("601s")
        rejects("ExpiredTokenException", lambda: oidc.create_token(**token_args))
        advance("2h")
        rejects("ExpiredToken", lambda: client("s3", credential=exported).put_object(Bucket=buckets[member], Key="expired", Body=b"must not exist"))
        observations.append("actual OIDC SDK returned pending, slow_down and expired device errors; shared clock expired issued AWS role credentials")
        for owner, principal_type, principal in ((account, "USER", user), (member, "USER", user)):
            admin.delete_account_assignment(**assignment, TargetId=owner, PrincipalType=principal_type, PrincipalId=principal)
        admin.delete_permission_set(InstanceArn=instance, PermissionSetArn=permission)
        admin.delete_instance(InstanceArn=instance)
        rejects("ResourceNotFoundException", lambda: directory.describe_user(IdentityStoreId=store, UserId=user))
        idp.delete_user_pool(UserPoolId=pool)
        for owner, bucket in buckets.items():
            s3 = client("s3", owner)
            for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        observations.append("owned instance, directory rows, permission sets, reserved roles, Cognito pool and S3 bytes deleted; disposable local organization state removed with database")
    finally:
        stop()
    report = {"observations": observations, "controller_exits": exits, "native_aws_mutations": False, "actual_cli": subprocess.check_output([args.aws_cli, "--version"], text=True).strip()}
    (state / "evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
