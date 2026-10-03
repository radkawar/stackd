#!/usr/bin/env python3
"""Run actual stackd, exchange Cognito tokens with SDK, sign S3, then restart SQLite."""
import argparse
import json
import os
import secrets
import signal
import socket
import subprocess
import tempfile
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    binary = os.path.abspath(args.binary)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    account = "123456789012"
    configuration = Config(retries={"max_attempts": 0}, s3={"addressing_style": "path"})

    def client(service, credentials=None):
        credentials = credentials or {"AccessKeyId": account, "SecretKey": "test", "SessionToken": ""}
        return boto3.client(service, region_name="us-east-1", endpoint_url=endpoint, aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretKey"], aws_session_token=credentials["SessionToken"], config=configuration)

    def rejects(code, fn):
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != code:
                raise
        else:
            raise RuntimeError("expected " + code)

    process = None
    observations = []
    with tempfile.TemporaryDirectory(prefix="stackd-cognitoidentity-") as directory:
        with open(os.path.join(directory, "server.log"), "w+", encoding="utf-8") as log:
            def stop():
                nonlocal process
                if process is not None:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=30)
                    if process.returncode != 0:
                        raise RuntimeError("controller failed to stop normally")
                    process = None

            def start():
                nonlocal process
                process = subprocess.Popen([binary, "-listen", f"127.0.0.1:{port}", "-database", os.path.join(directory, "state.sqlite"), "-account-id", account], stdout=log, stderr=log)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            return
                    except OSError:
                        time.sleep(0.05)
                raise RuntimeError("controller did not bind")

            try:
                start()
                ci, idp, iam, s3 = (client(service) for service in ("cognito-identity", "cognito-idp", "iam", "s3"))
                up = idp.create_user_pool(PoolName="identity-smoke", UserPoolTier="LITE")["UserPool"]["Id"]
                app = idp.create_user_pool_client(UserPoolId=up, ClientName="identity-app", ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])["UserPoolClient"]["ClientId"]
                idp.admin_create_user(UserPoolId=up, Username="alice", MessageAction="SUPPRESS")
                password = secrets.token_urlsafe(24) + "Aa1!"
                idp.admin_set_user_password(UserPoolId=up, Username="alice", Password=password, Permanent=True)
                auth = idp.initiate_auth(ClientId=app, AuthFlow="USER_PASSWORD_AUTH", AuthParameters={"USERNAME": "alice", "PASSWORD": password})["AuthenticationResult"]
                provider = "cognito-idp.us-east-1.amazonaws.com/" + up
                pool = ci.create_identity_pool(IdentityPoolName="identity-smoke", AllowUnauthenticatedIdentities=True, CognitoIdentityProviders=[{"ProviderName": provider, "ClientId": app, "ServerSideTokenCheck": True}])["IdentityPoolId"]
                trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool}, "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": ["authenticated", "unauthenticated"]}}}]}
                role = iam.create_role(RoleName="identity-smoke", AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
                bucket = "identity-smoke-bucket"
                s3.create_bucket(Bucket=bucket)
                policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + bucket + "/*"}]}
                iam.put_role_policy(RoleName="identity-smoke", PolicyName="write", PolicyDocument=json.dumps(policy))
                ci.set_identity_pool_roles(IdentityPoolId=pool, Roles={"authenticated": role, "unauthenticated": role})
                guest = ci.get_id(IdentityPoolId=pool)["IdentityId"]
                logins = {provider: auth["IdToken"]}
                authenticated = ci.get_id(IdentityPoolId=pool, Logins=logins)["IdentityId"]
                guest_credentials = ci.get_credentials_for_identity(IdentityId=guest)["Credentials"]
                credentials = ci.get_credentials_for_identity(IdentityId=authenticated, Logins=logins)["Credentials"]
                client("s3", guest_credentials).put_object(Bucket=bucket, Key="guest", Body=b"guest bytes")
                client("s3", credentials).put_object(Bucket=bucket, Key="authenticated", Body=b"authenticated bytes")
                assert s3.get_object(Bucket=bucket, Key="guest")["Body"].read() == b"guest bytes"
                assert s3.get_object(Bucket=bucket, Key="authenticated")["Body"].read() == b"authenticated bytes"
                observations.append("guest and user-pool ID-token SDK credentials signed actual S3 writes")
                tag_args = {"IdentityPoolId": pool, "IdentityProviderName": provider}
                defaults = ci.set_principal_tag_attribute_map(**tag_args, UseDefaults=True)
                assert defaults["PrincipalTags"] == {"client": "aud", "username": "sub"}
                ci.set_principal_tag_attribute_map(**tag_args, UseDefaults=False, PrincipalTags={"application": "aud"})
                rejects("InvalidIdentityPoolConfigurationException", lambda: ci.get_credentials_for_identity(IdentityId=authenticated, Logins=logins))
                trust["Statement"][0]["Action"] = ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]
                iam.update_assume_role_policy(RoleName="identity-smoke", PolicyDocument=json.dumps(trust))
                tagged = ci.get_credentials_for_identity(IdentityId=authenticated, Logins=logins)["Credentials"]
                bucket_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + bucket + "/tagged", "Condition": {"StringNotEquals": {"aws:PrincipalTag/application": app}}}]}
                s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))
                rejects("AccessDenied", lambda: client("s3", credentials).put_object(Bucket=bucket, Key="tagged", Body=b"untagged"))
                client("s3", tagged).put_object(Bucket=bucket, Key="tagged", Body=b"tagged")
                assert s3.get_object(Bucket=bucket, Key="tagged")["Body"].read() == b"tagged"
                observations.append("native-calibrated defaults; missing TagSession denied; verified aud principal tag permitted actual resource-policy S3 write")
                stop()
                start()
                assert ci.get_id(IdentityPoolId=pool, Logins=logins)["IdentityId"] == authenticated
                client("s3", credentials).put_object(Bucket=bucket, Key="restart", Body=b"retained credential")
                assert s3.get_object(Bucket=bucket, Key="restart")["Body"].read() == b"retained credential"
                observations.append("SQLite process restart retained pool, login identity, user-pool signing keys and issued credentials")
                assert ci.get_principal_tag_attribute_map(**tag_args)["PrincipalTags"] == {"application": "aud"}
                ci.set_principal_tag_attribute_map(**tag_args, UseDefaults=False, PrincipalTags={"application": "sub"})
                remapped = ci.get_credentials_for_identity(IdentityId=authenticated, Logins=logins)["Credentials"]
                rejects("AccessDenied", lambda: client("s3", remapped).put_object(Bucket=bucket, Key="tagged", Body=b"remapped"))
                client("s3", tagged).put_object(Bucket=bucket, Key="tagged", Body=b"old session retained")
                ci.set_principal_tag_attribute_map(**tag_args, UseDefaults=False, PrincipalTags={})
                rejects("ResourceNotFoundException", lambda: ci.get_principal_tag_attribute_map(**tag_args))
                reset = ci.get_credentials_for_identity(IdentityId=authenticated, Logins=logins)["Credentials"]
                rejects("AccessDenied", lambda: client("s3", reset).put_object(Bucket=bucket, Key="tagged", Body=b"reset"))
                observations.append("principal map survived restart; remapping/reset changed only fresh credentials and retained session tags remained authoritative")
                rejects("NotAuthorizedException", lambda: ci.get_credentials_for_identity(IdentityId=authenticated))
                idp.admin_user_global_sign_out(UserPoolId=up, Username="alice")
                rejects("NotAuthorizedException", lambda: ci.get_credentials_for_identity(IdentityId=authenticated, Logins=logins))
                client("s3", tagged).put_object(Bucket=bucket, Key="tagged", Body=b"issued before revocation")
                observations.append("missing login and revoked user-pool token rejected")
                policy["Statement"][0]["Effect"] = "Deny"
                iam.put_role_policy(RoleName="identity-smoke", PolicyName="write", PolicyDocument=json.dumps(policy))
                rejects("AccessDenied", lambda: client("s3", credentials).put_object(Bucket=bucket, Key="denied", Body=b"must not exist"))
                trust["Statement"][0]["Effect"] = "Deny"
                iam.update_assume_role_policy(RoleName="identity-smoke", PolicyDocument=json.dumps(trust))
                rejects("InvalidIdentityPoolConfigurationException", lambda: ci.get_credentials_for_identity(IdentityId=guest))
                observations.append("current IAM policy rejects issued credentials; current trust rejects exchange")
                ci.delete_identity_pool(IdentityPoolId=pool)
                idp.delete_user_pool(UserPoolId=up)
                iam.delete_role_policy(RoleName="identity-smoke", PolicyName="write")
                iam.delete_role(RoleName="identity-smoke")
                s3.delete_bucket_policy(Bucket=bucket)
                for key in ("guest", "authenticated", "restart", "tagged"):
                    s3.delete_object(Bucket=bucket, Key=key)
                s3.delete_bucket(Bucket=bucket)
                observations.append("exact local resources deleted; disposable database removed")
            finally:
                stop()
    print(json.dumps({"observations": observations, "controller_exits": [0, 0]}, indent=2))


if __name__ == "__main__":
    main()
