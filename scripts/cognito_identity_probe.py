#!/usr/bin/env python3
"""Exact-owned native Cognito Identity enhanced-flow calibration; no secrets emitted."""
import argparse
import json
import secrets
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("unexpected native account")
    ci, idp, iam = (session.client(n) for n in ("cognito-identity", "cognito-idp", "iam"))
    name = "stackd-next-cognitoidentity-" + secrets.token_hex(5)
    pool = user_pool = role = None
    observations = {"captured_at": datetime.now(timezone.utc).isoformat(), "account": identity["Account"], "region": region, "name": name, "observations": [], "cleanup": []}

    def record(case, result):
        observations["observations"].append({"case": case, **result})

    def error_case(case, fn):
        try:
            fn()
        except ClientError as exc:
            record(case, {"error": exc.response["Error"]["Code"]})
        else:
            raise RuntimeError(case + " unexpectedly succeeded")

    def exchange(identity_id, logins=None):
        request = {"IdentityId": identity_id}
        if logins:
            request["Logins"] = logins
        return ci.get_credentials_for_identity(**request)["Credentials"]

    def client(credentials, service):
        return boto3.client(service, region_name=region, aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretKey"], aws_session_token=credentials["SessionToken"])

    try:
        user_pool = idp.create_user_pool(PoolName=name)["UserPool"]["Id"]
        app = idp.create_user_pool_client(UserPoolId=user_pool, ClientName=name, ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])["UserPoolClient"]["ClientId"]
        idp.admin_create_user(UserPoolId=user_pool, Username="probe", MessageAction="SUPPRESS")
        password = secrets.token_urlsafe(28) + "!aA1"
        idp.admin_set_user_password(UserPoolId=user_pool, Username="probe", Password=password, Permanent=True)
        auth = idp.initiate_auth(ClientId=app, AuthFlow="USER_PASSWORD_AUTH", AuthParameters={"USERNAME": "probe", "PASSWORD": password})["AuthenticationResult"]
        provider = "cognito-idp." + region + ".amazonaws.com/" + user_pool
        pool = ci.create_identity_pool(IdentityPoolName=name, AllowUnauthenticatedIdentities=True, CognitoIdentityProviders=[{"ProviderName": provider, "ClientId": app, "ServerSideTokenCheck": True}], IdentityPoolTags={"stackd-probe": name})["IdentityPoolId"]
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool}, "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": ["authenticated", "unauthenticated"]}}}]}
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        iam.put_role_policy(RoleName=name, PolicyName="probe", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}))
        ci.set_identity_pool_roles(IdentityPoolId=pool, Roles={"authenticated": role, "unauthenticated": role})
        guest = ci.get_id(IdentityPoolId=pool)["IdentityId"]
        logins = {provider: auth["IdToken"]}
        signed = ci.get_id(IdentityPoolId=pool, Logins=logins)["IdentityId"]
        assert ci.get_id(IdentityPoolId=pool, Logins=logins)["IdentityId"] == signed
        record("authenticated_getid_repeat", {"same_identity": True})
        for attempt in range(12):
            try:
                guest_credentials = exchange(guest)
                client(guest_credentials, "s3").list_buckets()
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("InvalidIdentityPoolConfigurationException", "AccessDenied") or attempt == 11:
                    raise
                time.sleep(5)
        record("guest_signed_s3", {"success": True})
        credentials = exchange(signed, logins)
        client(credentials, "s3").list_buckets()
        record("authenticated_signed_s3", {"success": True})
        error_case("authenticated_without_login", lambda: exchange(signed))
        idp.admin_user_global_sign_out(UserPoolId=user_pool, Username="probe")
        error_case("server_side_revocation", lambda: exchange(signed, logins))
        deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}
        iam.put_role_policy(RoleName=name, PolicyName="probe", PolicyDocument=json.dumps(deny))
        for attempt in range(12):
            try:
                client(guest_credentials, "s3").list_buckets()
            except ClientError as exc:
                record("issued_credentials_current_policy", {"error": exc.response["Error"]["Code"]})
                break
            if attempt == 11:
                raise RuntimeError("role policy deny did not propagate")
            time.sleep(5)
        trust["Statement"][0]["Effect"] = "Deny"
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
        for attempt in range(12):
            try:
                exchange(guest)
            except ClientError as exc:
                record("current_trust_rejection", {"error": exc.response["Error"]["Code"]})
                break
            if attempt == 11:
                raise RuntimeError("trust deny did not propagate")
            time.sleep(5)
    finally:
        if pool:
            ci.delete_identity_pool(IdentityPoolId=pool)
            observations["cleanup"].append({"resource": "identity_pool", "id": pool, "deleted": True})
        if user_pool:
            idp.delete_user_pool(UserPoolId=user_pool)
            observations["cleanup"].append({"resource": "user_pool", "id": user_pool, "deleted": True})
        if role:
            iam.delete_role_policy(RoleName=name, PolicyName="probe")
            iam.delete_role(RoleName=name)
            observations["cleanup"].append({"resource": "role_and_inline_policy", "arn": role, "deleted": True})
        with open(args.output, "w", encoding="utf-8") as output:
            json.dump(observations, output, indent=2)
            output.write("\n")
    print(json.dumps(observations, indent=2))


if __name__ == "__main__":
    main()
