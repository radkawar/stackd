#!/usr/bin/env python3
"""Capture bounded native Cognito login contracts without outbound messages.

Requires AWS CLI credentials for --account and Python cryptography + pycognito.
Uses pycognito's existing SRP implementation, not a probe-specific SRP algorithm.
Creates only owned pools/clients/users; --cleanup resumes owned-pool cleanup.
The rotation slice upgrades one pool to Essentials and can incur one user's MAU
charge. Other slices request Lite. No message delivery, domains, MFA or advanced
security add-ons. Alias cases use reserved example.com addresses and SUPPRESS.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import importlib.metadata
import json
import os
from functools import partial
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.request
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pycognito.aws_srp import AWSSRP

from aws_cli import observe
from cognito_rotation_probe import rotation_slice
from signed_requests import signed_post

REGION = "us-east-1"  # shared signed_post currently signs this region
HOST = "cognito-idp." + REGION + ".amazonaws.com"
TARGET = "AWSCognitoIdentityProviderService."
SENSITIVE = {"TemporaryPassword", "Password", "PASSWORD", "NEW_PASSWORD", "ClientSecret",
             "SECRET_HASH", "AccessToken", "IdToken", "RefreshToken", "REFRESH_TOKEN", "Token",
             "Session", "SECRET_BLOCK", "PASSWORD_CLAIM_SECRET_BLOCK", "PASSWORD_CLAIM_SIGNATURE"}
DOC_BASE = "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def secret_hash(username, client, secret):
    return base64.b64encode(hmac.new(secret.encode(), (username + client).encode(), hashlib.sha256).digest()).decode()


def decode64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def jwt_projection(token, jwks, issuer, client, token_use):
    """Verify signature separately from claim checks; neither checks revocation."""
    header_part, claims_part, signature_part = token.split(".")
    header, claims = json.loads(decode64(header_part)), json.loads(decode64(claims_part))
    key = next(item for item in jwks["keys"] if item["kid"] == header["kid"])
    public = rsa.RSAPublicNumbers(int.from_bytes(decode64(key["e"])), int.from_bytes(decode64(key["n"]))).public_key()
    valid = False
    if header["alg"] == "RS256" and key["kty"] == "RSA":
        try:
            public.verify(decode64(signature_part), (header_part + "." + claims_part).encode(), padding.PKCS1v15(), hashes.SHA256())
            valid = True
        except InvalidSignature:
            pass
    return {"token_sha256": hashlib.sha256(token.encode()).hexdigest(), "header": header, "claims": claims,
            "signature_verified": valid, "rsa_bits": public.key_size,
            "claim_checks": {"issuer": claims.get("iss") == issuer, "token_use": claims.get("token_use") == token_use,
                             "client": claims.get("client_id" if token_use == "access" else "aud") == client,
                             "unexpired_at_capture": claims.get("exp", 0) > time.time()},
            "revocation_checked": False, "verified_at": now()}


def raw_call(operation, parameters, mode, environment=None):
    body = json.dumps(parameters).encode()
    headers = {"content-type": "application/x-amz-json-1.1", "x-amz-target": TARGET + operation}
    if mode == "signed":
        response = signed_post(HOST, "cognito-idp", body, headers, environment)
        status, response_body, request_id = response.status, response.body, response.request_id
    else:
        if mode == "invalid-signature":
            instant = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            headers.update({"x-amz-date": instant, "authorization": "AWS4-HMAC-SHA256 Credential=AKIAINVALIDPROBE00000/" + instant[:8] + "/" + REGION + "/cognito-idp/aws4_request, SignedHeaders=host;x-amz-date;x-amz-target, Signature=" + "0" * 64})
        elif mode == "malformed-authorization":
            headers["authorization"] = "intentionally-invalid-probe"
        elif mode != "unsigned":
            raise ValueError("Unknown transport mode")
        request = urllib.request.Request("https://" + HOST + "/", data=body, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, response_body = response.status, response.read()
            request_id = response.headers.get("x-amzn-requestid")
    output = json.loads(response_body) if response_body else {}
    result = {"http_status": status, "body_bytes": len(response_body), "request_id": request_id}
    if 200 <= status < 300:
        result.update(code="Success", output=output)
    else:
        result.update(code=output["__type"].split("#")[-1], error=output)
    return result


def admission_slice(evidence, record, required):
    """Observe hidden SRP, challenge interoperability, and alias collisions."""
    evidence["scope"] = "Two owned Lite pools: hidden-user SRP/challenge crossover and reserved-address alias collisions; no message delivery"
    evidence["bounds"] = {"max_pools": 2, "max_requests": 60, "max_users_per_pool": 3, "max_clients_per_pool": 2}
    evidence["documentation"].append("https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html")
    evidence["limitations"].append("Admission slice sends deliberately invalid zero-byte SRP signatures; it does not claim these are valid SRP proofs. JWT verification and refresh lifecycle are covered by the separate full login fixture.")
    pool = required("admission-create-pool", "CreateUserPool", {"PoolName": evidence["prefix"], "UserPoolTier": "LITE"})["UserPool"]["Id"]
    flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    client_args = {"UserPoolId": pool, "ClientName": "hidden-srp", "PreventUserExistenceErrors": "ENABLED", "ExplicitAuthFlows": flows}
    client = required("admission-create-hidden-client", "CreateUserPoolClient", client_args)["UserPoolClient"]["ClientId"]
    second_client = required("admission-create-second-hidden-client", "CreateUserPoolClient", dict(client_args, ClientName="hidden-srp-second"))["UserPoolClient"]["ClientId"]

    def srp(label, username, client_id=client):
        return required(label, "InitiateAuth", {"ClientId": client_id, "AuthFlow": "USER_SRP_AUTH",
                        "AuthParameters": {"USERNAME": username, "SRP_A": "2"}}, "unsigned")

    def wrong_proof(label, username, challenge):
        parameters = challenge["ChallengeParameters"]
        responses = {"USERNAME": parameters.get("USERNAME", username),
                     "PASSWORD_CLAIM_SECRET_BLOCK": parameters["SECRET_BLOCK"],
                     "PASSWORD_CLAIM_SIGNATURE": base64.b64encode(bytes(32)).decode(),
                     "TIMESTAMP": AWSSRP.get_cognito_formatted_timestamp(datetime.datetime.now(datetime.timezone.utc))}
        request = {"ClientId": client, "ChallengeName": "PASSWORD_VERIFIER", "ChallengeResponses": responses}
        if "Session" in challenge:
            request["Session"] = challenge["Session"]
        return record(label, "RespondToAuthChallenge", request, "unsigned")

    absent = "absent-owned-a"
    first = srp("hidden-absent-first", absent)
    repeated = srp("hidden-absent-repeat", absent)
    absent_result = wrong_proof("hidden-absent-invalid-proof", absent, repeated)
    different = srp("hidden-different-username", "absent-owned-b")
    cross_client = srp("hidden-same-username-other-client", absent, second_client)
    parameters = {key: value["ChallengeParameters"] for key, value in
                  (("first", first), ("repeat", repeated), ("different", different), ("other_client", cross_client))}
    evidence["admission_comparisons"] = {
        "repeat_salt_equal": parameters["first"]["SALT"] == parameters["repeat"]["SALT"],
        "repeat_user_id_for_srp_equal": parameters["first"]["USER_ID_FOR_SRP"] == parameters["repeat"]["USER_ID_FOR_SRP"],
        "different_username_salt_equal": parameters["first"]["SALT"] == parameters["different"]["SALT"],
        "different_username_user_id_for_srp_equal": parameters["first"]["USER_ID_FOR_SRP"] == parameters["different"]["USER_ID_FOR_SRP"],
        "other_client_salt_equal": parameters["first"]["SALT"] == parameters["other_client"]["SALT"],
        "other_client_user_id_for_srp_equal": parameters["first"]["USER_ID_FOR_SRP"] == parameters["other_client"]["USER_ID_FOR_SRP"],
        "absent_user_id_for_srp_echoes_username": parameters["first"]["USER_ID_FOR_SRP"] == absent}
    temporary, password = "TempA1!" + secrets.token_hex(12), "FinalA1!" + secrets.token_hex(12)
    real_user = {"UserPoolId": pool, "Username": "confirmed-owned"}
    required("admission-create-real-user", "AdminCreateUser", dict(real_user, TemporaryPassword=temporary, MessageAction="SUPPRESS"))
    required("admission-confirm-real-user", "AdminSetUserPassword", dict(real_user, Password=password, Permanent=True))
    required("admission-describe-real-user", "AdminGetUser", real_user)
    real_challenge = srp("hidden-real-user-challenge", real_user["Username"])
    real_result = wrong_proof("hidden-real-user-invalid-proof", real_user["Username"], real_challenge)
    evidence["admission_comparisons"]["wrong_proof_errors_equal"] = absent_result.get("error") == real_result.get("error")
    evidence["admission_comparisons"]["wrong_proof_http_status_equal"] = absent_result["http_status"] == real_result["http_status"]
    for admin_origin in (True, False):
        label = "admin-to-public" if admin_origin else "public-to-admin"
        user = {"UserPoolId": pool, "Username": label}
        required(label + "-create-user", "AdminCreateUser", dict(user, TemporaryPassword=temporary, MessageAction="SUPPRESS"))
        request = {"ClientId": client, "AuthFlow": "ADMIN_USER_PASSWORD_AUTH" if admin_origin else "USER_PASSWORD_AUTH",
                   "AuthParameters": {"USERNAME": user["Username"], "PASSWORD": temporary}}
        if admin_origin:
            request["UserPoolId"] = pool
        challenge = required(label + "-initiate", "AdminInitiateAuth" if admin_origin else "InitiateAuth",
                             request, "signed" if admin_origin else "unsigned")
        answer = {"ClientId": client, "ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": challenge["Session"],
                  "ChallengeResponses": {"USERNAME": user["Username"], "NEW_PASSWORD": password}}
        if not admin_origin:
            answer["UserPoolId"] = pool
        result = record(label + "-respond", "RespondToAuthChallenge" if admin_origin else "AdminRespondToAuthChallenge",
                        answer, "unsigned" if admin_origin else "signed")
        required(label + "-describe-user-after", "AdminGetUser", user)
        authentication = result.get("output", {}).get("AuthenticationResult")
        if authentication:
            record(label + "-get-user", "GetUser", {"AccessToken": authentication["AccessToken"]}, "unsigned")
    evidence["documentation"].append(DOC_BASE + "AdminUpdateUserAttributes.html")
    alias_pool = required("alias-create-pool", "CreateUserPool",
                          {"PoolName": evidence["prefix"] + "-aliases", "UserPoolTier": "LITE",
                           "AliasAttributes": ["email", "preferred_username"]})["UserPool"]["Id"]
    required("alias-create-alice", "AdminCreateUser",
             {"UserPoolId": alias_pool, "Username": "alice", "TemporaryPassword": temporary, "MessageAction": "SUPPRESS",
              "UserAttributes": [{"Name": "email", "Value": "shared@example.com"}, {"Name": "email_verified", "Value": "true"}]})
    required("alias-create-bob", "AdminCreateUser",
             {"UserPoolId": alias_pool, "Username": "bob", "TemporaryPassword": temporary, "MessageAction": "SUPPRESS"})
    required("alias-email-lookup-before", "AdminGetUser", {"UserPoolId": alias_pool, "Username": "shared@example.com"})
    record("alias-cross-attribute-collision", "AdminUpdateUserAttributes",
           {"UserPoolId": alias_pool, "Username": "bob", "UserAttributes": [{"Name": "preferred_username", "Value": "shared@example.com"}]})
    for label, username in (("email", "shared@example.com"), ("alice", "alice"), ("bob", "bob")):
        record("alias-after-cross-attribute-" + label, "AdminGetUser", {"UserPoolId": alias_pool, "Username": username})
    record("alias-canonical-username-collision", "AdminUpdateUserAttributes",
           {"UserPoolId": alias_pool, "Username": "bob", "UserAttributes": [{"Name": "preferred_username", "Value": "alice"}]})
    for label, username in (("email", "shared@example.com"), ("alice", "alice"), ("bob", "bob")):
        record("alias-after-canonical-collision-" + label, "AdminGetUser", {"UserPoolId": alias_pool, "Username": username})
    evidence["completed_at"] = now()


def group_slice(evidence, record, required):
    """Capture group CRUD, membership and JWT role selection without assuming roles."""
    evidence["scope"] = "Two owned Lite pools; group membership and signed JWT claims; no messages or AWS role assumption"
    evidence["bounds"] = {"max_pools": 2, "max_requests": 130, "max_users_per_pool": 2, "max_clients_per_pool": 1, "max_groups_per_pool": 6}
    evidence["documentation"].append("https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html")
    evidence["documentation"].extend(DOC_BASE + operation + ".html" for operation in (
        "CreateGroup", "GetGroup", "UpdateGroup", "DeleteGroup", "ListGroups",
        "AdminAddUserToGroup", "AdminRemoveUserFromGroup", "AdminListGroupsForUser", "ListUsersInGroup"))
    evidence["limitations"].append("Group role ARNs name nonexistent probe-owned roles. No role is created or assumed; claims are not evidence of Identity Pool credential issuance or iam:PassRole authorization.")
    pool = required("groups-create-pool", "CreateUserPool", {
        "PoolName": evidence["prefix"], "UserPoolTier": "LITE", "AliasAttributes": ["email"]})["UserPool"]["Id"]
    client = required("groups-create-client", "CreateUserPoolClient", {
        "UserPoolId": pool, "ClientName": "group-claims",
        "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]})["UserPoolClient"]["ClientId"]
    password = "GroupA1!" + secrets.token_hex(12)
    for username in ("alice", "bob"):
        required("groups-create-" + username, "AdminCreateUser", {
            "UserPoolId": pool, "Username": username, "TemporaryPassword": password, "MessageAction": "SUPPRESS",
            "UserAttributes": [{"Name": "email", "Value": username + "@example.com"}, {"Name": "email_verified", "Value": "true"}]})
        required("groups-confirm-" + username, "AdminSetUserPassword", {
            "UserPoolId": pool, "Username": username, "Password": password, "Permanent": True})

    def tokens(label, username="alice", refresh=None):
        parameters = {"REFRESH_TOKEN": refresh} if refresh else {"USERNAME": username, "PASSWORD": password}
        return required(label, "InitiateAuth", {
            "ClientId": client, "AuthFlow": "REFRESH_TOKEN_AUTH" if refresh else "USER_PASSWORD_AUTH",
            "AuthParameters": parameters}, "unsigned")["AuthenticationResult"]

    def group(operation, label, name, **fields):
        return record(label, operation, dict(UserPoolId=pool, GroupName=name, **fields))

    def member(operation, label, name, username="alice"):
        return group(operation, label, name, Username=username)

    required("groups-list-empty", "ListGroups", {"UserPoolId": pool})
    required("groups-user-memberships-empty", "AdminListGroupsForUser", {"UserPoolId": pool, "Username": "alice"})
    group("GetGroup", "groups-get-missing", "absent")
    original = tokens("groups-login-empty")
    role_a = "arn:aws:iam::" + evidence["account"] + ":role/" + evidence["prefix"] + "-reader"
    role_b = "arn:aws:iam::" + evidence["account"] + ":role/" + evidence["prefix"] + "-writer"
    for name, fields in (
        ("z-default", {}),
        ("reader", {"RoleArn": role_a, "Precedence": 10, "Description": "reader role"}),
        ("writer", {"RoleArn": role_b, "Precedence": 10}),
        ("empty-first", {"Precedence": 0}),
        ("null-b", {"RoleArn": role_b}),
        ("null-a", {"RoleArn": role_a}),
    ):
        required("groups-create-" + name, "CreateGroup", dict(UserPoolId=pool, GroupName=name, **fields))
    group("CreateGroup", "groups-create-duplicate", "reader", Description="must not replace")
    group("GetGroup", "groups-get-after-duplicate", "reader")
    group("CreateGroup", "groups-negative-precedence", "invalid", Precedence=-1)
    group("UpdateGroup", "groups-update-missing", "absent", Description="missing")
    group("ListUsersInGroup", "groups-members-empty", "reader")
    member("AdminAddUserToGroup", "groups-add-first", "reader")
    member("AdminAddUserToGroup", "groups-add-idempotent", "reader")
    tokens("groups-login-reader")
    tokens("groups-refresh-reader", refresh=original["RefreshToken"])
    member("AdminAddUserToGroup", "groups-add-alias", "writer", "alice@example.com")
    required("groups-alias-memberships", "AdminListGroupsForUser", {"UserPoolId": pool, "Username": "alice@example.com"})
    member("AdminAddUserToGroup", "groups-add-writer", "writer")
    record("groups-zero-limit-list", "ListGroups", {"UserPoolId": pool, "Limit": 0})
    record("groups-zero-limit-memberships", "AdminListGroupsForUser", {"UserPoolId": pool, "Username": "alice", "Limit": 0})
    group("ListUsersInGroup", "groups-zero-limit-users", "reader", Limit=0)
    member("AdminAddUserToGroup", "groups-add-missing-user-and-group", "absent", "absent-user")
    member("AdminRemoveUserFromGroup", "groups-remove-missing-user-and-group", "absent", "absent-user")
    tokens("groups-login-tied-roles")
    group("UpdateGroup", "groups-update-winner", "writer", Precedence=9)
    tokens("groups-refresh-new-winner", refresh=original["RefreshToken"])
    member("AdminAddUserToGroup", "groups-add-empty-winner", "empty-first")
    tokens("groups-login-empty-winner")
    member("AdminRemoveUserFromGroup", "groups-remove-empty-winner", "empty-first")
    member("AdminRemoveUserFromGroup", "groups-remove-idempotent", "empty-first")
    group("UpdateGroup", "groups-update-same-role-tie", "writer", Precedence=10, RoleArn=role_a)
    tokens("groups-login-same-role-tie")
    group("UpdateGroup", "groups-update-description-only", "writer", Description="updated only")
    group("GetGroup", "groups-get-after-description", "writer")
    group("UpdateGroup", "groups-update-identical-description", "writer", Description="updated only")
    group("GetGroup", "groups-get-after-identical-description", "writer")
    group("UpdateGroup", "groups-clear-description", "writer", Description="")
    group("UpdateGroup", "groups-null-optionals", "writer", RoleArn=None, Precedence=None, Description=None)
    group("GetGroup", "groups-get-after-null", "writer")
    group("UpdateGroup", "groups-empty-role", "writer", RoleArn="")
    group("GetGroup", "groups-get-after-empty-role", "writer")
    tokens("groups-login-after-empty-role")
    member("AdminAddUserToGroup", "groups-add-null-b", "null-b")
    tokens("groups-login-number-before-null")
    member("AdminAddUserToGroup", "groups-bob-add-null-a", "null-a", "bob")
    tokens("groups-login-single-unranked", username="bob")
    member("AdminAddUserToGroup", "groups-bob-add-null-b", "null-b", "bob")
    tokens("groups-login-null-tied-roles", username="bob")
    group("UpdateGroup", "groups-null-same-role", "null-a", RoleArn=role_b)
    tokens("groups-login-null-same-role", username="bob")
    member("AdminAddUserToGroup", "groups-add-missing-group", "absent")
    member("AdminAddUserToGroup", "groups-add-missing-user", "reader", "absent")
    member("AdminRemoveUserFromGroup", "groups-remove-missing-group", "absent")
    member("AdminRemoveUserFromGroup", "groups-remove-missing-user", "reader", "absent")
    required("groups-list-memberships", "AdminListGroupsForUser", {"UserPoolId": pool, "Username": "alice"})
    group("ListUsersInGroup", "groups-list-two-members", "null-b")
    for operation, fields, member_name in (
        ("ListGroups", {}, "Groups"),
        ("AdminListGroupsForUser", {"Username": "alice"}, "Groups"),
        ("ListUsersInGroup", {"GroupName": "null-b"}, "Users"),
    ):
        token = None
        for page in range(8):
            request = dict(UserPoolId=pool, Limit=1, **fields)
            if token:
                request["NextToken"] = token
            result = required("groups-page-" + operation + "-" + str(page), operation, request)
            if member_name not in result:
                raise RuntimeError("Missing native collection " + member_name)
            token = result.get("NextToken")
            if not token:
                break
        else:
            raise RuntimeError("Group pagination page bound reached")
        record("groups-invalid-cursor-" + operation, operation, dict(UserPoolId=pool, NextToken="invalid", **fields))
    second = required("groups-create-isolated-pool", "CreateUserPool", {
        "PoolName": evidence["prefix"] + "-isolated", "UserPoolTier": "LITE"})["UserPool"]["Id"]
    record("groups-other-pool-group-absent", "GetGroup", {"UserPoolId": second, "GroupName": "reader"})
    required("groups-other-pool-same-group", "CreateGroup", {"UserPoolId": second, "GroupName": "reader"})
    required("groups-other-pool-members-empty", "ListUsersInGroup", {"UserPoolId": second, "GroupName": "reader"})
    group("DeleteGroup", "groups-delete-writer", "writer")
    group("GetGroup", "groups-get-deleted", "writer")
    group("DeleteGroup", "groups-delete-again", "writer")
    required("groups-memberships-after-delete", "AdminListGroupsForUser", {"UserPoolId": pool, "Username": "alice"})
    tokens("groups-refresh-after-group-delete", refresh=original["RefreshToken"])
    required("groups-delete-alice", "AdminDeleteUser", {"UserPoolId": pool, "Username": "alice"})
    group("ListUsersInGroup", "groups-members-after-user-delete", "null-b")
    record("groups-memberships-deleted-user", "AdminListGroupsForUser", {"UserPoolId": pool, "Username": "alice"})
    required("groups-recreate-alice", "AdminCreateUser", {
        "UserPoolId": pool, "Username": "alice", "TemporaryPassword": password, "MessageAction": "SUPPRESS"})
    required("groups-recreated-user-memberships", "AdminListGroupsForUser", {"UserPoolId": pool, "Username": "alice"})
    evidence["completed_at"] = now()


def credential_slice(evidence, record, required):
    """Observe existing credentials across suspension and password transitions."""
    evidence["scope"] = "One owned Lite pool and user; existing-token acceptance across disable/enable, password changes and client deletion; no delivery"
    evidence["bounds"] = {"max_pools": 1, "max_requests": 80, "max_users_per_pool": 1, "max_clients_per_pool": 1}
    evidence["documentation"].extend(DOC_BASE + operation + ".html" for operation in (
        "AdminDisableUser", "AdminEnableUser", "AdminSetUserPassword", "ChangePassword", "DeleteUserPoolClient"))
    pool = required("credentials-create-pool", "CreateUserPool", {
        "PoolName": evidence["prefix"], "UserPoolTier": "LITE"})["UserPool"]["Id"]
    client = required("credentials-create-client", "CreateUserPoolClient", {
        "UserPoolId": pool, "ClientName": "credential-transitions",
        "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]})["UserPoolClient"]["ClientId"]
    user = {"UserPoolId": pool, "Username": "owned-user"}
    passwords = ["TransitionA1!" + secrets.token_hex(12) for _ in range(5)]
    required("credentials-create-user", "AdminCreateUser", dict(user, TemporaryPassword=passwords[0], MessageAction="SUPPRESS"))
    required("credentials-set-permanent", "AdminSetUserPassword", dict(user, Password=passwords[0], Permanent=True))

    def login(label, password):
        return record(label, "InitiateAuth", {"ClientId": client, "AuthFlow": "USER_PASSWORD_AUTH",
                      "AuthParameters": {"USERNAME": user["Username"], "PASSWORD": password}}, "unsigned")

    def family(label, authentication):
        record(label + "-access", "GetUser", {"AccessToken": authentication["AccessToken"]}, "unsigned")
        record(label + "-refresh", "InitiateAuth", {"ClientId": client, "AuthFlow": "REFRESH_TOKEN_AUTH",
               "AuthParameters": {"REFRESH_TOKEN": authentication["RefreshToken"]}}, "unsigned")

    original = login("credentials-login-before-disable", passwords[0])["output"]["AuthenticationResult"]
    required("credentials-disable", "AdminDisableUser", user)
    family("credentials-disabled", original)
    required("credentials-enable", "AdminEnableUser", user)
    family("credentials-after-enable", original)
    active = login("credentials-login-before-change", passwords[0])["output"]["AuthenticationResult"]
    required("credentials-change-password", "ChangePassword", {
        "AccessToken": active["AccessToken"], "PreviousPassword": passwords[0], "ProposedPassword": passwords[1]}, "unsigned")
    family("credentials-after-change", active)
    login("credentials-old-password-after-change", passwords[0])
    login("credentials-new-password-after-change", passwords[1])
    required("credentials-admin-permanent-reset", "AdminSetUserPassword", dict(user, Password=passwords[2], Permanent=True))
    family("credentials-after-permanent-reset", active)
    login("credentials-old-password-after-permanent-reset", passwords[1])
    before_temporary = login("credentials-login-before-temporary-reset", passwords[2])["output"]["AuthenticationResult"]
    required("credentials-admin-temporary-reset", "AdminSetUserPassword", dict(user, Password=passwords[3], Permanent=False))
    required("credentials-describe-temporary-status", "AdminGetUser", user)
    family("credentials-after-temporary-reset", before_temporary)
    challenge = login("credentials-temporary-login", passwords[3])["output"]
    completed = required("credentials-complete-temporary-challenge", "RespondToAuthChallenge", {
        "ClientId": client, "ChallengeName": challenge["ChallengeName"], "Session": challenge["Session"],
        "ChallengeResponses": {"USERNAME": user["Username"], "NEW_PASSWORD": passwords[4]}}, "unsigned")["AuthenticationResult"]
    family("credentials-after-challenge-completion", before_temporary)
    required("credentials-delete-client", "DeleteUserPoolClient", {"UserPoolId": pool, "ClientId": client})
    family("credentials-after-client-delete", completed)
    evidence["completed_at"] = now()


def client_access_slice(evidence, record, required):
    """Observe bearer attribute permissions after client update and deletion."""
    evidence["scope"] = "One owned Lite pool/user and two clients; default versus restricted bearer read permissions after client update/deletion, including delayed reads; no messages"
    evidence["bounds"] = {"max_pools": 1, "max_requests": 50, "max_users_per_pool": 1, "max_clients_per_pool": 2, "post_delete_wait_seconds": 65}
    evidence["documentation"].extend(DOC_BASE + operation + ".html" for operation in (
        "GetUser", "UpdateUserPoolClient", "DeleteUserPoolClient", "ChangePassword", "GlobalSignOut"))
    pool = required("client-access-create-pool", "CreateUserPool", {
        "PoolName": evidence["prefix"], "UserPoolTier": "LITE",
        "Schema": [{"Name": "department", "AttributeDataType": "String", "Mutable": True}]})["UserPool"]["Id"]
    flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    client = required("client-access-create-client", "CreateUserPoolClient", {
        "UserPoolId": pool, "ClientName": "attribute-permissions", "ExplicitAuthFlows": flows,
        "ReadAttributes": ["email"]})["UserPoolClient"]["ClientId"]
    default_client = required("client-access-create-default-client", "CreateUserPoolClient", {
        "UserPoolId": pool, "ClientName": "default-attributes", "ExplicitAuthFlows": flows})["UserPoolClient"]["ClientId"]
    user = {"UserPoolId": pool, "Username": "owned-user"}
    password = "ReadA1!" + secrets.token_hex(12)
    required("client-access-create-user", "AdminCreateUser", dict(user,
        TemporaryPassword=password, MessageAction="SUPPRESS", UserAttributes=[
            {"Name": "email", "Value": "owned@example.com"}, {"Name": "given_name", "Value": "Owned"},
            {"Name": "custom:department", "Value": "engineering"}]))
    required("client-access-set-password", "AdminSetUserPassword", dict(user, Password=password, Permanent=True))

    def login(label, client_id=client):
        return required(label, "InitiateAuth", {"ClientId": client_id, "AuthFlow": "USER_PASSWORD_AUTH",
                        "AuthParameters": {"USERNAME": user["Username"], "PASSWORD": password}}, "unsigned")["AuthenticationResult"]

    def get(label, authentication):
        return record(label, "GetUser", {"AccessToken": authentication["AccessToken"]}, "unsigned")

    original = login("client-access-login-email")
    get("client-access-get-email", original)
    default = login("client-access-login-default", default_client)
    get("client-access-get-default", default)
    required("client-access-update-given-name", "UpdateUserPoolClient", {
        "UserPoolId": pool, "ClientId": client, "ExplicitAuthFlows": flows, "ReadAttributes": ["given_name"]})
    get("client-access-old-token-after-update", original)
    updated = login("client-access-login-given-name")
    get("client-access-new-token-after-update", updated)
    required("client-access-update-custom", "UpdateUserPoolClient", {
        "UserPoolId": pool, "ClientId": client, "ExplicitAuthFlows": flows, "ReadAttributes": ["custom:department"]})
    get("client-access-old-token-after-custom", original)
    required("client-access-delete-client", "DeleteUserPoolClient", {"UserPoolId": pool, "ClientId": client})
    get("client-access-original-after-delete", original)
    get("client-access-updated-after-delete", updated)
    required("client-access-delete-default-client", "DeleteUserPoolClient", {"UserPoolId": pool, "ClientId": default_client})
    get("client-access-default-after-delete", default)
    time.sleep(evidence["bounds"]["post_delete_wait_seconds"])
    get("client-access-original-after-delay", original)
    get("client-access-updated-after-delay", updated)
    get("client-access-default-after-delay", default)
    record("client-access-change-password-after-delete", "ChangePassword", {
        "AccessToken": updated["AccessToken"], "PreviousPassword": password,
        "ProposedPassword": "NewReadA1!" + secrets.token_hex(12)}, "unsigned")
    record("client-access-global-signout-after-delete", "GlobalSignOut", {"AccessToken": updated["AccessToken"]}, "unsigned")
    get("client-access-original-after-signout", original)
    evidence["completed_at"] = now()


def profile_slice(evidence, record, required):
    """Observe bearer-owned profile changes without verification delivery."""
    evidence["scope"] = "One owned Lite pool, two clients and synthetic users; default/restricted attribute writes and self-deletion; no auto-verification or messages"
    evidence["bounds"] = {"max_pools": 1, "max_requests": 80, "max_users_per_pool": 2, "max_clients_per_pool": 2}
    evidence["documentation"].extend(DOC_BASE + op + ".html" for op in (
        "SignUp", "UpdateUserAttributes", "DeleteUserAttributes", "DeleteUser"))
    pool = required("profile-create-pool", "CreateUserPool", {
        "PoolName": evidence["prefix"], "UserPoolTier": "LITE",
        "Schema": [{"Name": "team", "AttributeDataType": "String", "Mutable": True},
                   {"Name": "tenant", "AttributeDataType": "String", "Mutable": False},
                   {"Name": "family_name", "AttributeDataType": "String", "Mutable": True, "Required": True}]})["UserPool"]["Id"]
    flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    client = required("profile-create-client", "CreateUserPoolClient", {
        "UserPoolId": pool, "ClientName": "default-permissions", "ExplicitAuthFlows": flows})["UserPoolClient"]["ClientId"]
    record("profile-client-missing-required-write", "CreateUserPoolClient", {
        "UserPoolId": pool, "ClientName": "missing-required-write", "ExplicitAuthFlows": flows,
        "ReadAttributes": ["given_name"], "WriteAttributes": ["given_name"]})
    restricted = required("profile-create-restricted-client", "CreateUserPoolClient", {
        "UserPoolId": pool, "ClientName": "restricted-permissions", "ExplicitAuthFlows": flows,
        "ReadAttributes": ["given_name"], "WriteAttributes": ["given_name", "family_name"]})["UserPoolClient"]["ClientId"]
    password = "ProfileA1!" + secrets.token_hex(12)
    user = {"UserPoolId": pool, "Username": "alice"}
    record("profile-signup-missing-required", "SignUp", {
        "ClientId": client, "Username": "missing", "Password": password}, "unsigned")
    signup = {"ClientId": client, "Username": "alice", "Password": password, "UserAttributes": [
        {"Name": "family_name", "Value": "Example"}, {"Name": "given_name", "Value": "Alice"},
        {"Name": "email", "Value": "alice@example.com"}, {"Name": "custom:team", "Value": "initial"},
        {"Name": "custom:tenant", "Value": "owned"}]}
    record("profile-signup-verified-flag", "SignUp", dict(signup, Username="protected",
        UserAttributes=signup["UserAttributes"] + [{"Name": "email_verified", "Value": "true"}]), "unsigned")
    required("profile-signup-custom-defaults", "SignUp", signup, "unsigned")
    required("profile-confirm-user", "AdminConfirmSignUp", user)

    def login(label, app_client=client):
        return required(label, "InitiateAuth", {"ClientId": app_client, "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"USERNAME": user["Username"], "PASSWORD": password}}, "unsigned")["AuthenticationResult"]

    full, narrow = login("profile-login-default"), login("profile-login-restricted", restricted)

    def update(label, attributes, authentication=full):
        return record(label, "UpdateUserAttributes", {"AccessToken": authentication["AccessToken"],
            "UserAttributes": [{"Name": name, "Value": value} for name, value in attributes]}, "unsigned")

    def get(label, authentication=full):
        return record(label, "GetUser", {"AccessToken": authentication["AccessToken"]}, "unsigned")

    def delete_attributes(label, names, authentication=full):
        return record(label, "DeleteUserAttributes", {"AccessToken": authentication["AccessToken"],
            "UserAttributeNames": names}, "unsigned")

    get("profile-get-initial")
    update("profile-update-custom-default", [("custom:team", "updated"), ("given_name", "Alicia")])
    get("profile-get-updated")
    update("profile-restricted-write-denied", [("custom:team", "forbidden")], narrow)
    update("profile-restricted-write-allowed", [("given_name", "Scoped")], narrow)
    get("profile-restricted-read", narrow)
    update("profile-immutable-batch-denied", [("given_name", "must-not-stick"), ("custom:tenant", "changed")])
    get("profile-get-after-immutable")
    update("profile-verified-flag-denied", [("email_verified", "true")])
    update("profile-sub-denied", [("sub", "not-a-subject")])
    update("profile-unknown-attribute", [("custom:unknown", "value")])
    update("profile-invalid-birthdate", [("birthdate", "not-a-date")])
    update("profile-duplicate-attribute", [("given_name", "first"), ("given_name", "second")])
    get("profile-get-after-duplicate")
    update("profile-duplicate-validates-last", [("birthdate", "short"), ("birthdate", "not-a-date")])
    record("profile-admin-birthdate-and-duplicates", "AdminUpdateUserAttributes", dict(user,
        UserAttributes=[{"Name": "birthdate", "Value": "also-not-a-date"},
                        {"Name": "given_name", "Value": "admin-first"}, {"Name": "given_name", "Value": "admin-second"}]))
    get("profile-get-after-admin-duplicates")
    record("profile-admin-valid-duplicates", "AdminUpdateUserAttributes", dict(user,
        UserAttributes=[{"Name": "birthdate", "Value": "short"}, {"Name": "birthdate", "Value": "not-a-date"},
                        {"Name": "given_name", "Value": "admin-first"}, {"Name": "given_name", "Value": "admin-second"}]))
    get("profile-get-after-valid-admin-duplicates")
    required("profile-admin-verify-email", "AdminUpdateUserAttributes", dict(user,
        UserAttributes=[{"Name": "email_verified", "Value": "true"}]))
    update("profile-change-email", [("email", "changed@example.com")])
    get("profile-get-changed-email")
    delete_attributes("profile-delete-custom-default", ["custom:team"])
    delete_attributes("profile-delete-absent-idempotent", ["custom:team"])
    delete_attributes("profile-restricted-delete-denied", ["email"], narrow)
    delete_attributes("profile-delete-verification-flag", ["email_verified"])
    delete_attributes("profile-delete-required-denied", ["family_name"])
    delete_attributes("profile-delete-immutable-denied", ["custom:tenant"])
    delete_attributes("profile-delete-unknown", ["custom:unknown"])
    update("profile-empty-value-delete", [("given_name", "")])
    get("profile-get-after-empty")
    delete_attributes("profile-delete-email", ["email"])
    get("profile-get-after-email-delete")
    required("profile-create-group", "CreateGroup", {"UserPoolId": pool, "GroupName": "members"})
    required("profile-add-member", "AdminAddUserToGroup", dict(user, GroupName="members"))
    record("profile-delete-self", "DeleteUser", {"AccessToken": full["AccessToken"]}, "unsigned")
    get("profile-old-access-after-delete")
    record("profile-old-refresh-after-delete", "InitiateAuth", {"ClientId": client, "AuthFlow": "REFRESH_TOKEN_AUTH",
        "AuthParameters": {"REFRESH_TOKEN": full["RefreshToken"]}}, "unsigned")
    record("profile-admin-get-after-delete", "AdminGetUser", user)
    required("profile-members-after-delete", "ListUsersInGroup", {"UserPoolId": pool, "GroupName": "members"})
    required("profile-recreate-user", "SignUp", signup, "unsigned")
    required("profile-recreated-memberships", "AdminListGroupsForUser", user)
    get("profile-old-access-after-recreate")
    required("profile-confirm-recreated-user", "AdminConfirmSignUp", user)
    get("profile-old-access-after-reconfirmed")
    record("profile-old-refresh-after-reconfirmed", "InitiateAuth", {"ClientId": client, "AuthFlow": "REFRESH_TOKEN_AUTH",
        "AuthParameters": {"REFRESH_TOKEN": full["RefreshToken"]}}, "unsigned")
    login("profile-login-recreated-user")
    evidence["completed_at"] = now()


def group_authority_slice(evidence, record, required):
    """Separate group role configuration from permission to pass an IAM role."""
    evidence["scope"] = "One owned Lite pool and scoped 15-minute STS sessions testing iam:PassRole denies and condition keys; no role assumption or identity-pool credentials"
    evidence["bounds"] = {"max_pools": 2, "max_requests": 60, "max_users_per_pool": 0, "max_clients_per_pool": 0}
    evidence["documentation"].extend(DOC_BASE + op + ".html" for op in ("CreateGroup", "UpdateGroup"))
    pool = required("authority-create-pool", "CreateUserPool", {"PoolName": evidence["prefix"], "UserPoolTier": "LITE"})["UserPool"]
    role = "arn:aws:iam::" + evidence["account"] + ":role/" + evidence["prefix"]
    evidence["authorities"] = {}

    def session(principal, role_statement):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["cognito-idp:CreateGroup", "cognito-idp:UpdateGroup", "cognito-idp:GetGroup"], "Resource": pool["Arn"]},
            dict(role_statement, Action="iam:PassRole", Resource=role + "*")]}
        result = observe("sts", "get-federation-token", {"Name": evidence["prefix"], "DurationSeconds": 900, "Policy": json.dumps(policy)})
        authority = {"policy": policy, "session_code": result["code"], "duration_seconds": 900}
        evidence["authorities"][principal] = authority
        if result["code"] != "Success":
            raise RuntimeError("Unable to establish scoped authority session: " + result["code"])
        output = result["output"]
        credentials = output["Credentials"]
        authority.update(federated_user=output["FederatedUser"], expiration=credentials["Expiration"])
        return dict(os.environ, AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                    AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"], AWS_SESSION_TOKEN=credentials["SessionToken"])

    def scoped(principal, environment, label, operation, parameters):
        return record(label, operation, dict(parameters, UserPoolId=pool["Id"]),
                      environment=environment, principal=principal)

    denied = session("passrole-denied", {"Effect": "Deny"})

    def deny(label, operation, parameters):
        return scoped("passrole-denied", denied, label, operation, parameters)

    control = deny("authority-create-without-role", "CreateGroup", {"GroupName": "control"})
    if control["code"] != "Success":
        raise RuntimeError("Scoped Cognito control was not authorized: " + control["code"])
    deny("authority-create-with-role", "CreateGroup", {"GroupName": "with-role", "RoleArn": role})
    deny("authority-get-created-role", "GetGroup", {"GroupName": "with-role"})
    deny("authority-create-existing-role", "CreateGroup", {"GroupName": "control", "RoleArn": role})
    deny("authority-assign-role", "UpdateGroup", {"GroupName": "control", "RoleArn": role})
    deny("authority-get-assigned-role", "GetGroup", {"GroupName": "control"})
    deny("authority-update-missing-group", "UpdateGroup", {"GroupName": "absent", "RoleArn": role})
    for principal, condition in (
            ("passed-idp", {"StringEquals": {"iam:PassedToService": "cognito-idp.amazonaws.com"}}),
            ("passed-identity", {"StringEquals": {"iam:PassedToService": "cognito-identity.amazonaws.com"}}),
            ("passed-absent", {"Null": {"iam:PassedToService": "true"}}),
            ("associated-pool", {"ArnEquals": {"iam:AssociatedResourceArn": pool["Arn"]}}),
            ("associated-absent", {"Null": {"iam:AssociatedResourceArn": "true"}}),
            ("unconditional", None)):
        statement = {"Effect": "Allow"}
        if condition is not None:
            statement["Condition"] = condition
        environment = session(principal, statement)
        scoped(principal, environment, principal + "-create", "CreateGroup", {"GroupName": principal, "RoleArn": role})
        scoped(principal, environment, principal + "-get-created", "GetGroup", {"GroupName": principal})
        scoped(principal, environment, principal + "-update", "UpdateGroup", {"GroupName": "control", "RoleArn": role})
        scoped(principal, environment, principal + "-get-updated", "GetGroup", {"GroupName": "control"})
    deny("authority-reassign-same-role", "UpdateGroup", {"GroupName": "control", "RoleArn": role})
    deny("authority-replace-role", "UpdateGroup", {"GroupName": "control", "RoleArn": role + "-other"})
    deny("authority-get-replaced-role", "GetGroup", {"GroupName": "control"})
    deny("authority-description-with-existing-role", "UpdateGroup", {"GroupName": "control", "Description": "no role parameter"})
    record("authority-create-pool-denied", "CreateUserPool", {"PoolName": evidence["prefix"] + "-denied", "UserPoolTier": "LITE"},
           environment=denied, principal="passrole-denied")
    deny("authority-list-groups-denied", "ListGroups", {})
    deny("authority-delete-group-denied", "DeleteGroup", {"GroupName": "control"})
    deny("authority-get-after-denied-delete", "GetGroup", {"GroupName": "control"})
    evidence["completed_at"] = now()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cognito/login_workflows.json"))
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--slice", choices=("login", "admission", "groups", "group-authority", "credentials", "client-access", "profile", "rotation"), default="login")
    args = parser.parse_args()
    if args.output.exists() and not args.cleanup:
        raise RuntimeError("Refusing to overwrite evidence; select another output")
    identity = observe("sts", "get-caller-identity")
    if identity.get("output", {}).get("Account") != args.account:
        raise RuntimeError("Native account identity mismatch")
    evidence = json.loads(args.output.read_text()) if args.cleanup else {
        "service": "cognito-idp", "source": "Native AWS HTTPS endpoints; raw AWS JSON requests and responses",
        "captured_at": now(), "region": REGION, "account": args.account,
        "identity": identity, "prefix": "stackd-cognito-" + uuid.uuid4().hex[:10],
        "scope": "Owned Lite pools, synthetic usernames with no email/phone attributes, SUPPRESS provisioning only",
        "bounds": {"max_pools": 2, "max_requests": 180, "max_users_per_pool": 4, "max_clients_per_pool": 4},
        "documentation": [DOC_BASE + op + ".html" for op in ("CreateUserPool", "CreateUserPoolClient", "AdminCreateUser", "InitiateAuth", "AdminInitiateAuth", "RespondToAuthChallenge", "RevokeToken", "GlobalSignOut")]
            + ["https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html"],
        "srp_helper": {"package": "pycognito", "version": importlib.metadata.version("pycognito"), "class": "pycognito.aws_srp.AWSSRP"},
        "redaction": "Passwords, client secrets, hashes, bearer tokens, sessions and SRP secret blocks/signatures replaced by SHA256-labeled placeholders. Decoded synthetic-user claims and public JWKS retained. No credentials captured.",
        "limitations": ["No SMTP/SMS, federation, hosted UI, OAuth/custom domains, MFA, device remembering, Lambda triggers or paid add-ons.",
                        "Pool tiers are explicit in capture requests; omitted UserPoolTier defaults are not established.",
                        "No token-lifetime expiry waiting, temporary-password expiry, cross-account, or cross-region claims.",
                        "JWT signature/claim verification is offline cryptographic evidence, not evidence of revocation status; GetUser and refresh requests independently exercise server acceptance."],
        "resources": {"pools": []}, "observations": [], "token_projections": {}, "jwks": {}, "cleanup": {},
        "probe_source": {"path": str(Path(__file__)), "text": Path(__file__).read_text()}}
    if evidence["account"] != args.account or evidence["region"] != REGION:
        raise RuntimeError("Capture account/region does not match cleanup selection")
    secret_values = {}

    def discover(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in SENSITIVE and isinstance(item, str) and item and not item.startswith("<redacted-"):
                    secret_values[item] = "<redacted-" + key.lower() + "-sha256:" + hashlib.sha256(item.encode()).hexdigest() + ">"
                discover(item)
        elif isinstance(value, list):
            for item in value:
                discover(item)

    def redacted(value):
        if isinstance(value, dict):
            return {key: redacted(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redacted(item) for item in value]
        if isinstance(value, str):
            if value in secret_values:
                return secret_values[value]
            for secret, replacement in secret_values.items():
                if len(secret) >= 24:
                    value = value.replace(secret, replacement)
        return value

    def save():
        discover(evidence)
        text = json.dumps(redacted(evidence), indent=2)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")

    def record(label, operation, parameters, mode="signed", *, cleanup=False, environment=None, principal=None):
        if not cleanup and len(evidence["observations"]) >= evidence["bounds"]["max_requests"]:
            raise RuntimeError("Request bound reached")
        started = now()
        result = raw_call(operation, parameters, mode, environment)
        observation = {"label": label, "operation": operation, "transport": mode,
                       "input": parameters, "started_at": started, "finished_at": now(), "result": result}
        if principal is not None:
            observation["principal"] = principal
        evidence["observations"].append(observation)
        if operation == "CreateUserPool" and result["code"] == "Success":
            evidence["resources"]["pools"].append(result["output"]["UserPool"]["Id"])
        authentication = result.get("output", {}).get("AuthenticationResult")
        if authentication:
            claims = json.loads(decode64(authentication["AccessToken"].split(".")[1]))
            pool_id = claims["iss"].rsplit("/", 1)[-1]
            issuer = "https://" + HOST + "/" + pool_id
            if pool_id not in evidence["jwks"]:
                with urllib.request.urlopen(issuer + "/.well-known/jwks.json", timeout=30) as response:
                    evidence["jwks"][pool_id] = {"url": issuer + "/.well-known/jwks.json",
                        "http_status": response.status, "output": json.load(response), "captured_at": now()}
            for member, use in (("AccessToken", "access"), ("IdToken", "id")):
                projection = jwt_projection(authentication[member], evidence["jwks"][pool_id]["output"],
                                            issuer, parameters["ClientId"], use)
                if not projection["signature_verified"] or not all(projection["claim_checks"].values()):
                    raise RuntimeError("Native token verification failed")
                evidence["token_projections"][label + "-" + use] = projection
        save()
        print(label + ": " + str(result["http_status"]) + " " + result["code"], flush=True)
        return result

    def required(label, operation, parameters, mode="signed"):
        result = record(label, operation, parameters, mode)
        if result["code"] != "Success":
            raise RuntimeError(label + ": " + result["code"])
        return result["output"]

    def cleanup():
        for pool in reversed(evidence["resources"]["pools"]):
            before = record("cleanup-describe-" + pool, "DescribeUserPool", {"UserPoolId": pool}, cleanup=True)
            if before["code"] == "Success":
                if not before["output"]["UserPool"]["Name"].startswith(evidence["prefix"]):
                    raise RuntimeError("Cleanup ownership mismatch")
                record("cleanup-delete-" + pool, "DeleteUserPool", {"UserPoolId": pool}, cleanup=True)
            after = record("cleanup-absence-" + pool, "DescribeUserPool", {"UserPoolId": pool}, cleanup=True)
            evidence["cleanup"][pool] = {"absent": after["code"] == "ResourceNotFoundException", "observed_at": now(), "result": after}
        evidence["cleanup"]["complete"] = all(evidence["cleanup"].get(pool, {}).get("absent", False) for pool in evidence["resources"]["pools"])
        save()
        if not evidence["cleanup"]["complete"]:
            raise RuntimeError("Owned pool cleanup incomplete")

    if args.cleanup:
        if evidence["account"] != args.account:
            raise RuntimeError("Cleanup account mismatch")
        cleanup()
        return
    save()
    try:
        capture = {"admission": admission_slice, "groups": group_slice, "group-authority": group_authority_slice,
                   "credentials": credential_slice, "client-access": client_access_slice,
                   "profile": profile_slice, "rotation": partial(rotation_slice, secret_hash=secret_hash)}.get(args.slice)
        if capture is not None:
            capture(evidence, record, required)
            save()
            return
        pool = required("create-pool-defaults", "CreateUserPool", {"PoolName": evidence["prefix"], "UserPoolTier": "LITE"})["UserPool"]["Id"]
        required("describe-pool-defaults", "DescribeUserPool", {"UserPoolId": pool})
        default_client = required("create-client-defaults", "CreateUserPoolClient", {"UserPoolId": pool, "ClientName": "default"})["UserPoolClient"]["ClientId"]
        required("describe-client-defaults", "DescribeUserPoolClient", {"UserPoolId": pool, "ClientId": default_client})
        flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
        client = required("create-password-client", "CreateUserPoolClient", {"UserPoolId": pool, "ClientName": "password", "ExplicitAuthFlows": flows})["UserPoolClient"]["ClientId"]
        private = required("create-secret-client", "CreateUserPoolClient", {"UserPoolId": pool, "ClientName": "secret", "GenerateSecret": True, "ExplicitAuthFlows": flows})["UserPoolClient"]
        private_id, private_secret = private["ClientId"], private["ClientSecret"]
        hidden = required("create-hidden-client", "CreateUserPoolClient", {"UserPoolId": pool, "ClientName": "hidden", "ExplicitAuthFlows": flows, "PreventUserExistenceErrors": "ENABLED"})["UserPoolClient"]["ClientId"]
        required("list-clients", "ListUserPoolClients", {"UserPoolId": pool, "MaxResults": 60})
        user = "owned-user"
        temporary, password = "TempA1!" + secrets.token_hex(12), "FinalA1!" + secrets.token_hex(12)
        weak = "short"
        user_args = {"UserPoolId": pool, "Username": user}
        record("weak-temporary-password", "AdminCreateUser", dict(user_args, TemporaryPassword=weak, MessageAction="SUPPRESS"))
        required("create-user-suppress", "AdminCreateUser", dict(user_args, TemporaryPassword=temporary, MessageAction="SUPPRESS"))
        record("duplicate-user", "AdminCreateUser", dict(user_args, TemporaryPassword=temporary, MessageAction="SUPPRESS"))
        required("get-user-force-change", "AdminGetUser", user_args)
        required("list-users-force-change", "ListUsers", {"UserPoolId": pool, "Limit": 60})

        def login(label, client_id=client, value=password, username=user, mode="unsigned", extra=None, admin=False):
            params = {"ClientId": client_id, "AuthFlow": "ADMIN_USER_PASSWORD_AUTH" if admin else "USER_PASSWORD_AUTH",
                      "AuthParameters": dict({"USERNAME": username, "PASSWORD": value}, **(extra or {}))}
            if admin:
                params["UserPoolId"] = pool
            return record(label, "AdminInitiateAuth" if admin else "InitiateAuth", params, mode)

        def tokens(result):
            if result["code"] != "Success" or "AuthenticationResult" not in result["output"]:
                raise RuntimeError("Expected successful authentication, got " + result["code"])
            return result["output"]["AuthenticationResult"]

        def refresh(label, token, client_id=client, extra=None):
            return record(label, "InitiateAuth", {"ClientId": client_id, "AuthFlow": "REFRESH_TOKEN_AUTH", "AuthParameters": dict({"REFRESH_TOKEN": token}, **(extra or {}))}, "unsigned")

        login("default-client-password-disabled", default_client, temporary)
        for mode in ("unsigned", "invalid-signature", "malformed-authorization"):
            record("protected-describe-" + mode, "DescribeUserPool", {"UserPoolId": pool}, mode)
            login("public-new-password-" + mode, value=temporary, mode=mode)
        challenge = login("new-password-challenge", value=temporary)["output"]
        challenge_args = {"ClientId": client, "ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": challenge["Session"], "ChallengeResponses": {"USERNAME": user, "NEW_PASSWORD": weak}}
        record("new-password-policy-failure", "RespondToAuthChallenge", challenge_args, "unsigned")
        challenge_args = dict(challenge_args, ChallengeResponses={"USERNAME": user, "NEW_PASSWORD": password})
        initial = required("complete-new-password", "RespondToAuthChallenge", challenge_args, "unsigned")["AuthenticationResult"]
        record("replay-new-password-session", "RespondToAuthChallenge", challenge_args, "unsigned")
        required("get-user-confirmed", "AdminGetUser", user_args)
        login("temporary-password-after-confirmation", value=temporary)
        login("incorrect-password", value="IncorrectA1!" + secrets.token_hex(12))
        login("missing-user-legacy", username="absent-user")
        login("missing-user-hidden", hidden, username="absent-user")
        for mode in ("unsigned", "invalid-signature", "malformed-authorization", "signed"):
            login("public-password-" + mode, mode=mode)
        login("admin-password-signed", mode="signed", admin=True)
        login("admin-password-unsigned", admin=True)
        record("admin-flow-on-public-api", "InitiateAuth", {"ClientId": client, "AuthFlow": "ADMIN_USER_PASSWORD_AUTH", "AuthParameters": {"USERNAME": user, "PASSWORD": password}}, "unsigned")
        login("secret-hash-missing", private_id)
        login("secret-hash-invalid", private_id, extra={"SECRET_HASH": "invalid"})
        valid_hash = secret_hash(user, private_id, private_secret)
        private_tokens = tokens(login("secret-hash-valid", private_id, extra={"SECRET_HASH": valid_hash}))
        refresh("secret-refresh-hash-missing", private_tokens["RefreshToken"], private_id)
        refresh("secret-refresh-hash-valid", private_tokens["RefreshToken"], private_id, {"SECRET_HASH": valid_hash})

        srp = AWSSRP(username=user, password=password, pool_id=pool, client_id=default_client, pool_region=REGION)
        srp_params = srp.get_auth_params()
        srp_challenge = required("default-client-srp-challenge", "InitiateAuth", {"ClientId": default_client, "AuthFlow": "USER_SRP_AUTH", "AuthParameters": srp_params}, "unsigned")
        srp_response = srp.process_challenge(srp_challenge["ChallengeParameters"], srp_params)
        srp_args = {"ClientId": default_client, "ChallengeName": "PASSWORD_VERIFIER", "ChallengeResponses": srp_response}
        if "Session" in srp_challenge:
            srp_args["Session"] = srp_challenge["Session"]
        required("default-client-srp-proof", "RespondToAuthChallenge", srp_args, "unsigned")
        record("srp-missing-a", "InitiateAuth", {"ClientId": default_client, "AuthFlow": "USER_SRP_AUTH", "AuthParameters": {"USERNAME": user}}, "unsigned")
        record("srp-zero-a", "InitiateAuth", {"ClientId": default_client, "AuthFlow": "USER_SRP_AUTH", "AuthParameters": {"USERNAME": user, "SRP_A": "0"}}, "unsigned")

        issuer = "https://" + HOST + "/" + pool
        jwks = evidence["jwks"][pool]["output"]
        record("get-user-access-token", "GetUser", {"AccessToken": initial["AccessToken"]}, "unsigned")
        record("get-user-id-token-denied", "GetUser", {"AccessToken": initial["IdToken"]}, "unsigned")
        record("get-user-invalid-signature-header", "GetUser", {"AccessToken": initial["AccessToken"]}, "invalid-signature")
        parts = initial["AccessToken"].split(".")
        signature = bytearray(decode64(parts[2]))
        signature[0] ^= 1
        tampered = ".".join(parts[:2] + [base64.urlsafe_b64encode(signature).decode().rstrip("=")])
        evidence["token_projections"]["tampered-access"] = jwt_projection(tampered, jwks, issuer, client, "access")
        record("get-user-tampered-signature", "GetUser", {"AccessToken": tampered}, "unsigned")
        renewed = tokens(refresh("refresh-success", initial["RefreshToken"]))
        refresh("refresh-wrong-client", initial["RefreshToken"], hidden)
        refresh("refresh-invalid-token", "not-a-real-refresh-token")
        independent = tokens(login("independent-session-before-revoke"))
        record("revoke-refresh-token", "RevokeToken", {"ClientId": client, "Token": initial["RefreshToken"]}, "unsigned")
        refresh("refresh-after-revoke", initial["RefreshToken"])
        record("get-user-original-after-revoke", "GetUser", {"AccessToken": initial["AccessToken"]}, "unsigned")
        record("get-user-refreshed-after-revoke", "GetUser", {"AccessToken": renewed["AccessToken"]}, "unsigned")
        record("get-user-independent-after-revoke", "GetUser", {"AccessToken": independent["AccessToken"]}, "unsigned")
        refresh("independent-refresh-after-revoke", independent["RefreshToken"])
        evidence["token_projections"]["revoked-access-offline"] = jwt_projection(initial["AccessToken"], jwks, issuer, client, "access")
        record("revoke-again", "RevokeToken", {"ClientId": client, "Token": initial["RefreshToken"]}, "unsigned")
        record("revoke-secret-missing", "RevokeToken", {"ClientId": private_id, "Token": private_tokens["RefreshToken"]}, "unsigned")
        record("revoke-secret-valid", "RevokeToken", {"ClientId": private_id, "ClientSecret": private_secret, "Token": private_tokens["RefreshToken"]}, "unsigned")
        record("global-signout", "GlobalSignOut", {"AccessToken": independent["AccessToken"]}, "unsigned")
        record("get-user-after-global-signout", "GetUser", {"AccessToken": independent["AccessToken"]}, "unsigned")
        refresh("refresh-after-global-signout", independent["RefreshToken"])
        active = tokens(login("login-after-global-signout"))
        required("admin-global-signout", "AdminUserGlobalSignOut", user_args)
        record("get-user-after-admin-signout", "GetUser", {"AccessToken": active["AccessToken"]}, "unsigned")
        refresh("refresh-after-admin-signout", active["RefreshToken"])

        active = tokens(login("login-before-disable"))
        required("disable-user", "AdminDisableUser", user_args)
        required("describe-disabled-user", "AdminGetUser", user_args)
        login("disabled-user-login")
        record("disabled-user-get-user", "GetUser", {"AccessToken": active["AccessToken"]}, "unsigned")
        refresh("disabled-user-refresh", active["RefreshToken"])
        required("enable-user", "AdminEnableUser", user_args)
        active = tokens(login("enabled-user-login"))
        record("weak-admin-set-password", "AdminSetUserPassword", dict(user_args, Password=weak, Permanent=True))
        permanent = "SetA1!" + secrets.token_hex(12)
        required("admin-set-permanent-password", "AdminSetUserPassword", dict(user_args, Password=permanent, Permanent=True))
        login("old-password-after-admin-set")
        login("new-password-after-admin-set", value=permanent)

        second = required("create-isolated-pool", "CreateUserPool", {"PoolName": evidence["prefix"] + "-isolated", "UserPoolTier": "LITE"})["UserPool"]["Id"]
        second_client = required("create-isolated-client", "CreateUserPoolClient", {"UserPoolId": second, "ClientName": "isolated", "ExplicitAuthFlows": flows})["UserPoolClient"]["ClientId"]
        record("admin-client-pool-mismatch", "AdminInitiateAuth", {"UserPoolId": second, "ClientId": client, "AuthFlow": "ADMIN_USER_PASSWORD_AUTH", "AuthParameters": {"USERNAME": user, "PASSWORD": permanent}})
        login("user-absent-from-other-pool", second_client, permanent)
        required("create-same-username-other-pool", "AdminCreateUser", {"UserPoolId": second, "Username": user, "TemporaryPassword": temporary, "MessageAction": "SUPPRESS"})
        required("set-other-pool-password", "AdminSetUserPassword", {"UserPoolId": second, "Username": user, "Password": password, "Permanent": True})
        login("other-pool-wrong-password", second_client, permanent)
        login("other-pool-correct-password", second_client, password)
        refresh("refresh-cross-pool-denied", active["RefreshToken"], second_client)

        required("delete-user", "AdminDeleteUser", user_args)
        record("describe-deleted-user", "AdminGetUser", user_args)
        login("deleted-user-login", value=permanent)
        record("deleted-user-get-user", "GetUser", {"AccessToken": active["AccessToken"]}, "unsigned")
        refresh("deleted-user-refresh", active["RefreshToken"])
        required("update-client-name", "UpdateUserPoolClient", {"UserPoolId": pool, "ClientId": hidden, "ClientName": "renamed", "ExplicitAuthFlows": flows, "PreventUserExistenceErrors": "ENABLED"})
        required("delete-client", "DeleteUserPoolClient", {"UserPoolId": pool, "ClientId": hidden})
        record("describe-deleted-client", "DescribeUserPoolClient", {"UserPoolId": pool, "ClientId": hidden})
        login("deleted-client-login", hidden, permanent)
        required("update-pool", "UpdateUserPool", {"UserPoolId": pool, "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True}})
        required("describe-updated-pool", "DescribeUserPool", {"UserPoolId": pool})
        evidence["completed_at"] = now()
        save()
    except Exception as error:
        evidence["capture_failure"] = {"type": type(error).__name__, "message": str(error)}
        save()
        raise
    finally:
        cleanup()


if __name__ == "__main__":
    main()
