#!/usr/bin/env python3
"""Probe service-credential permissions and public token syntax on owned users."""

import base64
import datetime
import json
import os
import pathlib
import secrets
import sys
import time

sys.dont_write_bytecode = True
from iam_service_credentials_probe import call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    prefix = "stackd-svcauth-" + secrets.token_hex(8)
    actor, target = prefix + "-actor", prefix + "-target"
    owned = []
    access_key = None
    observations = []

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError("Probe setup failed: " + result["code"])
        return result["output"]

    def observe(case, result):
        observations.append({"case": case, "code": result["code"]})
        print(case + ": " + result["code"], flush=True)
        return result

    def clear_credentials():
        for name in owned:
            for credential in require(call("list-service-specific-credentials", {"UserName": name})).get("ServiceSpecificCredentials", []):
                require(call("delete-service-specific-credential", {"UserName": name, "ServiceSpecificCredentialId": credential["ServiceSpecificCredentialId"]}))

    try:
        user_records = {}
        for name in [actor, target]:
            user_records[name] = require(call("create-user", {"UserName": name}))["User"]
            owned.append(name)
        for service in ["bedrock.amazonaws.com", "logs.amazonaws.com", "cloudwatch.amazonaws.com", "aws-external-anthropic.amazonaws.com"]:
            created = require(call("create-service-specific-credential", {"UserName": target, "ServiceName": service}))["ServiceSpecificCredential"]
            secret, alias = created["ServiceCredentialSecret"], created["ServiceCredentialAlias"]
            shape = {"case": service + ":public-token-envelope", "found_alias_payload": False}
            for offset in range(17):
                try:
                    payload = base64.b64decode(secret[offset:], validate=True).decode()
                except (ValueError, UnicodeError):
                    continue
                if payload.startswith(alias + ":"):
                    shape.update(found_alias_payload=True, public_prefix=secret[:offset], secret_payload_length=len(payload) - len(alias) - 1)
                    break
            observations.append(shape)
            print(service + ": public envelope identified=" + str(shape["found_alias_payload"]), flush=True)
            for operation in ["update-service-specific-credential", "delete-service-specific-credential"]:
                parameters = {"UserName": actor, "ServiceSpecificCredentialId": created["ServiceSpecificCredentialId"]}
                if operation.startswith("update"):
                    parameters["Status"] = "Inactive"
                observe(service + ":wrong-owner-" + operation, call(operation, parameters))
        credential = require(call("create-service-specific-credential", {"UserName": target, "ServiceName": "codecommit.amazonaws.com", "CredentialAgeDays": 1}))["ServiceSpecificCredential"]
        clear_credentials()
        credential = require(call("create-service-specific-credential", {"UserName": target, "ServiceName": "codecommit.amazonaws.com"}))["ServiceSpecificCredential"]
        access_key = require(call("create-access-key", {"UserName": actor}))["AccessKey"]
        env = dict(os.environ, AWS_ACCESS_KEY_ID=access_key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=access_key["SecretAccessKey"])
        env.pop("AWS_SESSION_TOKEN", None)
        env.pop("AWS_PROFILE", None)
        for label, resource in [("self", user_records[actor]["Arn"]), ("target", user_records[target]["Arn"]), ("account-users", user_records[actor]["Arn"].rsplit("/", 1)[0] + "/*"), ("global", "*")]:
            policy = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "iam:ListServiceSpecificCredentials", "Resource": resource}}
            require(call("put-user-policy", {"UserName": actor, "PolicyName": "Probe", "PolicyDocument": json.dumps(policy)}))
            time.sleep(5)
            for case, parameters in [("all-users", {"AllUsers": True}), ("target-user", {"UserName": target}), ("self-implicit", {})]:
                observe(label + ":" + case, call("list-service-specific-credentials", parameters, env))
        policy = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "iam:CreateServiceSpecificCredential", "Resource": user_records[actor]["Arn"], "Condition": {"StringEquals": {"iam:ServiceSpecificCredentialServiceName": "codecommit.amazonaws.com"}, "NumericLessThanEquals": {"iam:ServiceSpecificCredentialAgeDays": "2"}}}}
        require(call("put-user-policy", {"UserName": actor, "PolicyName": "Probe", "PolicyDocument": json.dumps(policy)}))
        time.sleep(5)
        for label, parameters in [("uppercase-service-condition", {"UserName": actor, "ServiceName": "CodeCommit.amazonaws.com", "CredentialAgeDays": 1}), ("omitted-age-condition", {"UserName": actor, "ServiceName": "codecommit.amazonaws.com"}), ("lowercase-service-condition", {"UserName": actor, "ServiceName": "codecommit.amazonaws.com", "CredentialAgeDays": 1})]:
            observe(label, call("create-service-specific-credential", parameters, env))
    finally:
        cleanup = []
        if access_key:
            cleanup.append(call("delete-access-key", {"UserName": actor, "AccessKeyId": access_key["AccessKeyId"]})["code"])
        if actor in owned:
            cleanup.append(call("delete-user-policy", {"UserName": actor, "PolicyName": "Probe"})["code"])
        for name in owned:
            result = call("list-service-specific-credentials", {"UserName": name})
            cleanup.append(result["code"])
            for record in result.get("output", {}).get("ServiceSpecificCredentials", []):
                cleanup.append(call("delete-service-specific-credential", {"UserName": name, "ServiceSpecificCredentialId": record["ServiceSpecificCredentialId"]})["code"])
            cleanup.append(call("delete-user", {"UserName": name})["code"])
            cleanup.append(call("get-user", {"UserName": name})["code"])
        fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": "Real AWS IAM; owned temporary users, service credentials, inline permission policy and access key. Secrets never persisted.", "observations": observations, "cleanup": cleanup}
        destination = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/iam/service_credentials_authorization_aws.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2) + "\n")
        if any(code not in {"Success", "NoSuchEntity"} for code in cleanup) or (owned and cleanup[-1] != "NoSuchEntity"):
            raise RuntimeError("Cleanup failed; inspect owned stackd-svcauth users")


if __name__ == "__main__":
    main()
