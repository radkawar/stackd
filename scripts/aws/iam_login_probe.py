#!/usr/bin/env python3
"""Probe real IAM login behavior using one temporary user, then delete it.

Uses the AWS CLI's current credential configuration. Creates a login profile,
access key, and a policy allowing that user only to change its own password.
Does not change shared account password policies or aliases. Passwords and key
material are generated at runtime and never written into the result fixture.
"""

import datetime
import json
import os
import pathlib
import secrets
import time

from aws_cli import run as run_cli, result as cli_result, error_code


def call(operation, parameters=None, env=None):
    process = run_cli("iam", operation, parameters, env, options=["--no-paginate"])
    if process.returncode:
        return {"code": error_code(process)}
    return cli_result(process)


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    name = "stackd-login-probe-" + secrets.token_hex(8)
    first = "Aa1!" + secrets.token_urlsafe(24)
    second = "Bb2!" + secrets.token_urlsafe(24)
    owned_user = owned_profile = owned_policy = False
    access_key = None
    observations = []

    def observe(case, operation, parameters=None, env=None):
        result = call(operation, parameters, env)
        observation = {"case": case, "code": result["code"]}
        if "LoginProfile" in result.get("output", {}):
            observation["password_reset_required"] = result["output"]["LoginProfile"].get("PasswordResetRequired")
        observations.append(observation)
        print(f"{case}: {result['code']}", flush=True)
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError("Probe setup failed: " + result["code"])
        return result["output"]

    try:
        policy = call("get-account-password-policy")
        if policy["code"] != "NoSuchEntity":
            raise RuntimeError("This default-policy probe requires an account with no custom password policy")
        user = require(observe("create_user", "create-user", {"UserName": name, "Tags": [{"Key": "stackd-probe", "Value": "login-profile"}]}))
        owned_user = True
        weak = observe("default_policy_weak_password", "create-login-profile", {"UserName": name, "Password": "abc123"})
        owned_profile = weak["code"] == "Success"
        if owned_profile:
            require(observe("set_strong_password", "update-login-profile", {"UserName": name, "Password": first, "PasswordResetRequired": True}))
        else:
            require(observe("create_strong_password", "create-login-profile", {"UserName": name, "Password": first, "PasswordResetRequired": True}))
            owned_profile = True
        observe("duplicate_login_profile", "create-login-profile", {"UserName": name, "Password": first})
        observe("update_no_fields", "update-login-profile", {"UserName": name})
        observe("get_login_profile", "get-login-profile", {"UserName": name})
        observe("set_reset_required", "update-login-profile", {"UserName": name, "PasswordResetRequired": True})
        observe("password_update_omitting_reset_flag", "update-login-profile", {"UserName": name, "Password": second})
        observe("get_after_password_update", "get-login-profile", {"UserName": name})
        permission = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:ChangePassword", "Resource": user["User"]["Arn"]}]}
        require(observe("grant_self_change", "put-user-policy", {"UserName": name, "PolicyName": "stackd-probe-self-change", "PolicyDocument": json.dumps(permission)}))
        owned_policy = True
        access_key = require(observe("create_access_key", "create-access-key", {"UserName": name}))["AccessKey"]
        env = dict(os.environ, AWS_ACCESS_KEY_ID=access_key["AccessKeyId"], AWS_SECRET_ACCESS_KEY=access_key["SecretAccessKey"])
        env.pop("AWS_SESSION_TOKEN", None)
        env.pop("AWS_PROFILE", None)
        for _ in range(15):
            changed = call("change-password", {"OldPassword": second, "NewPassword": first}, env)
            if changed["code"] not in {"InvalidClientTokenId", "AccessDenied"}:
                break
            time.sleep(1)
        observations.append({"case": "change_correct_password", "code": changed["code"]})
        require(changed)
        observe("change_incorrect_old_password", "change-password", {"OldPassword": second, "NewPassword": "Cc3!" + secrets.token_urlsafe(24)}, env)
        observe("change_to_same_password", "change-password", {"OldPassword": first, "NewPassword": first}, env)
        observe("get_after_self_change", "get-login-profile", {"UserName": name})
        observe("delete_user_with_profile", "delete-user", {"UserName": name})
    finally:
        cleanup = []
        if access_key:
            cleanup.append(call("delete-access-key", {"UserName": name, "AccessKeyId": access_key["AccessKeyId"]})["code"])
        if owned_policy:
            cleanup.append(call("delete-user-policy", {"UserName": name, "PolicyName": "stackd-probe-self-change"})["code"])
        if owned_profile:
            cleanup.append(call("delete-login-profile", {"UserName": name})["code"])
        if owned_user:
            cleanup.append(call("delete-user", {"UserName": name})["code"])
            cleanup.append(call("get-user", {"UserName": name})["code"])
        fixture = {
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": "Real AWS IAM API; temporary owned user/profile/access key; no custom account password policy. Identifiers and credentials omitted.",
            "observations": observations,
            "cleanup": cleanup,
            "limits": ["No shared account password policy or alias was changed.", "History/alias rules are based on official documentation, not this experiment."],
            "reference_urls": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html", "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ChangePassword.html"],
        }
        destination = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/iam/login_profile_aws.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2) + "\n")
        if owned_user and (cleanup[-1] != "NoSuchEntity" or any(code != "Success" for code in cleanup[:-1])):
            raise RuntimeError("Probe cleanup failed; inspect the cleanup entries and the stackd-login-probe resources")


if __name__ == "__main__":
    main()
