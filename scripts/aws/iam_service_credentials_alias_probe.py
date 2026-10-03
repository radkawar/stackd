#!/usr/bin/env python3
"""Probe public service-login case and rename collisions on temporary users."""

import json
import pathlib
import secrets
import sys

sys.dont_write_bytecode = True
from iam_service_credentials_probe import call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    original = "stackd-MixedCred-" + secrets.token_hex(6)
    renamed = original + "-new"
    owned = []
    observations = []
    cleanup = []

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError("Probe setup failed: " + result["code"])
        return result["output"]

    try:
        require(call("create-user", {"UserName": original}))
        owned.append(original)
        credential = require(call("create-service-specific-credential", {"UserName": original, "ServiceName": "codecommit.amazonaws.com"}))["ServiceSpecificCredential"]
        observations.append({"case": "legacy-alias-case", "preserves_input_case": credential["ServiceUserName"].startswith(original + "-at-"), "lowercases_input": credential["ServiceUserName"].startswith(original.lower() + "-at-")})
        require(call("update-user", {"UserName": original, "NewUserName": renamed}))
        owned.remove(original)
        owned.append(renamed)
        require(call("create-user", {"UserName": original}))
        owned.append(original)
        result = call("create-service-specific-credential", {"UserName": original, "ServiceName": "codecommit.amazonaws.com"})
        observations.append({"case": "recreated-username-public-alias-collision", "code": result["code"], "uses_plus_one": result.get("output", {}).get("ServiceSpecificCredential", {}).get("ServiceUserName", "").startswith(original + "+1-at-")})
    finally:
        for name in owned:
            result = call("list-service-specific-credentials", {"UserName": name})
            cleanup.append(result["code"])
            for credential in result.get("output", {}).get("ServiceSpecificCredentials", []):
                cleanup.append(call("delete-service-specific-credential", {"UserName": name, "ServiceSpecificCredentialId": credential["ServiceSpecificCredentialId"]})["code"])
            cleanup.append(call("delete-user", {"UserName": name})["code"])
            cleanup.append(call("get-user", {"UserName": name})["code"])
        path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/iam/service_credentials_authorization_aws.json'
        fixture = json.loads(path.read_text()) if path.exists() else {"observations": []}
        cases = {observation["case"] for observation in observations}
        fixture["observations"] = [observation for observation in fixture["observations"] if observation["case"] not in cases] + observations
        fixture["supplemental_cleanup"] = cleanup
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fixture, indent=2) + "\n")
        print(json.dumps({"observations": observations, "cleanup": cleanup}), flush=True)
        if any(code not in {"Success", "NoSuchEntity"} for code in cleanup) or (owned and cleanup[-1] != "NoSuchEntity"):
            raise RuntimeError("Cleanup failed; inspect temporary stackd-MixedCred users")


if __name__ == "__main__":
    main()
