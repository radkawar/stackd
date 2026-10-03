#!/usr/bin/env python3
"""Capture HMAC behavior on owned temporary KMS keys; schedule their deletion."""

import base64
import datetime
import json
import os
import pathlib

from aws_cli import call, observe as observe_cli


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    identity = require_account(probe_args.account)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS KMS; commercial management account; temporary HMAC keys", "region": os.environ["AWS_DEFAULT_REGION"],
               "observations": [], "keys": [], "cleanup": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/hmac.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    ids = []

    def save():
        encoded = json.dumps(fixture, indent=2).replace(identity["Account"], "111111111111")
        for index, key in enumerate(ids):
            encoded = encoded.replace(key, f"00000000-0000-4000-8000-{index+1:012d}")
        path.write_text(encoded + "\n")

    def observe(case, operation, parameters, spec):
        row = {"case": case, "operation": operation, "spec": spec}
        if "MacAlgorithm" in parameters:
            row["algorithm"] = parameters["MacAlgorithm"]
        row.update(observe_cli("kms", operation, parameters))
        result = row.get("output")
        if result is not None:
            row["output"] = {k: v for k, v in result.items() if k not in {"Mac", "GrantToken"}}
            if "Mac" in result:
                row["output"]["mac_bytes"] = len(base64.b64decode(result["Mac"]))
        fixture["observations"].append(row)
        save()
        print(spec + " " + case + ": " + row["code"], flush=True)
        return result

    try:
        for bits in [224, 256, 384, 512]:
            spec, algorithm = f"HMAC_{bits}", f"HMAC_SHA_{bits}"
            for case, extra in [("default_usage", {}), ("incompatible_usage", {"KeyUsage": "ENCRYPT_DECRYPT"})]:
                result = observe(case, "create-key", dict(KeySpec=spec, **extra), spec)
                if result:
                    ids.append(result["KeyMetadata"]["KeyId"])
                    fixture["keys"].append(result["KeyMetadata"])
                    save()
            created = call("kms", "create-key", {"KeySpec": spec, "KeyUsage": "GENERATE_VERIFY_MAC", "Description": "stackd HMAC conformance probe"})["KeyMetadata"]
            key = created["KeyId"]
            ids.append(key)
            fixture["keys"].append(created)
            save()
            print("Owned probe key: " + key, flush=True)
            message = base64.b64encode(b"stackd HMAC behavior").decode()
            parameters = {"KeyId": key, "Message": message, "MacAlgorithm": algorithm}
            generated = observe("generate", "generate-mac", parameters, spec)
            if generated is None:
                raise RuntimeError("Owned HMAC key could not generate a MAC")
            repeated = observe("repeat", "generate-mac", parameters, spec)
            fixture["observations"][-1]["same_mac"] = repeated is not None and repeated["Mac"] == generated["Mac"]
            verify = dict(parameters, Mac=generated["Mac"])
            observe("verify", "verify-mac", verify, spec)
            observe("wrong_algorithm", "generate-mac", dict(parameters, MacAlgorithm="HMAC_SHA_512" if bits != 512 else "HMAC_SHA_256"), spec)
            incorrect = bytearray(base64.b64decode(generated["Mac"]))
            incorrect[0] ^= 1
            wrong = dict(verify, Mac=base64.b64encode(incorrect).decode())
            observe("wrong_mac", "verify-mac", wrong, spec)
            observe("short_mac", "verify-mac", dict(verify, Mac=base64.b64encode(b"x").decode()), spec)
            observe("dry_generate", "generate-mac", dict(parameters, DryRun=True), spec)
            observe("dry_verify_wrong_mac", "verify-mac", dict(wrong, DryRun=True), spec)
            observe("max_message", "generate-mac", dict(parameters, Message=base64.b64encode(b"a" * 4096).decode()), spec)
            observe("empty_message", "generate-mac", dict(parameters, Message=""), spec)
            observe("encrypt_with_hmac", "encrypt", {"KeyId": key, "Plaintext": message}, spec)
            grant = observe("mac_grant", "create-grant", {"KeyId": key, "GranteePrincipal": identity["Arn"], "Operations": ["GenerateMac", "VerifyMac"]}, spec)
            if grant:
                call("kms", "revoke-grant", {"KeyId": key, "GrantId": grant["GrantId"]})
            for case, extra in [("encryption_grant", {"Operations": ["Encrypt"]}), ("constrained_mac_grant", {"Operations": ["GenerateMac"], "Constraints": {"EncryptionContextEquals": {"purpose": "probe"}}})]:
                grant = observe(case, "create-grant", dict(KeyId=key, GranteePrincipal=identity["Arn"], **extra), spec)
                if grant:
                    call("kms", "revoke-grant", {"KeyId": key, "GrantId": grant["GrantId"]})
            call("kms", "disable-key", {"KeyId": key})
            observe("disabled_generate", "generate-mac", parameters, spec)
            observe("disabled_wrong_algorithm", "generate-mac", dict(parameters, MacAlgorithm="HMAC_SHA_512" if bits != 512 else "HMAC_SHA_256"), spec)
            scheduled = call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7})
            fixture["cleanup"].append(scheduled)
            save()
            observe("pending_deletion_generate", "generate-mac", parameters, spec)
        fixture["capture_complete"] = True
    finally:
        for key in ids:
            current = call("kms", "describe-key", {"KeyId": key})["KeyMetadata"]
            if current["KeyState"] != "PendingDeletion":
                fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7}))
        save()
        print("Temporary HMAC keys are scheduled for deletion", flush=True)


if __name__ == "__main__":
    main()
