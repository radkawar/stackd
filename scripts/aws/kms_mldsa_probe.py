#!/usr/bin/env python3
"""Capture native ML-DSA behavior on owned temporary KMS keys."""

import base64
import datetime
import hashlib
import json
import os
import pathlib

from aws_cli import call, observe as observe_cli


def b64(value):
    return base64.b64encode(value).decode()


def raw_public_key(spki):
    # Read the outer SEQUENCE, AlgorithmIdentifier and BIT STRING from AWS's
    # DER SPKI. The final leading byte is the BIT STRING unused-bit count.
    def content(data, offset):
        length, start = data[offset + 1], offset + 2
        if length & 128:
            count = length & 127
            length = int.from_bytes(data[start:start + count], "big")
            start += count
        return data[start:start + length], start + length
    sequence, _ = content(spki, 0)
    _, end = content(sequence, 0)
    bits, _ = content(sequence, end)
    return bits[1:]


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    identity = require_account(probe_args.account)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS KMS ML-DSA; owned commercial account; synthetic messages",
               "region": os.environ["AWS_DEFAULT_REGION"], "keys": [], "observations": [], "cleanup": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/mldsa.json'
    ids = []

    def save():
        encoded = json.dumps(fixture, indent=2).replace(identity["Account"], "111111111111")
        for index, key in enumerate(ids):
            encoded = encoded.replace(key, f"00000000-0000-4000-8000-{index+1:012d}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded + "\n")

    def observe(case, operation, parameters, spec):
        row = {"case": case, "operation": operation, "spec": spec, "usage": "SIGN_VERIFY"}
        for name in ["SigningAlgorithm", "MessageType"]:
            if name in parameters:
                row[name] = parameters[name]
        row.update(observe_cli("kms", operation, parameters))
        result = row.get("output")
        if result is not None:
            row.update(output={k: v for k, v in result.items() if k != "GrantToken"})
        fixture["observations"].append(row)
        save()
        print(spec + " " + case + ": " + row["code"], flush=True)
        return result

    try:
        for size in [44, 65, 87]:
            spec = f"ML_DSA_{size}"
            for case, usage in [("default_usage", None), ("encryption_usage", "ENCRYPT_DECRYPT"), ("agreement_usage", "KEY_AGREEMENT")]:
                parameters = {"KeySpec": spec}
                if usage:
                    parameters["KeyUsage"] = usage
                unexpected = observe(case, "create-key", parameters, spec)
                if unexpected:
                    ids.append(unexpected["KeyMetadata"]["KeyId"])
                    fixture["keys"].append(unexpected["KeyMetadata"])
                    save()
            created = call("kms", "create-key", {"KeySpec": spec, "KeyUsage": "SIGN_VERIFY", "Description": "stackd ML-DSA conformance probe"})["KeyMetadata"]
            key = created["KeyId"]
            ids.append(key)
            fixture["keys"].append(created)
            save()
            print("Owned probe key: " + key, flush=True)
            public = observe("public_key", "get-public-key", {"KeyId": key}, spec)
            if public is None:
                raise RuntimeError("Owned ML-DSA key has no public key")
            message = b"stackd ML-DSA interoperability"
            raw = raw_public_key(base64.b64decode(public["PublicKey"]))
            tr = hashlib.shake_256(raw).digest(64)
            mu = hashlib.shake_256(tr + b"\x00\x00" + message).digest(64)
            parameters = {"KeyId": key, "Message": b64(message), "SigningAlgorithm": "ML_DSA_SHAKE_256"}
            signed = observe("sign_raw", "sign", parameters, spec)
            if signed is None:
                raise RuntimeError("Owned ML-DSA key could not sign")
            observe("repeat_raw", "sign", parameters, spec)
            verify = dict(parameters, Signature=signed["Signature"])
            observe("verify_raw", "verify", verify, spec)
            matched = observe("verify_raw_with_mu", "verify", dict(verify, Message=b64(mu), MessageType="EXTERNAL_MU"), spec)
            if matched is None or not matched["SignatureValid"]:
                raise RuntimeError("AWS rejected the independently computed FIPS 204 message representative")
            external = dict(parameters, Message=b64(mu), MessageType="EXTERNAL_MU")
            external_signed = observe("sign_mu", "sign", external, spec)
            if external_signed:
                observe("verify_mu_with_raw", "verify", dict(verify, Signature=external_signed["Signature"]), spec)
            observe("dry_sign", "sign", dict(parameters, DryRun=True), spec)
            observe("dry_verify", "verify", dict(verify, DryRun=True), spec)
            observe("sign_digest", "sign", dict(parameters, Message=b64(mu), MessageType="DIGEST"), spec)
            observe("verify_digest", "verify", dict(verify, Message=b64(mu), MessageType="DIGEST"), spec)
            for length in [1, 63, 65]:
                observe("mu_length_" + str(length), "sign", dict(external, Message=b64(b"x" * length)), spec)
            observe("max_raw", "sign", dict(parameters, Message=b64(b"x" * 4096)), spec)
            observe("empty_raw", "sign", dict(parameters, Message=""), spec)
            observe("wrong_algorithm", "sign", dict(parameters, SigningAlgorithm="ECDSA_SHA_256"), spec)
            signature = bytearray(base64.b64decode(signed["Signature"]))
            signature[0] ^= 1
            wrong = dict(verify, Signature=b64(signature))
            observe("invalid_signature", "verify", wrong, spec)
            observe("dry_invalid_signature", "verify", dict(wrong, DryRun=True), spec)
            observe("short_signature", "verify", dict(verify, Signature=b64(b"x")), spec)
            for case, extra in [("compatible_grant", {}), ("constrained_grant", {"Constraints": {"EncryptionContextEquals": {"purpose": "probe"}}})]:
                grant = observe(case, "create-grant", dict(KeyId=key, GranteePrincipal=identity["Arn"], Operations=["GetPublicKey", "Sign", "Verify"], **extra), spec)
                if grant:
                    call("kms", "revoke-grant", {"KeyId": key, "GrantId": grant["GrantId"]})
            call("kms", "disable-key", {"KeyId": key})
            observe("disabled_public_key", "get-public-key", {"KeyId": key}, spec)
            observe("disabled_sign", "sign", parameters, spec)
            observe("disabled_verify", "verify", verify, spec)
            fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7}))
            save()
            observe("deleting_public_key", "get-public-key", {"KeyId": key}, spec)
        fixture["capture_complete"] = True
    finally:
        for key in ids:
            current = call("kms", "describe-key", {"KeyId": key})["KeyMetadata"]
            if current["KeyState"] != "PendingDeletion":
                fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7}))
        save()
        print("Owned ML-DSA probe keys are scheduled for deletion", flush=True)


if __name__ == "__main__":
    main()
