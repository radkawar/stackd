#!/usr/bin/env python3
"""Capture ECC signing, agreement and data-key pairs on owned temporary KMS keys."""

import base64
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from aws_cli import call, observe as observe_cli


def b64(value):
    return base64.b64encode(value).decode()


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    identity = require_account(probe_args.account)
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS KMS ECC; owned commercial account; synthetic messages and ephemeral OpenSSL peers",
               "region": os.environ["AWS_DEFAULT_REGION"], "keys": [], "observations": [], "cleanup": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/ecc.json'
    ids = []
    later_reads = []

    def save():
        encoded = json.dumps(fixture, indent=2).replace(identity["Account"], "111111111111")
        for index, key in enumerate(ids):
            encoded = encoded.replace(key, f"00000000-0000-4000-8000-{index+1:012d}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded + "\n")

    def observe(case, operation, parameters, spec, usage):
        row = {"case": case, "operation": operation, "spec": spec, "usage": usage,
               "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        for name in ["SigningAlgorithm", "MessageType", "KeyAgreementAlgorithm"]:
            if name in parameters:
                row[name] = parameters[name]
        row.update(observe_cli("kms", operation, parameters))
        result = row.get("output")
        if result is not None:
            hidden = {"GrantToken", "PrivateKeyPlaintext", "PrivateKeyCiphertextBlob", "SharedSecret"}
            row.update(output={k: v for k, v in result.items() if k not in hidden})
            for field in hidden - {"GrantToken"}:
                if field in result:
                    row["output"][field + "Bytes"] = len(base64.b64decode(result[field]))
        fixture["observations"].append(row)
        save()
        print(spec + " " + usage + " " + case + ": " + row["code"], flush=True)
        return result

    def create(spec, usage):
        created = call("kms", "create-key", {"KeySpec": spec, "KeyUsage": usage, "Description": "stackd ECC conformance probe"})["KeyMetadata"]
        ids.append(created["KeyId"])
        fixture["keys"].append(created)
        save()
        print("Owned probe key: " + created["KeyId"], flush=True)
        return created["KeyId"]

    try:
        symmetric = create("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT")
        curves = [("ECC_NIST_P256", "prime256v1"), ("ECC_NIST_P384", "secp384r1"), ("ECC_NIST_P521", "secp521r1"), ("ECC_SECG_P256K1", "secp256k1"), ("ECC_NIST_EDWARDS25519", "ED25519")]
        for spec, curve in curves:
            for case, usage in [("default_usage", None), ("encryption_usage", "ENCRYPT_DECRYPT")]:
                parameters = {"KeySpec": spec}
                if usage:
                    parameters["KeyUsage"] = usage
                unexpected = observe(case, "create-key", parameters, spec, "SIGN_VERIFY")
                if unexpected:
                    ids.append(unexpected["KeyMetadata"]["KeyId"])
                    fixture["keys"].append(unexpected["KeyMetadata"])
                    save()
            usages = ["SIGN_VERIFY", "KEY_AGREEMENT"] if spec.startswith("ECC_NIST_P") else ["SIGN_VERIFY"]
            for usage in usages:
                key = create(spec, usage)
                public = observe("public_key", "get-public-key", {"KeyId": key}, spec, usage)
                if public is None:
                    raise RuntimeError("Owned ECC key has no public key")
                message = b"stackd ECC interoperability"
                if usage == "SIGN_VERIFY":
                    for algorithm in public["SigningAlgorithms"]:
                        digest = hashlib.new("sha" + algorithm.rsplit("_", 1)[1], message).digest()
                        for message_type, payload in [("RAW", message), ("DIGEST", digest), ("EXTERNAL_MU", b"a" * 64)]:
                            parameters = {"KeyId": key, "Message": b64(payload), "MessageType": message_type, "SigningAlgorithm": algorithm}
                            signed = observe("sign", "sign", parameters, spec, usage)
                            if signed:
                                observe("verify", "verify", dict(parameters, Signature=signed["Signature"]), spec, usage)
                                observe("repeat_sign", "sign", parameters, spec, usage)
                                observe("dry_sign", "sign", dict(parameters, DryRun=True), spec, usage)
                                observe("invalid_signature", "verify", dict(parameters, Signature=b64(b"invalid")), spec, usage)
                                observe("dry_invalid_signature", "verify", dict(parameters, Signature=b64(b"invalid"), DryRun=True), spec, usage)
                        observe("short_digest", "sign", {"KeyId": key, "Message": b64(b"short"), "MessageType": "DIGEST", "SigningAlgorithm": algorithm}, spec, usage)
                    observe("wrong_algorithm", "sign", {"KeyId": key, "Message": b64(message), "SigningAlgorithm": "RSASSA_PSS_SHA_256"}, spec, usage)
                    operations = ["GetPublicKey", "Sign", "Verify"]
                else:
                    with tempfile.TemporaryDirectory(prefix="stackd-ecdh-") as directory:
                        private_path = pathlib.Path(directory) / "peer.der"
                        public_path = pathlib.Path(directory) / "kms.der"
                        public_path.write_bytes(base64.b64decode(public["PublicKey"]))
                        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + curve, "-outform", "DER", "-out", str(private_path)], capture_output=True, check=True)
                        peer = subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(private_path), "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
                        parameters = {"KeyId": key, "PublicKey": b64(peer), "KeyAgreementAlgorithm": "ECDH"}
                        derived = observe("derive", "derive-shared-secret", parameters, spec, usage)
                        if derived:
                            external = subprocess.run(["openssl", "pkeyutl", "-derive", "-inkey", str(private_path), "-keyform", "DER", "-peerkey", str(public_path), "-peerform", "DER"], capture_output=True, check=True).stdout
                            fixture["observations"][-1]["openssl_matches"] = external == base64.b64decode(derived["SharedSecret"])
                            if not fixture["observations"][-1]["openssl_matches"]:
                                raise RuntimeError("OpenSSL shared secret differs from AWS")
                            save()
                        observe("derive_self", "derive-shared-secret", dict(parameters, PublicKey=public["PublicKey"]), spec, usage)
                        observe("dry_derive", "derive-shared-secret", dict(parameters, DryRun=True), spec, usage)
                        observe("invalid_public_key", "derive-shared-secret", dict(parameters, PublicKey=b64(b"invalid")), spec, usage)
                        observe("dry_invalid_public_key", "derive-shared-secret", dict(parameters, PublicKey=b64(b"invalid"), DryRun=True), spec, usage)
                        other_curve = "secp384r1" if curve == "prime256v1" else "prime256v1"
                        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + other_curve, "-outform", "DER", "-out", str(private_path)], capture_output=True, check=True)
                        wrong = subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(private_path), "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
                        observe("wrong_curve", "derive-shared-secret", dict(parameters, PublicKey=b64(wrong)), spec, usage)
                    operations = ["GetPublicKey", "DeriveSharedSecret"]
                for case, extra in [("compatible_grant", {}), ("constrained_grant", {"Constraints": {"EncryptionContextEquals": {"purpose": "probe"}}})]:
                    grant = observe(case, "create-grant", dict(KeyId=key, GranteePrincipal=identity["Arn"], Operations=operations, **extra), spec, usage)
                    if grant:
                        call("kms", "revoke-grant", {"KeyId": key, "GrantId": grant["GrantId"]})
                call("kms", "disable-key", {"KeyId": key})
                observe("disabled_public_key", "get-public-key", {"KeyId": key}, spec, usage)
                if usage == "KEY_AGREEMENT":
                    observe("disabled_derive", "derive-shared-secret", parameters, spec, usage)
                fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7}))
                save()
                if observe("deleting_public_key", "get-public-key", {"KeyId": key}, spec, usage):
                    later_reads.append((key, spec, usage))
            for case, operation in [("data_key_pair", "generate-data-key-pair"), ("data_key_pair_without_plaintext", "generate-data-key-pair-without-plaintext")]:
                pair = observe(case, operation, {"KeyId": symmetric, "KeyPairSpec": spec}, spec, "ENCRYPT_DECRYPT")
                if pair:
                    decoded = call("kms", "decrypt", {"CiphertextBlob": pair["PrivateKeyCiphertextBlob"]})["Plaintext"]
                    with tempfile.TemporaryDirectory(prefix="stackd-ecc-pair-") as directory:
                        private = pathlib.Path(directory) / "private.der"
                        private.write_bytes(base64.b64decode(decoded))
                        public = subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(private), "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
                    fixture["observations"][-1]["public_matches_private"] = public == base64.b64decode(pair["PublicKey"])
                    fixture["observations"][-1]["private_ciphertext_round_trip"] = "PrivateKeyPlaintext" not in pair or decoded == pair["PrivateKeyPlaintext"]
                    save()
        fixture["capture_complete"] = True
    finally:
        for key in ids:
            current = call("kms", "describe-key", {"KeyId": key})["KeyMetadata"]
            if current["KeyState"] != "PendingDeletion":
                fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7}))
        for key, spec, usage in later_reads:
            observe("later_deleting_public_key", "get-public-key", {"KeyId": key}, spec, usage)
        save()
        print("Owned ECC probe keys are scheduled for deletion", flush=True)


if __name__ == "__main__":
    main()
