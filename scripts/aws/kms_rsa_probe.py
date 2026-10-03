#!/usr/bin/env python3
"""Capture RSA KMS behavior on temporary owned keys and schedule their deletion."""

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
               "source": "AWS KMS RSA keys; owned commercial account; synthetic messages", "region": os.environ["AWS_DEFAULT_REGION"],
               "keys": [], "observations": [], "cleanup": [], "capture_complete": False}
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/rsa.json'
    ids = []

    def save():
        encoded = json.dumps(fixture, indent=2).replace(identity["Account"], "111111111111")
        for i, key in enumerate(ids):
            encoded = encoded.replace(key, f"00000000-0000-4000-8000-{i+1:012d}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded + "\n")

    def create(spec, usage):
        result = call("kms", "create-key", {"KeySpec": spec, "KeyUsage": usage, "Description": "stackd RSA conformance probe"})["KeyMetadata"]
        ids.append(result["KeyId"])
        fixture["keys"].append(result)
        save()
        print("Owned probe key: " + result["KeyId"], flush=True)
        return result["KeyId"]

    def observe(case, operation, parameters, spec, usage):
        row = {"case": case, "operation": operation, "spec": spec, "usage": usage}
        for name in ["EncryptionAlgorithm", "SigningAlgorithm", "MessageType"]:
            if name in parameters:
                row[name] = parameters[name]
        row.update(observe_cli("kms", operation, parameters))
        result = row.get("output")
        if result is not None:
            row.update(output={k: v for k, v in result.items() if k not in {"GrantToken", "PrivateKeyPlaintext", "PrivateKeyCiphertextBlob"}})
            for field in ["PrivateKeyPlaintext", "PrivateKeyCiphertextBlob"]:
                if field in result:
                    row["output"][field + "Bytes"] = len(base64.b64decode(result[field]))
        fixture["observations"].append(row)
        save()
        print(spec + " " + usage + " " + case + ": " + row["code"], flush=True)
        return result

    try:
        symmetric = create("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT")
        observe("symmetric_public_key", "get-public-key", {"KeyId": symmetric}, "SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT")
        for bits in [2048, 3072, 4096]:
            spec = f"RSA_{bits}"
            for usage in ["ENCRYPT_DECRYPT", "SIGN_VERIFY"]:
                key = create(spec, usage)
                public = observe("public_key", "get-public-key", {"KeyId": key}, spec, usage)
                if public is None:
                    raise RuntimeError("Owned RSA key has no public key")
                message = b"stackd RSA interoperability"
                if usage == "ENCRYPT_DECRYPT":
                    for algorithm, digest in [("RSAES_OAEP_SHA_1", "sha1"), ("RSAES_OAEP_SHA_256", "sha256")]:
                        parameters = {"KeyId": key, "Plaintext": b64(message), "EncryptionAlgorithm": algorithm}
                        encrypted = observe("encrypt", "encrypt", parameters, spec, usage)
                        if encrypted is None:
                            raise RuntimeError("Owned RSA key could not encrypt")
                        decrypt = {"KeyId": key, "CiphertextBlob": encrypted["CiphertextBlob"], "EncryptionAlgorithm": algorithm}
                        observe("decrypt", "decrypt", decrypt, spec, usage)
                        observe("decrypt_no_key", "decrypt", {k: v for k, v in decrypt.items() if k != "KeyId"}, spec, usage)
                        observe("decrypt_default_algorithm", "decrypt", {k: v for k, v in decrypt.items() if k != "EncryptionAlgorithm"}, spec, usage)
                        other_algorithm = "RSAES_OAEP_SHA_256" if digest == "sha1" else "RSAES_OAEP_SHA_1"
                        observe("decrypt_wrong_algorithm", "decrypt", dict(decrypt, EncryptionAlgorithm=other_algorithm), spec, usage)
                        observe("encryption_context", "encrypt", dict(parameters, EncryptionContext={"purpose": "probe"}), spec, usage)
                        observe("encryption_empty_context", "encrypt", dict(parameters, EncryptionContext={}), spec, usage)
                        observe("decryption_empty_context", "decrypt", dict(decrypt, EncryptionContext={}), spec, usage)
                        observe("decrypt_nonempty_context", "decrypt", dict(decrypt, EncryptionContext={"purpose": "probe"}), spec, usage)
                        observe("encryption_dry_run", "encrypt", dict(parameters, DryRun=True), spec, usage)
                        maximum = bits // 8 - 2 * hashlib.new(digest).digest_size - 2
                        observe("encrypt_max", "encrypt", dict(parameters, Plaintext=b64(b"a" * maximum)), spec, usage)
                        observe("encrypt_too_large", "encrypt", dict(parameters, Plaintext=b64(b"a" * (maximum + 1))), spec, usage)
                        bad = dict(decrypt, CiphertextBlob=b64(b"x" * (bits // 8)))
                        observe("invalid_ciphertext", "decrypt", bad, spec, usage)
                        observe("dry_invalid_ciphertext", "decrypt", dict(bad, DryRun=True), spec, usage)
                        with tempfile.TemporaryDirectory(prefix="stackd-rsa-public-") as directory:
                            public_path = pathlib.Path(directory) / "public.der"
                            public_path.write_bytes(base64.b64decode(public["PublicKey"]))
                            cipher = subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(public_path), "-keyform", "DER", "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:" + digest, "-pkeyopt", "rsa_mgf1_md:" + digest], input=message, capture_output=True, check=True).stdout
                        external = observe("openssl_decrypt", "decrypt", dict(decrypt, CiphertextBlob=b64(cipher)), spec, usage)
                        if external is None or base64.b64decode(external["Plaintext"]) != message:
                            raise RuntimeError("AWS did not decrypt OpenSSL RSA ciphertext")
                        moved = observe("reencrypt_to_symmetric", "re-encrypt", {"SourceKeyId": key, "SourceEncryptionAlgorithm": algorithm, "DestinationKeyId": symmetric, "CiphertextBlob": encrypted["CiphertextBlob"]}, spec, usage)
                        if moved:
                            returned = observe("reencrypt_from_symmetric", "re-encrypt", {"DestinationKeyId": key, "DestinationEncryptionAlgorithm": algorithm, "CiphertextBlob": moved["CiphertextBlob"]}, spec, usage)
                            if returned:
                                observe("decrypt_reencrypted", "decrypt", dict(decrypt, CiphertextBlob=returned["CiphertextBlob"]), spec, usage)
                    observe("encrypt_default_algorithm", "encrypt", {"KeyId": key, "Plaintext": b64(message)}, spec, usage)
                    observe("data_key_pair_asymmetric_master", "generate-data-key-pair", {"KeyId": key, "KeyPairSpec": spec}, spec, usage)
                else:
                    for algorithm in public["SigningAlgorithms"]:
                        digest = "sha" + algorithm.rsplit("_", 1)[1]
                        parameters = {"KeyId": key, "Message": b64(message), "SigningAlgorithm": algorithm}
                        signed = observe("sign_raw", "sign", parameters, spec, usage)
                        if signed is None:
                            raise RuntimeError("Owned RSA key could not sign")
                        observe("verify_raw", "verify", dict(parameters, Signature=signed["Signature"]), spec, usage)
                        observe("sign_dry_run", "sign", dict(parameters, DryRun=True), spec, usage)
                        hashed = dict(parameters, MessageType="DIGEST", Message=b64(hashlib.new(digest, message).digest()))
                        observe("verify_digest", "verify", dict(hashed, Signature=signed["Signature"]), spec, usage)
                        observe("sign_digest", "sign", hashed, spec, usage)
                        observe("wrong_digest_length", "sign", dict(hashed, Message=b64(b"short")), spec, usage)
                        wrong = dict(parameters, Signature=b64(b"x" * (bits // 8)))
                        observe("invalid_signature", "verify", wrong, spec, usage)
                        observe("dry_invalid_signature", "verify", dict(wrong, DryRun=True), spec, usage)
                    observe("external_mu", "sign", dict(parameters, MessageType="EXTERNAL_MU", Message=b64(b"a" * 64)), spec, usage)
                operations = ["GetPublicKey", "Sign", "Verify"] if usage == "SIGN_VERIFY" else ["GetPublicKey", "Encrypt", "Decrypt", "ReEncryptFrom", "ReEncryptTo"]
                for case, extra in [("compatible_grant", {}), ("constrained_grant", {"Constraints": {"EncryptionContextEquals": {"purpose": "probe"}}})]:
                    grant = observe(case, "create-grant", dict(KeyId=key, GranteePrincipal=identity["Arn"], Operations=operations, **extra), spec, usage)
                    if grant:
                        call("kms", "revoke-grant", {"KeyId": key, "GrantId": grant["GrantId"]})
                call("kms", "disable-key", {"KeyId": key})
                observe("disabled_public_key", "get-public-key", {"KeyId": key}, spec, usage)
                fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7}))
                save()
                observe("deleting_public_key", "get-public-key", {"KeyId": key}, spec, usage)
            pair = observe("data_key_pair", "generate-data-key-pair", {"KeyId": symmetric, "KeyPairSpec": spec}, spec, "ENCRYPT_DECRYPT")
            if pair:
                with tempfile.TemporaryDirectory(prefix="stackd-rsa-pair-") as directory:
                    private = pathlib.Path(directory) / "private.der"
                    private.write_bytes(base64.b64decode(pair["PrivateKeyPlaintext"]))
                    public = subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(private), "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
                fixture["observations"][-1]["public_matches_private"] = public == base64.b64decode(pair["PublicKey"])
                plaintext = call("kms", "decrypt", {"CiphertextBlob": pair["PrivateKeyCiphertextBlob"]})["Plaintext"]
                fixture["observations"][-1]["private_ciphertext_round_trip"] = plaintext == pair["PrivateKeyPlaintext"]
                save()
            observe("data_key_pair_without_plaintext", "generate-data-key-pair-without-plaintext", {"KeyId": symmetric, "KeyPairSpec": spec}, spec, "ENCRYPT_DECRYPT")
            observe("data_key_pair_dry_run", "generate-data-key-pair", {"KeyId": symmetric, "KeyPairSpec": spec, "DryRun": True}, spec, "ENCRYPT_DECRYPT")
        fixture["capture_complete"] = True
    finally:
        for key in ids:
            current = call("kms", "describe-key", {"KeyId": key})["KeyMetadata"]
            if current["KeyState"] != "PendingDeletion":
                fixture["cleanup"].append(call("kms", "schedule-key-deletion", {"KeyId": key, "PendingWindowInDays": 7}))
        save()
        print("Owned RSA probe keys are scheduled for deletion", flush=True)


if __name__ == "__main__":
    main()
