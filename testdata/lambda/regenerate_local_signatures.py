#!/usr/bin/env python3
"""Regenerate public local-only Lambda and EC2 signature vectors, offline.

Requires cryptography >=45 and pycryptodome. All keys are derived from public
fixture labels: NEVER use them outside tests. No AWS keys or requests are used.
The Lambda CMS layout/digest mirrors compute/lambda/signature/sign.go; EC2 CMS
mirrors internal/services/ec2/instance_identity_crypto.go. Original ZIP entry
order, names and bodies remain inputs, including the canonical collision cases.
"""
import base64
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
import zipfile

from Crypto.Hash import SHA1, SHA256, SHA384
from Crypto.PublicKey import DSA, ECC, RSA
from Crypto.Signature import DSS, pkcs1_15
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
SIGNATURE = "META_INF/aws_signer_signature_v1.0.SF"
SIGNING_TIME = "20260928091926.806Z"
EXPIRY = "20371228091926.806Z"
PROVENANCE = {
    "kind": "locally-re-signed-regression-vector",
    "generator": "testdata/lambda/regenerate_local_signatures.py",
    "trust": "Public deterministic test keys only; not AWS signatures or native signing evidence.",
}


def der(tag, body):
    n = len(body)
    length = bytes([n]) if n < 128 else bytes([128 + (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + body


def seq(*items):
    return der(0x30, b"".join(items))


def integer(n):
    value = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    return der(2, (b"\0" if value[0] & 128 else b"") + value)


def oid(value):
    numbers = list(map(int, value.split(".")))
    encoded = bytearray([40 * numbers[0] + numbers[1]])
    for number in numbers[2:]:
        parts = [number & 127]
        while number >> 7:
            number >>= 7
            parts.insert(0, 128 | (number & 127))
        encoded.extend(parts)
    return der(6, bytes(encoded))


def aset(*items):
    return der(0x31, b"".join(sorted(items)))


def attr(name, value):
    return seq(oid(name), aset(value))


def pem(kind, value):
    encoded = base64.b64encode(value).decode()
    return f"-----BEGIN {kind}-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + f"\n-----END {kind}-----\n"


def b64(value):
    return base64.b64encode(value).decode()


def random_stream(label):
    counter = 0
    pending = b""
    def read(size):
        nonlocal counter, pending
        while len(pending) < size:
            pending += hashlib.sha256(("stackd public fixture key: " + label).encode() + counter.to_bytes(8, "big")).digest()
            counter += 1
        result, pending = pending[:size], pending[size:]
        return result
    return read


def certificate_name(label):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stackd public fixture " + label)])


def lambda_chain():
    keys, certificates = [], []
    start = datetime(2026, 9, 27, tzinfo=timezone.utc)
    for index, label in enumerate(["root", "parent", "regional", "leaf"]):
        scalar = int.from_bytes(hashlib.sha384(("stackd public fixture Signer " + label).encode()).digest(), "big") % (int(ECC._curves["P-384"].order) - 1) + 1
        key = ec.derive_private_key(scalar, ec.SECP384R1())
        issuer = keys[-1] if keys else key
        ca = label != "leaf"
        builder = (x509.CertificateBuilder().subject_name(certificate_name("Signer " + label))
                   .issuer_name(certificates[-1].subject if certificates else certificate_name("Signer " + label))
                   .public_key(key.public_key()).serial_number(index + 1).not_valid_before(start)
                   .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc) if ca else datetime(2026, 9, 30, tzinfo=timezone.utc))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
                                               data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                                               crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
        if not ca:
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
        certificates.append(builder.sign(issuer, hashes.SHA384(), ecdsa_deterministic=True))
        keys.append(key)
    scalar = keys[-1].private_numbers().private_value
    return ECC.construct(curve="P-384", d=scalar), list(reversed(certificates))


DATA = oid("1.2.840.113549.1.7.1")
SIGNED_DATA = oid("1.2.840.113549.1.7.2")
SHA384_ALG = seq(oid("2.16.840.1.101.3.4.2.2"))
ECDSA_ALG = seq(oid("1.2.840.10045.4.3.3"))


def sign_zip(unsigned, profile, job, key, chain):
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(unsigned))) as archive:
        entries = [(entry, archive.read(entry)) for entry in archive.infolist()]
    if not any(entry.filename == "META_INF/" for entry, _ in entries):
        entries.append((zipfile.ZipInfo("META_INF/", (2026, 9, 28, 9, 19, 26)), b""))
    digest = hashlib.sha384(hashlib.sha384(b"".join(entry.filename.encode() + body for entry, body in entries)).digest()).digest()
    attributes = sorted([
        attr("1.2.840.113549.1.9.3", DATA),
        attr("1.2.840.113549.1.9.4", der(4, digest)),
        attr("1.2.840.113549.1.9.5", der(24, SIGNING_TIME.encode())),
        attr("1.3.187.137.1.3", der(24, EXPIRY.encode())),
        attr("1.3.187.137.1.2", der(12, job.encode())),
        attr("1.3.187.137.1.4", der(12, profile.encode())),
        attr("1.2.840.113549.1.9.52", seq(SHA384_ALG, der(0xa1, oid("1.2.840.10045.4.3.3")))),
    ])
    signature = DSS.new(key, "deterministic-rfc6979", encoding="der").sign(SHA384.new(aset(*attributes)))
    leaf = chain[0]
    signer = seq(integer(1), seq(leaf.issuer.public_bytes(), integer(leaf.serial_number)), SHA384_ALG,
                 der(0xa0, b"".join(attributes)), ECDSA_ALG, der(4, signature))
    certificates = sorted(cert.public_bytes(serialization.Encoding.DER) for cert in chain)
    # Preserve positive BER-decoder coverage without retaining an AWS signature.
    signed_data = seq(integer(1), aset(SHA384_ALG), seq(DATA), der(0xa0, b"".join(certificates)), aset(signer))
    cms = b"\x30\x80" + SIGNED_DATA + b"\xa0\x80" + signed_data + b"\0\0\0\0"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for entry, body in entries:
            archive.writestr(entry, body)
        entry = zipfile.ZipInfo(SIGNATURE, (2026, 9, 28, 9, 19, 26))
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, pem("PKCS7", cms))
    return b64(output.getvalue())


def generate_lambda():
    key, chain = lambda_chain()
    root = b64(chain[-1].public_bytes(serialization.Encoding.DER))
    hashes = [hashlib.sha384(cert.tbs_certificate_bytes).hexdigest() for cert in chain]
    for name in ["code_signing_local.json", "signature_canonical_local.json"]:
        path = ROOT / "testdata/lambda" / name
        fixture = json.loads(path.read_text())
        fixture["provenance"] = PROVENANCE
        fixture["trustedRootCertificateBase64"] = root
        fixture["certificateHashes"] = [value + hashes[min(i + 1, len(hashes) - 1)] for i, value in enumerate(hashes)]
        for vector in fixture.get("vectors", [fixture]):
            vector["signedZipBase64"] = sign_zip(vector["unsignedZipBase64"], fixture["profileVersionArn"],
                                               "arn:aws:signer:us-east-1:000000000000:/signing-jobs/" + vector["jobId"], key, chain)
        path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n")


def identity_material(kind):
    key = DSA.generate(1024, randfunc=random_stream(kind)) if kind == "dsa" else RSA.generate(1024 if kind == "rsa" else 2048, randfunc=random_stream(kind))
    name = certificate_name("EC2 identity " + kind).public_bytes()
    algorithm = seq(oid("2.16.840.1.101.3.4.3.2")) if kind == "dsa" else seq(oid("1.2.840.113549.1.1.11"), der(5, b""))
    tbs = seq(integer(1), algorithm, name, seq(der(23, b"000101000000Z"), der(24, b"21000101000000Z")), name, key.public_key().export_key(format="DER"))
    signature = DSS.new(key, "deterministic-rfc6979", encoding="der").sign(SHA256.new(tbs)) if kind == "dsa" else pkcs1_15.new(key).sign(SHA256.new(tbs))
    return key, name, pem("CERTIFICATE", seq(tbs, algorithm, der(3, b"\0" + signature)))


def identity_signature(document, kind, key, name):
    if kind == "rsa":
        return pkcs1_15.new(key).sign(SHA256.new(document))
    legacy = kind == "dsa"
    digest_algorithm = seq(oid("1.3.14.3.2.26"), der(5, b"")) if legacy else seq(oid("2.16.840.1.101.3.4.2.1"))
    signature_oid = oid("1.2.840.10040.4.3") if legacy else oid("1.2.840.113549.1.1.11") + der(5, b"")
    h = SHA1 if legacy else SHA256
    attributes = sorted([
        attr("1.2.840.113549.1.9.3", DATA),
        attr("1.2.840.113549.1.9.4", der(4, h.new(document).digest())),
        attr("1.2.840.113549.1.9.5", der(23, b"260926110754Z")),
        attr("1.2.840.113549.1.9.52", seq(digest_algorithm, der(0xa1, signature_oid))),
    ])
    digest = h.new(aset(*attributes))
    signature = DSS.new(key, "deterministic-rfc6979", encoding="der").sign(digest) if legacy else pkcs1_15.new(key).sign(digest)
    signer = seq(integer(1), seq(name, integer(1)), digest_algorithm, der(0xa0, b"".join(attributes)), seq(signature_oid), der(4, signature))
    return seq(SIGNED_DATA, der(0xa0, seq(integer(1), aset(digest_algorithm), seq(DATA, der(0xa0, der(4, document))), aset(signer))))


def generate_ec2():
    materials = {kind: identity_material(kind) for kind in ["rsa", "dsa", "rsa2048"]}
    for name in ["identity", "empty_tags", "secondary", "tag_convergence"]:
        path = ROOT / "testdata/aws/ec2" / ("instances_metadata_" + name + "_handoff.json")
        fixture = json.loads(path.read_text())
        fixture["identity_signature_provenance"] = PROVENANCE
        fixture["identity_signature_certificates"] = {kind: value[2] for kind, value in materials.items()}
        rows = fixture["metadata_http"]
        documents = {row.get("repeat", 0): row["body"].encode() for row in rows if row["path"] == "/latest/dynamic/instance-identity/document" and row["code"] == 200}
        for row in rows:
            endpoint = row["path"].removeprefix("/latest/dynamic/instance-identity/")
            kind = {"signature": "rsa", "pkcs7": "dsa", "rsa2048": "rsa2048"}.get(endpoint)
            if kind and row["code"] == 200:
                key, subject, _ = materials[kind]
                row["body"] = b64(identity_signature(documents[row.get("repeat", 0)], kind, key, subject))
        path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    generate_lambda()
    generate_ec2()
