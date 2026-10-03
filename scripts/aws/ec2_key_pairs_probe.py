#!/usr/bin/env python3
"""Capture owned, non-compute EC2 key pairs; retain no private keys or credentials.

Requires Python cryptography. AWS CLI output/debug logs remain in memory; retained
XML replaces generated keyMaterial with a marker after independent crypto checks.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import struct
import uuid
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec

from aws_cli import call, raw_xml, result, run
from cloudtrail_events import CollectionError, collect_history



MARKER = "<private-material-verified-and-discarded>"


def ssh_field(value):
    return struct.pack(">I", len(value)) + value


def fields(value):
    parts = []
    while value:
        size = struct.unpack(">I", value[:4])[0]
        parts.append(value[4:4+size])
        value = value[4+size:]
    return parts


def private_evidence(material, key_type, key_format, fingerprint):
    body = material.encode()
    evidence = {"key_type": key_type, "key_format": key_format, "header": material.splitlines()[0]}
    if key_format == "ppk":
        lines = material.splitlines()
        values, sections, index = {}, {}, 0
        while index < len(lines):
            key, value = lines[index].split(": ", 1)
            index += 1
            if key in ("Public-Lines", "Private-Lines"):
                sections[key] = base64.b64decode("".join(lines[index:index+int(value)]))
                index += int(value)
            else:
                values[key] = value
        algorithm = values["PuTTY-User-Key-File-2"]
        public = sections["Public-Lines"]
        secret = sections["Private-Lines"]
        mac_data = b"".join(ssh_field(value) for value in (algorithm.encode(), values["Encryption"].encode(), values["Comment"].encode(), public, secret))
        mac = hmac.new(hashlib.sha1(b"putty-private-key-file-mac-key").digest(), mac_data, hashlib.sha1).hexdigest()
        assert hmac.compare_digest(mac, values["Private-MAC"]), "PPK MAC mismatch"
        evidence.update({"ppk_mac_valid": True, "ppk_comment": values["Comment"], "ppk_encryption": values["Encryption"]})
        pub, priv = fields(public), fields(secret)
        if key_type == "rsa":
            e, n = (int.from_bytes(value, "big") for value in pub[1:])
            d, p, q, iqmp = (int.from_bytes(value, "big") for value in priv)
            key = rsa.RSAPrivateNumbers(p, q, d, d % (p-1), d % (q-1), iqmp, rsa.RSAPublicNumbers(e, n)).private_key()
        else:
            key = ed25519.Ed25519PrivateKey.from_private_bytes(priv[0][:32])
    elif body.startswith(b"-----BEGIN OPENSSH"):
        key = serialization.load_ssh_private_key(body, password=None)
    else:
        key = serialization.load_pem_private_key(body, password=None)
    public_text = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    public_wire = base64.b64decode(public_text.split()[1])
    if key_type == "rsa":
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        calculated = hashlib.sha1(der).digest().hex(":")
        evidence.update({"bits": key.key_size, "fingerprint_algorithm": "SHA1-PKCS8-private-DER"})
    else:
        calculated = base64.b64encode(hashlib.sha256(public_wire).digest()).decode().rstrip("=")
        evidence["fingerprint_algorithm"] = "SHA256-SSH-public-blob-base64"
    evidence["fingerprint_matches"] = fingerprint.removeprefix("SHA256:").rstrip("=") == calculated
    assert evidence["fingerprint_matches"], "Native fingerprint did not match generated material"
    evidence["derived_public_key"] = public_text
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/key_pairs.json"))
    parser.add_argument("--audit-only", action="store_true", help="Read delayed CloudTrail events for the existing capture")
    parser.add_argument("--supplement", action="store_true", help="Capture additional import and selector boundaries instead of the primary workflow")
    parser.add_argument("--import-boundaries", action="store_true", help="Probe constructed public-only RSA lengths and multiple authorized-key lines")
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION=args.region, AWS_DEFAULT_REGION=args.region, AWS_MAX_ATTEMPTS="1")
    identity = call("sts", "get-caller-identity", env=env)
    if identity["Account"] != args.account:
        raise RuntimeError("Refusing writes outside the authorized account")
    if args.audit_only:
        evidence = json.loads(args.output.read_text())
        if evidence["account"] != args.account or evidence["region"] != args.region:
            raise RuntimeError("Capture account/region mismatch")
        try:
            capture_audit(evidence, env)
        finally:
            args.output.write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({"audit_events": len(evidence["cloudtrail"]["events"]), "missing": evidence["cloudtrail"]["missing"]}))
        return
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    prefix = "stackd-kp-" + uuid.uuid4().hex[:12]
    evidence = {"account": args.account, "region": args.region, "prefix": prefix,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "documentation": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateKeyPair.html", "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ImportKeyPair.html", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-keys.html"],
        "redaction": "Private key material is parsed and checked in memory, then discarded. Raw XML replaces keyMaterial; no credentials or CLI debug logs are retained.",
        "calls": [], "cleanup": {"deleted_ids": [], "remaining_owned": None}}
    owned = set()
    generated = {}

    def observe(label, operation, parameters):
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        process = run("ec2", operation, parameters, env, options=["--debug", "--no-paginate", "--cli-binary-format", "base64", "--cli-connect-timeout", "10", "--cli-read-timeout", "30"], timeout=60)
        observed = result(process, debug=True)
        raw = raw_xml(process)
        row = {"sequence": len(evidence["calls"])+1, "label": label, "service": "ec2", "operation": operation, "input": parameters, "started_at": started,
               "code": observed["code"], "http_status": observed.get("http_status", 0)}
        output = observed.get("output", {})
        if observed["code"] == "Success" and operation in ("create-key-pair", "import-key-pair"):
            owned.add(output["KeyPairId"])
        if "KeyMaterial" in output:
            check = private_evidence(output.pop("KeyMaterial"), parameters.get("KeyType", "rsa"), parameters.get("KeyFormat", "pem"), output["KeyFingerprint"])
            row["crypto"] = check
            generated[output["KeyPairId"]] = check["derived_public_key"]
            output["KeyMaterial"] = MARKER
        if operation == "describe-key-pairs":
            for pair in output.get("KeyPairs", []):
                if pair.get("KeyPairId") in generated and "PublicKey" in pair:
                    assert " ".join(pair["PublicKey"].split()[:2]) == generated[pair["KeyPairId"]], "Described public key mismatch"
                    row.setdefault("crypto_public_matches", []).append(pair["KeyPairId"])
        if raw is not None:
            text = raw.decode()
            text = re.sub(r"(<keyMaterial>).*?(</keyMaterial>)", r"\1private-material-verified-and-discarded\2", text, flags=re.S)
            root = ET.fromstring(text)
            row["requestID"] = next((node.text for node in root.iter() if node.tag.split("}")[-1] in ("requestId", "RequestID")), None)
            row["rawResponseBody"] = text
        row["output"] = output
        if "message" in observed:
            row["message"] = observed["message"]
        evidence["calls"].append(row)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
        print(label + ": " + row["code"], flush=True)
        return output

    def describe(label, **parameters):
        return observe(label, "describe-key-pairs", parameters)

    def imported(label, material, **extra):
        return observe(label, "import-key-pair", {"KeyName": prefix+"-"+label, "PublicKeyMaterial": base64.b64encode(material).decode(), **extra})

    def primary():
        tags = [{"ResourceType": "key-pair", "Tags": [{"Key": "Name", "Value": "probe"}, {"Key": "suite", "Value": prefix}]}]
        pairs = []
        for key_type in ("rsa", "ed25519"):
            for key_format in ("pem", "ppk"):
                name = prefix + "-" + key_type + "-" + key_format
                pair = observe("create-"+key_type+"-"+key_format, "create-key-pair", {"KeyName": name, "KeyType": key_type, "KeyFormat": key_format, "TagSpecifications": tags})
                pairs.append(pair)
                describe("describe-"+key_type+"-"+key_format, KeyPairIds=[pair["KeyPairId"]], IncludePublicKey=True)
        first, second = pairs[:2]
        observe("duplicate", "create-key-pair", {"KeyName": first["KeyName"]})
        describe("describe-default-public-omitted", KeyNames=[first["KeyName"]])
        describe("describe-name-id-same", KeyNames=[first["KeyName"]], KeyPairIds=[first["KeyPairId"]])
        describe("describe-name-id-mismatch", KeyNames=[first["KeyName"]], KeyPairIds=[second["KeyPairId"]])
        describe("describe-duplicate-selectors", KeyNames=[first["KeyName"], first["KeyName"]])
        missing = prefix + "-missing"
        missing_id = "key-00000000000000000"
        for label, parameters in [("missing-name", {"KeyNames": [missing]}), ("missing-id", {"KeyPairIds": [missing_id]}), ("malformed-id", {"KeyPairIds": ["bad"]}), ("empty-name", {"KeyNames": [""]}), ("mixed-missing", {"KeyNames": [first["KeyName"], missing]}), ("existing-name-missing-id", {"KeyNames": [first["KeyName"]], "KeyPairIds": [missing_id]})]:
            describe("describe-"+label, **parameters)
        for label, filters in [("name", [{"Name": "key-name", "Values": [prefix+"-rsa-*"]}]), ("id", [{"Name": "key-pair-id", "Values": [first["KeyPairId"]]}]), ("fingerprint", [{"Name": "fingerprint", "Values": [first["KeyFingerprint"]]}]), ("tag", [{"Name": "tag:suite", "Values": [prefix]}]), ("tag-key", [{"Name": "tag-key", "Values": ["suite"]}, {"Name": "key-name", "Values": [prefix+"-*"]}]), ("unknown", [{"Name": "unsupported", "Values": ["x"]}]), ("key-type", [{"Name": "key-type", "Values": ["rsa"]}]), ("empty-values", [{"Name": "key-name", "Values": []}])]:
            describe("filter-"+label, Filters=filters)
        describe("filter-selector-intersection", KeyNames=[first["KeyName"]], Filters=[{"Name": "key-name", "Values": [second["KeyName"]]}])
        observe("tag-update", "create-tags", {"Resources": [first["KeyPairId"]], "Tags": [{"Key": "Name", "Value": "changed"}]})
        describe("describe-retagged", KeyPairIds=[first["KeyPairId"]], IncludePublicKey=True)
        observe("tag-delete", "delete-tags", {"Resources": [first["KeyPairId"]], "Tags": [{"Key": "Name"}]})
        describe("describe-untagged", KeyPairIds=[first["KeyPairId"]])
        for label, parameters in [("empty-name", {"KeyName": ""}), ("missing-name", {}), ("long-name", {"KeyName": prefix+"x"*256}), ("leading-space", {"KeyName": " "+prefix+"-space"}), ("newline-name", {"KeyName": prefix+"\nname"}), ("unicode-name", {"KeyName": prefix+"-é"}), ("invalid-type", {"KeyName": prefix+"-badtype", "KeyType": "ecdsa"}), ("invalid-format", {"KeyName": prefix+"-badformat", "KeyFormat": "der"}), ("wrong-tag-resource", {"KeyName": prefix+"-badtag", "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "x", "Value": "y"}]}]})]:
            observe("create-"+label, "create-key-pair", parameters)
        for label, parameters in [("normal", {"KeyName": prefix+"-dry"}), ("duplicate", {"KeyName": first["KeyName"]}), ("empty", {"KeyName": ""}), ("type", {"KeyName": prefix+"-drytype", "KeyType": "bad"})]:
            observe("dry-create-"+label, "create-key-pair", {**parameters, "DryRun": True})
        describe("dry-describe-missing", KeyNames=[missing], DryRun=True)
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ed_key = ed25519.Ed25519PrivateKey.generate()
        for key_type, key in (("rsa", rsa_key), ("ed25519", ed_key)):
            public = key.public_key()
            openssh = public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
            blob = openssh.split()[1]
            rfc = b"---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"owned probe\"\n" + blob + b"\n---- END SSH2 PUBLIC KEY ----\n"
            formats = [("openssh", openssh), ("comment", openssh+b" owned comment\n"), ("rfc4716", rfc), ("pem-spki", public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)), ("der-spki", public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))]
            if key_type == "rsa":
                formats += [("pem-pkcs1", public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)), ("der-pkcs1", public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1))]
            for format_name, material in formats:
                pair = imported("import-"+key_type+"-"+format_name, material, TagSpecifications=tags)
                if "KeyPairId" in pair:
                    describe("describe-import-"+key_type+"-"+format_name, KeyPairIds=[pair["KeyPairId"]], IncludePublicKey=True)
            imported("import-"+key_type+"-options", b'no-port-forwarding '+openssh)
        imported("import-rsa-1024", rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH))
        imported("import-ecdsa", ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH))
        imported("import-empty", b"")
        imported("import-malformed", b"not a public key")
        imported("dry-import-malformed", b"not a public key", DryRun=True)
        observe("import-duplicate-malformed", "import-key-pair", {"KeyName": first["KeyName"], "PublicKeyMaterial": base64.b64encode(b"bad").decode()})
        observe("dry-delete-missing", "delete-key-pair", {"KeyName": missing, "DryRun": True})
        observe("delete-no-selector", "delete-key-pair", {})
        observe("delete-missing-name", "delete-key-pair", {"KeyName": missing})
        observe("delete-missing-id", "delete-key-pair", {"KeyPairId": missing_id})
        observe("delete-malformed-id", "delete-key-pair", {"KeyPairId": "bad"})
        observe("delete-mismatch", "delete-key-pair", {"KeyName": first["KeyName"], "KeyPairId": second["KeyPairId"]})
        describe("describe-after-mismatch", Filters=[{"Name": "key-name", "Values": [prefix+"-rsa-*"]}])
        observe("delete-existing-id-missing-name", "delete-key-pair", {"KeyName": missing, "KeyPairId": first["KeyPairId"]})
        describe("describe-after-delete-selectors", Filters=[{"Name": "key-name", "Values": [prefix+"-rsa-*"]}])
    def supplement():
        tags = [{"ResourceType": "key-pair", "Tags": [{"Key": "suite", "Value": prefix}]}]
        for bits in (3072, 4096):
            public = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
            imported("import-rsa-"+str(bits), public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH), TagSpecifications=tags)
        public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        for name, form in (("spki", serialization.PublicFormat.SubjectPublicKeyInfo), ("pkcs1", serialization.PublicFormat.PKCS1)):
            pair = imported("import-rsa-base64-der-"+name, base64.b64encode(public.public_bytes(serialization.Encoding.DER, form)))
            if pair.get("KeyPairId"):
                describe("describe-base64-der-"+name, KeyPairIds=[pair["KeyPairId"]], IncludePublicKey=True)
        pair = imported("import-selector", public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH), TagSpecifications=tags)
        for key_id in ("key-0123456789abcdef0", "key-12345678", "key-123456789abcdef01", "key-fffffffffffffffff"):
            describe("describe-absent-"+key_id, KeyPairIds=[key_id])
            # Only delete IDs previously created by this process; arbitrary
            # syntactically valid IDs are read-only probes, not deletion targets.
        describe("filter-tag-value", Filters=[{"Name": "tag-value", "Values": [prefix]}])
        describe("dry-describe-both", KeyNames=[pair["KeyName"]], KeyPairIds=[pair["KeyPairId"]], DryRun=True)
        describe("dry-describe-malformed", KeyPairIds=["bad"], DryRun=True)
        for label, request in (("none", {}), ("malformed", {"KeyPairId": "bad"}), ("empty", {"KeyName": ""})):
            observe("dry-delete-"+label, "delete-key-pair", {**request, "DryRun": True})
        observe("delete-owned-id", "delete-key-pair", {"KeyPairId": pair["KeyPairId"]})
        observe("delete-absent-owned-id", "delete-key-pair", {"KeyPairId": pair["KeyPairId"]})
        observe("delete-absent-id-existing-name", "delete-key-pair", {"KeyPairId": pair["KeyPairId"], "KeyName": prefix+"-import-rsa-3072"})
        describe("describe-retained-name-after-id-precedence", KeyNames=[prefix+"-import-rsa-3072"], IncludePublicKey=True)

    def import_boundaries():
        evidence["constructed_public_inputs"] = "RSA size cases use public N = 2**(bits-1)+65537, E=65537; no private key exists in this probe. These establish admission only, not usable generated keys."
        for bits in (512, 768, 1023, 1025, 1536, 8192, 16384, 16385, 32768):
            public = rsa.RSAPublicNumbers(65537, (1 << (bits-1)) + 65537).public_key()
            pair = imported("import-rsa-constructed-"+str(bits), public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH))
            if pair.get("KeyPairId"):
                describe("describe-rsa-constructed-"+str(bits), KeyPairIds=[pair["KeyPairId"]], IncludePublicKey=True)
        first = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        second = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        for label, material in (("two-key-lines", first+b"\\n"+second+b"\\n"), ("trailing-text", first+b"\\nnot a key"), ("leading-comment", b"# owned comment\\n"+first)):
            pair = imported("import-"+label, material)
            if pair.get("KeyPairId"):
                describe("describe-"+label, KeyPairIds=[pair["KeyPairId"]], IncludePublicKey=True)

    try:
        if args.import_boundaries:
            import_boundaries()
        elif args.supplement:
            supplement()
        else:
            primary()
    finally:
        for key_id in sorted(owned):
            deleted = observe("cleanup-"+key_id, "delete-key-pair", {"KeyPairId": key_id})
            if deleted.get("Return"):
                evidence["cleanup"]["deleted_ids"].append(key_id)
        remaining = describe("cleanup-absence", Filters=[{"Name": "key-name", "Values": ["*"+prefix+"*"]}])
        evidence["cleanup"]["remaining_owned"] = remaining.get("KeyPairs")
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    assert evidence["cleanup"]["remaining_owned"] == [], "Owned key pairs remain"
    try:
        capture_audit(evidence, env)
    finally:
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"calls": len(evidence["calls"]), "deleted": len(evidence["cleanup"]["deleted_ids"]), "remaining": evidence["cleanup"]["remaining_owned"], "audit_events": len(evidence["cloudtrail"]["events"])}))


def capture_audit(evidence, env):
    requests = {row["requestID"]: row["label"] for row in evidence["calls"] if row.get("requestID")}
    start = datetime.datetime.fromisoformat(evidence["captured_at"]) - datetime.timedelta(seconds=1)

    def redact(value):
        if isinstance(value, dict):
            return {key: "<redacted>" if key.lower() in ("accesskeyid", "sourceipaddress", "secretaccesskey", "sessiontoken") else redact(child) for key, child in value.items()}
        if isinstance(value, list):
            return [redact(child) for child in value]
        return value

    audit = None
    try:
        audit = collect_history(
            lambda parameters: call("cloudtrail", "lookup-events", parameters, env=env,
                                    paginate=False, error_format="json"),
            requests, start_time=start, event_sources=("ec2.amazonaws.com",), max_pages=8)
    except CollectionError as error:
        audit = error.result
        raise
    finally:
        if audit is not None:
            events = [redact(row["event"]) for row in audit["events"]]
            text = json.dumps(events)
            assert "PRIVATE KEY-----" not in text and "PuTTY-User-Key-File" not in text, "Private material in native audit"
            evidence["cloudtrail"] = {**audit, "events": events, "missing": audit["missing_calls"]}


if __name__ == "__main__":
    main()
