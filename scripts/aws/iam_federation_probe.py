#!/usr/bin/env python3
"""Refresh owned-resource IAM federation observations; all AWS resources are deleted.

Run explicitly with working AWS credentials. Normal Go tests only replay the
checked-in JSON. Private keys in testdata are public, generated test material.
"""
import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "internal/services/iam/testdata/federation"
COMMON = ["--endpoint-url", "https://iam.amazonaws.com", "--region", "us-east-1",
          "--output", "json", "--no-cli-pager"]


class Probe:
    def __init__(self, kind):
        self.kind = kind
        self.prefix = "stackd-federation-" + uuid.uuid4().hex[:12]
        self.rows = []
        self.owned = []
        self.keys = {path.read_text(): path.name for path in FIXTURES.glob("*.pem")}

    def call(self, action, inputs):
        result = subprocess.run(["aws", "iam", action, "--cli-input-json",
                                 json.dumps(inputs), *COMMON],
                                capture_output=True, text=True, timeout=60)
        output = json.loads(result.stdout) if not result.returncode and result.stdout.strip() else {}
        recorded = dict(inputs)
        if "AddPrivateKey" in recorded:
            recorded["AddPrivateKey"] = "<fixture:" + self.keys[recorded["AddPrivateKey"]] + ">"
        self.rows.append({"operation": action, "input": recorded, "output": output,
                          "exit_code": result.returncode, "error": result.stderr,
                          "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
        if action.startswith("create-") and not result.returncode:
            field = "SAMLProviderArn" if self.kind.startswith("saml") else "OpenIDConnectProviderArn"
            self.owned.append(output[field])
        print(action, result.returncode, flush=True)
        return output if not result.returncode else None

    def finish(self):
        field, action = (("SAMLProviderArn", "delete-saml-provider") if self.kind.startswith("saml")
                         else ("OpenIDConnectProviderArn", "delete-open-id-connect-provider"))
        failures = []
        for arn in self.owned:
            if self.call(action, {field: arn}) is None:
                failures.append(arn)
        fixture = {"source": "Real AWS IAM; uniquely owned providers; test-only key material",
                   "endpoint": "https://iam.amazonaws.com", "region": "us-east-1",
                   "probe": "scripts/aws/iam_federation_probe.py " + self.kind,
                   "cleanup_complete": not failures, "scenarios": self.rows}
        raw = re.sub(r"arn:aws:iam::\d{12}:", "arn:aws:iam::<source-account>:",
                     json.dumps(fixture, indent=2))
        (ROOT / '.stackd/probes/iam/federation' / (self.kind + '.json')).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / ".stackd/probes/iam/federation" / (self.kind + ".json")).write_text(raw + "\n")
        if failures:
            raise RuntimeError("Delete these owned provider ARNs: " + ", ".join(failures))


def oidc(p):
    create, get = "create-open-id-connect-provider", "get-open-id-connect-provider"
    issuer = "https://" + p.prefix + ".example.com/path/"
    out = p.call(create, {"Url": issuer, "ClientIDList": ["z", "a", "z"],
                          "ThumbprintList": ["A" * 40, "a" * 40],
                          "Tags": [{"Key": "key", "Value": "value"}, {"Key": "Key", "Value": "Value"}]})
    if out:
        base = {"OpenIDConnectProviderArn": out["OpenIDConnectProviderArn"]}
        p.call(get, base)
        p.call(create, {"Url": issuer[:-1], "ThumbprintList": ["b" * 40]})
        p.call("add-client-id-to-open-id-connect-provider", {**base, "ClientID": "a"})
        p.call("remove-client-id-from-open-id-connect-provider", {**base, "ClientID": "missing"})
        p.call("update-open-id-connect-provider-thumbprint", {**base, "ThumbprintList": ["C" * 40] * 2})
        p.call(get, base)
        p.call("update-open-id-connect-provider-thumbprint", {**base, "ThumbprintList": []})
    for suffix, prints in [(":443", ["b" * 40]), ("/?q=value", ["b" * 40]),
                           ("/#fragment", ["b" * 40]), ("/nonhex", ["g" * 40]),
                           ("/six", ["b" * 40] * 6), ("/MixedCase", ["b" * 40])]:
        out = p.call(create, {"Url": "https://" + p.prefix.upper() + ".EXAMPLE.COM" + suffix,
                              "ThumbprintList": prints})
        if out:
            p.call(get, {"OpenIDConnectProviderArn": out["OpenIDConnectProviderArn"]})


def saml(p):
    metadata = (FIXTURES / "metadata.xml").read_text()
    key = (FIXTURES / "private-key-1.pem").read_text()
    out = p.call("create-saml-provider", {"Name": p.prefix, "SAMLMetadataDocument": metadata})
    if not out:
        return
    base = {"SAMLProviderArn": out["SAMLProviderArn"]}
    p.call("get-saml-provider", base)
    p.call("update-saml-provider", base)
    p.call("update-saml-provider", {**base, "AssertionEncryptionMode": "Required"})
    for _ in range(3):
        p.call("update-saml-provider", {**base, "AddPrivateKey": key})
    p.call("update-saml-provider", {**base, "AssertionEncryptionMode": "Required"})
    state = p.call("get-saml-provider", base)
    if state:
        for entry in state["PrivateKeyList"]:
            p.call("update-saml-provider", {**base, "RemovePrivateKey": entry["KeyId"]})
    p.call("get-saml-provider", base)
    if p.kind != "saml-validation":
        return
    for name in ["pkcs1", "rsa1024", "ec"]:
        p.call("create-saml-provider", {"Name": p.prefix + "-" + name,
                                       "SAMLMetadataDocument": metadata,
                                       "AddPrivateKey": (FIXTURES / (name + ".pem")).read_text()})
    variants = {
        "no-entity": re.sub(r' entityID="[^"]*"', "", metadata),
        "collection": '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">' + metadata + '</EntitiesDescriptor>',
        "encryption-only": metadata.replace('use="signing"', 'use="encryption"'),
        "empty": '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/"/><!--' + "x" * 1000 + "-->",
        "no-certificate": re.sub(r'<KeyDescriptor.*?</KeyDescriptor>', '', metadata) + '<!--' + 'x' * 1100 + '-->',
        "expired-metadata": metadata.replace('2030-01-01', '2020-01-01'),
    }
    for name, document in variants.items():
        out = p.call("create-saml-provider", {"Name": p.prefix + "-" + name, "SAMLMetadataDocument": document})
        if out:
            base = {"SAMLProviderArn": out["SAMLProviderArn"]}
            p.call("get-saml-provider", base)
            p.call("update-saml-provider", {**base, "SAMLMetadataDocument": metadata})
            p.call("get-saml-provider", base)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["oidc", "saml", "saml-validation"])
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    probe = Probe(args.scenario)
    try:
        (oidc if args.scenario == "oidc" else saml)(probe)
    finally:
        probe.finish()


if __name__ == "__main__":
    main()
