#!/usr/bin/env python3
"""Measure IAM-to-STS outbound feature propagation and public key continuity.

Requires initially disabled outbound federation and temporarily enables it. The
feature is disabled again in cleanup. Existing identity policies are unchanged.
Only token timing, issuer and public key IDs are retained; bearer tokens and
principal/session claims remain in memory.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import time
import urllib.request

sys.dont_write_bytecode = True
from iam_outbound_identity_probe import OutboundProbe, ROOT, call, stamp


class LifecycleProbe(OutboundProbe):
    def __init__(self, output):
        super().__init__(output)
        self.issuance = True
        self.probe_name = "scripts/aws/iam_outbound_lifecycle_probe.py"
        self.limitations = [
            "The initially disabled account feature is enabled temporarily and restored to disabled. No existing policies or identities are changed.",
            "This bounded commercial-account capture observes propagation across three STS regions; timings are measurements, not an AWS latency guarantee.",
            "Only JWT issuer, key ID and timestamps are retained. Tokens, credential secrets and identity claims are discarded.",
            "No long-term signing-key rotation interval can be established by this short observation window.",
        ]

    def token(self, region):
        started = time.monotonic()
        result = self.query("sts", "get-web-identity-token",
                            {"Audience": ["https://stackd-lifecycle.example.invalid"], "SigningAlgorithm": "ES384", "DurationSeconds": 60},
                            None, region, "https://sts." + region + ".amazonaws.com")
        output = result.get("output", {})
        record = {"region": region, "code": result["code"], "http_status": result["http_status"],
                  "observed_at": stamp(), "request_seconds": round(time.monotonic() - started, 3)}
        token = output.get("WebIdentityToken")
        if token:
            header, claims, _ = token.split(".")
            decode = lambda text: json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
            head, body = decode(header), decode(claims)
            record.update(key_id=head["kid"], issuer=body["iss"], issued_at=body["iat"], expires_at=body["exp"])
        return record

    def configure(self, case, enabled):
        action = "enable-outbound-web-identity-federation" if enabled else "disable-outbound-web-identity-federation"
        result = self.request(case, "iam", action)
        if result["code"] != "Success":
            raise RuntimeError("Feature configuration failed: " + result["code"])
        return result["output"]

    def wait_vending(self, phase, enabled, regions):
        expected = "Success" if enabled else "OutboundWebIdentityFederationDisabledException"
        started = time.monotonic()
        consecutive = dict.fromkeys(regions, 0)
        # Observe each endpoint concurrently so regional timing is comparable.
        # Keep probing settled regions until all have three matching rounds.
        with ThreadPoolExecutor(max_workers=len(regions)) as executor:
            while time.monotonic() - started < 240:
                observations = list(executor.map(self.token, regions))
                elapsed = round(time.monotonic() - started, 3)
                for row in observations:
                    row.update(case=phase, elapsed_seconds=elapsed)
                    self.observations.append(self.normalize(row))
                    consecutive[row["region"]] = consecutive[row["region"]] + 1 if row["code"] == expected else 0
                    if row["code"] not in ("Success", "OutboundWebIdentityFederationDisabledException") and row["http_status"] < 500:
                        raise RuntimeError("Unexpected regional token response: " + row["code"])
                self.write()
                print(phase, elapsed, [(row["region"], row["code"]) for row in observations], flush=True)
                if min(consecutive.values()) >= 3:
                    return
                time.sleep(2)
        raise RuntimeError("Propagation did not settle within the observation window")

    def keys(self, case, issuer):
        with urllib.request.urlopen(issuer + "/.well-known/jwks.json", timeout=30) as response:
            keys = json.load(response)
            self.observations.append(self.normalize({"case": case, "observed_at": stamp(), "http_status": response.status, "output": keys}))
            self.write()
            return keys


def run(p):
    identity = call("sts", "get-caller-identity")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable")
    p.account = identity["output"]["Account"]
    state = p.request("initial", "iam", "get-outbound-web-identity-federation-info")
    if state["code"] != "FeatureDisabled":
        raise RuntimeError("Lifecycle capture requires initially disabled configuration")
    regions = ["us-east-1", "eu-west-2", "us-west-2"]
    # Prime credential loading before starting the concurrent signed requests.
    p.observations.append(p.normalize({"case": "initial_token", **p.token(regions[0])}))
    enabled = p.configure("enable", True)
    p.own("iam", "disable-outbound-web-identity-federation", {})
    issuer = enabled["IssuerIdentifier"]
    keys = p.keys("keys_enabled", issuer)
    p.wait_vending("enable_propagation", True, regions)
    p.configure("disable", False)
    p.request("info_after_disable", "iam", "get-outbound-web-identity-federation-info")
    p.wait_vending("disable_propagation", False, regions)
    disabled_keys = p.keys("keys_disabled", issuer)
    again = p.configure("reenable", True)
    p.wait_vending("reenable_propagation", True, regions)
    final_keys = p.keys("keys_reenabled", issuer)
    p.eligibility.update(issuer_stable=again["IssuerIdentifier"] == issuer,
                         keys_stable_while_disabled=keys == disabled_keys, keys_stable_after_reenable=keys == final_keys)
    # Distinguish an ordered transition stream from coalescing the latest IAM
    # value. The account is enabled before this brief disable/re-enable pair.
    p.configure("rapid_disable", False)
    time.sleep(2)
    p.configure("rapid_reenable", True)
    started = time.monotonic()
    while time.monotonic() - started < 25:
        row = p.token("us-east-1")
        row.update(case="rapid_propagation", elapsed_seconds=round(time.monotonic()-started, 3))
        p.observations.append(p.normalize(row))
        p.write()
        print("rapid_propagation", row["elapsed_seconds"], row["code"], flush=True)
        time.sleep(0.5)


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / '.stackd/probes/iam/outbound_lifecycle.json')
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    p = LifecycleProbe(probe_args.output)
    try:
        run(p)
        p.complete = True
    finally:
        p.finish()


if __name__ == "__main__":
    main()
