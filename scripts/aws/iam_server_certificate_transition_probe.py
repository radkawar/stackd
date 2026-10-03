#!/usr/bin/env python3
"""Distinguish IAM server-certificate update state from tag propagation."""
import datetime
import json
import pathlib
import re
import secrets
import subprocess
import tempfile
import time
from iam_certificates_probe import call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--empty-only", action="store_true")
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    prefix = "stackd-CertTxn-" + secrets.token_hex(8)
    names, observations = set(), []
    def require(result):
        if result["code"] != "Success": raise RuntimeError(result["code"])
        return result["output"]
    def observe(case, name):
        result = call("get-server-certificate", {"ServerCertificateName": name})
        row = {"case": case, "code": result["code"]}
        if result["code"] == "Success":
            cert = result["output"]["ServerCertificate"]
            row["metadata"] = {k: re.sub(r"\b\d{12}\b", "<account>", v.replace(prefix, "<owned>")) for k, v in cert["ServerCertificateMetadata"].items() if k in ["Arn", "Path", "ServerCertificateName"]}
            row["tags"] = cert.get("Tags")
        observations.append(row)
        print(case + ": " + row["code"], flush=True)
    with tempfile.TemporaryDirectory(prefix="stackd-cert-txn-") as temp:
        path = pathlib.Path(temp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(path / "private.pem"), "-out", str(path / "public.pem"), "-days", "3", "-subj", "/CN=owned.invalid"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for case in (["empty"] if probe_args.empty_only else ["empty", "rename", "path"]):
                name = prefix + "-" + case
                require(call("upload-server-certificate", {"ServerCertificateName": name, "Path": "/before/", "CertificateBody": (path / "public.pem").read_text(), "PrivateKey": (path / "private.pem").read_text(), "Tags": [{"Key": "Team", "Value": "one"}, {"Key": "team", "Value": "two"}]}))
                names.add(name)
                args = {"ServerCertificateName": name}
                if case == "rename": args["NewServerCertificateName"] = name + "-new"
                if case == "path": args["NewPath"] = "/after/"
                observe(case + ":before", name)
                require(call("update-server-certificate", args))
                if case == "rename":
                    names.remove(name)
                    name = args["NewServerCertificateName"]
                    names.add(name)
                observe(case + ":immediate", name)
            time.sleep(15)
            for name in sorted(names):
                case = name.replace(prefix + "-", "")
                observe(case + ":delayed", name)
                tagged = call("tag-server-certificate", {"ServerCertificateName": name, "Tags": [{"Key": "Team", "Value": "retagged"}]})
                observations.append({"case": case + ":retag-delayed", "code": tagged["code"], "message": tagged.get("message", "").replace(prefix, "<owned>")})
                observe(case + ":after-retag", name)
                if case == "empty":
                    require(call("update-server-certificate", {"ServerCertificateName": name, "NewPath": "/before/"}))
                    observe("empty:after-explicit-repair", name)
                    fixed = call("tag-server-certificate", {"ServerCertificateName": name, "Tags": [{"Key": "Team", "Value": "fixed"}]})
                    observations.append({"case": "empty:retag-after-repair", "code": fixed["code"]})
        finally:
            for name in names:
                require(call("delete-server-certificate", {"ServerCertificateName": name}))
                assert call("get-server-certificate", {"ServerCertificateName": name})["code"] == "NoSuchEntity"
            filename = "server_certificate_empty_update_aws.json" if probe_args.empty_only else "server_certificate_transitions_aws.json"
            pathlib.Path('.stackd/probes/iam/' + filename).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path('.stackd/probes/iam/' + filename).write_text(json.dumps({"source": "AWS IAM owned server-certificate update/readback with 15-second settling interval", "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "cleanup_verified": True, "observations": observations}, indent=2) + "\n")


if __name__ == "__main__": main()
