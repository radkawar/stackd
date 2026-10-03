#!/usr/bin/env python3
"""Follow-up certificate normalization and chain probes with verified cleanup."""
import base64
import datetime
import hashlib
import json
import pathlib
import secrets
import subprocess
import tempfile
from iam_certificates_probe import call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    name = "stackd-CertEdge-" + secrets.token_hex(8)
    rows, servers = [], set()
    def require(result):
        if result["code"] != "Success":
            raise RuntimeError(result["code"])
        return result["output"]
    def observe(case, operation, args):
        result = call(operation, args)
        row = {"case": case, "code": result["code"]}
        if "message" in result: row["message"] = result["message"].replace(name, "<owned>")
        if operation == "upload-server-certificate" and result["code"] == "Success":
            servers.add(args["ServerCertificateName"])
        rows.append(row)
        print(case + ": " + row["code"], flush=True)
        return result, row
    with tempfile.TemporaryDirectory(prefix="stackd-cert-edge-") as temp:
        path = pathlib.Path(temp)
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=temp, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem", "-days", "3", "-subj", "/CN=stackd-owned-root.invalid")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=stackd-owned.invalid")
        openssl("x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-days", "3", "-out", "leaf.pem")
        read = lambda file: (path / file).read_text()
        try:
            require(call("create-user", {"UserName": name}))
            cert = require(call("upload-signing-certificate", {"UserName": name, "CertificateBody": read("root.pem")}))["Certificate"]
            require(call("update-signing-certificate", {"UserName": name, "CertificateId": cert["CertificateId"], "Status": "Inactive"}))
            result, row = observe("signing:duplicate-inactive", "upload-signing-certificate", {"UserName": name, "CertificateBody": read("root.pem")})
            duplicate = require(result)["Certificate"]
            row.update(same_id=cert["CertificateId"] == duplicate["CertificateId"], same_upload_date=cert["UploadDate"] == duplicate["UploadDate"], status=duplicate["Status"])
            row["listed_status"] = require(call("list-signing-certificates", {"UserName": name}))["Certificates"][0]["Status"]
            der = base64.b64decode("".join(read("root.pem").splitlines()[1:-1]))
            row["id_is_base32_sha1_der"] = cert["CertificateId"] == base64.b32encode(hashlib.sha1(der).digest()).decode()
            ssh = subprocess.run(["ssh-keygen", "-y", "-f", str(path / "root.key")], check=True, capture_output=True, text=True).stdout.strip() + " kept-comment"
            key = require(call("upload-ssh-public-key", {"UserName": name, "SSHPublicKeyBody": ssh}))["SSHPublicKey"]
            output, row = observe("ssh:get-comment", "get-ssh-public-key", {"UserName": name, "SSHPublicKeyId": key["SSHPublicKeyId"], "Encoding": "SSH"})
            row["body_equals_uploaded_with_comment"] = require(output)["SSHPublicKey"]["SSHPublicKeyBody"] == ssh
            for case, body, extra in [("missing-chain", read("leaf.pem"), {}), ("valid-chain", read("leaf.pem"), {"CertificateChain": read("root.pem")}), ("leaf-in-chain", read("leaf.pem"), {"CertificateChain": read("leaf.pem") + read("root.pem")}), ("duplicate-chain", read("leaf.pem"), {"CertificateChain": read("root.pem") + read("root.pem")})]:
                observe("server:" + case, "upload-server-certificate", dict(ServerCertificateName=name + "-" + case, CertificateBody=body, PrivateKey=read("leaf.key"), **extra))
            server = name + "-tags"
            upload = {"ServerCertificateName": server, "CertificateBody": read("root.pem"), "PrivateKey": read("root.key"), "Tags": [{"Key": "Team", "Value": "one"}, {"Key": "team", "Value": "two"}]}
            require(observe("server:upload-tags", "upload-server-certificate", upload)[0])
            for case in ["initial", "after-tag", "after-empty-update"]:
                if case == "after-tag":
                    require(call("tag-server-certificate", {"ServerCertificateName": server, "Tags": [{"Key": "third", "Value": "three"}]}))
                if case == "after-empty-update":
                    require(call("update-server-certificate", {"ServerCertificateName": server}))
                result, row = observe("server:tags-" + case, "list-server-certificate-tags", {"ServerCertificateName": server})
                row["tags"] = require(result).get("Tags")
                output = require(call("get-server-certificate", {"ServerCertificateName": server}))["ServerCertificate"]
                row["get_tags"] = output.get("Tags")
                row["metadata"] = {k: v.replace(name, "<owned>") if isinstance(v, str) else v for k, v in output["ServerCertificateMetadata"].items() if k in ["Path", "ServerCertificateName"]}
            observe("server:untag-missing", "untag-server-certificate", {"ServerCertificateName": server, "TagKeys": ["Team"]})
            observe("server:retag-after-empty-update", "tag-server-certificate", {"ServerCertificateName": server, "Tags": [{"Key": "Team", "Value": "one"}, {"Key": "team", "Value": "two"}]})
            observe("server:untag-mixed-missing", "untag-server-certificate", {"ServerCertificateName": server, "TagKeys": ["Team", "missing"]})
            observe("server:untag-after-empty-update", "untag-server-certificate", {"ServerCertificateName": server, "TagKeys": ["Team"]})
            output, row = observe("server:case-sensitive-untag", "list-server-certificate-tags", {"ServerCertificateName": server})
            row["tags"] = require(output).get("Tags")
        finally:
            for server in servers:
                require(call("delete-server-certificate", {"ServerCertificateName": server}))
                assert call("get-server-certificate", {"ServerCertificateName": server})["code"] == "NoSuchEntity"
            for cert in require(call("list-signing-certificates", {"UserName": name})).get("Certificates", []):
                require(call("delete-signing-certificate", {"UserName": name, "CertificateId": cert["CertificateId"]}))
            for key in require(call("list-ssh-public-keys", {"UserName": name})).get("SSHPublicKeys", []):
                require(call("delete-ssh-public-key", {"UserName": name, "SSHPublicKeyId": key["SSHPublicKeyId"]}))
            require(call("delete-user", {"UserName": name}))
            assert call("get-user", {"UserName": name})["code"] == "NoSuchEntity"
            pathlib.Path('.stackd/probes/iam/certificate_edges_aws.json').parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path('.stackd/probes/iam/certificate_edges_aws.json').write_text(json.dumps({"source": "real AWS IAM with owned temporary resources", "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "cleanup_verified": True, "observations": rows}, indent=2) + "\n")


if __name__ == "__main__":
    main()
