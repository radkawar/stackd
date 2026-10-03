#!/usr/bin/env python3
"""Bounded IAM certificate/key probes; owned resources, no retained private keys."""
import datetime
import json
import pathlib
import re
import secrets
import subprocess
import tempfile

from aws_cli import run as run_cli, result as cli_result


def call(op, args):
    process = run_cli("iam", op, args, options=["--no-paginate"])
    return cli_result(process, cli_message="Client validation failure")


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    prefix = "stackd-Cert-" + secrets.token_hex(8)
    users = [prefix, prefix + "-other"]
    owned_users, owned_servers, rows = set(), set(), []
    def require(r):
        if r["code"] != "Success":
            raise RuntimeError(r["code"])
        return r["output"]
    def observe(case, op, args):
        result = call(op, args)
        row = {"case": case, "code": result["code"]}
        if "message" in result:
            row["message"] = re.sub(r"\b\d{12}\b", "<account>", result["message"].replace(prefix, "<owned>"))
        for name in ["Certificate", "SSHPublicKey", "ServerCertificateMetadata", "ServerCertificate"]:
            if name in result.get("output", {}):
                item = result["output"][name]
                row["fields"] = sorted(item)
                for key in ["Status", "Fingerprint", "UserName", "Path", "ServerCertificateName"]:
                    if key in item:
                        row[key] = item[key].replace(prefix, "<owned>")
                for key in ["CertificateId", "SSHPublicKeyId", "ServerCertificateId"]:
                    if key in item:
                        row["id_length"] = len(item[key])
                        row["id_prefix"] = item[key][:4] if key != "CertificateId" else "variable"
                for key in ["CertificateBody", "SSHPublicKeyBody"]:
                    if key in item:
                        row[key + "_matches_input"] = item[key] == args.get(key)
                        row[key + "_first_line"] = item[key].splitlines()[0][:35]
                        row[key + "_trailing_newline"] = item[key].endswith("\n")
        if "Tags" in result.get("output", {}):
            row["Tags"] = result["output"]["Tags"]
        rows.append(row)
        if op == "upload-server-certificate" and result["code"] == "Success":
            owned_servers.add(args["ServerCertificateName"])
        print(case + ": " + result["code"], flush=True)
        return result
    with tempfile.TemporaryDirectory(prefix="stackd-cert-probe-") as temp:
        path = pathlib.Path(temp)
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=temp, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name, bits in [("rsa", "2048"), ("small", "1024"), ("other", "2048")]:
            openssl("req", "-x509", "-newkey", "rsa:" + bits, "-nodes", "-keyout", name + ".key", "-out", name + ".pem", "-days", "3", "-subj", "/CN=stackd-owned.invalid")
            openssl("pkey", "-in", name + ".key", "-pubout", "-out", name + ".pub")
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ec.key", "-out", "ec.pem", "-days", "3", "-subj", "/CN=stackd-owned.invalid")
        openssl("x509", "-in", "rsa.pem", "-signkey", "rsa.key", "-days", "-1", "-out", "expired.pem")
        read = lambda name: (path / name).read_text()
        ssh = subprocess.run(["ssh-keygen", "-y", "-f", str(path / "rsa.key")], check=True, capture_output=True, text=True).stdout.strip() + " probe-comment"
        try:
            for user in users:
                require(call("create-user", {"UserName": user}))
                owned_users.add(user)
            # Signing certificate validation, account-wide duplicate detection, lifecycle.
            for case, body in [("malformed", "not a certificate"), ("expired", read("expired.pem")), ("ec", read("ec.pem")), ("rsa1024", read("small.pem"))]:
                r = observe("signing:" + case, "upload-signing-certificate", {"UserName": users[0], "CertificateBody": body})
                if r["code"] == "Success":
                    require(call("delete-signing-certificate", {"UserName": users[0], "CertificateId": r["output"]["Certificate"]["CertificateId"]}))
            first = require(observe("signing:create", "upload-signing-certificate", {"UserName": users[0], "CertificateBody": read("rsa.pem")}))["Certificate"]
            target = {"UserName": users[0], "CertificateId": first["CertificateId"]}
            observe("signing:duplicate", "upload-signing-certificate", {"UserName": users[0], "CertificateBody": read("rsa.pem")})
            observe("signing:duplicate-other-user", "upload-signing-certificate", {"UserName": users[1], "CertificateBody": read("rsa.pem")})
            for status in ["Inactive", "Expired", "Active"]:
                observe("signing:status-" + status, "update-signing-certificate", dict(target, Status=status))
            observe("signing:wrong-owner", "delete-signing-certificate", dict(target, UserName=users[1]))
            observe("signing:second", "upload-signing-certificate", {"UserName": users[0], "CertificateBody": read("other.pem")})
            observe("signing:third", "upload-signing-certificate", {"UserName": users[0], "CertificateBody": read("small.pem")})
            observe("signing:user-delete-blocked", "delete-user", {"UserName": users[0]})
            # SSH encoding, RSA size, duplicate scope and wire representation.
            for case, body in [("malformed", "not a key"), ("rsa1024", read("small.pub")), ("certificate", read("rsa.pem"))]:
                observe("ssh:" + case, "upload-ssh-public-key", {"UserName": users[0], "SSHPublicKeyBody": body})
            first = require(observe("ssh:create", "upload-ssh-public-key", {"UserName": users[0], "SSHPublicKeyBody": ssh}))["SSHPublicKey"]
            target = {"UserName": users[0], "SSHPublicKeyId": first["SSHPublicKeyId"]}
            observe("ssh:duplicate-pem", "upload-ssh-public-key", {"UserName": users[0], "SSHPublicKeyBody": read("rsa.pub")})
            observe("ssh:duplicate-other-user", "upload-ssh-public-key", {"UserName": users[1], "SSHPublicKeyBody": ssh})
            for encoding in ["SSH", "PEM", "ssh"]:
                observe("ssh:get-" + encoding, "get-ssh-public-key", dict(target, Encoding=encoding))
            for status in ["Inactive", "Expired", "Active"]:
                observe("ssh:status-" + status, "update-ssh-public-key", dict(target, Status=status))
            observe("ssh:wrong-owner", "delete-ssh-public-key", dict(target, UserName=users[1]))
            observe("ssh:second", "upload-ssh-public-key", {"UserName": users[0], "SSHPublicKeyBody": read("other.pub")})
            # Server validation retains no private material in observations.
            for case, body, key, extra in [
                ("malformed", "bad cert", read("rsa.key"), {}), ("mismatch", read("rsa.pem"), read("other.key"), {}),
                ("expired", read("expired.pem"), read("rsa.key"), {}), ("ec", read("ec.pem"), read("ec.key"), {}),
                ("rsa1024", read("small.pem"), read("small.key"), {}), ("invalid-chain", read("rsa.pem"), read("rsa.key"), {"CertificateChain": "bad chain"}),
                ("unrelated-chain", read("rsa.pem"), read("rsa.key"), {"CertificateChain": read("other.pem")})]:
                observe("server:" + case, "upload-server-certificate", dict(ServerCertificateName=prefix + "-" + case, CertificateBody=body, PrivateKey=key, **extra))
            name = prefix + "-server"
            upload = {"ServerCertificateName": name, "CertificateBody": read("rsa.pem"), "PrivateKey": read("rsa.key"), "Path": "/probe/", "Tags": [{"Key": "Team", "Value": "one"}, {"Key": "team", "Value": "two"}]}
            require(observe("server:create", "upload-server-certificate", upload))
            observe("server:duplicate-name-case", "upload-server-certificate", dict(upload, ServerCertificateName=name.upper()))
            observe("server:get", "get-server-certificate", {"ServerCertificateName": name})
            observe("server:empty-update", "update-server-certificate", {"ServerCertificateName": name})
            observe("server:tags", "list-server-certificate-tags", {"ServerCertificateName": name})
            observe("server:empty-tags", "tag-server-certificate", {"ServerCertificateName": name, "Tags": []})
            observe("server:empty-untag", "untag-server-certificate", {"ServerCertificateName": name, "TagKeys": []})
            new_name = name + "-renamed"
            r = observe("server:rename", "update-server-certificate", {"ServerCertificateName": name, "NewServerCertificateName": new_name, "NewPath": "/changed/"})
            if r["code"] == "Success":
                owned_servers.remove(name)
                owned_servers.add(new_name)
            observe("server:get-old-name", "get-server-certificate", {"ServerCertificateName": name})
        finally:
            for name in sorted(owned_servers):
                require(call("delete-server-certificate", {"ServerCertificateName": name}))
                if call("get-server-certificate", {"ServerCertificateName": name})["code"] != "NoSuchEntity":
                    raise RuntimeError("Server cleanup not verified")
            for user in sorted(owned_users):
                for item in require(call("list-signing-certificates", {"UserName": user})).get("Certificates", []):
                    require(call("delete-signing-certificate", {"UserName": user, "CertificateId": item["CertificateId"]}))
                for item in require(call("list-ssh-public-keys", {"UserName": user})).get("SSHPublicKeys", []):
                    require(call("delete-ssh-public-key", {"UserName": user, "SSHPublicKeyId": item["SSHPublicKeyId"]}))
                require(call("delete-user", {"UserName": user}))
                if call("get-user", {"UserName": user})["code"] != "NoSuchEntity":
                    raise RuntimeError("User cleanup not verified")
            output = {"source": "real AWS IAM via AWS CLI; owned temporary resources", "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "cleanup_verified": True, "observations": rows}
            pathlib.Path('.stackd/probes/iam/certificates_aws.json').parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path('.stackd/probes/iam/certificates_aws.json').write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
