#!/usr/bin/env python3
"""Probe IAM service credentials on owned temporary users; never persist secrets."""

import base64
import datetime
import json
import pathlib
import re
import secrets

from aws_cli import run as run_cli, result as cli_result, error_code


SERVICES = ["codecommit.amazonaws.com", "cassandra.amazonaws.com", "bedrock.amazonaws.com", "logs.amazonaws.com", "cloudwatch.amazonaws.com", "aws-external-anthropic.amazonaws.com"]


def call(operation, parameters, env=None):
    process = run_cli("iam", operation, parameters, env, options=["--no-paginate"])
    result = cli_result(process, cli_message="Client-side rejection")
    if process.returncode:
        result["code"] = error_code(process)
    return result


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    original = "stackd-SvcCred-" + secrets.token_hex(8)
    names = [original, original + "-other", original + "-renamed"]
    active_name = original
    owned = set()
    observations = []

    def redact(text):
        for name in names:
            text = re.sub(re.escape(name), "<owned-user>", text, flags=re.I)
        text = re.sub(r"\b\d{12}\b", "<account>", text)
        text = re.sub(r"ACCA[A-Z0-9]+", "<credential-id>", text)
        return text

    def metadata(record):
        out = {"fields": sorted(record)}
        for key in ["ServiceName", "Status", "ServiceUserName", "ServiceCredentialAlias", "UserName"]:
            if key in record:
                out[key] = redact(record[key])
        if record.get("UserName") not in names:
            for key in ["UserName", "ServiceUserName", "ServiceCredentialAlias"]:
                if key in out:
                    out[key] = "<other-user-metadata>"
        if "ServiceSpecificCredentialId" in record:
            out["id_prefix"] = record["ServiceSpecificCredentialId"][:4]
            out["id_length"] = len(record["ServiceSpecificCredentialId"])
        if "ExpirationDate" in record:
            start = datetime.datetime.fromisoformat(record["CreateDate"].replace("Z", "+00:00"))
            end = datetime.datetime.fromisoformat(record["ExpirationDate"].replace("Z", "+00:00"))
            out["expiration_seconds_after_creation"] = (end - start).total_seconds()
        for key in ["ServicePassword", "ServiceCredentialSecret"]:
            if key in record:
                value = record[key]
                out[key + "_length"] = len(value)
                out[key + "_starts_ABSK"] = value.startswith("ABSK")
                try:
                    decoded = base64.b64decode(value, validate=True).decode()
                    out[key + "_base64_alias_colon_secret"] = decoded.startswith(record.get("ServiceCredentialAlias", "missing") + ":")
                except (ValueError, UnicodeError):
                    pass
        return out

    def observe(case, operation, parameters):
        result = call(operation, parameters)
        out = {"case": case, "code": result["code"]}
        if "message" in result:
            out["message"] = redact(result["message"])
        body = result.get("output", {})
        if "ServiceSpecificCredential" in body:
            out["credential"] = metadata(body["ServiceSpecificCredential"])
        if "ServiceSpecificCredentials" in body:
            out["output_fields"] = sorted(body)
            out["credentials"] = [metadata(record) for record in body["ServiceSpecificCredentials"]]
            out["is_truncated"] = body.get("IsTruncated")
        observations.append(out)
        print(case + ": " + result["code"], flush=True)
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError("Probe setup failed: " + result["code"])
        return result["output"]

    try:
        for name in names[:2]:
            require(call("create-user", {"UserName": name, "Tags": [{"Key": "stackd-probe", "Value": "service-credentials"}]}))
            owned.add(name)
        observe("unsupported-service", "create-service-specific-credential", {"UserName": active_name, "ServiceName": "sqs.amazonaws.com"})
        observe("uppercase-service", "create-service-specific-credential", {"UserName": active_name, "ServiceName": "CodeCommit.amazonaws.com"})
        observe("legacy-expiration", "create-service-specific-credential", {"UserName": active_name, "ServiceName": SERVICES[0], "CredentialAgeDays": 1})
        for service in SERVICES:
            # Earlier accepted variants may already have created one credential.
            existing = require(call("list-service-specific-credentials", {"UserName": active_name, "ServiceName": service})).get("ServiceSpecificCredentials", [])
            for record in existing:
                require(call("delete-service-specific-credential", {"UserName": active_name, "ServiceSpecificCredentialId": record["ServiceSpecificCredentialId"]}))
            arguments = {"UserName": active_name, "ServiceName": service}
            if service not in SERVICES[:2]:
                arguments["CredentialAgeDays"] = 1
            first = observe(service + ":create-first", "create-service-specific-credential", arguments)
            if first["code"] != "Success":
                continue
            record = first["output"]["ServiceSpecificCredential"]
            credential_id = record["ServiceSpecificCredentialId"]
            target = {"UserName": active_name, "ServiceSpecificCredentialId": credential_id}
            observe(service + ":create-second-no-expiry", "create-service-specific-credential", {"UserName": active_name, "ServiceName": service})
            observe(service + ":create-third", "create-service-specific-credential", {"UserName": active_name, "ServiceName": service})
            observe(service + ":wrong-owner", "reset-service-specific-credential", dict(target, UserName=names[1]))
            observe(service + ":disable", "update-service-specific-credential", dict(target, Status="Inactive"))
            reset = observe(service + ":reset-inactive", "reset-service-specific-credential", target)
            if reset["code"] == "Success":
                updated = reset["output"]["ServiceSpecificCredential"]
                observations[-1]["create_date_preserved"] = updated.get("CreateDate") == record.get("CreateDate")
                observations[-1]["expiration_preserved"] = updated.get("ExpirationDate") == record.get("ExpirationDate")
                observations[-1]["secret_changed"] = updated.get("ServicePassword", updated.get("ServiceCredentialSecret")) != record.get("ServicePassword", record.get("ServiceCredentialSecret"))
            observe(service + ":set-expired", "update-service-specific-credential", dict(target, Status="Expired"))
            observe(service + ":reactivate", "update-service-specific-credential", dict(target, Status="Active"))
            observe(service + ":list-single-page", "list-service-specific-credentials", {"UserName": active_name, "ServiceName": service, "MaxItems": 1})
        observe("list-unknown-service", "list-service-specific-credentials", {"UserName": active_name, "ServiceName": "sqs.amazonaws.com"})
        observe("list-empty-service", "list-service-specific-credentials", {"UserName": active_name, "ServiceName": ""})
        observe("list-invalid-service-characters", "list-service-specific-credentials", {"UserName": active_name, "ServiceName": " CODECOMMIT.amazonaws.com "})
        observe("list-unsupported-cn-service", "list-service-specific-credentials", {"UserName": active_name, "ServiceName": "codecommit.amazonaws.com.cn"})
        observe("list-all-users-missing-service", "list-service-specific-credentials", {"AllUsers": True, "MaxItems": 1})
        observe("list-all-users-legacy", "list-service-specific-credentials", {"AllUsers": True, "ServiceName": SERVICES[0], "MaxItems": 1})
        observe("list-all-users-api-key", "list-service-specific-credentials", {"AllUsers": True, "ServiceName": SERVICES[2], "MaxItems": 1})
        observe("list-all-users-and-user", "list-service-specific-credentials", {"AllUsers": True, "UserName": active_name})
        observe("list-false-all-users-and-user", "list-service-specific-credentials", {"AllUsers": False, "UserName": active_name})
        observe("caller-list-omitted-user", "list-service-specific-credentials", {})
        observe("missing-credential-id", "delete-service-specific-credential", {"UserName": active_name, "ServiceSpecificCredentialId": "ACCA" + "X" * 16})
        require(observe("rename-owner", "update-user", {"UserName": active_name, "NewUserName": names[2]}))
        owned.remove(active_name)
        active_name = names[2]
        owned.add(active_name)
        observe("list-after-rename", "list-service-specific-credentials", {"UserName": active_name})
        result = observe("delete-user-with-service-credentials", "delete-user", {"UserName": active_name})
        if result["code"] == "Success":
            owned.remove(active_name)
    finally:
        cleanup = []
        for name in sorted(owned):
            listed = call("list-service-specific-credentials", {"UserName": name})
            cleanup.append(listed["code"])
            if listed["code"] == "Success":
                for record in listed["output"].get("ServiceSpecificCredentials", []):
                    cleanup.append(call("delete-service-specific-credential", {"UserName": name, "ServiceSpecificCredentialId": record["ServiceSpecificCredentialId"]})["code"])
            cleanup.append(call("delete-user", {"UserName": name})["code"])
            cleanup.append(call("get-user", {"UserName": name})["code"])
        fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": "Real AWS IAM; owned temporary users and service credentials. Credential values and identifiers omitted.", "observations": observations, "cleanup": cleanup, "reference_urls": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceSpecificCredential.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_api_keys_for_aws_services.html"]}
        destination = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/iam/service_credentials_aws.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2) + "\n")
        if any(code not in {"Success", "NoSuchEntity"} for code in cleanup) or (owned and cleanup[-1] != "NoSuchEntity"):
            raise RuntimeError("Cleanup failed; inspect temporary stackd-SvcCred users")


if __name__ == "__main__":
    main()
